// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! HTTPRoute reconciler.
//!
//! Watches HTTPRoute resources, resolves parentRefs against Gateway
//! listeners, computes `Accepted` / `ResolvedRefs` conditions on
//! `.status.parents[]`, and emits `RouteState` for the reconciled view.

use crate::gateway::api::HTTPRoute;
use crate::gateway::model::{
    GatewayState, HeaderMatch, HeaderMatchValue, HTTPRouteRule, HTTPRouteState, HostnameMatch, ListenerState,
    ParentRef, PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch, RouteState,
    WeightedBackend,
};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use gateway_api::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteRulesFilters,
    HttpRouteRulesFiltersRequestRedirectPathType, HttpRouteRulesFiltersRequestRedirectScheme,
    HttpRouteRulesFiltersType, HttpRouteRulesFiltersUrlRewritePathType,
    HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
};
use serde_json::Value;
use std::sync::Arc;

/// Result of reconciling a single HTTPRoute.
#[derive(Clone, Debug)]
pub struct ReconciledHTTPRoute {
    pub route_state: RouteState,
    pub parent_statuses: Vec<HTTPRouteParentStatus>,
}

/// Status conditions for a single parentRef entry.
#[derive(Clone, Debug)]
pub struct HTTPRouteParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

/// Reconcile a slice of HTTPRoute CRDs against the current Gateway set.
pub fn reconcile_httproutes(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    routes
        .iter()
        .map(|route| {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let backend_resolution = resolve_backend_refs(route, route_ns, grant_index);
            reconcile_single(route, gateways, grant_index, backend_resolution)
        })
        .collect()
}

pub fn reconcile_single(
    route: &HTTPRoute,
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
    backend_resolution: BackendResolution,
) -> ReconciledHTTPRoute {
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = route.metadata.name.as_deref().unwrap_or("");
    let generation = route.metadata.generation.unwrap_or(0);
    let route_hostnames = parse_route_hostnames(route);

    let parsed_refs = parse_parent_refs(route);
    let mut parent_refs = Vec::with_capacity(parsed_refs.len());
    let mut parent_statuses = Vec::with_capacity(parsed_refs.len());

    for parsed in &parsed_refs {
        let (resolved, mut conditions) = resolve_parent_ref(
            parsed,
            route_ns,
            generation,
            &route_hostnames,
            gateways,
            grant_index,
        );
        let status_parent_ref = resolved.clone().unwrap_or_else(|| ParentRef {
            namespace: Some(Arc::from(
                parsed.namespace.as_deref().unwrap_or(route_ns),
            )),
            name: Arc::from(parsed.name.clone()),
            section_name: parsed.section_name.clone().map(Arc::from),
        });
        let accepted = resolved.is_some();
        if let Some(pr) = resolved {
            parent_refs.push(pr);
        }

        // Merge backend ref resolution into the parent status.
        let resolved_refs = match &backend_resolution {
            BackendResolution::Ok => resolved_refs_true(generation),
            BackendResolution::RefNotPermitted(msg) => StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: msg.clone(),
                observed_generation: generation,
            },
            BackendResolution::Unsupported(msg) => StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "InvalidKind".to_string(),
                message: msg.clone(),
                observed_generation: generation,
            },
            BackendResolution::BackendNotFound(msg) => StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "BackendNotFound".to_string(),
                message: msg.clone(),
                observed_generation: generation,
            },
        };
        conditions.push(resolved_refs);

        // Programmed mirrors Accepted: the route is considered programmed when
        // it is accepted and all refs are resolved.
        let programmed = if matches!(&backend_resolution, BackendResolution::Ok) && accepted {
            StatusCondition {
                condition_type: ConditionType::Programmed,
                status: ConditionStatus::True,
                reason: "Programmed".to_string(),
                message: "Route programmed into proxy".to_string(),
                observed_generation: generation,
            }
        } else {
            StatusCondition {
                condition_type: ConditionType::Programmed,
                status: ConditionStatus::False,
                reason: "NotProgrammed".to_string(),
                message: "Route not programmed into proxy".to_string(),
                observed_generation: generation,
            }
        };
        conditions.push(programmed);

        parent_statuses.push(HTTPRouteParentStatus {
            parent_ref: status_parent_ref,
            conditions,
        });
    }

    let route_state = RouteState {
        namespace: Arc::from(route_ns),
        name: Arc::from(route_name),
        kind: Arc::from("HTTPRoute"),
        generation,
        parent_refs,
    };

    ReconciledHTTPRoute {
        route_state,
        parent_statuses,
    }
}

#[derive(Clone, Debug)]
pub enum BackendResolution {
    Ok,
    RefNotPermitted(String),
    Unsupported(String),
    BackendNotFound(String),
}

fn resolve_backend_refs(route: &HTTPRoute, route_ns: &str, grant_index: &GrantIndex) -> BackendResolution {
    let rules = match route.spec.rules.as_ref() {
        Some(r) => r,
        None => return BackendResolution::Ok,
    };

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => continue,
        };
        for backend in backends {
            let group = backend.group.as_deref().unwrap_or("");
            let kind = backend.kind.as_deref().unwrap_or("Service");
            let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);

            if !group.is_empty() || kind != "Service" {
                return BackendResolution::Unsupported(format!(
                    "backendRef group {} kind {} is not supported",
                    group, kind
                ));
            }

            let permitted = grant_index.is_permitted(
                route_ns,
                "gateway.networking.k8s.io",
                "HTTPRoute",
                target_ns,
                group,
                kind,
                &backend.name,
            );

            if !permitted {
                return BackendResolution::RefNotPermitted(format!(
                    "cross-namespace backend reference from {} to {}/{} is not permitted",
                    route_ns, target_ns, backend.name
                ));
            }
        }
    }

    BackendResolution::Ok
}

/// Async variant of [`resolve_backend_refs`] that also validates that
/// referenced backend Services exist in the cluster.
pub async fn resolve_backend_refs_async(
    client: &kube::Client,
    route: &HTTPRoute,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.spec.rules.as_ref() {
        Some(r) => r,
        None => return BackendResolution::Ok,
    };

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => continue,
        };
        for backend in backends {
            let group = backend.group.as_deref().unwrap_or("");
            let kind = backend.kind.as_deref().unwrap_or("Service");
            let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);

            if !group.is_empty() || kind != "Service" {
                return BackendResolution::Unsupported(format!(
                    "backendRef group {} kind {} is not supported",
                    group, kind
                ));
            }

            let permitted = grant_index.is_permitted(
                route_ns,
                "gateway.networking.k8s.io",
                "HTTPRoute",
                target_ns,
                group,
                kind,
                &backend.name,
            );

            if !permitted {
                return BackendResolution::RefNotPermitted(format!(
                    "cross-namespace backend reference from {} to {}/{} is not permitted",
                    route_ns, target_ns, backend.name
                ));
            }

            let services: kube::Api<k8s_openapi::api::core::v1::Service> =
                kube::Api::namespaced(client.clone(), target_ns);
            if services.get(&backend.name).await.is_err() {
                return BackendResolution::BackendNotFound(format!(
                    "backend Service {}/{} not found",
                    target_ns, backend.name
                ));
            }
        }
    }

    BackendResolution::Ok
}

#[derive(Clone, Debug)]
struct ParsedParentRef {
    group: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    section_name: Option<String>,
    port: Option<i32>,
}

fn parse_parent_refs(route: &HTTPRoute) -> Vec<ParsedParentRef> {
    route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_parent_ref).collect())
        .unwrap_or_default()
}

fn parse_parent_ref(value: &HttpRouteParentRefs) -> Option<ParsedParentRef> {
    Some(ParsedParentRef {
        group: value
            .group
            .as_deref()
            .unwrap_or("gateway.networking.k8s.io")
            .to_string(),
        kind: value
            .kind
            .as_deref()
            .unwrap_or("Gateway")
            .to_string(),
        namespace: value.namespace.clone(),
        name: value.name.clone(),
        section_name: value.section_name.clone(),
        port: value.port,
    })
}

/// Parse hostnames from an HTTPRoute spec into the model's HostnameMatch types.
fn parse_route_hostnames(route: &HTTPRoute) -> Vec<crate::gateway::model::HostnameMatch> {
    use crate::gateway::model::HostnameMatch;
    use std::sync::Arc;
    route
        .spec
        .hostnames
        .as_ref()
        .map(|h| {
            h.iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_parent_ref(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    // Only Gateway parentRefs are supported in T1.
    if parsed.group != "gateway.networking.k8s.io" || parsed.kind != "Gateway" {
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "UnsupportedValue".to_string(),
            message: format!(
                "parentRef group {} kind {} is not supported",
                parsed.group, parsed.kind
            ),
            observed_generation,
        }];
        return (None, conditions);
    }

    // Check cross-namespace permission.
    let permitted = grant_index.is_permitted(
        route_ns,
        "gateway.networking.k8s.io",
        "HTTPRoute",
        target_ns,
        &parsed.group,
        &parsed.kind,
        &parsed.name,
    );

    if !permitted {
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "RefNotPermitted".to_string(),
            message: format!(
                "cross-namespace reference from {route_ns} to Gateway {}/{} is not permitted",
                target_ns, parsed.name
            ),
            observed_generation,
        }];
        return (None, conditions);
    }

    // Find the gateway.
    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "NoMatchingParent".to_string(),
            message: format!("Gateway {}/{} not found", target_ns, parsed.name),
            observed_generation,
        }];
        return (None, conditions);
    };

    // Find listeners that match this parentRef (by sectionName and/or port).
    let matching_listeners: Vec<&ListenerState> = gateway
        .listeners
        .iter()
        .filter(|l| {
            let section_matches = parsed
                .section_name
                .as_deref()
                .map(|s| s == l.name.as_ref())
                .unwrap_or(true);
            let port_matches = parsed
                .port
                .map(|p| p == l.port as i32)
                .unwrap_or(true);
            section_matches && port_matches
        })
        .collect();

    // If sectionName is specified, the listener must exist.
    if let Some(ref section) = parsed.section_name {
        let listener_exists = gateway
            .listeners
            .iter()
            .any(|l| l.name.as_ref() == section.as_str());
        if !listener_exists {
            let conditions = vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingParent".to_string(),
                message: format!(
                    "listener {} not found on Gateway {}/{}",
                    section, target_ns, parsed.name
                ),
                observed_generation,
            }];
            return (None, conditions);
        }
    }

    // If port is specified but no listener matches, reject.
    if parsed.port.is_some() && matching_listeners.is_empty() {
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "NoMatchingParent".to_string(),
            message: format!(
                "no listener matching port {} on Gateway {}/{}",
                parsed.port.unwrap(),
                target_ns,
                parsed.name
            ),
            observed_generation,
        }];
        return (None, conditions);
    }

    // Check hostname intersection: the route is accepted if at least one
    // matching listener accepts it by hostname.
    let hostname_accepted = route_hostnames.is_empty()
        || matching_listeners.iter().any(|l| {
            let intersected =
                crate::gateway::translate::intersect_hostnames(route_hostnames, l.hostname.as_deref());
            !intersected.is_empty()
        });

    if !hostname_accepted {
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "NoMatchingListenerHostname".to_string(),
            message: "no matching listener hostname".to_string(),
            observed_generation,
        }];
        return (None, conditions);
    }

    // Parent ref is accepted. The namespace is always included in status
    // parentRef because Gateway API CRDs require it as a string (not null).
    let parent_ref = ParentRef {
        namespace: Some(Arc::from(target_ns)),
        name: Arc::from(parsed.name.clone()),
        section_name: parsed.section_name.as_ref().map(|s| Arc::from(s.as_str())),
    };

    let conditions = vec![StatusCondition {
        condition_type: ConditionType::Accepted,
        status: ConditionStatus::True,
        reason: "Accepted".to_string(),
        message: "Route accepted by parent".to_string(),
        observed_generation,
    }];

    (Some(parent_ref), conditions)
}

/// Parse an HTTPRoute CRD into the full `HTTPRouteState` model,
/// including hostnames and rules extracted from the raw spec.
pub fn parse_httproute_state(route: &HTTPRoute) -> HTTPRouteState {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let hostnames: Vec<HostnameMatch> = route
        .spec
        .hostnames
        .as_ref()
        .map(|h| {
            h.iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let route_ns_str: &str = ns.as_ref();
    let rules: Vec<HTTPRouteRule> = route
        .spec
        .rules
        .as_ref()
        .map(|r| r.iter().filter_map(|rule| parse_rule(rule, route_ns_str)).collect())
        .unwrap_or_default();

    HTTPRouteState {
        namespace: ns,
        name,
        generation,
        hostnames,
        rules,
        parent_refs: vec![], // filled by reconcile_single
    }
}

fn parse_rule(value: &HttpRouteRules, route_ns: &str) -> Option<HTTPRouteRule> {
    let matches: Vec<RouteMatch> = value
        .matches
        .as_ref()
        .map(|arr| arr.iter().filter_map(parse_match).collect())
        .unwrap_or_default();

    let backends: Vec<WeightedBackend> = value
        .backend_refs
        .as_ref()
        .map(|arr| arr.iter().filter_map(|b| parse_backend_ref(b, route_ns)).collect())
        .unwrap_or_default();

    let filters: Vec<RouteFilter> = value
        .filters
        .as_ref()
        .map(|arr| arr.iter().flat_map(|f| parse_filter(f, route_ns)).collect())
        .unwrap_or_default();

    let timeout_secs = value.timeouts.as_ref().and_then(|t| {
        t.backend_request.as_ref().and_then(|dur| {
            dur.parse::<gateway_api::Duration>().ok().map(|d| d.as_secs())
        })
    });

    Some(HTTPRouteRule {
        matches,
        backends,
        filters,
        timeout_secs,
    })
}

fn parse_match(value: &HttpRouteRulesMatches) -> Option<RouteMatch> {
    let path = value.path.as_ref().and_then(parse_path_match);
    let method = value
        .method
        .as_ref()
        .map(|m| Arc::from(method_to_str(m)) as Arc<str>);
    let headers = value
        .headers
        .as_ref()
        .map(|arr| arr.iter().filter_map(parse_header_match).collect())
        .unwrap_or_default();
    let query_params = value
        .query_params
        .as_ref()
        .map(|arr| arr.iter().filter_map(parse_query_param_match).collect())
        .unwrap_or_default();
    Some(RouteMatch {
        path,
        headers,
        query_params,
        method,
    })
}

fn parse_header_match(value: &HttpRouteRulesMatchesHeaders) -> Option<HeaderMatch> {
    use gateway_api::httproutes::HttpRouteRulesMatchesHeadersType;
    let value_match = match value.r#type.as_ref().unwrap_or(&HttpRouteRulesMatchesHeadersType::Exact) {
        HttpRouteRulesMatchesHeadersType::Exact => HeaderMatchValue::Exact(Arc::from(value.value.as_str())),
        HttpRouteRulesMatchesHeadersType::RegularExpression => HeaderMatchValue::Regex(Arc::from(value.value.as_str())),
    };
    Some(HeaderMatch {
        name: Arc::from(value.name.as_str()),
        value: value_match,
    })
}

fn parse_query_param_match(value: &HttpRouteRulesMatchesQueryParams) -> Option<QueryParamMatch> {
    use gateway_api::httproutes::HttpRouteRulesMatchesQueryParamsType;
    let value_match = match value.r#type.as_ref().unwrap_or(&HttpRouteRulesMatchesQueryParamsType::Exact) {
        HttpRouteRulesMatchesQueryParamsType::Exact => QueryParamMatchValue::Exact(Arc::from(value.value.as_str())),
        HttpRouteRulesMatchesQueryParamsType::RegularExpression => QueryParamMatchValue::Regex(Arc::from(value.value.as_str())),
    };
    Some(QueryParamMatch {
        name: Arc::from(value.name.as_str()),
        value: value_match,
    })
}

fn method_to_str(method: &HttpRouteRulesMatchesMethod) -> &'static str {
    match method {
        HttpRouteRulesMatchesMethod::Get => "GET",
        HttpRouteRulesMatchesMethod::Head => "HEAD",
        HttpRouteRulesMatchesMethod::Post => "POST",
        HttpRouteRulesMatchesMethod::Put => "PUT",
        HttpRouteRulesMatchesMethod::Delete => "DELETE",
        HttpRouteRulesMatchesMethod::Connect => "CONNECT",
        HttpRouteRulesMatchesMethod::Options => "OPTIONS",
        HttpRouteRulesMatchesMethod::Trace => "TRACE",
        HttpRouteRulesMatchesMethod::Patch => "PATCH",
    }
}

fn parse_path_match(value: &HttpRouteRulesMatchesPath) -> Option<PathMatch> {
    let typ = value.r#type.as_ref().unwrap_or(&HttpRouteRulesMatchesPathType::PathPrefix);
    let val = value.value.as_deref().unwrap_or("/");
    Some(match typ {
        HttpRouteRulesMatchesPathType::Exact => PathMatch::Exact(Arc::from(val)),
        HttpRouteRulesMatchesPathType::PathPrefix => PathMatch::Prefix(Arc::from(val)),
        HttpRouteRulesMatchesPathType::RegularExpression => PathMatch::Regex(Arc::from(val)),
    })
}

fn parse_backend_ref(value: &HttpRouteRulesBackendRefs, route_ns: &str) -> Option<WeightedBackend> {
    let name = &value.name;
    let ns = value.namespace.as_deref().unwrap_or(route_ns);
    let port = value.port.unwrap_or(80);
    let weight = value.weight.unwrap_or(1) as u32;

    // Build a cluster-internal service address.  Always use the FQDN so that
    // the proxy resolves the backend in the route's namespace regardless of
    // which namespace the proxy pod itself runs in.
    let backend = format!("{}.{}.svc.cluster.local.:{}", name, ns, port);
    Some(WeightedBackend {
        backend: Arc::from(backend),
        weight,
    })
}

fn parse_filter(value: &HttpRouteRulesFilters, route_ns: &str) -> Vec<RouteFilter> {
    match value.r#type {
        HttpRouteRulesFiltersType::UrlRewrite => {
            let Some(url_rewrite) = value.url_rewrite.as_ref() else { return vec![] };
            let hostname = url_rewrite.hostname.as_deref().map(Arc::from);
            let path = url_rewrite.path.as_ref();
            let path_rewrite = match path {
                Some(p) => match p.r#type {
                    HttpRouteRulesFiltersUrlRewritePathType::ReplacePrefixMatch => {
                        Some(PathRewrite::PrefixReplace {
                            prefix: Arc::from("/"),
                            replacement: Arc::from(p.replace_prefix_match.as_deref().unwrap_or("")),
                        })
                    }
                    HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath => {
                        p.replace_full_path.as_deref().map(|s| PathRewrite::FullReplace(Arc::from(s)))
                    }
                },
                None => None,
            };
            if hostname.is_none() && path_rewrite.is_none() {
                return vec![];
            }
            vec![RouteFilter::UrlRewrite {
                hostname,
                path: path_rewrite.unwrap_or(PathRewrite::FullReplace(Arc::from(""))),
            }]
        }
        HttpRouteRulesFiltersType::RequestHeaderModifier => {
            let Some(modifier) = value.request_header_modifier.as_ref() else { return vec![] };
            let mut out = Vec::new();
            if let Some(set) = &modifier.set {
                for h in set {
                    out.push(RouteFilter::RequestHeaderSet {
                        name: Arc::from(h.name.as_str()),
                        value: Arc::from(h.value.as_str()),
                    });
                }
            }
            if let Some(add) = &modifier.add {
                for h in add {
                    out.push(RouteFilter::RequestHeaderAdd {
                        name: Arc::from(h.name.as_str()),
                        value: Arc::from(h.value.as_str()),
                    });
                }
            }
            if let Some(remove) = &modifier.remove {
                for h in remove {
                    out.push(RouteFilter::RequestHeaderRemove {
                        name: Arc::from(h.as_str()),
                    });
                }
            }
            out
        }
        HttpRouteRulesFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else { return vec![] };
            let mut out = Vec::new();
            if let Some(set) = &modifier.set {
                for h in set {
                    out.push(RouteFilter::ResponseHeaderSet {
                        name: Arc::from(h.name.as_str()),
                        value: Arc::from(h.value.as_str()),
                    });
                }
            }
            if let Some(add) = &modifier.add {
                for h in add {
                    out.push(RouteFilter::ResponseHeaderAdd {
                        name: Arc::from(h.name.as_str()),
                        value: Arc::from(h.value.as_str()),
                    });
                }
            }
            if let Some(remove) = &modifier.remove {
                for h in remove {
                    out.push(RouteFilter::ResponseHeaderRemove {
                        name: Arc::from(h.as_str()),
                    });
                }
            }
            out
        }
        HttpRouteRulesFiltersType::RequestRedirect => {
            let Some(redirect) = value.request_redirect.as_ref() else { return vec![] };
            let scheme = redirect.scheme.as_ref().map(|s| match s {
                HttpRouteRulesFiltersRequestRedirectScheme::Http => Arc::from("http"),
                HttpRouteRulesFiltersRequestRedirectScheme::Https => Arc::from("https"),
            });
            let hostname = redirect.hostname.as_ref().map(|s| Arc::from(s.as_str()));
            let port = redirect.port.map(|p| p as u16);
            let status_code = redirect.status_code.unwrap_or(302) as u16;
            let path = redirect.path.as_ref().and_then(parse_redirect_path);
            vec![RouteFilter::RequestRedirect {
                scheme,
                hostname,
                path,
                port,
                status_code,
            }]
        }
        HttpRouteRulesFiltersType::RequestMirror => {
            let Some(mirror) = value.request_mirror.as_ref() else { return vec![] };
            let name = &mirror.backend_ref.name;
            let ns = mirror.backend_ref.namespace.as_deref().unwrap_or(route_ns);
            let port = mirror.backend_ref.port.unwrap_or(80);
            let backend = format!("{}.{}.svc.cluster.local.:{}", name, ns, port);
            vec![RouteFilter::RequestMirror {
                backend: Arc::from(backend),
            }]
        }
        HttpRouteRulesFiltersType::Cors => {
            let Some(cors) = value.cors.as_ref() else { return vec![] };
            let allow_origins = cors.allow_origins.as_ref().map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect()).unwrap_or_default();
            let allow_methods = cors.allow_methods.as_ref().map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect()).unwrap_or_default();
            let allow_headers = cors.allow_headers.as_ref().map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect()).unwrap_or_default();
            let expose_headers = cors.expose_headers.as_ref().map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect()).unwrap_or_default();
            vec![RouteFilter::Cors {
                allow_origins,
                allow_methods,
                allow_headers,
                expose_headers,
                max_age: cors.max_age,
                allow_credentials: cors.allow_credentials.unwrap_or(false),
            }]
        }
        _ => vec![],
    }
}

fn parse_redirect_path(value: &gateway_api::httproutes::HttpRouteRulesFiltersRequestRedirectPath) -> Option<PathRewrite> {
    match value.r#type {
        HttpRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath => value
            .replace_full_path
            .as_ref()
            .map(|s| PathRewrite::FullReplace(Arc::from(s.as_str()))),
        HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch => value
            .replace_prefix_match
            .as_ref()
            .map(|s| {
                PathRewrite::PrefixReplace {
                    prefix: Arc::from("/"),
                    replacement: Arc::from(s.as_str()),
                }
            }),
    }
}

fn resolved_refs_true(observed_generation: i64) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All references resolved".to_string(),
        observed_generation,
    }
}

// ---------------------------------------------------------------------------
// HTTPRoute controller (kube::runtime::Controller)
// ---------------------------------------------------------------------------

use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Context shared across HTTPRoute reconcile invocations.
#[derive(Clone)]
pub struct HTTPRouteContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Reconcile a single HTTPRoute: resolve parentRefs, compute status,
/// and patch `.status.parents[]` when leader.
pub async fn reconcile_httproute(
    route: Arc<HTTPRoute>,
    ctx: Arc<HTTPRouteContext>,
) -> Result<Action, kube::Error> {
    let ns = route.metadata.namespace.clone().unwrap_or_default();
    let name = route.metadata.name.clone().unwrap_or_default();
    let _observed_generation = route.metadata.generation.unwrap_or(0);

    // Fetch all Gateways and ReferenceGrants for parentRef resolution.
    // In T1 we do a fresh list per reconcile; a shared cache can be added later.
    let gateways: Api<crate::gateway::api::Gateway> = Api::all(ctx.client.clone());
    let grants: Api<crate::gateway::api::ReferenceGrant> = Api::all(ctx.client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for HTTPRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for HTTPRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();

    let grant_states = crate::gateway::reconcile::refgrant::reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states);

    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let backend_resolution = resolve_backend_refs_async(&ctx.client, &route, route_ns, &grant_index).await;
    let reconciled = reconcile_single(&route, &gateway_states, &grant_index, backend_resolution);

    if ctx.is_leader.load(Ordering::Relaxed) {
        let parents: Vec<Value> = reconciled
            .parent_statuses
            .iter()
            .map(|ps| {
                let conditions: Vec<Value> = ps
                    .conditions
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "type": match c.condition_type {
                                ConditionType::Accepted => "Accepted",
                                ConditionType::Programmed => "Programmed",
                                ConditionType::ResolvedRefs => "ResolvedRefs",
                                ConditionType::Conflicted => "Conflicted",
                                ConditionType::Poison => "Poison",
                                ConditionType::NoMatchingParent => "NoMatchingParent",
                                ConditionType::RefNotPermitted => "RefNotPermitted",
                                ConditionType::UnsupportedFeature => "UnsupportedFeature",
                            },
                            "status": match c.status {
                                ConditionStatus::True => "True",
                                ConditionStatus::False => "False",
                                ConditionStatus::Unknown => "Unknown",
                            },
                            "reason": c.reason,
                            "message": c.message,
                            "observedGeneration": c.observed_generation,
                            "lastTransitionTime": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        })
                    })
                    .collect();

                let mut parent_ref = serde_json::Map::new();
                parent_ref.insert("group".into(), "gateway.networking.k8s.io".into());
                parent_ref.insert("kind".into(), "Gateway".into());
                parent_ref.insert("name".into(), serde_json::json!(ps.parent_ref.name.as_ref()));
                parent_ref.insert("namespace".into(), serde_json::json!(ps.parent_ref.namespace.as_ref()));
                if let Some(section) = ps.parent_ref.section_name.as_deref() {
                    parent_ref.insert("sectionName".into(), serde_json::json!(section));
                }
                serde_json::json!({
                    "parentRef": parent_ref,
                    "controllerName": crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME,
                    "conditions": conditions,
                })
            })
            .collect();

        let new_status = serde_json::json!({ "parents": parents });

        let old_status_json = route.status.as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

        if old_stripped == new_stripped {
            tracing::debug!(name, namespace = ns, "HTTPRoute status unchanged, skipping patch");
        } else {
            let patch_body = serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "HTTPRoute",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "status": new_status,
            });

            let api: Api<HTTPRoute> = Api::namespaced(ctx.client.clone(), &ns);
            let pp = PatchParams::apply("sunbeam-proxy");
            if let Err(e) = api.patch_status(&name, &pp, &Patch::Apply(&patch_body)).await {
                tracing::warn!(error = %e, name, namespace = ns, "HTTPRoute status patch failed");
            } else {
                tracing::debug!(name, namespace = ns, "HTTPRoute status patched");
            }
        }
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy_httproute(
    _route: Arc<HTTPRoute>,
    _error: &kube::Error,
    _ctx: Arc<HTTPRouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Start the HTTPRoute controller.
pub fn run_httproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(HTTPRouteContext {
        client: client.clone(),
        is_leader,
    });
    let httproutes = Api::<HTTPRoute>::all(client);
    tokio::spawn(async move {
        Controller::new(httproutes, kube::runtime::watcher::Config::default())
            .run(reconcile_httproute, error_policy_httproute, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("HTTPRoute controller error: {e}"),
                }
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{GrantSubject, ListenerState, ReferenceGrantState};

    fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
            }],
        }
    }

    fn sample_route(parent_refs: Vec<Value>) -> HTTPRoute {
        let json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {
                "name": "route-1",
                "namespace": "default",
                "generation": 1
            },
            "spec": {
                "parentRefs": parent_refs
            }
        });
        serde_json::from_value(json).expect("valid HTTPRoute")
    }

    #[test]
    fn accepted_when_parent_matches_same_namespace() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.route_state.parent_refs.len(), 1);

        let accepted = result.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        assert_eq!(accepted.reason, "Accepted");

        let programmed = result.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Programmed))
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::True);
        assert_eq!(programmed.reason, "Programmed");
    }

    #[test]
    fn programmed_false_when_not_accepted() {
        let route = sample_route(vec![serde_json::json!({
            "name": "missing-gw"
        })]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let programmed = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Programmed))
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
        assert_eq!(programmed.reason, "NotProgrammed");
    }

    #[test]
    fn denied_when_gateway_not_found() {
        let route = sample_route(vec![serde_json::json!({
            "name": "missing-gw"
        })]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn denied_when_listener_not_found() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "sectionName": "https"
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn cross_namespace_requires_grant() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "RefNotPermitted");
    }

    #[test]
    fn cross_namespace_accepted_with_grant() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant = ReferenceGrantState {
            namespace: Arc::from("prod"),
            name: Arc::from("grant-1"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: None,
            }],
        };
        let grant_index = GrantIndex::new(vec![grant]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn unsupported_parent_kind_rejected() {
        let route = sample_route(vec![serde_json::json!({
            "group": "example.com",
            "kind": "Foo",
            "name": "foo-1"
        })]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "UnsupportedValue");
    }

    #[test]
    fn route_without_parent_refs_has_empty_parents() {
        let route = sample_route(vec![]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results[0].route_state.parent_refs.len(), 0);
        assert_eq!(results[0].parent_statuses.len(), 0);
    }

    #[test]
    fn multiple_parent_refs_mixed_results() {
        let route = sample_route(vec![
            serde_json::json!({"name": "gw-1", "sectionName": "http"}),
            serde_json::json!({"name": "missing-gw"}),
        ]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results[0].route_state.parent_refs.len(), 1);
        assert_eq!(results[0].parent_statuses.len(), 2);

        let first = &results[0].parent_statuses[0];
        let first_accepted = first
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(first_accepted.status, ConditionStatus::True);

        let second = &results[0].parent_statuses[1];
        let second_accepted = second
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(second_accepted.status, ConditionStatus::False);
    }

    #[test]
    fn resolved_refs_true_when_no_backend_refs() {
        let route = sample_route(vec![serde_json::json!({"name": "missing-gw"})]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::True);
    }

    fn route_with_backends(parent_refs: Vec<serde_json::Value>, backends: Vec<serde_json::Value>) -> HTTPRoute {
        let json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": {
                "name": "route-1",
                "namespace": "default",
                "generation": 1
            },
            "spec": {
                "parentRefs": parent_refs,
                "rules": [{ "backendRefs": backends }]
            }
        });
        serde_json::from_value(json).expect("valid HTTPRoute")
    }

    #[test]
    fn resolved_refs_true_for_same_namespace_service() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
            vec![serde_json::json!({"name": "svc-1", "port": 80})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::True);
        assert_eq!(resolved.reason, "ResolvedRefs");
    }

    #[test]
    fn resolved_refs_false_for_cross_namespace_backend_without_grant() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
            vec![serde_json::json!({"namespace": "prod", "name": "svc-1", "port": 80})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::False);
        assert_eq!(resolved.reason, "RefNotPermitted");
    }

    #[test]
    fn resolved_refs_true_for_cross_namespace_backend_with_grant() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
            vec![serde_json::json!({"namespace": "prod", "name": "svc-1", "port": 80})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant = ReferenceGrantState {
            namespace: Arc::from("prod"),
            name: Arc::from("allow-default"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from(""),
                kind: Arc::from("Service"),
                namespace: None,
                name: None,
            }],
        };
        let grant_index = GrantIndex::new(vec![grant]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::True);
    }

    #[test]
    fn resolved_refs_false_for_unsupported_backend_kind() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
            vec![serde_json::json!({"group": "example.com", "kind": "Foo", "name": "foo-1"})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::False);
        assert_eq!(resolved.reason, "InvalidKind");
    }

    fn route_from_json(json: serde_json::Value) -> HTTPRoute {
        serde_json::from_value(json).expect("valid HTTPRoute")
    }

    #[test]
    fn parse_httproute_state_populates_hostnames_and_rules() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 2 },
            "spec": {
                "hostnames": ["example.com", "*.wildcard.test"],
                "rules": [
                    {
                        "matches": [
                            {
                                "path": { "type": "PathPrefix", "value": "/api" },
                                "method": "GET"
                            }
                        ],
                        "backendRefs": [
                            { "name": "svc-1", "port": 8080, "weight": 3 }
                        ]
                    }
                ]
            }
        }));

        let state = parse_httproute_state(&route);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "route-1");
        assert_eq!(state.generation, 2);
        assert_eq!(state.hostnames.len(), 2);
        assert_eq!(state.hostnames[0], HostnameMatch::Exact(Arc::from("example.com")));
        assert_eq!(state.hostnames[1], HostnameMatch::Wildcard(Arc::from("wildcard.test")));
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].matches.len(), 1);
        assert_eq!(state.rules[0].matches[0].path, Some(PathMatch::Prefix(Arc::from("/api"))));
        assert_eq!(state.rules[0].matches[0].method.as_deref(), Some("GET"));
        assert_eq!(state.rules[0].backends.len(), 1);
        assert_eq!(state.rules[0].backends[0].backend.as_ref(), "svc-1.default.svc.cluster.local.:8080");
        assert_eq!(state.rules[0].backends[0].weight, 3);
    }

    #[test]
    fn parse_httproute_state_empty_spec() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "empty", "namespace": "ns" },
            "spec": {}
        }));
        let state = parse_httproute_state(&route);
        assert_eq!(state.namespace.as_ref(), "ns");
        assert!(state.hostnames.is_empty());
        assert!(state.rules.is_empty());
        assert!(state.parent_refs.is_empty());
    }

    #[test]
    fn parse_path_match_all_types() {
        let exact = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{"matches": [{"path": {"type": "Exact", "value": "/foo"}}]}]
            }
        }));
        let prefix = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/bar"}}]}]
            }
        }));
        let regex = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{"matches": [{"path": {"type": "RegularExpression", "value": "^/baz$"}}]}]
            }
        }));
        let default_type = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{"matches": [{"path": {"value": "/ defaulted"}}]}]
            }
        }));

        assert_eq!(parse_httproute_state(&exact).rules[0].matches[0].path, Some(PathMatch::Exact(Arc::from("/foo"))));
        assert_eq!(parse_httproute_state(&prefix).rules[0].matches[0].path, Some(PathMatch::Prefix(Arc::from("/bar"))));
        assert_eq!(parse_httproute_state(&regex).rules[0].matches[0].path, Some(PathMatch::Regex(Arc::from("^/baz$"))));
        assert_eq!(parse_httproute_state(&default_type).rules[0].matches[0].path, Some(PathMatch::Prefix(Arc::from("/ defaulted"))));
    }

    #[test]
    fn parse_method_all_variants() {
        for (method, expected) in [
            ("GET", "GET"),
            ("HEAD", "HEAD"),
            ("POST", "POST"),
            ("PUT", "PUT"),
            ("DELETE", "DELETE"),
            ("CONNECT", "CONNECT"),
            ("OPTIONS", "OPTIONS"),
            ("TRACE", "TRACE"),
            ("PATCH", "PATCH"),
        ] {
            let route = route_from_json(serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "HTTPRoute",
                "metadata": { "name": "r" },
                "spec": {
                    "rules": [{"matches": [{"method": method}]}]
                }
            }));
            assert_eq!(
                parse_httproute_state(&route).rules[0].matches[0].method.as_deref(),
                Some(expected),
                "method {method}"
            );
        }
    }

    #[test]
    fn parse_backend_ref_defaults() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "rules": [{"backendRefs": [{"name": "svc"}]}]
            }
        }));
        let backend = &parse_httproute_state(&route).rules[0].backends[0];
        assert_eq!(backend.backend.as_ref(), "svc.default.svc.cluster.local.:80");
        assert_eq!(backend.weight, 1);
    }

    #[test]
    fn parse_backend_ref_cross_namespace_uses_fqdn() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "rules": [{"backendRefs": [{"name": "svc", "namespace": "other", "port": 9090}]}]
            }
        }));
        let backend = &parse_httproute_state(&route).rules[0].backends[0];
        assert_eq!(backend.backend.as_ref(), "svc.other.svc.cluster.local.:9090");
        assert_eq!(backend.weight, 1);
    }

    #[test]
    fn parse_url_rewrite_filter_replace_prefix_match() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "URLRewrite",
                        "urlRewrite": {
                            "path": {
                                "type": "ReplacePrefixMatch",
                                "replacePrefixMatch": "/v2"
                            }
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::UrlRewrite {
                hostname: None,
                path: PathRewrite::PrefixReplace {
                    prefix: Arc::from("/"),
                    replacement: Arc::from("/v2"),
                },
            }
        );
    }

    #[test]
    fn parse_url_rewrite_filter_replace_full_path() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "URLRewrite",
                        "urlRewrite": {
                            "path": {
                                "type": "ReplaceFullPath",
                                "replaceFullPath": "/new"
                            }
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::UrlRewrite {
                hostname: None,
                path: PathRewrite::FullReplace(Arc::from("/new")),
            }
        );
    }

    #[test]
    fn parse_request_header_modifier_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "RequestHeaderModifier",
                        "requestHeaderModifier": {
                            "set": [{"name": "X-Custom", "value": "val"}]
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::RequestHeaderSet {
                name: Arc::from("X-Custom"),
                value: Arc::from("val"),
            }
        );
    }

    #[test]
    fn parse_response_header_modifier_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "ResponseHeaderModifier",
                        "responseHeaderModifier": {
                            "set": [{"name": "X-Out", "value": "out"}]
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::ResponseHeaderSet {
                name: Arc::from("X-Out"),
                value: Arc::from("out"),
            }
        );
    }

    #[test]
    fn parse_request_redirect_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "RequestRedirect",
                        "requestRedirect": {
                            "scheme": "https",
                            "hostname": "new.example.com",
                            "port": 8443,
                            "statusCode": 301,
                            "path": {
                                "type": "ReplaceFullPath",
                                "replaceFullPath": "/redirected"
                            }
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::RequestRedirect {
                scheme: Some(Arc::from("https")),
                hostname: Some(Arc::from("new.example.com")),
                port: Some(8443),
                status_code: 301,
                path: Some(PathRewrite::FullReplace(Arc::from("/redirected"))),
            }
        );
    }

    #[test]
    fn parse_request_redirect_filter_defaults() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{"type": "RequestRedirect", "requestRedirect": {}}]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::RequestRedirect {
                scheme: None,
                hostname: None,
                port: None,
                status_code: 302,
                path: None,
            }
        );
    }

    #[test]
    fn parse_request_redirect_replace_prefix() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "RequestRedirect",
                        "requestRedirect": {
                            "path": {
                                "type": "ReplacePrefixMatch",
                                "replacePrefixMatch": "/new-prefix"
                            }
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        match filter {
            RouteFilter::RequestRedirect { path: Some(PathRewrite::PrefixReplace { prefix, replacement }), .. } => {
                assert_eq!(prefix.as_ref(), "/");
                assert_eq!(replacement.as_ref(), "/new-prefix");
            }
            _ => panic!("unexpected filter: {filter:?}"),
        }
    }

    #[test]
    fn parse_unknown_filter_type_is_skipped() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "ExtensionRef",
                        "extensionRef": {
                            "group": "example.com",
                            "kind": "Foo",
                            "name": "bar"
                        }
                    }]
                }]
            }
        }));
        assert!(parse_httproute_state(&route).rules[0].filters.is_empty());
    }
}
