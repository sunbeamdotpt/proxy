// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPRoute reconciler.
//!
//! Watches HTTPRoute resources, resolves parentRefs against Gateway
//! listeners, computes `Accepted` / `ResolvedRefs` conditions on
//! `.status.parents[]`, and emits `RouteState` for the reconciled view.

use crate::gateway::api::HTTPRoute;
use crate::gateway::model::{
    AllowedRoutes, Fraction, GatewayState, HTTPRouteRule, HTTPRouteState, HeaderMatch,
    HeaderMatchValue, HostnameMatch, ListenerSetState, ListenerState, NamespaceFrom, ParentRef,
    PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch,
    RouteNamespaces, RouteState, WeightedBackend,
};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use gateway_api::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersRequestRedirectPathType, HttpRouteRulesFiltersRequestRedirectScheme,
    HttpRouteRulesFiltersType, HttpRouteRulesFiltersUrlRewritePathType, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of reconciling a single HTTPRoute.
#[derive(Clone, Debug)]
pub struct ReconciledHTTPRoute {
    pub route_state: RouteState,
    pub parent_statuses: Vec<HTTPRouteParentStatus>,
    /// True only when the route is accepted and all backend references resolve.
    pub programmed: bool,
}

/// Status conditions for a single parentRef entry.
#[derive(Clone, Debug)]
pub struct HTTPRouteParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

/// Reconcile a slice of HTTPRoute CRDs against the current Gateway set.
///
/// This is the test-friendly entry point that uses default listener
/// permissions (same-namespace, HTTPRoute allowed) and no namespace labels.
pub fn reconcile_httproutes(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    reconcile_httproutes_with_context(
        routes,
        gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        grant_index,
    )
}

/// Reconcile HTTPRoutes with full listener permission context.
pub fn reconcile_httproutes_with_context(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    routes
        .iter()
        .map(|route| {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let backend_resolution = resolve_backend_refs(route, route_ns, grant_index);
            reconcile_single(
                route,
                gateways,
                listener_sets,
                namespace_labels,
                listener_allowed,
                listener_set_allowed,
                grant_index,
                backend_resolution,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_single(
    route: &HTTPRoute,
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    _grant_index: &GrantIndex,
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
            listener_sets,
            namespace_labels,
            listener_allowed,
            listener_set_allowed,
            "HTTPRoute",
        );
        let status_parent_ref = resolved.clone().unwrap_or_else(|| ParentRef {
            group: Arc::from(parsed.group.clone()),
            kind: Arc::from(parsed.kind.clone()),
            namespace: Some(Arc::from(parsed.namespace.as_deref().unwrap_or(route_ns))),
            name: Arc::from(parsed.name.clone()),
            section_name: parsed.section_name.clone().map(Arc::from),
            port: parsed.port.map(|p| p as u16),
        });
        let accepted = resolved.is_some();
        if let Some(pr) = resolved {
            parent_refs.push(pr);
        }

        // Merge backend ref resolution into the parent status.
        let resolved_refs = match &backend_resolution.overall {
            BackendResolutionStatus::Ok => resolved_refs_true(generation),
            BackendResolutionStatus::RefNotPermitted(msg) => StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: msg.clone(),
                observed_generation: generation,
            },
            BackendResolutionStatus::Unsupported(msg) => StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "InvalidKind".to_string(),
                message: msg.clone(),
                observed_generation: generation,
            },
            BackendResolutionStatus::BackendNotFound(msg) => StatusCondition {
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
        let programmed =
            if matches!(&backend_resolution.overall, BackendResolutionStatus::Ok) && accepted {
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
    let programmed = !route_state.parent_refs.is_empty()
        && matches!(backend_resolution.overall, BackendResolutionStatus::Ok);

    ReconciledHTTPRoute {
        route_state,
        parent_statuses,
        programmed,
    }
}

#[derive(Clone, Debug)]
pub enum BackendResolutionStatus {
    Ok,
    RefNotPermitted(String),
    Unsupported(String),
    BackendNotFound(String),
}

/// Per-rule backend resolution result.
#[derive(Clone, Debug)]
pub struct RuleBackendResolution {
    pub ok: bool,
    pub message: String,
}

/// Backend-ref resolution for an HTTPRoute. `overall` drives status conditions;
/// `rules` is parallel to `route.spec.rules` and drives per-rule programming.
#[derive(Clone, Debug)]
pub struct BackendResolution {
    pub overall: BackendResolutionStatus,
    pub rules: Vec<RuleBackendResolution>,
}

impl BackendResolution {
    pub fn ok() -> Self {
        Self {
            overall: BackendResolutionStatus::Ok,
            rules: Vec::new(),
        }
    }
}

fn check_backend_permitted(
    backend: &HttpRouteRulesBackendRefs,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> Result<(), BackendResolutionStatus> {
    let group = backend.group.as_deref().unwrap_or("");
    let kind = backend.kind.as_deref().unwrap_or("Service");
    let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);

    if !group.is_empty() || kind != "Service" {
        return Err(BackendResolutionStatus::Unsupported(format!(
            "backendRef group {} kind {} is not supported",
            group, kind
        )));
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
        return Err(BackendResolutionStatus::RefNotPermitted(format!(
            "cross-namespace backend reference from {} to {}/{} is not permitted",
            route_ns, target_ns, backend.name
        )));
    }

    Ok(())
}

fn resolve_backend_refs(
    route: &HTTPRoute,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.spec.rules.as_ref() {
        Some(r) => r,
        None => return BackendResolution::ok(),
    };

    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, grant_index) {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
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
        None => return BackendResolution::ok(),
    };

    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, grant_index) {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
                continue;
            }

            let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);
            let services: kube::Api<k8s_openapi::api::core::v1::Service> =
                kube::Api::namespaced(client.clone(), target_ns);
            if services.get(&backend.name).await.is_err() {
                let status = BackendResolutionStatus::BackendNotFound(format!(
                    "backend Service {}/{} not found",
                    target_ns, backend.name
                ));
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::BackendNotFound(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedParentRef {
    pub(crate) group: String,
    pub(crate) kind: String,
    pub(crate) namespace: Option<String>,
    pub(crate) name: String,
    pub(crate) section_name: Option<String>,
    pub(crate) port: Option<i32>,
}

pub(crate) fn parse_parent_refs(route: &HTTPRoute) -> Vec<ParsedParentRef> {
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
        kind: value.kind.as_deref().unwrap_or("Gateway").to_string(),
        namespace: value.namespace.clone(),
        name: value.name.clone(),
        section_name: value.section_name.clone(),
        port: value.port,
    })
}

/// Parse hostnames from an HTTPRoute spec into the model's HostnameMatch types.
pub(crate) fn parse_route_hostnames(
    route: &HTTPRoute,
) -> Vec<crate::gateway::model::HostnameMatch> {
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

/// Check whether `allowed` permits the given route kind.
pub(crate) fn listener_allows_kind(allowed: &AllowedRoutes, group: &str, kind: &str) -> bool {
    allowed.kinds.is_empty()
        || allowed
            .kinds
            .iter()
            .any(|k| k.group.as_ref() == group && k.kind.as_ref() == kind)
}

/// Check whether a listener's namespace scope allows routes from `route_ns`.
pub(crate) fn namespace_allowed(
    namespaces: &RouteNamespaces,
    route_ns: &str,
    gateway_ns: &str,
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> bool {
    match namespaces.from {
        NamespaceFrom::All => true,
        NamespaceFrom::Same => route_ns == gateway_ns,
        NamespaceFrom::None => false,
        NamespaceFrom::Selector => {
            let labels = match namespace_labels.get(route_ns) {
                Some(l) => l,
                None => return false,
            };
            namespaces
                .selector
                .as_ref()
                .is_some_and(|sel| sel.iter().all(|(k, v)| labels.get(k) == Some(v)))
        }
    }
}

/// Check whether `route_hostnames` intersect a listener's hostname.
pub(crate) fn listener_hostname_intersects(
    listener_hostname: Option<&str>,
    route_hostnames: &[HostnameMatch],
) -> bool {
    if route_hostnames.is_empty() {
        return true;
    }
    let Some(listener_hostname) = listener_hostname else {
        return true;
    };
    let listener_match = crate::gateway::translate::parse_listener_hostname(listener_hostname);
    route_hostnames
        .iter()
        .any(|rh| crate::gateway::translate::hostname_intersects(rh, &listener_match))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_parent_ref(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    if parsed.group != "gateway.networking.k8s.io" {
        return unsupported_parent(parsed, observed_generation, route_kind);
    }

    match parsed.kind.as_str() {
        "Gateway" => resolve_gateway_parent(
            parsed,
            route_ns,
            observed_generation,
            route_hostnames,
            gateways,
            namespace_labels,
            listener_allowed,
            route_kind,
        ),
        "ListenerSet" => resolve_listenerset_parent(
            parsed,
            route_ns,
            observed_generation,
            route_hostnames,
            listener_sets,
            namespace_labels,
            listener_set_allowed,
            route_kind,
        ),
        _ => unsupported_parent(parsed, observed_generation, route_kind),
    }
}

fn unsupported_parent(
    parsed: &ParsedParentRef,
    observed_generation: i64,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let conditions = vec![StatusCondition {
        condition_type: ConditionType::Accepted,
        status: ConditionStatus::False,
        reason: "UnsupportedValue".to_string(),
        message: format!(
            "parentRef group {} kind {} is not supported for {}",
            parsed.group, parsed.kind, route_kind
        ),
        observed_generation,
    }];
    (None, conditions)
}

#[allow(clippy::too_many_arguments)]
fn resolve_gateway_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingParent".to_string(),
                message: format!("Gateway {}/{} not found", target_ns, parsed.name),
                observed_generation,
            }],
        );
    };

    let no_conflicts = std::collections::BTreeMap::<Arc<str>, Arc<str>>::new();
    resolve_listener_parent(
        parsed,
        route_ns,
        observed_generation,
        route_hostnames,
        &gateway.listeners,
        namespace_labels,
        listener_allowed,
        target_ns,
        &parsed.name,
        "Gateway",
        &no_conflicts,
        route_kind,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_listenerset_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    let ls = listener_sets
        .iter()
        .find(|s| s.namespace.as_ref() == target_ns && s.name.as_ref() == parsed.name);

    let Some(ls) = ls else {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingParent".to_string(),
                message: format!("ListenerSet {}/{} not found", target_ns, parsed.name),
                observed_generation,
            }],
        );
    };

    resolve_listener_parent(
        parsed,
        route_ns,
        observed_generation,
        route_hostnames,
        &ls.listeners,
        namespace_labels,
        listener_set_allowed,
        target_ns,
        &parsed.name,
        "ListenerSet",
        &ls.conflicts,
        route_kind,
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_listener_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    listeners: &[ListenerState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    allowed_map: &HashMap<(String, String, String), AllowedRoutes>,
    target_ns: &str,
    owner_name: &str,
    owner_kind: &str,
    conflicts: &std::collections::BTreeMap<Arc<str>, Arc<str>>,
    route_kind: &str,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let matching_listeners: Vec<&ListenerState> = listeners
        .iter()
        .filter(|l| {
            if conflicts.contains_key(l.name.as_ref()) {
                return false;
            }
            let section_matches = parsed
                .section_name
                .as_deref()
                .map(|s| s == l.name.as_ref())
                .unwrap_or(true);
            let port_matches = parsed.port.map(|p| p == l.port as i32).unwrap_or(true);
            section_matches && port_matches
        })
        .collect();

    if let Some(ref section) = parsed.section_name {
        let listener_exists = listeners
            .iter()
            .any(|l| l.name.as_ref() == section.as_str());
        if !listener_exists {
            return (
                None,
                vec![StatusCondition {
                    condition_type: ConditionType::Accepted,
                    status: ConditionStatus::False,
                    reason: "NoMatchingParent".to_string(),
                    message: format!(
                        "listener {} not found on {} {}/{}",
                        section, owner_kind, target_ns, owner_name
                    ),
                    observed_generation,
                }],
            );
        }
    }

    if let Some(port) = parsed.port {
        if matching_listeners.is_empty() {
            return (
                None,
                vec![StatusCondition {
                    condition_type: ConditionType::Accepted,
                    status: ConditionStatus::False,
                    reason: "NoMatchingParent".to_string(),
                    message: format!(
                        "no listener matching port {} on {} {}/{}",
                        port, owner_kind, target_ns, owner_name
                    ),
                    observed_generation,
                }],
            );
        }
    }

    let mut kind_allowed = false;
    let mut namespace_allowed_flag = false;
    let mut hostname_intersects = false;

    for listener in matching_listeners {
        let allowed = allowed_map
            .get(&(
                target_ns.to_string(),
                owner_name.to_string(),
                listener.name.to_string(),
            ))
            .cloned()
            .unwrap_or_default();
        if !listener_allows_kind(&allowed, "gateway.networking.k8s.io", route_kind) {
            continue;
        }
        kind_allowed = true;
        if !namespace_allowed(&allowed.namespaces, route_ns, target_ns, namespace_labels) {
            continue;
        }
        namespace_allowed_flag = true;
        if !listener_hostname_intersects(listener.hostname.as_deref(), route_hostnames) {
            continue;
        }
        hostname_intersects = true;
    }

    if !kind_allowed || !namespace_allowed_flag {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NotAllowedByListeners".to_string(),
                message: format!(
                    "Route is not allowed by any listener of {} {}/{}",
                    owner_kind, target_ns, owner_name
                ),
                observed_generation,
            }],
        );
    }

    if !hostname_intersects {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingListenerHostname".to_string(),
                message: format!(
                    "Route hostnames do not intersect with any listener of {} {}/{}",
                    owner_kind, target_ns, owner_name
                ),
                observed_generation,
            }],
        );
    }

    let parent_ref = ParentRef {
        group: Arc::from(parsed.group.clone()),
        kind: Arc::from(parsed.kind.clone()),
        namespace: Some(Arc::from(target_ns)),
        name: Arc::from(parsed.name.clone()),
        section_name: parsed.section_name.as_ref().map(|s| Arc::from(s.as_str())),
        port: parsed.port.map(|p| p as u16),
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
        .map(|r| {
            r.iter()
                .filter_map(|rule| parse_rule(rule, route_ns_str))
                .collect()
        })
        .unwrap_or_default();

    HTTPRouteState {
        namespace: ns,
        name,
        generation,
        hostnames,
        rules,
        parent_refs: vec![], // filled by reconcile_single
        programmed: false,   // filled by reconcile_single
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
        .map(|arr| {
            arr.iter()
                .filter_map(|b| parse_backend_ref(b, route_ns))
                .collect()
        })
        .unwrap_or_default();

    let filters: Vec<RouteFilter> = value
        .filters
        .as_ref()
        .map(|arr| arr.iter().flat_map(|f| parse_filter(f, route_ns)).collect())
        .unwrap_or_default();

    let timeout_ms = value.timeouts.as_ref().and_then(|t| {
        t.backend_request.as_ref().and_then(|dur| {
            dur.parse::<gateway_api::Duration>()
                .ok()
                .map(|d| d.as_millis() as u64)
        })
    });
    let request_timeout_ms = value.timeouts.as_ref().and_then(|t| {
        t.request.as_ref().and_then(|dur| {
            dur.parse::<gateway_api::Duration>()
                .ok()
                .map(|d| d.as_millis() as u64)
        })
    });

    Some(HTTPRouteRule {
        matches,
        backends,
        filters,
        timeout_ms,
        request_timeout_ms,
        programmed: true,
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
    let value_match = match value
        .r#type
        .as_ref()
        .unwrap_or(&HttpRouteRulesMatchesHeadersType::Exact)
    {
        HttpRouteRulesMatchesHeadersType::Exact => {
            HeaderMatchValue::Exact(Arc::from(value.value.as_str()))
        }
        HttpRouteRulesMatchesHeadersType::RegularExpression => {
            HeaderMatchValue::Regex(Arc::from(value.value.as_str()))
        }
    };
    Some(HeaderMatch {
        name: Arc::from(value.name.as_str()),
        value: value_match,
    })
}

fn parse_query_param_match(value: &HttpRouteRulesMatchesQueryParams) -> Option<QueryParamMatch> {
    use gateway_api::httproutes::HttpRouteRulesMatchesQueryParamsType;
    let value_match = match value
        .r#type
        .as_ref()
        .unwrap_or(&HttpRouteRulesMatchesQueryParamsType::Exact)
    {
        HttpRouteRulesMatchesQueryParamsType::Exact => {
            QueryParamMatchValue::Exact(Arc::from(value.value.as_str()))
        }
        HttpRouteRulesMatchesQueryParamsType::RegularExpression => {
            QueryParamMatchValue::Regex(Arc::from(value.value.as_str()))
        }
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
    let typ = value
        .r#type
        .as_ref()
        .unwrap_or(&HttpRouteRulesMatchesPathType::PathPrefix);
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

    let filters = value
        .filters
        .as_ref()
        .map(|arr| {
            arr.iter()
                .flat_map(|f| parse_backend_filter(f, route_ns))
                .collect()
        })
        .unwrap_or_default();

    // Build a cluster-internal service address.  Always use the FQDN so that
    // the proxy resolves the backend in the route's namespace regardless of
    // which namespace the proxy pod itself runs in.
    let backend = format!("{}.{}.svc.cluster.local.:{}", name, ns, port);
    Some(WeightedBackend {
        backend: Arc::from(backend),
        weight,
        filters,
        protocol: crate::ir::BackendProtocol::Http,
        tls: None,
    })
}

fn parse_filter(value: &HttpRouteRulesFilters, route_ns: &str) -> Vec<RouteFilter> {
    match value.r#type {
        HttpRouteRulesFiltersType::UrlRewrite => {
            let Some(url_rewrite) = value.url_rewrite.as_ref() else {
                return vec![];
            };
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
                    HttpRouteRulesFiltersUrlRewritePathType::ReplaceFullPath => p
                        .replace_full_path
                        .as_deref()
                        .map(|s| PathRewrite::FullReplace(Arc::from(s))),
                },
                None => None,
            };
            if hostname.is_none() && path_rewrite.is_none() {
                return vec![];
            }
            vec![RouteFilter::UrlRewrite {
                hostname,
                path: path_rewrite,
            }]
        }
        HttpRouteRulesFiltersType::RequestHeaderModifier => {
            let Some(modifier) = value.request_header_modifier.as_ref() else {
                return vec![];
            };
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
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
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
            let Some(redirect) = value.request_redirect.as_ref() else {
                return vec![];
            };
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
            let Some(mirror) = value.request_mirror.as_ref() else {
                return vec![];
            };
            let name = &mirror.backend_ref.name;
            let ns = mirror.backend_ref.namespace.as_deref().unwrap_or(route_ns);
            let port = mirror.backend_ref.port.unwrap_or(80);
            let backend = format!("{}.{}.svc.cluster.local.:{}", name, ns, port);
            let fraction = mirror
                .fraction
                .as_ref()
                .map(|f| {
                    let denom = f.denominator.unwrap_or(100).max(1);
                    let num = f.numerator.max(0) as u32;
                    Fraction {
                        numerator: num,
                        denominator: denom as u32,
                    }
                })
                .or_else(|| {
                    mirror.percent.map(|p| Fraction {
                        numerator: p.max(0) as u32,
                        denominator: 100,
                    })
                });
            vec![RouteFilter::RequestMirror {
                backend: Arc::from(backend),
                fraction,
            }]
        }
        HttpRouteRulesFiltersType::Cors => {
            let Some(cors) = value.cors.as_ref() else {
                return vec![];
            };
            let allow_origins = cors
                .allow_origins
                .as_ref()
                .map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect())
                .unwrap_or_default();
            let allow_methods = cors
                .allow_methods
                .as_ref()
                .map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect())
                .unwrap_or_default();
            let allow_headers = cors
                .allow_headers
                .as_ref()
                .map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect())
                .unwrap_or_default();
            let expose_headers = cors
                .expose_headers
                .as_ref()
                .map(|v| v.iter().map(|s| Arc::from(s.as_str())).collect())
                .unwrap_or_default();
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

fn parse_backend_filter(
    value: &HttpRouteRulesBackendRefsFilters,
    _route_ns: &str,
) -> Vec<RouteFilter> {
    match value.r#type {
        HttpRouteRulesBackendRefsFiltersType::RequestHeaderModifier => {
            let Some(modifier) = value.request_header_modifier.as_ref() else {
                return vec![];
            };
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
        HttpRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
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
        _ => vec![],
    }
}

fn parse_redirect_path(
    value: &gateway_api::httproutes::HttpRouteRulesFiltersRequestRedirectPath,
) -> Option<PathRewrite> {
    match value.r#type {
        HttpRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath => value
            .replace_full_path
            .as_ref()
            .map(|s| PathRewrite::FullReplace(Arc::from(s.as_str()))),
        HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch => value
            .replace_prefix_match
            .as_ref()
            .map(|s| PathRewrite::PrefixReplace {
                prefix: Arc::from("/"),
                replacement: Arc::from(s.as_str()),
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

    // Fetch all Gateways, Namespaces, and ReferenceGrants for parentRef resolution.
    // In T1 we do a fresh list per reconcile; a shared cache can be added later.
    let gateways: Api<crate::gateway::api::Gateway> = Api::all(ctx.client.clone());
    let grants: Api<crate::gateway::api::ReferenceGrant> = Api::all(ctx.client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());

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
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for HTTPRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();

    let grant_states =
        crate::gateway::reconcile::refgrant::reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states);

    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();

    // Only fetch ListenerSets when this route actually parents to one.
    let parsed_refs = parse_parent_refs(&route);
    let needs_listener_sets = parsed_refs
        .iter()
        .any(|p| p.group == "gateway.networking.k8s.io" && p.kind == "ListenerSet");

    let (listener_set_list_items, mut listener_set_states) = if needs_listener_sets {
        let listener_sets: Api<crate::gateway::api::ListenerSet> = Api::all(ctx.client.clone());
        let listener_set_list = match listener_sets.list(&Default::default()).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list ListenerSets for HTTPRoute reconcile");
                return Ok(Action::requeue(Duration::from_secs(5)));
            }
        };
        let mut states = Vec::new();
        for ls in &listener_set_list.items {
            states.push(
                crate::gateway::reconcile::listenerset::build_listener_set_state(
                    ls,
                    &gateway_list.items,
                    &namespace_labels,
                    &ctx.client,
                    &grant_index,
                )
                .await,
            );
        }
        (listener_set_list.items, states)
    } else {
        (Vec::new(), Vec::new())
    };
    if !listener_set_states.is_empty() {
        crate::gateway::reconcile::listenerset::resolve_listener_set_conflicts(
            &mut listener_set_states,
            &gateway_states,
        );
    }
    let listener_allowed =
        crate::gateway::reconcile::gateway::build_listener_allowed_map(&gateway_list.items);
    let listener_set_allowed =
        crate::gateway::reconcile::listenerset::build_listener_set_allowed_map(
            &listener_set_list_items,
            &listener_set_states,
        );

    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let backend_resolution =
        resolve_backend_refs_async(&ctx.client, &route, route_ns, &grant_index).await;
    let reconciled = reconcile_single(
        &route,
        &gateway_states,
        &listener_set_states,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
        backend_resolution,
    );

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
                parent_ref.insert("group".into(), serde_json::json!(ps.parent_ref.group.as_ref()));
                parent_ref.insert("kind".into(), serde_json::json!(ps.parent_ref.kind.as_ref()));
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

        let old_status_json = route
            .status
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

        if old_stripped == new_stripped {
            tracing::debug!(
                name,
                namespace = ns,
                "HTTPRoute status unchanged, skipping patch"
            );
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
            if let Err(e) = api
                .patch_status(&name, &pp, &Patch::Apply(&patch_body))
                .await
            {
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
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        }
    }

    fn grant_allowing_http_route(
        from_ns: &str,
        gateway_ns: &str,
        gateway_name: &str,
    ) -> ReferenceGrantState {
        ReferenceGrantState {
            namespace: Arc::from(gateway_ns),
            name: Arc::from("allow"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
                namespace: Some(Arc::from(from_ns)),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: Some(Arc::from(gateway_name)),
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
    fn cross_namespace_default_same_not_allowed() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant_index =
            GrantIndex::new(vec![grant_allowing_http_route("default", "prod", "gw-1")]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NotAllowedByListeners");
    }

    #[test]
    fn cross_namespace_accepted_when_allowed_all() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant_index =
            GrantIndex::new(vec![grant_allowing_http_route("default", "prod", "gw-1")]);
        let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        listener_allowed.insert(
            ("prod".to_string(), "gw-1".to_string(), "http".to_string()),
            AllowedRoutes {
                kinds: vec![],
                namespaces: RouteNamespaces {
                    from: NamespaceFrom::All,
                    selector: None,
                },
            },
        );

        let listener_sets = Vec::<ListenerSetState>::new();
        let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        let results = reconcile_httproutes_with_context(
            &[route],
            &gateways,
            &listener_sets,
            &namespace_labels,
            &listener_allowed,
            &listener_set_allowed,
            &grant_index,
        );
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn namespace_selector_accepts_matching_route() {
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "team-a", "generation": 1 },
            "spec": {
                "parentRefs": [{ "namespace": "infra", "name": "gw-1", "sectionName": "http" }]
            }
        }))
        .expect("valid HTTPRoute");
        let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
        let grant_index =
            GrantIndex::new(vec![grant_allowing_http_route("team-a", "infra", "gw-1")]);
        let mut namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        namespace_labels.insert(
            "team-a".to_string(),
            [("allowed".to_string(), "true".to_string())]
                .into_iter()
                .collect(),
        );
        let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        listener_allowed.insert(
            ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
            AllowedRoutes {
                kinds: vec![],
                namespaces: RouteNamespaces {
                    from: NamespaceFrom::Selector,
                    selector: Some(
                        [("allowed".to_string(), "true".to_string())]
                            .into_iter()
                            .collect(),
                    ),
                },
            },
        );

        let listener_sets = Vec::<ListenerSetState>::new();
        let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        let results = reconcile_httproutes_with_context(
            &[route],
            &gateways,
            &listener_sets,
            &namespace_labels,
            &listener_allowed,
            &listener_set_allowed,
            &grant_index,
        );
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn namespace_selector_rejects_non_matching_route() {
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "team-b", "generation": 1 },
            "spec": {
                "parentRefs": [{ "namespace": "infra", "name": "gw-1", "sectionName": "http" }]
            }
        }))
        .expect("valid HTTPRoute");
        let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
        let grant_index =
            GrantIndex::new(vec![grant_allowing_http_route("team-b", "infra", "gw-1")]);
        let mut namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        namespace_labels.insert(
            "team-b".to_string(),
            [("allowed".to_string(), "false".to_string())]
                .into_iter()
                .collect(),
        );
        let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        listener_allowed.insert(
            ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
            AllowedRoutes {
                kinds: vec![],
                namespaces: RouteNamespaces {
                    from: NamespaceFrom::Selector,
                    selector: Some(
                        [("allowed".to_string(), "true".to_string())]
                            .into_iter()
                            .collect(),
                    ),
                },
            },
        );

        let listener_sets = Vec::<ListenerSetState>::new();
        let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        let results = reconcile_httproutes_with_context(
            &[route],
            &gateways,
            &listener_sets,
            &namespace_labels,
            &listener_allowed,
            &listener_set_allowed,
            &grant_index,
        );
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NotAllowedByListeners");
    }

    #[test]
    fn unsupported_route_kind_rejected_by_listener() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "infra",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
        let grant_index =
            GrantIndex::new(vec![grant_allowing_http_route("default", "infra", "gw-1")]);
        let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        listener_allowed.insert(
            ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
            AllowedRoutes {
                kinds: vec![crate::gateway::model::RouteGroupKind {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("GRPCRoute"),
                }],
                namespaces: RouteNamespaces {
                    from: NamespaceFrom::All,
                    selector: None,
                },
            },
        );

        let listener_sets = Vec::<ListenerSetState>::new();
        let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
        let results = reconcile_httproutes_with_context(
            &[route],
            &gateways,
            &listener_sets,
            &namespace_labels,
            &listener_allowed,
            &listener_set_allowed,
            &grant_index,
        );
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NotAllowedByListeners");
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

    fn route_with_backends(
        parent_refs: Vec<serde_json::Value>,
        backends: Vec<serde_json::Value>,
    ) -> HTTPRoute {
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
        assert_eq!(
            state.hostnames[0],
            HostnameMatch::Exact(Arc::from("example.com"))
        );
        assert_eq!(
            state.hostnames[1],
            HostnameMatch::Wildcard(Arc::from("wildcard.test"))
        );
        assert_eq!(state.rules.len(), 1);
        assert_eq!(state.rules[0].matches.len(), 1);
        assert_eq!(
            state.rules[0].matches[0].path,
            Some(PathMatch::Prefix(Arc::from("/api")))
        );
        assert_eq!(state.rules[0].matches[0].method.as_deref(), Some("GET"));
        assert_eq!(state.rules[0].backends.len(), 1);
        assert_eq!(
            state.rules[0].backends[0].backend.as_ref(),
            "svc-1.default.svc.cluster.local.:8080"
        );
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

        assert_eq!(
            parse_httproute_state(&exact).rules[0].matches[0].path,
            Some(PathMatch::Exact(Arc::from("/foo")))
        );
        assert_eq!(
            parse_httproute_state(&prefix).rules[0].matches[0].path,
            Some(PathMatch::Prefix(Arc::from("/bar")))
        );
        assert_eq!(
            parse_httproute_state(&regex).rules[0].matches[0].path,
            Some(PathMatch::Regex(Arc::from("^/baz$")))
        );
        assert_eq!(
            parse_httproute_state(&default_type).rules[0].matches[0].path,
            Some(PathMatch::Prefix(Arc::from("/ defaulted")))
        );
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
                parse_httproute_state(&route).rules[0].matches[0]
                    .method
                    .as_deref(),
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
        assert_eq!(
            backend.backend.as_ref(),
            "svc.default.svc.cluster.local.:80"
        );
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
        assert_eq!(
            backend.backend.as_ref(),
            "svc.other.svc.cluster.local.:9090"
        );
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
                path: Some(PathRewrite::PrefixReplace {
                    prefix: Arc::from("/"),
                    replacement: Arc::from("/v2"),
                }),
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
                path: Some(PathRewrite::FullReplace(Arc::from("/new"))),
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
    fn parse_backend_ref_request_header_modifier_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "backendRefs": [{
                        "name": "svc",
                        "port": 8080,
                        "filters": [{
                            "type": "RequestHeaderModifier",
                            "requestHeaderModifier": {
                                "set": [{"name": "X-Backend", "value": "yes"}]
                            }
                        }]
                    }]
                }]
            }
        }));
        let backend = &parse_httproute_state(&route).rules[0].backends[0];
        assert_eq!(
            backend.backend.as_ref(),
            "svc.default.svc.cluster.local.:8080"
        );
        assert_eq!(
            backend.filters[0],
            RouteFilter::RequestHeaderSet {
                name: Arc::from("X-Backend"),
                value: Arc::from("yes"),
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
            RouteFilter::RequestRedirect {
                path:
                    Some(PathRewrite::PrefixReplace {
                        prefix,
                        replacement,
                    }),
                ..
            } => {
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

    #[test]
    fn parse_cors_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "CORS",
                        "cors": {
                            "allowOrigins": ["https://example.com"],
                            "allowMethods": ["GET", "POST"],
                            "allowHeaders": ["X-Custom"],
                            "exposeHeaders": ["X-Response"],
                            "maxAge": 3600,
                            "allowCredentials": true
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::Cors {
                allow_origins: vec![Arc::from("https://example.com")],
                allow_methods: vec![Arc::from("GET"), Arc::from("POST")],
                allow_headers: vec![Arc::from("X-Custom")],
                expose_headers: vec![Arc::from("X-Response")],
                max_age: Some(3600),
                allow_credentials: true,
            }
        );
    }

    #[test]
    fn parse_cors_filter_defaults() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "CORS",
                        "cors": {}
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert!(
            matches!(filter, RouteFilter::Cors { allow_origins, allow_methods, allow_headers, expose_headers, max_age, allow_credentials }
                if allow_origins.is_empty() && allow_methods.is_empty() && allow_headers.is_empty() && expose_headers.is_empty() && max_age.is_none() && !allow_credentials)
        );
    }

    #[test]
    fn parse_request_mirror_filter() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "rules": [{
                    "filters": [{
                        "type": "RequestMirror",
                        "requestMirror": {
                            "backendRef": {
                                "namespace": "mirror-ns",
                                "name": "mirror-svc",
                                "port": 8080
                            }
                        }
                    }]
                }]
            }
        }));
        let filter = &parse_httproute_state(&route).rules[0].filters[0];
        assert_eq!(
            *filter,
            RouteFilter::RequestMirror {
                backend: Arc::from("mirror-svc.mirror-ns.svc.cluster.local.:8080"),
                fraction: None,
            }
        );
    }

    #[test]
    fn parse_backend_request_timeout() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "timeouts": { "backendRequest": "30s" },
                    "backendRefs": [{"name": "svc"}]
                }]
            }
        }));
        let rule = &parse_httproute_state(&route).rules[0];
        assert_eq!(rule.timeout_ms, Some(30_000));
    }

    #[test]
    fn parse_invalid_backend_request_timeout_is_ignored() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r" },
            "spec": {
                "rules": [{
                    "timeouts": { "backendRequest": "not-a-duration" },
                    "backendRefs": [{"name": "svc"}]
                }]
            }
        }));
        let rule = &parse_httproute_state(&route).rules[0];
        assert_eq!(rule.timeout_ms, None);
    }

    fn gw_with_hostname(ns: &str, name: &str, listener: &str, hostname: &str) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from(hostname)),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        }
    }

    #[test]
    fn parent_ref_port_matching_accepted() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "port": 80
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn parent_ref_port_matching_rejected() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "port": 9999
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn hostname_mismatch_rejected() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "parentRefs": [{"name": "gw-1"}],
                "hostnames": ["foo.example.com"]
            }
        }));
        let gateways = vec![gw_with_hostname(
            "default",
            "gw-1",
            "http",
            "bar.example.com",
        )];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingListenerHostname");
    }

    #[test]
    fn hostname_intersection_accepted() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "parentRefs": [{"name": "gw-1"}],
                "hostnames": ["*.example.com"]
            }
        }));
        let gateways = vec![gw_with_hostname("default", "gw-1", "http", "*.example.com")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn wildcard_route_intersects_specific_listener() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "parentRefs": [{"name": "gw-1"}],
                "hostnames": ["*.specific.com"]
            }
        }));
        let gateways = vec![gw_with_hostname(
            "default",
            "gw-1",
            "http",
            "very.specific.com",
        )];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn no_intersecting_hostnames_rejected() {
        let route = route_from_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": {
                "parentRefs": [{"name": "gw-1"}],
                "hostnames": ["specific.but.wrong.com", "wildcard.io"]
            }
        }));
        let gateways = vec![gw_with_hostname(
            "default",
            "gw-1",
            "http",
            "very.specific.com",
        )];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let accepted = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingListenerHostname");
    }

    #[test]
    fn resolve_backend_refs_async_finds_service() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let route = route_with_backends(
                vec![serde_json::json!({"name": "gw-1"})],
                vec![serde_json::json!({"name": "svc-1", "port": 80})],
            );
            let client = kube::Client::new(
                tower::service_fn(|req: http::Request<kube::client::Body>| async move {
                    let path = req.uri().path();
                    let body = if path.contains("/services/svc-1") {
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Service",
                            "metadata": { "name": "svc-1", "namespace": "default" }
                        })
                    } else {
                        serde_json::json!({"apiVersion": "v1", "kind": "List", "items": []})
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }),
                "default",
            );
            let grant_index = GrantIndex::new(vec![]);
            let result = resolve_backend_refs_async(&client, &route, "default", &grant_index).await;
            assert!(matches!(result.overall, BackendResolutionStatus::Ok));
        });
    }

    #[test]
    fn resolve_backend_refs_async_missing_service() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let route = route_with_backends(
                vec![serde_json::json!({"name": "gw-1"})],
                vec![serde_json::json!({"name": "missing-svc", "port": 80})],
            );
            let client = kube::Client::new(
                tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(404)
                            .body(kube::client::Body::empty())
                            .unwrap(),
                    )
                }),
                "default",
            );
            let grant_index = GrantIndex::new(vec![]);
            let result = resolve_backend_refs_async(&client, &route, "default", &grant_index).await;
            assert!(
                matches!(result.overall, BackendResolutionStatus::BackendNotFound(ref msg) if msg.contains("missing-svc")),
                "unexpected result: {result:?}"
            );
        });
    }

    #[tokio::test]
    async fn error_policy_httproute_requeues_after_5s() {
        let route = Arc::new(sample_route(vec![]));
        let ctx = Arc::new(HTTPRouteContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        kube::client::Body::empty(),
                    ))
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let err = kube::Error::Service(std::io::Error::other("test").into());
        let action = error_policy_httproute(route, &err, ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[test]
    fn parse_header_and_query_param_matches() {
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "r", "namespace": "default", "generation": 1 },
            "spec": {
                "rules": [{
                    "matches": [
                        {
                            "headers": [
                                { "name": "X-Version", "value": "v1" },
                                { "name": "X-Debug", "type": "RegularExpression", "value": "on|off" }
                            ],
                            "queryParams": [
                                { "name": "page", "value": "1" },
                                { "name": "filter", "type": "RegularExpression", "value": ".*" }
                            ]
                        }
                    ]
                }]
            }
        }))
        .expect("valid HTTPRoute");

        let state = parse_httproute_state(&route);
        let m = &state.rules[0].matches[0];
        assert_eq!(m.headers.len(), 2);
        assert_eq!(m.headers[0].name.as_ref(), "X-Version");
        assert_eq!(m.headers[0].value, HeaderMatchValue::Exact(Arc::from("v1")));
        assert_eq!(m.headers[1].name.as_ref(), "X-Debug");
        assert_eq!(
            m.headers[1].value,
            HeaderMatchValue::Regex(Arc::from("on|off"))
        );

        assert_eq!(m.query_params.len(), 2);
        assert_eq!(m.query_params[0].name.as_ref(), "page");
        assert_eq!(
            m.query_params[0].value,
            QueryParamMatchValue::Exact(Arc::from("1"))
        );
        assert_eq!(m.query_params[1].name.as_ref(), "filter");
        assert_eq!(
            m.query_params[1].value,
            QueryParamMatchValue::Regex(Arc::from(".*"))
        );
    }

    #[tokio::test]
    async fn reconcile_httproute_non_leader_returns_requeue() {
        let route: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .expect("valid HTTPRoute");

        let gateway_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayList",
            "items": []
        });
        let grant_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ReferenceGrantList",
            "items": []
        });
        let namespace_list = serde_json::json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "items": []
        });

        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path();
                let body = if path.contains("/namespaces") {
                    namespace_list.clone()
                } else if path.contains("/referencegrants") {
                    grant_list.clone()
                } else {
                    gateway_list.clone()
                };
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );

        let ctx = Arc::new(HTTPRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn run_httproute_controller_returns_handle() {
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let handle = run_httproute_controller(client, Arc::new(AtomicBool::new(false)));
        handle.abort();
    }

    #[tokio::test]
    async fn httproute_context_clone_smoke() {
        let ctx = HTTPRouteContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        kube::client::Body::empty(),
                    ))
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        };
        let cloned = ctx.clone();
        assert!(!cloned.is_leader.load(Ordering::Relaxed));
    }
}
