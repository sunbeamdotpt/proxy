// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPRoute parsing helpers.

use crate::gateway::api::HTTPRoute;
use crate::gateway::model::{
    Fraction, HTTPRouteRule, HTTPRouteState, HeaderMatch, HeaderMatchValue, HostnameMatch,
    ParentRef, PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter,
    RouteMatch, RouteState, WeightedBackend,
};
use crate::gateway::reconcile::backend::RouteLike;
use crate::gateway::reconcile::parent::ParsedParentRef;
use crate::gateway::reconcile::route::RouteResource;
use crate::ir::BackendProtocol;
use gateway_api::httproutes::{
    HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType, HttpRouteRulesFilters,
    HttpRouteRulesFiltersRequestRedirectPathType, HttpRouteRulesFiltersRequestRedirectScheme,
    HttpRouteRulesFiltersType, HttpRouteRulesFiltersUrlRewritePathType, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
};
use std::sync::Arc;

crate::impl_parse_parent_refs!(parse_parent_refs, HTTPRoute, HttpRouteParentRefs);

/// Parse hostnames from an HTTPRoute spec into the model's HostnameMatch types.
pub fn parse_route_hostnames(route: &HTTPRoute) -> Vec<HostnameMatch> {
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

/// Parse an HTTPRoute CRD into the full `HTTPRouteState` model,
/// including hostnames and rules extracted from the raw spec.
pub fn parse_httproute_state(route: &HTTPRoute) -> HTTPRouteState {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let hostnames: Vec<HostnameMatch> = parse_route_hostnames(route);

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
        protocol: BackendProtocol::Http,
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
            crate::parse_request_header_modifier!(modifier)
        }
        HttpRouteRulesFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            crate::parse_response_header_modifier!(modifier)
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
            crate::parse_request_header_modifier!(modifier)
        }
        HttpRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            crate::parse_response_header_modifier!(modifier)
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

crate::impl_backend_ref_like!(HttpRouteRulesBackendRefs);

impl crate::gateway::reconcile::backend::RuleLike for HttpRouteRules {
    type BackendRef = HttpRouteRulesBackendRefs;
    fn backend_refs(&self) -> Option<&[Self::BackendRef]> {
        self.backend_refs.as_deref()
    }
}

impl RouteLike for HTTPRoute {
    type Rule = HttpRouteRules;
    fn rules(&self) -> Option<&[Self::Rule]> {
        self.spec.rules.as_deref()
    }
    fn kind() -> &'static str {
        "HTTPRoute"
    }
}

impl RouteResource for HTTPRoute {
    fn kind_str() -> &'static str {
        "HTTPRoute"
    }
    fn status_kind_str() -> &'static str {
        "HTTPRoute"
    }
    fn parse_hostnames(&self) -> Vec<HostnameMatch> {
        parse_route_hostnames(self)
    }
    fn parse_parent_refs(&self) -> Vec<ParsedParentRef> {
        parse_parent_refs(self)
    }
    fn route_state(&self, parent_refs: Vec<ParentRef>) -> RouteState {
        RouteState {
            namespace: Arc::from(self.metadata_namespace()),
            name: Arc::from(self.metadata_name()),
            kind: Arc::from(Self::kind_str()),
            generation: self.generation(),
            parent_refs,
        }
    }
    fn metadata_name(&self) -> &str {
        self.metadata.name.as_deref().unwrap_or("")
    }
    fn metadata_namespace(&self) -> &str {
        self.metadata.namespace.as_deref().unwrap_or("default")
    }
    fn generation(&self) -> i64 {
        self.metadata.generation.unwrap_or(0)
    }
}
