// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Route / listener translation layer.
//!
//! Converts a `GatewayView` into Pingora-native configuration.

use crate::config::{
    HeaderMatchConfig, HeaderMatchValueConfig, HeaderRule, PathRoute, QueryParamMatchConfig,
    QueryParamMatchValueConfig, RedirectRule, RewriteRule, RouteConfig, WeightedBackendConfig,
};
use crate::gateway::model::{
    GatewayState, GatewayView, HeaderMatch, HeaderMatchValue, HostnameMatch, HTTPRouteRule, ListenerState, PathMatch,
    PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Check if `child` hostname is a subset of `parent` hostname.
pub fn is_hostname_subset(child: &HostnameMatch, parent: &HostnameMatch) -> bool {
    match (child, parent) {
        (_, HostnameMatch::Any) => true,
        (HostnameMatch::Exact(c), HostnameMatch::Exact(p)) => c == p,
        // Intersection is more permissive than request matching:
        // a multi-level subdomain is considered a subset of a wildcard.
        (HostnameMatch::Exact(c), HostnameMatch::Wildcard(p)) => c
            .strip_suffix(p.as_ref())
            .and_then(|rest| rest.strip_suffix('.'))
            .map_or(false, |rest| !rest.is_empty()),
        (HostnameMatch::Wildcard(c), HostnameMatch::Wildcard(p)) => {
            c == p || c.strip_suffix(p.as_ref()).map_or(false, |rest| rest.ends_with('.'))
        }
        (HostnameMatch::Any, _) => false,
        _ => false,
    }
}

/// Intersect route hostnames with a listener hostname.
pub fn intersect_hostnames(
    route_hostnames: &[HostnameMatch],
    listener_hostname: Option<&str>,
) -> Vec<HostnameMatch> {
    let Some(lh_str) = listener_hostname else {
        return route_hostnames.to_vec();
    };
    let listener_match = parse_listener_hostname(lh_str);
    route_hostnames
        .iter()
        .filter(|rh| is_hostname_subset(rh, &listener_match))
        .cloned()
        .collect()
}

/// An effective hostname for a route, paired with its originating listener hostname.
struct EffectiveHostname {
    host_prefix: String,
    listener_hostname: Option<String>,
}

/// Compute effective hostnames for an HTTPRoute, considering listener hostname intersection.
fn compute_effective_hostnames(
    route: &crate::gateway::model::HTTPRouteState,
    gateways: &[GatewayState],
) -> Vec<EffectiveHostname> {
    let mut result = Vec::new();

    for parent in &route.parent_refs {
        let gw_ns = parent.namespace.as_deref().unwrap_or(route.namespace.as_ref());
        let gw_name = parent.name.as_ref();
        let gateway = gateways
            .iter()
            .find(|g| g.namespace.as_ref() == gw_ns && g.name.as_ref() == gw_name);

        if route.hostnames.is_empty() {
            // Route has no hostnames: inherit from listener
            let Some(gateway) = gateway else {
                result.push(EffectiveHostname {
                    host_prefix: "*".to_string(),
                    listener_hostname: None,
                });
                continue;
            };

            let listeners: Vec<&ListenerState> =
                if let Some(section) = parent.section_name.as_deref() {
                    gateway
                        .listeners
                        .iter()
                        .filter(|l| l.name.as_ref() == section)
                        .collect()
                } else {
                    gateway.listeners.iter().collect()
                };

            for listener in listeners {
                // Use Some("") for listeners with no hostname so we can distinguish
                // Gateway API routes from legacy TOML routes in the proxy hot path.
                let listener_hostname_str = Some(listener.hostname.as_ref().map(|h| h.to_string()).unwrap_or_default());
                let hostnames = if let Some(ref h) = listener.hostname {
                    vec![parse_listener_hostname(h)]
                } else {
                    vec![HostnameMatch::Any]
                };
                for hostname in hostnames {
                    result.push(EffectiveHostname {
                        host_prefix: hostname_to_prefix(&hostname),
                        listener_hostname: listener_hostname_str.clone(),
                    });
                }
            }
        } else {
            // Route has hostnames: intersect with listener hostname if gateway found
            if let Some(gateway) = gateway {
                let listeners: Vec<&ListenerState> =
                    if let Some(section) = parent.section_name.as_deref() {
                        gateway
                            .listeners
                            .iter()
                            .filter(|l| l.name.as_ref() == section)
                            .collect()
                    } else {
                        gateway.listeners.iter().collect()
                    };

                for listener in listeners {
                    let listener_hostname_str = Some(listener.hostname.as_ref().map(|h| h.to_string()).unwrap_or_default());
                    let hostnames = intersect_hostnames(&route.hostnames, listener.hostname.as_deref());
                    for hostname in hostnames {
                        result.push(EffectiveHostname {
                            host_prefix: hostname_to_prefix(&hostname),
                            listener_hostname: listener_hostname_str.clone(),
                        });
                    }
                }
            } else {
                // Gateway not found — use route hostnames directly
                for hostname in &route.hostnames {
                    result.push(EffectiveHostname {
                        host_prefix: hostname_to_prefix(hostname),
                        listener_hostname: None,
                    });
                }
            }
        }
    }

    result
}

fn parse_listener_hostname(hostname: &str) -> HostnameMatch {
    if let Some(rest) = hostname.strip_prefix("*.") {
        HostnameMatch::Wildcard(Arc::from(rest))
    } else {
        HostnameMatch::Exact(Arc::from(hostname))
    }
}

/// Translate a reconciled view into proxy `RouteConfig` entries.
///
/// Routes are grouped by (listener_hostname, host_prefix) and merged so that
/// multiple HTTPRoutes attached to the same listener with the same hostname
/// produce a single `RouteConfig` containing all their paths.
pub fn translate_view(view: &GatewayView) -> Vec<RouteConfig> {
    // Key: (listener_hostname, host_prefix)
    let mut groups: HashMap<(Option<String>, String), RouteConfig> = HashMap::new();

    for http_route in &view.http_routes {
        // If the route has no accepted parent refs, skip it.
        if http_route.parent_refs.is_empty() {
            continue;
        }

        let effective = compute_effective_hostnames(http_route, &view.gateways);

        for eff in effective {
            let key = (eff.listener_hostname.clone(), eff.host_prefix.clone());

            let mut paths = Vec::new();
            let mut rewrites = Vec::new();

            for (rule_idx, rule) in http_route.rules.iter().enumerate() {
                let rule_paths = translate_rule_paths(rule, &http_route.namespace, rule_idx);
                paths.extend(rule_paths);

                for filter in &rule.filters {
                    match filter {
                        RouteFilter::UrlRewrite { hostname, path } => {
                            if let Some(rw) = translate_rewrite(path) {
                                rewrites.push(rw);
                            }
                            // hostname rewrite is handled per-path-route below
                            let _ = hostname;
                        }
                        _ => {}
                    }
                }
            }

            // If no paths were produced, create a default catch-all path
            // using the first backend from the first rule (common case).
            if paths.is_empty() && !http_route.rules.is_empty() {
                if let Some(first_backend) = http_route.rules[0].backends.first() {
                    paths.push(PathRoute {
                        prefix: "/".to_string(),
                        backend: first_backend.backend.to_string(),
                        strip_prefix: false,
                        websocket: false,
                        auth_request: None,
                        auth_capture_headers: vec![],
                        upstream_path_prefix: None,
                        path_rewrite_full: None,
                        hostname_rewrite: None,
                        timeout_secs: None,
                        mirror_backends: vec![],
                        deny: false,
                        methods: vec![],
                        weighted_backends: vec![],
                        redirect: None,
                        header_matches: vec![],
                        query_param_matches: vec![],
                        rule_order: 0,
                        path_match_exact: false,
                        request_headers: vec![],
                        request_headers_add: vec![],
                        request_headers_remove: vec![],
                        response_headers: vec![],
                        response_headers_add: vec![],
                        response_headers_remove: vec![],
                        cors: None,
                    });
                }
            }

            let group = groups.entry(key).or_insert_with(|| RouteConfig {
                host_prefix: eff.host_prefix.clone(),
                backend: paths.first().map(|p| p.backend.clone()).unwrap_or_default(),
                websocket: false,
                disable_secure_redirection: true,
                paths: vec![],
                static_root: None,
                fallback: None,
                rewrites: vec![],
                body_rewrites: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                cache: None,
            cors: None,
                timeout_secs: None,
                listener_hostname: eff.listener_hostname.clone(),
                gateway_api: true,
            });

            group.paths.extend(paths);
            group.rewrites.extend(rewrites);
            if group.backend.is_empty() && !group.paths.is_empty() {
                group.backend = group.paths[0].backend.clone();
            }
        }
    }

    let mut result: Vec<RouteConfig> = groups.into_values().collect();
    result.sort_by(|a, b| a.host_prefix.cmp(&b.host_prefix));
    result
}

fn hostname_to_prefix(hostname: &HostnameMatch) -> String {
    match hostname {
        HostnameMatch::Exact(h) => h.to_string(),
        HostnameMatch::Wildcard(h) => format!("*.{}", h),
        HostnameMatch::Any => "*".to_string(),
    }
}

fn translate_rule_paths(rule: &HTTPRouteRule, _namespace: &str, rule_idx: usize) -> Vec<PathRoute> {
    let weighted_backends: Vec<WeightedBackendConfig> = rule
        .backends
        .iter()
        .map(|b| WeightedBackendConfig {
            backend: b.backend.to_string(),
            weight: b.weight,
        })
        .collect();

    let dummy_backend = crate::gateway::model::WeightedBackend {
        backend: Arc::from("127.0.0.1:1"),
        weight: 1,
    };
    let backend = rule.backends.first().unwrap_or(&dummy_backend);

    let strip_prefix = rule
        .filters
        .iter()
        .any(|f| matches!(f, RouteFilter::UrlRewrite { path: PathRewrite::PrefixReplace { .. }, .. }));

    let upstream_path_prefix = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            path: PathRewrite::PrefixReplace { replacement, .. }, ..
        } => Some(replacement.to_string()),
        _ => None,
    });

    let path_rewrite_full = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            path: PathRewrite::FullReplace(s), ..
        } => Some(s.to_string()),
        _ => None,
    });

    let hostname_rewrite = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite { hostname: Some(h), .. } => Some(h.to_string()),
        _ => None,
    });

    let mirror_backends: Vec<String> = rule.filters.iter().filter_map(|f| match f {
        RouteFilter::RequestMirror { backend } => Some(backend.to_string()),
        _ => None,
    }).collect();

    let cors_config = rule.filters.iter().find_map(|f| match f {
        RouteFilter::Cors { allow_origins, allow_methods, allow_headers, expose_headers, max_age, allow_credentials } => {
            Some(crate::config::CorsConfig {
                allow_origins: allow_origins.iter().map(|s| s.to_string()).collect(),
                allow_methods: allow_methods.iter().map(|s| s.to_string()).collect(),
                allow_headers: allow_headers.iter().map(|s| s.to_string()).collect(),
                expose_headers: expose_headers.iter().map(|s| s.to_string()).collect(),
                max_age: *max_age,
                allow_credentials: *allow_credentials,
            })
        }
        _ => None,
    });

    let mut redirect = None;
    let mut request_headers = Vec::new();
    let mut request_headers_add = Vec::new();
    let mut request_headers_remove = Vec::new();
    let mut response_headers = Vec::new();
    let mut response_headers_add = Vec::new();
    let mut response_headers_remove = Vec::new();

    for filter in &rule.filters {
        match filter {
            RouteFilter::RequestHeaderSet { name, value } => {
                request_headers.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::RequestHeaderAdd { name, value } => {
                request_headers_add.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::RequestHeaderRemove { name } => {
                request_headers_remove.push(name.to_string());
            }
            RouteFilter::ResponseHeaderSet { name, value } => {
                response_headers.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::ResponseHeaderAdd { name, value } => {
                response_headers_add.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::ResponseHeaderRemove { name } => {
                response_headers_remove.push(name.to_string());
            }
            RouteFilter::RequestRedirect {
                scheme,
                hostname,
                path,
                port,
                status_code,
            } => {
                redirect = Some(translate_redirect(scheme, hostname, path, *port, *status_code));
            }
            _ => {}
        }
    }

    // Gateway API semantics: each RouteMatch within a rule is an independent
    // AND combination of path/headers/query/method; the list of matches is OR'd.
    // Create one PathRoute per RouteMatch so the proxy can evaluate them correctly.
    let mut result = Vec::new();

    if rule.matches.is_empty() {
        if let Some(pr) = build_path_route(
            &RouteMatch {
                path: None,
                headers: vec![],
                query_params: vec![],
                method: None,
            },
            backend,
            strip_prefix,
            upstream_path_prefix.clone(),
            path_rewrite_full.clone(),
            hostname_rewrite.clone(),
            rule.timeout_secs,
            mirror_backends.clone(),
            cors_config.clone(),
            &weighted_backends,
            redirect.clone(),
            &request_headers,
            &request_headers_add,
            &request_headers_remove,
            &response_headers,
            &response_headers_add,
            &response_headers_remove,
            rule_idx,
        ) {
            result.push(pr);
        }
    } else {
        for m in &rule.matches {
            if let Some(pr) = build_path_route(
                m,
                backend,
                strip_prefix,
                upstream_path_prefix.clone(),
                path_rewrite_full.clone(),
                hostname_rewrite.clone(),
                rule.timeout_secs,
                mirror_backends.clone(),
                cors_config.clone(),
                &weighted_backends,
                redirect.clone(),
                &request_headers,
                &request_headers_add,
                &request_headers_remove,
                &response_headers,
                &response_headers_add,
                &response_headers_remove,
                rule_idx,
            ) {
                result.push(pr);
            }
        }
    }

    result
}

fn build_path_route(
    m: &RouteMatch,
    backend: &crate::gateway::model::WeightedBackend,
    strip_prefix: bool,
    upstream_path_prefix: Option<String>,
    path_rewrite_full: Option<String>,
    hostname_rewrite: Option<String>,
    timeout_secs: Option<u64>,
    mirror_backends: Vec<String>,
    cors_config: Option<crate::config::CorsConfig>,
    weighted_backends: &[WeightedBackendConfig],
    redirect: Option<RedirectRule>,
    request_headers: &[HeaderRule],
    request_headers_add: &[HeaderRule],
    request_headers_remove: &[String],
    response_headers: &[HeaderRule],
    response_headers_add: &[HeaderRule],
    response_headers_remove: &[String],
    rule_idx: usize,
) -> Option<PathRoute> {
    let (prefix, path_match_exact) = match m.path.as_ref() {
        Some(PathMatch::Prefix(p)) => (p.to_string(), false),
        Some(PathMatch::Exact(p)) => (p.to_string(), true),
        Some(PathMatch::Regex(_)) => {
            tracing::debug!("Regex path match not supported in T1");
            return None;
        }
        None => ("/".to_string(), false),
    };
    let methods: Vec<String> = m.method.as_ref().map(|s| vec![s.to_string()]).unwrap_or_default();
    let header_matches: Vec<HeaderMatchConfig> =
        m.headers.iter().map(translate_header_match).collect();
    let query_param_matches: Vec<QueryParamMatchConfig> =
        m.query_params.iter().map(translate_query_param_match).collect();

    // For RequestRedirect ReplacePrefixMatch, the matched path prefix must be
    // captured so the proxy can compute the correct Location header.
    let redirect = redirect.map(|mut r| {
        if r.path_prefix.is_some() {
            r.path_prefix = Some(prefix.clone());
        }
        r
    });

    Some(PathRoute {
        prefix,
        backend: backend.backend.to_string(),
        strip_prefix,
        websocket: false,
        auth_request: None,
        auth_capture_headers: vec![],
        upstream_path_prefix,
        path_rewrite_full,
        hostname_rewrite,
        timeout_secs,
        mirror_backends,
        cors: cors_config,
        deny: false,
        methods,
        weighted_backends: weighted_backends.to_vec(),
        redirect,
        header_matches,
        query_param_matches,
        rule_order: rule_idx,
        path_match_exact,
        request_headers: request_headers.to_vec(),
        request_headers_add: request_headers_add.to_vec(),
        request_headers_remove: request_headers_remove.to_vec(),
        response_headers: response_headers.to_vec(),
        response_headers_add: response_headers_add.to_vec(),
        response_headers_remove: response_headers_remove.to_vec(),
    })
}

fn translate_header_match(hm: &HeaderMatch) -> HeaderMatchConfig {
    HeaderMatchConfig {
        name: hm.name.to_string(),
        value: match &hm.value {
            HeaderMatchValue::Exact(v) => HeaderMatchValueConfig::Exact(v.to_string()),
            HeaderMatchValue::Regex(v) => HeaderMatchValueConfig::Regex(v.to_string()),
            HeaderMatchValue::Present => HeaderMatchValueConfig::Present,
            HeaderMatchValue::Absent => HeaderMatchValueConfig::Absent,
        },
    }
}

fn translate_query_param_match(qm: &QueryParamMatch) -> QueryParamMatchConfig {
    QueryParamMatchConfig {
        name: qm.name.to_string(),
        value: match &qm.value {
            QueryParamMatchValue::Exact(v) => QueryParamMatchValueConfig::Exact(v.to_string()),
            QueryParamMatchValue::Regex(v) => QueryParamMatchValueConfig::Regex(v.to_string()),
        },
    }
}

fn translate_redirect(
    scheme: &Option<Arc<str>>,
    hostname: &Option<Arc<str>>,
    path: &Option<PathRewrite>,
    port: Option<u16>,
    status_code: u16,
) -> RedirectRule {
    let (path, is_prefix_replace) = match path.as_ref() {
        Some(PathRewrite::FullReplace(target)) => (Some(target.to_string()), false),
        Some(PathRewrite::PrefixReplace { replacement, .. }) => {
            (Some(replacement.to_string()), true)
        }
        None => (None, false),
    };
    RedirectRule {
        status_code,
        scheme: scheme.as_ref().map(|s| s.to_string()),
        hostname: hostname.as_ref().map(|h| h.to_string()),
        port,
        path,
        path_prefix: if is_prefix_replace { Some(String::new()) } else { None },
    }
}

fn translate_rewrite(path: &PathRewrite) -> Option<RewriteRule> {
    match path {
        PathRewrite::FullReplace(target) => Some(RewriteRule {
            pattern: "^/.*$".to_string(),
            target: target.to_string(),
        }),
        PathRewrite::PrefixReplace { prefix, replacement } => Some(RewriteRule {
            pattern: format!("^{}", regex::escape(prefix)),
            target: replacement.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{
        BackendTarget, HeaderMatch, HostnameMatch, HTTPRouteState, ListenerKey, ParentRef,
        PathMatch, PathRewrite, QueryParamMatch, RouteFilter, RouteMatch, RouteRule,
        WeightedBackend,
    };
    use std::sync::Arc;

    fn make_view(routes: Vec<HTTPRouteState>) -> GatewayView {
        GatewayView {
            gateways: vec![],
            routes: vec![],
            http_routes: routes,
            reference_grants: vec![],
        }
    }

    fn simple_route(hostnames: Vec<&str>, backend: &str) -> HTTPRouteState {
        HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("test-route"),
            generation: 1,
            hostnames: hostnames
                .into_iter()
                .map(|h| HostnameMatch::Exact(Arc::from(h)))
                .collect(),
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from(backend),
                    weight: 1,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        }
    }

    #[test]
    fn translate_single_hostname_route() {
        let view = make_view(vec![simple_route(vec!["example.com"], "10.0.0.1:80")]);
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].host_prefix, "example.com");
        assert_eq!(configs[0].paths[0].backend, "10.0.0.1:80");
        assert_eq!(configs[0].paths[0].prefix, "/");
    }

    #[test]
    fn translate_multiple_hostnames_creates_multiple_configs() {
        let view = make_view(vec![simple_route(
            vec!["a.example.com", "b.example.com"],
            "10.0.0.1:80",
        )]);
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].host_prefix, "a.example.com");
        assert_eq!(configs[1].host_prefix, "b.example.com");
    }

    #[test]
    fn translate_path_prefix_match() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("api-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("api.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/v1"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("api-svc:8080"),
                    weight: 1,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].prefix, "/v1");
        assert_eq!(configs[0].paths[0].backend, "api-svc:8080");
    }

    #[test]
    fn translate_url_rewrite_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("rewrite-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("app.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/api"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("backend:80"),
                    weight: 1,
                }],
                filters: vec![RouteFilter::UrlRewrite {
                    hostname: None,
                    path: PathRewrite::PrefixReplace {
                        prefix: Arc::from("/api"),
                        replacement: Arc::from("/v2"),
                    },
                }],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let path = &configs[0].paths[0];
        assert!(path.strip_prefix);
        assert_eq!(path.upstream_path_prefix, Some("/v2".to_string()));
        assert_eq!(configs[0].rewrites[0].target, "/v2");
    }

    #[test]
    fn translate_response_header_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("header-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("hdr.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![RouteFilter::ResponseHeaderAdd {
                    name: Arc::from("X-Custom"),
                    value: Arc::from("value"),
                }],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].response_headers_add.len(), 1);
        assert_eq!(configs[0].paths[0].response_headers_add[0].name, "X-Custom");
        assert_eq!(configs[0].paths[0].response_headers_add[0].value, "value");
    }

    #[test]
    fn translate_skips_routes_without_parent_refs() {
        let mut route = simple_route(vec!["orphan.example.com"], "10.0.0.1:80");
        route.parent_refs.clear();
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert!(configs.is_empty());
    }

    #[test]
    fn translate_wildcard_hostname() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Wildcard(Arc::from("example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].host_prefix, "*.example.com");
    }

    #[test]
    fn translate_method_match() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("method-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("m.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: Some(Arc::from("POST")),
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].methods, vec!["POST"]);
    }

    #[test]
    fn translate_weighted_backends() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("split-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("split.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![],
                backends: vec![
                    WeightedBackend {
                        backend: Arc::from("svc-a:80"),
                        weight: 3,
                    },
                    WeightedBackend {
                        backend: Arc::from("svc-b:80"),
                        weight: 7,
                    },
                ],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].weighted_backends.len(), 2);
        assert_eq!(configs[0].paths[0].weighted_backends[0].backend, "svc-a:80");
        assert_eq!(configs[0].paths[0].weighted_backends[0].weight, 3);
        assert_eq!(configs[0].paths[0].weighted_backends[1].backend, "svc-b:80");
        assert_eq!(configs[0].paths[0].weighted_backends[1].weight, 7);
    }

    #[test]
    fn translate_request_header_modifier() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("req-hdr-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("req-hdr.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![RouteFilter::RequestHeaderAdd {
                    name: Arc::from("X-In"),
                    value: Arc::from("in-value"),
                }],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].request_headers_add.len(), 1);
        assert_eq!(configs[0].paths[0].request_headers_add[0].name, "X-In");
        assert_eq!(configs[0].paths[0].request_headers_add[0].value, "in-value");
    }

    #[test]
    fn translate_request_redirect_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("redirect-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("redirect.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/old"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: Some(Arc::from("https")),
                    hostname: Some(Arc::from("new.example.com")),
                    port: Some(8443),
                    status_code: 308,
                    path: Some(PathRewrite::FullReplace(Arc::from("/new"))),
                }],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let redirect = configs[0].paths[0].redirect.as_ref().unwrap();
        assert_eq!(redirect.status_code, 308);
        assert_eq!(redirect.scheme.as_deref(), Some("https"));
        assert_eq!(redirect.hostname.as_deref(), Some("new.example.com"));
        assert_eq!(redirect.port, Some(8443));
        assert_eq!(redirect.path.as_deref(), Some("/new"));
        assert_eq!(redirect.path_prefix.as_deref(), None);
    }

    #[test]
    fn translate_request_redirect_prefix_replace_captures_matched_prefix() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("redirect-prefix-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("redirect.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/original-prefix"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: None,
                    hostname: None,
                    port: None,
                    status_code: 302,
                    path: Some(PathRewrite::PrefixReplace {
                        prefix: Arc::from("/"),
                        replacement: Arc::from("/replacement-prefix"),
                    }),
                }],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let redirect = configs[0].paths[0].redirect.as_ref().unwrap();
        assert_eq!(redirect.path.as_deref(), Some("/replacement-prefix"));
        assert_eq!(redirect.path_prefix.as_deref(), Some("/original-prefix"));
    }

    #[test]
    fn hostname_subset_exact_exact() {
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.example.com")),
            &HostnameMatch::Exact(Arc::from("foo.example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("bar.example.com")),
            &HostnameMatch::Exact(Arc::from("foo.example.com"))
        ));
    }

    #[test]
    fn hostname_subset_exact_wildcard() {
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        // Multi-level subdomains are valid for intersection (Gateway API semantics).
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.bar.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
    }

    #[test]
    fn hostname_subset_wildcard_wildcard() {
        assert!(is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("foo.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("foo.example.com"))
        ));
        assert!(is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
    }

    #[test]
    fn hostname_intersection_filters_non_subset() {
        let route = vec![
            HostnameMatch::Exact(Arc::from("bar.com")),
            HostnameMatch::Wildcard(Arc::from("example.com")),
            HostnameMatch::Wildcard(Arc::from("foo.example.com")),
            HostnameMatch::Exact(Arc::from("abc.foo.example.com")),
        ];
        let result = intersect_hostnames(&route, Some("*.example.com"));
        assert_eq!(result.len(), 3);
        assert!(!result.contains(&HostnameMatch::Exact(Arc::from("bar.com"))));
        assert!(result.contains(&HostnameMatch::Wildcard(Arc::from("example.com"))));
        assert!(result.contains(&HostnameMatch::Wildcard(Arc::from("foo.example.com"))));
        assert!(result.contains(&HostnameMatch::Exact(Arc::from("abc.foo.example.com"))));
    }

    #[test]
    fn translate_multiple_matches_in_rule_are_or_d() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("or-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("or.example.com"))],
            rules: vec![HTTPRouteRule {
                timeout_secs: None,
                matches: vec![
                    RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/path3"))),
                        headers: vec![],
                        query_params: vec![],
                        method: Some(Arc::from("PATCH")),
                    },
                    RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/path4"))),
                        headers: vec![HeaderMatch {
                            name: Arc::from("version"),
                            value: HeaderMatchValue::Exact(Arc::from("three")),
                        }],
                        query_params: vec![],
                        method: Some(Arc::from("DELETE")),
                    },
                ],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths.len(), 2);
        assert_eq!(configs[0].paths[0].prefix, "/path3");
        assert_eq!(configs[0].paths[0].methods, vec!["PATCH"]);
        assert!(configs[0].paths[0].header_matches.is_empty());
        assert_eq!(configs[0].paths[1].prefix, "/path4");
        assert_eq!(configs[0].paths[1].methods, vec!["DELETE"]);
        assert_eq!(configs[0].paths[1].header_matches.len(), 1);
    }

    #[test]
    fn translate_preserves_rule_order_for_tie_breaking() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("order-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("order.example.com"))],
            rules: vec![
                HTTPRouteRule {
                timeout_secs: None,
                    matches: vec![RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/"))),
                        headers: vec![],
                        query_params: vec![],
                        method: Some(Arc::from("PATCH")),
                    }],
                    backends: vec![WeightedBackend {
                        backend: Arc::from("v2:80"),
                        weight: 1,
                    }],
                    filters: vec![],
                },
                HTTPRouteRule {
                timeout_secs: None,
                    matches: vec![RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/"))),
                        headers: vec![HeaderMatch {
                            name: Arc::from("version"),
                            value: HeaderMatchValue::Exact(Arc::from("four")),
                        }],
                        query_params: vec![],
                        method: None,
                    }],
                    backends: vec![WeightedBackend {
                        backend: Arc::from("v3:80"),
                        weight: 1,
                    }],
                    filters: vec![],
                },
            ],
            parent_refs: vec![ParentRef {
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
            }],
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].rule_order, 0);
        assert_eq!(configs[0].paths[1].rule_order, 1);
    }
}
