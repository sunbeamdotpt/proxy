// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Route / listener translation layer.
//!
//! Converts a `GatewayView` into Pingora-native configuration.

use crate::config::{HeaderRule, PathRoute, RewriteRule, RouteConfig};
use crate::gateway::model::{
    GatewayView, HostnameMatch, HTTPRouteRule, PathMatch, PathRewrite, RouteFilter, WeightedBackend,
};

/// Translate a reconciled view into proxy `RouteConfig` entries.
///
/// Each distinct hostname on an HTTPRoute produces one `RouteConfig`.
/// Rules within that HTTPRoute become `PathRoute` entries under the
/// corresponding `RouteConfig`.
pub fn translate_view(view: &GatewayView) -> Vec<RouteConfig> {
    let mut configs = Vec::new();

    for http_route in &view.http_routes {
        // If the route has no accepted parent refs, skip it.
        if http_route.parent_refs.is_empty() {
            continue;
        }

        let hostnames = if http_route.hostnames.is_empty() {
            vec![HostnameMatch::Any]
        } else {
            http_route.hostnames.clone()
        };

        for hostname in &hostnames {
            let host_prefix = hostname_to_prefix(hostname);

            let mut paths = Vec::new();
            let mut rewrites = Vec::new();
            let mut response_headers = Vec::new();

            for rule in &http_route.rules {
                if let Some(path_route) = translate_rule_path(rule, &http_route.namespace) {
                    paths.push(path_route);
                }

                for filter in &rule.filters {
                    match filter {
                        RouteFilter::UrlRewrite { path } => {
                            if let Some(rw) = translate_rewrite(path) {
                                rewrites.push(rw);
                            }
                        }
                        RouteFilter::ResponseHeaderAdd { name, value } => {
                            response_headers.push(HeaderRule {
                                name: name.to_string(),
                                value: value.to_string(),
                            });
                        }
                        _ => {
                            // Request header filters are applied in the proxy
                            // request filter; skip for now in T1.
                            tracing::debug!(filter = ?filter, "skipping unsupported filter in T1");
                        }
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
                        timeout_secs: None,
                        deny: false,
                    });
                }
            }

            configs.push(RouteConfig {
                host_prefix,
                backend: paths.first().map(|p| p.backend.clone()).unwrap_or_default(),
                websocket: false,
                disable_secure_redirection: false,
                paths,
                static_root: None,
                fallback: None,
                rewrites,
                body_rewrites: vec![],
                response_headers,
                cache: None,
                timeout_secs: None,
            });
        }
    }

    configs
}

fn hostname_to_prefix(hostname: &HostnameMatch) -> String {
    match hostname {
        HostnameMatch::Exact(h) => h.to_string(),
        HostnameMatch::Wildcard(h) => format!("*.{}", h),
        HostnameMatch::Any => "*".to_string(),
    }
}

fn translate_rule_path(rule: &HTTPRouteRule, _namespace: &str) -> Option<PathRoute> {
    // In T1 we only support a single path match per rule.
    let path_match = rule.matches.iter().find_map(|m| m.path.as_ref());
    let prefix = match path_match {
        Some(PathMatch::Prefix(p)) => p.to_string(),
        Some(PathMatch::Exact(p)) => p.to_string(),
        Some(PathMatch::Regex(_)) => {
            tracing::debug!("Regex path match not supported in T1");
            return None;
        }
        None => "/".to_string(),
    };

    let backend = rule.backends.first()?;
    let strip_prefix = rule
        .filters
        .iter()
        .any(|f| matches!(f, RouteFilter::UrlRewrite { path: PathRewrite::PrefixReplace { .. } }));

    let upstream_path_prefix = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            path: PathRewrite::PrefixReplace { replacement, .. },
        } => Some(replacement.to_string()),
        _ => None,
    });

    Some(PathRoute {
        prefix,
        backend: backend.backend.to_string(),
        strip_prefix,
        websocket: false,
        auth_request: None,
        auth_capture_headers: vec![],
        upstream_path_prefix,
        timeout_secs: None,
        deny: false,
    })
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
        assert_eq!(configs[0].response_headers.len(), 1);
        assert_eq!(configs[0].response_headers[0].name, "X-Custom");
        assert_eq!(configs[0].response_headers[0].value, "value");
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
}
