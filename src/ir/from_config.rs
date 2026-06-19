// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Temporary converter from legacy `RouteConfig` to IR.
//!
//! This exists only while TOML-based `[[routes]]` tables are still parsed at
//! startup. Once TOML routes are fully removed, this module can be deleted.

use super::*;
use crate::config::RouteConfig;
use std::collections::HashMap;
use std::sync::Arc;

/// Convert a vector of legacy `RouteConfig` into an `ir::RouteTable`.
pub fn from_route_configs(routes: &[RouteConfig]) -> RouteTable {
    let mut hosts: Vec<HostRoute> = Vec::new();

    for route in routes {
        let hostname = parse_host_prefix(&route.host_prefix);

        let mut rules: Vec<Rule> = Vec::new();
        let mut rule_order = 0usize;

        // Each PathRoute becomes a Rule with a RouteAction.
        for pr in &route.paths {
            let mut req_match = RequestMatch {
                path: Some(if pr.path_match_exact {
                    PathMatch::Exact(Arc::from(pr.prefix.as_str()))
                } else {
                    PathMatch::Prefix(Arc::from(pr.prefix.as_str()))
                }),
                ..Default::default()
            };
            if !pr.methods.is_empty() {
                req_match.method = Some(Arc::from(pr.methods[0].as_str()));
            }
            for hm in &pr.header_matches {
                req_match.headers.push(HeaderMatch {
                    name: Arc::from(hm.name.as_str()),
                    value: match &hm.value {
                        crate::config::HeaderMatchValueConfig::Exact(v) => {
                            HeaderMatchValue::Exact(Arc::from(v.as_str()))
                        }
                        crate::config::HeaderMatchValueConfig::Regex(v) => {
                            HeaderMatchValue::Regex(Arc::from(v.as_str()))
                        }
                        crate::config::HeaderMatchValueConfig::Present => HeaderMatchValue::Present,
                        crate::config::HeaderMatchValueConfig::Absent => HeaderMatchValue::Absent,
                    },
                });
            }
            for qm in &pr.query_param_matches {
                req_match.query_params.push(QueryParamMatch {
                    name: Arc::from(qm.name.as_str()),
                    value: match &qm.value {
                        crate::config::QueryParamMatchValueConfig::Exact(v) => {
                            QueryParamMatchValue::Exact(Arc::from(v.as_str()))
                        }
                        crate::config::QueryParamMatchValueConfig::Regex(v) => {
                            QueryParamMatchValue::Regex(Arc::from(v.as_str()))
                        }
                    },
                });
            }

            let mut request_filters: Vec<RequestFilter> = Vec::new();
            let mut response_filters: Vec<ResponseFilter> = Vec::new();

            if pr.strip_prefix {
                request_filters.push(RequestFilter::StripPrefix(Arc::from(pr.prefix.as_str())));
            }
            if let Some(ref upstream) = pr.upstream_path_prefix {
                request_filters.push(RequestFilter::PrependPath(Arc::from(upstream.as_str())));
            }
            if let Some(ref full) = pr.path_rewrite_full {
                request_filters.push(RequestFilter::RewritePath(PathRewrite::FullReplace(
                    Arc::from(full.as_str()),
                )));
            }
            if let Some(ref hostname) = pr.hostname_rewrite {
                request_filters.push(RequestFilter::RewriteHostname(Arc::from(hostname.as_str())));
            }
            for hdr in &pr.request_headers {
                request_filters.push(RequestFilter::SetHeader {
                    name: Arc::from(hdr.name.as_str()),
                    value: Arc::from(hdr.value.as_str()),
                });
            }
            for hdr in &pr.request_headers_add {
                request_filters.push(RequestFilter::AddHeader {
                    name: Arc::from(hdr.name.as_str()),
                    value: Arc::from(hdr.value.as_str()),
                });
            }
            for name in &pr.request_headers_remove {
                request_filters.push(RequestFilter::RemoveHeader(Arc::from(name.as_str())));
            }
            for hdr in &pr.response_headers {
                response_filters.push(ResponseFilter::SetHeader {
                    name: Arc::from(hdr.name.as_str()),
                    value: Arc::from(hdr.value.as_str()),
                });
            }
            for hdr in &pr.response_headers_add {
                response_filters.push(ResponseFilter::AddHeader {
                    name: Arc::from(hdr.name.as_str()),
                    value: Arc::from(hdr.value.as_str()),
                });
            }
            for name in &pr.response_headers_remove {
                response_filters.push(ResponseFilter::RemoveHeader(Arc::from(name.as_str())));
            }
            if let Some(ref cors) = pr.cors {
                response_filters.push(ResponseFilter::Cors(CorsConfig {
                    allow_origins: cors
                        .allow_origins
                        .iter()
                        .map(|s| Arc::from(s.as_str()))
                        .collect(),
                    allow_methods: cors
                        .allow_methods
                        .iter()
                        .map(|s| Arc::from(s.as_str()))
                        .collect(),
                    allow_headers: cors
                        .allow_headers
                        .iter()
                        .map(|s| Arc::from(s.as_str()))
                        .collect(),
                    expose_headers: cors
                        .expose_headers
                        .iter()
                        .map(|s| Arc::from(s.as_str()))
                        .collect(),
                    max_age: cors.max_age,
                    allow_credentials: cors.allow_credentials,
                }));
            }

            let action = if pr.gateway_api_unprogrammed {
                Action::FixedResponse(FixedResponseAction {
                    status: 500,
                    headers: vec![],
                    body: None,
                })
            } else if let Some(ref redirect) = pr.redirect {
                Action::Redirect(RedirectAction {
                    status_code: redirect.status_code,
                    scheme: redirect.scheme.as_ref().map(|s| Arc::from(s.as_str())),
                    hostname: redirect.hostname.as_ref().map(|s| Arc::from(s.as_str())),
                    port: redirect.port,
                    path: redirect.path.as_ref().map(|p| {
                        if let Some(ref prefix) = redirect.path_prefix {
                            PathRewrite::PrefixReplace {
                                prefix: Arc::from(prefix.as_str()),
                                replacement: Arc::from(p.as_str()),
                            }
                        } else {
                            PathRewrite::FullReplace(Arc::from(p.as_str()))
                        }
                    }),
                })
            } else if pr.deny {
                Action::FixedResponse(FixedResponseAction {
                    status: 403,
                    headers: vec![],
                    body: None,
                })
            } else {
                let backends = if pr.weighted_backends.is_empty() {
                    vec![WeightedBackend {
                        backend: Arc::from(pr.backend.as_str()),
                        weight: 1,
                        request_filters: vec![],
                        protocol: BackendProtocol::Http,
                        tls: None,
                    }]
                } else {
                    pr.weighted_backends
                        .iter()
                        .map(|wb| WeightedBackend {
                            backend: Arc::from(wb.backend.as_str()),
                            weight: wb.weight,
                            request_filters: vec![],
                            protocol: BackendProtocol::Http,
                            tls: None,
                        })
                        .collect()
                };

                Action::Route(RouteAction {
                    backends,
                    timeout: pr
                        .timeout_ms
                        .map(Duration::from_millis)
                        .or(pr.timeout_secs.map(Duration::from_secs)),
                    request_filters,
                    response_filters,
                    mirror_backends: pr
                        .mirror_backends
                        .iter()
                        .map(|s| Arc::from(s.as_str()))
                        .collect(),
                    mirror_fractions: vec![],
                    cache: route.cache.as_ref().map(|c| CachePolicy {
                        enabled: c.enabled,
                        default_ttl_secs: c.default_ttl_secs,
                        stale_while_revalidate_secs: c.stale_while_revalidate_secs,
                        max_file_size: c.max_file_size,
                    }),
                    body_rewrites: route
                        .body_rewrites
                        .iter()
                        .map(|br| BodyRewrite {
                            find: Arc::from(br.find.as_str()),
                            replace: Arc::from(br.replace.as_str()),
                            types: br.types.iter().map(|t| Arc::from(t.as_str())).collect(),
                        })
                        .collect(),
                    auth: pr.auth_request.as_ref().map(|url| AuthConfig {
                        url: Arc::from(url.as_str()),
                        capture_headers: pr
                            .auth_capture_headers
                            .iter()
                            .map(|s| Arc::from(s.as_str()))
                            .collect(),
                    }),
                    websocket: pr.websocket || route.websocket,
                    disable_https_redirect: route.disable_secure_redirection,
                    client_cert_id: None,
                })
            };

            rules.push(Rule {
                matches: vec![req_match],
                action,
                rule_order,
            });
            rule_order += 1;
        }

        // If no path routes, create a catch-all rule with host-level backend.
        if rules.is_empty() {
            rules.push(Rule {
                matches: vec![RequestMatch::default()],
                action: Action::Route(RouteAction {
                    backends: vec![WeightedBackend {
                        backend: Arc::from(route.backend.as_str()),
                        weight: 1,
                        request_filters: vec![],
                        protocol: BackendProtocol::Http,
                        tls: None,
                    }],
                    timeout: route.timeout_secs.map(Duration::from_secs),
                    request_filters: vec![],
                    response_filters: route
                        .response_headers
                        .iter()
                        .map(|h| ResponseFilter::SetHeader {
                            name: Arc::from(h.name.as_str()),
                            value: Arc::from(h.value.as_str()),
                        })
                        .chain(route.response_headers_add.iter().map(|h| {
                            ResponseFilter::AddHeader {
                                name: Arc::from(h.name.as_str()),
                                value: Arc::from(h.value.as_str()),
                            }
                        }))
                        .chain(
                            route
                                .response_headers_remove
                                .iter()
                                .map(|n| ResponseFilter::RemoveHeader(Arc::from(n.as_str()))),
                        )
                        .collect(),
                    mirror_backends: vec![],
                    mirror_fractions: vec![],
                    cache: route.cache.as_ref().map(|c| CachePolicy {
                        enabled: c.enabled,
                        default_ttl_secs: c.default_ttl_secs,
                        stale_while_revalidate_secs: c.stale_while_revalidate_secs,
                        max_file_size: c.max_file_size,
                    }),
                    body_rewrites: route
                        .body_rewrites
                        .iter()
                        .map(|br| BodyRewrite {
                            find: Arc::from(br.find.as_str()),
                            replace: Arc::from(br.replace.as_str()),
                            types: br.types.iter().map(|t| Arc::from(t.as_str())).collect(),
                        })
                        .collect(),
                    auth: None,
                    websocket: route.websocket,
                    disable_https_redirect: route.disable_secure_redirection,
                    client_cert_id: None,
                }),
                rule_order: 0,
            });
        }

        // Static file serving at host level.
        if let Some(ref root) = route.static_root {
            let static_req_match = RequestMatch {
                path: Some(PathMatch::Prefix("/".into())),
                ..Default::default()
            };
            rules.push(Rule {
                matches: vec![static_req_match],
                action: Action::StaticFiles(StaticFileAction {
                    root: Arc::from(root.as_str()),
                    fallback: route.fallback.as_ref().map(|s| Arc::from(s.as_str())),
                    rewrites: route
                        .rewrites
                        .iter()
                        .map(|r| RewriteRule {
                            pattern: Arc::from(r.pattern.as_str()),
                            target: Arc::from(r.target.as_str()),
                        })
                        .collect(),
                    extra_headers: route
                        .response_headers
                        .iter()
                        .map(|h| (Arc::from(h.name.as_str()), Arc::from(h.value.as_str())))
                        .collect(),
                }),
                rule_order,
            });
        }

        hosts.push(HostRoute {
            hostname,
            listener_ids: route
                .listener_hostname
                .as_ref()
                .map(|s| vec![Arc::from(s.as_str())])
                .unwrap_or_default(),
            listener_hostname: route.listener_hostname.as_ref().map(|s| {
                if s == "*" {
                    HostnameMatch::Any
                } else if let Some(rest) = s.strip_prefix("*.") {
                    HostnameMatch::Wildcard(Arc::from(rest))
                } else {
                    HostnameMatch::Exact(Arc::from(s.as_str()))
                }
            }),
            listener_port: None,
            gateway_api: route.gateway_api,
            disable_secure_redirection: route.disable_secure_redirection,
            rules,
        });
    }

    RouteTable {
        listeners: vec![],
        hosts,
        acme_routes: HashMap::new(),
        l4_routes: vec![],
        tls_certs: vec![],
    }
}

fn parse_host_prefix(prefix: &str) -> HostnameMatch {
    if prefix == "*" {
        HostnameMatch::Any
    } else if let Some(rest) = prefix.strip_prefix("*.") {
        HostnameMatch::Wildcard(Arc::from(rest))
    } else if prefix.contains('.') {
        HostnameMatch::Exact(Arc::from(prefix))
    } else {
        HostnameMatch::Prefix(Arc::from(prefix))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PathRoute, RouteConfig};

    #[test]
    fn empty_routes_produce_empty_table() {
        let rt = from_route_configs(&[]);
        assert!(rt.hosts.is_empty());
    }

    #[test]
    fn simple_route_conversion() {
        let routes = vec![RouteConfig {
            host_prefix: "example.com".into(),
            backend: "http://svc:8080".into(),
            websocket: false,
            disable_secure_redirection: false,
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
            listener_hostname: None,
            gateway_api: false,
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(rt.hosts.len(), 1);
        assert_eq!(
            rt.hosts[0].hostname,
            HostnameMatch::Exact("example.com".into())
        );
        assert_eq!(rt.hosts[0].rules.len(), 1);
        assert!(matches!(rt.hosts[0].rules[0].action, Action::Route(_)));
    }

    #[test]
    fn wildcard_host_prefix() {
        let routes = vec![RouteConfig {
            host_prefix: "*.example.com".into(),
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(
            rt.hosts[0].hostname,
            HostnameMatch::Wildcard("example.com".into())
        );
    }

    #[test]
    fn any_host_prefix() {
        let routes = vec![RouteConfig {
            host_prefix: "*".into(),
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(rt.hosts[0].hostname, HostnameMatch::Any);
    }

    #[test]
    fn unprogrammed_gateway_api_route_returns_500() {
        let routes = vec![RouteConfig {
            host_prefix: "invalid.example.com".into(),
            backend: "http://svc:8080".into(),
            websocket: false,
            disable_secure_redirection: true,
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "nonexistent:80".into(),
                gateway_api_unprogrammed: true,
                ..Default::default()
            }],
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
            listener_hostname: None,
            gateway_api: true,
        }];
        let rt = from_route_configs(&routes);
        let action = &rt.hosts[0].rules[0].action;
        assert_eq!(
            *action,
            Action::FixedResponse(FixedResponseAction {
                status: 500,
                headers: vec![],
                body: None,
            })
        );
    }

    impl Default for PathRoute {
        fn default() -> Self {
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: String::new(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                hostname_rewrite: None,
                timeout_secs: None,
                mirror_backends: vec![],
                cors: None,
                deny: false,
                gateway_api_unprogrammed: false,
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
            }
        }
    }

    fn simple_route() -> RouteConfig {
        RouteConfig {
            host_prefix: "example.com".into(),
            backend: "http://svc:8080".into(),
            websocket: false,
            disable_secure_redirection: false,
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
            listener_hostname: None,
            gateway_api: false,
        }
    }

    #[test]
    fn prefix_host_prefix_becomes_hostname_prefix() {
        let routes = vec![RouteConfig {
            host_prefix: "api".into(),
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(rt.hosts[0].hostname, HostnameMatch::Prefix("api".into()));
    }

    #[test]
    fn exact_path_match_conversion() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/health".into(),
                backend: "svc".into(),
                path_match_exact: true,
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let m = &rt.hosts[0].rules[0].matches[0];
        assert_eq!(m.path, Some(PathMatch::Exact("/health".into())));
    }

    #[test]
    fn method_match_conversion() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                methods: vec!["POST".into()],
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(rt.hosts[0].rules[0].matches[0].method, Some("POST".into()));
    }

    #[test]
    fn header_matches_all_variants() {
        use crate::config::HeaderMatchValueConfig;
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                header_matches: vec![
                    crate::config::HeaderMatchConfig {
                        name: "X-Exact".into(),
                        value: HeaderMatchValueConfig::Exact("v".into()),
                    },
                    crate::config::HeaderMatchConfig {
                        name: "X-Regex".into(),
                        value: HeaderMatchValueConfig::Regex(".*".into()),
                    },
                    crate::config::HeaderMatchConfig {
                        name: "X-Present".into(),
                        value: HeaderMatchValueConfig::Present,
                    },
                    crate::config::HeaderMatchConfig {
                        name: "X-Absent".into(),
                        value: HeaderMatchValueConfig::Absent,
                    },
                ],
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let headers = &rt.hosts[0].rules[0].matches[0].headers;
        assert_eq!(headers[0].value, HeaderMatchValue::Exact("v".into()));
        assert_eq!(headers[1].value, HeaderMatchValue::Regex(".*".into()));
        assert_eq!(headers[2].value, HeaderMatchValue::Present);
        assert_eq!(headers[3].value, HeaderMatchValue::Absent);
    }

    #[test]
    fn query_param_matches_both_variants() {
        use crate::config::QueryParamMatchValueConfig;
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                query_param_matches: vec![
                    crate::config::QueryParamMatchConfig {
                        name: "page".into(),
                        value: QueryParamMatchValueConfig::Exact("1".into()),
                    },
                    crate::config::QueryParamMatchConfig {
                        name: "filter".into(),
                        value: QueryParamMatchValueConfig::Regex(".*".into()),
                    },
                ],
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let qps = &rt.hosts[0].rules[0].matches[0].query_params;
        assert_eq!(qps[0].value, QueryParamMatchValue::Exact("1".into()));
        assert_eq!(qps[1].value, QueryParamMatchValue::Regex(".*".into()));
    }

    #[test]
    fn request_filters_converted() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/app".into(),
                backend: "svc".into(),
                strip_prefix: true,
                upstream_path_prefix: Some("/api".into()),
                path_rewrite_full: Some("/x".into()),
                hostname_rewrite: Some("upstream".into()),
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        assert!(
            action
                .request_filters
                .contains(&RequestFilter::StripPrefix("/app".into()))
        );
        assert!(
            action
                .request_filters
                .contains(&RequestFilter::PrependPath("/api".into()))
        );
        assert!(action.request_filters.contains(&RequestFilter::RewritePath(
            PathRewrite::FullReplace("/x".into())
        )));
        assert!(
            action
                .request_filters
                .contains(&RequestFilter::RewriteHostname("upstream".into()))
        );
    }

    #[test]
    fn request_and_response_header_filters_converted() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                request_headers: vec![crate::config::HeaderRule {
                    name: "X-Set".into(),
                    value: "a".into(),
                }],
                request_headers_add: vec![crate::config::HeaderRule {
                    name: "X-Add".into(),
                    value: "b".into(),
                }],
                request_headers_remove: vec!["X-Del".into()],
                response_headers: vec![crate::config::HeaderRule {
                    name: "Y-Set".into(),
                    value: "c".into(),
                }],
                response_headers_add: vec![crate::config::HeaderRule {
                    name: "Y-Add".into(),
                    value: "d".into(),
                }],
                response_headers_remove: vec!["Y-Del".into()],
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        assert!(action.request_filters.contains(&RequestFilter::SetHeader {
            name: "X-Set".into(),
            value: "a".into()
        }));
        assert!(action.request_filters.contains(&RequestFilter::AddHeader {
            name: "X-Add".into(),
            value: "b".into()
        }));
        assert!(
            action
                .request_filters
                .contains(&RequestFilter::RemoveHeader("X-Del".into()))
        );
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::SetHeader {
                    name: "Y-Set".into(),
                    value: "c".into()
                })
        );
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::AddHeader {
                    name: "Y-Add".into(),
                    value: "d".into()
                })
        );
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::RemoveHeader("Y-Del".into()))
        );
    }

    #[test]
    fn cors_response_filter_converted() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                cors: Some(crate::config::CorsConfig {
                    allow_origins: vec!["*".into()],
                    allow_methods: vec!["GET".into()],
                    allow_headers: vec!["Content-Type".into()],
                    expose_headers: vec!["X-Total".into()],
                    max_age: Some(3600),
                    allow_credentials: true,
                }),
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        let cors = action
            .response_filters
            .iter()
            .find_map(|f| match f {
                ResponseFilter::Cors(c) => Some(c),
                _ => None,
            })
            .expect("cors filter");
        assert_eq!(cors.allow_origins, vec!["*".into()]);
        assert_eq!(cors.allow_methods, vec!["GET".into()]);
        assert_eq!(cors.allow_headers, vec!["Content-Type".into()]);
        assert_eq!(cors.expose_headers, vec!["X-Total".into()]);
        assert_eq!(cors.max_age, Some(3600));
        assert!(cors.allow_credentials);
    }

    #[test]
    fn redirect_action_prefix_replace() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/old".into(),
                backend: "svc".into(),
                redirect: Some(crate::config::RedirectRule {
                    status_code: 302,
                    scheme: Some("https".into()),
                    hostname: Some("new.com".into()),
                    port: Some(8443),
                    path: Some("/new".into()),
                    path_prefix: Some("/old".into()),
                }),
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(
            rt.hosts[0].rules[0].action,
            Action::Redirect(RedirectAction {
                status_code: 302,
                scheme: Some("https".into()),
                hostname: Some("new.com".into()),
                port: Some(8443),
                path: Some(PathRewrite::PrefixReplace {
                    prefix: "/old".into(),
                    replacement: "/new".into(),
                }),
            })
        );
    }

    #[test]
    fn redirect_action_full_replace() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                redirect: Some(crate::config::RedirectRule {
                    status_code: 301,
                    scheme: None,
                    hostname: None,
                    port: None,
                    path: Some("/elsewhere".into()),
                    path_prefix: None,
                }),
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(
            rt.hosts[0].rules[0].action,
            Action::Redirect(RedirectAction {
                status_code: 301,
                scheme: None,
                hostname: None,
                port: None,
                path: Some(PathRewrite::FullReplace("/elsewhere".into())),
            })
        );
    }

    #[test]
    fn deny_action_returns_403() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                deny: true,
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(
            rt.hosts[0].rules[0].action,
            Action::FixedResponse(FixedResponseAction {
                status: 403,
                headers: vec![],
                body: None,
            })
        );
    }

    #[test]
    fn weighted_backends_conversion() {
        let routes = vec![RouteConfig {
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "default".into(),
                weighted_backends: vec![
                    crate::config::WeightedBackendConfig {
                        backend: "a".into(),
                        weight: 3,
                    },
                    crate::config::WeightedBackendConfig {
                        backend: "b".into(),
                        weight: 7,
                    },
                ],
                ..Default::default()
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        assert_eq!(
            action.backends,
            vec![
                WeightedBackend {
                    backend: "a".into(),
                    weight: 3,
                    protocol: BackendProtocol::Http,
                    request_filters: vec![],
                    tls: None,
                },
                WeightedBackend {
                    backend: "b".into(),
                    weight: 7,
                    protocol: BackendProtocol::Http,
                    request_filters: vec![],
                    tls: None,
                },
            ]
        );
    }

    #[test]
    fn route_action_inherits_route_level_fields() {
        let routes = vec![RouteConfig {
            host_prefix: "example.com".into(),
            backend: "http://svc:8080".into(),
            websocket: true,
            disable_secure_redirection: true,
            paths: vec![PathRoute {
                prefix: "/".into(),
                backend: "svc".into(),
                auth_request: Some("http://auth".into()),
                auth_capture_headers: vec!["X-User".into()],
                mirror_backends: vec!["http://mirror".into()],
                timeout_secs: Some(42),
                ..Default::default()
            }],
            cache: Some(crate::config::CacheConfig {
                enabled: true,
                default_ttl_secs: 120,
                stale_while_revalidate_secs: 60,
                max_file_size: 1024,
            }),
            body_rewrites: vec![crate::config::BodyRewrite {
                find: "old".into(),
                replace: "new".into(),
                types: vec!["text/html".into()],
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        assert!(action.websocket);
        assert!(action.disable_https_redirect);
        assert_eq!(action.timeout, Some(std::time::Duration::from_secs(42)));
        assert_eq!(action.mirror_backends, vec!["http://mirror".into()]);
        let cache = action.cache.as_ref().unwrap();
        assert!(cache.enabled);
        assert_eq!(cache.default_ttl_secs, 120);
        assert_eq!(action.body_rewrites.len(), 1);
        let auth = action.auth.as_ref().unwrap();
        assert_eq!(auth.url, "http://auth".into());
        assert_eq!(auth.capture_headers, vec!["X-User".into()]);
    }

    #[test]
    fn host_level_catch_all_preserves_route_level_extras() {
        let routes = vec![RouteConfig {
            response_headers: vec![crate::config::HeaderRule {
                name: "Y-Set".into(),
                value: "c".into(),
            }],
            response_headers_add: vec![crate::config::HeaderRule {
                name: "Y-Add".into(),
                value: "d".into(),
            }],
            response_headers_remove: vec!["Y-Del".into()],
            cache: Some(crate::config::CacheConfig {
                enabled: false,
                default_ttl_secs: 120,
                stale_while_revalidate_secs: 0,
                max_file_size: 0,
            }),
            body_rewrites: vec![crate::config::BodyRewrite {
                find: "a".into(),
                replace: "b".into(),
                types: vec!["text/html".into()],
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = match &rt.hosts[0].rules[0].action {
            Action::Route(r) => r,
            other => panic!("expected Route action, got {other:?}"),
        };
        assert!(action.request_filters.is_empty());
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::SetHeader {
                    name: "Y-Set".into(),
                    value: "c".into()
                })
        );
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::AddHeader {
                    name: "Y-Add".into(),
                    value: "d".into()
                })
        );
        assert!(
            action
                .response_filters
                .contains(&ResponseFilter::RemoveHeader("Y-Del".into()))
        );
        assert_eq!(action.cache.as_ref().unwrap().enabled, false);
        assert_eq!(action.body_rewrites.len(), 1);
    }

    #[test]
    fn static_files_action_converted() {
        let routes = vec![RouteConfig {
            static_root: Some("/www".into()),
            fallback: Some("index.html".into()),
            rewrites: vec![crate::config::RewriteRule {
                pattern: "^/a$".into(),
                target: "/b".into(),
            }],
            response_headers: vec![crate::config::HeaderRule {
                name: "X-Foo".into(),
                value: "bar".into(),
            }],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        let action = &rt.hosts[0].rules[1].action;
        match action {
            Action::StaticFiles(s) => {
                assert_eq!(s.root, "/www".into());
                assert_eq!(s.fallback, Some("index.html".into()));
                assert_eq!(s.rewrites.len(), 1);
                assert_eq!(s.rewrites[0].pattern, "^/a$".into());
                assert_eq!(s.extra_headers, vec![("X-Foo".into(), "bar".into())]);
            }
            other => panic!("expected StaticFiles action, got {other:?}"),
        }
    }

    #[test]
    fn listener_hostname_wildcard_and_any() {
        let routes = vec![
            RouteConfig {
                listener_hostname: Some("*.example.com".into()),
                ..simple_route()
            },
            RouteConfig {
                listener_hostname: Some("*".into()),
                host_prefix: "other".into(),
                backend: "http://svc:8080".into(),
                ..simple_route()
            },
            RouteConfig {
                listener_hostname: Some("listener.example.com".into()),
                host_prefix: "third".into(),
                backend: "http://svc:8080".into(),
                ..simple_route()
            },
        ];
        let rt = from_route_configs(&routes);
        assert_eq!(
            rt.hosts[0].listener_hostname,
            Some(HostnameMatch::Wildcard("example.com".into()))
        );
        assert_eq!(rt.hosts[0].listener_ids, vec!["*.example.com".into()]);
        assert_eq!(rt.hosts[1].listener_hostname, Some(HostnameMatch::Any));
        assert_eq!(
            rt.hosts[2].listener_hostname,
            Some(HostnameMatch::Exact("listener.example.com".into()))
        );
        assert_eq!(
            rt.hosts[2].listener_ids,
            vec!["listener.example.com".into()]
        );
    }

    #[test]
    fn rule_order_increments_per_path() {
        let routes = vec![RouteConfig {
            paths: vec![
                PathRoute {
                    timeout_ms: None,
                    prefix: "/a".into(),
                    backend: "a".into(),
                    ..Default::default()
                },
                PathRoute {
                    timeout_ms: None,
                    prefix: "/b".into(),
                    backend: "b".into(),
                    ..Default::default()
                },
            ],
            ..simple_route()
        }];
        let rt = from_route_configs(&routes);
        assert_eq!(rt.hosts[0].rules[0].rule_order, 0);
        assert_eq!(rt.hosts[0].rules[1].rule_order, 1);
    }
}
