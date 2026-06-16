// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::http::{translate_redirect, translate_rewrite, translate_rule_paths};
use super::{translate_view, translate_view_to_ir};
use crate::gateway::model::{
    BackendTlsAttachment, GatewayState, GatewayView, HTTPRouteRule, HTTPRouteState, HostnameMatch,
    ListenerState, ParentRef, PathMatch, PathRewrite, QueryParamMatch, QueryParamMatchValue,
    RouteFilter, RouteMatch, WeightedBackend,
};
use crate::ir::compile::CompiledRouteTable;
use std::sync::Arc;

fn make_view(routes: Vec<HTTPRouteState>) -> GatewayView {
    GatewayView {
        http_routes: routes,
        ..Default::default()
    }
}

#[test]
fn translate_url_rewrite_filter() {
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("rewrite-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("app.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/api"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("backend:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::UrlRewrite {
                hostname: None,
                path: Some(PathRewrite::PrefixReplace {
                    prefix: Arc::from("/api"),
                    replacement: Arc::from("/v2"),
                }),
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::ResponseHeaderAdd {
                name: Arc::from("X-Custom"),
                value: Arc::from("value"),
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = make_view(vec![route]);
    let configs = translate_view(&view);
    assert_eq!(configs[0].paths[0].response_headers_add.len(), 1);
    assert_eq!(configs[0].paths[0].response_headers_add[0].name, "X-Custom");
    assert_eq!(configs[0].paths[0].response_headers_add[0].value, "value");
}
#[test]
fn translate_request_header_modifier() {
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("req-hdr-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("req-hdr.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::RequestHeaderAdd {
                name: Arc::from("X-In"),
                value: Arc::from("in-value"),
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/old"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
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
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/original-prefix"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
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
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = make_view(vec![route]);
    let configs = translate_view(&view);
    let redirect = configs[0].paths[0].redirect.as_ref().unwrap();
    assert_eq!(redirect.path.as_deref(), Some("/replacement-prefix"));
    assert_eq!(redirect.path_prefix.as_deref(), Some("/original-prefix"));
}
#[test]
fn translate_rewrite_full_replace() {
    let rewrite = translate_rewrite(&PathRewrite::FullReplace(Arc::from("/new")));
    assert_eq!(rewrite.as_ref().unwrap().pattern, "^/.*$");
    assert_eq!(rewrite.as_ref().unwrap().target, "/new");
}
#[test]
fn translate_rewrite_prefix_replace() {
    let rewrite = translate_rewrite(&PathRewrite::PrefixReplace {
        prefix: Arc::from("/api"),
        replacement: Arc::from("/v2"),
    });
    assert_eq!(rewrite.as_ref().unwrap().pattern, "^/api");
    assert_eq!(rewrite.as_ref().unwrap().target, "/v2");
}
#[test]
fn translate_redirect_full_replace_no_prefix() {
    let rule = translate_redirect(
        &Some(Arc::from("https")),
        &Some(Arc::from("new.example.com")),
        &Some(PathRewrite::FullReplace(Arc::from("/redirected"))),
        Some(8443),
        307,
    );
    assert_eq!(rule.status_code, 307);
    assert_eq!(rule.scheme.as_deref(), Some("https"));
    assert_eq!(rule.hostname.as_deref(), Some("new.example.com"));
    assert_eq!(rule.port, Some(8443));
    assert_eq!(rule.path.as_deref(), Some("/redirected"));
    assert_eq!(rule.path_prefix.as_deref(), None);
}
#[test]
fn translate_redirect_prefix_replace_has_prefix() {
    let rule = translate_redirect(
        &None,
        &None,
        &Some(PathRewrite::PrefixReplace {
            prefix: Arc::from("/"),
            replacement: Arc::from("/v2"),
        }),
        None,
        302,
    );
    assert_eq!(rule.path.as_deref(), Some("/v2"));
    assert_eq!(rule.path_prefix.as_deref(), Some(""));
}
#[test]
fn build_path_route_skips_regex_path_match() {
    let rule = HTTPRouteRule {
        programmed: true,
        timeout_ms: None,
        request_timeout_ms: None,
        matches: vec![RouteMatch {
            path: Some(PathMatch::Regex(Arc::from("^/api/.*$"))),
            headers: vec![],
            query_params: vec![],
            method: None,
        }],
        backends: vec![WeightedBackend {
            backend: Arc::from("svc:80"),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,

            filters: vec![],
            tls: None,
        }],
        filters: vec![],
    };
    let paths = translate_rule_paths(&rule, "default", 0, false);
    assert!(paths.is_empty());
}
#[test]
fn translate_query_param_match_to_ir() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("query-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("query.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
                headers: vec![],
                query_params: vec![
                    QueryParamMatch {
                        name: Arc::from("page"),
                        value: QueryParamMatchValue::Exact(Arc::from("1")),
                    },
                    QueryParamMatch {
                        name: Arc::from("filter"),
                        value: QueryParamMatchValue::Regex(Arc::from(".*")),
                    },
                ],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    let matches = &rule.matches[0];
    assert_eq!(matches.query_params.len(), 2);
    assert_eq!(
        matches.query_params[0],
        crate::ir::QueryParamMatch {
            name: Arc::from("page"),
            value: crate::ir::QueryParamMatchValue::Exact(Arc::from("1")),
        }
    );
    assert_eq!(
        matches.query_params[1],
        crate::ir::QueryParamMatch {
            name: Arc::from("filter"),
            value: crate::ir::QueryParamMatchValue::Regex(Arc::from(".*")),
        }
    );
}
#[test]
fn translate_view_to_ir_request_response_filters() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("filter-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("filter.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![
                RouteFilter::RequestHeaderSet {
                    name: Arc::from("X-In"),
                    value: Arc::from("in"),
                },
                RouteFilter::ResponseHeaderSet {
                    name: Arc::from("X-Out"),
                    value: Arc::from("out"),
                },
                RouteFilter::RequestHeaderRemove {
                    name: Arc::from("X-Old"),
                },
            ],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert_eq!(action.request_filters.len(), 2);
        assert_eq!(action.response_filters.len(), 1);
    } else {
        panic!("expected Route action");
    }
}
#[test]
fn translate_view_to_ir_hostname_rewrite() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("host-rewrite"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("host.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::UrlRewrite {
                hostname: Some(Arc::from("upstream.example.com")),
                path: None,
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert!(action
                .request_filters
                .iter()
                .any(|f| matches!(f, crate::ir::RequestFilter::RewriteHostname(h) if h.as_ref() == "upstream.example.com")));
    } else {
        panic!("expected Route action");
    }
}
#[test]
fn translate_view_to_ir_cors_filter() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("cors-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("cors.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::Cors {
                allow_origins: vec![Arc::from("*")],
                allow_methods: vec![Arc::from("GET")],
                allow_headers: vec![Arc::from("X-Custom")],
                expose_headers: vec![],
                max_age: Some(600),
                allow_credentials: false,
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert!(action
            .response_filters
            .iter()
            .any(|f| matches!(f, crate::ir::ResponseFilter::Cors(_))));
    } else {
        panic!("expected Route action");
    }
}
#[test]
fn translate_view_to_ir_request_mirror() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("mirror-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("mirror.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![RouteFilter::RequestMirror {
                backend: Arc::from("mirror-svc:80"),
                fraction: None,
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert_eq!(action.mirror_backends.len(), 1);
        assert_eq!(action.mirror_backends[0].as_ref(), "mirror-svc:80");
    } else {
        panic!("expected Route action");
    }
}
#[test]
fn translate_view_to_ir_307_redirect_no_hostname_lookup() {
    let gateway = GatewayState {
        namespace: Arc::from("infra"),
        name: Arc::from("same-namespace"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("307-redirect"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/temporary"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![],
            filters: vec![RouteFilter::RequestRedirect {
                scheme: None,
                hostname: None,
                path: None,
                port: None,
                status_code: 307,
            }],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("infra")),
            name: Arc::from("same-namespace"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    eprintln!("hosts: {:?}", table.hosts);
    let compiled = CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    let plan = compiled.lookup("192.168.252.19", 80, "/temporary", "GET", &headers, None);
    eprintln!("plan: {:?}", plan);
    assert!(plan.is_some(), "expected 307 redirect plan");
    let plan = plan.unwrap();
    assert_eq!(plan.request_stages.len(), 1);
    assert!(matches!(
        plan.request_stages[0],
        crate::ir::compile::RequestStage::Terminal(crate::ir::compile::TerminalAction::Redirect(_))
    ));
}
#[test]
fn translate_view_to_ir_websocket_backend_sets_flag() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("ws-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("ws.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::WebSocket,
                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert!(action.websocket);
        assert_eq!(
            action.backends[0].protocol,
            crate::ir::BackendProtocol::WebSocket
        );
    } else {
        panic!("expected Route action");
    }
}
#[test]
fn translate_view_to_ir_attaches_backend_tls_policy() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("https"),
            protocol: Arc::from("HTTPS"),
            port: 443,
            hostname: Some(Arc::from("*.example.com")),
            tls_mode: Some(crate::gateway::model::TlsMode::Terminate),
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("tls-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("app.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:443"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Https,
                filters: vec![],
                tls: Some(BackendTlsAttachment {
                    hostname: Arc::from("svc.example.com"),
                    ca_bundle_pem: Arc::from(
                        "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
                    ),
                    subject_alt_names: vec![Arc::from("svc.example.com")],
                }),
            }],
            filters: vec![],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: None,
            name: Arc::from("gw"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![route],
        grpc_routes: vec![],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let host = table.hosts.iter().find(|h| matches!(h.hostname, crate::ir::HostnameMatch::Exact(ref s) if s.as_ref() == "app.example.com")).expect("host");
    let rule = &host.rules[0];
    let action = match &rule.action {
        crate::ir::Action::Route(a) => a,
        _ => panic!("expected route action"),
    };
    let backend = action.backends.first().expect("backend");
    assert_eq!(backend.protocol, crate::ir::BackendProtocol::Https);
    let tls = backend.tls.as_ref().expect("tls config");
    assert_eq!(tls.sni.as_ref(), "svc.example.com");
    assert!(tls.ca_bundle_pem.is_some());
    assert_eq!(tls.subject_alt_names.len(), 1);
    assert_eq!(tls.subject_alt_names[0].as_ref(), "svc.example.com");
}
