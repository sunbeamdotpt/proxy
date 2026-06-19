// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{translate_view, translate_view_to_ir};
use crate::gateway::model::{
    GatewayState, GatewayView, HTTPRouteRule, HTTPRouteState, HeaderMatch, HeaderMatchValue,
    HostnameMatch, ListenerState, ParentRef, PathMatch, PathRewrite, RouteFilter, RouteMatch,
    WeightedBackend,
};
use crate::ir::compile::CompiledRouteTable;
use std::sync::Arc;

fn make_view(routes: Vec<HTTPRouteState>) -> GatewayView {
    GatewayView {
        http_routes: routes,
        ..Default::default()
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
                backend: Arc::from(backend),
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/v1"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("api-svc:8080"),
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
    let view = make_view(vec![route]);
    let configs = translate_view(&view);
    assert_eq!(configs[0].paths[0].prefix, "/v1");
    assert_eq!(configs[0].paths[0].backend, "api-svc:8080");
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
                headers: vec![],
                query_params: vec![],
                method: Some(Arc::from("POST")),
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
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![
                WeightedBackend {
                    backend: Arc::from("svc-a:80"),
                    weight: 3,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                },
                WeightedBackend {
                    backend: Arc::from("svc-b:80"),
                    weight: 7,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                },
            ],
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
    let view = make_view(vec![route]);
    let configs = translate_view(&view);
    assert_eq!(configs[0].paths[0].weighted_backends.len(), 2);
    assert_eq!(configs[0].paths[0].weighted_backends[0].backend, "svc-a:80");
    assert_eq!(configs[0].paths[0].weighted_backends[0].weight, 3);
    assert_eq!(configs[0].paths[0].weighted_backends[1].backend, "svc-b:80");
    assert_eq!(configs[0].paths[0].weighted_backends[1].weight, 7);
}
#[test]
fn translate_multiple_matches_in_rule_are_or_d() {
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("or-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("or.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
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
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: Some(Arc::from("PATCH")),
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("v2:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            },
            HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
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
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            },
        ],
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
    assert_eq!(configs[0].paths[0].rule_order, 0);
    assert_eq!(configs[0].paths[1].rule_order, 1);
}
#[test]
fn translate_view_to_ir_any_hostname_for_empty_listener_and_route() {
    let gateway = crate::gateway::model::GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![crate::gateway::model::ListenerState {
            programmed: true,
            name: Arc::from("http"),
            hostname: None,
            port: 80,
            protocol: Arc::from("HTTP"),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("test-route"),
        generation: 1,
        hostnames: vec![],
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
    assert_eq!(table.hosts.len(), 1);
    assert_eq!(table.hosts[0].hostname, crate::ir::HostnameMatch::Any);
    assert_eq!(
        table.hosts[0].listener_hostname,
        Some(crate::ir::HostnameMatch::Exact(Arc::from("")))
    );
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    assert!(
        compiled
            .lookup("", 80, "/", "GET", &headers, None)
            .is_some()
    );
    assert!(
        compiled
            .lookup("example.com", 80, "/", "GET", &headers, None)
            .is_some()
    );
}
#[test]
fn translate_view_to_ir_route_hostnames_with_empty_listener() {
    let gateway = crate::gateway::model::GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![crate::gateway::model::ListenerState {
            programmed: true,
            name: Arc::from("http"),
            hostname: None,
            port: 80,
            protocol: Arc::from("HTTP"),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("test-route"),
        generation: 1,
        hostnames: vec![
            HostnameMatch::Exact(Arc::from("first.com")),
            HostnameMatch::Exact(Arc::from("sub.first.com")),
            HostnameMatch::Exact(Arc::from("second.com")),
            HostnameMatch::Exact(Arc::from("sub.second.com")),
        ],
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
    assert_eq!(table.hosts.len(), 4);
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    assert!(
        compiled
            .lookup("first.com", 80, "/", "GET", &headers, None)
            .is_some()
    );
    assert!(
        compiled
            .lookup("third.com", 80, "/", "GET", &headers, None)
            .is_none()
    );
    assert!(
        compiled
            .lookup("sub.third.com", 80, "/", "GET", &headers, None)
            .is_none()
    );
}
#[test]
fn translate_view_to_ir_unprogrammed_route_returns_500() {
    let gateway = crate::gateway::model::GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![crate::gateway::model::ListenerState {
            programmed: true,
            name: Arc::from("http"),
            hostname: None,
            port: 80,
            protocol: Arc::from("HTTP"),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("unprogrammed-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: false,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
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
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: false,
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
    assert_eq!(table.hosts.len(), 1);
    let rule = &table.hosts[0].rules[0];
    assert_eq!(rule.matches.len(), 1);
    assert!(
        matches!(&rule.action, crate::ir::Action::FixedResponse(resp) if resp.status == 500),
        "unprogrammed route should return 500, got {:?}",
        rule.action
    );
}
#[test]
fn translate_view_to_ir_fixes_redirect_prefix_replace() {
    let gateway = crate::gateway::model::GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![crate::gateway::model::ListenerState {
            programmed: true,
            name: Arc::from("http"),
            hostname: None,
            port: 80,
            protocol: Arc::from("HTTP"),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("redirect-route"),
        generation: 1,
        hostnames: vec![],
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
            backends: vec![],
            filters: vec![RouteFilter::RequestRedirect {
                scheme: None,
                hostname: None,
                path: Some(PathRewrite::PrefixReplace {
                    prefix: Arc::from("/"),
                    replacement: Arc::from("/v2"),
                }),
                port: None,
                status_code: 302,
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
    assert_eq!(table.hosts.len(), 1);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Redirect(redirect) = &rule.action {
        if let Some(crate::ir::PathRewrite::PrefixReplace {
            prefix,
            replacement,
        }) = &redirect.path
        {
            assert_eq!(prefix.as_ref(), "/api");
            assert_eq!(replacement.as_ref(), "/v2");
        } else {
            panic!("expected PrefixReplace");
        }
    } else {
        panic!("expected Redirect action");
    }
}
#[test]
fn debug_both_routes_lookup_wildcard() {
    let gateway = GatewayState {
        namespace: Arc::from("infra"),
        name: Arc::from("gw"),
        generation: 1,
        listeners: vec![
            ListenerState {
                programmed: true,
                name: Arc::from("empty-hostname"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("wildcard-example-com"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: None,
                frontend_validation: None,
            },
        ],
        backend_client_cert_id: None,
    };
    let empty_route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("empty-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/empty-hostname"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("empty-backend.infra.svc.cluster.local.:8080"),
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

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("empty-hostname")),
            port: None,
        }],
        programmed: true,
    };
    let wildcard_route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("wildcard-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("wildcard-backend.infra.svc.cluster.local.:8080"),
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

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("wildcard-example-com")),
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![empty_route, wildcard_route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    let plan = compiled.lookup(
        "bar.example.com",
        80,
        "/wildcard-example-com",
        "GET",
        &headers,
        None,
    );
    assert!(plan.is_some(), "expected wildcard plan");
    let plan = plan.unwrap();
    assert!(plan.upstream.is_some(), "expected upstream");
    assert_eq!(
        plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
        "wildcard-backend.infra.svc.cluster.local.:8080"
    );
}
#[test]
fn listener_isolation_empty_listener_loses_to_wildcard_listener() {
    // A route on an empty-hostname listener is a catch-all but must not
    // receive traffic for hosts that match a more specific listener.
    let gateway = GatewayState {
        namespace: Arc::from("infra"),
        name: Arc::from("gw"),
        generation: 1,
        listeners: vec![
            ListenerState {
                programmed: true,
                name: Arc::from("empty-hostname"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("wildcard-example-com"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: None,
                frontend_validation: None,
            },
        ],
        backend_client_cert_id: None,
    };
    let empty_route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("empty-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/empty-hostname"))),
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
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("empty-hostname")),
            port: None,
        }],
        programmed: true,
    };
    let wildcard_route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("wildcard-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
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
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("wildcard-example-com")),
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![empty_route, wildcard_route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    // Empty-listener route is used when no more specific listener matches.
    assert!(
        compiled
            .lookup("bar.com", 80, "/empty-hostname", "GET", &headers, None)
            .is_some()
    );
    assert!(
        compiled
            .lookup(
                "bar.example.com",
                80,
                "/empty-hostname",
                "GET",
                &headers,
                None
            )
            .is_none()
    );
    // Wildcard-listener route is used for matching hosts.
    assert!(
        compiled
            .lookup(
                "bar.example.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_some()
    );
    assert!(
        compiled
            .lookup(
                "bar.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_none()
    );
}
#[test]
fn debug_wildcard_route_has_upstream() {
    let gateway = GatewayState {
        namespace: Arc::from("infra"),
        name: Arc::from("gw"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("wildcard-example-com"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: Some(Arc::from("*.example.com")),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("wildcard-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("infra-backend-v1.infra.svc.cluster.local.:8080"),
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

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("wildcard-example-com")),
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
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    let plan = compiled.lookup(
        "bar.example.com",
        80,
        "/wildcard-example-com",
        "GET",
        &headers,
        None,
    );
    assert!(plan.is_some(), "expected plan for wildcard route");
    assert!(
        plan.unwrap().upstream.is_some(),
        "expected upstream action in plan"
    );
}
#[test]
fn listener_isolation_wildcard_listener_matches_subdomain() {
    // Gateway listener *.example.com + route with no hostnames should match
    // bar.example.com for the listener's path.
    let gateway = GatewayState {
        namespace: Arc::from("infra"),
        name: Arc::from("gw"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("wildcard-example-com"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: Some(Arc::from("*.example.com")),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("infra"),
        name: Arc::from("wildcard-route"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
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
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("infra")),
            name: Arc::from("gw"),
            section_name: Some(Arc::from("wildcard-example-com")),
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
    let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
    let headers = http::header::HeaderMap::new();
    assert!(
        compiled
            .lookup(
                "bar.example.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_some()
    );
}
#[test]
fn translate_unprogrammed_route_keeps_path_and_marks_unprogrammed() {
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("unprogrammed-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("invalid.example.com"))],
        rules: vec![HTTPRouteRule {
            programmed: false,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("nonexistent-svc:80"),
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
        programmed: false,
    };
    let view = make_view(vec![route]);
    let configs = translate_view(&view);
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].paths.len(), 1);
    assert!(configs[0].paths[0].gateway_api_unprogrammed);
}
#[test]
fn single_route_with_multiple_parent_refs_matches_conformance_scenario() {
    // Same scenario as above, but backend-v3 is a single HTTPRoute with two
    // parentRefs (listener-3 and listener-4) just like the real conformance
    // manifest, instead of two separate route states.
    let gateway = GatewayState {
        namespace: Arc::from("gateway-conformance-infra"),
        name: Arc::from("httproute-listener-hostname-matching"),
        generation: 1,
        listeners: vec![
            ListenerState {
                programmed: true,
                name: Arc::from("listener-1"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("bar.com")),
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("listener-2"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("foo.bar.com")),
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("listener-3"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.bar.com")),
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("listener-4"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.foo.com")),
                tls_mode: None,
                frontend_validation: None,
            },
        ],
        backend_client_cert_id: None,
    };

    fn route(name: &str, listeners: &[&str], backend: &str) -> HTTPRouteState {
        HTTPRouteState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from(name),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from(backend),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: listeners
                .iter()
                .map(|l| ParentRef {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("Gateway"),

                    namespace: Some(Arc::from("gateway-conformance-infra")),
                    name: Arc::from("httproute-listener-hostname-matching"),
                    section_name: Some(Arc::from(*l)),
                    port: None,
                })
                .collect(),
            programmed: true,
        }
    }

    let routes = vec![
        route("backend-v1", &["listener-1"], "infra-backend-v1:8080"),
        route("backend-v2", &["listener-2"], "infra-backend-v2:8080"),
        route(
            "backend-v3",
            &["listener-3", "listener-4"],
            "infra-backend-v3:8080",
        ),
    ];

    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: routes,
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };

    let ir = translate_view_to_ir(&view);
    let compiled = CompiledRouteTable::compile(ir).unwrap();

    fn backend_for(compiled: &CompiledRouteTable, host: &str) -> Option<Arc<str>> {
        let plan = compiled.lookup(host, 80, "/", "GET", &Default::default(), None)?;
        plan.upstream
            .as_ref()
            .map(|u| Arc::clone(&u.backends[0].backend))
    }

    assert_eq!(
        backend_for(&compiled, "bar.com").as_deref(),
        Some("infra-backend-v1:8080")
    );
    assert_eq!(
        backend_for(&compiled, "foo.bar.com").as_deref(),
        Some("infra-backend-v2:8080")
    );
    assert_eq!(
        backend_for(&compiled, "multiple.prefixes.bar.com").as_deref(),
        Some("infra-backend-v3:8080")
    );
    assert_eq!(
        backend_for(&compiled, "one.foo.com").as_deref(),
        Some("infra-backend-v3:8080")
    );
}
#[test]
fn unprogrammed_invalid_backend_route_returns_500() {
    let gateway = GatewayState {
        namespace: Arc::from("gateway-conformance-infra"),
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
        namespace: Arc::from("gateway-conformance-infra"),
        name: Arc::from("invalid-backend-ref-unknown-kind"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: false,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(Arc::from("/"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from(
                    "infra-backend-v1.gateway-conformance-infra.svc.cluster.local.:8080",
                ),
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

            namespace: Some(Arc::from("gateway-conformance-infra")),
            name: Arc::from("same-namespace"),
            section_name: None,
            port: None,
        }],
        programmed: false,
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
    let compiled = CompiledRouteTable::compile(table).unwrap();
    let plan = compiled.lookup("", 80, "/", "GET", &Default::default(), None);
    assert!(
        plan.is_some(),
        "unprogrammed route should still match so it can return 500"
    );
    let plan = plan.unwrap();
    assert!(
        plan.upstream.is_none(),
        "unprogrammed route must not have an upstream, got {:?}",
        plan.upstream
    );
}
