// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::hostnames::{intersect_hostnames, is_hostname_subset};
use super::{translate_view, translate_view_to_ir};
use crate::gateway::model::{
    GatewayState, GatewayView, HTTPRouteRule, HTTPRouteState, HostnameMatch, ListenerState,
    ParentRef, PathMatch, RouteMatch, WeightedBackend,
};
use crate::ir::compile::CompiledRouteTable;
use std::sync::Arc;

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
fn compute_effective_hostnames_intersects_with_listener_hostname() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: Some(Arc::from("*.example.com")),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = HTTPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("route"),
        generation: 1,
        hostnames: vec![
            HostnameMatch::Exact(Arc::from("foo.example.com")),
            HostnameMatch::Exact(Arc::from("bar.other.com")),
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
    let configs = translate_view(&view);
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].host_prefix, "foo.example.com");
}
#[test]
fn hostname_intersection_yields_only_intersected_hosts() {
    // Reproduces the HTTPRouteHostnameIntersection conformance manifest.
    let specific_gateway = GatewayState {
        namespace: Arc::from("gateway-conformance-infra"),
        name: Arc::from("httproute-hostname-intersection"),
        generation: 1,
        listeners: vec![
            ListenerState {
                programmed: true,
                name: Arc::from("listener-1"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("very.specific.com")),
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("listener-2"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.wildcard.io")),
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("listener-3"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.anotherwildcard.io")),
                tls_mode: None,
                frontend_validation: None,
            },
        ],
        backend_client_cert_id: None,
    };
    let all_gateway = GatewayState {
        namespace: Arc::from("gateway-conformance-infra"),
        name: Arc::from("httproute-hostname-intersection-all"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("listener-1"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };

    fn route(
        name: &str,
        gw: &str,
        hostnames: &[&str],
        path: &str,
        backend: &str,
    ) -> HTTPRouteState {
        HTTPRouteState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from(name),
            generation: 1,
            hostnames: hostnames
                .iter()
                .map(|h| {
                    if let Some(rest) = h.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(*h))
                    }
                })
                .collect(),
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from(path))),
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

                namespace: Some(Arc::from("gateway-conformance-infra")),
                name: Arc::from(gw),
                section_name: None,
                port: None,
            }],
            programmed: true,
        }
    }

    let routes = vec![
        route(
            "specific-host-matches-listener-specific-host",
            "httproute-hostname-intersection",
            &[
                "non.matching.com",
                "*.nonmatchingwildcard.io",
                "very.specific.com",
            ],
            "/s1",
            "infra-backend-v1:8080",
        ),
        route(
            "specific-host-matches-listener-wildcard-host",
            "httproute-hostname-intersection",
            &[
                "non.matching.com",
                "wildcard.io",
                "foo.wildcard.io",
                "bar.wildcard.io",
                "foo.bar.wildcard.io",
            ],
            "/s2",
            "infra-backend-v2:8080",
        ),
        route(
            "wildcard-host-matches-listener-specific-host",
            "httproute-hostname-intersection",
            &["non.matching.com", "*.specific.com"],
            "/s3",
            "infra-backend-v3:8080",
        ),
        route(
            "wildcard-host-matches-listener-wildcard-host",
            "httproute-hostname-intersection",
            &["*.anotherwildcard.io"],
            "/s4",
            "infra-backend-v1:8080",
        ),
        route(
            "no-intersecting-hosts",
            "httproute-hostname-intersection",
            &["specific.but.wrong.com", "wildcard.io"],
            "/s5",
            "infra-backend-v2:8080",
        ),
        route(
            "httproute-hostname-intersection-all",
            "httproute-hostname-intersection-all",
            &["first.com", "sub.first.com", "second.com", "sub.second.com"],
            "/",
            "infra-backend-v2:8080",
        ),
    ];

    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![specific_gateway, all_gateway],
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

    fn backend_for(compiled: &CompiledRouteTable, host: &str, path: &str) -> Option<Arc<str>> {
        let plan = compiled.lookup(host, 80, path, "GET", &Default::default(), None)?;
        plan.upstream
            .as_ref()
            .map(|u| Arc::clone(&u.backends[0].backend))
    }

    // Intersecting hostnames should route to the expected backend.
    assert_eq!(
        backend_for(&compiled, "very.specific.com", "/s1").as_deref(),
        Some("infra-backend-v1:8080"),
        "very.specific.com/s1 should route"
    );
    assert_eq!(
        backend_for(&compiled, "foo.wildcard.io", "/s2").as_deref(),
        Some("infra-backend-v2:8080"),
        "foo.wildcard.io/s2 should route"
    );
    assert_eq!(
        backend_for(&compiled, "bar.wildcard.io", "/s2").as_deref(),
        Some("infra-backend-v2:8080"),
        "bar.wildcard.io/s2 should route"
    );
    assert_eq!(
        backend_for(&compiled, "foo.bar.wildcard.io", "/s2").as_deref(),
        Some("infra-backend-v2:8080"),
        "foo.bar.wildcard.io/s2 should route"
    );
    assert_eq!(
        backend_for(&compiled, "very.specific.com", "/s3").as_deref(),
        Some("infra-backend-v3:8080"),
        "very.specific.com/s3 should route"
    );
    assert_eq!(
        backend_for(&compiled, "sub.anotherwildcard.io", "/s4").as_deref(),
        Some("infra-backend-v1:8080"),
        "sub.anotherwildcard.io/s4 should route"
    );
    assert!(
        backend_for(&compiled, "foo.specific.com", "/s3").is_none(),
        "foo.specific.com/s3 should not match; intersection is very.specific.com"
    );
    assert_eq!(
        backend_for(&compiled, "first.com", "/").as_deref(),
        Some("infra-backend-v2:8080"),
        "first.com/ should route"
    );

    // Non-intersecting hostnames should not match any route.
    assert!(
        backend_for(&compiled, "non.matching.com", "/s1").is_none(),
        "non.matching.com/s1 should not match"
    );
    assert!(
        backend_for(&compiled, "foo.nonmatchingwildcard.io", "/s1").is_none(),
        "foo.nonmatchingwildcard.io/s1 should not match"
    );
    assert!(
        backend_for(&compiled, "wildcard.io", "/s2").is_none(),
        "wildcard.io/s2 should not match *.wildcard.io"
    );
    assert!(
        backend_for(&compiled, "non.matching.com", "/s2").is_none(),
        "non.matching.com/s2 should not match"
    );
    assert!(
        backend_for(&compiled, "non.matching.com", "/s3").is_none(),
        "non.matching.com/s3 should not match"
    );
    assert!(
        backend_for(&compiled, "anotherwildcard.io", "/s4").is_none(),
        "anotherwildcard.io/s4 should not match *.anotherwildcard.io"
    );
    assert!(
        backend_for(&compiled, "specific.but.wrong.com", "/s5").is_none(),
        "specific.but.wrong.com/s5 should not match"
    );
    assert!(
        backend_for(&compiled, "wildcard.io", "/s5").is_none(),
        "wildcard.io/s5 should not match *.wildcard.io"
    );
    assert!(
        backend_for(&compiled, "third.com", "/").is_none(),
        "third.com/ should not match"
    );
}
#[test]
fn listener_hostname_isolation_matches_conformance_scenario() {
    // Reproduces the HTTPRouteListenerHostnameMatching conformance Gateway:
    // four HTTP listeners with distinct hostnames, three HTTPRoutes attached
    // by sectionName and with no route hostnames.
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

    fn route_for_listener(name: &str, listener: &str, backend: &str) -> HTTPRouteState {
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
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("gateway-conformance-infra")),
                name: Arc::from("httproute-listener-hostname-matching"),
                section_name: Some(Arc::from(listener)),
                port: None,
            }],
            programmed: true,
        }
    }

    let routes = vec![
        route_for_listener("backend-v1", "listener-1", "infra-backend-v1:8080"),
        route_for_listener("backend-v2", "listener-2", "infra-backend-v2:8080"),
        route_for_listener("backend-v3", "listener-3", "infra-backend-v3:8080"),
        route_for_listener("backend-v3", "listener-4", "infra-backend-v3:8080"),
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
