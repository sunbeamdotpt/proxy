// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::super::*;
use std::sync::Arc;

fn arc(s: &str) -> Arc<str> {
    Arc::from(s)
}

fn sample_view() -> ReconciledView {
    ReconciledView {
        listener_sets: vec![],
        gateways: vec![GatewayState {
            namespace: arc("default"),
            name: arc("gw-1"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    programmed: true,
                    name: arc("http"),
                    protocol: arc("HTTP"),
                    port: 80,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    programmed: true,
                    name: arc("https"),
                    protocol: arc("HTTPS"),
                    port: 443,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        }],
        routes: vec![RouteState {
            namespace: arc("default"),
            name: arc("route-a"),
            kind: arc("HTTPRoute"),
            generation: 2,
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(arc("default")),
                name: arc("gw-1"),
                section_name: Some(arc("http")),
                port: None,
            }],
        }],
        http_routes: vec![],
        reference_grants: vec![ReferenceGrantState {
            namespace: arc("default"),
            name: arc("grant-1"),
            generation: 1,
            from: vec![GrantSubject {
                group: arc("gateway.networking.k8s.io"),
                kind: arc("HTTPRoute"),
                namespace: Some(arc("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: arc(""),
                kind: arc("Service"),
                namespace: Some(arc("default")),
                name: Some(arc("svc-1")),
            }],
        }],
        ..Default::default()
    }
}

// (a) Equivalent inputs — including different collection orderings —
//     must produce identical hashes.
#[test]
fn equivalent_inputs_same_hash() {
    let base = sample_view();
    let h1 = compute_digest(&base);

    // Same data, re-ordered listeners.
    let mut reordered = base.clone();
    reordered.gateways[0].listeners.reverse();
    let h2 = compute_digest(&reordered);
    assert_eq!(h1, h2, "listener reordering changed the digest");

    // Same data, re-ordered routes.
    let mut reordered_routes = base.clone();
    reordered_routes.routes.push(RouteState {
        namespace: arc("default"),
        name: arc("route-b"),
        kind: arc("HTTPRoute"),
        generation: 1,
        parent_refs: vec![],
    });
    reordered_routes.routes.swap(0, 1);
    let h3 = compute_digest(&reordered_routes);
    // Build the same set in a different order.
    let mut ordered_routes = base.clone();
    ordered_routes.routes.push(RouteState {
        namespace: arc("default"),
        name: arc("route-b"),
        kind: arc("HTTPRoute"),
        generation: 1,
        parent_refs: vec![],
    });
    let h4 = compute_digest(&ordered_routes);
    assert_eq!(h3, h4, "route reordering changed the digest");
}

// (b) Non-equivalent inputs must produce different hashes.
#[test]
fn non_equivalent_inputs_different_hash() {
    let base = sample_view();
    let h1 = compute_digest(&base);

    let mut changed = base.clone();
    changed.gateways[0].generation = 42;
    let h2 = compute_digest(&changed);
    assert_ne!(h1, h2, "generation change did not alter digest");

    let mut changed = base.clone();
    changed.routes[0].name = arc("route-b");
    let h3 = compute_digest(&changed);
    assert_ne!(h1, h3, "route name change did not alter digest");

    let mut changed = base.clone();
    changed.reference_grants.clear();
    let h4 = compute_digest(&changed);
    assert_ne!(h1, h4, "removing grants did not alter digest");
}

// Extra stability test: two independently constructed identical views.
#[test]
fn independent_construction_same_hash() {
    let a = sample_view();
    let b = sample_view();
    assert_eq!(compute_digest(&a), compute_digest(&b));
}

// Verify that different structurally-equivalent strings still hash
// differently (i.e. we aren't accidentally normalising away data).
#[test]
fn string_content_matters() {
    let mut a = sample_view();
    a.gateways[0].name = arc("gw-1");

    let mut b = sample_view();
    b.gateways[0].name = arc("gw-2");

    assert_ne!(compute_digest(&a), compute_digest(&b));
}

use crate::gateway::model::routing::{
    HTTPRouteRule, HostnameMatch, PathMatch, RouteMatch, WeightedBackend,
};

fn view_with_http_routes(routes: Vec<HTTPRouteState>) -> ReconciledView {
    ReconciledView {
        http_routes: routes,
        ..Default::default()
    }
}

fn http_route(name: &str, hostnames: Vec<HostnameMatch>, generation: i64) -> HTTPRouteState {
    HTTPRouteState {
        namespace: arc("default"),
        name: arc(name),
        generation,
        hostnames,
        rules: vec![],
        parent_refs: vec![],
        programmed: true,
    }
}

#[test]
fn http_route_hostname_changes_digest() {
    let a = view_with_http_routes(vec![http_route(
        "r1",
        vec![HostnameMatch::Exact(arc("a.example.com"))],
        1,
    )]);
    let b = view_with_http_routes(vec![http_route(
        "r1",
        vec![HostnameMatch::Exact(arc("b.example.com"))],
        1,
    )]);
    assert_ne!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_wildcard_and_exact_differ() {
    let a = view_with_http_routes(vec![http_route(
        "r1",
        vec![HostnameMatch::Exact(arc("example.com"))],
        1,
    )]);
    let b = view_with_http_routes(vec![http_route(
        "r1",
        vec![HostnameMatch::Wildcard(arc("example.com"))],
        1,
    )]);
    assert_ne!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_hostname_reordering_stable() {
    let mut a = view_with_http_routes(vec![http_route(
        "r1",
        vec![
            HostnameMatch::Exact(arc("z.example.com")),
            HostnameMatch::Exact(arc("a.example.com")),
            HostnameMatch::Wildcard(arc("w.example.com")),
        ],
        1,
    )]);
    let b = a.clone();
    a.http_routes[0].hostnames.swap(0, 1);
    assert_eq!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_generation_changes_digest() {
    let a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
    let b = view_with_http_routes(vec![http_route("r1", vec![], 2)]);
    assert_ne!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_parent_ref_changes_digest() {
    let mut a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
    a.http_routes[0].parent_refs.push(ParentRef {
        group: Arc::from("gateway.networking.k8s.io"),
        kind: Arc::from("Gateway"),

        namespace: None,
        name: arc("gw-1"),
        section_name: None,
        port: None,
    });
    let mut b = a.clone();
    b.http_routes[0].parent_refs[0].name = arc("gw-2");
    assert_ne!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_rules_change_digest() {
    let mut a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
    a.http_routes[0].rules.push(HTTPRouteRule {
        programmed: true,
        timeout_ms: None,
        request_timeout_ms: None,
        matches: vec![RouteMatch {
            path: Some(PathMatch::Prefix(arc("/api"))),
            headers: vec![],
            query_params: vec![],
            method: Some(arc("GET")),
        }],
        backends: vec![WeightedBackend {
            backend: arc("svc:80"),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![],
            tls: None,
        }],
        filters: vec![],
    });
    let b = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
    assert_ne!(compute_digest(&a), compute_digest(&b));
}

use crate::gateway::model::routing::{
    HeaderMatch, HeaderMatchValue, PathRewrite, QueryParamMatch, QueryParamMatchValue, RouteFilter,
};

#[test]
fn http_route_all_path_match_types() {
    let exact = HTTPRouteState {
        namespace: arc("default"),
        name: arc("exact"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Exact(arc("/e"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    };
    let prefix = HTTPRouteState {
        namespace: arc("default"),
        name: arc("prefix"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(arc("/p"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    };
    let regex = HTTPRouteState {
        namespace: arc("default"),
        name: arc("regex"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Regex(arc("^/r$"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    };
    let a = compute_digest(&view_with_http_routes(vec![exact]));
    let b = compute_digest(&view_with_http_routes(vec![prefix]));
    let c = compute_digest(&view_with_http_routes(vec![regex]));
    assert_ne!(a, b);
    assert_ne!(b, c);
}

#[test]
fn http_route_header_and_query_matches_affect_digest() {
    let base = HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: None,
                headers: vec![HeaderMatch {
                    name: arc("x-version"),
                    value: HeaderMatchValue::Exact(arc("v1")),
                }],
                query_params: vec![QueryParamMatch {
                    name: arc("debug"),
                    value: QueryParamMatchValue::Exact(arc("1")),
                }],
                method: None,
            }],
            backends: vec![],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    };
    let mut changed = base.clone();
    changed.rules[0].matches[0].headers[0].value = HeaderMatchValue::Present;
    assert_ne!(
        compute_digest(&view_with_http_routes(vec![base])),
        compute_digest(&view_with_http_routes(vec![changed]))
    );
}

#[test]
fn http_route_all_filter_types_change_digest() {
    fn route_with_filter(filter: RouteFilter) -> ReconciledView {
        view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: vec![filter],
            }],
            parent_refs: vec![],
            programmed: true,
        }])
    }

    let filters = vec![
        RouteFilter::RequestHeaderSet {
            name: arc("X-In"),
            value: arc("in"),
        },
        RouteFilter::RequestHeaderAdd {
            name: arc("X-In-Add"),
            value: arc("in-add"),
        },
        RouteFilter::RequestHeaderRemove { name: arc("X-Old") },
        RouteFilter::ResponseHeaderSet {
            name: arc("X-Out"),
            value: arc("out"),
        },
        RouteFilter::ResponseHeaderAdd {
            name: arc("X-Out-Add"),
            value: arc("out-add"),
        },
        RouteFilter::ResponseHeaderRemove { name: arc("X-Old") },
        RouteFilter::UrlRewrite {
            hostname: None,
            path: Some(PathRewrite::PrefixReplace {
                prefix: arc("/api"),
                replacement: arc("/v2"),
            }),
        },
        RouteFilter::UrlRewrite {
            hostname: Some(arc("rewrite.example.com")),
            path: Some(PathRewrite::FullReplace(arc("/new"))),
        },
        RouteFilter::RequestRedirect {
            scheme: Some(arc("https")),
            hostname: Some(arc("example.com")),
            path: Some(PathRewrite::FullReplace(arc("/redirected"))),
            port: Some(8443),
            status_code: 308,
        },
    ];

    let base = compute_digest(&route_with_filter(filters[0].clone()));
    for f in filters.into_iter().skip(1) {
        let h = compute_digest(&route_with_filter(f));
        assert_ne!(base, h);
    }
}

#[test]
fn http_route_weighted_backend_ordering_stable() {
    let a = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![
                WeightedBackend {
                    backend: arc("b:80"),
                    weight: 2,
                    protocol: crate::ir::BackendProtocol::Http,
                    filters: vec![],
                    tls: None,
                },
                WeightedBackend {
                    backend: arc("a:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,
                    filters: vec![],
                    tls: None,
                },
            ],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    let mut b = a.clone();
    b.http_routes[0].rules[0].backends.swap(0, 1);
    assert_eq!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn reference_grant_subjects_affect_digest() {
    let base = ReconciledView {
        reference_grants: vec![ReferenceGrantState {
            namespace: arc("default"),
            name: arc("g1"),
            generation: 1,
            from: vec![GrantSubject {
                group: arc("gateway.networking.k8s.io"),
                kind: arc("HTTPRoute"),
                namespace: Some(arc("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: arc(""),
                kind: arc("Service"),
                namespace: None,
                name: Some(arc("svc")),
            }],
        }],
        ..Default::default()
    };
    let mut changed = base.clone();
    changed.reference_grants[0].from[0].name = Some(arc("specific"));
    assert_ne!(compute_digest(&base), compute_digest(&changed));
}

#[test]
fn http_route_request_mirror_changes_digest() {
    let base = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![],
            filters: vec![RouteFilter::RequestMirror {
                backend: arc("mirror-svc:80"),
                fraction: None,
            }],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    let changed = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![],
            filters: vec![RouteFilter::RequestMirror {
                backend: arc("other-svc:80"),
                fraction: None,
            }],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    assert_ne!(compute_digest(&base), compute_digest(&changed));
}

#[test]
fn http_route_cors_filter_changes_digest() {
    let base = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![],
            filters: vec![RouteFilter::Cors {
                allow_origins: vec![arc("*")],
                allow_methods: vec![arc("GET")],
                allow_headers: vec![arc("X-Custom")],
                expose_headers: vec![],
                max_age: Some(600),
                allow_credentials: false,
            }],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    let changed = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![],
            filters: vec![RouteFilter::Cors {
                allow_origins: vec![arc("*")],
                allow_methods: vec![arc("GET")],
                allow_headers: vec![arc("X-Custom")],
                expose_headers: vec![],
                max_age: Some(600),
                allow_credentials: true,
            }],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    assert_ne!(compute_digest(&base), compute_digest(&changed));
}

#[test]
fn http_route_rule_match_reordering_stable() {
    let mut a = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![
                RouteMatch {
                    path: Some(PathMatch::Prefix(arc("/z"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                },
                RouteMatch {
                    path: Some(PathMatch::Prefix(arc("/a"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                },
            ],
            backends: vec![],
            filters: vec![],
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    let b = a.clone();
    a.http_routes[0].rules[0].matches.swap(0, 1);
    assert_eq!(compute_digest(&a), compute_digest(&b));
}

#[test]
fn http_route_filter_reordering_stable() {
    // Exercise route_filter_ord by putting multiple RouteFilter variants
    // in a single rule out of canonical order.
    let filters = vec![
        RouteFilter::ResponseHeaderRemove { name: arc("X-Old") },
        RouteFilter::RequestHeaderSet {
            name: arc("X-In"),
            value: arc("in"),
        },
        RouteFilter::UrlRewrite {
            hostname: None,
            path: Some(PathRewrite::PrefixReplace {
                prefix: arc("/api"),
                replacement: arc("/v2"),
            }),
        },
        RouteFilter::RequestHeaderAdd {
            name: arc("X-In-Add"),
            value: arc("in-add"),
        },
    ];
    let base = view_with_http_routes(vec![HTTPRouteState {
        namespace: arc("default"),
        name: arc("r1"),
        generation: 1,
        hostnames: vec![],
        rules: vec![HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![],
            backends: vec![],
            filters: filters.clone(),
        }],
        parent_refs: vec![],
        programmed: true,
    }]);
    let mut reversed = base.clone();
    reversed.http_routes[0].rules[0].filters.reverse();
    assert_eq!(compute_digest(&base), compute_digest(&reversed));
}

#[test]
fn full_view_digest_is_stable() {
    use crate::gateway::model::routing::{
        GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, MethodMatch, MethodMatchType, TCPRouteState,
        TLSRouteState, UDPRouteState,
    };

    let mut view = sample_view();
    view.listener_sets.push(ListenerSetState {
        namespace: arc("default"),
        name: arc("ls-1"),
        generation: 1,
        created_at: 1,
        parent_ref: ParentRef {
            group: arc("gateway.networking.k8s.io"),
            kind: arc("Gateway"),
            namespace: Some(arc("default")),
            name: arc("gw-1"),
            section_name: None,
            port: None,
        },
        listeners: vec![ListenerState {
            programmed: true,
            name: arc("extra"),
            protocol: arc("HTTP"),
            port: 8080,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        conflicts: [(arc("extra"), arc("HostnameConflict"))]
            .into_iter()
            .collect(),
        accepted: true,
        programmed: true,
        reason: arc("Accepted"),
        listener_cert_errors: vec![],
        listener_kind_errors: vec![],
    });
    view.grpc_routes.push(GRPCRouteState {
        namespace: arc("default"),
        name: arc("grpc-1"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(arc("grpc.example.com"))],
        rules: vec![GRPCRouteRule {
            name: Some(arc("rule-1")),
            matches: vec![GRPCRouteMatch {
                method: Some(MethodMatch {
                    match_type: MethodMatchType::Exact,
                    service: arc("example.Greeter"),
                    method: Some(arc("SayHello")),
                    case_sensitive: true,
                }),
                headers: vec![],
            }],
            backends: vec![WeightedBackend {
                backend: arc("grpc-svc:50051"),
                weight: 1,
                filters: vec![],
                protocol: crate::ir::BackendProtocol::Http,
                tls: None,
            }],
            filters: vec![],
            programmed: true,
        }],
        parent_refs: vec![],
        programmed: true,
    });
    view.tcp_routes.push(TCPRouteState {
        namespace: arc("default"),
        name: arc("tcp-1"),
        generation: 1,
        parent_refs: vec![],
        backends: vec![],
        programmed: true,
    });
    view.udp_routes.push(UDPRouteState {
        namespace: arc("default"),
        name: arc("udp-1"),
        generation: 1,
        parent_refs: vec![],
        backends: vec![],
        programmed: true,
    });
    view.tls_routes.push(TLSRouteState {
        namespace: arc("default"),
        name: arc("tls-1"),
        generation: 1,
        hostnames: vec![HostnameMatch::Wildcard(arc("*.example.com"))],
        parent_refs: vec![],
        backends: vec![],
        programmed: true,
    });
    view.backend_tls_policies.push(BackendTLSPolicyState {
        namespace: arc("default"),
        name: arc("btp-1"),
        generation: 1,
        ..Default::default()
    });
    view.namespace_labels.insert(
        arc("default"),
        [(arc("team"), arc("gateway"))].into_iter().collect(),
    );
    view.listener_allowed.insert(
        (arc("default"), arc("gw-1"), arc("http")),
        AllowedRoutes {
            kinds: vec![RouteGroupKind {
                group: arc("gateway.networking.k8s.io"),
                kind: arc("HTTPRoute"),
            }],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );
    view.listener_set_allowed.insert(
        (arc("default"), arc("ls-1"), arc("extra")),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::Selector,
                selector: Some([("team".into(), "gateway".into())].into_iter().collect()),
            },
        },
    );

    let a = compute_digest(&view);
    // Reordering top-level collections must not change the digest.
    view.gateways.reverse();
    view.listener_sets.reverse();
    view.routes.reverse();
    view.http_routes.reverse();
    view.grpc_routes.reverse();
    view.tcp_routes.reverse();
    view.udp_routes.reverse();
    view.tls_routes.reverse();
    view.reference_grants.reverse();
    view.backend_tls_policies.reverse();
    let b = compute_digest(&view);
    assert_eq!(a, b);
}

#[test]
fn empty_view_digest() {
    let view = ReconciledView::default();
    let h = compute_digest(&view);
    assert_eq!(compute_digest(&view), h);
}
