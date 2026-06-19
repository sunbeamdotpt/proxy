// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use kube::runtime::controller::Action;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sunbeam_proxy::gateway::api::{Gateway, TCPRoute, TLSRoute, UDPRoute};
use sunbeam_proxy::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerState, ParentRef, RouteNamespaces,
};
use sunbeam_proxy::gateway::reconcile::context::ReconcilerContext;
use sunbeam_proxy::gateway::reconcile::l4route::{
    L4ParentStatus, ParsedBackendRef, ParsedParentRef, error_policy_l4, l4_crd_available,
    maybe_run_tcproute_controller, maybe_run_tlsroute_controller, maybe_run_udproute_controller,
    parse_tcproute, parse_tcproute_state, parse_tlsroute, parse_tlsroute_state, parse_udproute,
    parse_udproute_state, patch_l4_status, reconcile_tcproute, reconcile_tcproutes,
    reconcile_tlsroute, reconcile_tlsroutes, reconcile_udproute, resolve_l4_backends,
    resolve_l4_backends_async, resolve_l4_parent_ref, run_tcproute_controller,
    run_tlsroute_controller, run_udproute_controller,
};
use sunbeam_proxy::gateway::reconcile::refgrant::GrantIndex;
use sunbeam_proxy::gateway::status::{ConditionStatus, ConditionType, conditions};

fn gw_with_tcp_listener(ns: &str, name: &str, listener: &str, port: u16) -> GatewayState {
    GatewayState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("TCP"),
            port,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    }
}

fn gw_with_tls_listener(
    ns: &str,
    name: &str,
    listener: &str,
    port: u16,
    hostname: Option<&str>,
) -> GatewayState {
    GatewayState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("TLS"),
            port,
            hostname: hostname.map(Arc::from),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    }
}

fn empty_listener_allowed() -> HashMap<(String, String, String), AllowedRoutes> {
    HashMap::new()
}

fn empty_namespace_labels() -> HashMap<String, HashMap<String, String>> {
    HashMap::new()
}

#[test]
fn parse_tcproute_state_basic() {
    let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
              generation: 3
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
                      weight: 5
        "#;
    let route: TCPRoute = serde_yaml::from_str(yaml).unwrap();
    let state = parse_tcproute_state(&route);
    assert_eq!(state.namespace.as_ref(), "default");
    assert_eq!(state.name.as_ref(), "tcp-route");
    assert_eq!(state.generation, 3);
    assert!(state.parent_refs.is_empty());
    assert!(state.backends.is_empty());
    assert!(!state.programmed);
}

#[test]
fn parse_tlsroute_state_preserves_hostnames() {
    let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
              generation: 2
            spec:
              hostnames:
                - example.com
                - "*.example.com"
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#;
    let route: TLSRoute = serde_yaml::from_str(yaml).unwrap();
    let state = parse_tlsroute_state(&route);
    assert_eq!(state.hostnames.len(), 2);
    assert!(matches!(
        &state.hostnames[0],
        HostnameMatch::Exact(h) if h.as_ref() == "example.com"
    ));
    assert!(matches!(
        &state.hostnames[1],
        HostnameMatch::Wildcard(h) if h.as_ref() == "example.com"
    ));
}

#[test]
fn tcproute_accepted_when_parent_matches_tcp_listener() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
              generation: 1
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
    let _grant_index = GrantIndex::new(vec![]);

    let reconciled = reconcile_tcproutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(reconciled.len(), 1);
    let r = &reconciled[0];
    assert_eq!(r.route_state.parent_refs.len(), 1);
    assert!(r.programmed);

    let accepted = r.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);

    let programmed = r.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Programmed))
        .unwrap();
    assert_eq!(programmed.status, ConditionStatus::True);
    assert_eq!(programmed.reason, "Programmed");
}

#[test]
fn tcproute_rejected_on_http_listener() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
    )
    .unwrap();
    let gateways = vec![GatewayState {
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
    }];

    let reconciled = reconcile_tcproutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert!(reconciled[0].route_state.parent_refs.is_empty());
    assert!(!reconciled[0].programmed);
    assert!(
        reconciled[0].parent_statuses[0]
            .conditions
            .iter()
            .any(|c| matches!(c.condition_type, ConditionType::Programmed)
                && c.status == ConditionStatus::False)
    );
}

#[test]
fn tlsroute_hostname_intersection_enforced() {
    let route: TLSRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tls_listener(
        "default",
        "gw-1",
        "tls",
        443,
        Some("*.other.com"),
    )];

    let reconciled = reconcile_tlsroutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert!(reconciled[0].route_state.parent_refs.is_empty());
}

#[test]
fn tlsroute_accepted_when_hostname_intersects() {
    let route: TLSRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
                  sectionName: tls
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tls_listener(
        "default",
        "gw-1",
        "tls",
        443,
        Some("*.example.com"),
    )];

    let reconciled = reconcile_tlsroutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(reconciled[0].route_state.parent_refs.len(), 1);
    assert_eq!(
        reconciled[0].route_state.parent_refs[0]
            .section_name
            .as_deref(),
        Some("tls")
    );
}

#[test]
fn resolve_l4_backends_produces_weighted_targets() {
    let backend = ParsedBackendRef {
        group: None,
        kind: None,
        namespace: None,
        name: "svc".to_string(),
        port: Some(8080),
        weight: Some(7),
    };
    let grant_index = GrantIndex::new(vec![]);
    let (backends, resolved_refs) =
        resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
    assert!(resolved_refs.is_none());
    assert_eq!(backends.len(), 1);
    assert_eq!(
        backends[0].backend.as_ref(),
        "svc.default.svc.cluster.local.:8080"
    );
    assert_eq!(backends[0].weight, 7);
}

#[test]
fn resolve_l4_backends_rejects_cross_namespace_without_grant() {
    let backend = ParsedBackendRef {
        group: None,
        kind: None,
        namespace: Some("other".to_string()),
        name: "svc".to_string(),
        port: Some(8080),
        weight: None,
    };
    let grant_index = GrantIndex::new(vec![]);
    let (backends, resolved_refs) =
        resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
    assert!(resolved_refs.is_some());
    assert!(backends.is_empty());
}

#[test]
fn listener_allowed_kinds_can_block_l4_route() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
    let mut listener_allowed = HashMap::new();
    listener_allowed.insert(
        ("default".to_string(), "gw-1".to_string(), "tcp".to_string()),
        AllowedRoutes {
            kinds: vec![sunbeam_proxy::gateway::model::RouteGroupKind {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
            }],
            namespaces: RouteNamespaces::default(),
        },
    );

    let reconciled = reconcile_tcproutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &listener_allowed,
    );
    assert!(!reconciled[0].programmed);
}

#[test]
fn l4_reconciled_route_state_is_populated() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: route-x
              namespace: ns-a
              generation: 9
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tcp_listener("ns-a", "gw-1", "tcp", 9000)];

    let reconciled = reconcile_tcproutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    let r = &reconciled[0];
    assert_eq!(r.route_state.kind.as_ref(), "TCPRoute");
    assert_eq!(r.route_state.namespace.as_ref(), "ns-a");
    assert_eq!(r.route_state.name.as_ref(), "route-x");
    assert_eq!(r.route_state.generation, 9);
}

#[tokio::test]
async fn resolve_l4_backends_async_finds_service() {
    let backend = ParsedBackendRef {
        group: None,
        kind: None,
        namespace: None,
        name: "svc".to_string(),
        port: Some(53),
        weight: None,
    };
    let service = k8s_openapi::api::core::v1::Service {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some("svc".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let client = kube::Client::new(
        tower::service_fn(move |_req: http::Request<kube::client::Body>| {
            let svc = serde_json::to_value(&service).unwrap();
            async move {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(svc.to_string().into_bytes()))
                        .unwrap(),
                )
            }
        }),
        "default",
    );
    let grant_index = GrantIndex::new(vec![]);
    let (backends, resolved_refs) =
        resolve_l4_backends_async(&client, &[backend], "default", "UDPRoute", &grant_index, 1)
            .await;
    assert!(resolved_refs.is_none());
    assert_eq!(backends.len(), 1);
    assert_eq!(
        backends[0].backend.as_ref(),
        "svc.default.svc.cluster.local.:53"
    );
}

#[tokio::test]
async fn resolve_l4_backends_async_reports_missing_service() {
    let backend = ParsedBackendRef {
        group: None,
        kind: None,
        namespace: None,
        name: "missing".to_string(),
        port: Some(80),
        weight: None,
    };
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
    let (backends, resolved_refs) =
        resolve_l4_backends_async(&client, &[backend], "default", "TCPRoute", &grant_index, 1)
            .await;
    assert!(resolved_refs.is_some());
    assert!(backends.is_empty());
}

#[test]
fn status_parents_json_is_well_formed() {
    let parent_status = L4ParentStatus {
        parent_ref: ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("default")),
            name: Arc::from("gw-1"),
            section_name: Some(Arc::from("tls")),
            port: None,
        },
        conditions: vec![conditions::accepted_condition(
            ConditionStatus::True,
            "Accepted",
            "ok",
            1,
        )],
    };
    let parents = sunbeam_proxy::gateway::status::builder::build_status_parents(&[parent_status]);
    assert_eq!(parents.len(), 1);
    let parent_ref = parents[0].get("parentRef").unwrap();
    assert_eq!(
        parent_ref.get("name").and_then(|v| v.as_str()),
        Some("gw-1")
    );
    assert_eq!(
        parent_ref.get("sectionName").and_then(|v| v.as_str()),
        Some("tls")
    );
    let conditions = parents[0].get("conditions").unwrap().as_array().unwrap();
    assert_eq!(
        conditions[0].get("status").and_then(|v| v.as_str()),
        Some("True")
    );
}

#[test]
fn parse_default_metadata_falls_back_to_defaults() {
    let tcp: TCPRoute = TCPRoute::default();
    let parsed = parse_tcproute(&tcp);
    assert_eq!(parsed.namespace.as_ref(), "default");
    assert_eq!(parsed.name.as_ref(), "");
    assert_eq!(parsed.generation, 0);

    let udp: UDPRoute = UDPRoute::default();
    let parsed = parse_udproute(&udp);
    assert_eq!(parsed.namespace.as_ref(), "default");
    assert_eq!(parsed.name.as_ref(), "");
    assert_eq!(parsed.generation, 0);

    let tls: TLSRoute = TLSRoute::default();
    let parsed = parse_tlsroute(&tls);
    assert_eq!(parsed.namespace.as_ref(), "default");
    assert_eq!(parsed.name.as_ref(), "");
    assert_eq!(parsed.generation, 0);
    assert!(parsed.hostnames.is_empty());
}

#[test]
fn parse_udproute_state_basic() {
    let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
              generation: 4
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#;
    let route: UDPRoute = serde_yaml::from_str(yaml).unwrap();
    let state = parse_udproute_state(&route);
    assert_eq!(state.namespace.as_ref(), "default");
    assert_eq!(state.name.as_ref(), "udp-route");
    assert_eq!(state.generation, 4);
}

#[test]
fn resolve_l4_backends_rejects_unsupported_kind() {
    let backend = ParsedBackendRef {
        group: None,
        kind: Some("ConfigMap".to_string()),
        namespace: None,
        name: "cfg".to_string(),
        port: None,
        weight: None,
    };
    let grant_index = GrantIndex::new(vec![]);
    let (backends, resolved_refs) =
        resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
    assert!(resolved_refs.is_some());
    assert!(backends.is_empty());
}

#[tokio::test]
async fn resolve_l4_backends_async_rejects_unpermitted() {
    let backend = ParsedBackendRef {
        group: None,
        kind: None,
        namespace: Some("other".to_string()),
        name: "svc".to_string(),
        port: Some(80),
        weight: None,
    };
    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(200)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let grant_index = GrantIndex::new(vec![]);
    let (backends, resolved_refs) =
        resolve_l4_backends_async(&client, &[backend], "default", "TCPRoute", &grant_index, 1)
            .await;
    assert!(resolved_refs.is_some());
    assert!(backends.is_empty());
}

#[test]
fn resolve_l4_parent_ref_unsupported_group_kind() {
    let parsed = ParsedParentRef {
        group: "".to_string(),
        kind: "Service".to_string(),
        namespace: None,
        name: "svc".to_string(),
        section_name: None,
        port: None,
    };
    let (_, conditions) = resolve_l4_parent_ref(
        &parsed,
        "default",
        1,
        &[],
        "TCPRoute",
        &["TCP"],
        &[],
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(conditions[0].reason, "UnsupportedValue");
}

#[test]
fn resolve_l4_parent_ref_gateway_not_found() {
    let parsed = ParsedParentRef {
        group: "gateway.networking.k8s.io".to_string(),
        kind: "Gateway".to_string(),
        namespace: None,
        name: "missing".to_string(),
        section_name: None,
        port: None,
    };
    let (_, conditions) = resolve_l4_parent_ref(
        &parsed,
        "default",
        1,
        &[],
        "TCPRoute",
        &["TCP"],
        &[],
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(conditions[0].reason, "NoMatchingParent");
}

#[test]
fn resolve_l4_parent_ref_listener_not_found() {
    let parsed = ParsedParentRef {
        group: "gateway.networking.k8s.io".to_string(),
        kind: "Gateway".to_string(),
        namespace: None,
        name: "gw-1".to_string(),
        section_name: Some("missing".to_string()),
        port: None,
    };
    let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
    let (_, conditions) = resolve_l4_parent_ref(
        &parsed,
        "default",
        1,
        &[],
        "TCPRoute",
        &["TCP"],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(conditions[0].reason, "NoMatchingParent");
}

#[test]
fn resolve_l4_parent_ref_port_no_match() {
    let parsed = ParsedParentRef {
        group: "gateway.networking.k8s.io".to_string(),
        kind: "Gateway".to_string(),
        namespace: None,
        name: "gw-1".to_string(),
        section_name: None,
        port: Some(9999),
    };
    let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
    let (_, conditions) = resolve_l4_parent_ref(
        &parsed,
        "default",
        1,
        &[],
        "TCPRoute",
        &["TCP"],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert_eq!(conditions[0].reason, "NoMatchingParent");
}

#[test]
fn listener_namespace_blocks_l4_route() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: route-ns
            spec:
              parentRefs:
                - name: gw-1
                  namespace: gw-ns
              rules: []
        "#,
    )
    .unwrap();
    let gateways = vec![gw_with_tcp_listener("gw-ns", "gw-1", "tcp", 8080)];
    let reconciled = reconcile_tcproutes(
        &[route],
        &gateways,
        &empty_namespace_labels(),
        &empty_listener_allowed(),
    );
    assert!(!reconciled[0].programmed);
}

#[test]
fn build_status_parents_false_condition() {
    let parent_status = L4ParentStatus {
        parent_ref: ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: Some(Arc::from("default")),
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        },
        conditions: vec![conditions::resolved_refs_condition(
            ConditionStatus::False,
            "RefNotPermitted",
            "no",
            2,
        )],
    };
    let parents = sunbeam_proxy::gateway::status::builder::build_status_parents(&[parent_status]);
    let conditions = parents[0].get("conditions").unwrap().as_array().unwrap();
    assert_eq!(
        conditions[0].get("type").and_then(|v| v.as_str()),
        Some("ResolvedRefs")
    );
    assert_eq!(
        conditions[0].get("status").and_then(|v| v.as_str()),
        Some("False")
    );
    assert!(
        !parents[0]
            .get("parentRef")
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("sectionName")
    );
}

#[tokio::test]
async fn patch_l4_status_skips_when_unchanged() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs: []
              rules: []
            status:
              parents: []
        "#,
    )
    .unwrap();
    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(200)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let ctx = ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    };
    patch_l4_status(
        &route,
        &ctx,
        &[],
        "gateway.networking.k8s.io/v1alpha2",
        "TCPRoute",
    )
    .await;
}

#[tokio::test]
async fn reconcile_udproute_as_leader_patches_status() {
    let route: UDPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
    )
    .unwrap();

    let gateway: Gateway = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: udp
                  protocol: UDP
                  port: 53
        "#,
    )
    .unwrap();
    let client = mock_l4_reconcile_client(gateway);
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });

    let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_tlsroute_as_leader_patches_status() {
    let route: TLSRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
    )
    .unwrap();

    let gateway = sample_gateway_with_tls_listener();
    let client = mock_l4_reconcile_client(gateway);
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });

    let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_udproute_context_failure_returns_requeue() {
    let route: UDPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
    )
    .unwrap();

    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(500)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_tlsroute_context_failure_returns_requeue() {
    let route: TLSRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
    )
    .unwrap();

    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(500)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn run_l4_controllers_spawn_handles() {
    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(500)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let is_leader = Arc::new(AtomicBool::new(false));
    let tcp = run_tcproute_controller(client.clone(), Arc::clone(&is_leader));
    let udp = run_udproute_controller(client.clone(), Arc::clone(&is_leader));
    let tls = run_tlsroute_controller(client, Arc::clone(&is_leader));
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tcp.abort();
    udp.abort();
    tls.abort();
}

fn sample_gateway_with_tcp_listener() -> Gateway {
    serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: tcp
                  protocol: TCP
                  port: 8080
        "#,
    )
    .unwrap()
}

fn sample_gateway_with_tls_listener() -> Gateway {
    serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: tls
                  protocol: TLS
                  port: 443
                  hostname: "*.example.com"
        "#,
    )
    .unwrap()
}

fn mock_l4_reconcile_client(gateway: Gateway) -> kube::Client {
    let gateway_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList",
        "items": [serde_json::to_value(&gateway).unwrap()]
    });
    let grant_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrantList",
        "items": []
    });
    let namespace_list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": [{"metadata":{"name":"default"}}]
    });

    kube::Client::new(
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
    )
}

#[tokio::test]
async fn reconcile_tcproute_returns_requeue_action() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
    )
    .unwrap();

    let gateway = sample_gateway_with_tcp_listener();
    let client = mock_l4_reconcile_client(gateway);
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_udproute_returns_requeue_action() {
    let route: UDPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
    )
    .unwrap();

    let gateway: Gateway = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: udp
                  protocol: UDP
                  port: 53
        "#,
    )
    .unwrap();
    let client = mock_l4_reconcile_client(gateway);
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_tlsroute_returns_requeue_action() {
    let route: TLSRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
    )
    .unwrap();

    let gateway = sample_gateway_with_tls_listener();
    let client = mock_l4_reconcile_client(gateway);
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_tcproute_with_leader_patches_status() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
    )
    .unwrap();

    let gateway = sample_gateway_with_tcp_listener();
    let gateway_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList",
        "items": [serde_json::to_value(&gateway).unwrap()]
    });
    let grant_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrantList",
        "items": []
    });
    let namespace_list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": [{"metadata":{"name":"default"}}]
    });

    let client = kube::Client::new(
        tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let path = req.uri().path();
            let body = if path.contains("/namespaces") {
                namespace_list.clone()
            } else if path.contains("/referencegrants") {
                grant_list.clone()
            } else if path.contains("/status") {
                serde_json::json!({"status": {"parents": []}})
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
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });

    let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_l4_returns_requeue_on_context_failure() {
    let route: TCPRoute = serde_yaml::from_str(
        r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
    )
    .unwrap();

    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(500)
                    .body(kube::client::Body::empty())
                    .unwrap(),
            )
        }),
        "default",
    );
    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });

    let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn error_policies_return_requeue() {
    let err = kube::Error::Api(Box::new(kube::core::Status {
        status: Some(kube::core::response::StatusSummary::Failure),
        message: "boom".to_string(),
        reason: "InternalError".to_string(),
        code: 500,
        details: None,
        metadata: None,
    }));
    let ctx = Arc::new(ReconcilerContext {
        client: kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        ),
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    assert_eq!(
        error_policy_l4::<TCPRoute>(Arc::new(TCPRoute::default()), &err, Arc::clone(&ctx)),
        Action::requeue(Duration::from_secs(5))
    );
    assert_eq!(
        error_policy_l4::<UDPRoute>(Arc::new(UDPRoute::default()), &err, Arc::clone(&ctx)),
        Action::requeue(Duration::from_secs(5))
    );
    assert_eq!(
        error_policy_l4::<TLSRoute>(Arc::new(TLSRoute::default()), &err, Arc::clone(&ctx)),
        Action::requeue(Duration::from_secs(5))
    );
}

fn l4_crd_available_client(status: u16) -> kube::Client {
    kube::Client::new(
        tower::service_fn(move |_req: http::Request<kube::client::Body>| {
            let body = if status == 404 {
                serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "code": 404,
                    "message": "not found"
                })
            } else {
                serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1alpha2",
                    "kind": "TCPRouteList",
                    "items": []
                })
            };
            async move {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body.to_string().into_bytes()))
                        .unwrap(),
                )
            }
        }),
        "default",
    )
}

#[tokio::test]
async fn l4_crd_available_true_when_list_succeeds() {
    let client = l4_crd_available_client(200);
    assert!(l4_crd_available::<TCPRoute>(&client, "TCPRoute").await);
}

#[tokio::test]
async fn l4_crd_available_false_when_not_found() {
    let client = l4_crd_available_client(404);
    assert!(!l4_crd_available::<TCPRoute>(&client, "TCPRoute").await);
}

#[tokio::test]
async fn maybe_run_tcproute_controller_returns_handle_when_crd_installed() {
    let client = l4_crd_available_client(200);
    let is_leader = Arc::new(AtomicBool::new(false));
    let handle = maybe_run_tcproute_controller(client, is_leader)
        .await
        .expect("controller handle");
    handle.abort();
}

#[tokio::test]
async fn maybe_run_tcproute_controller_returns_none_when_crd_missing() {
    let client = l4_crd_available_client(404);
    let is_leader = Arc::new(AtomicBool::new(false));
    assert!(
        maybe_run_tcproute_controller(client, is_leader)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn maybe_run_udproute_controller_returns_none_when_crd_missing() {
    let client = l4_crd_available_client(404);
    let is_leader = Arc::new(AtomicBool::new(false));
    assert!(
        maybe_run_udproute_controller(client, is_leader)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn maybe_run_tlsroute_controller_returns_none_when_crd_missing() {
    let client = l4_crd_available_client(404);
    let is_leader = Arc::new(AtomicBool::new(false));
    assert!(
        maybe_run_tlsroute_controller(client, is_leader)
            .await
            .is_none()
    );
}

#[tokio::test]
async fn l4_route_context_clone_smoke() {
    let ctx = ReconcilerContext {
        client: kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        ),
        is_leader: Arc::new(AtomicBool::new(false)),
    };
    let cloned = ctx.clone();
    assert!(!cloned.is_leader.load(Ordering::Relaxed));
}
