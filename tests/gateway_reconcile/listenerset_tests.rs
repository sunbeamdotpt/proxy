// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use kube::runtime::controller::Action;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use sunbeam_proxy::gateway::api::listenerset::{ListenerSet, ListenerSetListeners};
use sunbeam_proxy::gateway::api::{Gateway, HTTPRoute};
use sunbeam_proxy::gateway::model::{
    AllowedRoutes, GatewayState, ListenerSetState, ListenerState, NamespaceFrom, ParentRef,
    RouteGroupKind, RouteNamespaces, TlsMode,
};
use sunbeam_proxy::gateway::reconcile::context::ReconcilerContext;
use sunbeam_proxy::gateway::reconcile::listener_common::parse_tls_mode;
use sunbeam_proxy::gateway::reconcile::listenerset::controller::{
    error_policy_listenerset, patch_listener_set_statuses, reconcile_listenerset,
    run_listenerset_controller,
};
use sunbeam_proxy::gateway::reconcile::listenerset::state::{
    attached_routes_per_listener, build_listener_set_allowed_map, build_listener_set_state,
    build_listener_set_status, build_listener_state, count_attached_listener_sets,
    find_parent_gateway, listener_set_allowed, parse_allowed_listeners,
    resolve_listener_set_conflicts,
};
use sunbeam_proxy::gateway::reconcile::refgrant::GrantIndex;

fn sample_listener(name: &str, protocol: &str, port: u16) -> ListenerState {
    ListenerState {
        name: Arc::from(name),
        protocol: Arc::from(protocol),
        port,
        hostname: None,
        tls_mode: None,
        frontend_validation: None,
        programmed: true,
    }
}

fn sample_gateway_state(name: &str, listeners: Vec<ListenerState>) -> GatewayState {
    GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from(name),
        generation: 1,
        listeners,
        backend_client_cert_id: None,
    }
}

fn sample_listener_set_state(
    name: &str,
    listeners: Vec<ListenerState>,
    accepted: bool,
) -> ListenerSetState {
    ListenerSetState {
        namespace: Arc::from("default"),
        name: Arc::from(name),
        generation: 1,
        created_at: 1,
        parent_ref: ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: None,
            name: Arc::from("gw"),
            section_name: None,
            port: None,
        },
        listeners,
        conflicts: BTreeMap::new(),
        accepted,
        programmed: accepted,
        reason: Arc::from("Accepted"),
        listener_cert_errors: vec![],
        listener_kind_errors: vec![],
    }
}

#[test]
fn parse_tls_mode_https_terminates() {
    let obj = serde_json::Map::new();
    assert_eq!(parse_tls_mode(&obj, "HTTPS"), Some(TlsMode::Terminate));
}

#[test]
fn parse_tls_mode_tls_respects_mode() {
    let mut obj = serde_json::Map::new();
    obj.insert("tls".into(), serde_json::json!({"mode": "Terminate"}));
    assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Terminate));

    obj.insert("tls".into(), serde_json::json!({"mode": "Passthrough"}));
    assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Passthrough));

    obj.insert("tls".into(), serde_json::json!({"mode": "Unknown"}));
    assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Passthrough));
}

#[test]
fn parse_tls_mode_http_returns_none() {
    let obj = serde_json::Map::new();
    assert_eq!(parse_tls_mode(&obj, "HTTP"), None);
}

#[test]
fn build_listener_state_parses_entry() {
    let entry = ListenerSetListeners {
        name: "https".into(),
        port: 8443,
        protocol: "HTTPS".into(),
        hostname: Some("example.com".into()),
        tls: None,
        allowed_routes: None,
    };
    let state = build_listener_state(&entry);
    assert_eq!(state.name.as_ref(), "https");
    assert_eq!(state.port, 8443);
    assert_eq!(state.protocol.as_ref(), "HTTPS");
    assert_eq!(state.hostname.as_deref(), Some("example.com"));
    assert_eq!(state.tls_mode, Some(TlsMode::Terminate));
    assert!(state.programmed);
}

#[test]
fn parse_allowed_listeners_defaults() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
    }))
    .unwrap();
    let ns = parse_allowed_listeners(&gw);
    assert_eq!(ns.from, NamespaceFrom::None);
    assert!(ns.selector.is_none());
}

#[test]
fn parse_allowed_listeners_all_and_selector() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": {
                "namespaces": { "from": "All" }
            }
        }
    }))
    .unwrap();
    assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::All);

    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": {
                "namespaces": {
                    "from": "Selector",
                    "selector": { "matchLabels": { "team": "gateway" } }
                }
            }
        }
    }))
    .unwrap();
    let ns = parse_allowed_listeners(&gw);
    assert_eq!(ns.from, NamespaceFrom::Selector);
    assert_eq!(
        ns.selector.unwrap().get("team"),
        Some(&"gateway".to_string())
    );
}

#[test]
fn listener_set_allowed_by_same_namespace() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": { "from": "Same" } }
        }
    }))
    .unwrap();
    let labels = HashMap::new();
    assert!(listener_set_allowed("default", &gw, &labels));
    assert!(!listener_set_allowed("other", &gw, &labels));
}

#[test]
fn listener_set_allowed_by_selector() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": {
                "namespaces": {
                    "from": "Selector",
                    "selector": { "matchLabels": { "team": "gateway" } }
                }
            }
        }
    }))
    .unwrap();
    let mut labels = HashMap::new();
    labels.insert(
        "other".into(),
        [("team".into(), "gateway".into())].into_iter().collect(),
    );
    assert!(listener_set_allowed("other", &gw, &labels));
    labels.clear();
    assert!(!listener_set_allowed("other", &gw, &labels));
}

fn sample_listener_set(name: &str, listeners: Vec<ListenerSetListeners>) -> ListenerSet {
    serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": name, "namespace": "default" },
        "spec": {
            "parentRef": { "name": "gw" },
            "listeners": listeners
        }
    }))
    .unwrap()
}

#[test]
fn find_parent_gateway_matches() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
    }))
    .unwrap();
    let ls = sample_listener_set("ls", vec![]);
    let gateways = [gw];
    let (idx, found) = find_parent_gateway(&ls, &gateways).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(found.metadata.name.as_deref().unwrap(), "gw");
}

#[test]
fn find_parent_gateway_not_found() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "other", "namespace": "default" },
        "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
    }))
    .unwrap();
    let ls = sample_listener_set("ls", vec![]);
    let gateways = [gw];
    assert!(find_parent_gateway(&ls, &gateways).is_none());
}

#[test]
fn resolve_listener_set_conflicts_prefers_gateway() {
    let gw = sample_gateway_state("gw", vec![sample_listener("http", "HTTP", 80)]);
    let ls = sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    let mut slice = [ls];
    resolve_listener_set_conflicts(&mut slice, &[gw]);
    let ls = slice.into_iter().next().unwrap();
    assert_eq!(
        ls.conflicts.get("http").map(|r| r.as_ref()),
        Some("HostnameConflict")
    );

    // When all listeners conflict, the ListenerSet is no longer accepted.
    let mut slice = [ls];
    resolve_listener_set_conflicts(&mut slice, &[]);
    let ls = slice.into_iter().next().unwrap();
    assert!(!ls.accepted);
}

#[test]
fn resolve_listener_set_conflicts_detects_protocol_conflict() {
    let gw = sample_gateway_state(
        "gw",
        vec![ListenerState {
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: Some(Arc::from("example.com")),
            tls_mode: None,
            frontend_validation: None,
            programmed: true,
        }],
    );
    let ls = sample_listener_set_state(
        "ls",
        vec![ListenerState {
            name: Arc::from("https"),
            protocol: Arc::from("HTTPS"),
            port: 80,
            hostname: Some(Arc::from("example.com")),
            tls_mode: Some(TlsMode::Terminate),
            frontend_validation: None,
            programmed: true,
        }],
        true,
    );
    let mut slice = [ls];
    resolve_listener_set_conflicts(&mut slice, &[gw]);
    let ls = slice.into_iter().next().unwrap();
    assert_eq!(
        ls.conflicts.get("https").map(|r| r.as_ref()),
        Some("ProtocolConflict")
    );
}

#[test]
fn count_attached_listener_sets_filters_accepted() {
    let mut accepted = sample_listener_set_state("ls1", vec![], true);
    accepted.accepted = true;
    accepted.programmed = true;
    let mut rejected = sample_listener_set_state("ls2", vec![], false);
    rejected.accepted = false;
    rejected.programmed = false;
    assert_eq!(
        count_attached_listener_sets("default", "gw", &[accepted, rejected]),
        1
    );
}

#[test]
fn build_listener_set_status_accepted() {
    let state = sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    let features = std::collections::HashSet::new();
    let status = build_listener_set_status(&state, &[1], &features);
    let listeners = status.get("listeners").unwrap().as_array().unwrap();
    assert_eq!(listeners.len(), 1);
    let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
    assert!(conditions
        .iter()
        .any(|c| c.get("type").unwrap() == "Accepted"));
}

#[test]
fn build_listener_set_status_not_allowed() {
    let mut state = sample_listener_set_state("ls", vec![], false);
    state.reason = Arc::from("NotAllowed");
    let status = build_listener_set_status(&state, &[], &std::collections::HashSet::new());
    let conditions = status.get("conditions").unwrap().as_array().unwrap();
    assert!(conditions
        .iter()
        .any(|c| c.get("reason").unwrap() == "NotAllowed"));
}

#[test]
fn build_listener_set_status_conflicted_listener() {
    let mut state =
        sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    state
        .conflicts
        .insert(Arc::from("http"), Arc::from("HostnameConflict"));
    let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
    let listeners = status.get("listeners").unwrap().as_array().unwrap();
    assert!(listeners[0]
        .get("conditions")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c.get("type").unwrap() == "Conflicted"));
}

#[test]
fn build_listener_set_status_kind_error() {
    let mut state =
        sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    state.listener_kind_errors = vec![Some(Arc::from("InvalidRouteKinds"))];
    let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
    let listeners = status.get("listeners").unwrap().as_array().unwrap();
    let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
    assert!(conditions
        .iter()
        .any(|c| c.get("type").unwrap() == "ResolvedRefs"));
}

#[test]
fn build_listener_set_status_cert_error() {
    let mut state =
        sample_listener_set_state("ls", vec![sample_listener("https", "HTTPS", 443)], true);
    state.listener_cert_errors = vec![Some(Arc::from("RefNotPermitted"))];
    let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
    let listeners = status.get("listeners").unwrap().as_array().unwrap();
    let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
    assert!(conditions
        .iter()
        .any(|c| c.get("reason").unwrap() == "RefNotPermitted"));
}

#[test]
fn build_listener_set_allowed_map_skips_conflicts() {
    let raw = sample_listener_set(
        "ls",
        vec![ListenerSetListeners {
            name: "http".into(),
            port: 80,
            protocol: "HTTP".into(),
            hostname: None,
            tls: None,
            allowed_routes: None,
        }],
    );
    let mut state =
        sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    state
        .conflicts
        .insert(Arc::from("http"), Arc::from("HostnameConflict"));
    let map = build_listener_set_allowed_map(&[raw], &[state]);
    assert!(map.is_empty());
}

#[test]
fn attached_routes_per_listener_counts_matches() {
    let ls_state = sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
    let httproute: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": {
            "parentRefs": [{ "group": "gateway.networking.k8s.io", "kind": "ListenerSet", "name": "ls", "sectionName": "http" }],
            "hostnames": ["example.com"],
            "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
        }
    })).unwrap();
    let mut allowed = HashMap::new();
    allowed.insert(
        ("default".into(), "ls".into(), "http".into()),
        AllowedRoutes {
            kinds: vec![RouteGroupKind {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
            }],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );
    let counts = attached_routes_per_listener(&ls_state, &[httproute], &HashMap::new(), &allowed);
    assert_eq!(counts, vec![1]);
}

#[test]
fn parse_allowed_listeners_invalid_and_missing_namespaces() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": "not-an-object"
        }
    }))
    .unwrap();
    assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::Same);

    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": "not-an-object" }
        }
    }))
    .unwrap();
    assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::Same);
}

fn fake_client() -> kube::Client {
    kube::Client::new(
        tower::service_fn(|req: http::Request<kube::client::Body>| async move {
            let path = req.uri().path();
            let body = if path.contains("/namespaces") {
                serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []})
            } else if path.ends_with("/status") && req.method() == "PATCH" {
                serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ListenerSet", "metadata": {"name": "ls-1", "namespace": "default"}, "status": {}})
            } else {
                serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "List", "items": []})
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
    )
}

#[tokio::test]
async fn build_listener_set_state_allowed_http_listener() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": { "from": "All" } }
        }
    }))
    .unwrap();
    let ls = sample_listener_set(
        "ls",
        vec![ListenerSetListeners {
            name: "http".into(),
            port: 80,
            protocol: "HTTP".into(),
            hostname: None,
            tls: None,
            allowed_routes: None,
        }],
    );
    let state = build_listener_set_state(
        &ls,
        &[gw],
        &HashMap::new(),
        &fake_client(),
        &GrantIndex::new(vec![]),
    )
    .await;
    assert!(state.accepted);
    assert!(state.programmed);
    assert_eq!(state.listeners.len(), 1);
    assert!(state.listener_cert_errors.iter().all(|e| e.is_none()));
}

#[tokio::test]
async fn build_listener_set_state_not_allowed() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": { "from": "Same" } }
        }
    }))
    .unwrap();
    let ls: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls", "namespace": "other" },
        "spec": { "parentRef": { "name": "gw" }, "listeners": [] }
    }))
    .unwrap();
    let state = build_listener_set_state(
        &ls,
        &[gw],
        &HashMap::new(),
        &fake_client(),
        &GrantIndex::new(vec![]),
    )
    .await;
    assert!(!state.accepted);
    assert_eq!(state.reason.as_ref(), "NotAllowed");
}

#[tokio::test]
async fn build_listener_set_state_invalid_kind() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": { "from": "All" } }
        }
    }))
    .unwrap();
    let ls: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls", "namespace": "default" },
        "spec": {
            "parentRef": { "name": "gw" },
            "listeners": [{
                "name": "http",
                "port": 80,
                "protocol": "HTTP",
                "allowedRoutes": { "kinds": [{ "group": "gateway.networking.k8s.io", "kind": "TCPRoute" }] }
            }]
        }
    }))
    .unwrap();
    let state = build_listener_set_state(
        &ls,
        &[gw],
        &HashMap::new(),
        &fake_client(),
        &GrantIndex::new(vec![]),
    )
    .await;
    assert!(state.listener_kind_errors.iter().any(|e| e.is_some()));
}

#[tokio::test]
async fn build_listener_set_state_cert_error() {
    let gw: Gateway = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "Gateway",
        "metadata": { "name": "gw", "namespace": "default" },
        "spec": {
            "gatewayClassName": "sunbeam",
            "listeners": [],
            "allowedListeners": { "namespaces": { "from": "All" } }
        }
    }))
    .unwrap();
    let ls: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls", "namespace": "default" },
        "spec": {
            "parentRef": { "name": "gw" },
            "listeners": [{
                "name": "https",
                "port": 443,
                "protocol": "HTTPS",
                "tls": { "certificateRefs": [{ "name": "missing-secret" }] }
            }]
        }
    }))
    .unwrap();
    let state = build_listener_set_state(
        &ls,
        &[gw],
        &HashMap::new(),
        &fake_client(),
        &GrantIndex::new(vec![]),
    )
    .await;
    assert!(state.listener_cert_errors.iter().any(|e| e.is_some()));
}

#[tokio::test]
async fn reconcile_listenerset_patches_status_when_leader() {
    let ls: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
    }))
    .unwrap();
    let ctx = Arc::new(ReconcilerContext {
        client: fake_client(),
        is_leader: Arc::new(AtomicBool::new(true)),
    });
    let action = reconcile_listenerset(Arc::new(ls), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn error_policy_listenerset_requeues_after_5s() {
    let ls = Arc::new(sample_listener_set("ls", vec![]));
    let ctx = Arc::new(ReconcilerContext {
        client: fake_client(),
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = error_policy_listenerset(
        ls,
        &kube::Error::Service(std::io::Error::other("test").into()),
        ctx,
    );
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn run_listenerset_controller_returns_handle() {
    let ctx = Arc::new(AtomicBool::new(false));
    let handle = run_listenerset_controller(fake_client(), ctx);
    handle.abort();
}

#[tokio::test]
async fn reconcile_listenerset_non_leader_skips_patch() {
    let ls: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
    }))
    .unwrap();
    let ctx = Arc::new(ReconcilerContext {
        client: fake_client(),
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_listenerset(Arc::new(ls), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn patch_listener_set_statuses_leader_patches() {
    let raw: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
    }))
    .unwrap();
    let state = sample_listener_set_state("ls-1", vec![], true);
    patch_listener_set_statuses(&fake_client(), &[raw], &[state], &[], &HashMap::new(), true).await;
}

#[tokio::test]
async fn patch_listener_set_statuses_non_leader_returns() {
    let raw: ListenerSet = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSet",
        "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
    }))
    .unwrap();
    let state = sample_listener_set_state("ls-1", vec![], true);
    patch_listener_set_statuses(
        &fake_client(),
        &[raw],
        &[state],
        &[],
        &HashMap::new(),
        false,
    )
    .await;
}
