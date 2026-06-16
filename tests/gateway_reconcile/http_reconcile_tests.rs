// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::HashMap;
use std::sync::Arc;
use sunbeam_proxy::gateway::api::HTTPRoute;
use sunbeam_proxy::gateway::model::{
    AllowedRoutes, GatewayState, ListenerSetState, NamespaceFrom, ReferenceGrantState,
    RouteNamespaces,
};
use sunbeam_proxy::gateway::reconcile::backend::{resolve_backend_refs, BackendResolutionStatus};
use sunbeam_proxy::gateway::reconcile::refgrant::GrantIndex;
use sunbeam_proxy::gateway::reconcile::route::{
    reconcile_httproutes, reconcile_httproutes_with_context,
};
use sunbeam_proxy::gateway::status::{ConditionStatus, ConditionType};

use crate::route_test_helpers::{
    grant_allowing_http_route, gw_with_hostname, gw_with_listener, ls_with_listener,
    route_with_backends, sample_route,
};

// Reconcile tests
// -----------------------------------------------------------------------------

#[test]
fn accepted_when_parent_matches_same_namespace() {
    let route = sample_route(vec![serde_json::json!({
        "name": "gw-1",
        "sectionName": "http"
    })]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    assert_eq!(results.len(), 1);
    let result = &results[0];
    assert_eq!(result.route_state.parent_refs.len(), 1);

    let accepted = result.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
    assert_eq!(accepted.reason, "Accepted");

    let programmed = result.parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Programmed))
        .unwrap();
    assert_eq!(programmed.status, ConditionStatus::True);
    assert_eq!(programmed.reason, "Programmed");
}

#[test]
fn programmed_false_when_not_accepted() {
    let route = sample_route(vec![serde_json::json!({
        "name": "missing-gw"
    })]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let programmed = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Programmed))
        .unwrap();
    assert_eq!(programmed.status, ConditionStatus::False);
    assert_eq!(programmed.reason, "NotProgrammed");
}

#[test]
fn denied_when_gateway_not_found() {
    let route = sample_route(vec![serde_json::json!({
        "name": "missing-gw"
    })]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingParent");
}

#[test]
fn denied_when_listener_not_found() {
    let route = sample_route(vec![serde_json::json!({
        "name": "gw-1",
        "sectionName": "https"
    })]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingParent");
}

#[test]
fn cross_namespace_default_same_not_allowed() {
    let route = sample_route(vec![serde_json::json!({
        "namespace": "prod",
        "name": "gw-1",
        "sectionName": "http"
    })]);
    let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![grant_allowing_http_route("default", "prod", "gw-1")]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NotAllowedByListeners");
}

#[test]
fn cross_namespace_accepted_when_allowed_all() {
    let route = sample_route(vec![serde_json::json!({
        "namespace": "prod",
        "name": "gw-1",
        "sectionName": "http"
    })]);
    let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![grant_allowing_http_route("default", "prod", "gw-1")]);
    let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_allowed.insert(
        ("prod".to_string(), "gw-1".to_string(), "http".to_string()),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );

    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let results = reconcile_httproutes_with_context(
        &[route],
        &gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
}

#[test]
fn namespace_selector_accepts_matching_route() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "team-a", "generation": 1 },
        "spec": {
            "parentRefs": [{ "namespace": "infra", "name": "gw-1", "sectionName": "http" }]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![grant_allowing_http_route("team-a", "infra", "gw-1")]);
    let mut namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    namespace_labels.insert(
        "team-a".to_string(),
        [("allowed".to_string(), "true".to_string())]
            .into_iter()
            .collect(),
    );
    let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_allowed.insert(
        ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::Selector,
                selector: Some(
                    [("allowed".to_string(), "true".to_string())]
                        .into_iter()
                        .collect(),
                ),
            },
        },
    );

    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let results = reconcile_httproutes_with_context(
        &[route],
        &gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
}

#[test]
fn namespace_selector_rejects_non_matching_route() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "team-b", "generation": 1 },
        "spec": {
            "parentRefs": [{ "namespace": "infra", "name": "gw-1", "sectionName": "http" }]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![grant_allowing_http_route("team-b", "infra", "gw-1")]);
    let mut namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    namespace_labels.insert(
        "team-b".to_string(),
        [("allowed".to_string(), "false".to_string())]
            .into_iter()
            .collect(),
    );
    let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_allowed.insert(
        ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::Selector,
                selector: Some(
                    [("allowed".to_string(), "true".to_string())]
                        .into_iter()
                        .collect(),
                ),
            },
        },
    );

    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let results = reconcile_httproutes_with_context(
        &[route],
        &gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NotAllowedByListeners");
}

#[test]
fn unsupported_route_kind_rejected_by_listener() {
    let route = sample_route(vec![serde_json::json!({
        "namespace": "infra",
        "name": "gw-1",
        "sectionName": "http"
    })]);
    let gateways = vec![gw_with_listener("infra", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![grant_allowing_http_route("default", "infra", "gw-1")]);
    let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_allowed.insert(
        ("infra".to_string(), "gw-1".to_string(), "http".to_string()),
        AllowedRoutes {
            kinds: vec![sunbeam_proxy::gateway::model::RouteGroupKind {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("GRPCRoute"),
            }],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );

    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    let results = reconcile_httproutes_with_context(
        &[route],
        &gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
    );
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NotAllowedByListeners");
}

#[test]
fn unsupported_parent_kind_rejected() {
    let route = sample_route(vec![serde_json::json!({
        "group": "example.com",
        "kind": "Foo",
        "name": "foo-1"
    })]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let status = &results[0].parent_statuses[0];
    let accepted = status
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "UnsupportedValue");
}

#[test]
fn route_without_parent_refs_has_empty_parents() {
    let route = sample_route(vec![]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    assert_eq!(results[0].route_state.parent_refs.len(), 0);
    assert_eq!(results[0].parent_statuses.len(), 0);
}

#[test]
fn multiple_parent_refs_mixed_results() {
    let route = sample_route(vec![
        serde_json::json!({"name": "gw-1", "sectionName": "http"}),
        serde_json::json!({"name": "missing-gw"}),
    ]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    assert_eq!(results[0].route_state.parent_refs.len(), 1);
    assert_eq!(results[0].parent_statuses.len(), 2);

    let first = &results[0].parent_statuses[0];
    let first_accepted = first
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(first_accepted.status, ConditionStatus::True);

    let second = &results[0].parent_statuses[1];
    let second_accepted = second
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(second_accepted.status, ConditionStatus::False);
}

#[test]
fn resolved_refs_true_when_no_backend_refs() {
    let route = sample_route(vec![serde_json::json!({"name": "missing-gw"})]);
    let gateways: Vec<GatewayState> = vec![];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let resolved = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(resolved.status, ConditionStatus::True);
}

#[test]
fn resolved_refs_true_for_same_namespace_service() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
        vec![serde_json::json!({"name": "svc-1", "port": 80})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let resolved = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(resolved.status, ConditionStatus::True);
    assert_eq!(resolved.reason, "ResolvedRefs");
}

#[test]
fn resolved_refs_false_for_cross_namespace_backend_without_grant() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
        vec![serde_json::json!({"namespace": "prod", "name": "svc-1", "port": 80})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let resolved = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(resolved.status, ConditionStatus::False);
    assert_eq!(resolved.reason, "RefNotPermitted");
}

#[test]
fn resolved_refs_true_for_cross_namespace_backend_with_grant() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
        vec![serde_json::json!({"namespace": "prod", "name": "svc-1", "port": 80})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant = ReferenceGrantState {
        namespace: Arc::from("prod"),
        name: Arc::from("allow-default"),
        generation: 1,
        from: vec![sunbeam_proxy::gateway::model::GrantSubject {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("HTTPRoute"),
            namespace: Some(Arc::from("default")),
            name: None,
        }],
        to: vec![sunbeam_proxy::gateway::model::GrantSubject {
            group: Arc::from(""),
            kind: Arc::from("Service"),
            namespace: None,
            name: None,
        }],
    };
    let grant_index = GrantIndex::new(vec![grant]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let resolved = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(resolved.status, ConditionStatus::True);
}

#[test]
fn resolved_refs_false_for_unsupported_backend_kind() {
    let route = route_with_backends(
        vec![serde_json::json!({"name": "gw-1", "sectionName": "http"})],
        vec![serde_json::json!({"group": "example.com", "kind": "Foo", "name": "foo-1"})],
    );
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let resolved = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
        .unwrap();
    assert_eq!(resolved.status, ConditionStatus::False);
    assert_eq!(resolved.reason, "InvalidKind");
}

#[test]
fn parent_ref_port_matching_accepted() {
    let route = sample_route(vec![serde_json::json!({
        "name": "gw-1",
        "port": 80
    })]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
}

#[test]
fn parent_ref_port_matching_rejected() {
    let route = sample_route(vec![serde_json::json!({
        "name": "gw-1",
        "port": 9999
    })]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingParent");
}

#[test]
fn hostname_mismatch_rejected() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "parentRefs": [{"name": "gw-1"}],
            "hostnames": ["foo.example.com"]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_hostname(
        "default",
        "gw-1",
        "http",
        "bar.example.com",
    )];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingListenerHostname");
}

#[test]
fn hostname_intersection_accepted() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "parentRefs": [{"name": "gw-1"}],
            "hostnames": ["*.example.com"]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_hostname("default", "gw-1", "http", "*.example.com")];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
}

#[test]
fn wildcard_route_intersects_specific_listener() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "parentRefs": [{"name": "gw-1"}],
            "hostnames": ["*.specific.com"]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_hostname(
        "default",
        "gw-1",
        "http",
        "very.specific.com",
    )];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
}

#[test]
fn no_intersecting_hostnames_rejected() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "parentRefs": [{"name": "gw-1"}],
            "hostnames": ["specific.but.wrong.com", "wildcard.io"]
        }
    }))
    .expect("valid HTTPRoute");
    let gateways = vec![gw_with_hostname(
        "default",
        "gw-1",
        "http",
        "very.specific.com",
    )];
    let grant_index = GrantIndex::new(vec![]);

    let results = reconcile_httproutes(&[route], &gateways, &grant_index);
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingListenerHostname");
}

#[test]
fn resolve_backend_refs_async_finds_service() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"name": "svc-1", "port": 80})],
        );
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| async move {
                let path = req.uri().path();
                let body = if path.contains("/services/svc-1") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Service",
                        "metadata": { "name": "svc-1", "namespace": "default" }
                    })
                } else {
                    serde_json::json!({"apiVersion": "v1", "kind": "List", "items": []})
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
        );
        let grant_index = GrantIndex::new(vec![]);
        let result = sunbeam_proxy::gateway::reconcile::backend::resolve_backend_refs_async(
            &client,
            &route,
            "default",
            &grant_index,
        )
        .await;
        assert!(matches!(result.overall, BackendResolutionStatus::Ok));
    });
}

#[test]
fn resolve_backend_refs_async_missing_service() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"name": "missing-svc", "port": 80})],
        );
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
        let result = sunbeam_proxy::gateway::reconcile::backend::resolve_backend_refs_async(&client, &route, "default", &grant_index).await;
        assert!(
            matches!(result.overall, BackendResolutionStatus::BackendNotFound(ref msg) if msg.contains("missing-svc")),
            "unexpected result: {result:?}"
        );
    });
}

#[test]
fn listenerset_parent_accepted() {
    let route = sample_route(vec![serde_json::json!({
        "group": "gateway.networking.k8s.io",
        "kind": "ListenerSet",
        "name": "ls-1",
        "sectionName": "http"
    })]);
    let listener_sets = vec![ls_with_listener("default", "ls-1", "http")];
    let mut listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_set_allowed.insert(
        (
            "default".to_string(),
            "ls-1".to_string(),
            "http".to_string(),
        ),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );
    let grant_index = GrantIndex::new(vec![]);
    let results = reconcile_httproutes_with_context(
        &[route],
        &[],
        &listener_sets,
        &HashMap::new(),
        &HashMap::new(),
        &listener_set_allowed,
        &grant_index,
    );
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::True);
    assert_eq!(results[0].route_state.parent_refs.len(), 1);
}

#[test]
fn listenerset_parent_not_found() {
    let route = sample_route(vec![serde_json::json!({
        "group": "gateway.networking.k8s.io",
        "kind": "ListenerSet",
        "name": "missing-ls"
    })]);
    let grant_index = GrantIndex::new(vec![]);
    let results = reconcile_httproutes_with_context(
        &[route],
        &[],
        &[],
        &HashMap::new(),
        &HashMap::new(),
        &HashMap::new(),
        &grant_index,
    );
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingParent");
}

#[test]
fn listenerset_conflict_listener_skipped() {
    let route = sample_route(vec![serde_json::json!({
        "group": "gateway.networking.k8s.io",
        "kind": "ListenerSet",
        "name": "ls-1",
        "sectionName": "conflict"
    })]);
    let mut ls = ls_with_listener("default", "ls-1", "conflict");
    ls.conflicts
        .insert(Arc::from("conflict"), Arc::from("HostnameConflict"));
    let listener_sets = vec![ls];
    let mut listener_set_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_set_allowed.insert(
        (
            "default".to_string(),
            "ls-1".to_string(),
            "conflict".to_string(),
        ),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::All,
                selector: None,
            },
        },
    );
    let grant_index = GrantIndex::new(vec![]);
    let results = reconcile_httproutes_with_context(
        &[route],
        &[],
        &listener_sets,
        &HashMap::new(),
        &HashMap::new(),
        &listener_set_allowed,
        &grant_index,
    );
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NotAllowedByListeners");
}

#[test]
fn namespace_from_none_rejects_route() {
    let route = sample_route(vec![
        serde_json::json!({"name": "gw-1", "sectionName": "http"}),
    ]);
    let gateways = vec![gw_with_listener("default", "gw-1", "http")];
    let mut listener_allowed = HashMap::<(String, String, String), AllowedRoutes>::new();
    listener_allowed.insert(
        (
            "default".to_string(),
            "gw-1".to_string(),
            "http".to_string(),
        ),
        AllowedRoutes {
            kinds: vec![],
            namespaces: RouteNamespaces {
                from: NamespaceFrom::None,
                selector: None,
            },
        },
    );
    let grant_index = GrantIndex::new(vec![]);
    let results = reconcile_httproutes_with_context(
        &[route],
        &gateways,
        &[],
        &HashMap::new(),
        &listener_allowed,
        &HashMap::new(),
        &grant_index,
    );
    let accepted = results[0].parent_statuses[0]
        .conditions
        .iter()
        .find(|c| matches!(c.condition_type, ConditionType::Accepted))
        .unwrap();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NotAllowedByListeners");
}

#[test]
fn resolve_backend_refs_rule_without_backends_ok() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{ "matches": [{"path": {"type": "PathPrefix", "value": "/"}}] }]
        }
    }))
    .expect("valid HTTPRoute");
    let grant_index = GrantIndex::new(vec![]);
    let result = resolve_backend_refs(&route, "default", &grant_index);
    assert!(matches!(result.overall, BackendResolutionStatus::Ok));
    assert_eq!(result.rules.len(), 1);
    assert!(result.rules[0].ok);
}

#[test]
fn resolve_backend_refs_multiple_backends_first_error_wins() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{
                "backendRefs": [
                    { "namespace": "prod", "name": "svc-1", "port": 80 },
                    { "group": "example.com", "kind": "Foo", "name": "foo-1" }
                ]
            }]
        }
    }))
    .expect("valid HTTPRoute");
    let grant_index = GrantIndex::new(vec![]);
    let result = resolve_backend_refs(&route, "default", &grant_index);
    assert!(
        matches!(result.overall, BackendResolutionStatus::RefNotPermitted(_)),
        "unexpected result: {result:?}"
    );
    assert!(!result.rules[0].ok);
    assert!(result.rules[0].message.contains("svc-1"));
}

#[tokio::test]
async fn resolve_backend_refs_async_rule_without_backends() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "r", "namespace": "default" },
        "spec": {
            "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}]}]
        }
    }))
    .expect("valid HTTPRoute");
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
    let result = sunbeam_proxy::gateway::reconcile::backend::resolve_backend_refs_async(
        &client,
        &route,
        "default",
        &grant_index,
    )
    .await;
    assert!(matches!(result.overall, BackendResolutionStatus::Ok));
}

// -----------------------------------------------------------------------------
