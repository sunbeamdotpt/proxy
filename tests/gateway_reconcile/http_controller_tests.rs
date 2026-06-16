// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use kube::runtime::controller::Action;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use sunbeam_proxy::gateway::api::HTTPRoute;
use sunbeam_proxy::gateway::reconcile::context::ReconcilerContext;
use sunbeam_proxy::gateway::reconcile::route::{
    error_policy_httproute, reconcile_httproute, run_httproute_controller,
};

use crate::route_test_helpers::sample_route;

// Controller tests
// -----------------------------------------------------------------------------

#[tokio::test]
async fn error_policy_httproute_requeues_after_5s() {
    let route = Arc::new(sample_route(vec![]));
    let ctx = Arc::new(ReconcilerContext {
        client: kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        ),
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let err = kube::Error::Service(std::io::Error::other("test").into());
    let action = error_policy_httproute(route, &err, ctx);
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_httproute_non_leader_returns_requeue() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .expect("valid HTTPRoute");

    let gateway_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList",
        "items": []
    });
    let grant_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrantList",
        "items": []
    });
    let namespace_list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": []
    });

    let client = kube::Client::new(
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
    );

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn run_httproute_controller_returns_handle() {
    let client = kube::Client::new(
        tower::service_fn(|_req| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
        }),
        "default",
    );
    let handle = run_httproute_controller(client, Arc::new(AtomicBool::new(false)));
    handle.abort();
}

#[tokio::test]
async fn httproute_context_clone_smoke() {
    let ctx = ReconcilerContext {
        client: kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        ),
        is_leader: Arc::new(AtomicBool::new(false)),
    };
    let cloned = ctx.clone();
    assert!(!cloned.is_leader.load(Ordering::Relaxed));
}

#[tokio::test]
async fn reconcile_httproute_leader_patches_changed_status() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] },
        "status": { "parents": [] }
    }))
    .expect("valid HTTPRoute");

    let gateway_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList",
        "items": []
    });
    let grant_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrantList",
        "items": []
    });
    let namespace_list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": []
    });

    let client = kube::Client::new(
        tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let path = req.uri().path().to_string();
            let body = if path.contains("/namespaces") {
                namespace_list.clone()
            } else if path.contains("/referencegrants") {
                grant_list.clone()
            } else if path.contains("/status") {
                serde_json::json!({ "status": { "parents": [] } })
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
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_httproute_leader_skips_unchanged_status() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] },
        "status": { "parents": [] }
    }))
    .expect("valid HTTPRoute");

    let client = kube::Client::new(
        tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(
                http::Response::builder()
                    .status(200)
                    .header("content-type", "application/json")
                    .body(kube::client::Body::from(
                        serde_json::json!({ "items": [] }).to_string().into_bytes(),
                    ))
                    .unwrap(),
            )
        }),
        "default",
    );

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(true)),
    });
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_httproute_list_gateways_error_requeues() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": { "parentRefs": [] }
    }))
    .expect("valid HTTPRoute");

    let client = kube::Client::new(
        tower::service_fn(|req: http::Request<kube::client::Body>| {
            let status = if req.uri().path().contains("/gateways") {
                500
            } else {
                200
            };
            async move {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }
        }),
        "default",
    );

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}

#[tokio::test]
async fn reconcile_httproute_listenerset_parent_fetches_listener_sets() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": {
            "parentRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "ls-1"
            }]
        }
    }))
    .expect("valid HTTPRoute");

    let gateway_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "GatewayList",
        "items": []
    });
    let grant_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ReferenceGrantList",
        "items": []
    });
    let namespace_list = serde_json::json!({
        "apiVersion": "v1",
        "kind": "NamespaceList",
        "items": []
    });
    let listenerset_list = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "ListenerSetList",
        "items": []
    });

    let client = kube::Client::new(
        tower::service_fn(move |req: http::Request<kube::client::Body>| {
            let path = req.uri().path().to_string();
            let body = if path.contains("/namespaces") {
                namespace_list.clone()
            } else if path.contains("/referencegrants") {
                grant_list.clone()
            } else if path.contains("/listenersets") {
                listenerset_list.clone()
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
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

#[tokio::test]
async fn reconcile_httproute_listenerset_list_error_requeues() {
    let route: HTTPRoute = serde_json::from_value(serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
        "spec": {
            "parentRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "ls-1"
            }]
        }
    }))
    .expect("valid HTTPRoute");

    let client = kube::Client::new(
        tower::service_fn(|req: http::Request<kube::client::Body>| {
            let status = if req.uri().path().contains("/listenersets") {
                500
            } else {
                200
            };
            async move {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(status)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }
        }),
        "default",
    );

    let ctx = Arc::new(ReconcilerContext {
        client,
        is_leader: Arc::new(AtomicBool::new(false)),
    });
    let action = reconcile_httproute(Arc::new(route), ctx).await.unwrap();
    assert_eq!(action, Action::requeue(Duration::from_secs(5)));
}
