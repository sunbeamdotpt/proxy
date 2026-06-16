// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway controller wiring: reconcile, context, and run loop.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::ListenerSet;
use crate::gateway::model::GatewayState;
use crate::gateway::reconcile::context::{run_controller, ReconcilerContext};
use crate::gateway::reconcile::gateway::addresses::{
    compute_gateway_conditions, gateway_status_addresses, implementation_address,
    parse_gateway_addresses, validate_gateway_addresses, AddressValidation, GatewaySpecAddress,
};
use crate::gateway::reconcile::gateway::attachment::count_attached_routes;
use crate::gateway::reconcile::gateway::backend_tls::{
    gateway_backend_client_cert_ref, gateway_l4_ready, validate_gateway_backend_tls,
};
use crate::gateway::reconcile::gateway::certificates::{
    validate_listener_certificates, CertValidation,
};
use crate::gateway::reconcile::gateway::frontend_validation::{
    gateway_insecure_frontend_mode, validate_listener_frontend_validation,
};
use crate::gateway::reconcile::gateway::listeners::{
    build_listener_model, build_listener_status, listener_matches,
};
use crate::gateway::reconcile::gatewayclass::supported_features;
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::patch::patch_status_if_changed;
use crate::gateway::status::{ConditionStatus, ConditionType};
use k8s_openapi::api::core::v1::ServiceAccount;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::Client;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Reconcile a generated ServiceAccount that carries the Gateway's
/// infrastructure labels and annotations. This provides a concrete data-plane
/// resource for conformance tests that verify infrastructure propagation.
async fn reconcile_infrastructure_serviceaccount(gw: &Gateway, client: &Client) {
    let ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let name = gw.metadata.name.as_deref().unwrap_or("gateway");
    let gateway_name_label = "gateway.networking.k8s.io/gateway-name";

    let (mut labels, annotations) = match gw.spec.infrastructure.as_ref() {
        Some(v) => match v.as_object() {
            Some(obj) => {
                let mut labels: BTreeMap<String, String> = obj
                    .get("labels")
                    .and_then(|v| v.as_object())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                let annotations: BTreeMap<String, String> = obj
                    .get("annotations")
                    .and_then(|v| v.as_object())
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                            .collect()
                    })
                    .unwrap_or_default();
                labels.insert(gateway_name_label.to_string(), name.to_string());
                (labels, annotations)
            }
            None => {
                let mut labels = BTreeMap::new();
                labels.insert(gateway_name_label.to_string(), name.to_string());
                (labels, BTreeMap::new())
            }
        },
        None => {
            let mut labels = BTreeMap::new();
            labels.insert(gateway_name_label.to_string(), name.to_string());
            (labels, BTreeMap::new())
        }
    };
    labels.insert(gateway_name_label.to_string(), name.to_string());

    let sa_name = format!("sunbeam-gateway-{}", name);
    let sa = ServiceAccount {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(sa_name.clone()),
            namespace: Some(ns.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        ..Default::default()
    };

    let api: Api<ServiceAccount> = Api::namespaced(client.clone(), ns);
    let patch = serde_json::json!({
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": sa.metadata,
    });
    let pp = kube::api::PatchParams::apply("sunbeam-proxy").force();
    if let Err(e) = api
        .patch(&sa_name, &pp, &kube::api::Patch::Apply(patch))
        .await
    {
        tracing::warn!(error = %e, %name, %ns, "failed to reconcile infrastructure ServiceAccount");
    }
}

/// Build a [`GatewayState`] from a [`Gateway`].
pub fn build_gateway_state(gw: &Gateway) -> GatewayState {
    let backend_client_cert_id = gateway_backend_client_cert_ref(gw)
        .map(|(ns, name, _kind)| Arc::from(format!("gateway/{}/{}", ns, name)) as Arc<str>);
    GatewayState {
        namespace: gw.metadata.namespace.clone().unwrap_or_default().into(),
        name: gw.metadata.name.clone().unwrap_or_default().into(),
        generation: gw.metadata.generation.unwrap_or(0),
        listeners: build_listener_model(gw),
        backend_client_cert_id,
    }
}

/// Context shared across Gateway reconcile invocations.
pub type GatewayContext = ReconcilerContext;

/// Reconcile a single Gateway.
pub async fn reconcile_gateway(
    gw: Arc<Gateway>,
    ctx: Arc<GatewayContext>,
) -> Result<Action, kube::Error> {
    let ns = gw.metadata.namespace.clone().unwrap_or_default();
    let name = gw.metadata.name.clone().unwrap_or_default();
    let observed_generation = gw.metadata.generation.unwrap_or(0).max(1);

    // Look up the referenced GatewayClass (cluster-scoped).
    let gatewayclasses: Api<crate::gateway::api::gatewayclass::GatewayClass> =
        Api::all(ctx.client.clone());
    let gc = gatewayclasses.get(&gw.spec.gateway_class_name).await.ok();

    let grants: Api<crate::gateway::api::ReferenceGrant> = Api::all(ctx.client.clone());
    let grant_list = grants.list(&ListParams::default()).await?;
    let grant_index = GrantIndex::new(reconcile_reference_grants(&grant_list.items));

    let requested_addresses = parse_gateway_addresses(&gw);
    let address_validation = validate_gateway_addresses(&requested_addresses);
    let backend_tls_error = validate_gateway_backend_tls(&ctx.client, &gw, &grant_index).await;
    let insecure_frontend_mode = gateway_insecure_frontend_mode(&gw);
    let conditions = compute_gateway_conditions(
        &gw,
        gc.as_ref(),
        &address_validation,
        backend_tls_error,
        insecure_frontend_mode,
        observed_generation,
    );
    let programmed_true = conditions.iter().any(|c| {
        c.condition_type == ConditionType::Programmed && c.status == ConditionStatus::True
    });
    let _gateway_state = build_gateway_state(&gw);

    if ctx.is_leader.load(Ordering::Relaxed) {
        reconcile_infrastructure_serviceaccount(&gw, &ctx.client).await;
    }

    let namespaces_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());
    let namespace_list = namespaces_api.list(&ListParams::default()).await?;
    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();

    let gw_tls = gw.spec.tls.as_ref();
    let mut cert_errors: Vec<Option<CertValidation>> = Vec::new();
    for listener in &gw.spec.listeners {
        if let Some(obj) = listener.as_object() {
            let err =
                validate_listener_certificates(&ctx.client, &ns, "Gateway", obj, &grant_index)
                    .await
                    .or(validate_listener_frontend_validation(
                        &ctx.client,
                        &ns,
                        obj,
                        gw_tls,
                        &grant_index,
                    )
                    .await);
            cert_errors.push(err);
        } else {
            cert_errors.push(None);
        }
    }

    let listeners = listener_matches(&gw);
    let attached_routes =
        count_attached_routes(&ctx.client, &ns, &name, &listeners, &namespace_labels).await;

    let listener_sets_api: Api<ListenerSet> = Api::all(ctx.client.clone());
    let listener_set_list = match listener_sets_api.list(&ListParams::default()).await {
        Ok(list) => list.items,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ListenerSets for Gateway status");
            vec![]
        }
    };
    let mut listener_set_states = Vec::new();
    for ls in &listener_set_list {
        if ls.spec.parent_ref.name != name {
            continue;
        }
        if ls.spec.parent_ref.namespace.as_deref().unwrap_or(&ns) != ns {
            continue;
        }
        listener_set_states.push(
            crate::gateway::reconcile::listenerset::build_listener_set_state(
                ls,
                std::slice::from_ref(&gw),
                &namespace_labels,
                &ctx.client,
                &grant_index,
            )
            .await,
        );
    }
    crate::gateway::reconcile::listenerset::resolve_listener_set_conflicts(
        &mut listener_set_states,
        std::slice::from_ref(&build_gateway_state(&gw)),
    );
    let attached_listener_sets =
        crate::gateway::reconcile::listenerset::count_attached_listener_sets(
            &ns,
            &name,
            &listener_set_states,
        );

    if ctx.is_leader.load(Ordering::Relaxed) {
        if programmed_true {
            if let Some(l4_swap) = crate::l4::current::get() {
                let l4_config = l4_swap.load();
                if !gateway_l4_ready(&gw, &l4_config, &cert_errors) {
                    return Ok(Action::requeue(Duration::from_millis(100)));
                }
            }
        }

        let k8s_conditions: Vec<Condition> = conditions.iter().map(Condition::from).collect();
        let feature_set: std::collections::HashSet<String> =
            supported_features().into_iter().collect();
        let listener_statuses = build_listener_status(
            &gw,
            gc.as_ref(),
            observed_generation,
            &cert_errors,
            &attached_routes,
            &feature_set,
        );
        let addresses = gateway_status_addresses(&address_validation);
        let addresses = if addresses.is_empty() {
            // No addresses were requested or none are usable; fall back to the
            // implementation-defined address so callers still have an endpoint.
            gateway_status_addresses(&AddressValidation {
                usable: vec![GatewaySpecAddress {
                    type_: "IPAddress".into(),
                    value: Some(implementation_address()),
                }],
                ..Default::default()
            })
        } else {
            addresses
        };
        let new_status = serde_json::json!({
            "conditions": k8s_conditions,
            "listeners": listener_statuses,
            "addresses": addresses,
            "attachedListenerSets": attached_listener_sets,
        });

        let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), &ns);
        patch_status_if_changed(
            &api,
            &gw,
            new_status,
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "sunbeam-proxy",
        )
        .await?;
    }

    crate::gateway::reconcile::trigger::trigger();
    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy(_gw: Arc<Gateway>, _error: &kube::Error, _ctx: Arc<GatewayContext>) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Start the Gateway controller.
pub fn run_gateway_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    run_controller::<Gateway, _, _, _>(
        client,
        is_leader,
        reconcile_gateway,
        error_policy,
        "Gateway",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reconcile::gateway::test_helpers::{empty_list, sample_gw};
    use std::sync::atomic::Ordering;

    #[test]
    fn gateway_state_building() {
        let gw = sample_gw("test-gc");
        let state = build_gateway_state(&gw);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "test-gw");
        assert_eq!(state.generation, 1);
        assert_eq!(state.listeners.len(), 2);
    }

    #[tokio::test]
    async fn error_policy_requeues_after_5s() {
        let gw = Arc::new(sample_gw("test-gc"));
        let ctx = Arc::new(ReconcilerContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        kube::client::Body::empty(),
                    ))
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let err = kube::Error::Service(std::io::Error::other("test").into());
        let action = error_policy(gw, &err, ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_gateway_non_leader_skips_write() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| async move {
                let path = req.uri().path();
                let body = if path.contains("/referencegrants") {
                    empty_list("ReferenceGrantList")
                } else if path.contains("/gatewayclasses/") {
                    return Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(404)
                            .body(kube::client::Body::empty())
                            .unwrap(),
                    );
                } else {
                    empty_list("HTTPRouteList")
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
        let ctx = Arc::new(ReconcilerContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let gw = Arc::new(sample_gw("test-gc"));
        let result = reconcile_gateway(gw, ctx).await;
        assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_gateway_leader_patches_status() {
        let client = kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let method = req.method().clone();
                async move {
                    if method == http::Method::GET && path.contains("/gatewayclasses/") {
                        return Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(404)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        );
                    }
                    let body = if path.contains("/referencegrants") {
                        empty_list("ReferenceGrantList")
                    } else if path.contains("/gateways/") {
                        serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "Gateway",
                            "metadata": { "name": "test-gw", "namespace": "default" },
                            "spec": { "gatewayClassName": "test-gc" }
                        })
                    } else {
                        empty_list("HTTPRouteList")
                    };
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
        let gw = Arc::new(sample_gw("test-gc"));
        let result = reconcile_gateway(gw, ctx).await;
        assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn run_gateway_controller_returns_handle() {
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = run_gateway_controller(client, is_leader);
        handle.abort();
    }

    #[tokio::test]
    async fn gateway_context_clone_smoke() {
        let ctx = ReconcilerContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        kube::client::Body::empty(),
                    ))
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        };
        let cloned = ctx.clone();
        assert!(!cloned.is_leader.load(Ordering::Relaxed));
    }

    fn sa_client(status: u16) -> Client {
        Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let method = req.method().clone();
                async move {
                    if method == http::Method::PATCH
                        && path.contains("/serviceaccounts/sunbeam-gateway-")
                    {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(status)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(404)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn reconcile_infrastructure_serviceaccount_with_infrastructure() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              infrastructure:
                labels:
                  app: sunbeam
                annotations:
                  note: test
              listeners: []
        "#,
        )
        .unwrap();
        reconcile_infrastructure_serviceaccount(&gw, &sa_client(200)).await;
    }

    #[tokio::test]
    async fn reconcile_infrastructure_serviceaccount_with_non_object_infrastructure() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              infrastructure: not-an-object
              listeners: []
        "#,
        )
        .unwrap();
        reconcile_infrastructure_serviceaccount(&gw, &sa_client(200)).await;
    }

    #[tokio::test]
    async fn reconcile_infrastructure_serviceaccount_without_infrastructure() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners: []
        "#,
        )
        .unwrap();
        reconcile_infrastructure_serviceaccount(&gw, &sa_client(200)).await;
    }

    #[tokio::test]
    async fn reconcile_infrastructure_serviceaccount_warns_on_patch_error() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners: []
        "#,
        )
        .unwrap();
        reconcile_infrastructure_serviceaccount(&gw, &sa_client(500)).await;
    }
}
