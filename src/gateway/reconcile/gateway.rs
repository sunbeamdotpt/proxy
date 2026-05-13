// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gateway reconciler.
//!
//! Watches namespaced Gateway resources, computes `Accepted` and
//! `Programmed` status conditions, and builds the listener model.
//! Status writeback is gated on leadership.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::model::{GatewayState, ListenerState};
use crate::gateway::reconcile::gatewayclass::{to_k8s_condition, CONTROLLER_NAME};
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Build [`ListenerState`] entries from a Gateway's raw `listeners` spec.
pub fn build_listener_model(gw: &Gateway) -> Vec<ListenerState> {
    let mut listeners = Vec::new();
    for listener in &gw.spec.listeners {
        if let Some(obj) = listener.as_object() {
            let name = obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .into();
            let protocol = obj
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("HTTP")
                .into();
            let port = obj
                .get("port")
                .and_then(|v| v.as_u64())
                .unwrap_or(80) as u16;
            listeners.push(ListenerState {
                name,
                protocol,
                port,
            });
        }
    }
    listeners
}

/// Compute the status conditions for a Gateway.
///
/// * `Accepted` — `True` when the referenced GatewayClass exists and is
///   managed by this controller.
/// * `Programmed` — `False (Pending)` for T1 because the proxy is not yet
///   mutated.
pub fn compute_gateway_conditions(
    _gw: &Gateway,
    gateway_class: Option<&GatewayClass>,
    observed_generation: i64,
) -> Vec<StatusCondition> {
    let mut conditions = Vec::new();

    // Accepted
    let accepted = if let Some(gc) = gateway_class {
        if gc.spec.controller_name == CONTROLLER_NAME {
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::True,
                reason: "Accepted".into(),
                message: "Gateway references an accepted GatewayClass".into(),
                observed_generation,
            }
        } else {
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "InvalidGatewayClass".into(),
                message: format!(
                    "GatewayClass controller '{}' does not match '{}'",
                    gc.spec.controller_name, CONTROLLER_NAME
                ),
                observed_generation,
            }
        }
    } else {
        StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::False,
            reason: "GatewayClassNotFound".into(),
            message: "Referenced GatewayClass does not exist".into(),
            observed_generation,
        }
    };
    conditions.push(accepted);

    // Programmed = False (Pending) for T1
    conditions.push(StatusCondition {
        condition_type: ConditionType::Programmed,
        status: ConditionStatus::False,
        reason: "Pending".into(),
        message: "Gateway configuration accepted but not yet programmed into the proxy".into(),
        observed_generation,
    });

    conditions
}

/// Build a [`GatewayState`] from a [`Gateway`].
pub fn build_gateway_state(gw: &Gateway) -> GatewayState {
    GatewayState {
        namespace: gw.metadata.namespace.clone().unwrap_or_default().into(),
        name: gw.metadata.name.clone().unwrap_or_default().into(),
        generation: gw.metadata.generation.unwrap_or(0),
        listeners: build_listener_model(gw),
    }
}

/// Context shared across Gateway reconcile invocations.
#[derive(Clone)]
pub struct GatewayContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Reconcile a single Gateway.
pub async fn reconcile_gateway(
    gw: Arc<Gateway>,
    ctx: Arc<GatewayContext>,
) -> Result<Action, kube::Error> {
    let ns = gw.metadata.namespace.clone().unwrap_or_default();
    let name = gw.metadata.name.clone().unwrap_or_default();
    let observed_generation = gw.metadata.generation.unwrap_or(0);

    // Look up the referenced GatewayClass (cluster-scoped).
    let gatewayclasses: Api<GatewayClass> = Api::all(ctx.client.clone());
    let gc = gatewayclasses.get(&gw.spec.gateway_class_name).await.ok();

    let conditions = compute_gateway_conditions(&gw, gc.as_ref(), observed_generation);
    let _gateway_state = build_gateway_state(&gw);

    if ctx.is_leader.load(Ordering::Relaxed) {
        let k8s_conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition> =
            conditions.iter().map(to_k8s_condition).collect();
        let status = serde_json::json!({
            "status": {
                "conditions": k8s_conditions,
            }
        });
        let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), &ns);
        api.patch_status(
            &name,
            &PatchParams::apply("sunbeam-proxy"),
            &Patch::Merge(&status),
        )
        .await?;
        tracing::info!(%name, %ns, "patched Gateway status");
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy(
    _gw: Arc<Gateway>,
    _error: &kube::Error,
    _ctx: Arc<GatewayContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Start the Gateway controller.
pub fn run_gateway_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(GatewayContext {
        client: client.clone(),
        is_leader,
    });
    let gateways = Api::<Gateway>::all(client);
    tokio::spawn(async move {
        Controller::new(gateways, kube::runtime::watcher::Config::default())
            .run(reconcile_gateway, error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("Gateway controller error: {e}"),
                }
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::gatewayclass::GatewayClassSpec;

    fn sample_gw(gateway_class_name: &str) -> Gateway {
        let yaml = format!(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: test-gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: {gateway_class_name}
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                - name: https
                  protocol: HTTPS
                  port: 443
        "#
        );
        serde_yaml::from_str(&yaml).expect("deserializes")
    }

    fn sample_gc(controller_name: &str) -> GatewayClass {
        GatewayClass {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("test-gc".into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller_name.into(),
                description: None,
            },
            status: None,
        }
    }

    #[test]
    fn listener_model_from_gateway() {
        let gw = sample_gw("test-gc");
        let listeners = build_listener_model(&gw);
        assert_eq!(listeners.len(), 2);
        assert_eq!(listeners[0].name.as_ref(), "http");
        assert_eq!(listeners[0].protocol.as_ref(), "HTTP");
        assert_eq!(listeners[0].port, 80);
        assert_eq!(listeners[1].name.as_ref(), "https");
        assert_eq!(listeners[1].protocol.as_ref(), "HTTPS");
        assert_eq!(listeners[1].port, 443);
    }

    #[test]
    fn accepted_true_when_gatewayclass_matches() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let conds = compute_gateway_conditions(&gw, Some(&gc), 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        assert_eq!(accepted.reason, "Accepted");
    }

    #[test]
    fn accepted_false_when_gatewayclass_missing() {
        let gw = sample_gw("missing-gc");
        let conds = compute_gateway_conditions(&gw, None, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "GatewayClassNotFound");
    }

    #[test]
    fn accepted_false_when_gatewayclass_mismatched() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc("other/controller");
        let conds = compute_gateway_conditions(&gw, Some(&gc), 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "InvalidGatewayClass");
    }

    #[test]
    fn programmed_is_pending_for_t1() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let conds = compute_gateway_conditions(&gw, Some(&gc), 1);
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
        assert_eq!(programmed.reason, "Pending");
        assert!(programmed.message.contains("not yet programmed"));
    }

    #[test]
    fn gateway_state_building() {
        let gw = sample_gw("test-gc");
        let state = build_gateway_state(&gw);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "test-gw");
        assert_eq!(state.generation, 1);
        assert_eq!(state.listeners.len(), 2);
    }

    #[test]
    fn listeners_from_gateway_spec_empty() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: empty-gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners: []
        "#;
        let gw: Gateway = serde_yaml::from_str(yaml).expect("deserializes");
        let listeners = build_listener_model(&gw);
        assert!(listeners.is_empty());
    }

    #[test]
    fn listeners_from_gateway_spec_missing_port() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: no-port-gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
        "#;
        let gw: Gateway = serde_yaml::from_str(yaml).expect("deserializes");
        let listeners = build_listener_model(&gw);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].port, 80); // default
    }

    #[tokio::test]
    async fn error_policy_requeues_after_5s() {
        let gw = Arc::new(sample_gw("test-gc"));
        let ctx = Arc::new(GatewayContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
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
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let ctx = Arc::new(GatewayContext {
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
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(404)
                                .body(kube::client::Body::empty())
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "Gateway",
                            "metadata": { "name": "test-gw", "namespace": "default" },
                            "spec": { "gatewayClassName": "test-gc" }
                        });
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body.to_string().into_bytes()))
                                .unwrap(),
                        )
                    }
                }
            }),
            "default",
        );
        let ctx = Arc::new(GatewayContext {
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
}
