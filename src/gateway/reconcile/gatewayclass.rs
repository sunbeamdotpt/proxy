// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GatewayClass reconciler.
//!
//! Watches cluster-scoped GatewayClass resources and computes the
//! `Accepted` status condition.  Status writeback is gated on leadership.

use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use futures::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Name of the controller as advertised in GatewayClass `controllerName`.
pub const CONTROLLER_NAME: &str = "sunbeam.io/gateway-controller";

/// Core and extended features supported by this controller.
///
/// The set is advertised in `GatewayClass.status.supportedFeatures` and is
/// consumed by the upstream Gateway API conformance test suite to discover
/// which tests should be run.
pub fn supported_features() -> Vec<String> {
    vec![
        // Core
        "Gateway".to_string(),
        "HTTPRoute".to_string(),
        "ReferenceGrant".to_string(),
        // Gateway extended
        "GatewayPort8080".to_string(),
        "GatewayHTTPListenerIsolation".to_string(),
        "ListenerSet".to_string(),
        // L4 route support
        "TCPRoute".to_string(),
        "TLSRoute".to_string(),
        "TLSRouteModeTerminate".to_string(),
        "TLSRouteModeMixed".to_string(),
        // HTTPRoute extended
        "HTTPRouteMethodMatching".to_string(),
        "HTTPRouteQueryParamMatching".to_string(),
        "HTTPRoutePortRedirect".to_string(),
        "HTTPRouteSchemeRedirect".to_string(),
        "HTTPRoutePathRedirect".to_string(),
        "HTTPRoutePathRewrite".to_string(),
        "HTTPRouteHostRewrite".to_string(),
        "HTTPRouteResponseHeaderModification".to_string(),
        "HTTPRouteBackendRequestHeaderModification".to_string(),
        "HTTPRouteCORS".to_string(),
        "HTTPRouteRequestMirror".to_string(),
        "HTTPRouteRequestMultipleMirrors".to_string(),
        "HTTPRouteRequestPercentageMirror".to_string(),
        "HTTPRouteRequestTimeout".to_string(),
        "HTTPRouteBackendTimeout".to_string(),
        "HTTPRouteBackendProtocolH2C".to_string(),
        "HTTPRouteBackendProtocolWebSocket".to_string(),
        "HTTPRoute303RedirectStatusCode".to_string(),
        "HTTPRoute307RedirectStatusCode".to_string(),
        "HTTPRoute308RedirectStatusCode".to_string(),
        "HTTPRouteParentRefPort".to_string(),
        "HTTPRouteDestinationPortMatching".to_string(),
        "HTTPRouteNamedRouteRule".to_string(),
        "GatewayHTTPSListenerDetectMisdirectedRequests".to_string(),
    ]
}

/// Compute the `Accepted` condition for a GatewayClass.
///
/// Returns `True` when the GatewayClass's `controllerName` matches
/// [`CONTROLLER_NAME`], otherwise `False`.
pub fn compute_accepted_condition(gc: &GatewayClass, observed_generation: i64) -> StatusCondition {
    let matches = gc.spec.controller_name == CONTROLLER_NAME;
    StatusCondition {
        condition_type: ConditionType::Accepted,
        status: if matches {
            ConditionStatus::True
        } else {
            ConditionStatus::False
        },
        reason: if matches {
            "Accepted".into()
        } else {
            "InvalidControllerName".into()
        },
        message: if matches {
            "GatewayClass is managed by this controller".into()
        } else {
            format!(
                "ControllerName '{}' does not match '{}'",
                gc.spec.controller_name, CONTROLLER_NAME
            )
        },
        observed_generation,
    }
}

/// Convert a [`StatusCondition`] into a Kubernetes `Condition`.
pub fn to_k8s_condition(sc: &StatusCondition) -> Condition {
    Condition {
        last_transition_time: k8s_openapi::jiff::Timestamp::now().into(),
        message: sc.message.clone(),
        observed_generation: Some(sc.observed_generation),
        reason: sc.reason.clone(),
        status: match sc.status {
            ConditionStatus::True => "True".to_string(),
            ConditionStatus::False => "False".to_string(),
            ConditionStatus::Unknown => "Unknown".to_string(),
        },
        type_: match sc.condition_type {
            ConditionType::Accepted => "Accepted".to_string(),
            ConditionType::Programmed => "Programmed".to_string(),
            ConditionType::ResolvedRefs => "ResolvedRefs".to_string(),
            ConditionType::Conflicted => "Conflicted".to_string(),
            ConditionType::Poison => "Poison".to_string(),
            ConditionType::NoMatchingParent => "NoMatchingParent".to_string(),
            ConditionType::RefNotPermitted => "RefNotPermitted".to_string(),
            ConditionType::UnsupportedFeature => "UnsupportedFeature".to_string(),
        },
    }
}

/// Context shared across GatewayClass reconcile invocations.
#[derive(Clone)]
pub struct GatewayClassContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Reconcile a single GatewayClass.
pub async fn reconcile_gatewayclass(
    gc: Arc<GatewayClass>,
    ctx: Arc<GatewayClassContext>,
) -> Result<Action, kube::Error> {
    let observed_generation = gc.metadata.generation.unwrap_or(0);
    let condition = compute_accepted_condition(&gc, observed_generation);

    if ctx.is_leader.load(Ordering::Relaxed) {
        let conditions = vec![to_k8s_condition(&condition)];
        let features: Vec<serde_json::Value> = supported_features()
            .into_iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect();
        let new_status = serde_json::json!({
            "conditions": conditions,
            "supportedFeatures": features,
        });

        let old_status_json = gc
            .status
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

        let name = gc.metadata.name.as_deref().unwrap_or("");
        if old_stripped == new_stripped {
            tracing::debug!(name, "GatewayClass status unchanged, skipping patch");
        } else {
            let patch = serde_json::json!({ "status": new_status });
            let api: Api<GatewayClass> = Api::all(ctx.client.clone());
            api.patch_status(
                name,
                &PatchParams::apply("sunbeam-proxy"),
                &Patch::Merge(&patch),
            )
            .await?;
            tracing::info!(name, "patched GatewayClass status");
        }
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy(
    gc: Arc<GatewayClass>,
    error: &kube::Error,
    _ctx: Arc<GatewayClassContext>,
) -> Action {
    tracing::error!(name = gc.metadata.name.as_deref().unwrap_or(""), %error, "GatewayClass reconcile failed");
    Action::requeue(Duration::from_secs(5))
}

/// Start the GatewayClass controller.
///
/// Returns a [`JoinHandle`] that runs until the controller is shut down.
pub fn run_gatewayclass_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(GatewayClassContext {
        client: client.clone(),
        is_leader,
    });
    let gatewayclasses = Api::<GatewayClass>::all(client);
    tokio::spawn(async move {
        Controller::new(gatewayclasses, kube::runtime::watcher::Config::default())
            .run(reconcile_gatewayclass, error_policy, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("GatewayClass controller error: {e}"),
                }
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::gatewayclass::GatewayClassSpec;

    fn sample_gc(controller_name: &str) -> GatewayClass {
        GatewayClass {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("test-gc".into()),
                generation: Some(1),
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
    fn accepted_true_when_controller_matches() {
        let gc = sample_gc(CONTROLLER_NAME);
        let cond = compute_accepted_condition(&gc, 1);
        assert_eq!(cond.condition_type, ConditionType::Accepted);
        assert_eq!(cond.status, ConditionStatus::True);
        assert_eq!(cond.reason, "Accepted");
        assert_eq!(cond.observed_generation, 1);
    }

    #[test]
    fn supported_features_lists_core_capabilities() {
        let features = supported_features();
        assert!(features.contains(&"HTTPRoute".to_string()));
        assert!(features.contains(&"HTTPRouteMethodMatching".to_string()));
        assert!(features.contains(&"HTTPRoutePathRedirect".to_string()));
        assert!(features.contains(&"HTTPRouteRequestTimeout".to_string()));
        assert!(features.contains(&"HTTPRouteBackendTimeout".to_string()));
        assert!(features.contains(&"HTTPRouteRequestMirror".to_string()));
        assert!(features.contains(&"HTTPRouteBackendProtocolH2C".to_string()));
        assert!(features.contains(&"TCPRoute".to_string()));
        assert!(!features.contains(&"UDPRoute".to_string()));
        assert!(features.contains(&"TLSRoute".to_string()));
        assert!(features.contains(&"TLSRouteModeTerminate".to_string()));
        assert!(features.contains(&"TLSRouteModeMixed".to_string()));
        assert!(!features.is_empty());
    }

    #[test]
    fn accepted_false_when_controller_mismatches() {
        let gc = sample_gc("someone.else/controller");
        let cond = compute_accepted_condition(&gc, 2);
        assert_eq!(cond.condition_type, ConditionType::Accepted);
        assert_eq!(cond.status, ConditionStatus::False);
        assert_eq!(cond.reason, "InvalidControllerName");
        assert!(cond.message.contains("someone.else/controller"));
        assert_eq!(cond.observed_generation, 2);
    }

    #[test]
    fn k8s_condition_encoding() {
        let cond = StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::True,
            reason: "Accepted".into(),
            message: "ok".into(),
            observed_generation: 42,
        };
        let k8s = to_k8s_condition(&cond);
        assert_eq!(k8s.type_, "Accepted");
        assert_eq!(k8s.status, "True");
        assert_eq!(k8s.reason, "Accepted");
        assert_eq!(k8s.message, "ok");
        assert_eq!(k8s.observed_generation, Some(42));
    }

    #[test]
    fn k8s_condition_encoding_false() {
        let cond = StatusCondition {
            condition_type: ConditionType::Programmed,
            status: ConditionStatus::False,
            reason: "Pending".into(),
            message: "not ready".into(),
            observed_generation: 7,
        };
        let k8s = to_k8s_condition(&cond);
        assert_eq!(k8s.type_, "Programmed");
        assert_eq!(k8s.status, "False");
    }

    #[test]
    fn k8s_condition_encoding_unknown() {
        let cond = StatusCondition {
            condition_type: ConditionType::ResolvedRefs,
            status: ConditionStatus::Unknown,
            reason: "Pending".into(),
            message: "unknown".into(),
            observed_generation: 3,
        };
        let k8s = to_k8s_condition(&cond);
        assert_eq!(k8s.type_, "ResolvedRefs");
        assert_eq!(k8s.status, "Unknown");
    }

    #[test]
    fn k8s_condition_all_types_roundtrip() {
        let types = [
            (ConditionType::Accepted, "Accepted"),
            (ConditionType::Programmed, "Programmed"),
            (ConditionType::ResolvedRefs, "ResolvedRefs"),
            (ConditionType::Conflicted, "Conflicted"),
            (ConditionType::Poison, "Poison"),
            (ConditionType::NoMatchingParent, "NoMatchingParent"),
            (ConditionType::RefNotPermitted, "RefNotPermitted"),
            (ConditionType::UnsupportedFeature, "UnsupportedFeature"),
        ];
        for (ct, expected) in types {
            let cond = StatusCondition {
                condition_type: ct,
                status: ConditionStatus::True,
                reason: "Test".into(),
                message: "msg".into(),
                observed_generation: 1,
            };
            let k8s = to_k8s_condition(&cond);
            assert_eq!(k8s.type_, expected);
        }
    }

    #[tokio::test]
    async fn error_policy_requeues_after_5s() {
        let gc = Arc::new(sample_gc(CONTROLLER_NAME));
        let ctx = Arc::new(GatewayClassContext {
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
        let action = error_policy(gc, &err, ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_gatewayclass_non_leader_skips_write() {
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let ctx = Arc::new(GatewayClassContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let gc = Arc::new(sample_gc(CONTROLLER_NAME));
        let result = reconcile_gatewayclass(gc, ctx).await;
        assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_gatewayclass_leader_patches_status() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async move {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "GatewayClass",
                    "metadata": { "name": "test-gc" },
                    "spec": { "controllerName": CONTROLLER_NAME }
                });
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
        let ctx = Arc::new(GatewayClassContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });
        let gc = Arc::new(sample_gc(CONTROLLER_NAME));
        let result = reconcile_gatewayclass(gc, ctx).await;
        assert_eq!(result.unwrap(), Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn run_gatewayclass_controller_returns_handle() {
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = run_gatewayclass_controller(client, is_leader);
        handle.abort();
    }

    #[tokio::test]
    async fn gatewayclass_context_clone_smoke() {
        let ctx = GatewayClassContext {
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

    #[test]
    fn gatewayclass_spec_debug_smoke() {
        let spec = GatewayClassSpec {
            controller_name: CONTROLLER_NAME.into(),
            description: Some("test".into()),
        };
        let s = format!("{:?}", spec);
        assert!(s.contains("controller_name"));
        assert!(s.contains(CONTROLLER_NAME));
    }
}
