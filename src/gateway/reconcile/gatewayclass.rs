// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GatewayClass reconciler.
//!
//! Watches cluster-scoped GatewayClass resources and computes the
//! `Accepted` status condition.  Status writeback is gated on leadership.

use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::reconcile::context::{run_controller, ReconcilerContext};
use crate::gateway::status::patch::patch_status_if_changed;
use crate::gateway::status::{conditions, ConditionStatus, StatusCondition};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Name of the controller as advertised in GatewayClass `controllerName`.
pub const CONTROLLER_NAME: &str = "sunbeam.pt/sunbeam-proxy";

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
        "GRPCRoute".to_string(),
        "TLSRoute".to_string(),
        "ReferenceGrant".to_string(),
        "BackendTLSPolicy".to_string(),
        // Gateway extended
        "GatewayPort8080".to_string(),
        "GatewayStaticAddresses".to_string(),
        "GatewayHTTPListenerIsolation".to_string(),
        "GatewayHTTPSListenerDetectMisdirectedRequests".to_string(),
        "GatewayInfrastructurePropagation".to_string(),
        "GatewayAddressEmpty".to_string(),
        "GatewayBackendClientCertificate".to_string(),
        "GatewayFrontendClientCertificateValidation".to_string(),
        "GatewayFrontendClientCertificateValidationInsecureFallback".to_string(),
        "ListenerSet".to_string(),
        // HTTPRoute extended
        "HTTPRouteDestinationPortMatching".to_string(),
        "HTTPRouteBackendRequestHeaderModification".to_string(),
        "HTTPRouteQueryParamMatching".to_string(),
        "HTTPRouteMethodMatching".to_string(),
        "HTTPRouteResponseHeaderModification".to_string(),
        "HTTPRoutePortRedirect".to_string(),
        "HTTPRouteSchemeRedirect".to_string(),
        "HTTPRoutePathRedirect".to_string(),
        "HTTPRouteHostRewrite".to_string(),
        "HTTPRoutePathRewrite".to_string(),
        "HTTPRouteRequestMirror".to_string(),
        "HTTPRouteRequestMultipleMirrors".to_string(),
        "HTTPRouteRequestPercentageMirror".to_string(),
        "HTTPRouteRequestTimeout".to_string(),
        "HTTPRouteBackendTimeout".to_string(),
        "HTTPRouteParentRefPort".to_string(),
        "HTTPRouteBackendProtocolH2C".to_string(),
        "HTTPRouteBackendProtocolWebSocket".to_string(),
        "HTTPRouteNamedRouteRule".to_string(),
        "HTTPRouteCORS".to_string(),
        "HTTPRoute303RedirectStatusCode".to_string(),
        "HTTPRoute307RedirectStatusCode".to_string(),
        "HTTPRoute308RedirectStatusCode".to_string(),
        // GRPCRoute extended
        "GRPCRouteNamedRule".to_string(),
        // TLSRoute extended
        "TLSRouteModeTerminate".to_string(),
        "TLSRouteModeMixed".to_string(),
        // BackendTLSPolicy extended
        "BackendTLSPolicySANValidation".to_string(),
    ]
}

/// Compute the `Accepted` condition for a GatewayClass.
///
/// Returns `True` when the GatewayClass's `controllerName` matches
/// [`CONTROLLER_NAME`], otherwise `False`.
pub fn compute_accepted_condition(gc: &GatewayClass, observed_generation: i64) -> StatusCondition {
    let matches = gc.spec.controller_name == CONTROLLER_NAME;
    let message = if matches {
        "GatewayClass is managed by this controller".to_string()
    } else {
        format!(
            "ControllerName '{}' does not match '{}'",
            gc.spec.controller_name, CONTROLLER_NAME
        )
    };
    conditions::accepted_condition(
        if matches {
            ConditionStatus::True
        } else {
            ConditionStatus::False
        },
        if matches {
            "Accepted"
        } else {
            "InvalidControllerName"
        },
        &message,
        observed_generation,
    )
}

/// Context shared across GatewayClass reconcile invocations.
pub type GatewayClassContext = ReconcilerContext;

/// Reconcile a single GatewayClass.
pub async fn reconcile_gatewayclass(
    gc: Arc<GatewayClass>,
    ctx: Arc<GatewayClassContext>,
) -> Result<Action, kube::Error> {
    let observed_generation = gc.metadata.generation.unwrap_or(0);
    let condition = compute_accepted_condition(&gc, observed_generation);

    if ctx.is_leader.load(Ordering::Relaxed) {
        let conditions = vec![Condition::from(&condition)];
        let features: Vec<serde_json::Value> = supported_features()
            .into_iter()
            .map(|name| serde_json::json!({"name": name}))
            .collect();
        let new_status = serde_json::json!({
            "conditions": conditions,
            "supportedFeatures": features,
        });

        let api: Api<GatewayClass> = Api::all(ctx.client.clone());
        patch_status_if_changed(
            &api,
            &gc,
            new_status,
            "gateway.networking.k8s.io/v1",
            "GatewayClass",
            "sunbeam-proxy",
        )
        .await?;
    }

    crate::gateway::reconcile::trigger::trigger();
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
    run_controller::<GatewayClass, _, _, _>(
        client,
        is_leader,
        reconcile_gatewayclass,
        error_policy,
        "GatewayClass",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::gatewayclass::GatewayClassSpec;
    use crate::gateway::status::ConditionType;

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
        assert!(features.contains(&"Gateway".to_string()));
        assert!(features.contains(&"HTTPRoute".to_string()));
        assert!(features.contains(&"GRPCRoute".to_string()));
        assert!(features.contains(&"TLSRoute".to_string()));
        assert!(features.contains(&"ReferenceGrant".to_string()));
        assert!(features.contains(&"BackendTLSPolicy".to_string()));
        assert!(features.contains(&"HTTPRouteMethodMatching".to_string()));
        assert!(features.contains(&"HTTPRoutePathRedirect".to_string()));
        assert!(features.contains(&"HTTPRouteRequestTimeout".to_string()));
        assert!(features.contains(&"HTTPRouteBackendTimeout".to_string()));
        assert!(features.contains(&"HTTPRouteRequestMirror".to_string()));
        assert!(features.contains(&"HTTPRouteBackendProtocolH2C".to_string()));
        assert!(features.contains(&"HTTPRouteNamedRouteRule".to_string()));
        assert!(features.contains(&"GRPCRouteNamedRule".to_string()));
        assert!(features.contains(&"TLSRouteModeTerminate".to_string()));
        assert!(features.contains(&"TLSRouteModeMixed".to_string()));
        assert!(features.contains(&"GatewayInfrastructurePropagation".to_string()));
        assert!(features.contains(&"GatewayAddressEmpty".to_string()));
        assert!(features.contains(&"GatewayHTTPSListenerDetectMisdirectedRequests".to_string()));
        assert!(features.contains(&"ListenerSet".to_string()));
        assert!(features.contains(&"BackendTLSPolicySANValidation".to_string()));
        assert!(!features.contains(&"Mesh".to_string()));
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
        let cond = conditions::accepted_condition(ConditionStatus::True, "Accepted", "ok", 42);
        let k8s = Condition::from(&cond);
        assert_eq!(k8s.type_, "Accepted");
        assert_eq!(k8s.status, "True");
        assert_eq!(k8s.reason, "Accepted");
        assert_eq!(k8s.message, "ok");
        assert_eq!(k8s.observed_generation, Some(42));
    }

    #[test]
    fn k8s_condition_encoding_false() {
        let cond =
            conditions::programmed_condition(ConditionStatus::False, "Pending", "not ready", 7);
        let k8s = Condition::from(&cond);
        assert_eq!(k8s.type_, "Programmed");
        assert_eq!(k8s.status, "False");
    }

    #[test]
    fn k8s_condition_encoding_unknown() {
        let cond =
            conditions::resolved_refs_condition(ConditionStatus::Unknown, "Pending", "unknown", 3);
        let k8s = Condition::from(&cond);
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
            let cond = conditions::condition(ct, ConditionStatus::True, "Test", "msg", 1);
            let k8s = Condition::from(&cond);
            assert_eq!(k8s.type_, expected);
        }
    }

    #[tokio::test]
    async fn error_policy_requeues_after_5s() {
        let gc = Arc::new(sample_gc(CONTROLLER_NAME));
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
        let ctx = Arc::new(ReconcilerContext {
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
        let ctx = Arc::new(ReconcilerContext {
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
