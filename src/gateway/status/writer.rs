// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Status writeback to the Kubernetes API server.
//!
//! Only the leader may write status.  Callers must present a [`LeaderToken`]
//! obtained from the election module.  Writes use server-side apply
//! (`Patch::Apply`) with a per-pod field manager so that multiple controller
//! pods can cooperate without overwriting each other's conditions.

use crate::gateway::api::Gateway;
use crate::gateway::election::LeaderToken;
use crate::gateway::status::{ConditionStatus, StatusCondition};
use crate::metrics::REGISTRY;

use anyhow::{Context, Result};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, Patch, PatchParams};
use prometheus::IntCounter;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, error};

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Total number of gateway status write attempts that failed for any reason
/// other than a 409 Conflict.
pub static GATEWAY_STATUS_WRITE_FAILURES_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new(
        "gateway_status_write_failures_total",
        "Total gateway status write failures (excluding 409 conflicts)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Total number of gateway status write attempts that received a 409 Conflict.
pub static GATEWAY_STATUS_WRITE_CONFLICTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new(
        "gateway_status_write_conflicts_total",
        "Total gateway status write 409 conflicts",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

// ---------------------------------------------------------------------------
// Condition conversion
// ---------------------------------------------------------------------------

/// Convert our internal [`StatusCondition`] into a k8s-openapi [`Condition`].
fn to_k8s_condition(c: &StatusCondition) -> Condition {
    let status_str = match c.status {
        ConditionStatus::True => "True",
        ConditionStatus::False => "False",
        ConditionStatus::Unknown => "Unknown",
    };
    let type_str = match c.condition_type {
        super::ConditionType::Accepted => "Accepted",
        super::ConditionType::Programmed => "Programmed",
        super::ConditionType::ResolvedRefs => "ResolvedRefs",
        super::ConditionType::Conflicted => "Conflicted",
        super::ConditionType::Poison => "Poison",
        super::ConditionType::NoMatchingParent => "NoMatchingParent",
        super::ConditionType::RefNotPermitted => "RefNotPermitted",
        super::ConditionType::UnsupportedFeature => "UnsupportedFeature",
        super::ConditionType::InsecureFrontendValidationMode => "InsecureFrontendValidationMode",
    };

    Condition {
        last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        ),
        message: c.message.clone(),
        observed_generation: Some(c.observed_generation),
        reason: c.reason.clone(),
        status: status_str.to_string(),
        type_: type_str.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Retry helper
// ---------------------------------------------------------------------------

/// Retry an async operation with exponential backoff.
///
/// * `max_retries` – maximum number of attempts (including the first).
/// * `base_delay` – initial delay between retries.
/// * `op` – fallible async closure.
///
/// Returns the result of the last attempt.
async fn retry_with_backoff<F, Fut, T, E>(
    max_retries: usize,
    base_delay: Duration,
    mut op: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if attempt >= max_retries => return Err(e),
            Err(_) => {
                let delay = base_delay * 2_u32.pow((attempt - 1) as u32);
                tokio::time::sleep(delay).await;
                attempt += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Status writer
// ---------------------------------------------------------------------------

/// Writes Gateway API status back to the Kubernetes API server.
#[derive(Clone)]
pub struct StatusWriter {
    /// The Kubernetes API client.
    pub client: kube::Client,
    /// Per-pod leader identity used to build the field manager string.
    pub leader_id: String,
}

impl StatusWriter {
    /// Create a new status writer bound to the given leader identity.
    pub fn new(client: kube::Client, leader_id: impl Into<String>) -> Self {
        Self {
            client,
            leader_id: leader_id.into(),
        }
    }

    /// Write status conditions for a Gateway object.
    ///
    /// # Errors
    ///
    /// Returns an error immediately if `token` is no longer valid (leadership
    /// was lost).  Network or API errors are retried with exponential backoff.
    /// After all retries are exhausted the error is returned.
    pub async fn write_gateway_status(
        &self,
        token: &LeaderToken,
        name: &str,
        namespace: &str,
        conditions: &[StatusCondition],
    ) -> Result<()> {
        if !token.is_leader() {
            anyhow::bail!("leadership token expired; refusing to write status");
        }

        let field_manager = format!("sunbeam-gateway-controller-{}", self.leader_id);
        let pp = PatchParams::apply(&field_manager);

        let k8s_conditions: Vec<Condition> = conditions.iter().map(to_k8s_condition).collect();

        // Build a minimal Gateway object for SSA.  We intentionally omit
        // `.spec` so we do not claim ownership of spec fields.
        let patch_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": {
                "name": name,
                "namespace": namespace,
            },
            "status": {
                "conditions": k8s_conditions,
            }
        });

        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);

        let result = retry_with_backoff(3, Duration::from_millis(100), || async {
            api.patch_status(name, &pp, &Patch::Apply(&patch_body))
                .await
                .inspect_err(|e| {
                    if is_conflict(e) {
                        GATEWAY_STATUS_WRITE_CONFLICTS_TOTAL.inc();
                    } else {
                        GATEWAY_STATUS_WRITE_FAILURES_TOTAL.inc();
                    }
                })
        })
        .await;

        match result {
            Ok(_) => {
                debug!(name, namespace, "gateway status patched");
                Ok(())
            }
            Err(e) => {
                error!(name, namespace, error = %e, "gateway status patch failed after retries");
                Err(e).context("patch_status failed after retries")
            }
        }
    }
}

/// Returns `true` if the error is a 409 Conflict from the API server.
fn is_conflict(err: &kube::Error) -> bool {
    matches!(
        err,
        kube::Error::Api(status) if status.code == 409
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::status::{ConditionStatus, ConditionType};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn to_k8s_condition_maps_fields() {
        let sc = StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::True,
            reason: "Accepted".to_string(),
            message: "gateway is valid".to_string(),
            observed_generation: 7,
        };
        let kc = to_k8s_condition(&sc);
        assert_eq!(kc.type_, "Accepted");
        assert_eq!(kc.status, "True");
        assert_eq!(kc.reason, "Accepted");
        assert_eq!(kc.message, "gateway is valid");
        assert_eq!(kc.observed_generation, Some(7));
    }

    #[test]
    fn to_k8s_condition_unknown_status() {
        let sc = StatusCondition {
            condition_type: ConditionType::ResolvedRefs,
            status: ConditionStatus::Unknown,
            reason: "Pending".to_string(),
            message: "".to_string(),
            observed_generation: 1,
        };
        let kc = to_k8s_condition(&sc);
        assert_eq!(kc.status, "Unknown");
        assert_eq!(kc.type_, "ResolvedRefs");
    }

    #[tokio::test]
    async fn retry_with_backoff_succeeds_first_try() {
        let result =
            retry_with_backoff(3, Duration::from_millis(10), || async { Ok::<_, ()>(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn retry_with_backoff_succeeds_on_second_try() {
        let attempts = AtomicUsize::new(0);
        let result = retry_with_backoff(3, Duration::from_millis(10), || async {
            let a = attempts.fetch_add(1, Ordering::SeqCst);
            if a == 0 {
                Err("transient")
            } else {
                Ok::<_, &str>(42)
            }
        })
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retry_with_backoff_exhausts_retries() {
        let attempts = AtomicUsize::new(0);
        let result = retry_with_backoff(3, Duration::from_millis(10), || async {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>("always fails")
        })
        .await;
        assert_eq!(result, Err("always fails"));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn is_conflict_detects_409() {
        let status = kube::core::Status {
            code: 409,
            message: "Conflict".to_string(),
            reason: "Conflict".to_string(),
            status: None,
            details: None,
            metadata: None,
        };
        let err = kube::Error::Api(Box::new(status));
        assert!(is_conflict(&err));
    }

    #[test]
    fn is_conflict_rejects_other_codes() {
        let status = kube::core::Status {
            code: 500,
            message: "Internal Server Error".to_string(),
            reason: "InternalError".to_string(),
            status: None,
            details: None,
            metadata: None,
        };
        let err = kube::Error::Api(Box::new(status));
        assert!(!is_conflict(&err));
    }

    #[test]
    fn is_conflict_rejects_non_api_errors() {
        let err = kube::Error::Service(std::io::Error::other("network").into());
        assert!(!is_conflict(&err));
    }

    #[test]
    fn metrics_are_registerable() {
        // Touching the lazy statics forces registration.
        let _ = GATEWAY_STATUS_WRITE_FAILURES_TOTAL.get();
        let _ = GATEWAY_STATUS_WRITE_CONFLICTS_TOTAL.get();
        // If we get here without panicking, the metrics registered successfully.
    }

    #[tokio::test]
    async fn write_gateway_status_rejects_expired_token() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let valid = Arc::new(AtomicBool::new(false));
        let token = LeaderToken::new_for_test(valid);

        // We need a client to build StatusWriter, but the call should fail
        // before any network request because the token is expired.
        // Use a mock client (tower service that never gets called).
        let mock_svc = tower::service_fn(|_req: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
        });
        let client = kube::Client::new(mock_svc, "default");
        let writer = StatusWriter::new(client, "pod-1");

        let result = writer
            .write_gateway_status(&token, "gw", "default", &[])
            .await;

        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("leadership token expired"),
            "expected token expiry error, got: {msg}"
        );
    }

    #[test]
    fn to_k8s_condition_false_status() {
        let sc = StatusCondition {
            condition_type: ConditionType::Programmed,
            status: ConditionStatus::False,
            reason: "Pending".to_string(),
            message: "not ready".to_string(),
            observed_generation: 1,
        };
        let kc = to_k8s_condition(&sc);
        assert_eq!(kc.status, "False");
        assert_eq!(kc.type_, "Programmed");
    }

    #[test]
    fn to_k8s_condition_all_remaining_types() {
        let types = [
            (ConditionType::Programmed, "Programmed"),
            (ConditionType::Conflicted, "Conflicted"),
            (ConditionType::Poison, "Poison"),
            (ConditionType::NoMatchingParent, "NoMatchingParent"),
            (ConditionType::RefNotPermitted, "RefNotPermitted"),
            (ConditionType::UnsupportedFeature, "UnsupportedFeature"),
            (
                ConditionType::InsecureFrontendValidationMode,
                "InsecureFrontendValidationMode",
            ),
        ];
        for (ct, expected) in types {
            let sc = StatusCondition {
                condition_type: ct,
                status: ConditionStatus::True,
                reason: "Test".to_string(),
                message: "msg".to_string(),
                observed_generation: 1,
            };
            let kc = to_k8s_condition(&sc);
            assert_eq!(kc.type_, expected);
        }
    }

    #[tokio::test]
    async fn write_gateway_status_success() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async move {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "Gateway",
                    "metadata": { "name": "gw", "namespace": "default" },
                    "spec": { "gatewayClassName": "test-gc" }
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
        let writer = StatusWriter::new(client, "pod-1");
        let valid = Arc::new(AtomicBool::new(true));
        let token = LeaderToken::new_for_test(valid);
        let conditions = vec![StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::True,
            reason: "Accepted".to_string(),
            message: "ok".to_string(),
            observed_generation: 1,
        }];
        let result = writer
            .write_gateway_status(&token, "gw", "default", &conditions)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn write_gateway_status_conflict_retries_then_fails() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async move {
                let status = kube::core::Status {
                    code: 409,
                    message: "Conflict".to_string(),
                    reason: "Conflict".to_string(),
                    status: None,
                    details: None,
                    metadata: None,
                };
                let body = serde_json::to_vec(&status).unwrap();
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(409)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body))
                        .unwrap(),
                )
            }),
            "default",
        );
        let writer = StatusWriter::new(client, "pod-1");
        let valid = Arc::new(AtomicBool::new(true));
        let token = LeaderToken::new_for_test(valid);
        let result = writer
            .write_gateway_status(&token, "gw", "default", &[])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_gateway_status_retries_then_succeeds() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count2 = call_count.clone();
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let count = call_count2.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 2 {
                        let status = kube::core::Status {
                            code: 500,
                            message: "Internal Server Error".to_string(),
                            reason: "InternalError".to_string(),
                            status: None,
                            details: None,
                            metadata: None,
                        };
                        let body = serde_json::to_vec(&status).unwrap();
                        Ok::<_, std::convert::Infallible>(
                            http::Response::builder()
                                .status(500)
                                .header("content-type", "application/json")
                                .body(kube::client::Body::from(body))
                                .unwrap(),
                        )
                    } else {
                        let body = serde_json::json!({
                            "apiVersion": "gateway.networking.k8s.io/v1",
                            "kind": "Gateway",
                            "metadata": { "name": "gw", "namespace": "default" },
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
        let writer = StatusWriter::new(client, "pod-1");
        let valid = Arc::new(AtomicBool::new(true));
        let token = LeaderToken::new_for_test(valid);
        let result = writer
            .write_gateway_status(&token, "gw", "default", &[])
            .await;
        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }
}
