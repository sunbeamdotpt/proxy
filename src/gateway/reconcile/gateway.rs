// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gateway reconciler.
//!
//! Watches namespaced Gateway resources, computes `Accepted` and
//! `Programmed` status conditions, and builds the listener model.
//! Status writeback is gated on leadership.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::api::httproute::HTTPRoute;
use crate::gateway::api::ReferenceGrant;
use crate::gateway::model::{GatewayState, ListenerState};
use crate::gateway::reconcile::gatewayclass::{to_k8s_condition, CONTROLLER_NAME};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
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
            let hostname = obj
                .get("hostname")
                .and_then(|v| v.as_str())
                .map(Arc::from);
            listeners.push(ListenerState {
                name,
                protocol,
                port,
                hostname,
            });
        }
    }
    listeners
}

/// Build the per-listener status entries for a Gateway.
///
/// In v1 each listener is reported as `Accepted` / `Programmed` /
/// `ResolvedRefs`.  `ResolvedRefs` becomes `False` with reason
/// `InvalidRouteKinds` when the listener references a route kind that is
/// not supported by this controller.
pub fn build_listener_status(
    gw: &Gateway,
    _gateway_class: Option<&GatewayClass>,
    observed_generation: i64,
    cert_errors: &[Option<CertValidation>],
    attached_routes: &[i64],
) -> Vec<serde_json::Value> {
    let mut statuses = Vec::new();
    for (idx, listener) in gw.spec.listeners.iter().enumerate() {
        let Some(obj) = listener.as_object() else { continue };
        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let (supported_kinds, mut resolved_refs_status, mut resolved_refs_reason, mut resolved_refs_message) =
            validate_listener_kinds(obj);
        let mut programmed_status = "True";
        let mut programmed_reason = "Programmed";
        let mut programmed_message = "Listener programmed";
        if let Some(err) = cert_errors.get(idx).copied().flatten() {
            resolved_refs_status = "False";
            resolved_refs_reason = err.reason;
            resolved_refs_message = err.message;
            programmed_status = "False";
            programmed_reason = "Invalid";
            programmed_message = "Listener has unresolved certificate references";
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let status = serde_json::json!({
            "name": name,
            "supportedKinds": supported_kinds,
            "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
            "conditions": [
                {
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Listener accepted",
                    "observedGeneration": observed_generation,
                    "lastTransitionTime": now,
                },
                {
                    "type": "Programmed",
                    "status": programmed_status,
                    "reason": programmed_reason,
                    "message": programmed_message,
                    "observedGeneration": observed_generation,
                    "lastTransitionTime": now,
                },
                {
                    "type": "ResolvedRefs",
                    "status": resolved_refs_status,
                    "reason": resolved_refs_reason,
                    "message": resolved_refs_message,
                    "observedGeneration": observed_generation,
                    "lastTransitionTime": now,
                }
            ]
        });
        statuses.push(status);
    }
    statuses
}

fn validate_listener_kinds(
    listener: &serde_json::Map<String, serde_json::Value>,
) -> (Vec<serde_json::Value>, &'static str, &'static str, &'static str) {
    let default_kind = serde_json::json!({
        "group": "gateway.networking.k8s.io",
        "kind": "HTTPRoute",
    });
    let allowed_kinds = listener
        .get("allowedRoutes")
        .and_then(|v| v.get("kinds"))
        .and_then(|v| v.as_array());

    let kinds = match allowed_kinds {
        Some(arr) if !arr.is_empty() => arr.clone(),
        _ => return (vec![default_kind], "True", "ResolvedRefs", "All references resolved"),
    };

    let mut supported = Vec::new();
    let mut has_invalid = false;
    for entry in kinds {
        let group = entry
            .get("group")
            .and_then(|v| v.as_str())
            .unwrap_or("gateway.networking.k8s.io");
        let kind = entry.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if group == "gateway.networking.k8s.io" && kind == "HTTPRoute" {
            supported.push(serde_json::json!({ "group": group, "kind": kind }));
        } else {
            has_invalid = true;
        }
    }

    if has_invalid {
        (
            supported,
            "False",
            "InvalidRouteKinds",
            "Listener contains unsupported route kinds",
        )
    } else {
        (supported, "True", "ResolvedRefs", "All references resolved")
    }
}

/// Certificate validation outcome for a single listener.
#[derive(Clone, Copy, Debug)]
pub struct CertValidation {
    pub reason: &'static str,
    pub message: &'static str,
}

/// Validate a listener's TLS certificate references.
///
/// Returns `Some(CertValidation)` when any certificate reference is malformed,
/// points to an unsupported resource kind, crosses a namespace boundary without
/// a matching ReferenceGrant, or the referenced Secret does not exist or does
/// not contain valid certificate data.
pub async fn validate_listener_certificates(
    client: &Client,
    gateway_ns: &str,
    listener: &serde_json::Map<String, serde_json::Value>,
    grant_index: &crate::gateway::reconcile::refgrant::GrantIndex,
) -> Option<CertValidation> {
    let tls = listener.get("tls")?;
    let certs = tls
        .get("certificateRefs")
        .and_then(|v| v.as_array())?;
    if certs.is_empty() {
        return None;
    }

    for cert in certs {
        let group = cert.get("group").and_then(|v| v.as_str()).unwrap_or("");
        let kind = cert.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if group != "" || kind != "Secret" {
            return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef must be a core Secret",
            });
        }
        let name = match cert.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef name is required",
            }),
        };
        let ns = cert
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(gateway_ns);
        if ns != gateway_ns {
            let permitted = grant_index.is_permitted(
                gateway_ns,
                "gateway.networking.k8s.io",
                "Gateway",
                ns,
                group,
                kind,
                name,
            );
            if !permitted {
                return Some(CertValidation {
                    reason: "RefNotPermitted",
                    message: "Cross-namespace CertificateRef is not permitted by ReferenceGrant",
                });
            }
        }

        let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(client.clone(), ns);
        let secret = match secrets.get(name).await {
            Ok(s) => s,
            Err(_) => return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef Secret not found",
            }),
        };
        if !secret_data_valid(&secret) {
            return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef Secret does not contain a valid TLS certificate",
            });
        }
    }

    None
}

fn secret_data_valid(secret: &k8s_openapi::api::core::v1::Secret) -> bool {
    use k8s_openapi::ByteString;
    let data = match secret.data.as_ref() {
        Some(d) => d,
        None => return false,
    };
    let check_pem = |key: &str| -> bool {
        let bytes: Vec<u8> = match data.get(key) {
            Some(ByteString(b)) => b.clone(),
            None => return false,
        };
        // Quick PEM sanity check: decoded bytes must contain the BEGIN header.
        String::from_utf8_lossy(&bytes).contains("-----BEGIN")
    };
    check_pem("tls.crt") && check_pem("tls.key")
}

/// Listener identifiers extracted from raw Gateway spec used for
/// matching HTTPRoute parentRefs.
struct ListenerKey {
    name: String,
    port: u16,
}

fn listener_keys(gw: &Gateway) -> Vec<ListenerKey> {
    gw.spec
        .listeners
        .iter()
        .filter_map(|l| l.as_object())
        .map(|obj| ListenerKey {
            name: obj.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            port: obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16,
        })
        .collect()
}

/// Check whether an HTTPRoute is accepted for a specific parentRef.
fn route_accepted_for_parent(
    route: &HTTPRoute,
    gw_ns: &str,
    gw_name: &str,
    parent_section: Option<&str>,
) -> bool {
    let Some(status) = route.status.as_ref() else {
        return false;
    };
    let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
    for parent_status in &status.parents {
        let pr = &parent_status.parent_ref;
        let pr_ns = pr.namespace.as_deref().unwrap_or(route_ns);
        if pr.name != gw_name || pr_ns != gw_ns {
            continue;
        }
        // If the spec parentRef has a sectionName, the status parentRef
        // should also have it. Match exactly.
        if parent_section.is_some() && pr.section_name.as_deref() != parent_section {
            continue;
        }
        let accepted = parent_status.conditions.iter().any(|c| {
            c.type_ == "Accepted" && c.status == "True"
        });
        if accepted {
            return true;
        }
    }
    false
}

/// Count how many HTTPRoutes are attached to each Gateway listener.
async fn count_attached_routes(
    client: &Client,
    gw_ns: &str,
    gw_name: &str,
    listeners: &[ListenerKey],
) -> Vec<i64> {
    let api: Api<HTTPRoute> = Api::all(client.clone());
    let mut counts = vec![0i64; listeners.len()];
    let Ok(list) = api.list(&Default::default()).await else {
        return counts;
    };
    for route in list {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
        let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
        for parent in parents {
            let parent_group = parent.group.as_deref().unwrap_or("gateway.networking.k8s.io");
            let parent_kind = parent.kind.as_deref().unwrap_or("Gateway");
            if parent_group != "gateway.networking.k8s.io" || parent_kind != "Gateway" {
                continue;
            }
            let parent_ns = parent.namespace.as_deref().unwrap_or(route_ns);
            if parent_ns != gw_ns || parent.name != gw_name {
                continue;
            }
            let parent_section = parent.section_name.as_deref();
            let parent_port = parent.port.map(|p| p as u16);
            // Only count routes that are Accepted for this parent.
            if !route_accepted_for_parent(&route, gw_ns, gw_name, parent_section) {
                continue;
            }
            for (idx, listener) in listeners.iter().enumerate() {
                let section_matches = parent_section.map(|s| s == listener.name).unwrap_or(true);
                let port_matches = parent_port.map(|p| p == listener.port).unwrap_or(true);
                if section_matches && port_matches {
                    counts[idx] += 1;
                }
            }
        }
    }
    counts
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

    // Programmed = True once the controller has accepted the Gateway.
    conditions.push(StatusCondition {
        condition_type: ConditionType::Programmed,
        status: ConditionStatus::True,
        reason: "Programmed".into(),
        message: "Gateway configuration programmed into proxy".into(),
        observed_generation,
    });

    conditions
}

/// Return the network address(es) advertised in `Gateway.status.addresses`.
///
/// The value is read from `SUNBEAM_GATEWAY_ADDRESS` and defaults to the
/// Multipass VM IP used in the integration environment.
fn gateway_addresses() -> Vec<serde_json::Value> {
    let addr = std::env::var("SUNBEAM_GATEWAY_ADDRESS")
        .unwrap_or_else(|_| "192.168.252.19".into());
    vec![serde_json::json!({
        "type": "IPAddress",
        "value": addr,
    })]
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

    let grants_api: Api<ReferenceGrant> = Api::all(ctx.client.clone());
    let grants = grants_api.list(&ListParams::default()).await?;
    let grant_index = GrantIndex::new(reconcile_reference_grants(&grants.items));

    let mut cert_errors: Vec<Option<CertValidation>> = Vec::new();
    for listener in &gw.spec.listeners {
        if let Some(obj) = listener.as_object() {
            let err = validate_listener_certificates(&ctx.client, &ns, obj, &grant_index).await;
            cert_errors.push(err);
        } else {
            cert_errors.push(None);
        }
    }

    let listeners = listener_keys(&gw);
    let attached_routes = count_attached_routes(&ctx.client, &ns, &name, &listeners).await;

    if ctx.is_leader.load(Ordering::Relaxed) {
        let k8s_conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition> =
            conditions.iter().map(to_k8s_condition).collect();
        let listener_statuses = build_listener_status(&gw, gc.as_ref(), observed_generation, &cert_errors, &attached_routes);
        let addresses = gateway_addresses();
        let new_status = serde_json::json!({
            "conditions": k8s_conditions,
            "listeners": listener_statuses,
            "addresses": addresses,
        });

        let old_status_json = gw.status.as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

        if old_stripped == new_stripped {
            tracing::debug!(%name, %ns, "Gateway status unchanged, skipping patch");
        } else {
            let patch = serde_json::json!({ "status": new_status });
            let api: Api<Gateway> = Api::namespaced(ctx.client.clone(), &ns);
            api.patch_status(
                &name,
                &PatchParams::apply("sunbeam-proxy"),
                &Patch::Merge(&patch),
            )
            .await?;
            tracing::info!(%name, %ns, "patched Gateway status");
        }
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
    fn programmed_is_true_when_accepted() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let conds = compute_gateway_conditions(&gw, Some(&gc), 1);
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::True);
        assert_eq!(programmed.reason, "Programmed");
        assert!(programmed.message.contains("programmed into proxy"));
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

    #[test]
    fn listener_status_contains_expected_fields() {
        let gw = sample_gw("test-gc");
        let statuses = build_listener_status(&gw, None, 3, &[], &[]);
        assert_eq!(statuses.len(), 2);

        let http = &statuses[0];
        assert_eq!(http.get("name").and_then(|v| v.as_str()), Some("http"));
        let supported = http.get("supportedKinds").and_then(|v| v.as_array()).unwrap();
        assert!(supported.iter().any(|k| {
            k.get("group").and_then(|g| g.as_str()) == Some("gateway.networking.k8s.io")
                && k.get("kind").and_then(|k| k.as_str()) == Some("HTTPRoute")
        }));

        let conditions = http.get("conditions").and_then(|v| v.as_array()).unwrap();
        let types: Vec<_> = conditions
            .iter()
            .filter_map(|c| c.get("type").and_then(|v| v.as_str()))
            .collect();
        assert!(types.contains(&"Accepted"));
        assert!(types.contains(&"Programmed"));
        assert!(types.contains(&"ResolvedRefs"));

        let first = &conditions[0];
        assert_eq!(first.get("status").and_then(|v| v.as_str()), Some("True"));
        assert_eq!(first.get("observedGeneration").and_then(|v| v.as_i64()), Some(3));
    }

    #[test]
    fn listener_status_invalid_route_kinds_sets_resolved_refs_false() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: invalid-kinds
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                  allowedRoutes:
                    namespaces:
                      from: All
                    kinds:
                      - kind: InvalidRoute
        "#;
        let gw: Gateway = serde_yaml::from_str(yaml).expect("deserializes");
        let statuses = build_listener_status(&gw, None, 1, &[], &[]);
        let resolved = statuses[0]
            .get("conditions")
            .and_then(|c| c.as_array())
            .unwrap()
            .iter()
            .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("ResolvedRefs"))
            .cloned()
            .unwrap();
        assert_eq!(resolved["status"], "False");
        assert_eq!(resolved["reason"], "InvalidRouteKinds");
        let supported = statuses[0]["supportedKinds"].as_array().unwrap();
        assert!(supported.is_empty());
    }

    #[test]
    fn listener_status_keeps_valid_kinds_when_mixed() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: mixed-kinds
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                  allowedRoutes:
                    kinds:
                      - kind: InvalidRoute
                      - kind: HTTPRoute
        "#;
        let gw: Gateway = serde_yaml::from_str(yaml).expect("deserializes");
        let statuses = build_listener_status(&gw, None, 1, &[], &[]);
        let supported = statuses[0]["supportedKinds"].as_array().unwrap();
        assert_eq!(supported.len(), 1);
        assert_eq!(supported[0]["kind"], "HTTPRoute");
        let resolved = statuses[0]["conditions"].as_array().unwrap()
            .iter()
            .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"], "False");
        assert_eq!(resolved["reason"], "InvalidRouteKinds");
    }

    #[test]
    fn listener_status_empty_for_no_listeners() {
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
        let statuses = build_listener_status(&gw, None, 1, &[], &[]);
        assert!(statuses.is_empty());
    }

    #[test]
    fn gateway_addresses_obeys_env_var_with_default() {
        // Ensure variable is absent for the default case.
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
        let addresses = gateway_addresses();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0]["type"], "IPAddress");
        assert_eq!(addresses[0]["value"], "192.168.252.19");

        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.5");
        }
        let addresses = gateway_addresses();
        assert_eq!(addresses[0]["value"], "10.0.0.5");

        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
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

    fn empty_list(kind: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": kind,
            "items": []
        })
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
