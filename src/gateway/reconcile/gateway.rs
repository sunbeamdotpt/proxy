// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway reconciler.
//!
//! Watches namespaced Gateway resources, computes `Accepted` and
//! `Programmed` status conditions, and builds the listener model.
//! Status writeback is gated on leadership.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::api::httproute::HTTPRoute;
use crate::gateway::api::{ListenerSet, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute};
use crate::gateway::model::view::FrontendValidation;
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerState, NamespaceFrom, RouteGroupKind,
    RouteNamespaces, TlsMode,
};
use crate::gateway::reconcile::gatewayclass::{supported_features, CONTROLLER_NAME};
use crate::gateway::reconcile::httproute::{
    listener_allows_kind, listener_hostname_intersects, namespace_allowed, parse_route_hostnames,
};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::patch::patch_status_if_changed;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use crate::ir::compile::CompiledL4Config;
use futures::StreamExt;
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::api::{Api, ListParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Parse the TLS termination mode from a raw listener object.
///
/// HTTPS listeners default to `Terminate`. TLS listeners read `tls.mode`
/// and default to `Passthrough` when the field is absent.
pub fn parse_tls_mode(
    obj: &serde_json::Map<String, serde_json::Value>,
    protocol: &str,
) -> Option<TlsMode> {
    match protocol {
        "HTTPS" => Some(TlsMode::Terminate),
        "TLS" => {
            let explicit = obj
                .get("tls")
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("mode"))
                .and_then(|v| v.as_str());
            match explicit {
                Some("Terminate") => Some(TlsMode::Terminate),
                Some("Passthrough") => Some(TlsMode::Passthrough),
                _ => Some(TlsMode::Passthrough),
            }
        }
        _ => None,
    }
}

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
            let protocol: Arc<str> = obj
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("HTTP")
                .into();
            let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
            let hostname = obj.get("hostname").and_then(|v| v.as_str()).map(Arc::from);
            let tls_mode = parse_tls_mode(obj, protocol.as_ref());
            listeners.push(ListenerState {
                name,
                protocol,
                port,
                hostname,
                tls_mode,
                frontend_validation: None,
                programmed: true,
            });
        }
    }
    listeners
}

/// Parse `allowedRoutes` from a raw listener object.
pub fn parse_allowed_routes(
    listener: &serde_json::Map<String, serde_json::Value>,
) -> AllowedRoutes {
    let allowed = match listener.get("allowedRoutes").and_then(|v| v.as_object()) {
        Some(a) => a,
        None => return AllowedRoutes::default(),
    };

    let kinds = allowed
        .get("kinds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|k| {
                    let group = k
                        .get("group")
                        .and_then(|v| v.as_str())
                        .unwrap_or("gateway.networking.k8s.io");
                    let kind = k.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                    if kind.is_empty() {
                        None
                    } else {
                        Some(RouteGroupKind {
                            group: Arc::from(group),
                            kind: Arc::from(kind),
                        })
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let namespaces = allowed
        .get("namespaces")
        .and_then(|v| v.as_object())
        .map(|ns| {
            let from = ns
                .get("from")
                .and_then(|v| v.as_str())
                .map(|s| match s {
                    "All" => NamespaceFrom::All,
                    "Selector" => NamespaceFrom::Selector,
                    _ => NamespaceFrom::Same,
                })
                .unwrap_or_default();

            let selector = ns
                .get("selector")
                .and_then(|v| v.as_object())
                .and_then(|sel| {
                    let map: BTreeMap<String, String> = sel
                        .get("matchLabels")
                        .and_then(|v| v.as_object())?
                        .iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect();
                    if map.is_empty() {
                        None
                    } else {
                        Some(map)
                    }
                });

            RouteNamespaces { from, selector }
        })
        .unwrap_or_default();

    AllowedRoutes { kinds, namespaces }
}

/// Raw CA certificate reference extracted from a listener validation block.
#[derive(Clone, Debug)]
struct CaCertificateRefRaw {
    group: Arc<str>,
    kind: Arc<str>,
    name: Arc<str>,
    namespace: Option<Arc<str>>,
}

/// Raw frontend validation configuration parsed from a Gateway listener.
#[derive(Clone, Debug)]
struct FrontendValidationSpec {
    ca_certificate_refs: Vec<CaCertificateRefRaw>,
    allow_insecure_fallback: bool,
}

fn parse_frontend_validation_obj(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<FrontendValidationSpec> {
    let refs = obj.get("caCertificateRefs").and_then(|v| v.as_array())?;
    let mut ca_certificate_refs = Vec::new();
    for r in refs {
        let r = r.as_object()?;
        let name = r.get("name").and_then(|v| v.as_str())?;
        if name.is_empty() {
            return None;
        }
        ca_certificate_refs.push(CaCertificateRefRaw {
            group: Arc::from(r.get("group").and_then(|v| v.as_str()).unwrap_or("")),
            kind: Arc::from(r.get("kind").and_then(|v| v.as_str()).unwrap_or("")),
            name: Arc::from(name),
            namespace: r.get("namespace").and_then(|v| v.as_str()).map(Arc::from),
        });
    }
    let allow_insecure_fallback = obj
        .get("mode")
        .and_then(|v| v.as_str())
        .map(|s| s == "AllowInsecureFallback")
        .unwrap_or(false);
    Some(FrontendValidationSpec {
        ca_certificate_refs,
        allow_insecure_fallback,
    })
}

/// Return the frontend validation configuration that applies to a listener,
/// resolving per-port overrides against the Gateway default.
fn listener_frontend_validation(
    gw_tls: Option<&serde_json::Value>,
    port: u16,
) -> Option<FrontendValidationSpec> {
    let tls = gw_tls?.as_object()?;
    let frontend = tls.get("frontend").and_then(|v| v.as_object())?;
    if let Some(per_port) = frontend.get("perPort").and_then(|v| v.as_array()) {
        for entry in per_port {
            let entry_port = entry.get("port").and_then(|v| v.as_u64())? as u16;
            if entry_port == port {
                return entry
                    .get("tls")
                    .and_then(|v| v.as_object())?
                    .get("validation")
                    .and_then(|v| v.as_object())
                    .and_then(parse_frontend_validation_obj);
            }
        }
    }
    frontend
        .get("default")
        .and_then(|v| v.as_object())?
        .get("validation")
        .and_then(|v| v.as_object())
        .and_then(parse_frontend_validation_obj)
}

/// Returns true when any TLS-terminated listener on the Gateway uses a frontend
/// validation mode of `AllowInsecureFallback`.
fn gateway_insecure_frontend_mode(gw: &Gateway) -> bool {
    let gw_tls = gw.spec.tls.as_ref();
    for listener in &gw.spec.listeners {
        let Some(obj) = listener.as_object() else {
            continue;
        };
        let protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP");
        let tls_mode = parse_tls_mode(obj, protocol);
        if !matches!(protocol, "HTTPS" | "TLS") || tls_mode != Some(TlsMode::Terminate) {
            continue;
        }
        let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        if let Some(spec) = listener_frontend_validation(gw_tls, port) {
            if spec.allow_insecure_fallback {
                return true;
            }
        }
    }
    false
}

/// Returns true when the compiled L4 dataplane has applied this Gateway's
/// TLS-terminated listeners with a matching frontend validation mode.
///
/// This prevents the Gateway from reporting `Programmed=True` before the
/// listener socket is actually enforcing the requested client-certificate
/// policy.  Listeners with unresolved certificate references are skipped so
/// that invalid configs still get their status patched promptly.
fn gateway_l4_ready(
    gw: &Gateway,
    l4_config: &CompiledL4Config,
    cert_errors: &[Option<CertValidation>],
) -> bool {
    let gw_tls = gw.spec.tls.as_ref();
    for (idx, listener) in gw.spec.listeners.iter().enumerate() {
        let Some(obj) = listener.as_object() else {
            continue;
        };
        // A listener that failed validation is not expected to be programmed
        // into the dataplane with the requested frontend validation.
        if cert_errors.get(idx).copied().flatten().is_some() {
            continue;
        }
        let protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP");
        let tls_mode = parse_tls_mode(obj, protocol);
        if !matches!(protocol, "HTTPS" | "TLS") || tls_mode != Some(TlsMode::Terminate) {
            continue;
        }
        let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        let ir_protocol = match protocol {
            "HTTPS" => crate::ir::Protocol::Https,
            "TLS" => crate::ir::Protocol::Tls,
            _ => continue,
        };
        let id: Arc<str> = format!("0.0.0.0:{}#{:?}", port, ir_protocol).into();
        let expected =
            listener_frontend_validation(gw_tls, port).map(|spec| spec.allow_insecure_fallback);
        let actual = l4_config
            .listeners
            .iter()
            .find(|l| l.id == id)
            .and_then(|l| {
                l.frontend_validation
                    .as_ref()
                    .map(|v| v.allow_insecure_fallback)
            });
        match (expected, actual) {
            (None, None) => {}
            (Some(expected), Some(actual)) if expected == actual => {}
            _ => return false,
        }
    }
    true
}

fn ca_bundle_valid(pem: &[u8]) -> bool {
    crate::tls::registry::parse_cert_chain(pem).is_ok()
}

/// Validate a listener's frontend client-certificate configuration.
///
/// Frontend validation only applies to TLS-terminated listeners. For other
/// listeners the configuration is ignored so that an invalid default does not
/// break plain HTTP listeners.
///
/// Returns `Some(CertValidation)` when the listener references an unsupported
/// resource kind, a missing ConfigMap, a ConfigMap that does not contain a
/// valid `ca.crt` entry, or a cross-namespace reference without a matching
/// ReferenceGrant.
pub async fn validate_listener_frontend_validation(
    client: &Client,
    gw_ns: &str,
    listener: &serde_json::Map<String, serde_json::Value>,
    gw_tls: Option<&serde_json::Value>,
    grant_index: &crate::gateway::reconcile::refgrant::GrantIndex,
) -> Option<CertValidation> {
    let protocol = listener
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTP");
    let tls_mode = parse_tls_mode(listener, protocol);
    if !matches!(protocol, "HTTPS" | "TLS") || tls_mode != Some(TlsMode::Terminate) {
        return None;
    }

    let port = listener.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
    let spec = match listener_frontend_validation(gw_tls, port) {
        Some(s) => s,
        None => return None,
    };

    for r in &spec.ca_certificate_refs {
        if r.kind.as_ref() != "ConfigMap" || !r.group.as_ref().is_empty() {
            return Some(CertValidation {
                reason: "InvalidCACertificateKind",
                message: "Frontend CA certificate reference must be a core ConfigMap",
            });
        }
        let ref_ns = r.namespace.as_deref().unwrap_or(gw_ns);
        if ref_ns != gw_ns
            && !grant_index.is_permitted(
                gw_ns,
                "gateway.networking.k8s.io",
                "Gateway",
                ref_ns,
                "",
                "ConfigMap",
                r.name.as_ref(),
            )
        {
            return Some(CertValidation {
                reason: "RefNotPermitted",
                message: "Frontend CA certificate reference is not permitted by ReferenceGrant",
            });
        }
        let cms: Api<ConfigMap> = Api::namespaced(client.clone(), ref_ns);
        let cm = match cms.get(r.name.as_ref()).await {
            Ok(c) => c,
            Err(_) => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap not found",
                })
            }
        };
        let data = match cm.data.as_ref() {
            Some(d) => d,
            None => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap has no data",
                })
            }
        };
        let ca = match data.get("ca.crt") {
            Some(v) => v.as_bytes(),
            None => {
                return Some(CertValidation {
                    reason: "InvalidCACertificateRef",
                    message: "Frontend CA certificate ConfigMap missing ca.crt",
                })
            }
        };
        if !ca_bundle_valid(ca) {
            return Some(CertValidation {
                reason: "InvalidCACertificateRef",
                message: "Frontend CA certificate is not a valid PEM bundle",
            });
        }
    }

    None
}

/// Load the PEM CA bundle for each listener's frontend validation and store
/// it in the corresponding [`ListenerState`]. Invalid or missing references
/// mark the listener as unprogrammed so routes do not attach to it.
pub async fn load_gateway_frontend_validations(
    client: &Client,
    gateways: &[Gateway],
    states: &mut [GatewayState],
    grant_index: &crate::gateway::reconcile::refgrant::GrantIndex,
) {
    for (gw, state) in gateways.iter().zip(states.iter_mut()) {
        let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
        let gw_tls = gw.spec.tls.as_ref();
        for (idx, listener) in state.listeners.iter_mut().enumerate() {
            if !matches!(listener.protocol.as_ref(), "HTTPS" | "TLS")
                || listener.tls_mode != Some(TlsMode::Terminate)
            {
                continue;
            }

            let mut valid = true;
            if let Some(obj) = gw.spec.listeners.get(idx).and_then(|v| v.as_object()) {
                if validate_listener_certificates(client, gw_ns, "Gateway", obj, grant_index)
                    .await
                    .is_some()
                {
                    valid = false;
                }
            } else {
                valid = false;
            }

            let spec = match listener_frontend_validation(gw_tls, listener.port) {
                Some(s) if valid => s,
                _ => {
                    if !valid {
                        listener.programmed = false;
                    }
                    continue;
                }
            };

            let mut bundle = String::new();
            for r in &spec.ca_certificate_refs {
                if r.kind.as_ref() != "ConfigMap" || !r.group.as_ref().is_empty() {
                    valid = false;
                    break;
                }
                let ref_ns = r.namespace.as_deref().unwrap_or(gw_ns);
                if ref_ns != gw_ns
                    && !grant_index.is_permitted(
                        gw_ns,
                        "gateway.networking.k8s.io",
                        "Gateway",
                        ref_ns,
                        "",
                        "ConfigMap",
                        r.name.as_ref(),
                    )
                {
                    valid = false;
                    break;
                }
                let cms: Api<ConfigMap> = Api::namespaced(client.clone(), ref_ns);
                let cm = match cms.get(r.name.as_ref()).await {
                    Ok(c) => c,
                    Err(_) => {
                        valid = false;
                        break;
                    }
                };
                let Some(data) = cm.data.as_ref() else {
                    valid = false;
                    break;
                };
                let Some(ca) = data.get("ca.crt") else {
                    valid = false;
                    break;
                };
                if !ca_bundle_valid(ca.as_bytes()) {
                    valid = false;
                    break;
                }
                bundle.push_str(ca);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
            }

            if !valid {
                listener.programmed = false;
                continue;
            }
            listener.frontend_validation = Some(FrontendValidation {
                ca_bundle_pem: Arc::from(bundle),
                allow_insecure_fallback: spec.allow_insecure_fallback,
            });
        }
    }
}

/// Build a map from `(gateway_namespace, gateway_name, listener_name)` to the
/// parsed `AllowedRoutes` for that listener.
pub fn build_listener_allowed_map(
    gateways: &[Gateway],
) -> HashMap<(String, String, String), AllowedRoutes> {
    let mut map = HashMap::new();
    for gw in gateways {
        let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
        let gw_name = gw.metadata.name.as_deref().unwrap_or("");
        for listener in &gw.spec.listeners {
            if let Some(obj) = listener.as_object() {
                let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                map.insert(
                    (gw_ns.to_string(), gw_name.to_string(), name.to_string()),
                    parse_allowed_routes(obj),
                );
            }
        }
    }
    map
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
    supported_features: &std::collections::HashSet<String>,
) -> Vec<serde_json::Value> {
    let supports_tls_terminate = supported_features.contains("TLSRouteModeTerminate");
    let supports_tls_mixed = supported_features.contains("TLSRouteModeMixed");
    let mixed_conflict_names = mixed_tls_conflict_names(&gw.spec.listeners);

    let mut statuses = Vec::new();
    for (idx, listener) in gw.spec.listeners.iter().enumerate() {
        let Some(obj) = listener.as_object() else {
            continue;
        };
        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP");
        let (
            mut supported_kinds,
            mut resolved_refs_status,
            mut resolved_refs_reason,
            mut resolved_refs_message,
        ) = validate_listener_kinds(obj);
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

        let (mut accepted_status, mut accepted_reason, mut accepted_message) = listener_accepted(
            name,
            protocol,
            parse_tls_mode(obj, protocol),
            &mixed_conflict_names,
            supports_tls_terminate,
            supports_tls_mixed,
        );
        if accepted_status == "False"
            && (accepted_reason == "UnsupportedValue" || accepted_reason == "ProtocolConflict")
        {
            supported_kinds = Vec::new();
        }
        if accepted_status == "True" {
            if let Some(err) = cert_errors.get(idx).copied().flatten() {
                accepted_status = "False";
                accepted_reason = if is_frontend_ca_error(err.reason) {
                    "NoValidCACertificate"
                } else {
                    err.reason
                };
                accepted_message = err.message;
            }
        }

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let status = serde_json::json!({
            "name": name,
            "supportedKinds": supported_kinds,
            "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
            "conditions": [
                {
                    "type": "Accepted",
                    "status": accepted_status,
                    "reason": accepted_reason,
                    "message": accepted_message,
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

/// Return the set of TLS listener names that participate in an unsupported
/// mixed Terminate/Passthrough configuration on the same port.
fn mixed_tls_conflict_names(listeners: &[serde_json::Value]) -> std::collections::HashSet<String> {
    let mut conflicts = std::collections::HashSet::new();
    let tls: Vec<_> = listeners
        .iter()
        .enumerate()
        .filter_map(|(idx, l)| {
            let obj = l.as_object()?;
            if obj.get("protocol").and_then(|v| v.as_str()) != Some("TLS") {
                return None;
            }
            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let port = obj.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
            let mode = parse_tls_mode(obj, "TLS").unwrap_or(TlsMode::Passthrough);
            Some((idx, name, port, mode))
        })
        .collect();
    for (i, name_i, port_i, mode_i) in &tls {
        for (j, name_j, port_j, mode_j) in &tls {
            if i >= j {
                continue;
            }
            if port_i == port_j && mode_i != mode_j {
                conflicts.insert(name_i.to_string());
                conflicts.insert(name_j.to_string());
            }
        }
    }
    conflicts
}

/// Compute the `Accepted` condition for a listener.
fn listener_accepted(
    _name: &str,
    protocol: &str,
    tls_mode: Option<TlsMode>,
    mixed_conflict_names: &std::collections::HashSet<String>,
    supports_tls_terminate: bool,
    supports_tls_mixed: bool,
) -> (&'static str, &'static str, &'static str) {
    if protocol == "TLS" {
        if mixed_conflict_names.contains(_name) {
            if supports_tls_mixed {
                return ("True", "Accepted", "Listener accepted");
            }
            return (
                "False",
                "ProtocolConflict",
                "Mixed TLS termination modes on the same port are not supported",
            );
        }
        if tls_mode == Some(TlsMode::Terminate) && !supports_tls_terminate {
            return (
                "False",
                "UnsupportedValue",
                "TLS termination mode Terminate is not supported",
            );
        }
    }
    ("True", "Accepted", "Listener accepted")
}

/// Return the default supported route kinds for a listener protocol.
pub fn listener_supported_kinds(
    protocol: &str,
    _tls_mode: Option<TlsMode>,
    _supported_features: &std::collections::HashSet<String>,
) -> Vec<serde_json::Value> {
    match protocol {
        "TCP" => {
            vec![serde_json::json!({"group": "gateway.networking.k8s.io", "kind": "TCPRoute"})]
        }
        "UDP" => {
            vec![serde_json::json!({"group": "gateway.networking.k8s.io", "kind": "UDPRoute"})]
        }
        "TLS" => {
            vec![serde_json::json!({"group": "gateway.networking.k8s.io", "kind": "TLSRoute"})]
        }
        _ => vec![
            serde_json::json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}),
            serde_json::json!({"group": "gateway.networking.k8s.io", "kind": "GRPCRoute"}),
        ],
    }
}

pub(crate) fn validate_listener_kinds(
    listener: &serde_json::Map<String, serde_json::Value>,
) -> (
    Vec<serde_json::Value>,
    &'static str,
    &'static str,
    &'static str,
) {
    let protocol = listener
        .get("protocol")
        .and_then(|v| v.as_str())
        .unwrap_or("HTTP");
    let default_kind_name = match protocol {
        "TCP" => "TCPRoute",
        "UDP" => "UDPRoute",
        "TLS" => "TLSRoute",
        _ => "HTTPRoute",
    };
    let default_kind = serde_json::json!({
        "group": "gateway.networking.k8s.io",
        "kind": default_kind_name,
    });
    let allowed_kinds = listener
        .get("allowedRoutes")
        .and_then(|v| v.get("kinds"))
        .and_then(|v| v.as_array());

    let kinds = match allowed_kinds {
        Some(arr) if !arr.is_empty() => arr.clone(),
        _ => {
            return (
                vec![default_kind],
                "True",
                "ResolvedRefs",
                "All references resolved",
            )
        }
    };

    let valid_kinds_for_protocol: &[&str] = match protocol {
        "TCP" => &["TCPRoute"],
        "UDP" => &["UDPRoute"],
        "TLS" => &["TLSRoute"],
        _ => &["HTTPRoute"],
    };
    let mut supported = Vec::new();
    let mut has_invalid = false;
    for entry in kinds {
        let group = entry
            .get("group")
            .and_then(|v| v.as_str())
            .unwrap_or("gateway.networking.k8s.io");
        let kind = entry.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if group == "gateway.networking.k8s.io" && valid_kinds_for_protocol.contains(&kind) {
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

/// Returns true when a `CertValidation` reason is one produced by frontend
/// client-certificate validation, which uses `NoValidCACertificate` for the
/// `Accepted` condition.
fn is_frontend_ca_error(reason: &str) -> bool {
    matches!(
        reason,
        "InvalidCACertificateRef" | "InvalidCACertificateKind" | "RefNotPermitted"
    )
}

/// Validate a listener's TLS certificate references.
///
/// Returns `Some(CertValidation)` when any certificate reference is malformed,
/// points to an unsupported resource kind, crosses a namespace boundary without
/// a matching ReferenceGrant, or the referenced Secret does not exist or does
/// not contain valid certificate data.
pub async fn validate_listener_certificates(
    client: &Client,
    from_ns: &str,
    from_kind: &str,
    listener: &serde_json::Map<String, serde_json::Value>,
    grant_index: &crate::gateway::reconcile::refgrant::GrantIndex,
) -> Option<CertValidation> {
    let tls = listener.get("tls")?;
    let certs = tls.get("certificateRefs").and_then(|v| v.as_array())?;
    if certs.is_empty() {
        return None;
    }

    for cert in certs {
        let group = cert.get("group").and_then(|v| v.as_str()).unwrap_or("");
        let kind = cert.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if !group.is_empty() || kind != "Secret" {
            return Some(CertValidation {
                reason: "InvalidCertificateRef",
                message: "CertificateRef must be a core Secret",
            });
        }
        let name = match cert.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => {
                return Some(CertValidation {
                    reason: "InvalidCertificateRef",
                    message: "CertificateRef name is required",
                })
            }
        };
        let ns = cert
            .get("namespace")
            .and_then(|v| v.as_str())
            .unwrap_or(from_ns);
        if ns != from_ns {
            let permitted = grant_index.is_permitted(
                from_ns,
                "gateway.networking.k8s.io",
                from_kind,
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
            Err(_) => {
                return Some(CertValidation {
                    reason: "InvalidCertificateRef",
                    message: "CertificateRef Secret not found",
                })
            }
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

/// Extract a syntactically valid Gateway backend client certificate reference.
fn gateway_backend_client_cert_ref(gw: &Gateway) -> Option<(Arc<str>, Arc<str>, Arc<str>)> {
    let tls = gw.spec.tls.as_ref()?.as_object()?;
    let backend = tls.get("backend")?.as_object()?;
    let cert_ref = backend.get("clientCertificateRef")?.as_object()?;
    let group = cert_ref.get("group").and_then(|v| v.as_str()).unwrap_or("");
    let kind = cert_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if !group.is_empty() || kind != "Secret" {
        return None;
    }
    let name = cert_ref.get("name").and_then(|v| v.as_str())?;
    if name.is_empty() {
        return None;
    }
    let ns = cert_ref
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| gw.metadata.namespace.as_deref().unwrap_or("default"));
    Some((Arc::from(ns), Arc::from(name), Arc::from("Secret")))
}

/// Validate a Gateway's backend TLS client certificate reference.
pub async fn validate_gateway_backend_tls(
    client: &Client,
    gw: &Gateway,
    grant_index: &GrantIndex,
) -> Option<CertValidation> {
    let tls = match gw.spec.tls.as_ref().and_then(|v| v.as_object()) {
        Some(t) => t,
        None => return None,
    };
    let backend = match tls.get("backend").and_then(|v| v.as_object()) {
        Some(b) => b,
        None => return None,
    };
    let cert_ref = match backend
        .get("clientCertificateRef")
        .and_then(|v| v.as_object())
    {
        Some(r) => r,
        None => return None,
    };

    let group = cert_ref.get("group").and_then(|v| v.as_str()).unwrap_or("");
    let kind = cert_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    if !group.is_empty() || kind != "Secret" {
        return Some(CertValidation {
            reason: "InvalidClientCertificateRef",
            message: "Gateway backend clientCertificateRef must be a core Secret",
        });
    }
    let name = match cert_ref.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => {
            return Some(CertValidation {
                reason: "InvalidClientCertificateRef",
                message: "Gateway backend clientCertificateRef name is required",
            })
        }
    };
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let ns = cert_ref
        .get("namespace")
        .and_then(|v| v.as_str())
        .unwrap_or(gw_ns);

    if ns != gw_ns {
        let permitted = grant_index.is_permitted(
            gw_ns,
            "gateway.networking.k8s.io",
            "Gateway",
            ns,
            "",
            "Secret",
            name,
        );
        if !permitted {
            return Some(CertValidation {
                reason: "RefNotPermitted",
                message: "Cross-namespace Gateway backend clientCertificateRef is not permitted",
            });
        }
    }

    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    match secrets.get(name).await {
        Ok(s) => {
            if !secret_data_valid(&s) {
                return Some(CertValidation {
                    reason: "InvalidClientCertificateRef",
                    message: "Gateway backend clientCertificateRef Secret does not contain a valid TLS certificate",
                });
            }
        }
        Err(_) => {
            return Some(CertValidation {
                reason: "InvalidClientCertificateRef",
                message: "Gateway backend clientCertificateRef Secret not found",
            })
        }
    }

    None
}

/// Listener identifiers and permissions extracted from raw Gateway spec.
struct ListenerMatch {
    name: String,
    port: u16,
    hostname: Option<String>,
    protocol: String,
    allowed: AllowedRoutes,
}

fn listener_matches(gw: &Gateway) -> Vec<ListenerMatch> {
    gw.spec
        .listeners
        .iter()
        .filter_map(|l| l.as_object())
        .map(|obj| ListenerMatch {
            name: obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            port: obj.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16,
            hostname: obj
                .get("hostname")
                .and_then(|v| v.as_str())
                .map(String::from),
            protocol: obj
                .get("protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("HTTP")
                .to_string(),
            allowed: parse_allowed_routes(obj),
        })
        .collect()
}

/// Common shape for a route parentRef so HTTPRoute and L4 routes can share
/// attachment counting logic.
struct ParentRefInfo {
    group: Option<String>,
    kind: Option<String>,
    namespace: Option<String>,
    name: String,
    section_name: Option<String>,
    port: Option<i32>,
}

impl ParentRefInfo {
    fn is_gateway(&self) -> bool {
        self.group.as_deref().unwrap_or("gateway.networking.k8s.io") == "gateway.networking.k8s.io"
            && self.kind.as_deref().unwrap_or("Gateway") == "Gateway"
    }
}

struct AttachmentCounter<'a> {
    listeners: &'a [ListenerMatch],
    gw_ns: &'a str,
    gw_name: &'a str,
    namespace_labels: &'a HashMap<String, HashMap<String, String>>,
    counts: &'a mut [i64],
}

impl<'a> AttachmentCounter<'a> {
    fn increment(
        &mut self,
        parent: &ParentRefInfo,
        route_ns: &str,
        route_hostnames: &[HostnameMatch],
        route_kind: &str,
        expected_protocol: &str,
    ) {
        if !parent.is_gateway() {
            return;
        }
        let parent_ns = parent.namespace.as_deref().unwrap_or(route_ns);
        if parent_ns != self.gw_ns || parent.name != self.gw_name {
            return;
        }
        let parent_section = parent.section_name.as_deref();
        let parent_port = parent.port.map(|p| p as u16);
        for (idx, listener) in self.listeners.iter().enumerate() {
            let section_matches = parent_section.map(|s| s == listener.name).unwrap_or(true);
            let port_matches = parent_port.map(|p| p == listener.port).unwrap_or(true);
            if !section_matches || !port_matches {
                continue;
            }
            if listener.protocol != expected_protocol {
                continue;
            }
            if !listener_allows_kind(&listener.allowed, "gateway.networking.k8s.io", route_kind) {
                continue;
            }
            if !namespace_allowed(
                &listener.allowed.namespaces,
                route_ns,
                self.gw_ns,
                self.namespace_labels,
            ) {
                continue;
            }
            if listener_hostname_intersects(listener.hostname.as_deref(), route_hostnames) {
                self.counts[idx] += 1;
            }
        }
    }
}

/// Count how many routes of each supported kind are attached to each Gateway
/// listener.
async fn count_attached_routes(
    client: &Client,
    gw_ns: &str,
    gw_name: &str,
    listeners: &[ListenerMatch],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> Vec<i64> {
    let mut counts = vec![0i64; listeners.len()];
    let mut counter = AttachmentCounter {
        listeners,
        gw_ns,
        gw_name,
        namespace_labels,
        counts: &mut counts,
    };

    // HTTPRoutes
    if let Ok(list) = Api::<HTTPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let route_hostnames = parse_route_hostnames(&route);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &route_hostnames, "HTTPRoute", "HTTPS");
                counter.increment(&info, route_ns, &route_hostnames, "HTTPRoute", "HTTP");
            }
        }
    }

    // TCPRoutes
    if let Ok(list) = Api::<TCPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &[], "TCPRoute", "TCP");
            }
        }
    }

    // UDPRoutes
    if let Ok(list) = Api::<UDPRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &[], "UDPRoute", "UDP");
            }
        }
    }

    // TLSRoutes
    if let Ok(list) = Api::<TLSRoute>::all(client.clone())
        .list(&Default::default())
        .await
    {
        for route in list {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or(gw_ns);
            let hostnames: Vec<HostnameMatch> = route
                .spec
                .hostnames
                .iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect();
            let parents = route.spec.parent_refs.as_deref().unwrap_or(&[]);
            for parent in parents {
                let info = ParentRefInfo {
                    group: parent.group.clone(),
                    kind: parent.kind.clone(),
                    namespace: parent.namespace.clone(),
                    name: parent.name.clone(),
                    section_name: parent.section_name.clone(),
                    port: parent.port,
                };
                counter.increment(&info, route_ns, &hostnames, "TLSRoute", "TLS");
            }
        }
    }

    counts
}

/// A Gateway address requested in `spec.addresses`.
#[derive(Clone, Debug)]
pub(crate) struct GatewaySpecAddress {
    type_: String,
    value: Option<String>,
}

/// Result of validating `spec.addresses` against what this implementation can
/// assign.
#[derive(Clone, Debug, Default)]
pub(crate) struct AddressValidation {
    unsupported: Vec<GatewaySpecAddress>,
    unusable: Vec<GatewaySpecAddress>,
    usable: Vec<GatewaySpecAddress>,
}

/// Parse the requested addresses from a Gateway spec.
fn parse_gateway_addresses(gw: &Gateway) -> Vec<GatewaySpecAddress> {
    let Some(addrs) = gw.spec.addresses.as_deref() else {
        return Vec::new();
    };
    addrs
        .iter()
        .filter_map(|v| v.as_object())
        .map(|obj| GatewaySpecAddress {
            type_: obj
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("IPAddress")
                .to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).map(String::from),
        })
        .collect()
}

/// The implementation-defined address that can actually be assigned to a
/// Gateway. Read from `SUNBEAM_GATEWAY_ADDRESS` with a development default.
fn implementation_address() -> String {
    std::env::var("SUNBEAM_GATEWAY_ADDRESS").unwrap_or_else(|_| "192.168.252.19".into())
}

/// Validate requested addresses. Only `IPAddress` is supported; the assigned
/// value must match the implementation address unless the value is empty, in
/// which case it is filled in.
fn validate_gateway_addresses(addrs: &[GatewaySpecAddress]) -> AddressValidation {
    let impl_addr = implementation_address();
    let mut validation = AddressValidation::default();
    for addr in addrs {
        if addr.type_ != "IPAddress" {
            validation.unsupported.push(addr.clone());
            continue;
        }
        match &addr.value {
            Some(v) if v == &impl_addr => validation.usable.push(addr.clone()),
            Some(_) => validation.unusable.push(addr.clone()),
            None => validation.usable.push(GatewaySpecAddress {
                type_: addr.type_.clone(),
                value: Some(impl_addr.clone()),
            }),
        }
    }
    validation
}

/// Return the address(es) to publish in `Gateway.status.addresses`.
fn gateway_status_addresses(validation: &AddressValidation) -> Vec<serde_json::Value> {
    validation
        .usable
        .iter()
        .map(|a| {
            serde_json::json!({
                "type": a.type_,
                "value": a.value.as_deref().unwrap_or(""),
            })
        })
        .collect()
}

/// Compute the status conditions for a Gateway.
///
/// * `Accepted` — `True` when the referenced GatewayClass exists and is
///   managed by this controller and no unsupported addresses are requested.
/// * `Programmed` — `True` when the Gateway is accepted and all requested
///   addresses are usable.
pub(crate) fn compute_gateway_conditions(
    _gw: &Gateway,
    gateway_class: Option<&GatewayClass>,
    address_validation: &AddressValidation,
    backend_tls_error: Option<CertValidation>,
    insecure_frontend_mode: bool,
    observed_generation: i64,
) -> Vec<StatusCondition> {
    let mut conditions = Vec::new();

    // Accepted
    let accepted = if let Some(gc) = gateway_class {
        if gc.spec.controller_name != CONTROLLER_NAME {
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
        } else if !address_validation.unsupported.is_empty() {
            let types: Vec<_> = address_validation
                .unsupported
                .iter()
                .map(|a| format!("{}={}", a.type_, a.value.as_deref().unwrap_or("")))
                .collect();
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "UnsupportedAddress".into(),
                message: format!("Unsupported address type(s): {}", types.join(", ")),
                observed_generation,
            }
        } else {
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::True,
                reason: "Accepted".into(),
                message: "Gateway references an accepted GatewayClass".into(),
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
    let accepted_true = accepted.status == ConditionStatus::True;
    conditions.push(accepted);

    // Programmed
    let programmed = if !accepted_true {
        StatusCondition {
            condition_type: ConditionType::Programmed,
            status: ConditionStatus::False,
            reason: "Invalid".into(),
            message: "Gateway is not accepted".into(),
            observed_generation,
        }
    } else if !address_validation.unusable.is_empty() {
        let values: Vec<_> = address_validation
            .unusable
            .iter()
            .map(|a| a.value.as_deref().unwrap_or(""))
            .collect();
        StatusCondition {
            condition_type: ConditionType::Programmed,
            status: ConditionStatus::False,
            reason: "AddressNotUsable".into(),
            message: format!("Address(es) not usable: {}", values.join(", ")),
            observed_generation,
        }
    } else {
        StatusCondition {
            condition_type: ConditionType::Programmed,
            status: ConditionStatus::True,
            reason: "Programmed".into(),
            message: "Gateway configuration programmed into proxy".into(),
            observed_generation,
        }
    };
    conditions.push(programmed);

    // ResolvedRefs
    let resolved_refs = if let Some(err) = backend_tls_error {
        StatusCondition {
            condition_type: ConditionType::ResolvedRefs,
            status: ConditionStatus::False,
            reason: err.reason.into(),
            message: err.message.into(),
            observed_generation,
        }
    } else {
        StatusCondition {
            condition_type: ConditionType::ResolvedRefs,
            status: ConditionStatus::True,
            reason: "ResolvedRefs".into(),
            message: "All references resolved".into(),
            observed_generation,
        }
    };
    conditions.push(resolved_refs);

    if insecure_frontend_mode {
        conditions.push(StatusCondition {
            condition_type: ConditionType::InsecureFrontendValidationMode,
            status: ConditionStatus::True,
            reason: "ConfigurationChanged".into(),
            message: "Frontend validation mode is AllowInsecureFallback".into(),
            observed_generation,
        });
    }

    conditions
}

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
    let sa = k8s_openapi::api::core::v1::ServiceAccount {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(sa_name.clone()),
            namespace: Some(ns.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        ..Default::default()
    };

    let api: Api<k8s_openapi::api::core::v1::ServiceAccount> = Api::namespaced(client.clone(), ns);
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
    let observed_generation = gw.metadata.generation.unwrap_or(0).max(1);

    // Look up the referenced GatewayClass (cluster-scoped).
    let gatewayclasses: Api<GatewayClass> = Api::all(ctx.client.clone());
    let gc = gatewayclasses.get(&gw.spec.gateway_class_name).await.ok();

    let grants: Api<ReferenceGrant> = Api::all(ctx.client.clone());
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

        let k8s_conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition> =
            conditions.iter().map(Condition::from).collect();
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
    use crate::gateway::model::{GrantSubject, ReferenceGrantState};
    use crate::ir::compile::{CompiledFrontendValidation, CompiledL4Config, CompiledListener};

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
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
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
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, None, &validation, None, false, 1);
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
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
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
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
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

    fn empty_features() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    #[test]
    fn listener_status_contains_expected_fields() {
        let gw = sample_gw("test-gc");
        let statuses = build_listener_status(&gw, None, 3, &[], &[], &empty_features());
        assert_eq!(statuses.len(), 2);

        let http = &statuses[0];
        assert_eq!(http.get("name").and_then(|v| v.as_str()), Some("http"));
        let supported = http
            .get("supportedKinds")
            .and_then(|v| v.as_array())
            .unwrap();
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
        assert_eq!(
            first.get("observedGeneration").and_then(|v| v.as_i64()),
            Some(3)
        );
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
        let statuses = build_listener_status(&gw, None, 1, &[], &[], &empty_features());
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
        let statuses = build_listener_status(&gw, None, 1, &[], &[], &empty_features());
        let supported = statuses[0]["supportedKinds"].as_array().unwrap();
        assert_eq!(supported.len(), 1);
        assert_eq!(supported[0]["kind"], "HTTPRoute");
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
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
        let statuses = build_listener_status(&gw, None, 1, &[], &[], &empty_features());
        assert!(statuses.is_empty());
    }

    #[test]
    fn gateway_addresses_obeys_env_var_with_default() {
        // Ensure variable is absent for the default case.
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
        let validation = AddressValidation::default();
        let addresses = gateway_status_addresses(&validation);
        assert!(addresses.is_empty());
        assert_eq!(implementation_address(), "192.168.252.19");

        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.5");
        }
        let validation = AddressValidation {
            usable: vec![GatewaySpecAddress {
                type_: "IPAddress".into(),
                value: Some(implementation_address()),
            }],
            ..Default::default()
        };
        let addresses = gateway_status_addresses(&validation);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0]["type"], "IPAddress");
        assert_eq!(addresses[0]["value"], "10.0.0.5");

        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_marks_unsupported_type() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "test/fake".into(),
            value: Some("x".into()),
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.unsupported.len(), 1);
        assert!(v.usable.is_empty());
        assert!(v.unusable.is_empty());
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_marks_non_impl_address_unusable() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "IPAddress".into(),
            value: Some("10.0.0.2".into()),
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.unusable.len(), 1);
        assert!(v.usable.is_empty());
        assert!(v.unsupported.is_empty());
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_fills_empty_ip_address() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "IPAddress".into(),
            value: None,
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.usable.len(), 1);
        assert_eq!(v.usable[0].value.as_deref(), Some("10.0.0.1"));
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn unsupported_address_makes_accepted_false() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let validation = AddressValidation {
            unsupported: vec![GatewaySpecAddress {
                type_: "Hostname".into(),
                value: Some("x".into()),
            }],
            ..Default::default()
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "UnsupportedAddress");
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
    }

    #[test]
    fn unusable_address_leaves_accepted_true() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let validation = AddressValidation {
            unusable: vec![GatewaySpecAddress {
                type_: "IPAddress".into(),
                value: Some("10.0.0.2".into()),
            }],
            ..Default::default()
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
        assert_eq!(programmed.reason, "AddressNotUsable");
    }

    #[tokio::test]
    async fn error_policy_requeues_after_5s() {
        let gw = Arc::new(sample_gw("test-gc"));
        let ctx = Arc::new(GatewayContext {
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

    #[tokio::test]
    async fn gateway_context_clone_smoke() {
        let ctx = GatewayContext {
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
    fn secret_data_valid_requires_tls_crt_and_key() {
        let valid = k8s_openapi::api::core::v1::Secret {
            data: Some(std::collections::BTreeMap::from([
                (
                    "tls.crt".to_string(),
                    k8s_openapi::ByteString(b"-----BEGIN CERTIFICATE-----\n".to_vec()),
                ),
                (
                    "tls.key".to_string(),
                    k8s_openapi::ByteString(b"-----BEGIN PRIVATE KEY-----\n".to_vec()),
                ),
            ])),
            ..Default::default()
        };
        assert!(secret_data_valid(&valid));

        let missing_key = k8s_openapi::api::core::v1::Secret {
            data: Some(std::collections::BTreeMap::from([(
                "tls.crt".to_string(),
                k8s_openapi::ByteString(b"-----BEGIN CERTIFICATE-----\n".to_vec()),
            )])),
            ..Default::default()
        };
        assert!(!secret_data_valid(&missing_key));

        let no_data = k8s_openapi::api::core::v1::Secret {
            data: None,
            ..Default::default()
        };
        assert!(!secret_data_valid(&no_data));
    }

    #[tokio::test]
    async fn count_attached_routes_counts_accepted_routes() {
        let route_yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-1
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              hostnames:
                - example.com
            status:
              parents:
                - parentRef:
                    name: gw-1
                    namespace: default
                  controllerName: sunbeam.io/gateway-controller
                  conditions:
                    - type: Accepted
                      status: "True"
                      reason: Accepted
                      lastTransitionTime: "2026-01-01T00:00:00Z"
        "#;
        let route: HTTPRoute = serde_yaml::from_str(route_yaml).unwrap();
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "HTTPRouteList",
                    "items": [serde_json::to_value(&route).unwrap()]
                });
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
        let listeners = vec![crate::gateway::reconcile::gateway::ListenerMatch {
            name: "http".to_string(),
            port: 80,
            hostname: None,
            protocol: "HTTP".to_string(),
            allowed: crate::gateway::model::AllowedRoutes::default(),
        }];
        let namespace_labels =
            std::collections::HashMap::<String, std::collections::HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1]);
    }

    #[tokio::test]
    async fn count_attached_routes_filters_by_section_name() {
        let route: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-1
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: http
        "#,
        )
        .unwrap();
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let body = serde_json::json!({
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "HTTPRouteList",
                    "items": [serde_json::to_value(&route).unwrap()]
                });
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
        let listeners = vec![
            crate::gateway::reconcile::gateway::ListenerMatch {
                name: "http".to_string(),
                port: 80,
                hostname: None,
                protocol: "HTTP".to_string(),
                allowed: crate::gateway::model::AllowedRoutes::default(),
            },
            crate::gateway::reconcile::gateway::ListenerMatch {
                name: "https".to_string(),
                port: 443,
                hostname: None,
                protocol: "HTTPS".to_string(),
                allowed: crate::gateway::model::AllowedRoutes::default(),
            },
        ];
        let namespace_labels =
            std::collections::HashMap::<String, std::collections::HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1, 0]);
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_non_secret_ref() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "GatewayClass", "name": "gc"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = crate::gateway::reconcile::refgrant::GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert!(err.is_some());
        assert_eq!(err.unwrap().reason, "InvalidCertificateRef");
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_missing_name() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = crate::gateway::reconcile::refgrant::GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_cross_namespace_without_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "cert", "namespace": "other"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = crate::gateway::reconcile::refgrant::GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("RefNotPermitted"));
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_missing_secret() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "missing"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = crate::gateway::reconcile::refgrant::GrantIndex::new(vec![]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    fn tls_gateway_yaml(mode_a: &str, mode_b: Option<&str>) -> Gateway {
        let listeners = match mode_b {
            Some(mode_b) => serde_yaml::from_str(&format!(
                r#"
                apiVersion: gateway.networking.k8s.io/v1
                kind: Gateway
                metadata:
                  name: tls-gw
                  namespace: default
                  generation: 1
                spec:
                  gatewayClassName: test-gc
                  listeners:
                    - name: tls-a
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_a}
                        certificateRefs: [{{kind: Secret, name: cert-a}}]
                    - name: tls-b
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_b}
                        certificateRefs: [{{kind: Secret, name: cert-b}}]
                "#
            )),
            None => serde_yaml::from_str(&format!(
                r#"
                apiVersion: gateway.networking.k8s.io/v1
                kind: Gateway
                metadata:
                  name: tls-gw
                  namespace: default
                  generation: 1
                spec:
                  gatewayClassName: test-gc
                  listeners:
                    - name: tls-a
                      protocol: TLS
                      port: 8443
                      tls:
                        mode: {mode_a}
                        certificateRefs: [{{kind: Secret, name: cert-a}}]
                "#
            )),
        };
        listeners.expect("deserializes")
    }

    fn accepted_reason(statuses: &[serde_json::Value], name: &str) -> Option<String> {
        statuses
            .iter()
            .find(|s| s.get("name").and_then(|v| v.as_str()) == Some(name))
            .and_then(|s| s.get("conditions").and_then(|v| v.as_array()))
            .and_then(|conds| {
                conds
                    .iter()
                    .find(|c| c.get("type").and_then(|v| v.as_str()) == Some("Accepted"))
            })
            .and_then(|c| c.get("reason").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
    }

    #[test]
    fn listener_status_accepts_tls_terminate_when_supported() {
        let gw = tls_gateway_yaml("Terminate", None);
        let mut features = empty_features();
        features.insert("TLSRouteModeTerminate".to_string());
        let statuses = build_listener_status(&gw, None, 1, &[], &[0], &features);
        assert_eq!(
            accepted_reason(&statuses, "tls-a"),
            Some("Accepted".to_string())
        );
    }

    #[test]
    fn listener_status_rejects_tls_terminate_when_unsupported() {
        let gw = tls_gateway_yaml("Terminate", None);
        let statuses = build_listener_status(&gw, None, 1, &[], &[0], &empty_features());
        assert_eq!(
            accepted_reason(&statuses, "tls-a"),
            Some("UnsupportedValue".to_string())
        );
    }

    #[test]
    fn listener_status_rejects_mixed_tls_modes_when_unsupported() {
        let gw = tls_gateway_yaml("Terminate", Some("Passthrough"));
        let mut features = empty_features();
        features.insert("TLSRouteModeTerminate".to_string());
        let statuses = build_listener_status(&gw, None, 1, &[], &[0, 0], &features);
        assert_eq!(
            accepted_reason(&statuses, "tls-a"),
            Some("ProtocolConflict".to_string())
        );
        assert_eq!(
            accepted_reason(&statuses, "tls-b"),
            Some("ProtocolConflict".to_string())
        );
    }

    #[test]
    fn listener_status_accepts_mixed_tls_modes_when_supported() {
        let gw = tls_gateway_yaml("Terminate", Some("Passthrough"));
        let mut features = empty_features();
        features.insert("TLSRouteModeTerminate".to_string());
        features.insert("TLSRouteModeMixed".to_string());
        let statuses = build_listener_status(&gw, None, 1, &[], &[0, 0], &features);
        assert_eq!(
            accepted_reason(&statuses, "tls-a"),
            Some("Accepted".to_string())
        );
        assert_eq!(
            accepted_reason(&statuses, "tls-b"),
            Some("Accepted".to_string())
        );
    }

    #[test]
    fn parse_allowed_routes_defaults_when_missing() {
        let obj = serde_json::Map::new();
        let allowed = parse_allowed_routes(&obj);
        assert!(allowed.kinds.is_empty());
        assert_eq!(allowed.namespaces.from, NamespaceFrom::Same);
        assert!(allowed.namespaces.selector.is_none());
    }

    #[test]
    fn parse_allowed_routes_reads_kinds_and_namespaces() {
        let obj = serde_json::json!({
            "allowedRoutes": {
                "kinds": [
                    {"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"},
                    {"group": "", "kind": "TCPRoute"},
                    {"kind": ""}
                ],
                "namespaces": {
                    "from": "All",
                    "selector": {
                        "matchLabels": {"env": "prod"}
                    }
                }
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let allowed = parse_allowed_routes(&obj);
        assert_eq!(allowed.kinds.len(), 2);
        assert_eq!(allowed.kinds[0].kind.as_ref(), "HTTPRoute");
        assert_eq!(allowed.kinds[1].group.as_ref(), "");
        assert_eq!(allowed.namespaces.from, NamespaceFrom::All);
        assert_eq!(
            allowed.namespaces.selector,
            Some(std::collections::BTreeMap::from([(
                "env".to_string(),
                "prod".to_string()
            )]))
        );
    }

    #[test]
    fn parse_allowed_routes_selector_falls_back_to_same() {
        let obj = serde_json::json!({
            "allowedRoutes": {
                "namespaces": {
                    "from": "Selector"
                }
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let allowed = parse_allowed_routes(&obj);
        assert_eq!(allowed.namespaces.from, NamespaceFrom::Selector);
        assert!(allowed.namespaces.selector.is_none());
    }

    #[test]
    fn build_listener_allowed_map_populates_per_listener() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                  allowedRoutes:
                    namespaces:
                      from: All
        "#,
        )
        .unwrap();
        let map = build_listener_allowed_map(&[gw]);
        let key = (
            "default".to_string(),
            "gw-1".to_string(),
            "http".to_string(),
        );
        assert_eq!(map.get(&key).unwrap().namespaces.from, NamespaceFrom::All);
    }

    #[test]
    fn parse_frontend_validation_obj_extracts_configmap_refs() {
        let obj = serde_json::json!({
            "caCertificateRefs": [
                {"group": "", "kind": "ConfigMap", "name": "ca-1"},
                {"group": "", "kind": "ConfigMap", "name": "ca-2"}
            ],
            "mode": "AllowInsecureFallback"
        })
        .as_object()
        .unwrap()
        .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert_eq!(spec.ca_certificate_refs.len(), 2);
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "ca-1");
        assert!(spec.allow_insecure_fallback);
    }

    #[test]
    fn parse_frontend_validation_obj_preserves_non_configmap_kind() {
        let obj = serde_json::json!({
            "caCertificateRefs": [
                {"group": "", "kind": "Secret", "name": "ca-1"}
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].kind.as_ref(), "Secret");
    }

    #[test]
    fn listener_frontend_validation_default_applies_to_listener() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}],
                        "mode": "AllowValidOnly"
                    }
                }
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "ca");
        assert!(!spec.allow_insecure_fallback);
    }

    #[test]
    fn listener_frontend_validation_per_port_overrides_default() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [
                    {
                        "port": 8443,
                        "tls": {
                            "validation": {
                                "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "port-ca"}]
                            }
                        }
                    }
                ]
            }
        });
        let default_spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(
            default_spec.ca_certificate_refs[0].name.as_ref(),
            "default-ca"
        );
        let port_spec = listener_frontend_validation(Some(&tls), 8443).unwrap();
        assert_eq!(port_spec.ca_certificate_refs[0].name.as_ref(), "port-ca");
    }

    #[test]
    fn listener_frontend_validation_returns_none_without_tls() {
        assert!(listener_frontend_validation(None, 443).is_none());
    }

    #[test]
    fn listener_frontend_validation_insecure_mode() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}],
                        "mode": "AllowInsecureFallback"
                    }
                }
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert!(spec.allow_insecure_fallback);
    }

    #[test]
    fn build_listener_status_marks_invalid_frontend_validation() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            supported_features().into_iter().collect();
        let err = Some(CertValidation {
            reason: "InvalidFrontendClientCertificateValidation",
            message: "Frontend CA certificate ConfigMap not found",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(
            resolved["reason"].as_str(),
            Some("InvalidFrontendClientCertificateValidation")
        );
        let programmed = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Programmed"))
            .unwrap();
        assert_eq!(programmed["status"].as_str(), Some("False"));
    }

    #[test]
    fn is_frontend_ca_error_detects_ca_reasons() {
        assert!(is_frontend_ca_error("InvalidCACertificateRef"));
        assert!(is_frontend_ca_error("InvalidCACertificateKind"));
        assert!(is_frontend_ca_error("RefNotPermitted"));
        assert!(!is_frontend_ca_error("InvalidCertificateRef"));
        assert!(!is_frontend_ca_error(
            "InvalidFrontendClientCertificateValidation"
        ));
    }

    #[test]
    fn build_listener_status_maps_frontend_ca_error_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            supported_features().into_iter().collect();
        let err = Some(CertValidation {
            reason: "InvalidCACertificateRef",
            message: "Frontend CA certificate ConfigMap not found",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[test]
    fn build_listener_status_maps_invalid_ca_kind_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            supported_features().into_iter().collect();
        let err = Some(CertValidation {
            reason: "InvalidCACertificateKind",
            message: "Frontend CA certificate reference must be a core ConfigMap",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(
            resolved["reason"].as_str(),
            Some("InvalidCACertificateKind")
        );
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[test]
    fn build_listener_status_maps_ref_not_permitted_to_accepted_no_valid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let features: std::collections::HashSet<String> =
            supported_features().into_iter().collect();
        let err = Some(CertValidation {
            reason: "RefNotPermitted",
            message: "Frontend CA certificate reference is not permitted by ReferenceGrant",
        });
        let statuses = build_listener_status(&gw, None, 1, &[err], &[0], &features);
        let resolved = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("ResolvedRefs"))
            .unwrap();
        assert_eq!(resolved["status"].as_str(), Some("False"));
        assert_eq!(resolved["reason"].as_str(), Some("RefNotPermitted"));
        let accepted = statuses[0]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["type"].as_str() == Some("Accepted"))
            .unwrap();
        assert_eq!(accepted["status"].as_str(), Some("False"));
        assert_eq!(accepted["reason"].as_str(), Some("NoValidCACertificate"));
    }

    #[test]
    fn gateway_insecure_frontend_mode_detects_allow_insecure_fallback() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        assert!(gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn gateway_insecure_frontend_mode_false_for_allow_valid_only() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        assert!(!gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn compute_gateway_conditions_adds_insecure_frontend_mode() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, true, 1);
        let cond = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::InsecureFrontendValidationMode)
            .unwrap();
        assert_eq!(cond.status, ConditionStatus::True);
        assert_eq!(cond.reason, "ConfigurationChanged");
    }

    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBijCCATGgAwIBAgIUae+5bMkQvXZI8kjz4yoGasBrilYwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA2MTMxMDExMTJaFw0y
NzA2MTMxMDExMTJaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASnTjZLqwGQj3b8xkyDFQe38SBzfsyxNUEy5fzO
54cks0X7K9JIWJLigltzP4Jh5OwYUSD0UrKXSukj/LRKkL5Eo1MwUTAdBgNVHQ4E
FgQUyoVck0knQWBZB4na42ZOz3Ke/ykwHwYDVR0jBBgwFoAUyoVck0knQWBZB4na
42ZOz3Ke/ykwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAFHJQe
Ltr83KS7tC2NbWRybv6NdUG5fuzrS61t06Yi6wIgOkoD6+KlR4UOP4dFIojV5uz4
huKv4WWxIg9T0tCH/yU=
-----END CERTIFICATE-----
"#;

    const CERT_B64: &str = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpakNDQVRHZ0F3SUJBZ0lVYWUrNWJNa1F2WFpJOGtqejR5b0dhc0JyaWxZd0NnWUlLb1pJemowRUF3SXcKR3pFWk1CY0dBMVVFQXd3UWRHVnpkQzVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakEyTVRNeE1ERXhNVEphRncweQpOekEyTVRNeE1ERXhNVEphTUJzeEdUQVhCZ05WQkFNTUVIUmxjM1F1WlhoaGJYQnNaUzVqYjIwd1dUQVRCZ2NxCmhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBU25UalpMcXdHUWozYjh4a3lERlFlMzhTQnpmc3l4TlVFeTVmek8KNTRja3MwWDdLOUpJV0pMaWdsdHpQNEpoNU93WVVTRDBVcktYU3Vrai9MUktrTDVFbzFNd1VUQWRCZ05WSFE0RQpGZ1FVeW9WY2swa25RV0JaQjRuYTQyWk96M0tlL3lrd0h3WURWUjBqQkJnd0ZvQVV5b1ZjazBrblFXQlpCNG5hCjQyWk96M0tlL3lrd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBS0JnZ3Foa2pPUFFRREFnTkhBREJFQWlBRkhKUWUKTHRyODNLUzd0QzJOYldSeWJ2Nk5kVUc1ZnV6clM2MXQwNllpNndJZ09rb0Q2K0tsUjRVT1A0ZEZJb2pWNXV6NApodUt2NFdXeElnOVQwdENIL3lVPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==";
    const KEY_B64: &str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZzkvT2h2a2E0NFdqYXlXRHAKeHozYnVwekphNWpvWmxyL081NXF1QTI4VUpXaFJBTkNBQVNuVGpaTHF3R1FqM2I4eGt5REZRZTM4U0J6ZnN5eApOVUV5NWZ6TzU0Y2tzMFg3SzlKSVdKTGlnbHR6UDRKaDVPd1lVU0QwVXJLWFN1a2ovTFJLa0w1RQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==";

    fn fake_kube_client(response_body: String) -> Client {
        Client::new(
            tower::service_fn(move |_req| {
                let body = response_body.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .body(kube::client::Body::from(bytes::Bytes::from(body)))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_non_configmap_ref() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "example.com", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateKind"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_returns_none_for_http() {
        let listener = serde_json::json!({
            "name": "http",
            "protocol": "HTTP",
            "port": 80
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_configmap() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "missing"}]
                    }
                }
            }
        });
        let client = Client::new(
            tower::service_fn(|_req| async {
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
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_accepts_valid_configmap() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_listener_unprogrammed_on_invalid_ca() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: missing-ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
                  tls:
                    certificateRefs:
                    - kind: Secret
                      name: cert
        "#,
        )
        .unwrap();

        let mut state = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("https"),
                protocol: Arc::from("HTTPS"),
                port: 443,
                hostname: None,
                tls_mode: Some(TlsMode::Terminate),
                frontend_validation: None,
                programmed: true,
            }],
            backend_client_cert_id: None,
        };

        let client = Client::new(
            tower::service_fn(|_req| async {
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
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &grant_index,
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_invalid_kind() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: ConfigMap
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_missing_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: missing
              listeners: []
        "#,
        )
        .unwrap();
        let client = Client::new(
            tower::service_fn(|_req| async {
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
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_accepts_valid_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert!(err.is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_extracts_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let (ns, name, kind) = gateway_backend_client_cert_ref(&gw).unwrap();
        assert_eq!(ns.as_ref(), "default");
        assert_eq!(name.as_ref(), "cert");
        assert_eq!(kind.as_ref(), "Secret");
    }

    // Additional coverage tests for error branches, boundary cases, and
    // functions that currently lack coverage.

    #[test]
    fn parse_tls_mode_unknown_protocol_returns_none() {
        let obj = serde_json::Map::new();
        assert_eq!(parse_tls_mode(&obj, "TCP"), None);
        assert_eq!(parse_tls_mode(&obj, "UDP"), None);
    }

    #[test]
    fn parse_tls_mode_tls_explicit_modes() {
        let mut obj = serde_json::Map::new();
        obj.insert("tls".into(), serde_json::json!({"mode": "Terminate"}));
        assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Terminate));
        obj.insert("tls".into(), serde_json::json!({"mode": "Passthrough"}));
        assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Passthrough));
    }

    #[test]
    fn build_listener_model_skips_non_object_listener() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners:
                - http
                - name: real
                  protocol: HTTP
                  port: 80
        "#,
        )
        .unwrap();
        let listeners = build_listener_model(&gw);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].name.as_ref(), "real");
    }

    #[test]
    fn parse_allowed_routes_empty_kind_skipped() {
        let obj = serde_json::json!({
            "allowedRoutes": {
                "kinds": [
                    {"group": "gateway.networking.k8s.io", "kind": ""},
                    {"kind": "HTTPRoute"}
                ]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let allowed = parse_allowed_routes(&obj);
        assert_eq!(allowed.kinds.len(), 1);
        assert_eq!(allowed.kinds[0].kind.as_ref(), "HTTPRoute");
    }

    #[test]
    fn parse_allowed_routes_unknown_from_defaults_same() {
        let obj = serde_json::json!({
            "allowedRoutes": {
                "namespaces": {"from": "Unknown"}
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let allowed = parse_allowed_routes(&obj);
        assert_eq!(allowed.namespaces.from, NamespaceFrom::Same);
    }

    #[test]
    fn parse_frontend_validation_obj_missing_refs_returns_none() {
        assert!(parse_frontend_validation_obj(&serde_json::Map::new()).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_non_object_ref_returns_none() {
        let obj = serde_json::json!({"caCertificateRefs": ["not-object"]})
            .as_object()
            .unwrap()
            .clone();
        assert!(parse_frontend_validation_obj(&obj).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_empty_name_returns_none() {
        let obj = serde_json::json!({"caCertificateRefs": [{"kind": "ConfigMap", "name": ""}]})
            .as_object()
            .unwrap()
            .clone();
        assert!(parse_frontend_validation_obj(&obj).is_none());
    }

    #[test]
    fn parse_frontend_validation_obj_default_mode_false() {
        let obj = serde_json::json!({"caCertificateRefs": [{"kind": "ConfigMap", "name": "ca"}]})
            .as_object()
            .unwrap()
            .clone();
        let spec = parse_frontend_validation_obj(&obj).unwrap();
        assert!(!spec.allow_insecure_fallback);
    }

    #[test]
    fn listener_frontend_validation_port_mismatch_uses_default() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [
                    {
                        "port": 9999,
                        "tls": {
                            "validation": {
                                "caCertificateRefs": [{"kind": "ConfigMap", "name": "port-ca"}]
                            }
                        }
                    }
                ]
            }
        });
        let spec = listener_frontend_validation(Some(&tls), 443).unwrap();
        assert_eq!(spec.ca_certificate_refs[0].name.as_ref(), "default-ca");
    }

    #[test]
    fn listener_frontend_validation_per_port_missing_validation_returns_none() {
        let tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"kind": "ConfigMap", "name": "default-ca"}]
                    }
                },
                "perPort": [{"port": 8443, "tls": {}}]
            }
        });
        assert!(listener_frontend_validation(Some(&tls), 8443).is_none());
    }

    #[test]
    fn listener_frontend_validation_tls_not_object_returns_none() {
        assert!(
            listener_frontend_validation(Some(&serde_json::json!("not-object")), 443).is_none()
        );
        assert!(listener_frontend_validation(
            Some(&serde_json::json!({"frontend": "not-object"})),
            443
        )
        .is_none());
    }

    #[test]
    fn gateway_insecure_frontend_mode_ignores_non_object_listener() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - not-an-object
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        assert!(gateway_insecure_frontend_mode(&gw));
    }

    #[test]
    fn gateway_insecure_frontend_mode_ignores_non_tls() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
        "#,
        )
        .unwrap();
        assert!(!gateway_insecure_frontend_mode(&gw));
    }

    fn cross_ns_grant(to_ns: &str, to_kind: &str, to_name: Option<&str>) -> ReferenceGrantState {
        ReferenceGrantState {
            namespace: Arc::from(to_ns),
            name: Arc::from("grant"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from(""),
                kind: Arc::from(to_kind),
                namespace: None,
                name: to_name.map(Arc::from),
            }],
        }
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_non_configmap_kind() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "Secret", "name": "ca"}]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateKind"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_cross_namespace_without_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{
                            "group": "",
                            "kind": "ConfigMap",
                            "name": "ca",
                            "namespace": "other"
                        }]
                    }
                }
            }
        });
        let client = fake_kube_client(String::new());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("RefNotPermitted"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_accepts_cross_namespace_with_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{
                            "group": "",
                            "kind": "ConfigMap",
                            "name": "ca",
                            "namespace": "other"
                        }]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "other"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "ConfigMap", Some("ca"))]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_configmap_data() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_missing_ca_crt() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn validate_listener_frontend_validation_rejects_invalid_pem() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let gw_tls = serde_json::json!({
            "frontend": {
                "default": {
                    "validation": {
                        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "ca"}]
                    }
                }
            }
        });
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": "not a pem"}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        let grant_index = GrantIndex::new(vec![]);
        let err = validate_listener_frontend_validation(
            &client,
            "default",
            &listener,
            Some(&gw_tls),
            &grant_index,
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCACertificateRef"));
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_loads_valid_bundle() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = build_gateway_state(&gw);
        let cm = serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "ca", "namespace": "default"},
            "data": {"ca.crt": TEST_CERT_PEM}
        });
        let client = fake_kube_client(serde_json::to_string(&cm).unwrap());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listeners[0].programmed);
        let fv = state.listeners[0].frontend_validation.as_ref().unwrap();
        assert!(!fv.ca_bundle_pem.is_empty());
        assert!(fv.ca_bundle_pem.ends_with('\n'));
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_skips_http_listener() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
        "#,
        )
        .unwrap();
        let mut state = build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listeners[0].programmed);
        assert!(state.listeners[0].frontend_validation.is_none());
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_invalid_kind_unprogrammed() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: Secret
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_cross_namespace_unprogrammed() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
                        namespace: other
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[tokio::test]
    async fn load_gateway_frontend_validations_marks_non_object_listener_unprogrammed() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - not-an-object
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let mut state = build_gateway_state(&gw);
        let client = fake_kube_client(String::new());
        load_gateway_frontend_validations(
            &client,
            &[gw],
            std::slice::from_mut(&mut state),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.listeners[0].programmed);
    }

    #[test]
    fn listener_supported_kinds_returns_expected_kinds() {
        let empty = empty_features();
        assert_eq!(
            listener_supported_kinds("TCP", None, &empty)[0]["kind"],
            "TCPRoute"
        );
        assert_eq!(
            listener_supported_kinds("UDP", None, &empty)[0]["kind"],
            "UDPRoute"
        );
        assert_eq!(
            listener_supported_kinds("TLS", None, &empty)[0]["kind"],
            "TLSRoute"
        );
        let http = listener_supported_kinds("HTTP", None, &empty);
        assert!(http.iter().any(|k| k["kind"] == "HTTPRoute"));
        assert!(http.iter().any(|k| k["kind"] == "GRPCRoute"));
    }

    #[test]
    fn validate_listener_kinds_empty_array_defaults() {
        let obj = serde_json::json!({"protocol": "HTTP", "allowedRoutes": {"kinds": []}})
            .as_object()
            .unwrap()
            .clone();
        let (kinds, status, reason, _) = validate_listener_kinds(&obj);
        assert_eq!(kinds[0]["kind"], "HTTPRoute");
        assert_eq!(status, "True");
        assert_eq!(reason, "ResolvedRefs");
    }

    #[test]
    fn validate_listener_kinds_invalid_group() {
        let obj = serde_json::json!({
            "protocol": "HTTP",
            "allowedRoutes": {
                "kinds": [{"group": "example.com", "kind": "HTTPRoute"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let (kinds, status, reason, _) = validate_listener_kinds(&obj);
        assert!(kinds.is_empty());
        assert_eq!(status, "False");
        assert_eq!(reason, "InvalidRouteKinds");
    }

    #[test]
    fn validate_listener_kinds_tcp_valid() {
        let obj = serde_json::json!({
            "protocol": "TCP",
            "allowedRoutes": {"kinds": [{"kind": "TCPRoute"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let (kinds, status, _, _) = validate_listener_kinds(&obj);
        assert_eq!(kinds[0]["kind"], "TCPRoute");
        assert_eq!(status, "True");
    }

    #[tokio::test]
    async fn validate_listener_certificates_no_tls_returns_none() {
        let listener = serde_json::json!({"name": "http", "protocol": "HTTP", "port": 80})
            .as_object()
            .unwrap()
            .clone();
        let client = fake_kube_client(String::new());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_empty_certs_returns_none() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": []}
        })
        .as_object()
        .unwrap()
        .clone();
        let client = fake_kube_client(String::new());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_accepts_cross_namespace_with_grant() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {
                "certificateRefs": [{"kind": "Secret", "name": "cert", "namespace": "other"}]
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "other"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "Secret", Some("cert"))]);
        let err =
            validate_listener_certificates(&client, "default", "Gateway", &listener, &grant_index)
                .await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_listener_certificates_rejects_invalid_secret_data() {
        let listener = serde_json::json!({
            "name": "https",
            "protocol": "HTTPS",
            "port": 443,
            "tls": {"certificateRefs": [{"kind": "Secret", "name": "cert"}]}
        })
        .as_object()
        .unwrap()
        .clone();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": "bm90", "tls.key": "bm90"}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let err = validate_listener_certificates(
            &client,
            "default",
            "Gateway",
            &listener,
            &GrantIndex::new(vec![]),
        )
        .await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidCertificateRef"));
    }

    #[test]
    fn gateway_backend_client_cert_ref_rejects_non_secret() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: ConfigMap
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        assert!(gateway_backend_client_cert_ref(&gw).is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_rejects_empty_name() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: ""
              listeners: []
        "#,
        )
        .unwrap();
        assert!(gateway_backend_client_cert_ref(&gw).is_none());
    }

    #[test]
    fn gateway_backend_client_cert_ref_uses_default_namespace() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let (ns, name, kind) = gateway_backend_client_cert_ref(&gw).unwrap();
        assert_eq!(ns.as_ref(), "default");
        assert_eq!(name.as_ref(), "cert");
        assert_eq!(kind.as_ref(), "Secret");
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_tls_returns_none() {
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
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_backend_returns_none() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls: {}
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_no_cert_ref_returns_none() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend: {}
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_empty_name() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: ""
              listeners: []
        "#,
        )
        .unwrap();
        let client = fake_kube_client(String::new());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_accepts_cross_namespace_with_grant() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
                    namespace: other
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "other"},
            "data": {"tls.crt": CERT_B64, "tls.key": KEY_B64}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let grant_index = GrantIndex::new(vec![cross_ns_grant("other", "Secret", Some("cert"))]);
        let err = validate_gateway_backend_tls(&client, &gw, &grant_index).await;
        assert!(err.is_none());
    }

    #[tokio::test]
    async fn validate_gateway_backend_tls_rejects_invalid_secret_data() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              tls:
                backend:
                  clientCertificateRef:
                    kind: Secret
                    name: cert
              listeners: []
        "#,
        )
        .unwrap();
        let secret = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "cert", "namespace": "default"},
            "data": {"tls.crt": "bm90", "tls.key": "bm90"}
        });
        let client = fake_kube_client(serde_json::to_string(&secret).unwrap());
        let err = validate_gateway_backend_tls(&client, &gw, &GrantIndex::new(vec![])).await;
        assert_eq!(err.map(|e| e.reason), Some("InvalidClientCertificateRef"));
    }

    #[test]
    fn parse_gateway_addresses_filters_and_defaults() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              addresses:
                - type: IPAddress
                  value: 10.0.0.1
                - not-an-object
                - value: 10.0.0.2
              listeners: []
        "#,
        )
        .unwrap();
        let addrs = parse_gateway_addresses(&gw);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].type_, "IPAddress");
        assert_eq!(addrs[0].value.as_deref(), Some("10.0.0.1"));
        assert_eq!(addrs[1].type_, "IPAddress");
        assert_eq!(addrs[1].value.as_deref(), Some("10.0.0.2"));
    }

    #[test]
    fn parse_gateway_addresses_missing_returns_empty() {
        let gw = sample_gw("test-gc");
        assert!(parse_gateway_addresses(&gw).is_empty());
    }

    #[test]
    fn compute_gateway_conditions_resolved_refs_false_on_backend_tls_error() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let err = CertValidation {
            reason: "InvalidClientCertificateRef",
            message: "bad",
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, Some(err), false, 1);
        let resolved = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::ResolvedRefs)
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::False);
        assert_eq!(resolved.reason, "InvalidClientCertificateRef");
    }

    #[test]
    fn mixed_tls_conflict_names_detects_and_ignores() {
        let listeners = vec![
            serde_json::json!({"name": "a", "protocol": "TLS", "port": 8443, "tls": {"mode": "Terminate"}}),
            serde_json::json!({"name": "b", "protocol": "TLS", "port": 8443, "tls": {"mode": "Passthrough"}}),
            serde_json::json!({"name": "c", "protocol": "TLS", "port": 8443, "tls": {"mode": "Terminate"}}),
            serde_json::json!({"name": "http", "protocol": "HTTP", "port": 80}),
        ];
        let conflicts = mixed_tls_conflict_names(&listeners);
        assert!(conflicts.contains("a"));
        assert!(conflicts.contains("b"));
        assert!(conflicts.contains("c"));
        assert!(!conflicts.contains("http"));
    }

    #[test]
    fn build_listener_status_skips_non_object_listener() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              listeners:
                - not-an-object
        "#,
        )
        .unwrap();
        let statuses = build_listener_status(&gw, None, 1, &[], &[], &empty_features());
        assert!(statuses.is_empty());
    }

    #[test]
    fn build_listener_status_clears_supported_kinds_on_unsupported_tls() {
        let gw = tls_gateway_yaml("Terminate", None);
        let statuses = build_listener_status(&gw, None, 1, &[], &[0], &empty_features());
        assert_eq!(
            accepted_reason(&statuses, "tls-a"),
            Some("UnsupportedValue".to_string())
        );
        assert!(statuses[0]["supportedKinds"].as_array().unwrap().is_empty());
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

    #[tokio::test]
    async fn count_attached_routes_filters_and_counts_all_kinds() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: test-gc
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
                  hostname: example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: https
                  protocol: HTTPS
                  port: 443
                  hostname: secure.example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: tcp
                  protocol: TCP
                  port: 8080
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: tls
                  protocol: TLS
                  port: 8443
                  hostname: tls.example.com
                  allowedRoutes:
                    namespaces:
                      from: All
                - name: http-same
                  protocol: HTTP
                  port: 8081
                  hostname: same.example.com
                - name: http-kinds
                  protocol: HTTP
                  port: 8082
                  hostname: kinds.example.com
                  allowedRoutes:
                    kinds:
                      - kind: TCPRoute
                - name: udp
                  protocol: UDP
                  port: 9090
                  allowedRoutes:
                    namespaces:
                      from: All
        "#,
        )
        .unwrap();

        let http_route_ok: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-ok
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: http
                  port: 80
              hostnames:
                - example.com
        "#,
        )
        .unwrap();
        let http_route_port_mismatch: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-port
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 9999
        "#,
        )
        .unwrap();
        let http_route_section_mismatch: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-section
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  sectionName: other
        "#,
        )
        .unwrap();
        let http_route_wrong_name: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-wrong-name
              namespace: default
            spec:
              parentRefs:
                - name: other-gw
        "#,
        )
        .unwrap();
        let http_route_not_gateway: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-not-gw
              namespace: default
            spec:
              parentRefs:
                - group: example.com
                  kind: Gateway
                  name: gw-1
        "#,
        )
        .unwrap();
        let http_route_other_ns: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-other-ns
              namespace: other
            spec:
              parentRefs:
                - name: gw-1
                  port: 8081
        "#,
        )
        .unwrap();
        let http_route_kind_not_allowed: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-kind
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8082
              hostnames:
                - kinds.example.com
        "#,
        )
        .unwrap();
        let http_route_no_hostname: HTTPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: route-no-hostname
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 80
              hostnames:
                - other.com
        "#,
        )
        .unwrap();
        let http_routes = vec![
            http_route_ok,
            http_route_port_mismatch,
            http_route_section_mismatch,
            http_route_wrong_name,
            http_route_not_gateway,
            http_route_other_ns,
            http_route_kind_not_allowed,
            http_route_no_hostname,
        ];

        let tcp_route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8080
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
        )
        .unwrap();
        let udp_route: UDPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 9090
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
        )
        .unwrap();
        let tls_route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
                  port: 8443
              hostnames:
                - tls.example.com
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();

        let http_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRouteList",
            "metadata": {},
            "items": serde_json::to_value(&http_routes).unwrap()
        })
        .to_string();
        let tcp_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TCPRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&tcp_route).unwrap()]
        })
        .to_string();
        let udp_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "UDPRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&udp_route).unwrap()]
        })
        .to_string();
        let tls_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1alpha2",
            "kind": "TLSRouteList",
            "metadata": {},
            "items": [serde_json::to_value(&tls_route).unwrap()]
        })
        .to_string();
        let empty_body =
            serde_json::json!({"apiVersion": "v1", "kind": "List", "metadata": {}, "items": []})
                .to_string();

        let client = Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let http_body = http_body.clone();
                let tcp_body = tcp_body.clone();
                let udp_body = udp_body.clone();
                let tls_body = tls_body.clone();
                let empty_body = empty_body.clone();
                async move {
                    let body = if path.contains("/httproutes") {
                        http_body
                    } else if path.contains("/tcproutes") {
                        tcp_body
                    } else if path.contains("/udproutes") {
                        udp_body
                    } else if path.contains("/tlsroutes") {
                        tls_body
                    } else {
                        empty_body
                    };
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(bytes::Bytes::from(body)))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let listeners = listener_matches(&gw);
        let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
        let counts =
            count_attached_routes(&client, "default", "gw-1", &listeners, &namespace_labels).await;
        assert_eq!(counts, vec![1, 0, 1, 1, 0, 0, 1]);
    }

    #[test]
    fn gateway_l4_ready_true_when_validation_matches() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: Some(CompiledFrontendValidation {
                    ca_bundle_pem: TEST_CERT_PEM.into(),
                    allow_insecure_fallback: false,
                }),
            }],
            ..Default::default()
        };
        assert!(gateway_l4_ready(&gw, &l4, &[None]));
    }

    #[test]
    fn gateway_l4_ready_false_when_validation_mode_mismatches() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      mode: AllowInsecureFallback
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: ca
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: Some(CompiledFrontendValidation {
                    ca_bundle_pem: TEST_CERT_PEM.into(),
                    allow_insecure_fallback: false,
                }),
            }],
            ..Default::default()
        };
        assert!(!gateway_l4_ready(&gw, &l4, &[None]));
    }

    #[test]
    fn gateway_l4_ready_skips_listener_with_cert_error() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
              generation: 1
            spec:
              gatewayClassName: test-gc
              tls:
                frontend:
                  default:
                    validation:
                      caCertificateRefs:
                      - kind: ConfigMap
                        group: ""
                        name: does-not-exist
              listeners:
                - name: https
                  protocol: HTTPS
                  port: 443
        "#,
        )
        .unwrap();
        let l4 = CompiledL4Config {
            listeners: vec![CompiledListener {
                id: "0.0.0.0:443#Https".into(),
                bind_addr: "0.0.0.0:443".into(),
                protocol: crate::ir::Protocol::Https,
                tls: None,
                redirect_http_to_https: false,
                frontend_validation: None,
            }],
            ..Default::default()
        };
        let err = Some(CertValidation {
            reason: "InvalidCACertificateRef",
            message: "missing",
        });
        assert!(gateway_l4_ready(&gw, &l4, &[err]));
    }
}
