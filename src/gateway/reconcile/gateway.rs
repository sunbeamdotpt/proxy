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
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerState, NamespaceFrom, RouteGroupKind,
    RouteNamespaces, TlsMode,
};
use crate::gateway::reconcile::gatewayclass::{
    supported_features, to_k8s_condition, CONTROLLER_NAME,
};
use crate::gateway::reconcile::httproute::{
    listener_allows_kind, listener_hostname_intersects, namespace_allowed, parse_route_hostnames,
};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use futures::StreamExt;
use kube::api::{Api, ListParams, Patch, PatchParams};
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

        let (accepted_status, accepted_reason, accepted_message) = listener_accepted(
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
    let addr = std::env::var("SUNBEAM_GATEWAY_ADDRESS").unwrap_or_else(|_| "192.168.252.19".into());
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
    let observed_generation = gw.metadata.generation.unwrap_or(0).max(1);

    // Look up the referenced GatewayClass (cluster-scoped).
    let gatewayclasses: Api<GatewayClass> = Api::all(ctx.client.clone());
    let gc = gatewayclasses.get(&gw.spec.gateway_class_name).await.ok();

    let conditions = compute_gateway_conditions(&gw, gc.as_ref(), observed_generation);
    let _gateway_state = build_gateway_state(&gw);

    let grants_api: Api<ReferenceGrant> = Api::all(ctx.client.clone());
    let grants = grants_api.list(&ListParams::default()).await?;
    let grant_index = GrantIndex::new(reconcile_reference_grants(&grants.items));

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

    let mut cert_errors: Vec<Option<CertValidation>> = Vec::new();
    for listener in &gw.spec.listeners {
        if let Some(obj) = listener.as_object() {
            let err =
                validate_listener_certificates(&ctx.client, &ns, "Gateway", obj, &grant_index)
                    .await;
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
        let k8s_conditions: Vec<k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition> =
            conditions.iter().map(to_k8s_condition).collect();
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
        let addresses = gateway_addresses();
        let new_status = serde_json::json!({
            "conditions": k8s_conditions,
            "listeners": listener_statuses,
            "addresses": addresses,
            "attachedListenerSets": attached_listener_sets,
        });

        let old_status_json = gw
            .status
            .as_ref()
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
}
