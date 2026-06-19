// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared listener parsing and status-building helpers used by the Gateway
//! and ListenerSet reconcilers.

use crate::gateway::model::{
    AllowedRoutes, ListenerState, NamespaceFrom, RouteGroupKind, RouteNamespaces, TlsMode,
};
use crate::gateway::status::builder::condition_json;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

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

/// Build a [`ListenerState`] from raw listener fields and an optional raw JSON object.
pub fn build_listener_state_from_obj(
    name: Arc<str>,
    protocol: Arc<str>,
    port: u16,
    hostname: Option<Arc<str>>,
    obj: Option<&serde_json::Map<String, serde_json::Value>>,
) -> ListenerState {
    let empty = serde_json::Map::new();
    let obj = obj.unwrap_or(&empty);
    let tls_mode = parse_tls_mode(obj, protocol.as_ref());
    ListenerState {
        name,
        protocol,
        port,
        hostname,
        tls_mode,
        frontend_validation: None,
        programmed: true,
    }
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
                    if map.is_empty() { None } else { Some(map) }
                });

            RouteNamespaces { from, selector }
        })
        .unwrap_or_default();

    AllowedRoutes { kinds, namespaces }
}

/// Build the key used for the listener allowed-routes map.
pub fn build_listener_allowed_map_key(
    ns: &str,
    name: &str,
    listener_name: &str,
) -> (String, String, String) {
    (ns.to_string(), name.to_string(), listener_name.to_string())
}

/// Return the default supported route kinds for a listener protocol.
pub fn listener_supported_kinds(
    protocol: &str,
    _tls_mode: Option<TlsMode>,
    _supported_features: &HashSet<String>,
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

/// Compute the `Accepted` condition for a listener.
pub fn listener_accepted(
    name: &str,
    protocol: &str,
    tls_mode: Option<TlsMode>,
    mixed_conflict_names: &HashSet<String>,
    supports_tls_terminate: bool,
    supports_tls_mixed: bool,
) -> (&'static str, &'static str, &'static str) {
    if protocol == "TLS" {
        if mixed_conflict_names.contains(name) {
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

/// Validate the route kinds declared in a listener's `allowedRoutes`.
pub fn validate_listener_kinds(
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
            );
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

/// Build a single listener status JSON entry.
pub fn listener_status_json(
    name: &str,
    supported_kinds: &[serde_json::Value],
    attached_routes: i64,
    conditions: &[serde_json::Value],
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "supportedKinds": supported_kinds,
        "attachedRoutes": attached_routes,
        "conditions": conditions,
    })
}

/// Build the standard `Accepted` / `Programmed` / `ResolvedRefs` condition array.
pub fn standard_listener_conditions(
    accepted: (&str, &str, &str),
    programmed: (&str, &str, &str),
    resolved_refs: (&str, &str, &str),
    observed_generation: i64,
    now: &str,
) -> Vec<serde_json::Value> {
    vec![
        condition_json(
            "Accepted",
            accepted.0,
            accepted.1,
            accepted.2,
            observed_generation,
            now,
        ),
        condition_json(
            "Programmed",
            programmed.0,
            programmed.1,
            programmed.2,
            observed_generation,
            now,
        ),
        condition_json(
            "ResolvedRefs",
            resolved_refs.0,
            resolved_refs.1,
            resolved_refs.2,
            observed_generation,
            now,
        ),
    ]
}
