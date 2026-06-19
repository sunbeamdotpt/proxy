// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Listener model, parsing, allowed-routes, status, and conflict detection.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::model::{AllowedRoutes, ListenerState, TlsMode};
use crate::gateway::reconcile::gateway::certificates::{CertValidation, is_frontend_ca_error};
use crate::gateway::reconcile::gateway::frontend_validation::{
    FrontendValidationSpec, parse_frontend_validation_obj,
};
use crate::gateway::reconcile::listener_common::{
    build_listener_allowed_map_key, build_listener_state_from_obj, listener_status_json,
    standard_listener_conditions,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub use crate::gateway::reconcile::listener_common::parse_tls_mode;

/// Build [`ListenerState`] entries from a Gateway's raw `listeners` spec.
pub fn build_listener_model(gw: &Gateway) -> Vec<ListenerState> {
    let mut listeners = Vec::new();
    for listener in &gw.spec.listeners {
        if let Some(obj) = listener.as_object() {
            let name: Arc<str> = obj
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
            listeners.push(build_listener_state_from_obj(
                name,
                protocol,
                port,
                hostname,
                Some(obj),
            ));
        }
    }
    listeners
}

pub use crate::gateway::reconcile::listener_common::parse_allowed_routes;

/// Return the frontend validation configuration that applies to a listener,
/// resolving per-port overrides against the Gateway default.
pub(crate) fn listener_frontend_validation(
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
                    build_listener_allowed_map_key(gw_ns, gw_name, name),
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
    supported_features: &HashSet<String>,
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
        if accepted_status == "True"
            && let Some(err) = cert_errors.get(idx).copied().flatten()
        {
            accepted_status = "False";
            accepted_reason = if is_frontend_ca_error(err.reason) {
                "NoValidCACertificate"
            } else {
                err.reason
            };
            accepted_message = err.message;
        }

        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let conditions = standard_listener_conditions(
            (accepted_status, accepted_reason, accepted_message),
            (programmed_status, programmed_reason, programmed_message),
            (
                resolved_refs_status,
                resolved_refs_reason,
                resolved_refs_message,
            ),
            observed_generation,
            &now,
        );
        statuses.push(listener_status_json(
            name,
            &supported_kinds,
            attached_routes.get(idx).copied().unwrap_or(0),
            &conditions,
        ));
    }
    statuses
}

/// Return the set of TLS listener names that participate in an unsupported
/// mixed Terminate/Passthrough configuration on the same port.
fn mixed_tls_conflict_names(listeners: &[serde_json::Value]) -> HashSet<String> {
    let mut conflicts = HashSet::new();
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

pub(crate) use crate::gateway::reconcile::listener_common::listener_accepted;

pub use crate::gateway::reconcile::listener_common::listener_supported_kinds;
pub(crate) use crate::gateway::reconcile::listener_common::validate_listener_kinds;

/// Listener identifiers and permissions extracted from raw Gateway spec.
pub(crate) struct ListenerMatch {
    pub(crate) name: String,
    pub(crate) port: u16,
    pub(crate) hostname: Option<String>,
    pub(crate) protocol: String,
    pub(crate) allowed: AllowedRoutes,
}

pub(crate) fn listener_matches(gw: &Gateway) -> Vec<ListenerMatch> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::NamespaceFrom;
    use crate::gateway::reconcile::gateway::test_helpers::{
        accepted_reason, empty_features, sample_gw, tls_gateway_yaml,
    };

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
}
