// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared test helpers for the HTTPRoute reconciler.

use std::sync::Arc;
use sunbeam_proxy::gateway::api::HTTPRoute;
use sunbeam_proxy::gateway::model::{
    GatewayState, GrantSubject, ListenerSetState, ListenerState, ParentRef, ReferenceGrantState,
};

pub fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
    GatewayState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    }
}

pub fn grant_allowing_http_route(
    from_ns: &str,
    gateway_ns: &str,
    gateway_name: &str,
) -> ReferenceGrantState {
    ReferenceGrantState {
        namespace: Arc::from(gateway_ns),
        name: Arc::from("allow"),
        generation: 1,
        from: vec![GrantSubject {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("HTTPRoute"),
            namespace: Some(Arc::from(from_ns)),
            name: None,
        }],
        to: vec![GrantSubject {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: None,
            name: Some(Arc::from(gateway_name)),
        }],
    }
}

pub fn sample_route(parent_refs: Vec<serde_json::Value>) -> HTTPRoute {
    let json = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": "route-1",
            "namespace": "default",
            "generation": 1
        },
        "spec": {
            "parentRefs": parent_refs
        }
    });
    serde_json::from_value(json).expect("valid HTTPRoute")
}

pub fn route_with_backends(
    parent_refs: Vec<serde_json::Value>,
    backends: Vec<serde_json::Value>,
) -> HTTPRoute {
    let json = serde_json::json!({
        "apiVersion": "gateway.networking.k8s.io/v1",
        "kind": "HTTPRoute",
        "metadata": {
            "name": "route-1",
            "namespace": "default",
            "generation": 1
        },
        "spec": {
            "parentRefs": parent_refs,
            "rules": [{ "backendRefs": backends }]
        }
    });
    serde_json::from_value(json).expect("valid HTTPRoute")
}

pub fn route_from_json(json: serde_json::Value) -> HTTPRoute {
    serde_json::from_value(json).expect("valid HTTPRoute")
}

pub fn gw_with_hostname(ns: &str, name: &str, listener: &str, hostname: &str) -> GatewayState {
    GatewayState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: Some(Arc::from(hostname)),
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    }
}

pub fn ls_with_listener(ns: &str, name: &str, listener: &str) -> ListenerSetState {
    ListenerSetState {
        namespace: Arc::from(ns),
        name: Arc::from(name),
        generation: 1,
        created_at: 0,
        parent_ref: ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: Some(Arc::from(ns)),
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        },
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from(listener),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        conflicts: std::collections::BTreeMap::new(),
        accepted: true,
        programmed: true,
        reason: Arc::from(""),
        listener_cert_errors: vec![None],
        listener_kind_errors: vec![None],
    }
}
