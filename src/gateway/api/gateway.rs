// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Gateway describes how traffic can be translated to Services inside
/// the cluster.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "Gateway",
    plural = "gateways",
    namespaced,
    status = "GatewayStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// GatewayClassName used for this Gateway.
    pub gateway_class_name: String,
    /// Listeners associated with this Gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<serde_json::Value>,
    /// Addresses requested for this Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<serde_json::Value>>,
    /// ListenerSets that may attach listeners to this Gateway.
    #[serde(
        default,
        rename = "allowedListeners",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_listeners: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// Addresses assigned to this Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<serde_json::Value>>,
    /// Conditions describe the current conditions of the Gateway.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// Listeners provide status for each unique listener port
    /// defined in the Spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listeners: Option<Vec<serde_json::Value>>,
    /// Number of ListenerSets successfully attached to this Gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_listener_sets: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_gateway() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: example-gateway
              namespace: default
            spec:
              gatewayClassName: example-class
              listeners:
                - name: http
                  protocol: HTTP
                  port: 80
        "#;
        let gw: Gateway = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(gw.spec.gateway_class_name, "example-class");
        assert_eq!(gw.spec.listeners.len(), 1);
    }
}
