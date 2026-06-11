// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// GatewayClass describes a class of Gateways available to the user
/// for creating Gateway resources.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "GatewayClass",
    plural = "gatewayclasses",
    namespaced = false,
    status = "GatewayClassStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// ControllerName is the name of the controller that manages
    /// Gateways of this class.
    pub controller_name: String,
    /// Description helps users understand the intended use of this
    /// GatewayClass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayClassStatus {
    /// Conditions is the current status from the controller for this
    /// GatewayClass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
    /// SupportedFeatures lists the features the GatewayClass supports.
    /// Required by Gateway API v1.5.1 conformance tests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_features: Vec<SupportedFeature>,
}

/// A feature supported by this GatewayClass, as reported in status.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SupportedFeature {
    /// Name of the supported feature.
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_gatewayclass() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: GatewayClass
            metadata:
              name: example-class
            spec:
              controllerName: example.com/gateway-controller
        "#;
        let gc: GatewayClass = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(gc.spec.controller_name, "example.com/gateway-controller");
    }
}
