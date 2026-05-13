// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// TCPRoute provides a way to route TCP requests.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1alpha2",
    kind = "TCPRoute",
    plural = "tcproutes",
    status = "TCPRouteStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteSpec {
    /// ParentRefs references the resources to which this route wants
    /// to attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<Vec<serde_json::Value>>,
    /// Rules are a list of TCP matchers and actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TCPRouteStatus {
    /// Parents is a list of parent resources that are associated with
    /// the route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_tcproute() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: example-tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: example-gateway
        "#;
        let route: TCPRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert!(route.spec.parent_refs.is_some());
    }
}
