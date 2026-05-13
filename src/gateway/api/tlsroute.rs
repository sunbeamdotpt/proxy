// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// TLSRoute provides a way to route TLS requests based on SNI.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "TLSRoute",
    plural = "tlsroutes",
    status = "TLSRouteStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteSpec {
    /// ParentRefs references the resources to which this route wants
    /// to attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<Vec<serde_json::Value>>,
    /// Hostnames defines a set of SNI hostname values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
    /// Rules are a list of TLS matchers and actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TLSRouteStatus {
    /// Parents is a list of parent resources that are associated with
    /// the route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_tlsroute() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: example-tls-route
              namespace: default
            spec:
              parentRefs:
                - name: example-gateway
              hostnames:
                - tls.example.com
        "#;
        let route: TLSRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(
            route.spec.hostnames,
            Some(vec!["tls.example.com".to_string()])
        );
    }
}
