// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// HTTPRoute provides a way to route HTTP requests.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "HTTPRoute",
    plural = "httproutes",
    namespaced,
    status = "HTTPRouteStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteSpec {
    /// ParentRefs references the resources to which this route wants
    /// to attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<Vec<serde_json::Value>>,
    /// Hostnames defines a set of hostname values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostnames: Option<Vec<String>>,
    /// Rules are a list of HTTP matchers, filters and actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HTTPRouteStatus {
    /// Parents is a list of parent resources that are associated with
    /// the route.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parents: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_httproute() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: HTTPRoute
            metadata:
              name: example-route
              namespace: default
            spec:
              parentRefs:
                - name: example-gateway
              hostnames:
                - example.com
        "#;
        let route: HTTPRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(
            route.spec.hostnames,
            Some(vec!["example.com".to_string()])
        );
    }
}
