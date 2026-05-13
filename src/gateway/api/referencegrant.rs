// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ReferenceGrant identifies kinds of resources in other namespaces
/// that are trusted to reference the specified kinds of resources in
/// the same namespace as the ReferenceGrant.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.networking.k8s.io",
    version = "v1",
    kind = "ReferenceGrant",
    plural = "referencegrants"
)]
#[serde(rename_all = "camelCase")]
pub struct ReferenceGrantSpec {
    /// From describes the trusted sources of references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<serde_json::Value>,
    /// To describes the resources that references are allowed to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_referencegrant() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: ReferenceGrant
            metadata:
              name: example-grant
              namespace: default
            spec:
              from:
                - group: gateway.networking.k8s.io
                  kind: HTTPRoute
                  namespace: external
              to:
                - group: ""
                  kind: Service
        "#;
        let rg: ReferenceGrant = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(rg.spec.from.len(), 1);
        assert_eq!(rg.spec.to.len(), 1);
    }
}
