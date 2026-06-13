// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! ReferenceGrant reconciler.
//!
//! Parses ReferenceGrant CRDs into the model layer and builds an index
//! for fast cross-namespace permission checks.

use crate::gateway::api::ReferenceGrant;
use crate::gateway::model::{GrantSubject, ReferenceGrantState};
use serde_json::Value;
use std::sync::Arc;

/// Reconcile a slice of ReferenceGrant CRDs into model states.
pub fn reconcile_reference_grants(grants: &[ReferenceGrant]) -> Vec<ReferenceGrantState> {
    grants.iter().map(parse_reference_grant).collect()
}

fn parse_reference_grant(grant: &ReferenceGrant) -> ReferenceGrantState {
    let namespace = Arc::from(grant.metadata.namespace.as_deref().unwrap_or("default"));
    let name = Arc::from(grant.metadata.name.as_deref().unwrap_or(""));
    let generation = grant.metadata.generation.unwrap_or(0);

    let from = grant
        .spec
        .from
        .iter()
        .filter_map(parse_grant_subject)
        .collect();
    let to = grant
        .spec
        .to
        .iter()
        .filter_map(parse_grant_subject)
        .collect();

    ReferenceGrantState {
        namespace,
        name,
        generation,
        from,
        to,
    }
}

fn parse_grant_subject(value: &Value) -> Option<GrantSubject> {
    let obj = value.as_object()?;
    Some(GrantSubject {
        group: Arc::from(obj.get("group").and_then(|v| v.as_str()).unwrap_or("")),
        kind: Arc::from(obj.get("kind").and_then(|v| v.as_str()).unwrap_or("")),
        namespace: obj.get("namespace").and_then(|v| v.as_str()).map(Arc::from),
        name: obj.get("name").and_then(|v| v.as_str()).map(Arc::from),
    })
}

/// Fast lookup index for ReferenceGrant permissions.
#[derive(Clone, Debug, Default)]
pub struct GrantIndex {
    grants: Vec<ReferenceGrantState>,
}

impl GrantIndex {
    /// Build an index from reconciled grant states.
    pub fn new(grants: Vec<ReferenceGrantState>) -> Self {
        Self { grants }
    }

    /// Check whether a reference from `(from_ns, from_group, from_kind)` to a
    /// resource `(to_ns, to_group, to_kind, to_name)` is permitted.
    ///
    /// Same-namespace references are always allowed.
    #[allow(clippy::too_many_arguments)]
    pub fn is_permitted(
        &self,
        from_ns: &str,
        from_group: &str,
        from_kind: &str,
        to_ns: &str,
        to_group: &str,
        to_kind: &str,
        to_name: &str,
    ) -> bool {
        if from_ns == to_ns {
            return true;
        }

        self.grants.iter().any(|grant| {
            // The grant must live in the namespace of the referenced resource.
            grant.namespace.as_ref() == to_ns
                // At least one 'from' subject must match the referrer.
                && grant.from.iter().any(|f| {
                    f.group.as_ref() == from_group
                        && f.kind.as_ref() == from_kind
                        && f.namespace.as_deref() == Some(from_ns)
                })
                // At least one 'to' subject must match the referenced resource.
                && grant.to.iter().any(|t| {
                    t.group.as_ref() == to_group
                        && t.kind.as_ref() == to_kind
                        && (t.name.is_none() || t.name.as_deref() == Some(to_name))
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::referencegrant::ReferenceGrantSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn sample_grant() -> ReferenceGrantState {
        ReferenceGrantState {
            namespace: Arc::from("prod"),
            name: Arc::from("allow-default"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: None,
            }],
        }
    }

    #[test]
    fn same_namespace_always_permitted() {
        let index = GrantIndex::new(vec![sample_grant()]);
        assert!(index.is_permitted(
            "default",
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "default",
            "gateway.networking.k8s.io",
            "Gateway",
            "gw-1"
        ));
    }

    #[test]
    fn cross_namespace_permitted_when_grant_exists() {
        let index = GrantIndex::new(vec![sample_grant()]);
        assert!(index.is_permitted(
            "default",
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "prod",
            "gateway.networking.k8s.io",
            "Gateway",
            "gw-1"
        ));
    }

    #[test]
    fn cross_namespace_denied_when_no_grant() {
        let index = GrantIndex::new(vec![sample_grant()]);
        assert!(!index.is_permitted(
            "external",
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "prod",
            "gateway.networking.k8s.io",
            "Gateway",
            "gw-1"
        ));
    }

    #[test]
    fn cross_namespace_denied_when_grant_kind_mismatches() {
        let index = GrantIndex::new(vec![sample_grant()]);
        assert!(!index.is_permitted(
            "default",
            "gateway.networking.k8s.io",
            "TCPRoute",
            "prod",
            "gateway.networking.k8s.io",
            "Gateway",
            "gw-1"
        ));
    }

    #[test]
    fn grant_with_specific_name() {
        let grant = ReferenceGrantState {
            namespace: Arc::from("prod"),
            name: Arc::from("specific"),
            generation: 1,
            from: vec![GrantSubject {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("HTTPRoute"),
                namespace: Some(Arc::from("default")),
                name: None,
            }],
            to: vec![GrantSubject {
                group: Arc::from(""),
                kind: Arc::from("Service"),
                namespace: None,
                name: Some(Arc::from("svc-1")),
            }],
        };
        let index = GrantIndex::new(vec![grant]);
        assert!(index.is_permitted(
            "default",
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "prod",
            "",
            "Service",
            "svc-1"
        ));
        assert!(!index.is_permitted(
            "default",
            "gateway.networking.k8s.io",
            "HTTPRoute",
            "prod",
            "",
            "Service",
            "svc-2"
        ));
    }

    #[test]
    fn reconcile_empty_grants() {
        let result = reconcile_reference_grants(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn reconcile_reference_grant_parses_fields() {
        let grant = ReferenceGrant {
            metadata: ObjectMeta {
                namespace: Some("ns1".into()),
                name: Some("grant1".into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: ReferenceGrantSpec {
                from: vec![
                    serde_json::json!({"group": "g1", "kind": "K1", "namespace": "ns-from"}),
                    serde_json::json!({"group": "g2", "kind": "K2"}),
                    serde_json::json!("not-an-object"),
                ],
                to: vec![serde_json::json!({"group": "g3", "kind": "K3", "name": "target"})],
            },
        };
        let result = reconcile_reference_grants(&[grant]);
        assert_eq!(result.len(), 1);
        let state = &result[0];
        assert_eq!(state.namespace.as_ref(), "ns1");
        assert_eq!(state.name.as_ref(), "grant1");
        assert_eq!(state.generation, 2);
        assert_eq!(state.from.len(), 2);
        assert_eq!(state.from[0].group.as_ref(), "g1");
        assert_eq!(state.from[0].kind.as_ref(), "K1");
        assert_eq!(state.from[0].namespace.as_deref(), Some("ns-from"));
        assert_eq!(state.from[0].name, None);
        assert_eq!(state.from[1].group.as_ref(), "g2");
        assert_eq!(state.from[1].namespace, None);
        assert_eq!(state.to.len(), 1);
        assert_eq!(state.to[0].name.as_deref(), Some("target"));
    }

    #[test]
    fn parse_grant_subject_skips_non_object() {
        assert_eq!(parse_grant_subject(&serde_json::json!("string")), None);
        assert_eq!(parse_grant_subject(&serde_json::json!(42)), None);
        assert_eq!(parse_grant_subject(&serde_json::json!(null)), None);
    }

    #[test]
    fn parse_grant_subject_defaults_missing_fields() {
        let obj = serde_json::json!({});
        let subject = parse_grant_subject(&obj).unwrap();
        assert_eq!(subject.group.as_ref(), "");
        assert_eq!(subject.kind.as_ref(), "");
        assert_eq!(subject.namespace, None);
        assert_eq!(subject.name, None);
    }

    #[test]
    fn parse_reference_grant_defaults_missing_metadata() {
        let grant = ReferenceGrant {
            metadata: Default::default(),
            spec: ReferenceGrantSpec {
                from: vec![],
                to: vec![],
            },
        };
        let state = parse_reference_grant(&grant);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "");
        assert_eq!(state.generation, 0);
    }
}
