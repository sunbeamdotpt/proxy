// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! HTTPRoute reconciler.
//!
//! Watches HTTPRoute resources, resolves parentRefs against Gateway
//! listeners, computes `Accepted` / `ResolvedRefs` conditions on
//! `.status.parents[]`, and emits `RouteState` for the reconciled view.

use crate::gateway::api::HTTPRoute;
use crate::gateway::model::{GatewayState, ParentRef, RouteState};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use serde_json::Value;
use std::sync::Arc;

/// Result of reconciling a single HTTPRoute.
#[derive(Clone, Debug)]
pub struct ReconciledHTTPRoute {
    pub route_state: RouteState,
    pub parent_statuses: Vec<HTTPRouteParentStatus>,
}

/// Status conditions for a single parentRef entry.
#[derive(Clone, Debug)]
pub struct HTTPRouteParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

/// Reconcile a slice of HTTPRoute CRDs against the current Gateway set.
pub fn reconcile_httproutes(
    routes: &[HTTPRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledHTTPRoute> {
    routes
        .iter()
        .map(|route| reconcile_single(route, gateways, grant_index))
        .collect()
}

fn reconcile_single(
    route: &HTTPRoute,
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> ReconciledHTTPRoute {
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = route.metadata.name.as_deref().unwrap_or("");
    let generation = route.metadata.generation.unwrap_or(0);

    let parsed_refs = parse_parent_refs(route);
    let mut parent_refs = Vec::with_capacity(parsed_refs.len());
    let mut parent_statuses = Vec::with_capacity(parsed_refs.len());

    for parsed in &parsed_refs {
        let (resolved, conditions) =
            resolve_parent_ref(parsed, route_ns, generation, gateways, grant_index);
        let status_parent_ref = resolved.clone().unwrap_or_else(|| ParentRef {
            namespace: parsed.namespace.clone().map(Arc::from),
            name: Arc::from(parsed.name.clone()),
            section_name: parsed.section_name.clone().map(Arc::from),
        });
        if let Some(pr) = resolved {
            parent_refs.push(pr);
        }
        parent_statuses.push(HTTPRouteParentStatus {
            parent_ref: status_parent_ref,
            conditions,
        });
    }

    let route_state = RouteState {
        namespace: Arc::from(route_ns),
        name: Arc::from(route_name),
        kind: Arc::from("HTTPRoute"),
        generation,
        parent_refs,
    };

    ReconciledHTTPRoute {
        route_state,
        parent_statuses,
    }
}

#[derive(Clone, Debug)]
struct ParsedParentRef {
    group: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    section_name: Option<String>,
}

fn parse_parent_refs(route: &HTTPRoute) -> Vec<ParsedParentRef> {
    route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_parent_ref).collect())
        .unwrap_or_default()
}

fn parse_parent_ref(value: &Value) -> Option<ParsedParentRef> {
    let obj = value.as_object()?;
    Some(ParsedParentRef {
        group: obj
            .get("group")
            .and_then(|v| v.as_str())
            .unwrap_or("gateway.networking.k8s.io")
            .to_string(),
        kind: obj
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("Gateway")
            .to_string(),
        namespace: obj
            .get("namespace")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        name: obj.get("name").and_then(|v| v.as_str())?.to_string(),
        section_name: obj
            .get("sectionName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

fn resolve_parent_ref(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    // Only Gateway parentRefs are supported in T1.
    if parsed.group != "gateway.networking.k8s.io" || parsed.kind != "Gateway" {
        let conditions = vec![
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "UnsupportedValue".to_string(),
                message: format!(
                    "parentRef group {} kind {} is not supported",
                    parsed.group, parsed.kind
                ),
                observed_generation,
            },
            resolved_refs_true(observed_generation),
        ];
        return (None, conditions);
    }

    // Check cross-namespace permission.
    let permitted = grant_index.is_permitted(
        route_ns,
        "gateway.networking.k8s.io",
        "HTTPRoute",
        target_ns,
        &parsed.group,
        &parsed.kind,
        &parsed.name,
    );

    if !permitted {
        let conditions = vec![
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: format!(
                    "cross-namespace reference from {route_ns} to Gateway {}/{} is not permitted",
                    target_ns, parsed.name
                ),
                observed_generation,
            },
            resolved_refs_true(observed_generation),
        ];
        return (None, conditions);
    }

    // Find the gateway.
    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        let conditions = vec![
            StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingParent".to_string(),
                message: format!("Gateway {}/{} not found", target_ns, parsed.name),
                observed_generation,
            },
            resolved_refs_true(observed_generation),
        ];
        return (None, conditions);
    };

    // If sectionName is specified, the listener must exist.
    if let Some(ref section) = parsed.section_name {
        let listener_exists = gateway
            .listeners
            .iter()
            .any(|l| l.name.as_ref() == section.as_str());
        if !listener_exists {
            let conditions = vec![
                StatusCondition {
                    condition_type: ConditionType::Accepted,
                    status: ConditionStatus::False,
                    reason: "NoMatchingParent".to_string(),
                    message: format!(
                        "listener {} not found on Gateway {}/{}",
                        section, target_ns, parsed.name
                    ),
                    observed_generation,
                },
                resolved_refs_true(observed_generation),
            ];
            return (None, conditions);
        }
    }

    // Parent ref is accepted.
    let parent_ref = ParentRef {
        namespace: if target_ns == route_ns {
            None
        } else {
            Some(Arc::from(target_ns))
        },
        name: Arc::from(parsed.name.clone()),
        section_name: parsed.section_name.as_ref().map(|s| Arc::from(s.as_str())),
    };

    let conditions = vec![
        StatusCondition {
            condition_type: ConditionType::Accepted,
            status: ConditionStatus::True,
            reason: "Accepted".to_string(),
            message: "Route accepted by parent".to_string(),
            observed_generation,
        },
        resolved_refs_true(observed_generation),
    ];

    (Some(parent_ref), conditions)
}

fn resolved_refs_true(observed_generation: i64) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All references resolved".to_string(),
        observed_generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{GrantSubject, ListenerState, ReferenceGrantState};

    fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("HTTP"),
                port: 80,
            }],
        }
    }

    fn sample_route(parent_refs: Vec<Value>) -> HTTPRoute {
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

    #[test]
    fn accepted_when_parent_matches_same_namespace() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.route_state.parent_refs.len(), 1);

        let accepted = result.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        assert_eq!(accepted.reason, "Accepted");
    }

    #[test]
    fn denied_when_gateway_not_found() {
        let route = sample_route(vec![serde_json::json!({
            "name": "missing-gw"
        })]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn denied_when_listener_not_found() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "sectionName": "https"
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn cross_namespace_requires_grant() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "RefNotPermitted");
    }

    #[test]
    fn cross_namespace_accepted_with_grant() {
        let route = sample_route(vec![serde_json::json!({
            "namespace": "prod",
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("prod", "gw-1", "http")];
        let grant = ReferenceGrantState {
            namespace: Arc::from("prod"),
            name: Arc::from("grant-1"),
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
        };
        let grant_index = GrantIndex::new(vec![grant]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn unsupported_parent_kind_rejected() {
        let route = sample_route(vec![serde_json::json!({
            "group": "example.com",
            "kind": "Foo",
            "name": "foo-1"
        })]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "UnsupportedValue");
    }

    #[test]
    fn route_without_parent_refs_has_empty_parents() {
        let route = sample_route(vec![]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results[0].route_state.parent_refs.len(), 0);
        assert_eq!(results[0].parent_statuses.len(), 0);
    }

    #[test]
    fn multiple_parent_refs_mixed_results() {
        let route = sample_route(vec![
            serde_json::json!({"name": "gw-1", "sectionName": "http"}),
            serde_json::json!({"name": "missing-gw"}),
        ]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        assert_eq!(results[0].route_state.parent_refs.len(), 1);
        assert_eq!(results[0].parent_statuses.len(), 2);

        let first = &results[0].parent_statuses[0];
        let first_accepted = first
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(first_accepted.status, ConditionStatus::True);

        let second = &results[0].parent_statuses[1];
        let second_accepted = second
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(second_accepted.status, ConditionStatus::False);
    }

    #[test]
    fn resolved_refs_always_true_in_t1() {
        let route = sample_route(vec![serde_json::json!({"name": "missing-gw"})]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_httproutes(&[route], &gateways, &grant_index);
        let resolved = results[0].parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::True);
    }
}
