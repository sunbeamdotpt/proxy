// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ParentRef, RouteState, WeightedBackend,
};
use crate::gateway::reconcile::backend::BackendResolutionStatus;
use crate::gateway::reconcile::l4route::model::{
    L4ParentStatus, ParsedBackendRef, ParsedL4Route, ReconciledL4Route,
};
use crate::gateway::reconcile::parent::{ParsedParentRef, resolve_listener_parent};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition, conditions};
use std::collections::HashMap;
use std::sync::Arc;

/// Resolve backend references and verify that each referenced Service exists.
///
/// Returns the resolved backends plus an optional `ResolvedRefs=False`
/// condition when a backendRef is not permitted or the referenced Service does
/// not exist.
pub async fn resolve_l4_backends_async(
    client: &kube::Client,
    backends: &[ParsedBackendRef],
    route_ns: &str,
    route_kind: &str,
    grant_index: &GrantIndex,
    observed_generation: i64,
) -> (Vec<WeightedBackend>, Option<StatusCondition>) {
    let mut resolved = Vec::with_capacity(backends.len());
    let mut resolved_refs_condition: Option<StatusCondition> = None;

    for backend in backends {
        if let Err(status) = crate::gateway::reconcile::backend::check_backend_permitted(
            backend,
            route_ns,
            route_kind,
            grant_index,
        ) {
            let (reason, message) = match status {
                BackendResolutionStatus::Unsupported(msg) => ("InvalidKind", msg),
                BackendResolutionStatus::RefNotPermitted(msg) => ("RefNotPermitted", msg),
                _ => continue,
            };
            tracing::debug!(%message, reason, "L4 backendRef check failed");
            resolved_refs_condition.get_or_insert(conditions::resolved_refs_condition(
                ConditionStatus::False,
                reason,
                &message,
                observed_generation,
            ));
            continue;
        }

        let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);
        let services: kube::Api<k8s_openapi::api::core::v1::Service> =
            kube::Api::namespaced(client.clone(), target_ns);
        if services.get(&backend.name).await.is_err() {
            tracing::debug!(
                namespace = target_ns,
                name = backend.name,
                "L4 backend Service not found"
            );
            resolved_refs_condition.get_or_insert(conditions::resolved_refs_condition(
                ConditionStatus::False,
                "BackendNotFound",
                &format!("Service {}/{} not found", target_ns, backend.name),
                observed_generation,
            ));
            continue;
        }

        let port = backend.port.unwrap_or(0);
        let target = Arc::from(format!(
            "{}.{}.svc.cluster.local.:{}",
            backend.name, target_ns, port
        ));
        let weight = backend.weight.map(|w| w.max(0) as u32).unwrap_or(1);
        resolved.push(WeightedBackend {
            backend: target,
            weight,
            filters: vec![],
            protocol: crate::ir::BackendProtocol::Http,
            tls: None,
        });
    }

    (resolved, resolved_refs_condition)
}

pub fn resolve_l4_backends(
    backends: &[ParsedBackendRef],
    route_ns: &str,
    route_kind: &str,
    grant_index: &GrantIndex,
    observed_generation: i64,
) -> (Vec<WeightedBackend>, Option<StatusCondition>) {
    let mut resolved = Vec::with_capacity(backends.len());
    let mut resolved_refs_condition: Option<StatusCondition> = None;

    for backend in backends {
        if let Err(status) = crate::gateway::reconcile::backend::check_backend_permitted(
            backend,
            route_ns,
            route_kind,
            grant_index,
        ) {
            let (reason, message) = match status {
                BackendResolutionStatus::Unsupported(msg) => ("InvalidKind", msg),
                BackendResolutionStatus::RefNotPermitted(msg) => ("RefNotPermitted", msg),
                _ => continue,
            };
            tracing::debug!(%message, reason, "L4 backendRef check failed");
            resolved_refs_condition.get_or_insert(conditions::resolved_refs_condition(
                ConditionStatus::False,
                reason,
                &message,
                observed_generation,
            ));
            continue;
        }
        let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);
        let port = backend.port.unwrap_or(0);
        let target = Arc::from(format!(
            "{}.{}.svc.cluster.local.:{}",
            backend.name, target_ns, port
        ));
        let weight = backend.weight.map(|w| w.max(0) as u32).unwrap_or(1);
        resolved.push(WeightedBackend {
            backend: target,
            weight,
            filters: vec![],
            protocol: crate::ir::BackendProtocol::Http,
            tls: None,
        });
    }

    (resolved, resolved_refs_condition)
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_l4_parent_ref(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[HostnameMatch],
    route_kind: &str,
    expected_protocols: &[&str],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let target_ns = parsed.namespace.as_deref().unwrap_or(route_ns);

    if parsed.group != "gateway.networking.k8s.io" || parsed.kind != "Gateway" {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "UnsupportedValue",
                &format!(
                    "parentRef group {} kind {} is not supported",
                    parsed.group, parsed.kind
                ),
                observed_generation,
            )],
        );
    }

    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NoMatchingParent",
                &format!("Gateway {}/{} not found", target_ns, parsed.name),
                observed_generation,
            )],
        );
    };

    let no_conflicts = std::collections::BTreeMap::<Arc<str>, Arc<str>>::new();
    resolve_listener_parent(
        parsed,
        route_ns,
        observed_generation,
        route_hostnames,
        &gateway.listeners,
        namespace_labels,
        listener_allowed,
        target_ns,
        &parsed.name,
        "Gateway",
        &no_conflicts,
        route_kind,
        Some(expected_protocols),
    )
}

pub(crate) fn reconcile_l4_routes(
    routes: &[ParsedL4Route],
    route_kind: &str,
    expected_protocols: &[&str],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    routes
        .iter()
        .map(|route| {
            let mut parent_refs = Vec::new();
            let mut parent_statuses = Vec::new();

            for parsed in &route.parent_refs {
                let (parent_ref, conditions) = resolve_l4_parent_ref(
                    parsed,
                    route.namespace.as_ref(),
                    route.generation,
                    &route.hostnames,
                    route_kind,
                    expected_protocols,
                    gateways,
                    namespace_labels,
                    listener_allowed,
                );
                if let Some(parent_ref) = parent_ref {
                    parent_refs.push(parent_ref.clone());
                    parent_statuses.push(L4ParentStatus {
                        parent_ref,
                        conditions,
                    });
                } else if !conditions.is_empty() {
                    parent_statuses.push(L4ParentStatus {
                        parent_ref: ParentRef {
                            group: Arc::from("gateway.networking.k8s.io"),
                            kind: Arc::from("Gateway"),

                            namespace: parsed
                                .namespace
                                .as_ref()
                                .map(|ns| Arc::from(ns.as_str()))
                                .or_else(|| Some(Arc::from(route.namespace.as_ref()))),
                            name: Arc::from(parsed.name.as_str()),
                            section_name: parsed
                                .section_name
                                .as_ref()
                                .map(|s| Arc::from(s.as_str())),
                            port: parsed.port.map(|p| p as u16),
                        },
                        conditions,
                    });
                }
            }

            let route_state = RouteState {
                namespace: Arc::clone(&route.namespace),
                name: Arc::clone(&route.name),
                kind: Arc::from(route_kind),
                generation: route.generation,
                parent_refs,
            };

            let accepted = !parent_statuses.is_empty()
                && !parent_statuses.iter().any(|ps| {
                    ps.conditions.iter().any(|c| {
                        c.condition_type == ConditionType::Accepted
                            && c.status == ConditionStatus::False
                    })
                });

            let programmed_condition = if accepted {
                conditions::programmed_condition(
                    ConditionStatus::True,
                    "Programmed",
                    "Route programmed into proxy",
                    route.generation,
                )
            } else {
                conditions::programmed_condition(
                    ConditionStatus::False,
                    "NotProgrammed",
                    "Route not programmed into proxy",
                    route.generation,
                )
            };
            for parent_status in &mut parent_statuses {
                parent_status.conditions.push(programmed_condition.clone());
            }

            ReconciledL4Route {
                route_state,
                hostnames: route.hostnames.clone(),
                backends: vec![],
                programmed: accepted,
                parent_statuses,
            }
        })
        .collect()
}

/// Reconcile TCPRoutes against the current Gateway set.
pub fn reconcile_tcproutes(
    routes: &[crate::gateway::api::TCPRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes
        .iter()
        .map(crate::gateway::reconcile::l4route::kinds::parse_tcproute)
        .collect();
    reconcile_l4_routes(
        &parsed,
        "TCPRoute",
        &["TCP"],
        gateways,
        namespace_labels,
        listener_allowed,
    )
}

/// Reconcile UDPRoutes against the current Gateway set.
pub fn reconcile_udproutes(
    routes: &[crate::gateway::api::UDPRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes
        .iter()
        .map(crate::gateway::reconcile::l4route::kinds::parse_udproute)
        .collect();
    reconcile_l4_routes(
        &parsed,
        "UDPRoute",
        &["UDP"],
        gateways,
        namespace_labels,
        listener_allowed,
    )
}

/// Reconcile TLSRoutes against the current Gateway set.
pub fn reconcile_tlsroutes(
    routes: &[crate::gateway::api::TLSRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes
        .iter()
        .map(crate::gateway::reconcile::l4route::kinds::parse_tlsroute)
        .collect();
    reconcile_l4_routes(
        &parsed,
        "TLSRoute",
        &["TLS"],
        gateways,
        namespace_labels,
        listener_allowed,
    )
}
