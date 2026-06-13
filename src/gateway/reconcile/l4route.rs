// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 route reconciler (TCPRoute / UDPRoute / TLSRoute).
//!
//! Watches L4 route resources, resolves parentRefs against Gateway listeners,
//! validates backendRefs, computes status conditions, and emits the L4 route
//! states consumed by `translate_view_to_ir`.

use crate::gateway::api::{Gateway, ReferenceGrant, TCPRoute, TLSRoute, UDPRoute};
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerState, ParentRef, RouteState,
    TCPRouteState, TLSRouteState, UDPRouteState, WeightedBackend,
};
use crate::gateway::reconcile::httproute::{
    listener_allows_kind, listener_hostname_intersects, namespace_allowed,
};
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use futures::StreamExt;
use gateway_api::experimental::tcproutes::{
    TcpRouteParentRefs, TcpRouteRules, TcpRouteRulesBackendRefs,
};
use gateway_api::experimental::udproutes::{
    UdpRouteParentRefs, UdpRouteRules, UdpRouteRulesBackendRefs,
};
use gateway_api::tlsroutes::{TlsRouteParentRefs, TlsRouteRules, TlsRouteRulesBackendRefs};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Result of reconciling a single L4 route.
#[derive(Clone, Debug)]
pub struct ReconciledL4Route {
    /// Generic route identity produced by the reconcile.
    pub route_state: RouteState,
    /// SNI hostnames for TLSRoute; empty for TCP/UDP.
    pub hostnames: Vec<HostnameMatch>,
    /// Resolved weighted backends.
    pub backends: Vec<WeightedBackend>,
    /// True when the route is accepted and all backend references resolve.
    pub programmed: bool,
    /// Per-parentRef status entries.
    pub parent_statuses: Vec<L4ParentStatus>,
}

/// Status conditions for a single parentRef entry on an L4 route.
#[derive(Clone, Debug)]
pub struct L4ParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

#[derive(Clone, Debug)]
struct ParsedParentRef {
    group: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    section_name: Option<String>,
    port: Option<i32>,
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedBackendRef {
    group: Option<String>,
    kind: Option<String>,
    namespace: Option<String>,
    name: String,
    port: Option<i32>,
    weight: Option<i32>,
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedL4Route {
    namespace: Arc<str>,
    name: Arc<str>,
    generation: i64,
    hostnames: Vec<HostnameMatch>,
    parent_refs: Vec<ParsedParentRef>,
    pub(crate) backends: Vec<ParsedBackendRef>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub(crate) fn parse_tcproute(route: &TCPRoute) -> ParsedL4Route {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let parent_refs = route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_tcproute_parent).collect())
        .unwrap_or_default();
    let backends = flatten_tcp_backends(&route.spec.rules);

    ParsedL4Route {
        namespace: ns,
        name,
        generation,
        hostnames: vec![],
        parent_refs,
        backends,
    }
}

pub(crate) fn parse_udproute(route: &UDPRoute) -> ParsedL4Route {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let parent_refs = route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_udproute_parent).collect())
        .unwrap_or_default();
    let backends = flatten_udp_backends(&route.spec.rules);

    ParsedL4Route {
        namespace: ns,
        name,
        generation,
        hostnames: vec![],
        parent_refs,
        backends,
    }
}

pub(crate) fn parse_tlsroute(route: &TLSRoute) -> ParsedL4Route {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let hostnames: Vec<HostnameMatch> = route
        .spec
        .hostnames
        .iter()
        .map(|s| {
            if let Some(rest) = s.strip_prefix("*.") {
                HostnameMatch::Wildcard(Arc::from(rest))
            } else {
                HostnameMatch::Exact(Arc::from(s.as_str()))
            }
        })
        .collect();

    let parent_refs = route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_tlsroute_parent).collect())
        .unwrap_or_default();
    let backends = flatten_tls_backends(&route.spec.rules);

    ParsedL4Route {
        namespace: ns,
        name,
        generation,
        hostnames,
        parent_refs,
        backends,
    }
}

fn parse_tcproute_parent(value: &TcpRouteParentRefs) -> Option<ParsedParentRef> {
    Some(ParsedParentRef {
        group: value
            .group
            .as_deref()
            .unwrap_or("gateway.networking.k8s.io")
            .to_string(),
        kind: value.kind.as_deref().unwrap_or("Gateway").to_string(),
        namespace: value.namespace.clone(),
        name: value.name.clone(),
        section_name: value.section_name.clone(),
        port: value.port,
    })
}

fn parse_udproute_parent(value: &UdpRouteParentRefs) -> Option<ParsedParentRef> {
    Some(ParsedParentRef {
        group: value
            .group
            .as_deref()
            .unwrap_or("gateway.networking.k8s.io")
            .to_string(),
        kind: value.kind.as_deref().unwrap_or("Gateway").to_string(),
        namespace: value.namespace.clone(),
        name: value.name.clone(),
        section_name: value.section_name.clone(),
        port: value.port,
    })
}

fn parse_tlsroute_parent(value: &TlsRouteParentRefs) -> Option<ParsedParentRef> {
    Some(ParsedParentRef {
        group: value
            .group
            .as_deref()
            .unwrap_or("gateway.networking.k8s.io")
            .to_string(),
        kind: value.kind.as_deref().unwrap_or("Gateway").to_string(),
        namespace: value.namespace.clone(),
        name: value.name.clone(),
        section_name: value.section_name.clone(),
        port: value.port,
    })
}

fn flatten_tcp_backends(rules: &[TcpRouteRules]) -> Vec<ParsedBackendRef> {
    rules
        .iter()
        .flat_map(|rule| {
            rule.backend_refs
                .iter()
                .map(into_parsed_backend::<TcpRouteRulesBackendRefs>)
        })
        .collect()
}

fn flatten_udp_backends(rules: &[UdpRouteRules]) -> Vec<ParsedBackendRef> {
    rules
        .iter()
        .flat_map(|rule| {
            rule.backend_refs
                .iter()
                .map(into_parsed_backend::<UdpRouteRulesBackendRefs>)
        })
        .collect()
}

fn flatten_tls_backends(rules: &[TlsRouteRules]) -> Vec<ParsedBackendRef> {
    rules
        .iter()
        .flat_map(|rule| {
            rule.backend_refs
                .iter()
                .map(into_parsed_backend::<TlsRouteRulesBackendRefs>)
        })
        .collect()
}

fn into_parsed_backend<T: BackendRefLike>(value: &T) -> ParsedBackendRef {
    ParsedBackendRef {
        group: value.group(),
        kind: value.kind(),
        namespace: value.namespace(),
        name: value.name(),
        port: value.port(),
        weight: value.weight(),
    }
}

trait BackendRefLike {
    fn group(&self) -> Option<String>;
    fn kind(&self) -> Option<String>;
    fn namespace(&self) -> Option<String>;
    fn name(&self) -> String;
    fn port(&self) -> Option<i32>;
    fn weight(&self) -> Option<i32>;
}

impl BackendRefLike for TcpRouteRulesBackendRefs {
    fn group(&self) -> Option<String> {
        self.group.clone()
    }
    fn kind(&self) -> Option<String> {
        self.kind.clone()
    }
    fn namespace(&self) -> Option<String> {
        self.namespace.clone()
    }
    fn name(&self) -> String {
        self.name.clone()
    }
    fn port(&self) -> Option<i32> {
        self.port
    }
    fn weight(&self) -> Option<i32> {
        self.weight
    }
}

impl BackendRefLike for UdpRouteRulesBackendRefs {
    fn group(&self) -> Option<String> {
        self.group.clone()
    }
    fn kind(&self) -> Option<String> {
        self.kind.clone()
    }
    fn namespace(&self) -> Option<String> {
        self.namespace.clone()
    }
    fn name(&self) -> String {
        self.name.clone()
    }
    fn port(&self) -> Option<i32> {
        self.port
    }
    fn weight(&self) -> Option<i32> {
        self.weight
    }
}

impl BackendRefLike for TlsRouteRulesBackendRefs {
    fn group(&self) -> Option<String> {
        self.group.clone()
    }
    fn kind(&self) -> Option<String> {
        self.kind.clone()
    }
    fn namespace(&self) -> Option<String> {
        self.namespace.clone()
    }
    fn name(&self) -> String {
        self.name.clone()
    }
    fn port(&self) -> Option<i32> {
        self.port
    }
    fn weight(&self) -> Option<i32> {
        self.weight
    }
}

// ---------------------------------------------------------------------------
// Backend resolution
// ---------------------------------------------------------------------------

/// Check a single L4 backendRef for permission and supported kind.
fn check_l4_backend_permitted(
    backend: &ParsedBackendRef,
    route_ns: &str,
    route_kind: &str,
    grant_index: &GrantIndex,
) -> Result<(), String> {
    let group = backend.group.as_deref().unwrap_or("");
    let kind = backend.kind.as_deref().unwrap_or("Service");
    let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);

    if !group.is_empty() || kind != "Service" {
        return Err(format!(
            "backendRef group {} kind {} is not supported",
            group, kind
        ));
    }

    let permitted = grant_index.is_permitted(
        route_ns,
        "gateway.networking.k8s.io",
        route_kind,
        target_ns,
        group,
        kind,
        &backend.name,
    );

    if !permitted {
        return Err(format!(
            "cross-namespace backend reference from {} to {}/{} is not permitted",
            route_ns, target_ns, backend.name
        ));
    }

    Ok(())
}

/// Resolve backend references and verify that each referenced Service exists.
///
/// Returns the resolved backends plus an optional `ResolvedRefs=False`
/// condition when a backendRef is not permitted or the referenced Service does
/// not exist.
pub(crate) async fn resolve_l4_backends_async(
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
        if let Err(msg) = check_l4_backend_permitted(backend, route_ns, route_kind, grant_index) {
            tracing::debug!(%msg, "L4 backendRef not permitted");
            resolved_refs_condition.get_or_insert(StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: msg,
                observed_generation,
            });
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
            resolved_refs_condition.get_or_insert(StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "BackendNotFound".to_string(),
                message: format!("Service {}/{} not found", target_ns, backend.name),
                observed_generation,
            });
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
        });
    }

    (resolved, resolved_refs_condition)
}

#[cfg(test)]
pub(crate) fn resolve_l4_backends(
    backends: &[ParsedBackendRef],
    route_ns: &str,
    route_kind: &str,
    grant_index: &GrantIndex,
    observed_generation: i64,
) -> (Vec<WeightedBackend>, Option<StatusCondition>) {
    let mut resolved = Vec::with_capacity(backends.len());
    let mut resolved_refs_condition: Option<StatusCondition> = None;

    for backend in backends {
        if let Err(msg) = check_l4_backend_permitted(backend, route_ns, route_kind, grant_index) {
            tracing::debug!(%msg, "L4 backendRef not permitted");
            resolved_refs_condition.get_or_insert(StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: msg,
                observed_generation,
            });
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
        });
    }

    (resolved, resolved_refs_condition)
}

// ---------------------------------------------------------------------------
// ParentRef resolution
// ---------------------------------------------------------------------------

/// Check whether a listener can accept an L4 route of the given kind and protocol.
#[allow(clippy::too_many_arguments)]
fn listener_accepts_l4_route(
    listener: &ListenerState,
    allowed: &AllowedRoutes,
    route_ns: &str,
    gateway_ns: &str,
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    route_hostnames: &[HostnameMatch],
    route_kind: &str,
    expected_protocols: &[&str],
) -> bool {
    if !listener_allows_kind(allowed, "gateway.networking.k8s.io", route_kind) {
        return false;
    }
    if !expected_protocols
        .iter()
        .any(|p| p.eq_ignore_ascii_case(listener.protocol.as_ref()))
    {
        return false;
    }
    if !namespace_allowed(&allowed.namespaces, route_ns, gateway_ns, namespace_labels) {
        return false;
    }
    listener_hostname_intersects(listener.hostname.as_deref(), route_hostnames)
}

#[allow(clippy::too_many_arguments)]
fn resolve_l4_parent_ref(
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
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "UnsupportedValue".to_string(),
                message: format!(
                    "parentRef group {} kind {} is not supported",
                    parsed.group, parsed.kind
                ),
                observed_generation,
            }],
        );
    }

    let gateway = gateways
        .iter()
        .find(|g| g.namespace.as_ref() == target_ns && g.name.as_ref() == parsed.name);

    let Some(gateway) = gateway else {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingParent".to_string(),
                message: format!("Gateway {}/{} not found", target_ns, parsed.name),
                observed_generation,
            }],
        );
    };

    let matching_listeners: Vec<&ListenerState> = gateway
        .listeners
        .iter()
        .filter(|l| {
            let section_matches = parsed
                .section_name
                .as_deref()
                .map(|s| s == l.name.as_ref())
                .unwrap_or(true);
            let port_matches = parsed.port.map(|p| p == l.port as i32).unwrap_or(true);
            section_matches && port_matches
        })
        .collect();

    if let Some(ref section) = parsed.section_name {
        let listener_exists = gateway
            .listeners
            .iter()
            .any(|l| l.name.as_ref() == section.as_str());
        if !listener_exists {
            return (
                None,
                vec![StatusCondition {
                    condition_type: ConditionType::Accepted,
                    status: ConditionStatus::False,
                    reason: "NoMatchingParent".to_string(),
                    message: format!(
                        "listener {} not found on Gateway {}/{}",
                        section, target_ns, parsed.name
                    ),
                    observed_generation,
                }],
            );
        }
    }

    if let Some(port) = parsed.port {
        if matching_listeners.is_empty() {
            return (
                None,
                vec![StatusCondition {
                    condition_type: ConditionType::Accepted,
                    status: ConditionStatus::False,
                    reason: "NoMatchingParent".to_string(),
                    message: format!(
                        "no listener matching port {} on Gateway {}/{}",
                        port, target_ns, parsed.name
                    ),
                    observed_generation,
                }],
            );
        }
    }

    let mut kind_allowed = false;
    let mut namespace_allowed_flag = false;
    let mut hostname_intersects = false;

    for listener in matching_listeners {
        let allowed = listener_allowed
            .get(&(
                target_ns.to_string(),
                parsed.name.clone(),
                listener.name.to_string(),
            ))
            .cloned()
            .unwrap_or_default();
        if !listener_accepts_l4_route(
            listener,
            &allowed,
            route_ns,
            target_ns,
            namespace_labels,
            route_hostnames,
            route_kind,
            expected_protocols,
        ) {
            continue;
        }
        kind_allowed = true;
        namespace_allowed_flag = true;
        hostname_intersects = true;
    }

    if !kind_allowed || !namespace_allowed_flag {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NotAllowedByListeners".to_string(),
                message: format!(
                    "Route is not allowed by any listener of Gateway {}/{}",
                    target_ns, parsed.name
                ),
                observed_generation,
            }],
        );
    }

    if !hostname_intersects {
        return (
            None,
            vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::False,
                reason: "NoMatchingListenerHostname".to_string(),
                message: format!(
                    "Route hostnames do not intersect with any listener of Gateway {}/{}",
                    target_ns, parsed.name
                ),
                observed_generation,
            }],
        );
    }

    let parent_ref = ParentRef {
        namespace: Some(Arc::from(target_ns)),
        name: Arc::from(parsed.name.clone()),
        section_name: parsed.section_name.as_ref().map(|s| Arc::from(s.as_str())),
    };

    let conditions = vec![StatusCondition {
        condition_type: ConditionType::Accepted,
        status: ConditionStatus::True,
        reason: "Accepted".to_string(),
        message: "Route accepted by parent".to_string(),
        observed_generation,
    }];

    (Some(parent_ref), conditions)
}

// ---------------------------------------------------------------------------
// Generic reconcile
// ---------------------------------------------------------------------------

fn reconcile_l4_routes(
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

// ---------------------------------------------------------------------------
// Public entry points used by reconcile_tick and controllers
// ---------------------------------------------------------------------------

/// Reconcile TCPRoutes against the current Gateway set.
pub fn reconcile_tcproutes(
    routes: &[TCPRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes.iter().map(parse_tcproute).collect();
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
    routes: &[UDPRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes.iter().map(parse_udproute).collect();
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
    routes: &[TLSRoute],
    gateways: &[GatewayState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<ReconciledL4Route> {
    let parsed: Vec<_> = routes.iter().map(parse_tlsroute).collect();
    reconcile_l4_routes(
        &parsed,
        "TLSRoute",
        &["TLS"],
        gateways,
        namespace_labels,
        listener_allowed,
    )
}

/// Parse a TCPRoute CRD into the full `TCPRouteState` model.
pub fn parse_tcproute_state(route: &TCPRoute) -> TCPRouteState {
    let parsed = parse_tcproute(route);
    TCPRouteState {
        namespace: parsed.namespace,
        name: parsed.name,
        generation: parsed.generation,
        parent_refs: vec![],
        backends: vec![],
        programmed: false,
    }
}

/// Parse a UDPRoute CRD into the full `UDPRouteState` model.
pub fn parse_udproute_state(route: &UDPRoute) -> UDPRouteState {
    let parsed = parse_udproute(route);
    UDPRouteState {
        namespace: parsed.namespace,
        name: parsed.name,
        generation: parsed.generation,
        parent_refs: vec![],
        backends: vec![],
        programmed: false,
    }
}

/// Parse a TLSRoute CRD into the full `TLSRouteState` model.
pub fn parse_tlsroute_state(route: &TLSRoute) -> TLSRouteState {
    let parsed = parse_tlsroute(route);
    TLSRouteState {
        namespace: parsed.namespace,
        name: parsed.name,
        generation: parsed.generation,
        hostnames: parsed.hostnames,
        parent_refs: vec![],
        backends: vec![],
        programmed: false,
    }
}

// ---------------------------------------------------------------------------
// Controllers
// ---------------------------------------------------------------------------

/// Context shared by the L4 route controllers.
#[derive(Clone)]
pub struct L4RouteContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

async fn build_reconcile_context(
    client: &kube::Client,
) -> Option<(
    Vec<GatewayState>,
    GrantIndex,
    HashMap<String, HashMap<String, String>>,
    HashMap<(String, String, String), AllowedRoutes>,
)> {
    let gateways: Api<Gateway> = Api::all(client.clone());
    let grants: Api<ReferenceGrant> = Api::all(client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for L4 reconcile");
            return None;
        }
    };
    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for L4 reconcile");
            return None;
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for L4 reconcile");
            return None;
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();
    let grant_states = reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states);

    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();
    let listener_allowed =
        crate::gateway::reconcile::gateway::build_listener_allowed_map(&gateway_list.items);

    Some((
        gateway_states,
        grant_index,
        namespace_labels,
        listener_allowed,
    ))
}

fn build_status_parents(parent_statuses: &[L4ParentStatus]) -> Vec<Value> {
    parent_statuses
        .iter()
        .map(|ps| {
            let conditions: Vec<Value> = ps
                .conditions
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "type": match c.condition_type {
                            ConditionType::Accepted => "Accepted",
                            ConditionType::Programmed => "Programmed",
                            ConditionType::ResolvedRefs => "ResolvedRefs",
                            ConditionType::Conflicted => "Conflicted",
                            ConditionType::Poison => "Poison",
                            ConditionType::NoMatchingParent => "NoMatchingParent",
                            ConditionType::RefNotPermitted => "RefNotPermitted",
                            ConditionType::UnsupportedFeature => "UnsupportedFeature",
                        },
                        "status": match c.status {
                            ConditionStatus::True => "True",
                            ConditionStatus::False => "False",
                            ConditionStatus::Unknown => "Unknown",
                        },
                        "reason": c.reason,
                        "message": c.message,
                        "observedGeneration": c.observed_generation,
                        "lastTransitionTime": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    })
                })
                .collect();

            let mut parent_ref = serde_json::Map::new();
            parent_ref.insert("group".into(), "gateway.networking.k8s.io".into());
            parent_ref.insert("kind".into(), "Gateway".into());
            parent_ref.insert("name".into(), serde_json::json!(ps.parent_ref.name.as_ref()));
            parent_ref.insert(
                "namespace".into(),
                serde_json::json!(ps.parent_ref.namespace.as_deref().unwrap_or("")),
            );
            if let Some(section) = ps.parent_ref.section_name.as_deref() {
                parent_ref.insert("sectionName".into(), serde_json::json!(section));
            }
            serde_json::json!({
                "parentRef": parent_ref,
                "controllerName": crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME,
                "conditions": conditions,
            })
        })
        .collect()
}

async fn patch_l4_status<R>(
    route: &R,
    ctx: &L4RouteContext,
    parent_statuses: &[L4ParentStatus],
    api_version: &str,
    kind: &str,
) where
    R: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
        + kube::core::object::HasStatus
        + serde::de::DeserializeOwned,
    <R as kube::core::object::HasStatus>::Status: serde::Serialize,
{
    let meta = route.meta();
    let ns = meta.namespace.clone().unwrap_or_default();
    let name = meta.name.clone().unwrap_or_default();

    let new_status = serde_json::json!({ "parents": build_status_parents(parent_statuses) });

    let old_status_json = route
        .status()
        .and_then(|s| serde_json::to_value(s).ok())
        .unwrap_or(serde_json::Value::Null);
    let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
    let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

    if old_stripped == new_stripped {
        tracing::debug!(
            name,
            namespace = ns,
            "{} status unchanged, skipping patch",
            kind
        );
        return;
    }

    let patch_body = serde_json::json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": ns,
        },
        "status": new_status,
    });
    let api: Api<R> = Api::namespaced(ctx.client.clone(), &ns);
    let pp = PatchParams::apply("sunbeam-proxy");
    if let Err(e) = api
        .patch_status(&name, &pp, &Patch::Apply(&patch_body))
        .await
    {
        tracing::warn!(error = %e, name, namespace = ns, "{} status patch failed", kind);
    } else {
        tracing::debug!(name, namespace = ns, "{} status patched", kind);
    }
}

/// Reconcile a single TCPRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_tcproute(
    route: Arc<TCPRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    let ns = route.metadata.namespace.clone().unwrap_or_default();
    let name = route.metadata.name.clone().unwrap_or_default();
    let observed_generation = route.metadata.generation.unwrap_or(0);

    let Some((gateway_states, grant_index, namespace_labels, listener_allowed)) =
        build_reconcile_context(&ctx.client).await
    else {
        return Ok(Action::requeue(Duration::from_secs(5)));
    };

    let mut reconciled = reconcile_tcproutes(
        std::slice::from_ref(&*route),
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| ReconciledL4Route {
        route_state: RouteState {
            namespace: Arc::from(ns.as_str()),
            name: Arc::from(name.as_str()),
            kind: Arc::from("TCPRoute"),
            generation: observed_generation,
            parent_refs: vec![],
        },
        hostnames: vec![],
        backends: vec![],
        programmed: false,
        parent_statuses: vec![],
    });

    let parsed = parse_tcproute(&route);
    let (backends, resolved_refs_condition) = resolve_l4_backends_async(
        &ctx.client,
        &parsed.backends,
        &ns,
        "TCPRoute",
        &grant_index,
        observed_generation,
    )
    .await;
    reconciled.backends = backends;
    let resolved_refs = resolved_refs_condition.unwrap_or_else(|| StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All backend references resolved".to_string(),
        observed_generation,
    });
    for parent_status in &mut reconciled.parent_statuses {
        parent_status.conditions.push(resolved_refs.clone());
    }
    reconciled.programmed = reconciled.programmed && resolved_refs.status == ConditionStatus::True;

    if ctx.is_leader.load(Ordering::Relaxed) {
        patch_l4_status(
            &*route,
            &ctx,
            &reconciled.parent_statuses,
            "gateway.networking.k8s.io/v1alpha2",
            "TCPRoute",
        )
        .await;
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

/// Reconcile a single UDPRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_udproute(
    route: Arc<UDPRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    let ns = route.metadata.namespace.clone().unwrap_or_default();
    let name = route.metadata.name.clone().unwrap_or_default();
    let observed_generation = route.metadata.generation.unwrap_or(0);

    let Some((gateway_states, grant_index, namespace_labels, listener_allowed)) =
        build_reconcile_context(&ctx.client).await
    else {
        return Ok(Action::requeue(Duration::from_secs(5)));
    };

    let mut reconciled = reconcile_udproutes(
        std::slice::from_ref(&*route),
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| ReconciledL4Route {
        route_state: RouteState {
            namespace: Arc::from(ns.as_str()),
            name: Arc::from(name.as_str()),
            kind: Arc::from("UDPRoute"),
            generation: observed_generation,
            parent_refs: vec![],
        },
        hostnames: vec![],
        backends: vec![],
        programmed: false,
        parent_statuses: vec![],
    });

    let parsed = parse_udproute(&route);
    let (backends, resolved_refs_condition) = resolve_l4_backends_async(
        &ctx.client,
        &parsed.backends,
        &ns,
        "UDPRoute",
        &grant_index,
        observed_generation,
    )
    .await;
    reconciled.backends = backends;
    let resolved_refs = resolved_refs_condition.unwrap_or_else(|| StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All backend references resolved".to_string(),
        observed_generation,
    });
    for parent_status in &mut reconciled.parent_statuses {
        parent_status.conditions.push(resolved_refs.clone());
    }
    reconciled.programmed = reconciled.programmed && resolved_refs.status == ConditionStatus::True;

    if ctx.is_leader.load(Ordering::Relaxed) {
        patch_l4_status(
            &*route,
            &ctx,
            &reconciled.parent_statuses,
            "gateway.networking.k8s.io/v1alpha2",
            "UDPRoute",
        )
        .await;
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

/// Reconcile a single TLSRoute: resolve parentRefs, compute status, and patch
/// `.status.parents[]` when leader.
pub async fn reconcile_tlsroute(
    route: Arc<TLSRoute>,
    ctx: Arc<L4RouteContext>,
) -> Result<Action, kube::Error> {
    let ns = route.metadata.namespace.clone().unwrap_or_default();
    let name = route.metadata.name.clone().unwrap_or_default();
    let observed_generation = route.metadata.generation.unwrap_or(0);

    let Some((gateway_states, grant_index, namespace_labels, listener_allowed)) =
        build_reconcile_context(&ctx.client).await
    else {
        return Ok(Action::requeue(Duration::from_secs(5)));
    };

    let mut reconciled = reconcile_tlsroutes(
        std::slice::from_ref(&*route),
        &gateway_states,
        &namespace_labels,
        &listener_allowed,
    )
    .into_iter()
    .next()
    .unwrap_or_else(|| ReconciledL4Route {
        route_state: RouteState {
            namespace: Arc::from(ns.as_str()),
            name: Arc::from(name.as_str()),
            kind: Arc::from("TLSRoute"),
            generation: observed_generation,
            parent_refs: vec![],
        },
        hostnames: vec![],
        backends: vec![],
        programmed: false,
        parent_statuses: vec![],
    });

    let parsed = parse_tlsroute(&route);
    let (backends, resolved_refs_condition) = resolve_l4_backends_async(
        &ctx.client,
        &parsed.backends,
        &ns,
        "TLSRoute",
        &grant_index,
        observed_generation,
    )
    .await;
    reconciled.backends = backends;
    let resolved_refs = resolved_refs_condition.unwrap_or_else(|| StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All backend references resolved".to_string(),
        observed_generation,
    });
    for parent_status in &mut reconciled.parent_statuses {
        parent_status.conditions.push(resolved_refs.clone());
    }
    reconciled.programmed = reconciled.programmed && resolved_refs.status == ConditionStatus::True;

    if ctx.is_leader.load(Ordering::Relaxed) {
        patch_l4_status(
            &*route,
            &ctx,
            &reconciled.parent_statuses,
            "gateway.networking.k8s.io/v1",
            "TLSRoute",
        )
        .await;
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy_tcproute(
    _route: Arc<TCPRoute>,
    _error: &kube::Error,
    _ctx: Arc<L4RouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

fn error_policy_udproute(
    _route: Arc<UDPRoute>,
    _error: &kube::Error,
    _ctx: Arc<L4RouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

fn error_policy_tlsroute(
    _route: Arc<TLSRoute>,
    _error: &kube::Error,
    _ctx: Arc<L4RouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Check whether an L4 route CRD is installed by attempting a list.
///
/// Returns `false` when the API returns 404 (CRD missing) or any other
/// error, logging once at debug/warn level instead of letting the
/// controller enter a tight error backoff loop.
async fn l4_crd_available<R>(client: &Client, kind: &str) -> bool
where
    R: kube::Resource<DynamicType = ()> + serde::de::DeserializeOwned + Clone + std::fmt::Debug,
{
    let api: Api<R> = Api::all(client.clone());
    match api.list(&Default::default()).await {
        Ok(_) => true,
        Err(kube::Error::Api(s)) if s.code == 404 => {
            tracing::debug!(kind, "L4 route CRD is not installed; skipping controller");
            false
        }
        Err(e) => {
            tracing::warn!(error = %e, kind, "failed to list L4 route CRD; skipping controller");
            false
        }
    }
}

/// Start the TCPRoute controller only when the CRD is installed.
pub async fn maybe_run_tcproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if l4_crd_available::<TCPRoute>(&client, "TCPRoute").await {
        Some(run_tcproute_controller(client, is_leader))
    } else {
        None
    }
}

/// Start the TCPRoute controller.
pub fn run_tcproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(L4RouteContext {
        client: client.clone(),
        is_leader,
    });
    let routes = Api::<TCPRoute>::all(client);
    tokio::spawn(async move {
        Controller::new(routes, kube::runtime::watcher::Config::default())
            .run(reconcile_tcproute, error_policy_tcproute, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("TCPRoute controller error: {e}"),
                }
            })
            .await;
    })
}

/// Start the UDPRoute controller only when the CRD is installed.
pub async fn maybe_run_udproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if l4_crd_available::<UDPRoute>(&client, "UDPRoute").await {
        Some(run_udproute_controller(client, is_leader))
    } else {
        None
    }
}

/// Start the UDPRoute controller.
pub fn run_udproute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(L4RouteContext {
        client: client.clone(),
        is_leader,
    });
    let routes = Api::<UDPRoute>::all(client);
    tokio::spawn(async move {
        Controller::new(routes, kube::runtime::watcher::Config::default())
            .run(reconcile_udproute, error_policy_udproute, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("UDPRoute controller error: {e}"),
                }
            })
            .await;
    })
}

/// Start the TLSRoute controller only when the CRD is installed.
pub async fn maybe_run_tlsroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if l4_crd_available::<TLSRoute>(&client, "TLSRoute").await {
        Some(run_tlsroute_controller(client, is_leader))
    } else {
        None
    }
}

/// Start the TLSRoute controller.
pub fn run_tlsroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(L4RouteContext {
        client: client.clone(),
        is_leader,
    });
    let routes = Api::<TLSRoute>::all(client);
    tokio::spawn(async move {
        Controller::new(routes, kube::runtime::watcher::Config::default())
            .run(reconcile_tlsroute, error_policy_tlsroute, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("TLSRoute controller error: {e}"),
                }
            })
            .await;
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{AllowedRoutes, GatewayState, ListenerState, RouteNamespaces};

    fn gw_with_tcp_listener(ns: &str, name: &str, listener: &str, port: u16) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("TCP"),
                port,
                hostname: None,
                tls_mode: None,
            }],
        }
    }

    fn gw_with_tls_listener(
        ns: &str,
        name: &str,
        listener: &str,
        port: u16,
        hostname: Option<&str>,
    ) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("TLS"),
                port,
                hostname: hostname.map(Arc::from),
                tls_mode: None,
            }],
        }
    }

    fn empty_listener_allowed() -> HashMap<(String, String, String), AllowedRoutes> {
        HashMap::new()
    }

    fn empty_namespace_labels() -> HashMap<String, HashMap<String, String>> {
        HashMap::new()
    }

    #[test]
    fn parse_tcproute_state_basic() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
              generation: 3
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
                      weight: 5
        "#;
        let route: TCPRoute = serde_yaml::from_str(yaml).unwrap();
        let state = parse_tcproute_state(&route);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "tcp-route");
        assert_eq!(state.generation, 3);
        assert!(state.parent_refs.is_empty());
        assert!(state.backends.is_empty());
        assert!(!state.programmed);
    }

    #[test]
    fn parse_tlsroute_state_preserves_hostnames() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
              generation: 2
            spec:
              hostnames:
                - example.com
                - "*.example.com"
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#;
        let route: TLSRoute = serde_yaml::from_str(yaml).unwrap();
        let state = parse_tlsroute_state(&route);
        assert_eq!(state.hostnames.len(), 2);
        assert!(matches!(
            &state.hostnames[0],
            HostnameMatch::Exact(h) if h.as_ref() == "example.com"
        ));
        assert!(matches!(
            &state.hostnames[1],
            HostnameMatch::Wildcard(h) if h.as_ref() == "example.com"
        ));
    }

    #[test]
    fn tcproute_accepted_when_parent_matches_tcp_listener() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
              generation: 1
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
        let _grant_index = GrantIndex::new(vec![]);

        let reconciled = reconcile_tcproutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(reconciled.len(), 1);
        let r = &reconciled[0];
        assert_eq!(r.route_state.parent_refs.len(), 1);
        assert!(r.programmed);

        let accepted = r.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
    }

    #[test]
    fn tcproute_rejected_on_http_listener() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
        )
        .unwrap();
        let gateways = vec![GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
            }],
        }];

        let reconciled = reconcile_tcproutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert!(reconciled[0].route_state.parent_refs.is_empty());
        assert!(!reconciled[0].programmed);
    }

    #[test]
    fn tlsroute_hostname_intersection_enforced() {
        let route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tls_listener(
            "default",
            "gw-1",
            "tls",
            443,
            Some("*.other.com"),
        )];

        let reconciled = reconcile_tlsroutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert!(reconciled[0].route_state.parent_refs.is_empty());
    }

    #[test]
    fn tlsroute_accepted_when_hostname_intersects() {
        let route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
                  sectionName: tls
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tls_listener(
            "default",
            "gw-1",
            "tls",
            443,
            Some("*.example.com"),
        )];

        let reconciled = reconcile_tlsroutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(reconciled[0].route_state.parent_refs.len(), 1);
        assert_eq!(
            reconciled[0].route_state.parent_refs[0]
                .section_name
                .as_deref(),
            Some("tls")
        );
    }

    #[test]
    fn resolve_l4_backends_produces_weighted_targets() {
        let backend = ParsedBackendRef {
            group: None,
            kind: None,
            namespace: None,
            name: "svc".to_string(),
            port: Some(8080),
            weight: Some(7),
        };
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
        assert!(resolved_refs.is_none());
        assert_eq!(backends.len(), 1);
        assert_eq!(
            backends[0].backend.as_ref(),
            "svc.default.svc.cluster.local.:8080"
        );
        assert_eq!(backends[0].weight, 7);
    }

    #[test]
    fn resolve_l4_backends_rejects_cross_namespace_without_grant() {
        let backend = ParsedBackendRef {
            group: None,
            kind: None,
            namespace: Some("other".to_string()),
            name: "svc".to_string(),
            port: Some(8080),
            weight: None,
        };
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
        assert!(resolved_refs.is_some());
        assert!(backends.is_empty());
    }

    #[test]
    fn listener_allowed_kinds_can_block_l4_route() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
        let mut listener_allowed = HashMap::new();
        listener_allowed.insert(
            ("default".to_string(), "gw-1".to_string(), "tcp".to_string()),
            AllowedRoutes {
                kinds: vec![crate::gateway::model::RouteGroupKind {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("HTTPRoute"),
                }],
                namespaces: RouteNamespaces::default(),
            },
        );

        let reconciled = reconcile_tcproutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &listener_allowed,
        );
        assert!(!reconciled[0].programmed);
    }

    #[test]
    fn l4_reconciled_route_state_is_populated() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: route-x
              namespace: ns-a
              generation: 9
            spec:
              parentRefs:
                - name: gw-1
              rules: []
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tcp_listener("ns-a", "gw-1", "tcp", 9000)];

        let reconciled = reconcile_tcproutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        let r = &reconciled[0];
        assert_eq!(r.route_state.kind.as_ref(), "TCPRoute");
        assert_eq!(r.route_state.namespace.as_ref(), "ns-a");
        assert_eq!(r.route_state.name.as_ref(), "route-x");
        assert_eq!(r.route_state.generation, 9);
    }

    #[tokio::test]
    async fn resolve_l4_backends_async_finds_service() {
        let backend = ParsedBackendRef {
            group: None,
            kind: None,
            namespace: None,
            name: "svc".to_string(),
            port: Some(53),
            weight: None,
        };
        let service = k8s_openapi::api::core::v1::Service {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("svc".to_string()),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let client = kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let svc = serde_json::to_value(&service).unwrap();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(svc.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends_async(&client, &[backend], "default", "UDPRoute", &grant_index, 1)
                .await;
        assert!(resolved_refs.is_none());
        assert_eq!(backends.len(), 1);
        assert_eq!(
            backends[0].backend.as_ref(),
            "svc.default.svc.cluster.local.:53"
        );
    }

    #[tokio::test]
    async fn resolve_l4_backends_async_reports_missing_service() {
        let backend = ParsedBackendRef {
            group: None,
            kind: None,
            namespace: None,
            name: "missing".to_string(),
            port: Some(80),
            weight: None,
        };
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(404)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends_async(&client, &[backend], "default", "TCPRoute", &grant_index, 1)
                .await;
        assert!(resolved_refs.is_some());
        assert!(backends.is_empty());
    }

    #[test]
    fn status_parents_json_is_well_formed() {
        let parent_status = L4ParentStatus {
            parent_ref: ParentRef {
                namespace: Some(Arc::from("default")),
                name: Arc::from("gw-1"),
                section_name: Some(Arc::from("tls")),
            },
            conditions: vec![StatusCondition {
                condition_type: ConditionType::Accepted,
                status: ConditionStatus::True,
                reason: "Accepted".to_string(),
                message: "ok".to_string(),
                observed_generation: 1,
            }],
        };
        let parents = build_status_parents(&[parent_status]);
        assert_eq!(parents.len(), 1);
        let parent_ref = parents[0].get("parentRef").unwrap();
        assert_eq!(
            parent_ref.get("name").and_then(|v| v.as_str()),
            Some("gw-1")
        );
        assert_eq!(
            parent_ref.get("sectionName").and_then(|v| v.as_str()),
            Some("tls")
        );
        let conditions = parents[0].get("conditions").unwrap().as_array().unwrap();
        assert_eq!(
            conditions[0].get("status").and_then(|v| v.as_str()),
            Some("True")
        );
    }

    #[test]
    fn parse_default_metadata_falls_back_to_defaults() {
        let tcp: TCPRoute = TCPRoute::default();
        let parsed = parse_tcproute(&tcp);
        assert_eq!(parsed.namespace.as_ref(), "default");
        assert_eq!(parsed.name.as_ref(), "");
        assert_eq!(parsed.generation, 0);

        let udp: UDPRoute = UDPRoute::default();
        let parsed = parse_udproute(&udp);
        assert_eq!(parsed.namespace.as_ref(), "default");
        assert_eq!(parsed.name.as_ref(), "");
        assert_eq!(parsed.generation, 0);

        let tls: TLSRoute = TLSRoute::default();
        let parsed = parse_tlsroute(&tls);
        assert_eq!(parsed.namespace.as_ref(), "default");
        assert_eq!(parsed.name.as_ref(), "");
        assert_eq!(parsed.generation, 0);
        assert!(parsed.hostnames.is_empty());
    }

    #[test]
    fn parse_udproute_state_basic() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
              generation: 4
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#;
        let route: UDPRoute = serde_yaml::from_str(yaml).unwrap();
        let state = parse_udproute_state(&route);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "udp-route");
        assert_eq!(state.generation, 4);
    }

    #[test]
    fn resolve_l4_backends_rejects_unsupported_kind() {
        let backend = ParsedBackendRef {
            group: None,
            kind: Some("ConfigMap".to_string()),
            namespace: None,
            name: "cfg".to_string(),
            port: None,
            weight: None,
        };
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends(&[backend], "default", "TCPRoute", &grant_index, 1);
        assert!(resolved_refs.is_some());
        assert!(backends.is_empty());
    }

    #[tokio::test]
    async fn resolve_l4_backends_async_rejects_unpermitted() {
        let backend = ParsedBackendRef {
            group: None,
            kind: None,
            namespace: Some("other".to_string()),
            name: "svc".to_string(),
            port: Some(80),
            weight: None,
        };
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let grant_index = GrantIndex::new(vec![]);
        let (backends, resolved_refs) =
            resolve_l4_backends_async(&client, &[backend], "default", "TCPRoute", &grant_index, 1)
                .await;
        assert!(resolved_refs.is_some());
        assert!(backends.is_empty());
    }

    #[test]
    fn resolve_l4_parent_ref_unsupported_group_kind() {
        let parsed = ParsedParentRef {
            group: "".to_string(),
            kind: "Service".to_string(),
            namespace: None,
            name: "svc".to_string(),
            section_name: None,
            port: None,
        };
        let (_, conditions) = resolve_l4_parent_ref(
            &parsed,
            "default",
            1,
            &[],
            "TCPRoute",
            &["TCP"],
            &[],
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(conditions[0].reason, "UnsupportedValue");
    }

    #[test]
    fn resolve_l4_parent_ref_gateway_not_found() {
        let parsed = ParsedParentRef {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "missing".to_string(),
            section_name: None,
            port: None,
        };
        let (_, conditions) = resolve_l4_parent_ref(
            &parsed,
            "default",
            1,
            &[],
            "TCPRoute",
            &["TCP"],
            &[],
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(conditions[0].reason, "NoMatchingParent");
    }

    #[test]
    fn resolve_l4_parent_ref_listener_not_found() {
        let parsed = ParsedParentRef {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "gw-1".to_string(),
            section_name: Some("missing".to_string()),
            port: None,
        };
        let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
        let (_, conditions) = resolve_l4_parent_ref(
            &parsed,
            "default",
            1,
            &[],
            "TCPRoute",
            &["TCP"],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(conditions[0].reason, "NoMatchingParent");
    }

    #[test]
    fn resolve_l4_parent_ref_port_no_match() {
        let parsed = ParsedParentRef {
            group: "gateway.networking.k8s.io".to_string(),
            kind: "Gateway".to_string(),
            namespace: None,
            name: "gw-1".to_string(),
            section_name: None,
            port: Some(9999),
        };
        let gateways = vec![gw_with_tcp_listener("default", "gw-1", "tcp", 8080)];
        let (_, conditions) = resolve_l4_parent_ref(
            &parsed,
            "default",
            1,
            &[],
            "TCPRoute",
            &["TCP"],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert_eq!(conditions[0].reason, "NoMatchingParent");
    }

    #[test]
    fn listener_namespace_blocks_l4_route() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: route-ns
            spec:
              parentRefs:
                - name: gw-1
                  namespace: gw-ns
              rules: []
        "#,
        )
        .unwrap();
        let gateways = vec![gw_with_tcp_listener("gw-ns", "gw-1", "tcp", 8080)];
        let reconciled = reconcile_tcproutes(
            &[route],
            &gateways,
            &empty_namespace_labels(),
            &empty_listener_allowed(),
        );
        assert!(!reconciled[0].programmed);
    }

    #[test]
    fn build_status_parents_false_condition() {
        let parent_status = L4ParentStatus {
            parent_ref: ParentRef {
                namespace: Some(Arc::from("default")),
                name: Arc::from("gw-1"),
                section_name: None,
            },
            conditions: vec![StatusCondition {
                condition_type: ConditionType::ResolvedRefs,
                status: ConditionStatus::False,
                reason: "RefNotPermitted".to_string(),
                message: "no".to_string(),
                observed_generation: 2,
            }],
        };
        let parents = build_status_parents(&[parent_status]);
        let conditions = parents[0].get("conditions").unwrap().as_array().unwrap();
        assert_eq!(
            conditions[0].get("type").and_then(|v| v.as_str()),
            Some("ResolvedRefs")
        );
        assert_eq!(
            conditions[0].get("status").and_then(|v| v.as_str()),
            Some("False")
        );
        assert!(!parents[0]
            .get("parentRef")
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("sectionName"));
    }

    #[tokio::test]
    async fn patch_l4_status_skips_when_unchanged() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs: []
              rules: []
            status:
              parents: []
        "#,
        )
        .unwrap();
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let ctx = L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        };
        patch_l4_status(
            &route,
            &ctx,
            &[],
            "gateway.networking.k8s.io/v1alpha2",
            "TCPRoute",
        )
        .await;
    }

    #[tokio::test]
    async fn reconcile_udproute_as_leader_patches_status() {
        let route: UDPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
        )
        .unwrap();

        let gateway: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: udp
                  protocol: UDP
                  port: 53
        "#,
        )
        .unwrap();
        let client = mock_l4_reconcile_client(gateway);
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });

        let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_tlsroute_as_leader_patches_status() {
        let route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();

        let gateway = sample_gateway_with_tls_listener();
        let client = mock_l4_reconcile_client(gateway);
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });

        let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_udproute_context_failure_returns_requeue() {
        let route: UDPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
        )
        .unwrap();

        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_tlsroute_context_failure_returns_requeue() {
        let route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
        )
        .unwrap();

        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn run_l4_controllers_spawn_handles() {
        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let is_leader = Arc::new(AtomicBool::new(false));
        let tcp = run_tcproute_controller(client.clone(), Arc::clone(&is_leader));
        let udp = run_udproute_controller(client.clone(), Arc::clone(&is_leader));
        let tls = run_tlsroute_controller(client, Arc::clone(&is_leader));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tcp.abort();
        udp.abort();
        tls.abort();
    }

    fn sample_gateway_with_tcp_listener() -> Gateway {
        serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: tcp
                  protocol: TCP
                  port: 8080
        "#,
        )
        .unwrap()
    }

    fn sample_gateway_with_tls_listener() -> Gateway {
        serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: tls
                  protocol: TLS
                  port: 443
                  hostname: "*.example.com"
        "#,
        )
        .unwrap()
    }

    fn mock_l4_reconcile_client(gateway: Gateway) -> kube::Client {
        let gateway_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayList",
            "items": [serde_json::to_value(&gateway).unwrap()]
        });
        let grant_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ReferenceGrantList",
            "items": []
        });
        let namespace_list = serde_json::json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "items": [{"metadata":{"name":"default"}}]
        });

        kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path();
                let body = if path.contains("/namespaces") {
                    namespace_list.clone()
                } else if path.contains("/referencegrants") {
                    grant_list.clone()
                } else {
                    gateway_list.clone()
                };
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn reconcile_tcproute_returns_requeue_action() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
        )
        .unwrap();

        let gateway = sample_gateway_with_tcp_listener();
        let client = mock_l4_reconcile_client(gateway);
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_udproute_returns_requeue_action() {
        let route: UDPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: UDPRoute
            metadata:
              name: udp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 53
        "#,
        )
        .unwrap();

        let gateway: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw-1
              namespace: default
            spec:
              gatewayClassName: sunbeam
              listeners:
                - name: udp
                  protocol: UDP
                  port: 53
        "#,
        )
        .unwrap();
        let client = mock_l4_reconcile_client(gateway);
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_udproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_tlsroute_returns_requeue_action() {
        let route: TLSRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: TLSRoute
            metadata:
              name: tls-route
              namespace: default
            spec:
              hostnames:
                - foo.example.com
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 443
        "#,
        )
        .unwrap();

        let gateway = sample_gateway_with_tls_listener();
        let client = mock_l4_reconcile_client(gateway);
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_tlsroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_tcproute_with_leader_patches_status() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs:
                    - name: svc
                      port: 8080
        "#,
        )
        .unwrap();

        let gateway = sample_gateway_with_tcp_listener();
        let gateway_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GatewayList",
            "items": [serde_json::to_value(&gateway).unwrap()]
        });
        let grant_list = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ReferenceGrantList",
            "items": []
        });
        let namespace_list = serde_json::json!({
            "apiVersion": "v1",
            "kind": "NamespaceList",
            "items": [{"metadata":{"name":"default"}}]
        });

        let client = kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path();
                let body = if path.contains("/namespaces") {
                    namespace_list.clone()
                } else if path.contains("/referencegrants") {
                    grant_list.clone()
                } else if path.contains("/status") {
                    serde_json::json!({"status": {"parents": []}})
                } else {
                    gateway_list.clone()
                };
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });

        let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_l4_returns_requeue_on_context_failure() {
        let route: TCPRoute = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1alpha2
            kind: TCPRoute
            metadata:
              name: tcp-route
              namespace: default
            spec:
              parentRefs:
                - name: gw-1
              rules:
                - backendRefs: []
        "#,
        )
        .unwrap();

        let client = kube::Client::new(
            tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .body(kube::client::Body::empty())
                        .unwrap(),
                )
            }),
            "default",
        );
        let ctx = Arc::new(L4RouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });

        let action = reconcile_tcproute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn error_policies_return_requeue() {
        let err = kube::Error::Api(Box::new(kube::core::Status {
            status: Some(kube::core::response::StatusSummary::Failure),
            message: "boom".to_string(),
            reason: "InternalError".to_string(),
            code: 500,
            details: None,
            metadata: None,
        }));
        let ctx = Arc::new(L4RouteContext {
            client: kube::Client::new(
                tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .body(kube::client::Body::empty())
                            .unwrap(),
                    )
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        assert_eq!(
            error_policy_tcproute(Arc::new(TCPRoute::default()), &err, Arc::clone(&ctx)),
            Action::requeue(Duration::from_secs(5))
        );
        assert_eq!(
            error_policy_udproute(Arc::new(UDPRoute::default()), &err, Arc::clone(&ctx)),
            Action::requeue(Duration::from_secs(5))
        );
        assert_eq!(
            error_policy_tlsroute(Arc::new(TLSRoute::default()), &err, Arc::clone(&ctx)),
            Action::requeue(Duration::from_secs(5))
        );
    }

    fn l4_crd_available_client(status: u16) -> kube::Client {
        kube::Client::new(
            tower::service_fn(move |_req: http::Request<kube::client::Body>| {
                let body = if status == 404 {
                    serde_json::json!({
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "code": 404,
                        "message": "not found"
                    })
                } else {
                    serde_json::json!({
                        "apiVersion": "gateway.networking.k8s.io/v1alpha2",
                        "kind": "TCPRouteList",
                        "items": []
                    })
                };
                async move {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn l4_crd_available_true_when_list_succeeds() {
        let client = l4_crd_available_client(200);
        assert!(l4_crd_available::<TCPRoute>(&client, "TCPRoute").await);
    }

    #[tokio::test]
    async fn l4_crd_available_false_when_not_found() {
        let client = l4_crd_available_client(404);
        assert!(!l4_crd_available::<TCPRoute>(&client, "TCPRoute").await);
    }

    #[tokio::test]
    async fn maybe_run_tcproute_controller_returns_handle_when_crd_installed() {
        let client = l4_crd_available_client(200);
        let is_leader = Arc::new(AtomicBool::new(false));
        let handle = maybe_run_tcproute_controller(client, is_leader)
            .await
            .expect("controller handle");
        handle.abort();
    }

    #[tokio::test]
    async fn maybe_run_tcproute_controller_returns_none_when_crd_missing() {
        let client = l4_crd_available_client(404);
        let is_leader = Arc::new(AtomicBool::new(false));
        assert!(maybe_run_tcproute_controller(client, is_leader)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn maybe_run_udproute_controller_returns_none_when_crd_missing() {
        let client = l4_crd_available_client(404);
        let is_leader = Arc::new(AtomicBool::new(false));
        assert!(maybe_run_udproute_controller(client, is_leader)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn maybe_run_tlsroute_controller_returns_none_when_crd_missing() {
        let client = l4_crd_available_client(404);
        let is_leader = Arc::new(AtomicBool::new(false));
        assert!(maybe_run_tlsroute_controller(client, is_leader)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn l4_route_context_clone_smoke() {
        let ctx = L4RouteContext {
            client: kube::Client::new(
                tower::service_fn(|_req: http::Request<kube::client::Body>| async {
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(200)
                            .body(kube::client::Body::empty())
                            .unwrap(),
                    )
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        };
        let cloned = ctx.clone();
        assert!(!cloned.is_leader.load(Ordering::Relaxed));
    }
}
