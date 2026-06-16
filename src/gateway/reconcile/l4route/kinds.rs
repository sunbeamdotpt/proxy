// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::api::{TCPRoute, TLSRoute, UDPRoute};
use crate::gateway::model::{HostnameMatch, TCPRouteState, TLSRouteState, UDPRouteState};
use crate::gateway::reconcile::l4route::model::L4RouteKind;
use crate::gateway::reconcile::l4route::model::{
    into_parsed_backend, ParsedBackendRef, ParsedL4Route,
};
use gateway_api::experimental::tcproutes::{
    TcpRouteParentRefs, TcpRouteRules, TcpRouteRulesBackendRefs,
};
use gateway_api::experimental::udproutes::{
    UdpRouteParentRefs, UdpRouteRules, UdpRouteRulesBackendRefs,
};
use gateway_api::tlsroutes::{TlsRouteParentRefs, TlsRouteRules, TlsRouteRulesBackendRefs};
use std::sync::Arc;

pub fn parse_tcproute(route: &TCPRoute) -> ParsedL4Route {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let parent_refs = parse_tcp_parent_refs(route);
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

pub fn parse_udproute(route: &UDPRoute) -> ParsedL4Route {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let parent_refs = parse_udp_parent_refs(route);
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

pub fn parse_tlsroute(route: &TLSRoute) -> ParsedL4Route {
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

    let parent_refs = parse_tls_parent_refs(route);
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

crate::impl_parse_parent_refs!(parse_tcp_parent_refs, TCPRoute, TcpRouteParentRefs);
crate::impl_parse_parent_refs!(parse_udp_parent_refs, UDPRoute, UdpRouteParentRefs);
crate::impl_parse_parent_refs!(parse_tls_parent_refs, TLSRoute, TlsRouteParentRefs);

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

impl L4RouteKind for TCPRoute {
    fn kind_str() -> &'static str {
        "TCPRoute"
    }
    fn status_api_version() -> &'static str {
        "gateway.networking.k8s.io/v1alpha2"
    }
    fn protocols() -> &'static [&'static str] {
        &["TCP"]
    }
    fn parse(route: &Self) -> ParsedL4Route {
        parse_tcproute(route)
    }
}

impl L4RouteKind for UDPRoute {
    fn kind_str() -> &'static str {
        "UDPRoute"
    }
    fn status_api_version() -> &'static str {
        "gateway.networking.k8s.io/v1alpha2"
    }
    fn protocols() -> &'static [&'static str] {
        &["UDP"]
    }
    fn parse(route: &Self) -> ParsedL4Route {
        parse_udproute(route)
    }
}

impl L4RouteKind for TLSRoute {
    fn kind_str() -> &'static str {
        "TLSRoute"
    }
    fn status_api_version() -> &'static str {
        "gateway.networking.k8s.io/v1"
    }
    fn protocols() -> &'static [&'static str] {
        &["TLS"]
    }
    fn parse(route: &Self) -> ParsedL4Route {
        parse_tlsroute(route)
    }
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
