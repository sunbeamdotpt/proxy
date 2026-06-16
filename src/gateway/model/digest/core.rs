// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::common::{
    encode_allowed_routes_map, encode_i64, encode_listener_set, encode_namespace_labels,
    encode_parent_ref, encode_reference_grant, encode_str, encode_u16, encode_u32,
};
use super::http::encode_http_route;
use super::l4::{encode_tcp_routes, encode_tls_routes, encode_udp_routes};
use super::{GatewayState, ListenerState, ReconciledView, RouteState};

/// Compute a stable, deterministic [`blake3::Hash`] for a [`ReconciledView`].
///
/// The encoding rules are:
///
/// 1. All variable-length data is prefixed with its length as a big-endian `u32`.
/// 2. All integers are written in big-endian.
/// 3. Booleans are written as a single byte (`0x00` or `0x01`).
/// 4. All collections are sorted by their canonical key before being hashed,
///    so reordering of otherwise-equivalent inputs does not change the digest.
/// 5. `Option<T>` is encoded as a presence byte followed by the value (if present).
/// 6. `Arc<str>` is encoded as length-prefixed UTF-8 bytes.
pub fn compute_digest(view: &ReconciledView) -> blake3::Hash {
    let mut buf = Vec::with_capacity(4096);
    encode_view(&mut buf, view);
    blake3::hash(&buf)
}

fn encode_view(buf: &mut Vec<u8>, view: &ReconciledView) {
    // Gateways — sorted by (namespace, name) for stability.
    let mut gateways = view.gateways.clone();
    gateways.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, gateways.len() as u32);
    for g in &gateways {
        encode_gateway(buf, g);
    }

    // ListenerSets — sorted by (namespace, name).
    let mut listener_sets = view.listener_sets.clone();
    listener_sets.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, listener_sets.len() as u32);
    for s in &listener_sets {
        encode_listener_set(buf, s);
    }

    // Routes — sorted by (kind, namespace, name).
    let mut routes = view.routes.clone();
    routes.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, routes.len() as u32);
    for r in &routes {
        encode_route(buf, r);
    }

    // HTTP routes — sorted by (namespace, name).
    let mut http_routes = view.http_routes.clone();
    http_routes.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, http_routes.len() as u32);
    for r in &http_routes {
        encode_http_route(buf, r);
    }

    // TCP/UDP/TLS routes — sorted by (namespace, name).
    encode_tcp_routes(buf, &view.tcp_routes);
    encode_udp_routes(buf, &view.udp_routes);
    encode_tls_routes(buf, &view.tls_routes);

    // ReferenceGrants — sorted by (namespace, name).
    let mut grants = view.reference_grants.clone();
    grants.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, grants.len() as u32);
    for g in &grants {
        encode_reference_grant(buf, g);
    }

    // Namespace labels used by allowedRoutes selectors.
    encode_namespace_labels(buf, &view.namespace_labels);

    // Allowed routes configured on Gateway and ListenerSet listeners.
    encode_allowed_routes_map(buf, &view.listener_allowed);
    encode_allowed_routes_map(buf, &view.listener_set_allowed);
}

fn encode_gateway(buf: &mut Vec<u8>, g: &GatewayState) {
    encode_str(buf, &g.namespace);
    encode_str(buf, &g.name);
    encode_i64(buf, g.generation);

    let mut listeners = g.listeners.clone();
    listeners.sort_by(|a, b| a.name.cmp(&b.name));
    encode_u32(buf, listeners.len() as u32);
    for l in &listeners {
        encode_listener(buf, l);
    }
}

pub(crate) fn encode_listener(buf: &mut Vec<u8>, l: &ListenerState) {
    encode_str(buf, &l.name);
    encode_str(buf, &l.protocol);
    encode_u16(buf, l.port);
}

fn encode_route(buf: &mut Vec<u8>, r: &RouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_str(buf, &r.kind);
    encode_i64(buf, r.generation);

    let mut refs = r.parent_refs.clone();
    refs.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.section_name.cmp(&b.section_name))
    });
    encode_u32(buf, refs.len() as u32);
    for p in &refs {
        encode_parent_ref(buf, p);
    }
}
