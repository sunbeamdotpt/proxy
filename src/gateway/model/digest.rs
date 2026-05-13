// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Stable canonical digest of a [`ReconciledView`].

use super::view::{
    GatewayState, GrantSubject, ListenerState, ParentRef, ReferenceGrantState, ReconciledView,
    RouteState,
};

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

fn encode_listener(buf: &mut Vec<u8>, l: &ListenerState) {
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

fn encode_parent_ref(buf: &mut Vec<u8>, p: &ParentRef) {
    encode_option_str(buf, &p.namespace);
    encode_str(buf, &p.name);
    encode_option_str(buf, &p.section_name);
}

fn encode_reference_grant(buf: &mut Vec<u8>, g: &ReferenceGrantState) {
    encode_str(buf, &g.namespace);
    encode_str(buf, &g.name);
    encode_i64(buf, g.generation);

    let mut from = g.from.clone();
    from.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, from.len() as u32);
    for s in &from {
        encode_grant_subject(buf, s);
    }

    let mut to = g.to.clone();
    to.sort_by(|a, b| {
        a.group
            .cmp(&b.group)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, to.len() as u32);
    for s in &to {
        encode_grant_subject(buf, s);
    }
}

fn encode_grant_subject(buf: &mut Vec<u8>, s: &GrantSubject) {
    encode_str(buf, &s.group);
    encode_str(buf, &s.kind);
    encode_option_str(buf, &s.namespace);
    encode_option_str(buf, &s.name);
}

// ---------------------------------------------------------------------------
// Primitive encoders — fixed width, big endian.
// ---------------------------------------------------------------------------

fn encode_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn encode_option_str(buf: &mut Vec<u8>, opt: &Option<impl AsRef<str>>) {
    match opt {
        None => buf.push(0x00),
        Some(s) => {
            buf.push(0x01);
            encode_str(buf, s.as_ref());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn arc(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    fn sample_view() -> ReconciledView {
        ReconciledView {
            gateways: vec![GatewayState {
                namespace: arc("default"),
                name: arc("gw-1"),
                generation: 1,
                listeners: vec![
                    ListenerState {
                        name: arc("http"),
                        protocol: arc("HTTP"),
                        port: 80,
                    },
                    ListenerState {
                        name: arc("https"),
                        protocol: arc("HTTPS"),
                        port: 443,
                    },
                ],
            }],
            routes: vec![RouteState {
                namespace: arc("default"),
                name: arc("route-a"),
                kind: arc("HTTPRoute"),
                generation: 2,
                parent_refs: vec![ParentRef {
                    namespace: Some(arc("default")),
                    name: arc("gw-1"),
                    section_name: Some(arc("http")),
                }],
            }],
            reference_grants: vec![ReferenceGrantState {
                namespace: arc("default"),
                name: arc("grant-1"),
                generation: 1,
                from: vec![GrantSubject {
                    group: arc("gateway.networking.k8s.io"),
                    kind: arc("HTTPRoute"),
                    namespace: Some(arc("default")),
                    name: None,
                }],
                to: vec![GrantSubject {
                    group: arc(""),
                    kind: arc("Service"),
                    namespace: Some(arc("default")),
                    name: Some(arc("svc-1")),
                }],
            }],
        }
    }

    // (a) Equivalent inputs — including different collection orderings —
    //     must produce identical hashes.
    #[test]
    fn equivalent_inputs_same_hash() {
        let base = sample_view();
        let h1 = compute_digest(&base);

        // Same data, re-ordered listeners.
        let mut reordered = base.clone();
        reordered.gateways[0].listeners.reverse();
        let h2 = compute_digest(&reordered);
        assert_eq!(h1, h2, "listener reordering changed the digest");

        // Same data, re-ordered routes.
        let mut reordered_routes = base.clone();
        reordered_routes.routes.push(RouteState {
            namespace: arc("default"),
            name: arc("route-b"),
            kind: arc("HTTPRoute"),
            generation: 1,
            parent_refs: vec![],
        });
        reordered_routes.routes.swap(0, 1);
        let h3 = compute_digest(&reordered_routes);
        // Build the same set in a different order.
        let mut ordered_routes = base.clone();
        ordered_routes.routes.push(RouteState {
            namespace: arc("default"),
            name: arc("route-b"),
            kind: arc("HTTPRoute"),
            generation: 1,
            parent_refs: vec![],
        });
        let h4 = compute_digest(&ordered_routes);
        assert_eq!(h3, h4, "route reordering changed the digest");
    }

    // (b) Non-equivalent inputs must produce different hashes.
    #[test]
    fn non_equivalent_inputs_different_hash() {
        let base = sample_view();
        let h1 = compute_digest(&base);

        let mut changed = base.clone();
        changed.gateways[0].generation = 42;
        let h2 = compute_digest(&changed);
        assert_ne!(h1, h2, "generation change did not alter digest");

        let mut changed = base.clone();
        changed.routes[0].name = arc("route-b");
        let h3 = compute_digest(&changed);
        assert_ne!(h1, h3, "route name change did not alter digest");

        let mut changed = base.clone();
        changed.reference_grants.clear();
        let h4 = compute_digest(&changed);
        assert_ne!(h1, h4, "removing grants did not alter digest");
    }

    // Extra stability test: two independently constructed identical views.
    #[test]
    fn independent_construction_same_hash() {
        let a = sample_view();
        let b = sample_view();
        assert_eq!(compute_digest(&a), compute_digest(&b));
    }

    // Verify that different structurally-equivalent strings still hash
    // differently (i.e. we aren't accidentally normalising away data).
    #[test]
    fn string_content_matters() {
        let mut a = sample_view();
        a.gateways[0].name = arc("gw-1");

        let mut b = sample_view();
        b.gateways[0].name = arc("gw-2");

        assert_ne!(compute_digest(&a), compute_digest(&b));
    }
}
