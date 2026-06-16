// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::core::encode_listener;
use super::{
    AllowedRoutes, GrantSubject, ListenerSetState, NamespaceFrom, ParentRef, ReferenceGrantState,
    RouteGroupKind, RouteNamespaces,
};

pub(crate) fn encode_parent_ref(buf: &mut Vec<u8>, p: &ParentRef) {
    encode_option_str(buf, &p.namespace);
    encode_str(buf, &p.name);
    encode_option_str(buf, &p.section_name);
}

pub(crate) fn encode_reference_grant(buf: &mut Vec<u8>, g: &ReferenceGrantState) {
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

pub(crate) fn encode_grant_subject(buf: &mut Vec<u8>, s: &GrantSubject) {
    encode_str(buf, &s.group);
    encode_str(buf, &s.kind);
    encode_option_str(buf, &s.namespace);
    encode_option_str(buf, &s.name);
}

pub(crate) fn encode_listener_set(buf: &mut Vec<u8>, s: &ListenerSetState) {
    encode_str(buf, &s.namespace);
    encode_str(buf, &s.name);
    encode_i64(buf, s.generation);

    let mut listeners = s.listeners.clone();
    listeners.sort_by(|a, b| a.name.cmp(&b.name));
    encode_u32(buf, listeners.len() as u32);
    for l in &listeners {
        encode_listener(buf, l);
    }

    let mut conflicts: Vec<_> = s.conflicts.iter().collect();
    conflicts.sort_by(|a, b| a.0.cmp(b.0));
    encode_u32(buf, conflicts.len() as u32);
    for (name, reason) in &conflicts {
        encode_str(buf, name);
        encode_str(buf, reason);
    }

    buf.push(if s.accepted { 0x01 } else { 0x00 });
    buf.push(if s.programmed { 0x01 } else { 0x00 });
    encode_str(buf, &s.reason);
}

pub(crate) fn encode_namespace_labels(
    buf: &mut Vec<u8>,
    labels: &super::super::view::NamespaceLabels,
) {
    encode_u32(buf, labels.len() as u32);
    for (ns, inner) in labels {
        encode_str(buf, ns);
        encode_u32(buf, inner.len() as u32);
        for (k, v) in inner {
            encode_str(buf, k);
            encode_str(buf, v);
        }
    }
}

pub(crate) fn encode_allowed_routes_map(
    buf: &mut Vec<u8>,
    map: &super::super::view::ListenerAllowedMap,
) {
    encode_u32(buf, map.len() as u32);
    for ((ns, name, listener), allowed) in map {
        encode_str(buf, ns);
        encode_str(buf, name);
        encode_str(buf, listener);
        encode_allowed_routes(buf, allowed);
    }
}

pub(crate) fn encode_allowed_routes(buf: &mut Vec<u8>, allowed: &AllowedRoutes) {
    let mut kinds = allowed.kinds.clone();
    kinds.sort_by(|a, b| a.group.cmp(&b.group).then_with(|| a.kind.cmp(&b.kind)));
    encode_u32(buf, kinds.len() as u32);
    for k in &kinds {
        encode_route_group_kind(buf, k);
    }
    encode_route_namespaces(buf, &allowed.namespaces);
}

pub(crate) fn encode_route_group_kind(buf: &mut Vec<u8>, k: &RouteGroupKind) {
    encode_str(buf, &k.group);
    encode_str(buf, &k.kind);
}

pub(crate) fn encode_route_namespaces(buf: &mut Vec<u8>, ns: &RouteNamespaces) {
    encode_namespace_from(buf, ns.from);
    if let Some(selector) = &ns.selector {
        buf.push(0x01);
        encode_u32(buf, selector.len() as u32);
        let mut pairs: Vec<_> = selector.iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        for (k, v) in pairs {
            encode_str(buf, k);
            encode_str(buf, v);
        }
    } else {
        buf.push(0x00);
    }
}

pub(crate) fn encode_namespace_from(buf: &mut Vec<u8>, from: NamespaceFrom) {
    buf.push(match from {
        NamespaceFrom::Same => 0x00,
        NamespaceFrom::All => 0x01,
        NamespaceFrom::Selector => 0x02,
        NamespaceFrom::None => 0x03,
    });
}

pub(crate) fn encode_parent_refs(buf: &mut Vec<u8>, refs: &[ParentRef]) {
    let mut refs = refs.to_vec();
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

// ---------------------------------------------------------------------------
// Primitive encoders — fixed width, big endian.
// ---------------------------------------------------------------------------

pub(crate) fn encode_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn encode_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn encode_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn encode_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

pub(crate) fn encode_option_str(buf: &mut Vec<u8>, opt: &Option<impl AsRef<str>>) {
    match opt {
        None => buf.push(0x00),
        Some(s) => {
            buf.push(0x01);
            encode_str(buf, s.as_ref());
        }
    }
}

pub(crate) fn encode_option_u16(buf: &mut Vec<u8>, opt: &Option<u16>) {
    match opt {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            encode_u16(buf, *v);
        }
    }
}

pub(crate) fn encode_option_i32(buf: &mut Vec<u8>, opt: &Option<i32>) {
    match opt {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
}

pub(crate) fn encode_weighted_backend(
    buf: &mut Vec<u8>,
    b: &super::super::routing::WeightedBackend,
) {
    encode_str(buf, &b.backend);
    encode_u32(buf, b.weight);
}
