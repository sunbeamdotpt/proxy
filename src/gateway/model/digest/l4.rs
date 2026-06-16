// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::common::{
    encode_i64, encode_parent_refs, encode_str, encode_u32, encode_weighted_backend,
};
use super::{TCPRouteState, TLSRouteState, UDPRouteState};

pub(crate) fn encode_tcp_route(buf: &mut Vec<u8>, r: &TCPRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);
    encode_parent_refs(buf, &r.parent_refs);
    encode_u32(buf, r.backends.len() as u32);
    for b in &r.backends {
        encode_weighted_backend(buf, b);
    }
    buf.push(if r.programmed { 0x01 } else { 0x00 });
}

pub(crate) fn encode_udp_route(buf: &mut Vec<u8>, r: &UDPRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);
    encode_parent_refs(buf, &r.parent_refs);
    encode_u32(buf, r.backends.len() as u32);
    for b in &r.backends {
        encode_weighted_backend(buf, b);
    }
    buf.push(if r.programmed { 0x01 } else { 0x00 });
}

pub(crate) fn encode_tls_route(buf: &mut Vec<u8>, r: &TLSRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);
    encode_parent_refs(buf, &r.parent_refs);

    let mut hostnames = r.hostnames.clone();
    hostnames.sort_by(|a, b| {
        use super::super::routing::HostnameMatch;
        match (a, b) {
            (HostnameMatch::Exact(a), HostnameMatch::Exact(b)) => a.cmp(b),
            (HostnameMatch::Exact(_), _) => std::cmp::Ordering::Less,
            (HostnameMatch::Wildcard(a), HostnameMatch::Wildcard(b)) => a.cmp(b),
            (HostnameMatch::Wildcard(_), HostnameMatch::Exact(_)) => std::cmp::Ordering::Greater,
            (HostnameMatch::Wildcard(_), HostnameMatch::Any) => std::cmp::Ordering::Less,
            (HostnameMatch::Any, HostnameMatch::Any) => std::cmp::Ordering::Equal,
            (HostnameMatch::Any, _) => std::cmp::Ordering::Greater,
        }
    });
    encode_u32(buf, hostnames.len() as u32);
    for h in &hostnames {
        match h {
            super::super::routing::HostnameMatch::Exact(s) => {
                buf.push(0x00);
                encode_str(buf, s);
            }
            super::super::routing::HostnameMatch::Wildcard(s) => {
                buf.push(0x01);
                encode_str(buf, s);
            }
            super::super::routing::HostnameMatch::Any => {
                buf.push(0x02);
            }
        }
    }

    encode_u32(buf, r.backends.len() as u32);
    for b in &r.backends {
        encode_weighted_backend(buf, b);
    }
    buf.push(if r.programmed { 0x01 } else { 0x00 });
}

pub(crate) fn encode_tcp_routes(buf: &mut Vec<u8>, routes: &[TCPRouteState]) {
    let mut routes = routes.to_vec();
    routes.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, routes.len() as u32);
    for r in &routes {
        encode_tcp_route(buf, r);
    }
}

pub(crate) fn encode_udp_routes(buf: &mut Vec<u8>, routes: &[UDPRouteState]) {
    let mut routes = routes.to_vec();
    routes.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, routes.len() as u32);
    for r in &routes {
        encode_udp_route(buf, r);
    }
}

pub(crate) fn encode_tls_routes(buf: &mut Vec<u8>, routes: &[TLSRouteState]) {
    let mut routes = routes.to_vec();
    routes.sort_by(|a, b| {
        a.namespace
            .cmp(&b.namespace)
            .then_with(|| a.name.cmp(&b.name))
    });
    encode_u32(buf, routes.len() as u32);
    for r in &routes {
        encode_tls_route(buf, r);
    }
}
