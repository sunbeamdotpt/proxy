// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable canonical digest of a [`ReconciledView`].

use super::routing::{HTTPRouteState, TCPRouteState, TLSRouteState, UDPRouteState};
use super::view::{
    AllowedRoutes, GatewayState, GrantSubject, ListenerSetState, ListenerState, NamespaceFrom,
    ParentRef, ReconciledView, ReferenceGrantState, RouteGroupKind, RouteNamespaces, RouteState,
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

fn encode_http_route(buf: &mut Vec<u8>, r: &HTTPRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);

    let mut hostnames = r.hostnames.clone();
    hostnames.sort_by(|a, b| {
        use super::routing::HostnameMatch;
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
            super::routing::HostnameMatch::Exact(s) => {
                buf.push(0x00);
                encode_str(buf, s);
            }
            super::routing::HostnameMatch::Wildcard(s) => {
                buf.push(0x01);
                encode_str(buf, s);
            }
            super::routing::HostnameMatch::Any => {
                buf.push(0x02);
            }
        }
    }

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

    let mut rules = r.rules.clone();
    rules.sort_by(|a, b| {
        a.matches
            .len()
            .cmp(&b.matches.len())
            .then_with(|| a.backends.len().cmp(&b.backends.len()))
    });
    encode_u32(buf, rules.len() as u32);
    for rule in &rules {
        encode_http_route_rule(buf, rule);
    }
}

fn encode_http_route_rule(buf: &mut Vec<u8>, rule: &super::routing::HTTPRouteRule) {
    let mut matches = rule.matches.clone();
    matches.sort_by(|a, b| {
        use super::routing::PathMatch;
        let path_ord = match (a.path.as_ref(), b.path.as_ref()) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (Some(_), None) => std::cmp::Ordering::Greater,
            (Some(PathMatch::Exact(a)), Some(PathMatch::Exact(b))) => a.cmp(b),
            (Some(PathMatch::Exact(_)), _) => std::cmp::Ordering::Less,
            (Some(PathMatch::Prefix(a)), Some(PathMatch::Prefix(b))) => a.cmp(b),
            (Some(PathMatch::Prefix(_)), Some(PathMatch::Exact(_))) => std::cmp::Ordering::Greater,
            (Some(PathMatch::Prefix(_)), _) => std::cmp::Ordering::Less,
            (Some(PathMatch::Regex(a)), Some(PathMatch::Regex(b))) => a.cmp(b),
            (Some(PathMatch::Regex(_)), _) => std::cmp::Ordering::Greater,
        };
        path_ord
            .then_with(|| a.method.cmp(&b.method))
            .then_with(|| a.headers.len().cmp(&b.headers.len()))
            .then_with(|| a.query_params.len().cmp(&b.query_params.len()))
    });
    encode_u32(buf, matches.len() as u32);
    for m in &matches {
        encode_route_match(buf, m);
    }

    let mut backends = rule.backends.clone();
    backends.sort_by(|a, b| {
        a.backend
            .cmp(&b.backend)
            .then_with(|| a.weight.cmp(&b.weight))
    });
    encode_u32(buf, backends.len() as u32);
    for b in &backends {
        encode_weighted_backend(buf, b);
    }

    let mut filters = rule.filters.clone();
    filters.sort_by_key(route_filter_ord);
    encode_u32(buf, filters.len() as u32);
    for f in &filters {
        encode_route_filter(buf, f);
    }
}

fn route_filter_ord(f: &super::routing::RouteFilter) -> u8 {
    use super::routing::RouteFilter;
    match f {
        RouteFilter::RequestHeaderSet { .. } => 0,
        RouteFilter::RequestHeaderAdd { .. } => 1,
        RouteFilter::RequestHeaderRemove { .. } => 2,
        RouteFilter::ResponseHeaderSet { .. } => 3,
        RouteFilter::ResponseHeaderAdd { .. } => 4,
        RouteFilter::ResponseHeaderRemove { .. } => 5,
        RouteFilter::UrlRewrite { .. } => 6,
        RouteFilter::RequestRedirect { .. } => 7,
        RouteFilter::RequestMirror { .. } => 8,
        RouteFilter::Cors { .. } => 9,
    }
}

fn encode_route_match(buf: &mut Vec<u8>, m: &super::routing::RouteMatch) {
    encode_option_path_match(buf, &m.path);
    encode_option_str(buf, &m.method);

    let mut headers = m.headers.clone();
    headers.sort_by(|a, b| a.name.cmp(&b.name));
    encode_u32(buf, headers.len() as u32);
    for h in &headers {
        encode_header_match(buf, h);
    }

    let mut query_params = m.query_params.clone();
    query_params.sort_by(|a, b| a.name.cmp(&b.name));
    encode_u32(buf, query_params.len() as u32);
    for q in &query_params {
        encode_query_param_match(buf, q);
    }
}

fn encode_option_path_match(buf: &mut Vec<u8>, opt: &Option<super::routing::PathMatch>) {
    use super::routing::PathMatch;
    match opt {
        None => buf.push(0x00),
        Some(PathMatch::Exact(s)) => {
            buf.push(0x01);
            buf.push(0x00);
            encode_str(buf, s);
        }
        Some(PathMatch::Prefix(s)) => {
            buf.push(0x01);
            buf.push(0x01);
            encode_str(buf, s);
        }
        Some(PathMatch::Regex(s)) => {
            buf.push(0x01);
            buf.push(0x02);
            encode_str(buf, s);
        }
    }
}

fn encode_header_match(buf: &mut Vec<u8>, h: &super::routing::HeaderMatch) {
    encode_str(buf, &h.name);
    use super::routing::HeaderMatchValue;
    match &h.value {
        HeaderMatchValue::Exact(s) => {
            buf.push(0x00);
            encode_str(buf, s);
        }
        HeaderMatchValue::Regex(s) => {
            buf.push(0x01);
            encode_str(buf, s);
        }
        HeaderMatchValue::Present => buf.push(0x02),
        HeaderMatchValue::Absent => buf.push(0x03),
    }
}

fn encode_query_param_match(buf: &mut Vec<u8>, q: &super::routing::QueryParamMatch) {
    encode_str(buf, &q.name);
    use super::routing::QueryParamMatchValue;
    match &q.value {
        QueryParamMatchValue::Exact(s) => {
            buf.push(0x00);
            encode_str(buf, s);
        }
        QueryParamMatchValue::Regex(s) => {
            buf.push(0x01);
            encode_str(buf, s);
        }
    }
}

fn encode_weighted_backend(buf: &mut Vec<u8>, b: &super::routing::WeightedBackend) {
    encode_str(buf, &b.backend);
    encode_u32(buf, b.weight);
}

fn encode_route_filter(buf: &mut Vec<u8>, f: &super::routing::RouteFilter) {
    use super::routing::RouteFilter;
    match f {
        RouteFilter::RequestHeaderSet { name, value } => {
            buf.push(0x00);
            encode_str(buf, name);
            encode_str(buf, value);
        }
        RouteFilter::RequestHeaderAdd { name, value } => {
            buf.push(0x01);
            encode_str(buf, name);
            encode_str(buf, value);
        }
        RouteFilter::RequestHeaderRemove { name } => {
            buf.push(0x02);
            encode_str(buf, name);
        }
        RouteFilter::ResponseHeaderSet { name, value } => {
            buf.push(0x03);
            encode_str(buf, name);
            encode_str(buf, value);
        }
        RouteFilter::ResponseHeaderAdd { name, value } => {
            buf.push(0x04);
            encode_str(buf, name);
            encode_str(buf, value);
        }
        RouteFilter::ResponseHeaderRemove { name } => {
            buf.push(0x05);
            encode_str(buf, name);
        }
        RouteFilter::UrlRewrite { hostname, path } => {
            buf.push(0x06);
            encode_option_str(buf, hostname);
            encode_option_path_rewrite(buf, path);
        }
        RouteFilter::RequestRedirect {
            scheme,
            hostname,
            path,
            port,
            status_code,
        } => {
            buf.push(0x07);
            encode_option_str(buf, scheme);
            encode_option_str(buf, hostname);
            encode_option_path_rewrite(buf, path);
            encode_option_u16(buf, port);
            encode_u16(buf, *status_code);
        }
        RouteFilter::RequestMirror { backend, fraction } => {
            buf.push(0x08);
            encode_str(buf, backend);
            if let Some(f) = fraction {
                buf.extend_from_slice(&f.numerator.to_be_bytes());
                buf.extend_from_slice(&f.denominator.to_be_bytes());
            }
        }
        RouteFilter::Cors {
            allow_origins,
            allow_methods,
            allow_headers,
            expose_headers,
            max_age,
            allow_credentials,
        } => {
            buf.push(0x09);
            encode_u32(buf, allow_origins.len() as u32);
            for o in allow_origins {
                encode_str(buf, o);
            }
            encode_u32(buf, allow_methods.len() as u32);
            for m in allow_methods {
                encode_str(buf, m);
            }
            encode_u32(buf, allow_headers.len() as u32);
            for h in allow_headers {
                encode_str(buf, h);
            }
            encode_u32(buf, expose_headers.len() as u32);
            for h in expose_headers {
                encode_str(buf, h);
            }
            encode_option_i32(buf, max_age);
            buf.push(if *allow_credentials { 1 } else { 0 });
        }
    }
}

fn encode_path_rewrite(buf: &mut Vec<u8>, p: &super::routing::PathRewrite) {
    use super::routing::PathRewrite;
    match p {
        PathRewrite::FullReplace(s) => {
            buf.push(0x00);
            encode_str(buf, s);
        }
        PathRewrite::PrefixReplace {
            prefix,
            replacement,
        } => {
            buf.push(0x01);
            encode_str(buf, prefix);
            encode_str(buf, replacement);
        }
    }
}

fn encode_option_path_rewrite(buf: &mut Vec<u8>, opt: &Option<super::routing::PathRewrite>) {
    match opt {
        None => buf.push(0x00),
        Some(p) => {
            buf.push(0x01);
            encode_path_rewrite(buf, p);
        }
    }
}

fn encode_option_u16(buf: &mut Vec<u8>, opt: &Option<u16>) {
    match opt {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            encode_u16(buf, *v);
        }
    }
}

fn encode_option_i32(buf: &mut Vec<u8>, opt: &Option<i32>) {
    match opt {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            buf.extend_from_slice(&v.to_le_bytes());
        }
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

fn encode_listener_set(buf: &mut Vec<u8>, s: &ListenerSetState) {
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

fn encode_tcp_route(buf: &mut Vec<u8>, r: &TCPRouteState) {
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

fn encode_udp_route(buf: &mut Vec<u8>, r: &UDPRouteState) {
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

fn encode_tls_route(buf: &mut Vec<u8>, r: &TLSRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);
    encode_parent_refs(buf, &r.parent_refs);

    let mut hostnames = r.hostnames.clone();
    hostnames.sort_by(|a, b| {
        use super::routing::HostnameMatch;
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
            super::routing::HostnameMatch::Exact(s) => {
                buf.push(0x00);
                encode_str(buf, s);
            }
            super::routing::HostnameMatch::Wildcard(s) => {
                buf.push(0x01);
                encode_str(buf, s);
            }
            super::routing::HostnameMatch::Any => {
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

fn encode_tcp_routes(buf: &mut Vec<u8>, routes: &[TCPRouteState]) {
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

fn encode_udp_routes(buf: &mut Vec<u8>, routes: &[UDPRouteState]) {
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

fn encode_tls_routes(buf: &mut Vec<u8>, routes: &[TLSRouteState]) {
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

fn encode_namespace_labels(buf: &mut Vec<u8>, labels: &super::view::NamespaceLabels) {
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

fn encode_allowed_routes_map(buf: &mut Vec<u8>, map: &super::view::ListenerAllowedMap) {
    encode_u32(buf, map.len() as u32);
    for ((ns, name, listener), allowed) in map {
        encode_str(buf, ns);
        encode_str(buf, name);
        encode_str(buf, listener);
        encode_allowed_routes(buf, allowed);
    }
}

fn encode_allowed_routes(buf: &mut Vec<u8>, allowed: &AllowedRoutes) {
    let mut kinds = allowed.kinds.clone();
    kinds.sort_by(|a, b| a.group.cmp(&b.group).then_with(|| a.kind.cmp(&b.kind)));
    encode_u32(buf, kinds.len() as u32);
    for k in &kinds {
        encode_route_group_kind(buf, k);
    }
    encode_route_namespaces(buf, &allowed.namespaces);
}

fn encode_route_group_kind(buf: &mut Vec<u8>, k: &RouteGroupKind) {
    encode_str(buf, &k.group);
    encode_str(buf, &k.kind);
}

fn encode_route_namespaces(buf: &mut Vec<u8>, ns: &RouteNamespaces) {
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

fn encode_namespace_from(buf: &mut Vec<u8>, from: NamespaceFrom) {
    buf.push(match from {
        NamespaceFrom::Same => 0x00,
        NamespaceFrom::All => 0x01,
        NamespaceFrom::Selector => 0x02,
        NamespaceFrom::None => 0x03,
    });
}

fn encode_parent_refs(buf: &mut Vec<u8>, refs: &[ParentRef]) {
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
            listener_sets: vec![],
            gateways: vec![GatewayState {
                namespace: arc("default"),
                name: arc("gw-1"),
                generation: 1,
                listeners: vec![
                    ListenerState {
                        name: arc("http"),
                        protocol: arc("HTTP"),
                        port: 80,
                        hostname: None,
                        tls_mode: None,
        frontend_validation: None,
    },
                    ListenerState {
                        name: arc("https"),
                        protocol: arc("HTTPS"),
                        port: 443,
                        hostname: None,
                        tls_mode: None,
        frontend_validation: None,
    },
                ],
        backend_client_cert_id: None,
    }],
            routes: vec![RouteState {
                namespace: arc("default"),
                name: arc("route-a"),
                kind: arc("HTTPRoute"),
                generation: 2,
                parent_refs: vec![ParentRef {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("Gateway"),

                    namespace: Some(arc("default")),
                    name: arc("gw-1"),
                    section_name: Some(arc("http")),
                    port: None,
                }],
            }],
            http_routes: vec![],
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
            ..Default::default()
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

    use crate::gateway::model::routing::{
        HTTPRouteRule, HostnameMatch, PathMatch, RouteMatch, WeightedBackend,
    };

    fn view_with_http_routes(routes: Vec<HTTPRouteState>) -> ReconciledView {
        ReconciledView {
            http_routes: routes,
            ..Default::default()
        }
    }

    fn http_route(name: &str, hostnames: Vec<HostnameMatch>, generation: i64) -> HTTPRouteState {
        HTTPRouteState {
            namespace: arc("default"),
            name: arc(name),
            generation,
            hostnames,
            rules: vec![],
            parent_refs: vec![],
            programmed: true,
        }
    }

    #[test]
    fn http_route_hostname_changes_digest() {
        let a = view_with_http_routes(vec![http_route(
            "r1",
            vec![HostnameMatch::Exact(arc("a.example.com"))],
            1,
        )]);
        let b = view_with_http_routes(vec![http_route(
            "r1",
            vec![HostnameMatch::Exact(arc("b.example.com"))],
            1,
        )]);
        assert_ne!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_wildcard_and_exact_differ() {
        let a = view_with_http_routes(vec![http_route(
            "r1",
            vec![HostnameMatch::Exact(arc("example.com"))],
            1,
        )]);
        let b = view_with_http_routes(vec![http_route(
            "r1",
            vec![HostnameMatch::Wildcard(arc("example.com"))],
            1,
        )]);
        assert_ne!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_hostname_reordering_stable() {
        let mut a = view_with_http_routes(vec![http_route(
            "r1",
            vec![
                HostnameMatch::Exact(arc("z.example.com")),
                HostnameMatch::Exact(arc("a.example.com")),
                HostnameMatch::Wildcard(arc("w.example.com")),
            ],
            1,
        )]);
        let b = a.clone();
        a.http_routes[0].hostnames.swap(0, 1);
        assert_eq!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_generation_changes_digest() {
        let a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
        let b = view_with_http_routes(vec![http_route("r1", vec![], 2)]);
        assert_ne!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_parent_ref_changes_digest() {
        let mut a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
        a.http_routes[0].parent_refs.push(ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: arc("gw-1"),
            section_name: None,
            port: None,
        });
        let mut b = a.clone();
        b.http_routes[0].parent_refs[0].name = arc("gw-2");
        assert_ne!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_rules_change_digest() {
        let mut a = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
        a.http_routes[0].rules.push(HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Prefix(arc("/api"))),
                headers: vec![],
                query_params: vec![],
                method: Some(arc("GET")),
            }],
            backends: vec![WeightedBackend {
                backend: arc("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        });
        let b = view_with_http_routes(vec![http_route("r1", vec![], 1)]);
        assert_ne!(compute_digest(&a), compute_digest(&b));
    }

    use crate::gateway::model::routing::{
        HeaderMatch, HeaderMatchValue, PathRewrite, QueryParamMatch, QueryParamMatchValue,
        RouteFilter,
    };

    #[test]
    fn http_route_all_path_match_types() {
        let exact = HTTPRouteState {
            namespace: arc("default"),
            name: arc("exact"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Exact(arc("/e"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        };
        let prefix = HTTPRouteState {
            namespace: arc("default"),
            name: arc("prefix"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(arc("/p"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        };
        let regex = HTTPRouteState {
            namespace: arc("default"),
            name: arc("regex"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Regex(arc("^/r$"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        };
        let a = compute_digest(&view_with_http_routes(vec![exact]));
        let b = compute_digest(&view_with_http_routes(vec![prefix]));
        let c = compute_digest(&view_with_http_routes(vec![regex]));
        assert_ne!(a, b);
        assert_ne!(b, c);
    }

    #[test]
    fn http_route_header_and_query_matches_affect_digest() {
        let base = HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: None,
                    headers: vec![HeaderMatch {
                        name: arc("x-version"),
                        value: HeaderMatchValue::Exact(arc("v1")),
                    }],
                    query_params: vec![QueryParamMatch {
                        name: arc("debug"),
                        value: QueryParamMatchValue::Exact(arc("1")),
                    }],
                    method: None,
                }],
                backends: vec![],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        };
        let mut changed = base.clone();
        changed.rules[0].matches[0].headers[0].value = HeaderMatchValue::Present;
        assert_ne!(
            compute_digest(&view_with_http_routes(vec![base])),
            compute_digest(&view_with_http_routes(vec![changed]))
        );
    }

    #[test]
    fn http_route_all_filter_types_change_digest() {
        fn route_with_filter(filter: RouteFilter) -> ReconciledView {
            view_with_http_routes(vec![HTTPRouteState {
                namespace: arc("default"),
                name: arc("r1"),
                generation: 1,
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![],
                    backends: vec![],
                    filters: vec![filter],
                }],
                parent_refs: vec![],
                programmed: true,
            }])
        }

        let filters = vec![
            RouteFilter::RequestHeaderSet {
                name: arc("X-In"),
                value: arc("in"),
            },
            RouteFilter::RequestHeaderAdd {
                name: arc("X-In-Add"),
                value: arc("in-add"),
            },
            RouteFilter::RequestHeaderRemove { name: arc("X-Old") },
            RouteFilter::ResponseHeaderSet {
                name: arc("X-Out"),
                value: arc("out"),
            },
            RouteFilter::ResponseHeaderAdd {
                name: arc("X-Out-Add"),
                value: arc("out-add"),
            },
            RouteFilter::ResponseHeaderRemove { name: arc("X-Old") },
            RouteFilter::UrlRewrite {
                hostname: None,
                path: Some(PathRewrite::PrefixReplace {
                    prefix: arc("/api"),
                    replacement: arc("/v2"),
                }),
            },
            RouteFilter::UrlRewrite {
                hostname: Some(arc("rewrite.example.com")),
                path: Some(PathRewrite::FullReplace(arc("/new"))),
            },
            RouteFilter::RequestRedirect {
                scheme: Some(arc("https")),
                hostname: Some(arc("example.com")),
                path: Some(PathRewrite::FullReplace(arc("/redirected"))),
                port: Some(8443),
                status_code: 308,
            },
        ];

        let base = compute_digest(&route_with_filter(filters[0].clone()));
        for f in filters.into_iter().skip(1) {
            let h = compute_digest(&route_with_filter(f));
            assert_ne!(base, h);
        }
    }

    #[test]
    fn http_route_weighted_backend_ordering_stable() {
        let a = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![
                    WeightedBackend {
                        backend: arc("b:80"),
                        weight: 2,
                        protocol: crate::ir::BackendProtocol::Http,
                        filters: vec![],
                        tls: None,
                    },
                    WeightedBackend {
                        backend: arc("a:80"),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,
                        filters: vec![],
                        tls: None,
                    },
                ],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        let mut b = a.clone();
        b.http_routes[0].rules[0].backends.swap(0, 1);
        assert_eq!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn reference_grant_subjects_affect_digest() {
        let base = ReconciledView {
            reference_grants: vec![ReferenceGrantState {
                namespace: arc("default"),
                name: arc("g1"),
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
                    namespace: None,
                    name: Some(arc("svc")),
                }],
            }],
            ..Default::default()
        };
        let mut changed = base.clone();
        changed.reference_grants[0].from[0].name = Some(arc("specific"));
        assert_ne!(compute_digest(&base), compute_digest(&changed));
    }

    #[test]
    fn http_route_request_mirror_changes_digest() {
        let base = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: vec![RouteFilter::RequestMirror {
                    backend: arc("mirror-svc:80"),
                    fraction: None,
                }],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        let changed = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: vec![RouteFilter::RequestMirror {
                    backend: arc("other-svc:80"),
                    fraction: None,
                }],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        assert_ne!(compute_digest(&base), compute_digest(&changed));
    }

    #[test]
    fn http_route_cors_filter_changes_digest() {
        let base = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: vec![RouteFilter::Cors {
                    allow_origins: vec![arc("*")],
                    allow_methods: vec![arc("GET")],
                    allow_headers: vec![arc("X-Custom")],
                    expose_headers: vec![],
                    max_age: Some(600),
                    allow_credentials: false,
                }],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        let changed = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: vec![RouteFilter::Cors {
                    allow_origins: vec![arc("*")],
                    allow_methods: vec![arc("GET")],
                    allow_headers: vec![arc("X-Custom")],
                    expose_headers: vec![],
                    max_age: Some(600),
                    allow_credentials: true,
                }],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        assert_ne!(compute_digest(&base), compute_digest(&changed));
    }

    #[test]
    fn http_route_rule_match_reordering_stable() {
        let mut a = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![
                    RouteMatch {
                        path: Some(PathMatch::Prefix(arc("/z"))),
                        headers: vec![],
                        query_params: vec![],
                        method: None,
                    },
                    RouteMatch {
                        path: Some(PathMatch::Prefix(arc("/a"))),
                        headers: vec![],
                        query_params: vec![],
                        method: None,
                    },
                ],
                backends: vec![],
                filters: vec![],
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        let b = a.clone();
        a.http_routes[0].rules[0].matches.swap(0, 1);
        assert_eq!(compute_digest(&a), compute_digest(&b));
    }

    #[test]
    fn http_route_filter_reordering_stable() {
        // Exercise route_filter_ord by putting multiple RouteFilter variants
        // in a single rule out of canonical order.
        let filters = vec![
            RouteFilter::ResponseHeaderRemove { name: arc("X-Old") },
            RouteFilter::RequestHeaderSet {
                name: arc("X-In"),
                value: arc("in"),
            },
            RouteFilter::UrlRewrite {
                hostname: None,
                path: Some(PathRewrite::PrefixReplace {
                    prefix: arc("/api"),
                    replacement: arc("/v2"),
                }),
            },
            RouteFilter::RequestHeaderAdd {
                name: arc("X-In-Add"),
                value: arc("in-add"),
            },
        ];
        let base = view_with_http_routes(vec![HTTPRouteState {
            namespace: arc("default"),
            name: arc("r1"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![],
                filters: filters.clone(),
            }],
            parent_refs: vec![],
            programmed: true,
        }]);
        let mut reversed = base.clone();
        reversed.http_routes[0].rules[0].filters.reverse();
        assert_eq!(compute_digest(&base), compute_digest(&reversed));
    }
}
