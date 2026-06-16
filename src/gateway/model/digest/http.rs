// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::common::{
    encode_i64, encode_option_i32, encode_option_str, encode_option_u16, encode_parent_ref,
    encode_str, encode_u16, encode_u32, encode_weighted_backend,
};
use super::HTTPRouteState;

pub(crate) fn encode_http_route(buf: &mut Vec<u8>, r: &HTTPRouteState) {
    encode_str(buf, &r.namespace);
    encode_str(buf, &r.name);
    encode_i64(buf, r.generation);

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

fn encode_http_route_rule(buf: &mut Vec<u8>, rule: &super::super::routing::HTTPRouteRule) {
    let mut matches = rule.matches.clone();
    matches.sort_by(|a, b| {
        use super::super::routing::PathMatch;
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

fn route_filter_ord(f: &super::super::routing::RouteFilter) -> u8 {
    use super::super::routing::RouteFilter;
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

fn encode_route_match(buf: &mut Vec<u8>, m: &super::super::routing::RouteMatch) {
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

fn encode_option_path_match(buf: &mut Vec<u8>, opt: &Option<super::super::routing::PathMatch>) {
    use super::super::routing::PathMatch;
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

fn encode_header_match(buf: &mut Vec<u8>, h: &super::super::routing::HeaderMatch) {
    encode_str(buf, &h.name);
    use super::super::routing::HeaderMatchValue;
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

fn encode_query_param_match(buf: &mut Vec<u8>, q: &super::super::routing::QueryParamMatch) {
    encode_str(buf, &q.name);
    use super::super::routing::QueryParamMatchValue;
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

fn encode_route_filter(buf: &mut Vec<u8>, f: &super::super::routing::RouteFilter) {
    use super::super::routing::RouteFilter;
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

fn encode_path_rewrite(buf: &mut Vec<u8>, p: &super::super::routing::PathRewrite) {
    use super::super::routing::PathRewrite;
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

fn encode_option_path_rewrite(buf: &mut Vec<u8>, opt: &Option<super::super::routing::PathRewrite>) {
    match opt {
        None => buf.push(0x00),
        Some(p) => {
            buf.push(0x01);
            encode_path_rewrite(buf, p);
        }
    }
}
