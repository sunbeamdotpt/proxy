// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Host and path matching helpers.

#[cfg(test)]
use crate::config::PathRoute;
#[cfg(test)]
use crate::ir::compile::{ir_hostname_matches, ir_listener_specificity_score};
#[cfg(test)]
use std::cmp::Ordering;
use std::sync::atomic::AtomicU64;
#[cfg(test)]
use std::sync::Arc;

/// Return true if `prefix` is a Gateway API path-segment prefix of `req_path`.
/// A PathPrefix `/foo` matches `/foo`, `/foo/`, and `/foo/bar`, but not
/// `/foobar` or `/bar/foo`. The root prefix `/` matches every path.
#[cfg(test)]
pub fn path_prefix_matches(req_path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return req_path.starts_with('/');
    }
    if req_path == prefix {
        return true;
    }
    req_path
        .strip_prefix(prefix)
        .map(|rest| rest.starts_with('/'))
        .unwrap_or(false)
}

/// Check if an Origin matches the CORS allow_origins list.
///
/// An empty `allow_origins` list is treated as "deny all" when credentials are
/// enabled, so that a route with `allow_credentials: true` does not reflect
/// arbitrary origins.
pub fn cors_allow_origin(
    origin: &str,
    allow_origins: &[impl AsRef<str>],
    allow_credentials: bool,
) -> bool {
    if allow_origins.is_empty() {
        return !allow_credentials;
    }
    for allowed in allow_origins {
        let allowed = allowed.as_ref();
        if allowed == "*" {
            return true;
        }
        if allowed.eq_ignore_ascii_case(origin) {
            return true;
        }
        // Wildcard matching: e.g. "*.example.com" or "https://*.example.com"
        // matches "foo.example.com" or "https://foo.example.com" respectively.
        if let Some((prefix, suffix)) = allowed.split_once("*.")
            && let Some(rest) = origin.strip_prefix(prefix)
                && rest
                    .strip_suffix(suffix)
                    .and_then(|rest| rest.strip_suffix('.'))
                    .is_some_and(|rest| !rest.is_empty())
                {
                    return true;
                }
    }
    false
}

/// Select the best matching path route from a list, considering prefix and
/// optional HTTP method constraints. Longest prefix wins; method mismatch
/// excludes a candidate.
#[cfg(test)]
pub fn select_path_route<'a>(
    paths: &'a [PathRoute],
    req_path: &str,
    method: &str,
    req_headers: &http::header::HeaderMap,
    query: Option<&str>,
) -> Option<&'a PathRoute> {
    paths
        .iter()
        .filter(|p| {
            if p.path_match_exact {
                req_path == p.prefix.as_str()
            } else {
                path_prefix_matches(req_path, p.prefix.as_str())
            }
        })
        .filter(|p| {
            p.methods.is_empty() || p.methods.iter().any(|m| m.eq_ignore_ascii_case(method))
        })
        .filter(|p| {
            p.header_matches.iter().all(|hm| {
                let val = req_headers.get(&hm.name).and_then(|v| v.to_str().ok());
                match &hm.value {
                    crate::config::HeaderMatchValueConfig::Exact(expected) => {
                        val.is_some_and(|v| v.eq_ignore_ascii_case(expected.as_str()))
                    }
                    crate::config::HeaderMatchValueConfig::Regex(pattern) => val.is_some_and(|v| {
                        regex::Regex::new(pattern)
                            .ok()
                            .is_some_and(|re| re.is_match(v))
                    }),
                    crate::config::HeaderMatchValueConfig::Present => val.is_some(),
                    crate::config::HeaderMatchValueConfig::Absent => val.is_none(),
                }
            })
        })
        .filter(|p| {
            p.query_param_matches.iter().all(|qm| {
                let query_val = query.and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let mut parts = pair.splitn(2, '=');
                        let key = parts.next()?;
                        if key == qm.name {
                            Some(parts.next().unwrap_or(""))
                        } else {
                            None
                        }
                    })
                });
                match &qm.value {
                    crate::config::QueryParamMatchValueConfig::Exact(expected) => {
                        query_val == Some(expected.as_str())
                    }
                    crate::config::QueryParamMatchValueConfig::Regex(pattern) => query_val
                        .is_some_and(|v| {
                            regex::Regex::new(pattern)
                                .ok()
                                .is_some_and(|re| re.is_match(v))
                        }),
                }
            })
        })
        .max_by(|a, b| {
            let prefix_cmp = a.prefix.len().cmp(&b.prefix.len());
            if prefix_cmp != Ordering::Equal {
                return prefix_cmp;
            }
            // Gateway API precedence: on prefix-length ties, prefer the match
            // with the most header matches, then query param matches, then
            // method match, then earliest rule order.
            let header_cmp = a.header_matches.len().cmp(&b.header_matches.len());
            if header_cmp != Ordering::Equal {
                return header_cmp;
            }
            let query_cmp = a
                .query_param_matches
                .len()
                .cmp(&b.query_param_matches.len());
            if query_cmp != Ordering::Equal {
                return query_cmp;
            }
            let method_cmp = b.methods.is_empty().cmp(&a.methods.is_empty());
            if method_cmp != Ordering::Equal {
                return method_cmp;
            }
            // Earlier rule order wins on prefix-length ties (Gateway API
            // precedence semantics). Lower rule_order = earlier rule.
            b.rule_order.cmp(&a.rule_order)
        })
}

/// Pick a backend index from IR weighted backends using a round-robin counter.
pub fn pick_weighted_backend_ir_index(backends: &[crate::ir::WeightedBackend]) -> Option<usize> {
    if backends.is_empty() {
        return None;
    }
    let total: u64 = backends.iter().map(|b| b.weight as u64).sum();
    if total == 0 {
        return Some(0);
    }
    let pick = WEIGHTED_BACKEND_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % total;
    let mut cursor = 0;
    for (i, b) in backends.iter().enumerate() {
        cursor += b.weight as u64;
        if pick < cursor {
            return Some(i);
        }
    }
    Some(0)
}

/// Pick a backend from weighted backends using a hash of the request path
/// for deterministic distribution.
static WEIGHTED_BACKEND_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub fn pick_weighted_backend(
    backends: &[crate::config::WeightedBackendConfig],
    _path: &str,
) -> Option<String> {
    if backends.is_empty() {
        return None;
    }
    let total: u64 = backends.iter().map(|b| b.weight as u64).sum();
    if total == 0 {
        return Some(backends[0].backend.clone());
    }
    let pick = WEIGHTED_BACKEND_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % total;
    let mut cursor = 0;
    for b in backends {
        cursor += b.weight as u64;
        if pick < cursor {
            return Some(b.backend.clone());
        }
    }
    Some(backends[0].backend.clone())
}

/// Build a redirect Location header from an IR RedirectAction and the original request.
///
/// When the redirect specifies a scheme but no port, the well-known port for that
/// scheme is used (80 for http, 443 for https). When the redirect omits both scheme
/// and port, the downstream listener port is used. Default ports are omitted from
/// the resulting URL.
pub fn build_redirect_location_ir(
    redirect: &crate::ir::RedirectAction,
    original_uri: &http::Uri,
    request_host: &str,
    downstream_scheme: &str,
    downstream_port: u16,
) -> String {
    let scheme = redirect
        .scheme
        .as_ref()
        .map(|s| s.as_ref())
        .unwrap_or(downstream_scheme);
    let host = redirect
        .hostname
        .as_ref()
        .map(|s| s.as_ref())
        .or_else(|| original_uri.host())
        .unwrap_or(request_host);
    let original_path = original_uri.path();
    let path = match &redirect.path {
        Some(crate::ir::PathRewrite::PrefixReplace {
            prefix,
            replacement,
        }) => original_path
            .strip_prefix(prefix.as_ref())
            .map(|rest| format!("{}{}", replacement.as_ref(), rest))
            .unwrap_or_else(|| original_path.to_string()),
        Some(crate::ir::PathRewrite::FullReplace(replacement)) => replacement.to_string(),
        None => original_path.to_string(),
    };
    let default_port = if redirect.scheme.is_some() {
        if scheme == "https" {
            443
        } else if scheme == "http" {
            80
        } else {
            downstream_port
        }
    } else {
        downstream_port
    };
    let effective_port = redirect.port.unwrap_or(default_port);
    let omit_port = effective_port == 0
        || (scheme == "http" && effective_port == 80)
        || (scheme == "https" && effective_port == 443);
    if omit_port {
        format!("{}://{}{}", scheme, host, path)
    } else {
        format!("{}://{}:{}{}", scheme, host, effective_port, path)
    }
}

/// Build a redirect Location header from a RedirectRule and the original request.
#[cfg(test)]
pub fn build_redirect_location(
    redirect: &crate::config::RedirectRule,
    original_uri: &http::Uri,
) -> String {
    let scheme = redirect
        .scheme
        .as_deref()
        .or_else(|| original_uri.scheme_str())
        .unwrap_or("http");
    let host = redirect
        .hostname
        .as_deref()
        .or_else(|| original_uri.host())
        .unwrap_or("");
    let original_path = original_uri.path();
    let path = if let Some(prefix) = &redirect.path_prefix {
        original_path
            .strip_prefix(prefix)
            .map(|rest| format!("{}{}", redirect.path.as_deref().unwrap_or(""), rest))
            .unwrap_or_else(|| {
                redirect
                    .path
                    .clone()
                    .unwrap_or_else(|| original_path.to_string())
            })
    } else {
        redirect
            .path
            .clone()
            .unwrap_or_else(|| original_path.to_string())
    };
    match redirect.port {
        Some(port) => format!("{}://{}:{}{}", scheme, host, port, path),
        None => format!("{}://{}{}", scheme, host, path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_matches_respects_segment_boundary() {
        assert!(path_prefix_matches("/v2", "/v2"));
        assert!(path_prefix_matches("/v2/", "/v2"));
        assert!(path_prefix_matches("/v2/example", "/v2"));
        assert!(!path_prefix_matches("/v2example", "/v2"));
        assert!(!path_prefix_matches("/foo/v2/example", "/v2"));
        assert!(path_prefix_matches("/", "/"));
        assert!(path_prefix_matches("/foo", "/"));
        assert!(!path_prefix_matches("/foo", "/bar"));
    }

    #[test]
    fn select_path_route_prefers_longest_prefix() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "root".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/api".into(),
                backend: "api".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        let chosen = select_path_route(&paths, "/api/v1", "GET", &empty_headers, None).unwrap();
        assert_eq!(chosen.backend, "api");
    }

    #[test]
    fn select_path_route_respects_method_constraint() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/api".into(),
                backend: "api-read".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec!["GET".into(), "HEAD".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/api".into(),
                backend: "api-write".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec!["POST".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(
            select_path_route(&paths, "/api", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "api-read"
        );
        assert_eq!(
            select_path_route(&paths, "/api", "POST", &empty_headers, None)
                .unwrap()
                .backend,
            "api-write"
        );
        assert!(select_path_route(&paths, "/api", "DELETE", &empty_headers, None).is_none());
    }

    #[test]
    fn select_path_route_earlier_rule_wins_on_prefix_tie() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "first".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "second".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        let chosen = select_path_route(&paths, "/", "GET", &empty_headers, None).unwrap();
        assert_eq!(chosen.backend, "first");
    }

    #[test]
    fn select_path_route_respects_exact_match() {
        let paths = vec![PathRoute {
            timeout_ms: None,
            prefix: "/api".into(),
            backend: "exact".into(),
            strip_prefix: false,
            websocket: false,
            auth_request: None,
            auth_capture_headers: vec![],
            upstream_path_prefix: None,
            path_rewrite_full: None,
            cors: None,
            hostname_rewrite: None,
            mirror_backends: vec![],
            timeout_secs: None,
            deny: false,
            gateway_api_unprogrammed: false,
            methods: vec![],
            weighted_backends: vec![],
            redirect: None,
            header_matches: vec![],
            query_param_matches: vec![],
            rule_order: 0,
            path_match_exact: true,
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
        }];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(
            select_path_route(&paths, "/api", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "exact"
        );
        assert!(select_path_route(&paths, "/api/", "GET", &empty_headers, None).is_none());
        assert!(select_path_route(&paths, "/api/v1", "GET", &empty_headers, None).is_none());
    }

    #[test]
    fn select_path_route_prefers_more_header_matches_on_tie() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "no-header".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "with-header".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![crate::config::HeaderMatchConfig {
                    name: "version".into(),
                    value: crate::config::HeaderMatchValueConfig::Exact("one".into()),
                }],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("one"));
        let chosen = select_path_route(&paths, "/", "GET", &headers, None).unwrap();
        assert_eq!(chosen.backend, "with-header");
    }

    #[test]
    fn select_path_route_prefers_method_match_on_tie() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/api".into(),
                backend: "any-method".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/api".into(),
                backend: "post-only".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec!["POST".into()],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        let chosen = select_path_route(&paths, "/api", "POST", &empty_headers, None).unwrap();
        assert_eq!(chosen.backend, "post-only");
    }

    #[test]
    fn select_path_route_matches_conformance_path_prefix_cases() {
        let paths = vec![
            PathRoute {
                timeout_ms: None,
                prefix: "/".into(),
                backend: "root".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 0,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
            PathRoute {
                timeout_ms: None,
                prefix: "/v2".into(),
                backend: "v2".into(),
                strip_prefix: false,
                websocket: false,
                auth_request: None,
                auth_capture_headers: vec![],
                upstream_path_prefix: None,
                path_rewrite_full: None,
                cors: None,
                hostname_rewrite: None,
                mirror_backends: vec![],
                timeout_secs: None,
                deny: false,
                gateway_api_unprogrammed: false,
                methods: vec![],
                weighted_backends: vec![],
                redirect: None,
                header_matches: vec![],
                query_param_matches: vec![],
                rule_order: 1,
                path_match_exact: false,
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
            },
        ];
        let empty_headers = http::header::HeaderMap::new();
        assert_eq!(
            select_path_route(&paths, "/", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
        assert_eq!(
            select_path_route(&paths, "/v2", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2/", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2/example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "v2"
        );
        assert_eq!(
            select_path_route(&paths, "/v2example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
        assert_eq!(
            select_path_route(&paths, "/foo/v2/example", "GET", &empty_headers, None)
                .unwrap()
                .backend,
            "root"
        );
    }

    #[test]
    fn select_path_route_header_match_is_case_insensitive() {
        let paths = vec![PathRoute {
            timeout_ms: None,
            prefix: "/".into(),
            backend: "matched".into(),
            strip_prefix: false,
            websocket: false,
            auth_request: None,
            auth_capture_headers: vec![],
            upstream_path_prefix: None,
            path_rewrite_full: None,
            cors: None,
            hostname_rewrite: None,
            mirror_backends: vec![],
            timeout_secs: None,
            deny: false,
            gateway_api_unprogrammed: false,
            methods: vec![],
            weighted_backends: vec![],
            redirect: None,
            header_matches: vec![crate::config::HeaderMatchConfig {
                name: "version".into(),
                value: crate::config::HeaderMatchValueConfig::Exact("one".into()),
            }],
            query_param_matches: vec![],
            rule_order: 0,
            path_match_exact: false,
            request_headers: vec![],
            request_headers_add: vec![],
            request_headers_remove: vec![],
            response_headers: vec![],
            response_headers_add: vec![],
            response_headers_remove: vec![],
        }];
        let mut headers = http::header::HeaderMap::new();
        headers.insert("version", http::header::HeaderValue::from_static("ONE"));
        let chosen = select_path_route(&paths, "/", "GET", &headers, None).unwrap();
        assert_eq!(chosen.backend, "matched");
    }

    #[test]
    fn pick_weighted_backend_empty_returns_none() {
        assert!(pick_weighted_backend(&[], "/x").is_none());
    }

    #[test]
    fn pick_weighted_backend_selects_by_hash() {
        let backends = vec![
            crate::config::WeightedBackendConfig {
                backend: "a".into(),
                weight: 1,
            },
            crate::config::WeightedBackendConfig {
                backend: "b".into(),
                weight: 1,
            },
        ];
        let a = pick_weighted_backend(&backends, "/path-a").unwrap();
        let b = pick_weighted_backend(&backends, "/path-b").unwrap();
        assert!(a == "a" || a == "b");
        assert!(b == "a" || b == "b");
    }

    #[test]
    fn pick_weighted_backend_honors_weights() {
        let backends = vec![
            crate::config::WeightedBackendConfig {
                backend: "heavy".into(),
                weight: 100,
            },
            crate::config::WeightedBackendConfig {
                backend: "light".into(),
                weight: 1,
            },
        ];
        let choice = pick_weighted_backend(&backends, "/x").unwrap();
        assert!(choice == "heavy" || choice == "light");
    }

    #[test]
    fn build_redirect_location_preserves_unspecified_parts() {
        let redirect = crate::config::RedirectRule {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/new".into()),
            path_prefix: None,
        };
        let uri: http::Uri = "http://example.com/old".parse().unwrap();
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "http://example.com/new"
        );
    }

    #[test]
    fn build_redirect_location_overrides_all_parts() {
        let redirect = crate::config::RedirectRule {
            status_code: 301,
            scheme: Some("https".into()),
            hostname: Some("other.example.com".into()),
            port: Some(8443),
            path: Some("/redirected".into()),
            path_prefix: None,
        };
        let uri: http::Uri = "http://example.com/old".parse().unwrap();
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "https://other.example.com:8443/redirected"
        );
    }

    #[test]
    fn build_redirect_location_replaces_prefix() {
        let redirect = crate::config::RedirectRule {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some("/replacement-prefix".into()),
            path_prefix: Some("/original-prefix".into()),
        };
        let uri: http::Uri = "http://example.com/original-prefix/lemon".parse().unwrap();
        assert_eq!(
            build_redirect_location(&redirect, &uri),
            "http://example.com/replacement-prefix/lemon"
        );
    }

    #[test]
    fn build_redirect_location_ir_uses_request_host_when_uri_has_none() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/new"))),
        };
        let uri: http::Uri = "/old".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "192.168.1.1", "http", 0),
            "http://192.168.1.1/new"
        );
    }

    #[test]
    fn build_redirect_location_ir_prefix_replace() {
        let redirect = crate::ir::RedirectAction {
            status_code: 301,
            scheme: None,
            hostname: None,
            port: None,
            path: Some(crate::ir::PathRewrite::PrefixReplace {
                prefix: Arc::from("/original-prefix"),
                replacement: Arc::from("/replacement-prefix"),
            }),
        };
        let uri: http::Uri = "/original-prefix/lemon".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "http", 0),
            "http://example.com/replacement-prefix/lemon"
        );
    }

    #[test]
    fn build_redirect_location_ir_preserves_downstream_scheme() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/new"))),
        };
        let uri: http::Uri = "/old".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "https", 0),
            "https://example.com/new"
        );
    }

    #[test]
    fn build_redirect_location_ir_explicit_scheme_overrides_downstream() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: Some(Arc::from("http")),
            hostname: None,
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/new"))),
        };
        let uri: http::Uri = "/old".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "https", 0),
            "http://example.com/new"
        );
    }

    #[test]
    fn build_redirect_location_ir_defaults_to_downstream_port() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: Some(Arc::from("example.org")),
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/"))),
        };
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "http", 8080),
            "http://example.org:8080/"
        );
    }

    #[test]
    fn build_redirect_location_ir_omits_default_http_port() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: Some(Arc::from("example.org")),
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/"))),
        };
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "http", 80),
            "http://example.org/"
        );
    }

    #[test]
    fn build_redirect_location_ir_omits_default_https_port() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: Some(Arc::from("example.org")),
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/"))),
        };
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "https", 443),
            "https://example.org/"
        );
    }

    #[test]
    fn build_redirect_location_ir_explicit_port_overrides_downstream() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: None,
            hostname: Some(Arc::from("example.org")),
            port: Some(9090),
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/"))),
        };
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "http", 8080),
            "http://example.org:9090/"
        );
    }

    #[test]
    fn build_redirect_location_ir_explicit_scheme_uses_well_known_default_port() {
        let redirect = crate::ir::RedirectAction {
            status_code: 302,
            scheme: Some(Arc::from("https")),
            hostname: Some(Arc::from("example.org")),
            port: None,
            path: Some(crate::ir::PathRewrite::FullReplace(Arc::from("/"))),
        };
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_redirect_location_ir(&redirect, &uri, "example.com", "http", 8080),
            "https://example.org/"
        );
    }

    #[test]
    fn ir_hostname_matches_any_is_true() {
        assert!(ir_hostname_matches(
            "anything",
            &crate::ir::HostnameMatch::Any
        ));
        assert!(ir_hostname_matches("", &crate::ir::HostnameMatch::Any));
    }

    #[test]
    fn ir_listener_specificity_score_empty_exact_is_zero() {
        assert_eq!(
            ir_listener_specificity_score(&crate::ir::HostnameMatch::Exact(Arc::from(""))),
            0
        );
    }

    #[test]
    fn cors_allow_origin_empty_list_denies_when_credentials_enabled() {
        assert!(!cors_allow_origin(
            "https://evil.com",
            &[] as &[String],
            true
        ));
    }

    #[test]
    fn cors_allow_origin_empty_list_allows_without_credentials() {
        assert!(cors_allow_origin(
            "https://anything.com",
            &[] as &[String],
            false
        ));
    }

    #[test]
    fn cors_allow_origin_wildcard_allows_with_credentials() {
        assert!(cors_allow_origin("https://foo.example.com", &["*"], true));
    }

    #[test]
    fn cors_allow_origin_wildcard_allows_without_credentials() {
        assert!(cors_allow_origin("https://foo.example.com", &["*"], false));
    }

    #[test]
    fn cors_allow_origin_exact_match_ignores_case() {
        assert!(cors_allow_origin(
            "https://EXAMPLE.COM",
            &["https://example.com"],
            false
        ));
    }

    #[test]
    fn cors_allow_origin_wildcard_suffix_matches() {
        assert!(cors_allow_origin(
            "https://www.bar.com",
            &["https://*.bar.com"],
            true
        ));
        assert!(cors_allow_origin(
            "https://xpto.www.bar.com",
            &["https://*.bar.com"],
            true
        ));
        assert!(!cors_allow_origin(
            "http://www.bar.com",
            &["https://*.bar.com"],
            true
        ));
        assert!(!cors_allow_origin(
            "https://bar.com",
            &["https://*.bar.com"],
            true
        ));
    }

    #[test]
    fn cors_allow_origin_wildcard_without_scheme_matches() {
        assert!(cors_allow_origin(
            "https://www.bar.com",
            &["*.bar.com"],
            false
        ));
        assert!(!cors_allow_origin("https://bar.com", &["*.bar.com"], false));
    }

    #[test]
    fn pick_weighted_backend_ir_index_distributes_by_weight() {
        let backends = vec![
            crate::ir::WeightedBackend {
                backend: "a".into(),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            },
            crate::ir::WeightedBackend {
                backend: "b".into(),
                weight: 2,
                protocol: crate::ir::BackendProtocol::Http,
                request_filters: vec![],
                tls: None,
            },
        ];
        let total: usize = backends.iter().map(|b| b.weight as usize).sum();
        let mut counts = vec![0; backends.len()];
        for _ in 0..total * 10 {
            let idx = pick_weighted_backend_ir_index(&backends).unwrap();
            counts[idx] += 1;
        }
        assert!(counts[0] > 0);
        assert!(counts[1] > counts[0]);
    }
}
