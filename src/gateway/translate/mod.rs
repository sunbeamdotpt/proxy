// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Route / listener translation layer.
//!
//! Converts a `GatewayView` into Pingora-native configuration.

mod from_model;

use crate::config::{
    HeaderMatchConfig, HeaderMatchValueConfig, HeaderRule, PathRoute, QueryParamMatchConfig,
    QueryParamMatchValueConfig, RedirectRule, RewriteRule, RouteConfig, WeightedBackendConfig,
};
use crate::gateway::model::{
    GRPCRouteMatch, GRPCRouteRule, GatewayState, GatewayView, HTTPRouteRule, HeaderMatch,
    HeaderMatchValue, HostnameMatch, ListenerState, MethodMatchType, PathMatch, PathRewrite,
    QueryParamMatch, QueryParamMatchValue, RouteFilter, RouteMatch, TlsMode,
};
use crate::ir;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

/// Minimal trait used to share hostname/parent computation between
/// HTTPRoute and GRPCRoute.
pub(crate) trait RouteHostnames {
    fn route_namespace(&self) -> &Arc<str>;
    fn route_parent_refs(&self) -> &[crate::gateway::model::ParentRef];
    fn route_hostnames(&self) -> &[HostnameMatch];
}

impl RouteHostnames for crate::gateway::model::HTTPRouteState {
    fn route_namespace(&self) -> &Arc<str> {
        &self.namespace
    }
    fn route_parent_refs(&self) -> &[crate::gateway::model::ParentRef] {
        &self.parent_refs
    }
    fn route_hostnames(&self) -> &[HostnameMatch] {
        &self.hostnames
    }
}

impl RouteHostnames for crate::gateway::model::GRPCRouteState {
    fn route_namespace(&self) -> &Arc<str> {
        &self.namespace
    }
    fn route_parent_refs(&self) -> &[crate::gateway::model::ParentRef] {
        &self.parent_refs
    }
    fn route_hostnames(&self) -> &[HostnameMatch] {
        &self.hostnames
    }
}

/// Check if `child` hostname is a subset of `parent` hostname.
pub fn is_hostname_subset(child: &HostnameMatch, parent: &HostnameMatch) -> bool {
    match (child, parent) {
        (_, HostnameMatch::Any) => true,
        (HostnameMatch::Exact(c), HostnameMatch::Exact(p)) => c == p,
        // Intersection is more permissive than request matching:
        // a multi-level subdomain is considered a subset of a wildcard.
        (HostnameMatch::Exact(c), HostnameMatch::Wildcard(p)) => c
            .strip_suffix(p.as_ref())
            .and_then(|rest| rest.strip_suffix('.'))
            .is_some_and(|rest| !rest.is_empty()),
        (HostnameMatch::Wildcard(c), HostnameMatch::Wildcard(p)) => {
            c == p
                || c.strip_suffix(p.as_ref())
                    .is_some_and(|rest| rest.ends_with('.'))
        }
        (HostnameMatch::Any, _) => false,
        _ => false,
    }
}

/// Check whether two hostname patterns have a non-empty intersection.
pub fn hostname_intersects(a: &HostnameMatch, b: &HostnameMatch) -> bool {
    is_hostname_subset(a, b) || is_hostname_subset(b, a)
}

/// Return the most specific hostname pattern that represents the intersection
/// of `a` and `b`, or `None` if they do not intersect.
pub fn intersect_hostname_pair(a: &HostnameMatch, b: &HostnameMatch) -> Option<HostnameMatch> {
    if is_hostname_subset(a, b) {
        Some(a.clone())
    } else if is_hostname_subset(b, a) {
        Some(b.clone())
    } else {
        None
    }
}

/// Intersect route hostnames with a listener hostname.
pub fn intersect_hostnames(
    route_hostnames: &[HostnameMatch],
    listener_hostname: Option<&str>,
) -> Vec<HostnameMatch> {
    let Some(lh_str) = listener_hostname else {
        return route_hostnames.to_vec();
    };
    let listener_match = parse_listener_hostname(lh_str);
    route_hostnames
        .iter()
        .filter_map(|rh| intersect_hostname_pair(rh, &listener_match))
        .collect()
}

/// An effective hostname pair: the route's own hostname match and the listener
/// hostname it is attached to. Keeping these separate is required for listener
/// isolation, where the listener hostname determines which listener wins for a
/// request while the route hostname determines whether a given route matches.
struct EffectiveHostname {
    /// Effective hostname match for the route itself.
    route_hostname: HostnameMatch,
    /// Hostname match of the listener this route is attached to.
    listener_hostname: HostnameMatch,
    /// Port of the listener this route is attached to. `None` when no listener
    /// was resolved (legacy/fallback path).
    listener_port: Option<u16>,
    /// Optional Gateway-wide backend client certificate identifier.
    client_cert_id: Option<Arc<str>>,
}

/// Check whether a listener's namespace scope allows routes from `route_ns`.
fn namespace_allowed(
    namespaces: &crate::gateway::model::RouteNamespaces,
    route_ns: &str,
    gateway_ns: &str,
    namespace_labels: &BTreeMap<Arc<str>, BTreeMap<Arc<str>, Arc<str>>>,
) -> bool {
    use crate::gateway::model::NamespaceFrom;
    match namespaces.from {
        NamespaceFrom::All => true,
        NamespaceFrom::Same => route_ns == gateway_ns,
        NamespaceFrom::None => false,
        NamespaceFrom::Selector => {
            let labels = match namespace_labels.get(route_ns) {
                Some(l) => l,
                None => return false,
            };
            namespaces.selector.as_ref().is_some_and(|sel| {
                sel.iter()
                    .all(|(k, v)| labels.get(k.as_str()) == Some(&Arc::from(v.as_str())))
            })
        }
    }
}

/// Compute effective hostnames for an HTTPRoute or GRPCRoute, considering
/// listener hostname intersection.
fn compute_effective_hostnames<R: RouteHostnames>(
    route: &R,
    view: &GatewayView,
    route_kind: &str,
) -> Vec<EffectiveHostname> {
    use crate::gateway::reconcile::httproute::listener_allows_kind;

    let mut result = Vec::new();

    for parent in route.route_parent_refs() {
        let parent_ns = parent
            .namespace
            .as_deref()
            .unwrap_or(route.route_namespace().as_ref());
        let parent_name = parent.name.as_ref();
        let kind = parent.kind.as_ref();
        let mut client_cert_id: Option<Arc<str>> = None;

        let (listeners, found, allowed_map): (
            Vec<&ListenerState>,
            bool,
            &crate::gateway::model::ListenerAllowedMap,
        ) = match kind {
            "ListenerSet" => {
                let ls = view
                    .listener_sets
                    .iter()
                    .find(|s| s.namespace.as_ref() == parent_ns && s.name.as_ref() == parent_name);
                match ls {
                    Some(ls) if ls.programmed => {
                        let listeners: Vec<&ListenerState> =
                            if let Some(section) = parent.section_name.as_deref() {
                                ls.listeners
                                    .iter()
                                    .filter(|l| {
                                        l.name.as_ref() == section
                                            && parent.port.map(|p| p == l.port).unwrap_or(true)
                                    })
                                    .collect()
                            } else {
                                ls.listeners
                                    .iter()
                                    .filter(|l| parent.port.map(|p| p == l.port).unwrap_or(true))
                                    .collect()
                            };
                        (listeners, true, &view.listener_set_allowed)
                    }
                    _ => (Vec::new(), false, &view.listener_set_allowed),
                }
            }
            _ => {
                let gateway_state = view
                    .gateways
                    .iter()
                    .find(|g| g.namespace.as_ref() == parent_ns && g.name.as_ref() == parent_name);
                client_cert_id = gateway_state.and_then(|g| g.backend_client_cert_id.clone());
                match gateway_state {
                    Some(gateway) => {
                        let listeners: Vec<&ListenerState> =
                            if let Some(section) = parent.section_name.as_deref() {
                                gateway
                                    .listeners
                                    .iter()
                                    .filter(|l| {
                                        l.name.as_ref() == section
                                            && parent.port.map(|p| p == l.port).unwrap_or(true)
                                    })
                                    .collect()
                            } else {
                                gateway
                                    .listeners
                                    .iter()
                                    .filter(|l| parent.port.map(|p| p == l.port).unwrap_or(true))
                                    .collect()
                            };
                        (listeners, true, &view.listener_allowed)
                    }
                    None => (Vec::new(), false, &view.listener_allowed),
                }
            }
        };

        let route_ns = route.route_namespace().as_ref();

        let attached_listeners: Vec<&ListenerState> = if found {
            listeners
                .into_iter()
                .filter(|l| {
                    let key = (Arc::from(parent_ns), Arc::from(parent_name), l.name.clone());
                    let allowed = allowed_map.get(&key).cloned().unwrap_or_default();
                    listener_allows_kind(&allowed, "gateway.networking.k8s.io", route_kind)
                        && namespace_allowed(
                            &allowed.namespaces,
                            route_ns,
                            parent_ns,
                            &view.namespace_labels,
                        )
                        && crate::gateway::reconcile::httproute::listener_hostname_intersects(
                            l.hostname.as_deref(),
                            route.route_hostnames(),
                        )
                })
                .collect()
        } else {
            Vec::new()
        };

        if route.route_hostnames().is_empty() {
            if !found || attached_listeners.is_empty() {
                result.push(EffectiveHostname {
                    route_hostname: HostnameMatch::Any,
                    listener_hostname: HostnameMatch::Any,
                    listener_port: None,
                    client_cert_id: None,
                });
                continue;
            }

            for listener in attached_listeners {
                let listener_match = listener
                    .hostname
                    .as_deref()
                    .map(parse_listener_hostname)
                    .unwrap_or_else(|| HostnameMatch::Exact(Arc::from("")));
                let route_match = if listener.hostname.is_some() {
                    listener_match.clone()
                } else {
                    HostnameMatch::Any
                };
                result.push(EffectiveHostname {
                    route_hostname: route_match,
                    listener_hostname: listener_match,
                    listener_port: Some(listener.port),
                    client_cert_id: client_cert_id.clone(),
                });
            }
        } else {
            if found {
                for listener in attached_listeners {
                    let listener_match = listener
                        .hostname
                        .as_deref()
                        .map(parse_listener_hostname)
                        .unwrap_or_else(|| HostnameMatch::Exact(Arc::from("")));
                    let route_hostnames =
                        intersect_hostnames(route.route_hostnames(), listener.hostname.as_deref());
                    for hostname in route_hostnames {
                        result.push(EffectiveHostname {
                            route_hostname: hostname,
                            listener_hostname: listener_match.clone(),
                            listener_port: Some(listener.port),
                            client_cert_id: client_cert_id.clone(),
                        });
                    }
                }
            } else {
                for hostname in route.route_hostnames() {
                    result.push(EffectiveHostname {
                        route_hostname: hostname.clone(),
                        listener_hostname: HostnameMatch::Any,
                        listener_port: None,
                        client_cert_id: None,
                    });
                }
            }
        }
    }

    result
}

pub(crate) fn parse_listener_hostname(hostname: &str) -> HostnameMatch {
    if let Some(rest) = hostname.strip_prefix("*.") {
        HostnameMatch::Wildcard(Arc::from(rest))
    } else {
        HostnameMatch::Exact(Arc::from(hostname))
    }
}

/// Translate a reconciled view into proxy `RouteConfig` entries.
///
/// Routes are grouped by (listener_hostname, host_prefix) and merged so that
/// multiple HTTPRoutes attached to the same listener with the same hostname
/// produce a single `RouteConfig` containing all their paths.
pub fn translate_view(view: &GatewayView) -> Vec<RouteConfig> {
    // Key: (listener_hostname, host_prefix)
    let mut groups: HashMap<(Option<String>, String), RouteConfig> = HashMap::new();

    for http_route in &view.http_routes {
        // Routes that were accepted by a parent but whose backend references could
        // not be resolved must still be present in the dataplane so that matching
        // requests receive HTTP 500 rather than falling through to another route.
        let unprogrammed = !http_route.programmed && !http_route.parent_refs.is_empty();

        let effective = compute_effective_hostnames(http_route, view, "HTTPRoute");

        for eff in effective {
            let host_prefix = hostname_to_prefix(&eff.route_hostname);
            let listener_hostname_str = match &eff.listener_hostname {
                HostnameMatch::Any => None,
                HostnameMatch::Exact(s) if s.is_empty() => Some("".to_string()),
                _ => Some(hostname_to_prefix(&eff.listener_hostname)),
            };
            let key = (listener_hostname_str.clone(), host_prefix.clone());

            let mut paths = Vec::new();
            let mut rewrites = Vec::new();

            for (rule_idx, rule) in http_route.rules.iter().enumerate() {
                let rule_paths =
                    translate_rule_paths(rule, &http_route.namespace, rule_idx, unprogrammed);
                paths.extend(rule_paths);

                for filter in &rule.filters {
                    if let RouteFilter::UrlRewrite { hostname, path } = filter {
                        if let Some(path) = path {
                            if let Some(rw) = translate_rewrite(path) {
                                rewrites.push(rw);
                            }
                        }
                        // hostname rewrite is handled per-path-route below
                        let _ = hostname;
                    }
                }
            }

            // If no paths were produced, create a default catch-all path
            // using the first backend from the first rule (common case).
            if paths.is_empty() && !http_route.rules.is_empty() {
                if let Some(first_backend) = http_route.rules[0].backends.first() {
                    paths.push(PathRoute {
                        prefix: "/".to_string(),
                        backend: first_backend.backend.to_string(),
                        strip_prefix: false,
                        websocket: false,
                        auth_request: None,
                        auth_capture_headers: vec![],
                        upstream_path_prefix: None,
                        path_rewrite_full: None,
                        hostname_rewrite: None,
                        timeout_secs: None,
                        timeout_ms: None,
                        mirror_backends: vec![],
                        deny: false,
                        gateway_api_unprogrammed: unprogrammed,
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
                        cors: None,
                    });
                }
            }

            let group = groups.entry(key).or_insert_with(|| RouteConfig {
                host_prefix: host_prefix.clone(),
                backend: paths.first().map(|p| p.backend.clone()).unwrap_or_default(),
                websocket: false,
                disable_secure_redirection: true,
                paths: vec![],
                static_root: None,
                fallback: None,
                rewrites: vec![],
                body_rewrites: vec![],
                response_headers: vec![],
                response_headers_add: vec![],
                response_headers_remove: vec![],
                request_headers: vec![],
                request_headers_add: vec![],
                request_headers_remove: vec![],
                cache: None,
                cors: None,
                timeout_secs: None,
                listener_hostname: listener_hostname_str,
                gateway_api: true,
            });

            group.paths.extend(paths);
            group.rewrites.extend(rewrites);
            if group.backend.is_empty() && !group.paths.is_empty() {
                group.backend = group.paths[0].backend.clone();
            }
        }
    }

    let mut result: Vec<RouteConfig> = groups.into_values().collect();
    result.sort_by(|a, b| a.host_prefix.cmp(&b.host_prefix));
    result
}

fn hostname_to_prefix(hostname: &HostnameMatch) -> String {
    match hostname {
        HostnameMatch::Exact(h) => h.to_string(),
        HostnameMatch::Wildcard(h) => format!("*.{}", h),
        HostnameMatch::Any => "*".to_string(),
    }
}

fn to_ir_hostname(h: &HostnameMatch) -> ir::HostnameMatch {
    match h {
        HostnameMatch::Exact(s) => ir::HostnameMatch::Exact(Arc::clone(s)),
        HostnameMatch::Wildcard(s) => ir::HostnameMatch::Wildcard(Arc::clone(s)),
        HostnameMatch::Any => ir::HostnameMatch::Any,
    }
}

fn translate_rule_paths(
    rule: &HTTPRouteRule,
    _namespace: &str,
    rule_idx: usize,
    unprogrammed: bool,
) -> Vec<PathRoute> {
    let weighted_backends: Vec<WeightedBackendConfig> = rule
        .backends
        .iter()
        .map(|b| WeightedBackendConfig {
            backend: b.backend.to_string(),
            weight: b.weight,
        })
        .collect();

    let dummy_backend = crate::gateway::model::WeightedBackend {
        backend: Arc::from("127.0.0.1:1"),
        weight: 1,
        protocol: crate::ir::BackendProtocol::Http,
        filters: vec![],
        tls: None,
    };
    let backend = rule.backends.first().unwrap_or(&dummy_backend);

    let strip_prefix = rule.filters.iter().any(|f| {
        matches!(
            f,
            RouteFilter::UrlRewrite {
                path: Some(PathRewrite::PrefixReplace { .. }),
                ..
            }
        )
    });

    let upstream_path_prefix = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            path: Some(PathRewrite::PrefixReplace { replacement, .. }),
            ..
        } => Some(replacement.to_string()),
        _ => None,
    });

    let path_rewrite_full = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            path: Some(PathRewrite::FullReplace(s)),
            ..
        } => Some(s.to_string()),
        _ => None,
    });

    let hostname_rewrite = rule.filters.iter().find_map(|f| match f {
        RouteFilter::UrlRewrite {
            hostname: Some(h), ..
        } => Some(h.to_string()),
        _ => None,
    });

    let mirror_backends: Vec<String> = rule
        .filters
        .iter()
        .filter_map(|f| match f {
            RouteFilter::RequestMirror { backend, .. } => Some(backend.to_string()),
            _ => None,
        })
        .collect();

    let cors_config = rule.filters.iter().find_map(|f| match f {
        RouteFilter::Cors {
            allow_origins,
            allow_methods,
            allow_headers,
            expose_headers,
            max_age,
            allow_credentials,
        } => Some(crate::config::CorsConfig {
            allow_origins: allow_origins.iter().map(|s| s.to_string()).collect(),
            allow_methods: allow_methods.iter().map(|s| s.to_string()).collect(),
            allow_headers: allow_headers.iter().map(|s| s.to_string()).collect(),
            expose_headers: expose_headers.iter().map(|s| s.to_string()).collect(),
            max_age: *max_age,
            allow_credentials: *allow_credentials,
        }),
        _ => None,
    });

    let mut redirect = None;
    let mut request_headers = Vec::new();
    let mut request_headers_add = Vec::new();
    let mut request_headers_remove = Vec::new();
    let mut response_headers = Vec::new();
    let mut response_headers_add = Vec::new();
    let mut response_headers_remove = Vec::new();

    for filter in &rule.filters {
        match filter {
            RouteFilter::RequestHeaderSet { name, value } => {
                request_headers.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::RequestHeaderAdd { name, value } => {
                request_headers_add.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::RequestHeaderRemove { name } => {
                request_headers_remove.push(name.to_string());
            }
            RouteFilter::ResponseHeaderSet { name, value } => {
                response_headers.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::ResponseHeaderAdd { name, value } => {
                response_headers_add.push(HeaderRule {
                    name: name.to_string(),
                    value: value.to_string(),
                });
            }
            RouteFilter::ResponseHeaderRemove { name } => {
                response_headers_remove.push(name.to_string());
            }
            RouteFilter::RequestRedirect {
                scheme,
                hostname,
                path,
                port,
                status_code,
            } => {
                redirect = Some(translate_redirect(
                    scheme,
                    hostname,
                    path,
                    *port,
                    *status_code,
                ));
            }
            _ => {}
        }
    }

    // Gateway API semantics: each RouteMatch within a rule is an independent
    // AND combination of path/headers/query/method; the list of matches is OR'd.
    // Create one PathRoute per RouteMatch so the proxy can evaluate them correctly.
    let mut result = Vec::new();

    if rule.matches.is_empty() {
        if let Some(pr) = build_path_route(
            &RouteMatch {
                path: None,
                headers: vec![],
                query_params: vec![],
                method: None,
            },
            backend,
            strip_prefix,
            upstream_path_prefix.clone(),
            path_rewrite_full.clone(),
            hostname_rewrite.clone(),
            rule.timeout_ms,
            mirror_backends.clone(),
            cors_config.clone(),
            &weighted_backends,
            redirect.clone(),
            &request_headers,
            &request_headers_add,
            &request_headers_remove,
            &response_headers,
            &response_headers_add,
            &response_headers_remove,
            rule_idx,
            unprogrammed,
        ) {
            result.push(pr);
        }
    } else {
        for m in &rule.matches {
            if let Some(pr) = build_path_route(
                m,
                backend,
                strip_prefix,
                upstream_path_prefix.clone(),
                path_rewrite_full.clone(),
                hostname_rewrite.clone(),
                rule.timeout_ms,
                mirror_backends.clone(),
                cors_config.clone(),
                &weighted_backends,
                redirect.clone(),
                &request_headers,
                &request_headers_add,
                &request_headers_remove,
                &response_headers,
                &response_headers_add,
                &response_headers_remove,
                rule_idx,
                unprogrammed,
            ) {
                result.push(pr);
            }
        }
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn build_path_route(
    m: &RouteMatch,
    backend: &crate::gateway::model::WeightedBackend,
    strip_prefix: bool,
    upstream_path_prefix: Option<String>,
    path_rewrite_full: Option<String>,
    hostname_rewrite: Option<String>,
    timeout_ms: Option<u64>,
    mirror_backends: Vec<String>,
    cors_config: Option<crate::config::CorsConfig>,
    weighted_backends: &[WeightedBackendConfig],
    redirect: Option<RedirectRule>,
    request_headers: &[HeaderRule],
    request_headers_add: &[HeaderRule],
    request_headers_remove: &[String],
    response_headers: &[HeaderRule],
    response_headers_add: &[HeaderRule],
    response_headers_remove: &[String],
    rule_idx: usize,
    gateway_api_unprogrammed: bool,
) -> Option<PathRoute> {
    let (prefix, path_match_exact) = match m.path.as_ref() {
        Some(PathMatch::Prefix(p)) => (p.to_string(), false),
        Some(PathMatch::Exact(p)) => (p.to_string(), true),
        Some(PathMatch::Regex(_)) => {
            tracing::debug!("Regex path match not supported in T1");
            return None;
        }
        None => ("/".to_string(), false),
    };
    let methods: Vec<String> = m
        .method
        .as_ref()
        .map(|s| vec![s.to_string()])
        .unwrap_or_default();
    let header_matches: Vec<HeaderMatchConfig> =
        m.headers.iter().map(translate_header_match).collect();
    let query_param_matches: Vec<QueryParamMatchConfig> = m
        .query_params
        .iter()
        .map(translate_query_param_match)
        .collect();

    // For RequestRedirect ReplacePrefixMatch, the matched path prefix must be
    // captured so the proxy can compute the correct Location header.
    let redirect = redirect.map(|mut r| {
        if r.path_prefix.is_some() {
            r.path_prefix = Some(prefix.clone());
        }
        r
    });

    Some(PathRoute {
        prefix,
        backend: backend.backend.to_string(),
        strip_prefix,
        websocket: false,
        auth_request: None,
        auth_capture_headers: vec![],
        upstream_path_prefix,
        path_rewrite_full,
        hostname_rewrite,
        timeout_secs: None,
        timeout_ms,
        mirror_backends,
        cors: cors_config,
        deny: false,
        gateway_api_unprogrammed,
        methods,
        weighted_backends: weighted_backends.to_vec(),
        redirect,
        header_matches,
        query_param_matches,
        rule_order: rule_idx,
        path_match_exact,
        request_headers: request_headers.to_vec(),
        request_headers_add: request_headers_add.to_vec(),
        request_headers_remove: request_headers_remove.to_vec(),
        response_headers: response_headers.to_vec(),
        response_headers_add: response_headers_add.to_vec(),
        response_headers_remove: response_headers_remove.to_vec(),
    })
}

fn translate_header_match(hm: &HeaderMatch) -> HeaderMatchConfig {
    HeaderMatchConfig {
        name: hm.name.to_string(),
        value: match &hm.value {
            HeaderMatchValue::Exact(v) => HeaderMatchValueConfig::Exact(v.to_string()),
            HeaderMatchValue::Regex(v) => HeaderMatchValueConfig::Regex(v.to_string()),
            HeaderMatchValue::Present => HeaderMatchValueConfig::Present,
            HeaderMatchValue::Absent => HeaderMatchValueConfig::Absent,
        },
    }
}

fn translate_query_param_match(qm: &QueryParamMatch) -> QueryParamMatchConfig {
    QueryParamMatchConfig {
        name: qm.name.to_string(),
        value: match &qm.value {
            QueryParamMatchValue::Exact(v) => QueryParamMatchValueConfig::Exact(v.to_string()),
            QueryParamMatchValue::Regex(v) => QueryParamMatchValueConfig::Regex(v.to_string()),
        },
    }
}

fn translate_redirect(
    scheme: &Option<Arc<str>>,
    hostname: &Option<Arc<str>>,
    path: &Option<PathRewrite>,
    port: Option<u16>,
    status_code: u16,
) -> RedirectRule {
    let (path, is_prefix_replace) = match path.as_ref() {
        Some(PathRewrite::FullReplace(target)) => (Some(target.to_string()), false),
        Some(PathRewrite::PrefixReplace { replacement, .. }) => {
            (Some(replacement.to_string()), true)
        }
        None => (None, false),
    };
    RedirectRule {
        status_code,
        scheme: scheme.as_ref().map(|s| s.to_string()),
        hostname: hostname.as_ref().map(|h| h.to_string()),
        port,
        path,
        path_prefix: if is_prefix_replace {
            Some(String::new())
        } else {
            None
        },
    }
}

fn translate_rewrite(path: &PathRewrite) -> Option<RewriteRule> {
    match path {
        PathRewrite::FullReplace(target) => Some(RewriteRule {
            pattern: "^/.*$".to_string(),
            target: target.to_string(),
        }),
        PathRewrite::PrefixReplace {
            prefix,
            replacement,
        } => Some(RewriteRule {
            pattern: format!("^{}", regex::escape(prefix)),
            target: replacement.to_string(),
        }),
    }
}

// ============================================================================
// IR translator (new canonical path)
// ============================================================================

fn to_ir_weighted_backend(b: &crate::gateway::model::WeightedBackend) -> ir::WeightedBackend {
    ir::WeightedBackend {
        backend: Arc::clone(&b.backend),
        weight: b.weight,
        request_filters: vec![],
        protocol: b.protocol,
        tls: b.tls.as_ref().map(|t| ir::BackendTlsConfig {
            sni: Arc::clone(&t.hostname),
            verify_hostname: true,
            alternative_cn: None,
            client_cert_id: None,
            ca_bundle_pem: if t.ca_bundle_pem.is_empty() {
                None
            } else {
                Some(Arc::clone(&t.ca_bundle_pem))
            },
            subject_alt_names: t.subject_alt_names.clone(),
        }),
    }
}

fn listener_protocol_to_ir(protocol: &str) -> Option<ir::Protocol> {
    match protocol {
        "HTTP" => Some(ir::Protocol::Http),
        "HTTPS" => Some(ir::Protocol::Https),
        "TCP" => Some(ir::Protocol::Tcp),
        "UDP" => Some(ir::Protocol::Udp),
        "TLS" => Some(ir::Protocol::Tls),
        _ => None,
    }
}

fn add_l4_listener(
    listeners: &mut BTreeMap<Arc<str>, ir::ListenerConfig>,
    gateway: &GatewayState,
    listener: &ListenerState,
) {
    let id: Arc<str> = Arc::from(format!(
        "{}/{}/{}",
        gateway.namespace.as_ref(),
        gateway.name.as_ref(),
        listener.name.as_ref()
    ));
    if listeners.contains_key(&id) {
        return;
    }
    let Some(protocol) = listener_protocol_to_ir(listener.protocol.as_ref()) else {
        return;
    };
    let tls = match protocol {
        ir::Protocol::Https | ir::Protocol::Tls => Some(ir::TlsConfig::Registry {
            cert_id: Arc::from("gateway"),
        }),
        _ => None,
    };
    listeners.insert(
        Arc::clone(&id),
        ir::ListenerConfig {
            id,
            bind_addr: Arc::from(format!("0.0.0.0:{}", listener.port)),
            protocol,
            tls,
            redirect_http_to_https: false,
            frontend_validation: listener.frontend_validation.as_ref().map(|v| {
                ir::FrontendValidation {
                    ca_bundle_pem: Arc::clone(&v.ca_bundle_pem),
                    allow_insecure_fallback: v.allow_insecure_fallback,
                }
            }),
        },
    );
}

/// Translate L4 route states into IR listeners and routes.
fn translate_l4_routes(view: &GatewayView) -> (Vec<ir::ListenerConfig>, Vec<ir::L4Route>) {
    let mut listeners: BTreeMap<Arc<str>, ir::ListenerConfig> = BTreeMap::new();
    let mut l4_routes = Vec::new();

    for route in &view.tcp_routes {
        if !route.programmed {
            continue;
        }
        let backends: Vec<_> = route.backends.iter().map(to_ir_weighted_backend).collect();
        let match_ = ir::L4Match::Any;
        add_l4_routes_for_parents(
            &view.gateways,
            route,
            "TCP",
            &match_,
            |_listener| ir::L4Action::TcpRelay(backends.clone()),
            &mut listeners,
            &mut l4_routes,
        );
    }

    for route in &view.udp_routes {
        if !route.programmed {
            continue;
        }
        let backends: Vec<_> = route.backends.iter().map(to_ir_weighted_backend).collect();
        let match_ = ir::L4Match::Any;
        add_l4_routes_for_parents(
            &view.gateways,
            route,
            "UDP",
            &match_,
            |_listener| ir::L4Action::UdpRelay(backends.clone()),
            &mut listeners,
            &mut l4_routes,
        );
    }

    // TLSRoutes attach to TLS listeners, but only for hostnames that intersect
    // with the listener's hostname. Each intersecting hostname becomes an SNI
    // match so that non-intersecting hostnames are rejected.
    for route in &view.tls_routes {
        if !route.programmed {
            continue;
        }
        let backends: Vec<_> = route.backends.iter().map(to_ir_weighted_backend).collect();
        for parent in &route.parent_refs {
            let gw_ns = parent
                .namespace
                .as_deref()
                .unwrap_or(route.namespace.as_ref());
            let Some(gateway) = view
                .gateways
                .iter()
                .find(|g| g.namespace.as_ref() == gw_ns && g.name.as_ref() == parent.name.as_ref())
            else {
                continue;
            };
            let section_filter = parent.section_name.as_deref();
            for listener in &gateway.listeners {
                if listener.protocol.as_ref() != "TLS" {
                    continue;
                }
                if let Some(section) = section_filter {
                    if listener.name.as_ref() != section {
                        continue;
                    }
                }
                let listener_match = listener
                    .hostname
                    .as_deref()
                    .map(parse_listener_hostname)
                    .unwrap_or(HostnameMatch::Any);
                let effective_hostnames: Vec<HostnameMatch> = if route.hostnames.is_empty() {
                    vec![listener_match.clone()]
                } else {
                    route
                        .hostnames
                        .iter()
                        .filter_map(|rh| intersect_hostname_pair(rh, &listener_match))
                        .collect()
                };
                if effective_hostnames.is_empty() {
                    continue;
                }
                add_l4_listener(&mut listeners, gateway, listener);
                let id: Arc<str> = Arc::from(format!(
                    "{}/{}/{}",
                    gateway.namespace.as_ref(),
                    gateway.name.as_ref(),
                    listener.name.as_ref()
                ));
                for hostname in effective_hostnames {
                    let action = if listener.tls_mode == Some(TlsMode::Terminate) {
                        ir::L4Action::TlsTerminate(backends.clone())
                    } else {
                        ir::L4Action::TlsPassthrough(backends.clone())
                    };
                    l4_routes.push(ir::L4Route {
                        listener_id: Arc::clone(&id),
                        listener_hostname: to_ir_hostname(&listener_match),
                        match_: ir::L4Match::Sni(to_ir_hostname(&hostname)),
                        action,
                    });
                }
            }
        }
    }

    // HTTPS listeners terminate TLS and forward decrypted HTTP to the local
    // Pingora plaintext service. The catch-all route matches only SNI hostnames
    // that fall within the listener's hostname so that unrelated TLS traffic is
    // not terminated by this listener.
    const HTTPS_HTTP_TARGET: &str = "127.0.0.1:10443";
    const HTTP_TARGET: &str = "127.0.0.1:10443";
    for gateway in &view.gateways {
        for listener in &gateway.listeners {
            if listener.protocol.as_ref() != "HTTPS" {
                continue;
            }
            add_l4_listener(&mut listeners, gateway, listener);
            let id: Arc<str> = Arc::from(format!(
                "{}/{}/{}",
                gateway.namespace.as_ref(),
                gateway.name.as_ref(),
                listener.name.as_ref()
            ));
            let listener_hostname = listener
                .hostname
                .as_deref()
                .map(|h| to_ir_hostname(&parse_listener_hostname(h)))
                .unwrap_or(ir::HostnameMatch::Any);
            let match_ = if listener.hostname.is_some() {
                ir::L4Match::Sni(listener_hostname.clone())
            } else {
                ir::L4Match::Any
            };
            l4_routes.push(ir::L4Route {
                listener_id: id,
                listener_hostname,
                match_,
                action: ir::L4Action::TerminateAndHttp(Arc::from(HTTPS_HTTP_TARGET)),
            });
        }
    }

    // Plain HTTP listeners are bound by the L4 manager and relayed to the
    // internal Pingora plaintext service. This supports Gateway API HTTP
    // listeners on arbitrary ports without requiring each port to be listed in
    // the static config. HTTP has no SNI, so every connection on the listener
    // is forwarded; host matching happens inside the HTTP proxy.
    for gateway in &view.gateways {
        for listener in &gateway.listeners {
            if listener.protocol.as_ref() != "HTTP" {
                continue;
            }
            add_l4_listener(&mut listeners, gateway, listener);
            let id: Arc<str> = Arc::from(format!(
                "{}/{}/{}",
                gateway.namespace.as_ref(),
                gateway.name.as_ref(),
                listener.name.as_ref()
            ));
            let listener_hostname = listener
                .hostname
                .as_deref()
                .map(|h| to_ir_hostname(&parse_listener_hostname(h)))
                .unwrap_or(ir::HostnameMatch::Any);
            l4_routes.push(ir::L4Route {
                listener_id: id,
                listener_hostname,
                match_: ir::L4Match::Any,
                action: ir::L4Action::HttpRelay(Arc::from(HTTP_TARGET)),
            });
        }
    }

    (listeners.into_values().collect(), l4_routes)
}

fn add_l4_routes_for_parents<S, F>(
    gateways: &[GatewayState],
    route: &S,
    expected_protocol: &str,
    match_: &ir::L4Match,
    action_for: F,
    listeners: &mut BTreeMap<Arc<str>, ir::ListenerConfig>,
    l4_routes: &mut Vec<ir::L4Route>,
) where
    S: L4RouteState,
    F: Fn(&ListenerState) -> ir::L4Action,
{
    for parent in route.parent_refs() {
        let gw_ns = parent
            .namespace
            .as_deref()
            .unwrap_or_else(|| route.namespace());
        let Some(gateway) = gateways
            .iter()
            .find(|g| g.namespace.as_ref() == gw_ns && g.name.as_ref() == parent.name.as_ref())
        else {
            continue;
        };

        let section_filter = parent.section_name.as_deref();
        for listener in &gateway.listeners {
            if listener.protocol.as_ref() != expected_protocol {
                continue;
            }
            if let Some(section) = section_filter {
                if listener.name.as_ref() != section {
                    continue;
                }
            }
            add_l4_listener(listeners, gateway, listener);
            let id: Arc<str> = Arc::from(format!(
                "{}/{}/{}",
                gateway.namespace.as_ref(),
                gateway.name.as_ref(),
                listener.name.as_ref()
            ));
            l4_routes.push(ir::L4Route {
                listener_id: id,
                listener_hostname: ir::HostnameMatch::Any,
                match_: match_.clone(),
                action: action_for(listener),
            });
        }
    }
}

trait L4RouteState {
    fn namespace(&self) -> &str;
    fn parent_refs(&self) -> &[crate::gateway::model::ParentRef];
}

impl L4RouteState for crate::gateway::model::TCPRouteState {
    fn namespace(&self) -> &str {
        self.namespace.as_ref()
    }
    fn parent_refs(&self) -> &[crate::gateway::model::ParentRef] {
        &self.parent_refs
    }
}

impl L4RouteState for crate::gateway::model::UDPRouteState {
    fn namespace(&self) -> &str {
        self.namespace.as_ref()
    }
    fn parent_refs(&self) -> &[crate::gateway::model::ParentRef] {
        &self.parent_refs
    }
}

impl L4RouteState for crate::gateway::model::TLSRouteState {
    fn namespace(&self) -> &str {
        self.namespace.as_ref()
    }
    fn parent_refs(&self) -> &[crate::gateway::model::ParentRef] {
        &self.parent_refs
    }
}

/// Translate a reconciled view into the canonical IR.
pub fn translate_view_to_ir(view: &GatewayView) -> ir::RouteTable {
    // Key: (listener_hostname_prefix, route_hostname_prefix, listener_port) —
    // merge rules from multiple HTTPRoutes attached to the same listener with
    // the same hostname and port.
    let mut groups: std::collections::HashMap<(String, String, Option<u16>), ir::HostRoute> =
        std::collections::HashMap::new();

    for http_route in &view.http_routes {
        if http_route.parent_refs.is_empty() {
            continue;
        }

        let effective = compute_effective_hostnames(http_route, view, "HTTPRoute");

        for eff in effective {
            let mut rules: Vec<ir::Rule> = Vec::new();

            for (rule_idx, rule) in http_route.rules.iter().enumerate() {
                let ir_rules = translate_rule_to_ir(
                    rule,
                    rule_idx,
                    rule.programmed,
                    eff.client_cert_id.clone(),
                );
                rules.extend(ir_rules);
            }

            // If no rules produced any matches, create a default catch-all.
            if rules.is_empty() && !http_route.rules.is_empty() {
                if http_route.programmed {
                    if let Some(first_backend) = http_route.rules[0].backends.first() {
                        let websocket = http_route.rules[0].backends.iter().any(|b| {
                            matches!(
                                b.protocol,
                                crate::ir::BackendProtocol::WebSocket
                                    | crate::ir::BackendProtocol::WebSocketSecure
                            )
                        });
                        rules.push(ir::Rule {
                            matches: vec![ir::RequestMatch::default()],
                            action: ir::Action::Route(ir::RouteAction {
                                backends: vec![ir::WeightedBackend::from(first_backend)],
                                timeout: http_route.rules[0].timeout_ms.map(Duration::from_millis),
                                request_filters: vec![],
                                response_filters: vec![],
                                mirror_backends: vec![],
                                mirror_fractions: vec![],
                                cache: None,
                                body_rewrites: vec![],
                                auth: None,
                                websocket,
                                disable_https_redirect: true,
                                client_cert_id: eff.client_cert_id.clone(),
                            }),
                            rule_order: 0,
                        });
                    }
                } else {
                    rules.push(ir::Rule {
                        matches: vec![ir::RequestMatch::default()],
                        action: unprogrammed_action(),
                        rule_order: 0,
                    });
                }
            }

            let hostname = to_ir_hostname(&eff.route_hostname);
            let listener_id = hostname_to_prefix(&eff.listener_hostname);
            let listener_hostname = match &eff.listener_hostname {
                HostnameMatch::Any => None,
                HostnameMatch::Exact(s) if s.is_empty() => {
                    Some(ir::HostnameMatch::Exact(Arc::clone(s)))
                }
                _ => Some(to_ir_hostname(&eff.listener_hostname)),
            };

            let key = (
                hostname_to_prefix(&eff.listener_hostname),
                hostname_to_prefix(&eff.route_hostname),
                eff.listener_port,
            );
            match groups.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    e.get_mut().rules.extend(rules);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(ir::HostRoute {
                        hostname,
                        listener_ids: if listener_id.is_empty() {
                            vec![]
                        } else {
                            vec![Arc::from(listener_id)]
                        },
                        listener_hostname,
                        listener_port: eff.listener_port,
                        gateway_api: true,
                        disable_secure_redirection: true,
                        rules,
                    });
                }
            }
        }
    }

    for grpc_route in &view.grpc_routes {
        if grpc_route.parent_refs.is_empty() {
            continue;
        }

        let effective = compute_effective_hostnames(grpc_route, view, "GRPCRoute");

        for eff in effective {
            let mut rules: Vec<ir::Rule> = Vec::new();

            for (rule_idx, rule) in grpc_route.rules.iter().enumerate() {
                let ir_rules = translate_grpc_rule_to_ir(
                    rule,
                    rule_idx,
                    rule.programmed,
                    eff.client_cert_id.clone(),
                );
                rules.extend(ir_rules);
            }

            if rules.is_empty() && !grpc_route.rules.is_empty() {
                if grpc_route.programmed {
                    if let Some(first_backend) = grpc_route.rules[0].backends.first() {
                        rules.push(ir::Rule {
                            matches: vec![ir::RequestMatch::default()],
                            action: ir::Action::Route(ir::RouteAction {
                                backends: vec![ir::WeightedBackend::from(first_backend)],
                                timeout: None,
                                request_filters: vec![],
                                response_filters: vec![],
                                mirror_backends: vec![],
                                mirror_fractions: vec![],
                                cache: None,
                                body_rewrites: vec![],
                                auth: None,
                                websocket: false,
                                disable_https_redirect: true,
                                client_cert_id: eff.client_cert_id.clone(),
                            }),
                            rule_order: 0,
                        });
                    }
                } else {
                    rules.push(ir::Rule {
                        matches: vec![ir::RequestMatch::default()],
                        action: unprogrammed_action(),
                        rule_order: 0,
                    });
                }
            }

            let hostname = to_ir_hostname(&eff.route_hostname);
            let listener_id = hostname_to_prefix(&eff.listener_hostname);
            let listener_hostname = match &eff.listener_hostname {
                HostnameMatch::Any => None,
                HostnameMatch::Exact(s) if s.is_empty() => {
                    Some(ir::HostnameMatch::Exact(Arc::clone(s)))
                }
                _ => Some(to_ir_hostname(&eff.listener_hostname)),
            };

            let key = (
                hostname_to_prefix(&eff.listener_hostname),
                hostname_to_prefix(&eff.route_hostname),
                eff.listener_port,
            );
            match groups.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    e.get_mut().rules.extend(rules);
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(ir::HostRoute {
                        hostname,
                        listener_ids: if listener_id.is_empty() {
                            vec![]
                        } else {
                            vec![Arc::from(listener_id)]
                        },
                        listener_hostname,
                        listener_port: eff.listener_port,
                        gateway_api: true,
                        disable_secure_redirection: true,
                        rules,
                    });
                }
            }
        }
    }

    let (l4_listeners, l4_routes) = translate_l4_routes(view);

    ir::RouteTable {
        listeners: l4_listeners,
        hosts: groups.into_values().collect(),
        acme_routes: std::collections::HashMap::new(),
        l4_routes,
        tls_certs: vec![],
    }
}

fn unprogrammed_action() -> ir::Action {
    ir::Action::FixedResponse(ir::FixedResponseAction {
        status: 500,
        headers: vec![],
        body: None,
    })
}

fn translate_rule_to_ir(
    rule: &HTTPRouteRule,
    rule_idx: usize,
    programmed: bool,
    client_cert_id: Option<Arc<str>>,
) -> Vec<ir::Rule> {
    let mut result: Vec<ir::Rule> = Vec::new();

    if !programmed {
        let matches = if rule.matches.is_empty() {
            vec![ir::RequestMatch::default()]
        } else {
            rule.matches.iter().map(ir::RequestMatch::from).collect()
        };
        for m in matches {
            result.push(ir::Rule {
                matches: vec![m],
                action: unprogrammed_action(),
                rule_order: rule_idx,
            });
        }
        return result;
    }

    if rule.matches.is_empty() {
        result.push(build_ir_rule(
            rule,
            ir::RequestMatch::default(),
            rule_idx,
            client_cert_id.clone(),
        ));
        return result;
    }

    for m in &rule.matches {
        result.push(build_ir_rule(
            rule,
            ir::RequestMatch::from(m),
            rule_idx,
            client_cert_id.clone(),
        ));
    }

    result
}

fn build_ir_rule(
    rule: &HTTPRouteRule,
    req_match: ir::RequestMatch,
    rule_idx: usize,
    client_cert_id: Option<Arc<str>>,
) -> ir::Rule {
    let mut request_filters: Vec<ir::RequestFilter> = Vec::new();
    let mut response_filters: Vec<ir::ResponseFilter> = Vec::new();
    let mut mirror_backends: Vec<Arc<str>> = Vec::new();
    let mut mirror_fractions: Vec<Option<ir::Fraction>> = Vec::new();
    let mut redirect: Option<ir::RedirectAction> = None;

    // Gateway API ReplacePrefixMatch uses the matched PathPrefix as the prefix
    // to replace. The reconciler hardcodes "/" because it lacks access to the
    // route match at parse time; fix it here using the request match path.
    let matched_prefix = req_match.path.as_ref().and_then(|p| match p {
        ir::PathMatch::Prefix(s) => Some(Arc::clone(s)),
        _ => None,
    });

    for filter in &rule.filters {
        match filter {
            RouteFilter::UrlRewrite { hostname, path } => {
                if let Some(h) = hostname {
                    request_filters.push(ir::RequestFilter::RewriteHostname(Arc::clone(h)));
                }
                if let Some(path) = path {
                    request_filters.push(ir::RequestFilter::RewritePath(
                        ir::PathRewrite::from(path).with_matched_prefix(matched_prefix.as_ref()),
                    ));
                }
            }
            RouteFilter::RequestHeaderSet { name, value } => {
                request_filters.push(ir::RequestFilter::SetHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::RequestHeaderAdd { name, value } => {
                request_filters.push(ir::RequestFilter::AddHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::RequestHeaderRemove { name } => {
                request_filters.push(ir::RequestFilter::RemoveHeader(Arc::clone(name)));
            }
            RouteFilter::ResponseHeaderSet { name, value } => {
                response_filters.push(ir::ResponseFilter::SetHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::ResponseHeaderAdd { name, value } => {
                response_filters.push(ir::ResponseFilter::AddHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::ResponseHeaderRemove { name } => {
                response_filters.push(ir::ResponseFilter::RemoveHeader(Arc::clone(name)));
            }
            RouteFilter::RequestRedirect {
                scheme,
                hostname,
                path,
                port,
                status_code,
            } => {
                redirect = Some(ir::RedirectAction {
                    status_code: *status_code,
                    scheme: scheme.as_ref().map(Arc::clone),
                    hostname: hostname.as_ref().map(Arc::clone),
                    port: *port,
                    path: path.as_ref().map(|p| {
                        ir::PathRewrite::from(p).with_matched_prefix(matched_prefix.as_ref())
                    }),
                });
            }
            RouteFilter::RequestMirror { backend, fraction } => {
                mirror_backends.push(Arc::clone(backend));
                mirror_fractions.push(fraction.map(|f| ir::Fraction {
                    numerator: f.numerator,
                    denominator: f.denominator,
                }));
            }
            RouteFilter::Cors {
                allow_origins,
                allow_methods,
                allow_headers,
                expose_headers,
                max_age,
                allow_credentials,
            } => {
                response_filters.push(ir::ResponseFilter::Cors(ir::CorsConfig {
                    allow_origins: allow_origins.iter().map(Arc::clone).collect(),
                    allow_methods: allow_methods.iter().map(Arc::clone).collect(),
                    allow_headers: allow_headers.iter().map(Arc::clone).collect(),
                    expose_headers: expose_headers.iter().map(Arc::clone).collect(),
                    max_age: *max_age,
                    allow_credentials: *allow_credentials,
                }));
            }
        }
    }

    let action = if let Some(r) = redirect {
        ir::Action::Redirect(r)
    } else {
        let effective_timeout = rule
            .request_timeout_ms
            .filter(|&s| s > 0)
            .or(rule.timeout_ms.filter(|&s| s > 0));
        let websocket = rule.backends.iter().any(|b| {
            matches!(
                b.protocol,
                crate::ir::BackendProtocol::WebSocket | crate::ir::BackendProtocol::WebSocketSecure
            )
        });
        ir::Action::Route(ir::RouteAction {
            backends: rule
                .backends
                .iter()
                .map(ir::WeightedBackend::from)
                .collect(),
            timeout: effective_timeout.map(Duration::from_millis),
            request_filters,
            response_filters,
            mirror_backends,
            mirror_fractions,
            cache: None,
            body_rewrites: vec![],
            auth: None,
            websocket,
            disable_https_redirect: true,
            client_cert_id,
        })
    };

    ir::Rule {
        matches: vec![req_match],
        action,
        rule_order: rule_idx,
    }
}

fn grpc_match_to_route_match(m: &GRPCRouteMatch) -> RouteMatch {
    let path = m
        .method
        .as_ref()
        .and_then(|method| match method.match_type {
            MethodMatchType::Exact => method.exact_path().map(PathMatch::Exact),
            MethodMatchType::Regular => {
                if method.service.is_empty() {
                    None
                } else {
                    Some(PathMatch::Prefix(Arc::from(format!(
                        "/{}/",
                        method.service
                    ))))
                }
            }
        });
    RouteMatch {
        path,
        headers: m.headers.clone(),
        query_params: vec![],
        method: None,
    }
}

fn translate_grpc_rule_to_ir(
    rule: &GRPCRouteRule,
    rule_idx: usize,
    programmed: bool,
    client_cert_id: Option<Arc<str>>,
) -> Vec<ir::Rule> {
    let mut result: Vec<ir::Rule> = Vec::new();

    if !programmed {
        let matches = if rule.matches.is_empty() {
            vec![ir::RequestMatch::default()]
        } else {
            rule.matches
                .iter()
                .map(|m| ir::RequestMatch::from(&grpc_match_to_route_match(m)))
                .collect()
        };
        for m in matches {
            result.push(ir::Rule {
                matches: vec![m],
                action: unprogrammed_action(),
                rule_order: rule_idx,
            });
        }
        return result;
    }

    if rule.matches.is_empty() {
        result.push(build_ir_rule_from_grpc(
            rule,
            ir::RequestMatch::default(),
            rule_idx,
            client_cert_id.clone(),
        ));
        return result;
    }

    for m in &rule.matches {
        let route_match = grpc_match_to_route_match(m);
        result.push(build_ir_rule_from_grpc(
            rule,
            ir::RequestMatch::from(&route_match),
            rule_idx,
            client_cert_id.clone(),
        ));
    }

    result
}

fn build_ir_rule_from_grpc(
    rule: &GRPCRouteRule,
    req_match: ir::RequestMatch,
    rule_idx: usize,
    client_cert_id: Option<Arc<str>>,
) -> ir::Rule {
    let mut request_filters: Vec<ir::RequestFilter> = Vec::new();
    let mut response_filters: Vec<ir::ResponseFilter> = Vec::new();

    for filter in &rule.filters {
        match filter {
            RouteFilter::RequestHeaderSet { name, value } => {
                request_filters.push(ir::RequestFilter::SetHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::RequestHeaderAdd { name, value } => {
                request_filters.push(ir::RequestFilter::AddHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::RequestHeaderRemove { name } => {
                request_filters.push(ir::RequestFilter::RemoveHeader(Arc::clone(name)));
            }
            RouteFilter::ResponseHeaderSet { name, value } => {
                response_filters.push(ir::ResponseFilter::SetHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::ResponseHeaderAdd { name, value } => {
                response_filters.push(ir::ResponseFilter::AddHeader {
                    name: Arc::clone(name),
                    value: Arc::clone(value),
                });
            }
            RouteFilter::ResponseHeaderRemove { name } => {
                response_filters.push(ir::ResponseFilter::RemoveHeader(Arc::clone(name)));
            }
            _ => {}
        }
    }

    let action = ir::Action::Route(ir::RouteAction {
        backends: rule
            .backends
            .iter()
            .map(ir::WeightedBackend::from)
            .collect(),
        timeout: None,
        request_filters,
        response_filters,
        mirror_backends: vec![],
        mirror_fractions: vec![],
        cache: None,
        body_rewrites: vec![],
        auth: None,
        websocket: false,
        disable_https_redirect: true,
        client_cert_id,
    });

    ir::Rule {
        matches: vec![req_match],
        action,
        rule_order: rule_idx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::{
        BackendTlsAttachment, GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, GatewayState,
        HTTPRouteState, HeaderMatch, HeaderMatchValue, HostnameMatch, ListenerState, MethodMatch,
        MethodMatchType, ParentRef, PathMatch, PathRewrite, RouteFilter, RouteMatch, TCPRouteState,
        TLSRouteState, UDPRouteState, WeightedBackend,
    };
    use crate::ir::compile::CompiledRouteTable;
    use std::sync::Arc;

    fn make_view(routes: Vec<HTTPRouteState>) -> GatewayView {
        GatewayView {
            http_routes: routes,
            ..Default::default()
        }
    }

    fn simple_route(hostnames: Vec<&str>, backend: &str) -> HTTPRouteState {
        HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("test-route"),
            generation: 1,
            hostnames: hostnames
                .into_iter()
                .map(|h| HostnameMatch::Exact(Arc::from(h)))
                .collect(),
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from(backend),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        }
    }

    #[test]
    fn translate_single_hostname_route() {
        let view = make_view(vec![simple_route(vec!["example.com"], "10.0.0.1:80")]);
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].host_prefix, "example.com");
        assert_eq!(configs[0].paths[0].backend, "10.0.0.1:80");
        assert_eq!(configs[0].paths[0].prefix, "/");
    }

    #[test]
    fn translate_multiple_hostnames_creates_multiple_configs() {
        let view = make_view(vec![simple_route(
            vec!["a.example.com", "b.example.com"],
            "10.0.0.1:80",
        )]);
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].host_prefix, "a.example.com");
        assert_eq!(configs[1].host_prefix, "b.example.com");
    }

    #[test]
    fn translate_path_prefix_match() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("api-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("api.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/v1"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("api-svc:8080"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].prefix, "/v1");
        assert_eq!(configs[0].paths[0].backend, "api-svc:8080");
    }

    #[test]
    fn translate_url_rewrite_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("rewrite-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("app.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/api"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("backend:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::UrlRewrite {
                    hostname: None,
                    path: Some(PathRewrite::PrefixReplace {
                        prefix: Arc::from("/api"),
                        replacement: Arc::from("/v2"),
                    }),
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let path = &configs[0].paths[0];
        assert!(path.strip_prefix);
        assert_eq!(path.upstream_path_prefix, Some("/v2".to_string()));
        assert_eq!(configs[0].rewrites[0].target, "/v2");
    }

    #[test]
    fn translate_response_header_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("header-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("hdr.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::ResponseHeaderAdd {
                    name: Arc::from("X-Custom"),
                    value: Arc::from("value"),
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].response_headers_add.len(), 1);
        assert_eq!(configs[0].paths[0].response_headers_add[0].name, "X-Custom");
        assert_eq!(configs[0].paths[0].response_headers_add[0].value, "value");
    }

    #[test]
    fn translate_skips_routes_without_parent_refs() {
        let mut route = simple_route(vec!["orphan.example.com"], "10.0.0.1:80");
        route.parent_refs.clear();
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert!(configs.is_empty());
    }

    #[test]
    fn translate_wildcard_hostname() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Wildcard(Arc::from("example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].host_prefix, "*.example.com");
    }

    #[test]
    fn translate_method_match() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("method-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("m.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: Some(Arc::from("POST")),
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].methods, vec!["POST"]);
    }

    #[test]
    fn translate_weighted_backends() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("split-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("split.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![
                    WeightedBackend {
                        backend: Arc::from("svc-a:80"),
                        weight: 3,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    },
                    WeightedBackend {
                        backend: Arc::from("svc-b:80"),
                        weight: 7,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    },
                ],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].weighted_backends.len(), 2);
        assert_eq!(configs[0].paths[0].weighted_backends[0].backend, "svc-a:80");
        assert_eq!(configs[0].paths[0].weighted_backends[0].weight, 3);
        assert_eq!(configs[0].paths[0].weighted_backends[1].backend, "svc-b:80");
        assert_eq!(configs[0].paths[0].weighted_backends[1].weight, 7);
    }

    #[test]
    fn translate_request_header_modifier() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("req-hdr-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("req-hdr.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::RequestHeaderAdd {
                    name: Arc::from("X-In"),
                    value: Arc::from("in-value"),
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].request_headers_add.len(), 1);
        assert_eq!(configs[0].paths[0].request_headers_add[0].name, "X-In");
        assert_eq!(configs[0].paths[0].request_headers_add[0].value, "in-value");
    }

    #[test]
    fn translate_request_redirect_filter() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("redirect-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("redirect.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/old"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: Some(Arc::from("https")),
                    hostname: Some(Arc::from("new.example.com")),
                    port: Some(8443),
                    status_code: 308,
                    path: Some(PathRewrite::FullReplace(Arc::from("/new"))),
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let redirect = configs[0].paths[0].redirect.as_ref().unwrap();
        assert_eq!(redirect.status_code, 308);
        assert_eq!(redirect.scheme.as_deref(), Some("https"));
        assert_eq!(redirect.hostname.as_deref(), Some("new.example.com"));
        assert_eq!(redirect.port, Some(8443));
        assert_eq!(redirect.path.as_deref(), Some("/new"));
        assert_eq!(redirect.path_prefix.as_deref(), None);
    }

    #[test]
    fn translate_request_redirect_prefix_replace_captures_matched_prefix() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("redirect-prefix-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("redirect.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/original-prefix"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: None,
                    hostname: None,
                    port: None,
                    status_code: 302,
                    path: Some(PathRewrite::PrefixReplace {
                        prefix: Arc::from("/"),
                        replacement: Arc::from("/replacement-prefix"),
                    }),
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        let redirect = configs[0].paths[0].redirect.as_ref().unwrap();
        assert_eq!(redirect.path.as_deref(), Some("/replacement-prefix"));
        assert_eq!(redirect.path_prefix.as_deref(), Some("/original-prefix"));
    }

    #[test]
    fn hostname_subset_exact_exact() {
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.example.com")),
            &HostnameMatch::Exact(Arc::from("foo.example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("bar.example.com")),
            &HostnameMatch::Exact(Arc::from("foo.example.com"))
        ));
    }

    #[test]
    fn hostname_subset_exact_wildcard() {
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        // Multi-level subdomains are valid for intersection (Gateway API semantics).
        assert!(is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("foo.bar.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Exact(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
    }

    #[test]
    fn hostname_subset_wildcard_wildcard() {
        assert!(is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("foo.example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
        assert!(!is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("foo.example.com"))
        ));
        assert!(is_hostname_subset(
            &HostnameMatch::Wildcard(Arc::from("example.com")),
            &HostnameMatch::Wildcard(Arc::from("example.com"))
        ));
    }

    #[test]
    fn hostname_intersection_filters_non_subset() {
        let route = vec![
            HostnameMatch::Exact(Arc::from("bar.com")),
            HostnameMatch::Wildcard(Arc::from("example.com")),
            HostnameMatch::Wildcard(Arc::from("foo.example.com")),
            HostnameMatch::Exact(Arc::from("abc.foo.example.com")),
        ];
        let result = intersect_hostnames(&route, Some("*.example.com"));
        assert_eq!(result.len(), 3);
        assert!(!result.contains(&HostnameMatch::Exact(Arc::from("bar.com"))));
        assert!(result.contains(&HostnameMatch::Wildcard(Arc::from("example.com"))));
        assert!(result.contains(&HostnameMatch::Wildcard(Arc::from("foo.example.com"))));
        assert!(result.contains(&HostnameMatch::Exact(Arc::from("abc.foo.example.com"))));
    }

    #[test]
    fn translate_multiple_matches_in_rule_are_or_d() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("or-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("or.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![
                    RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/path3"))),
                        headers: vec![],
                        query_params: vec![],
                        method: Some(Arc::from("PATCH")),
                    },
                    RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/path4"))),
                        headers: vec![HeaderMatch {
                            name: Arc::from("version"),
                            value: HeaderMatchValue::Exact(Arc::from("three")),
                        }],
                        query_params: vec![],
                        method: Some(Arc::from("DELETE")),
                    },
                ],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths.len(), 2);
        assert_eq!(configs[0].paths[0].prefix, "/path3");
        assert_eq!(configs[0].paths[0].methods, vec!["PATCH"]);
        assert!(configs[0].paths[0].header_matches.is_empty());
        assert_eq!(configs[0].paths[1].prefix, "/path4");
        assert_eq!(configs[0].paths[1].methods, vec!["DELETE"]);
        assert_eq!(configs[0].paths[1].header_matches.len(), 1);
    }

    #[test]
    fn translate_preserves_rule_order_for_tie_breaking() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("order-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("order.example.com"))],
            rules: vec![
                HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/"))),
                        headers: vec![],
                        query_params: vec![],
                        method: Some(Arc::from("PATCH")),
                    }],
                    backends: vec![WeightedBackend {
                        backend: Arc::from("v2:80"),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    }],
                    filters: vec![],
                },
                HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from("/"))),
                        headers: vec![HeaderMatch {
                            name: Arc::from("version"),
                            value: HeaderMatchValue::Exact(Arc::from("four")),
                        }],
                        query_params: vec![],
                        method: None,
                    }],
                    backends: vec![WeightedBackend {
                        backend: Arc::from("v3:80"),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    }],
                    filters: vec![],
                },
            ],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs[0].paths[0].rule_order, 0);
        assert_eq!(configs[0].paths[1].rule_order, 1);
    }

    // ------------------------------------------------------------------
    // IR translator tests
    // ------------------------------------------------------------------

    #[test]
    fn translate_view_to_ir_any_hostname_for_empty_listener_and_route() {
        let gateway = crate::gateway::model::GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![crate::gateway::model::ListenerState {
                name: Arc::from("http"),
                hostname: None,
                port: 80,
                protocol: Arc::from("HTTP"),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("test-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        assert_eq!(table.hosts.len(), 1);
        assert_eq!(table.hosts[0].hostname, crate::ir::HostnameMatch::Any);
        assert_eq!(
            table.hosts[0].listener_hostname,
            Some(crate::ir::HostnameMatch::Exact(Arc::from("")))
        );
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        assert!(compiled
            .lookup("", 80, "/", "GET", &headers, None)
            .is_some());
        assert!(compiled
            .lookup("example.com", 80, "/", "GET", &headers, None)
            .is_some());
    }

    #[test]
    fn translate_view_to_ir_route_hostnames_with_empty_listener() {
        let gateway = crate::gateway::model::GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![crate::gateway::model::ListenerState {
                name: Arc::from("http"),
                hostname: None,
                port: 80,
                protocol: Arc::from("HTTP"),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("test-route"),
            generation: 1,
            hostnames: vec![
                HostnameMatch::Exact(Arc::from("first.com")),
                HostnameMatch::Exact(Arc::from("sub.first.com")),
                HostnameMatch::Exact(Arc::from("second.com")),
                HostnameMatch::Exact(Arc::from("sub.second.com")),
            ],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        assert_eq!(table.hosts.len(), 4);
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        assert!(compiled
            .lookup("first.com", 80, "/", "GET", &headers, None)
            .is_some());
        assert!(compiled
            .lookup("third.com", 80, "/", "GET", &headers, None)
            .is_none());
        assert!(compiled
            .lookup("sub.third.com", 80, "/", "GET", &headers, None)
            .is_none());
    }

    #[test]
    fn translate_view_to_ir_unprogrammed_route_returns_500() {
        let gateway = crate::gateway::model::GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![crate::gateway::model::ListenerState {
                name: Arc::from("http"),
                hostname: None,
                port: 80,
                protocol: Arc::from("HTTP"),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("unprogrammed-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: false,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: false,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        assert_eq!(table.hosts.len(), 1);
        let rule = &table.hosts[0].rules[0];
        assert_eq!(rule.matches.len(), 1);
        assert!(
            matches!(&rule.action, crate::ir::Action::FixedResponse(resp) if resp.status == 500),
            "unprogrammed route should return 500, got {:?}",
            rule.action
        );
    }

    #[test]
    fn translate_view_to_ir_fixes_redirect_prefix_replace() {
        let gateway = crate::gateway::model::GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![crate::gateway::model::ListenerState {
                name: Arc::from("http"),
                hostname: None,
                port: 80,
                protocol: Arc::from("HTTP"),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("redirect-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/api"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: None,
                    hostname: None,
                    path: Some(PathRewrite::PrefixReplace {
                        prefix: Arc::from("/"),
                        replacement: Arc::from("/v2"),
                    }),
                    port: None,
                    status_code: 302,
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        assert_eq!(table.hosts.len(), 1);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Redirect(redirect) = &rule.action {
            if let Some(crate::ir::PathRewrite::PrefixReplace {
                prefix,
                replacement,
            }) = &redirect.path
            {
                assert_eq!(prefix.as_ref(), "/api");
                assert_eq!(replacement.as_ref(), "/v2");
            } else {
                panic!("expected PrefixReplace");
            }
        } else {
            panic!("expected Redirect action");
        }
    }

    #[test]
    fn debug_both_routes_lookup_wildcard() {
        let gateway = GatewayState {
            namespace: Arc::from("infra"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("empty-hostname"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("wildcard-example-com"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.example.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        };
        let empty_route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("empty-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/empty-hostname"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("empty-backend.infra.svc.cluster.local.:8080"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("empty-hostname")),
                port: None,
            }],
            programmed: true,
        };
        let wildcard_route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("wildcard-backend.infra.svc.cluster.local.:8080"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("wildcard-example-com")),
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![empty_route, wildcard_route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        let plan = compiled.lookup(
            "bar.example.com",
            80,
            "/wildcard-example-com",
            "GET",
            &headers,
            None,
        );
        assert!(plan.is_some(), "expected wildcard plan");
        let plan = plan.unwrap();
        assert!(plan.upstream.is_some(), "expected upstream");
        assert_eq!(
            plan.upstream.as_ref().unwrap().backends[0].backend.as_ref(),
            "wildcard-backend.infra.svc.cluster.local.:8080"
        );
    }

    #[test]
    fn listener_isolation_empty_listener_loses_to_wildcard_listener() {
        // A route on an empty-hostname listener is a catch-all but must not
        // receive traffic for hosts that match a more specific listener.
        let gateway = GatewayState {
            namespace: Arc::from("infra"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("empty-hostname"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("wildcard-example-com"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.example.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        };
        let empty_route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("empty-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/empty-hostname"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("empty-hostname")),
                port: None,
            }],
            programmed: true,
        };
        let wildcard_route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("wildcard-example-com")),
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![empty_route, wildcard_route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        // Empty-listener route is used when no more specific listener matches.
        assert!(compiled
            .lookup("bar.com", 80, "/empty-hostname", "GET", &headers, None)
            .is_some());
        assert!(compiled
            .lookup(
                "bar.example.com",
                80,
                "/empty-hostname",
                "GET",
                &headers,
                None
            )
            .is_none());
        // Wildcard-listener route is used for matching hosts.
        assert!(compiled
            .lookup(
                "bar.example.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_some());
        assert!(compiled
            .lookup(
                "bar.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_none());
    }

    #[test]
    fn debug_wildcard_route_has_upstream() {
        let gateway = GatewayState {
            namespace: Arc::from("infra"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("wildcard-example-com"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("infra-backend-v1.infra.svc.cluster.local.:8080"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("wildcard-example-com")),
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        let plan = compiled.lookup(
            "bar.example.com",
            80,
            "/wildcard-example-com",
            "GET",
            &headers,
            None,
        );
        assert!(plan.is_some(), "expected plan for wildcard route");
        assert!(
            plan.unwrap().upstream.is_some(),
            "expected upstream action in plan"
        );
    }

    #[test]
    fn listener_isolation_wildcard_listener_matches_subdomain() {
        // Gateway listener *.example.com + route with no hostnames should match
        // bar.example.com for the listener's path.
        let gateway = GatewayState {
            namespace: Arc::from("infra"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("wildcard-example-com"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("wildcard-route"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/wildcard-example-com"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("gw"),
                section_name: Some(Arc::from("wildcard-example-com")),
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let compiled = crate::ir::compile::CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        assert!(compiled
            .lookup(
                "bar.example.com",
                80,
                "/wildcard-example-com",
                "GET",
                &headers,
                None
            )
            .is_some());
    }

    #[test]
    fn translate_rewrite_full_replace() {
        let rewrite = translate_rewrite(&PathRewrite::FullReplace(Arc::from("/new")));
        assert_eq!(rewrite.as_ref().unwrap().pattern, "^/.*$");
        assert_eq!(rewrite.as_ref().unwrap().target, "/new");
    }

    #[test]
    fn translate_rewrite_prefix_replace() {
        let rewrite = translate_rewrite(&PathRewrite::PrefixReplace {
            prefix: Arc::from("/api"),
            replacement: Arc::from("/v2"),
        });
        assert_eq!(rewrite.as_ref().unwrap().pattern, "^/api");
        assert_eq!(rewrite.as_ref().unwrap().target, "/v2");
    }

    #[test]
    fn translate_redirect_full_replace_no_prefix() {
        let rule = translate_redirect(
            &Some(Arc::from("https")),
            &Some(Arc::from("new.example.com")),
            &Some(PathRewrite::FullReplace(Arc::from("/redirected"))),
            Some(8443),
            307,
        );
        assert_eq!(rule.status_code, 307);
        assert_eq!(rule.scheme.as_deref(), Some("https"));
        assert_eq!(rule.hostname.as_deref(), Some("new.example.com"));
        assert_eq!(rule.port, Some(8443));
        assert_eq!(rule.path.as_deref(), Some("/redirected"));
        assert_eq!(rule.path_prefix.as_deref(), None);
    }

    #[test]
    fn translate_redirect_prefix_replace_has_prefix() {
        let rule = translate_redirect(
            &None,
            &None,
            &Some(PathRewrite::PrefixReplace {
                prefix: Arc::from("/"),
                replacement: Arc::from("/v2"),
            }),
            None,
            302,
        );
        assert_eq!(rule.path.as_deref(), Some("/v2"));
        assert_eq!(rule.path_prefix.as_deref(), Some(""));
    }

    #[test]
    fn build_path_route_skips_regex_path_match() {
        let rule = HTTPRouteRule {
            programmed: true,
            timeout_ms: None,
            request_timeout_ms: None,
            matches: vec![RouteMatch {
                path: Some(PathMatch::Regex(Arc::from("^/api/.*$"))),
                headers: vec![],
                query_params: vec![],
                method: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("svc:80"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,

                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        };
        let paths = translate_rule_paths(&rule, "default", 0, false);
        assert!(paths.is_empty());
    }

    #[test]
    fn compute_effective_hostnames_intersects_with_listener_hostname() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("route"),
            generation: 1,
            hostnames: vec![
                HostnameMatch::Exact(Arc::from("foo.example.com")),
                HostnameMatch::Exact(Arc::from("bar.other.com")),
            ],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].host_prefix, "foo.example.com");
    }

    #[test]
    fn translate_query_param_match_to_ir() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("query-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("query.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![
                        QueryParamMatch {
                            name: Arc::from("page"),
                            value: QueryParamMatchValue::Exact(Arc::from("1")),
                        },
                        QueryParamMatch {
                            name: Arc::from("filter"),
                            value: QueryParamMatchValue::Regex(Arc::from(".*")),
                        },
                    ],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        let matches = &rule.matches[0];
        assert_eq!(matches.query_params.len(), 2);
        assert_eq!(
            matches.query_params[0],
            crate::ir::QueryParamMatch {
                name: Arc::from("page"),
                value: crate::ir::QueryParamMatchValue::Exact(Arc::from("1")),
            }
        );
        assert_eq!(
            matches.query_params[1],
            crate::ir::QueryParamMatch {
                name: Arc::from("filter"),
                value: crate::ir::QueryParamMatchValue::Regex(Arc::from(".*")),
            }
        );
    }

    #[test]
    fn translate_view_to_ir_request_response_filters() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("filter-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("filter.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![
                    RouteFilter::RequestHeaderSet {
                        name: Arc::from("X-In"),
                        value: Arc::from("in"),
                    },
                    RouteFilter::ResponseHeaderSet {
                        name: Arc::from("X-Out"),
                        value: Arc::from("out"),
                    },
                    RouteFilter::RequestHeaderRemove {
                        name: Arc::from("X-Old"),
                    },
                ],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert_eq!(action.request_filters.len(), 2);
            assert_eq!(action.response_filters.len(), 1);
        } else {
            panic!("expected Route action");
        }
    }

    #[test]
    fn translate_view_to_ir_hostname_rewrite() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("host-rewrite"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("host.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::UrlRewrite {
                    hostname: Some(Arc::from("upstream.example.com")),
                    path: None,
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert!(action
                .request_filters
                .iter()
                .any(|f| matches!(f, crate::ir::RequestFilter::RewriteHostname(h) if h.as_ref() == "upstream.example.com")));
        } else {
            panic!("expected Route action");
        }
    }

    #[test]
    fn translate_view_to_ir_cors_filter() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("cors-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("cors.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::Cors {
                    allow_origins: vec![Arc::from("*")],
                    allow_methods: vec![Arc::from("GET")],
                    allow_headers: vec![Arc::from("X-Custom")],
                    expose_headers: vec![],
                    max_age: Some(600),
                    allow_credentials: false,
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert!(action
                .response_filters
                .iter()
                .any(|f| matches!(f, crate::ir::ResponseFilter::Cors(_))));
        } else {
            panic!("expected Route action");
        }
    }

    #[test]
    fn translate_view_to_ir_request_mirror() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("mirror-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("mirror.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![RouteFilter::RequestMirror {
                    backend: Arc::from("mirror-svc:80"),
                    fraction: None,
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert_eq!(action.mirror_backends.len(), 1);
            assert_eq!(action.mirror_backends[0].as_ref(), "mirror-svc:80");
        } else {
            panic!("expected Route action");
        }
    }

    #[test]
    fn translate_unprogrammed_route_keeps_path_and_marks_unprogrammed() {
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("unprogrammed-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("invalid.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: false,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("nonexistent-svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,

                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: false,
        };
        let view = make_view(vec![route]);
        let configs = translate_view(&view);
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].paths.len(), 1);
        assert!(configs[0].paths[0].gateway_api_unprogrammed);
    }

    #[test]
    fn listener_hostname_isolation_matches_conformance_scenario() {
        // Reproduces the HTTPRouteListenerHostnameMatching conformance Gateway:
        // four HTTP listeners with distinct hostnames, three HTTPRoutes attached
        // by sectionName and with no route hostnames.
        let gateway = GatewayState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("httproute-listener-hostname-matching"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("listener-1"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-2"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("foo.bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-3"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-4"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.foo.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        };

        fn route_for_listener(name: &str, listener: &str, backend: &str) -> HTTPRouteState {
            HTTPRouteState {
                namespace: Arc::from("gateway-conformance-infra"),
                name: Arc::from(name),
                generation: 1,
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![],
                    backends: vec![WeightedBackend {
                        backend: Arc::from(backend),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    }],
                    filters: vec![],
                }],
                parent_refs: vec![ParentRef {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("Gateway"),

                    namespace: Some(Arc::from("gateway-conformance-infra")),
                    name: Arc::from("httproute-listener-hostname-matching"),
                    section_name: Some(Arc::from(listener)),
                    port: None,
                }],
                programmed: true,
            }
        }

        let routes = vec![
            route_for_listener("backend-v1", "listener-1", "infra-backend-v1:8080"),
            route_for_listener("backend-v2", "listener-2", "infra-backend-v2:8080"),
            route_for_listener("backend-v3", "listener-3", "infra-backend-v3:8080"),
            route_for_listener("backend-v3", "listener-4", "infra-backend-v3:8080"),
        ];

        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: routes,
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };

        let ir = translate_view_to_ir(&view);
        let compiled = CompiledRouteTable::compile(ir).unwrap();

        fn backend_for(compiled: &CompiledRouteTable, host: &str) -> Option<Arc<str>> {
            let plan = compiled.lookup(host, 80, "/", "GET", &Default::default(), None)?;
            plan.upstream
                .as_ref()
                .map(|u| Arc::clone(&u.backends[0].backend))
        }

        assert_eq!(
            backend_for(&compiled, "bar.com").as_deref(),
            Some("infra-backend-v1:8080")
        );
        assert_eq!(
            backend_for(&compiled, "foo.bar.com").as_deref(),
            Some("infra-backend-v2:8080")
        );
        assert_eq!(
            backend_for(&compiled, "multiple.prefixes.bar.com").as_deref(),
            Some("infra-backend-v3:8080")
        );
        assert_eq!(
            backend_for(&compiled, "one.foo.com").as_deref(),
            Some("infra-backend-v3:8080")
        );
    }

    #[test]
    fn single_route_with_multiple_parent_refs_matches_conformance_scenario() {
        // Same scenario as above, but backend-v3 is a single HTTPRoute with two
        // parentRefs (listener-3 and listener-4) just like the real conformance
        // manifest, instead of two separate route states.
        let gateway = GatewayState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("httproute-listener-hostname-matching"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("listener-1"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-2"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("foo.bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-3"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.bar.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-4"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.foo.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        };

        fn route(name: &str, listeners: &[&str], backend: &str) -> HTTPRouteState {
            HTTPRouteState {
                namespace: Arc::from("gateway-conformance-infra"),
                name: Arc::from(name),
                generation: 1,
                hostnames: vec![],
                rules: vec![HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![],
                    backends: vec![WeightedBackend {
                        backend: Arc::from(backend),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    }],
                    filters: vec![],
                }],
                parent_refs: listeners
                    .iter()
                    .map(|l| ParentRef {
                        group: Arc::from("gateway.networking.k8s.io"),
                        kind: Arc::from("Gateway"),

                        namespace: Some(Arc::from("gateway-conformance-infra")),
                        name: Arc::from("httproute-listener-hostname-matching"),
                        section_name: Some(Arc::from(*l)),
                        port: None,
                    })
                    .collect(),
                programmed: true,
            }
        }

        let routes = vec![
            route("backend-v1", &["listener-1"], "infra-backend-v1:8080"),
            route("backend-v2", &["listener-2"], "infra-backend-v2:8080"),
            route(
                "backend-v3",
                &["listener-3", "listener-4"],
                "infra-backend-v3:8080",
            ),
        ];

        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: routes,
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };

        let ir = translate_view_to_ir(&view);
        let compiled = CompiledRouteTable::compile(ir).unwrap();

        fn backend_for(compiled: &CompiledRouteTable, host: &str) -> Option<Arc<str>> {
            let plan = compiled.lookup(host, 80, "/", "GET", &Default::default(), None)?;
            plan.upstream
                .as_ref()
                .map(|u| Arc::clone(&u.backends[0].backend))
        }

        assert_eq!(
            backend_for(&compiled, "bar.com").as_deref(),
            Some("infra-backend-v1:8080")
        );
        assert_eq!(
            backend_for(&compiled, "foo.bar.com").as_deref(),
            Some("infra-backend-v2:8080")
        );
        assert_eq!(
            backend_for(&compiled, "multiple.prefixes.bar.com").as_deref(),
            Some("infra-backend-v3:8080")
        );
        assert_eq!(
            backend_for(&compiled, "one.foo.com").as_deref(),
            Some("infra-backend-v3:8080")
        );
    }

    #[test]
    fn hostname_intersection_yields_only_intersected_hosts() {
        // Reproduces the HTTPRouteHostnameIntersection conformance manifest.
        let specific_gateway = GatewayState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("httproute-hostname-intersection"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("listener-1"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("very.specific.com")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-2"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.wildcard.io")),
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("listener-3"),
                    protocol: Arc::from("HTTP"),
                    port: 80,
                    hostname: Some(Arc::from("*.anotherwildcard.io")),
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        };
        let all_gateway = GatewayState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("httproute-hostname-intersection-all"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("listener-1"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };

        fn route(
            name: &str,
            gw: &str,
            hostnames: &[&str],
            path: &str,
            backend: &str,
        ) -> HTTPRouteState {
            HTTPRouteState {
                namespace: Arc::from("gateway-conformance-infra"),
                name: Arc::from(name),
                generation: 1,
                hostnames: hostnames
                    .iter()
                    .map(|h| {
                        if let Some(rest) = h.strip_prefix("*.") {
                            HostnameMatch::Wildcard(Arc::from(rest))
                        } else {
                            HostnameMatch::Exact(Arc::from(*h))
                        }
                    })
                    .collect(),
                rules: vec![HTTPRouteRule {
                    programmed: true,
                    timeout_ms: None,
                    request_timeout_ms: None,
                    matches: vec![RouteMatch {
                        path: Some(PathMatch::Prefix(Arc::from(path))),
                        headers: vec![],
                        query_params: vec![],
                        method: None,
                    }],
                    backends: vec![WeightedBackend {
                        backend: Arc::from(backend),
                        weight: 1,
                        protocol: crate::ir::BackendProtocol::Http,

                        filters: vec![],
                        tls: None,
                    }],
                    filters: vec![],
                }],
                parent_refs: vec![ParentRef {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("Gateway"),

                    namespace: Some(Arc::from("gateway-conformance-infra")),
                    name: Arc::from(gw),
                    section_name: None,
                    port: None,
                }],
                programmed: true,
            }
        }

        let routes = vec![
            route(
                "specific-host-matches-listener-specific-host",
                "httproute-hostname-intersection",
                &[
                    "non.matching.com",
                    "*.nonmatchingwildcard.io",
                    "very.specific.com",
                ],
                "/s1",
                "infra-backend-v1:8080",
            ),
            route(
                "specific-host-matches-listener-wildcard-host",
                "httproute-hostname-intersection",
                &[
                    "non.matching.com",
                    "wildcard.io",
                    "foo.wildcard.io",
                    "bar.wildcard.io",
                    "foo.bar.wildcard.io",
                ],
                "/s2",
                "infra-backend-v2:8080",
            ),
            route(
                "wildcard-host-matches-listener-specific-host",
                "httproute-hostname-intersection",
                &["non.matching.com", "*.specific.com"],
                "/s3",
                "infra-backend-v3:8080",
            ),
            route(
                "wildcard-host-matches-listener-wildcard-host",
                "httproute-hostname-intersection",
                &["*.anotherwildcard.io"],
                "/s4",
                "infra-backend-v1:8080",
            ),
            route(
                "no-intersecting-hosts",
                "httproute-hostname-intersection",
                &["specific.but.wrong.com", "wildcard.io"],
                "/s5",
                "infra-backend-v2:8080",
            ),
            route(
                "httproute-hostname-intersection-all",
                "httproute-hostname-intersection-all",
                &["first.com", "sub.first.com", "second.com", "sub.second.com"],
                "/",
                "infra-backend-v2:8080",
            ),
        ];

        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![specific_gateway, all_gateway],
            routes: vec![],
            http_routes: routes,
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };

        let ir = translate_view_to_ir(&view);
        let compiled = CompiledRouteTable::compile(ir).unwrap();

        fn backend_for(compiled: &CompiledRouteTable, host: &str, path: &str) -> Option<Arc<str>> {
            let plan = compiled.lookup(host, 80, path, "GET", &Default::default(), None)?;
            plan.upstream
                .as_ref()
                .map(|u| Arc::clone(&u.backends[0].backend))
        }

        // Intersecting hostnames should route to the expected backend.
        assert_eq!(
            backend_for(&compiled, "very.specific.com", "/s1").as_deref(),
            Some("infra-backend-v1:8080"),
            "very.specific.com/s1 should route"
        );
        assert_eq!(
            backend_for(&compiled, "foo.wildcard.io", "/s2").as_deref(),
            Some("infra-backend-v2:8080"),
            "foo.wildcard.io/s2 should route"
        );
        assert_eq!(
            backend_for(&compiled, "bar.wildcard.io", "/s2").as_deref(),
            Some("infra-backend-v2:8080"),
            "bar.wildcard.io/s2 should route"
        );
        assert_eq!(
            backend_for(&compiled, "foo.bar.wildcard.io", "/s2").as_deref(),
            Some("infra-backend-v2:8080"),
            "foo.bar.wildcard.io/s2 should route"
        );
        assert_eq!(
            backend_for(&compiled, "very.specific.com", "/s3").as_deref(),
            Some("infra-backend-v3:8080"),
            "very.specific.com/s3 should route"
        );
        assert_eq!(
            backend_for(&compiled, "sub.anotherwildcard.io", "/s4").as_deref(),
            Some("infra-backend-v1:8080"),
            "sub.anotherwildcard.io/s4 should route"
        );
        assert!(
            backend_for(&compiled, "foo.specific.com", "/s3").is_none(),
            "foo.specific.com/s3 should not match; intersection is very.specific.com"
        );
        assert_eq!(
            backend_for(&compiled, "first.com", "/").as_deref(),
            Some("infra-backend-v2:8080"),
            "first.com/ should route"
        );

        // Non-intersecting hostnames should not match any route.
        assert!(
            backend_for(&compiled, "non.matching.com", "/s1").is_none(),
            "non.matching.com/s1 should not match"
        );
        assert!(
            backend_for(&compiled, "foo.nonmatchingwildcard.io", "/s1").is_none(),
            "foo.nonmatchingwildcard.io/s1 should not match"
        );
        assert!(
            backend_for(&compiled, "wildcard.io", "/s2").is_none(),
            "wildcard.io/s2 should not match *.wildcard.io"
        );
        assert!(
            backend_for(&compiled, "non.matching.com", "/s2").is_none(),
            "non.matching.com/s2 should not match"
        );
        assert!(
            backend_for(&compiled, "non.matching.com", "/s3").is_none(),
            "non.matching.com/s3 should not match"
        );
        assert!(
            backend_for(&compiled, "anotherwildcard.io", "/s4").is_none(),
            "anotherwildcard.io/s4 should not match *.anotherwildcard.io"
        );
        assert!(
            backend_for(&compiled, "specific.but.wrong.com", "/s5").is_none(),
            "specific.but.wrong.com/s5 should not match"
        );
        assert!(
            backend_for(&compiled, "wildcard.io", "/s5").is_none(),
            "wildcard.io/s5 should not match *.wildcard.io"
        );
        assert!(
            backend_for(&compiled, "third.com", "/").is_none(),
            "third.com/ should not match"
        );
    }

    #[test]
    fn unprogrammed_invalid_backend_route_returns_500() {
        let gateway = GatewayState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("same-namespace"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("gateway-conformance-infra"),
            name: Arc::from("invalid-backend-ref-unknown-kind"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: false,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from(
                        "infra-backend-v1.gateway-conformance-infra.svc.cluster.local.:8080",
                    ),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,
                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("gateway-conformance-infra")),
                name: Arc::from("same-namespace"),
                section_name: None,
                port: None,
            }],
            programmed: false,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let compiled = CompiledRouteTable::compile(table).unwrap();
        let plan = compiled.lookup("", 80, "/", "GET", &Default::default(), None);
        assert!(
            plan.is_some(),
            "unprogrammed route should still match so it can return 500"
        );
        let plan = plan.unwrap();
        assert!(
            plan.upstream.is_none(),
            "unprogrammed route must not have an upstream, got {:?}",
            plan.upstream
        );
    }

    #[test]
    fn translate_view_to_ir_307_redirect_no_hostname_lookup() {
        let gateway = GatewayState {
            namespace: Arc::from("infra"),
            name: Arc::from("same-namespace"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("infra"),
            name: Arc::from("307-redirect"),
            generation: 1,
            hostnames: vec![],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/temporary"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![],
                filters: vec![RouteFilter::RequestRedirect {
                    scheme: None,
                    hostname: None,
                    path: None,
                    port: None,
                    status_code: 307,
                }],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: Some(Arc::from("infra")),
                name: Arc::from("same-namespace"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        eprintln!("hosts: {:?}", table.hosts);
        let compiled = CompiledRouteTable::compile(table).unwrap();
        let headers = http::header::HeaderMap::new();
        let plan = compiled.lookup("192.168.252.19", 80, "/temporary", "GET", &headers, None);
        eprintln!("plan: {:?}", plan);
        assert!(plan.is_some(), "expected 307 redirect plan");
        let plan = plan.unwrap();
        assert_eq!(plan.request_stages.len(), 1);
        assert!(matches!(
            plan.request_stages[0],
            crate::ir::compile::RequestStage::Terminal(
                crate::ir::compile::TerminalAction::Redirect(_)
            )
        ));
    }

    // ------------------------------------------------------------------
    // L4 route translation
    // ------------------------------------------------------------------

    fn l4_gateway() -> GatewayState {
        GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![
                ListenerState {
                    name: Arc::from("tcp"),
                    protocol: Arc::from("TCP"),
                    port: 9001,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("udp"),
                    protocol: Arc::from("UDP"),
                    port: 9002,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
                ListenerState {
                    name: Arc::from("tls"),
                    protocol: Arc::from("TLS"),
                    port: 9003,
                    hostname: None,
                    tls_mode: None,
                    frontend_validation: None,
                },
            ],
            backend_client_cert_id: None,
        }
    }

    fn tcp_route(programmed: bool) -> TCPRouteState {
        TCPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("tcp-route"),
            generation: 1,
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("10.0.0.1:8080"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            programmed,
        }
    }

    fn udp_route(programmed: bool) -> UDPRouteState {
        UDPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("udp-route"),
            generation: 1,
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("10.0.0.2:8080"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            programmed,
        }
    }

    fn tls_route(programmed: bool, hostnames: Vec<HostnameMatch>) -> TLSRouteState {
        TLSRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("tls-route"),
            generation: 1,
            hostnames,
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("10.0.0.3:8443"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            programmed,
        }
    }

    #[test]
    fn listener_protocol_to_ir_maps_protocols() {
        assert_eq!(listener_protocol_to_ir("HTTP"), Some(ir::Protocol::Http));
        assert_eq!(listener_protocol_to_ir("HTTPS"), Some(ir::Protocol::Https));
        assert_eq!(listener_protocol_to_ir("TCP"), Some(ir::Protocol::Tcp));
        assert_eq!(listener_protocol_to_ir("UDP"), Some(ir::Protocol::Udp));
        assert_eq!(listener_protocol_to_ir("TLS"), Some(ir::Protocol::Tls));
        assert_eq!(listener_protocol_to_ir("FTP"), None);
    }

    #[test]
    fn add_l4_listener_skips_duplicates_and_unknown_protocols() {
        let gateway = l4_gateway();
        let mut listeners: std::collections::BTreeMap<Arc<str>, ir::ListenerConfig> =
            std::collections::BTreeMap::new();
        add_l4_listener(&mut listeners, &gateway, &gateway.listeners[0]);
        assert_eq!(listeners.len(), 1);
        // duplicate is ignored
        add_l4_listener(&mut listeners, &gateway, &gateway.listeners[0]);
        assert_eq!(listeners.len(), 1);

        let unknown = ListenerState {
            name: Arc::from("weird"),
            protocol: Arc::from("SCTP"),
            port: 9004,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        };
        add_l4_listener(&mut listeners, &gateway, &unknown);
        assert_eq!(listeners.len(), 1);
    }

    #[test]
    fn translate_l4_routes_creates_listeners_and_routes() {
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![l4_gateway()],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![tcp_route(true)],
            udp_routes: vec![udp_route(true)],
            tls_routes: vec![tls_route(
                true,
                vec![HostnameMatch::Exact(Arc::from("foo.example.com"))],
            )],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert_eq!(listeners.len(), 3);
        assert_eq!(routes.len(), 3);
        let ids: Vec<_> = listeners.iter().map(|l| l.id.as_ref()).collect();
        assert!(ids.contains(&"default/gw-1/tcp"));
        assert!(ids.contains(&"default/gw-1/udp"));
        assert!(ids.contains(&"default/gw-1/tls"));
        assert!(routes
            .iter()
            .any(|r| matches!(r.action, ir::L4Action::TcpRelay(_))));
        assert!(routes
            .iter()
            .any(|r| matches!(r.action, ir::L4Action::UdpRelay(_))));
        assert!(routes
            .iter()
            .any(|r| matches!(r.action, ir::L4Action::TlsPassthrough(_))));
        assert!(routes
            .iter()
            .any(|r| matches!(r.match_, ir::L4Match::Sni(_))));
    }

    fn http_gateway() -> GatewayState {
        GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-http"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 8080,
                hostname: Some(Arc::from("foo.com")),
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        }
    }

    #[test]
    fn translate_l4_routes_relays_http_with_any_match() {
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![http_gateway()],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, ir::Protocol::Http);
        assert_eq!(routes.len(), 1);
        assert!(matches!(routes[0].action, ir::L4Action::HttpRelay(_)));
        assert_eq!(routes[0].match_, ir::L4Match::Any);
    }

    #[test]
    fn translate_l4_routes_skips_unprogrammed() {
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![l4_gateway()],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![tcp_route(false)],
            udp_routes: vec![udp_route(false)],
            tls_routes: vec![tls_route(false, vec![])],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert!(listeners.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn translate_l4_routes_filters_by_section_name() {
        let mut route = tcp_route(true);
        route.parent_refs[0].section_name = Some(Arc::from("tls"));
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![l4_gateway()],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![route],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert!(listeners.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn translate_l4_routes_skips_when_gateway_not_found() {
        let mut route = tcp_route(true);
        route.parent_refs[0].name = Arc::from("missing-gw");
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![l4_gateway()],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![route],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert!(listeners.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn translate_l4_routes_inherits_parent_namespace() {
        let mut route = tcp_route(true);
        route.namespace = Arc::from("other");
        route.parent_refs[0].namespace = None;
        let gateway = GatewayState {
            namespace: Arc::from("other"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("tcp"),
                protocol: Arc::from("TCP"),
                port: 9001,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![route],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert_eq!(listeners.len(), 1);
        assert_eq!(routes.len(), 1);
        assert_eq!(listeners[0].id.as_ref(), "other/gw-1/tcp");
    }

    #[test]
    fn translate_l4_routes_uses_terminate_action_for_terminate_listener() {
        let mut gateway = l4_gateway();
        gateway.listeners.retain(|l| l.protocol.as_ref() == "TLS");
        gateway.listeners[0].tls_mode = Some(TlsMode::Terminate);
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![tls_route(true, vec![])],
            reference_grants: vec![],
            ..Default::default()
        };
        let (listeners, routes) = translate_l4_routes(&view);
        assert_eq!(listeners.len(), 1);
        assert_eq!(routes.len(), 1);
        assert!(matches!(
            listeners[0].tls,
            Some(ir::TlsConfig::Registry { .. })
        ));
        assert!(matches!(routes[0].action, ir::L4Action::TlsTerminate(_)));
    }

    #[test]
    fn translate_l4_routes_uses_passthrough_action_for_passthrough_listener() {
        let mut gateway = l4_gateway();
        gateway.listeners.retain(|l| l.protocol.as_ref() == "TLS");
        gateway.listeners[0].tls_mode = Some(TlsMode::Passthrough);
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![tls_route(true, vec![])],
            reference_grants: vec![],
            ..Default::default()
        };
        let (_listeners, routes) = translate_l4_routes(&view);
        assert!(routes
            .iter()
            .any(|r| matches!(r.action, ir::L4Action::TlsPassthrough(_))));
    }

    #[test]
    fn translate_view_to_ir_websocket_backend_sets_flag() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("ws-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("ws.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:80"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::WebSocket,
                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),

                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert!(action.websocket);
            assert_eq!(
                action.backends[0].protocol,
                crate::ir::BackendProtocol::WebSocket
            );
        } else {
            panic!("expected Route action");
        }
    }

    #[test]
    fn translate_view_to_ir_grpc_exact_method_match() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = GRPCRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("grpc-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("grpc.example.com"))],
            rules: vec![GRPCRouteRule {
                name: None,
                programmed: true,
                matches: vec![GRPCRouteMatch {
                    method: Some(MethodMatch {
                        match_type: MethodMatchType::Exact,
                        service: Arc::from("foo.bar"),
                        method: Some(Arc::from("Baz")),
                        case_sensitive: true,
                    }),
                    headers: vec![],
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("grpc-svc:50051"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,
                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![],
            grpc_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        assert_eq!(table.hosts.len(), 1);
        let rule = &table.hosts[0].rules[0];
        if let crate::ir::Action::Route(action) = &rule.action {
            assert_eq!(action.backends[0].backend.as_ref(), "grpc-svc:50051");
        } else {
            panic!("expected Route action");
        }
        assert!(rule.matches.iter().any(|m| matches!(
            m.path,
            Some(crate::ir::PathMatch::Exact(ref p)) if p.as_ref() == "/foo.bar/Baz"
        )));
    }

    #[test]
    fn translate_view_to_ir_grpc_header_match() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw-1"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = GRPCRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("grpc-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("grpc.example.com"))],
            rules: vec![GRPCRouteRule {
                name: Some(Arc::from("named-rule")),
                programmed: true,
                matches: vec![GRPCRouteMatch {
                    method: Some(MethodMatch {
                        match_type: MethodMatchType::Exact,
                        service: Arc::from("foo.bar"),
                        method: Some(Arc::from("Baz")),
                        case_sensitive: true,
                    }),
                    headers: vec![HeaderMatch {
                        name: Arc::from("x-version"),
                        value: HeaderMatchValue::Exact(Arc::from("v1")),
                    }],
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("grpc-svc:50051"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Http,
                    filters: vec![],
                    tls: None,
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: Arc::from("gw-1"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![],
            grpc_routes: vec![route],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let rule = &table.hosts[0].rules[0];
        assert!(rule.matches.iter().any(|m| {
            m.headers.iter().any(|h| {
                h.name.as_ref() == "x-version"
                    && matches!(h.value, crate::ir::HeaderMatchValue::Exact(ref v) if v.as_ref() == "v1")
            })
        }));
    }

    #[test]
    fn translate_view_to_ir_attaches_backend_tls_policy() {
        let gateway = GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from("gw"),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from("https"),
                protocol: Arc::from("HTTPS"),
                port: 443,
                hostname: Some(Arc::from("*.example.com")),
                tls_mode: Some(crate::gateway::model::TlsMode::Terminate),
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        };
        let route = HTTPRouteState {
            namespace: Arc::from("default"),
            name: Arc::from("tls-route"),
            generation: 1,
            hostnames: vec![HostnameMatch::Exact(Arc::from("app.example.com"))],
            rules: vec![HTTPRouteRule {
                programmed: true,
                timeout_ms: None,
                request_timeout_ms: None,
                matches: vec![RouteMatch {
                    path: Some(PathMatch::Prefix(Arc::from("/"))),
                    headers: vec![],
                    query_params: vec![],
                    method: None,
                }],
                backends: vec![WeightedBackend {
                    backend: Arc::from("svc:443"),
                    weight: 1,
                    protocol: crate::ir::BackendProtocol::Https,
                    filters: vec![],
                    tls: Some(BackendTlsAttachment {
                        hostname: Arc::from("svc.example.com"),
                        ca_bundle_pem: Arc::from(
                            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
                        ),
                        subject_alt_names: vec![Arc::from("svc.example.com")],
                    }),
                }],
                filters: vec![],
            }],
            parent_refs: vec![ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: Arc::from("gw"),
                section_name: None,
                port: None,
            }],
            programmed: true,
        };
        let view = GatewayView {
            listener_sets: vec![],
            gateways: vec![gateway],
            routes: vec![],
            http_routes: vec![route],
            grpc_routes: vec![],
            tcp_routes: vec![],
            udp_routes: vec![],
            tls_routes: vec![],
            reference_grants: vec![],
            ..Default::default()
        };
        let table = translate_view_to_ir(&view);
        let host = table.hosts.iter().find(|h| matches!(h.hostname, crate::ir::HostnameMatch::Exact(ref s) if s.as_ref() == "app.example.com")).expect("host");
        let rule = &host.rules[0];
        let action = match &rule.action {
            crate::ir::Action::Route(a) => a,
            _ => panic!("expected route action"),
        };
        let backend = action.backends.first().expect("backend");
        assert_eq!(backend.protocol, crate::ir::BackendProtocol::Https);
        let tls = backend.tls.as_ref().expect("tls config");
        assert_eq!(tls.sni.as_ref(), "svc.example.com");
        assert!(tls.ca_bundle_pem.is_some());
        assert_eq!(tls.subject_alt_names.len(), 1);
        assert_eq!(tls.subject_alt_names[0].as_ref(), "svc.example.com");
    }
}
