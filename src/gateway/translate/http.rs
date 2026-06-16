// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::config::{
    HeaderMatchConfig, HeaderMatchValueConfig, HeaderRule, PathRoute, QueryParamMatchConfig,
    QueryParamMatchValueConfig, RedirectRule, RewriteRule, WeightedBackendConfig,
};
use crate::gateway::model::{
    HTTPRouteRule, HeaderMatch, HeaderMatchValue, PathMatch, PathRewrite, QueryParamMatch,
    QueryParamMatchValue, RouteFilter, RouteMatch,
};
use crate::ir;
use std::sync::Arc;
use std::time::Duration;

use super::ir::unprogrammed_action;

pub(crate) fn translate_rule_paths(
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
pub(crate) fn build_path_route(
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

pub(crate) fn translate_header_match(hm: &HeaderMatch) -> HeaderMatchConfig {
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

pub(crate) fn translate_query_param_match(qm: &QueryParamMatch) -> QueryParamMatchConfig {
    QueryParamMatchConfig {
        name: qm.name.to_string(),
        value: match &qm.value {
            QueryParamMatchValue::Exact(v) => QueryParamMatchValueConfig::Exact(v.to_string()),
            QueryParamMatchValue::Regex(v) => QueryParamMatchValueConfig::Regex(v.to_string()),
        },
    }
}

pub(crate) fn translate_redirect(
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

pub(crate) fn translate_rewrite(path: &PathRewrite) -> Option<RewriteRule> {
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

pub(crate) fn to_ir_weighted_backend(
    b: &crate::gateway::model::WeightedBackend,
) -> ir::WeightedBackend {
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

pub(crate) fn translate_rule_to_ir(
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

/// Apply header-modifier filters that are common to HTTP and GRPC routes.
pub(crate) fn apply_header_filters(
    filters: &[RouteFilter],
    request_filters: &mut Vec<ir::RequestFilter>,
    response_filters: &mut Vec<ir::ResponseFilter>,
) {
    for filter in filters {
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
}

pub(crate) fn build_ir_rule(
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

    apply_header_filters(&rule.filters, &mut request_filters, &mut response_filters);

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
            _ => {}
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
