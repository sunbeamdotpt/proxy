// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::grpc::translate_grpc_rule_to_ir;
use super::hostnames::compute_effective_hostnames;
use super::http::{translate_rewrite, translate_rule_paths, translate_rule_to_ir};
use super::l4::translate_l4_routes;
use super::{hostname_to_prefix, to_ir_hostname};
use crate::config::{PathRoute, RouteConfig};
use crate::gateway::model::{GatewayView, HostnameMatch, RouteFilter};
use crate::ir;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

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
                        if let Some(path) = path
                            && let Some(rw) = translate_rewrite(path)
                        {
                            rewrites.push(rw);
                        }
                        // hostname rewrite is handled per-path-route below
                        let _ = hostname;
                    }
                }
            }

            // If no paths were produced, create a default catch-all path
            // using the first backend from the first rule (common case).
            if paths.is_empty()
                && !http_route.rules.is_empty()
                && let Some(first_backend) = http_route.rules[0].backends.first()
            {
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

pub(crate) fn unprogrammed_action() -> ir::Action {
    ir::Action::FixedResponse(ir::FixedResponseAction {
        status: 500,
        headers: vec![],
        body: None,
    })
}
