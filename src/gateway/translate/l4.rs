// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::hostnames::{compute_effective_hostnames, intersect_hostname_pair};
use super::http::to_ir_weighted_backend;
use super::{parse_listener_hostname, to_ir_hostname};
use crate::gateway::model::{GatewayState, GatewayView, HostnameMatch, ListenerState, TlsMode};
use crate::ir;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

pub(crate) fn listener_protocol_to_ir(protocol: &str) -> Option<ir::Protocol> {
    match protocol {
        "HTTP" => Some(ir::Protocol::Http),
        "HTTPS" => Some(ir::Protocol::Https),
        "TCP" => Some(ir::Protocol::Tcp),
        "UDP" => Some(ir::Protocol::Udp),
        "TLS" => Some(ir::Protocol::Tls),
        _ => None,
    }
}

pub(crate) fn add_l4_listener(
    listeners: &mut BTreeMap<Arc<str>, ir::ListenerConfig>,
    gateway: &GatewayState,
    listener: &ListenerState,
) {
    if !listener.programmed {
        return;
    }
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
pub(crate) fn translate_l4_routes(
    view: &GatewayView,
) -> (Vec<ir::ListenerConfig>, Vec<ir::L4Route>) {
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
                if let Some(section) = section_filter
                    && listener.name.as_ref() != section {
                        continue;
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

    // Only open HTTPS listeners that have at least one HTTPRoute or GRPCRoute
    // attached. This prevents unrelated base-resource HTTPS listeners from
    // terminating TLS for hostnames whose intended listener is invalid or
    // unprogrammed.
    let mut https_listener_ids: HashSet<Arc<str>> = HashSet::new();
    for route in &view.http_routes {
        if route.parent_refs.is_empty() {
            continue;
        }
        for eff in compute_effective_hostnames(route, view, "HTTPRoute") {
            if let Some(id) = eff.listener_id {
                https_listener_ids.insert(id);
            }
        }
    }
    for route in &view.grpc_routes {
        if route.parent_refs.is_empty() {
            continue;
        }
        for eff in compute_effective_hostnames(route, view, "GRPCRoute") {
            if let Some(id) = eff.listener_id {
                https_listener_ids.insert(id);
            }
        }
    }

    for gateway in &view.gateways {
        for listener in &gateway.listeners {
            if listener.protocol.as_ref() != "HTTPS" {
                continue;
            }
            let id: Arc<str> = Arc::from(format!(
                "{}/{}/{}",
                gateway.namespace.as_ref(),
                gateway.name.as_ref(),
                listener.name.as_ref()
            ));
            if !https_listener_ids.contains(&id) {
                continue;
            }
            add_l4_listener(&mut listeners, gateway, listener);
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
            if let Some(section) = section_filter
                && listener.name.as_ref() != section {
                    continue;
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
