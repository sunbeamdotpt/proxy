// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::model::{GatewayView, HostnameMatch, ListenerState, RouteNamespaces};
use std::collections::BTreeMap;
use std::sync::Arc;

use super::parse_listener_hostname;

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
pub(crate) struct EffectiveHostname {
    /// Effective hostname match for the route itself.
    pub(crate) route_hostname: HostnameMatch,
    /// Hostname match of the listener this route is attached to.
    pub(crate) listener_hostname: HostnameMatch,
    /// Port of the listener this route is attached to. `None` when no listener
    /// was resolved (legacy/fallback path).
    pub(crate) listener_port: Option<u16>,
    /// Optional Gateway-wide backend client certificate identifier.
    pub(crate) client_cert_id: Option<Arc<str>>,
    /// Listener identifier when the route resolved to a concrete listener.
    pub(crate) listener_id: Option<Arc<str>>,
}

/// Check whether a listener's namespace scope allows routes from `route_ns`.
pub(crate) fn namespace_allowed(
    namespaces: &RouteNamespaces,
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
pub(crate) fn compute_effective_hostnames<R: RouteHostnames>(
    route: &R,
    view: &GatewayView,
    route_kind: &str,
) -> Vec<EffectiveHostname> {
    use crate::gateway::reconcile::parent::{listener_allows_kind, listener_hostname_intersects};

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
                        let listeners: Vec<&ListenerState> = if let Some(section) =
                            parent.section_name.as_deref()
                        {
                            gateway
                                .listeners
                                .iter()
                                .filter(|l| {
                                    l.programmed
                                        && l.name.as_ref() == section
                                        && parent.port.map(|p| p == l.port).unwrap_or(true)
                                })
                                .collect()
                        } else {
                            gateway
                                .listeners
                                .iter()
                                .filter(|l| {
                                    l.programmed && parent.port.map(|p| p == l.port).unwrap_or(true)
                                })
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
                        && listener_hostname_intersects(
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
                    listener_id: None,
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
                    listener_id: Some(Arc::from(format!(
                        "{}/{}/{}",
                        parent_ns,
                        parent_name,
                        listener.name.as_ref()
                    ))),
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
                            listener_id: Some(Arc::from(format!(
                                "{}/{}/{}",
                                parent_ns,
                                parent_name,
                                listener.name.as_ref()
                            ))),
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
                        listener_id: None,
                    });
                }
            }
        }
    }

    result
}
