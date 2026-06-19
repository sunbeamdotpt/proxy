// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::gateway::api::Gateway;
use crate::gateway::api::HTTPRoute;
use crate::gateway::api::listenerset::{ListenerSet, ListenerSetListeners};
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerSetState, ListenerState, NamespaceFrom,
    ParentRef, RouteNamespaces,
};
use crate::gateway::reconcile::httproute::{parse_parent_refs, parse_route_hostnames};
use crate::gateway::reconcile::listener_common::{
    build_listener_allowed_map_key, build_listener_state_from_obj, listener_status_json,
    listener_supported_kinds, parse_allowed_routes, standard_listener_conditions,
    validate_listener_kinds,
};
use crate::gateway::reconcile::parent::{
    listener_allows_kind, listener_hostname_intersects, namespace_allowed,
};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::builder::condition_json;
use kube::Client;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// Build a [`ListenerState`] from a raw ListenerSet listener entry.
pub fn build_listener_state(entry: &ListenerSetListeners) -> ListenerState {
    // The strongly-typed entry already exposes name/protocol/port/hostname as
    // strings, but allowedRoutes/tls are stored as raw JSON.  Convert to a JSON
    // object so we can reuse the shared listener parsing helpers.
    let obj = match serde_json::to_value(entry) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    let name: Arc<str> = entry.name.clone().into();
    let protocol: Arc<str> = entry.protocol.clone().into();
    let port = entry.port as u16;
    let hostname = entry.hostname.as_deref().map(Arc::from);
    build_listener_state_from_obj(name, protocol, port, hostname, Some(&obj))
}

/// Parse the namespace scope from a Gateway's `allowedListeners` field.
pub fn parse_allowed_listeners(gw: &Gateway) -> RouteNamespaces {
    let Some(value) = gw.spec.allowed_listeners.as_ref() else {
        // When unset, ListenerSets are not allowed on the Gateway.
        return RouteNamespaces {
            from: NamespaceFrom::None,
            selector: None,
        };
    };
    let Some(obj) = value.as_object() else {
        return RouteNamespaces::default();
    };
    let namespaces = obj.get("namespaces").and_then(|v| v.as_object());
    let Some(ns) = namespaces else {
        return RouteNamespaces::default();
    };
    let from = ns
        .get("from")
        .and_then(|v| v.as_str())
        .map(|s| match s {
            "All" => NamespaceFrom::All,
            "Selector" => NamespaceFrom::Selector,
            "None" => NamespaceFrom::None,
            _ => NamespaceFrom::Same,
        })
        .unwrap_or_default();

    let selector = ns
        .get("selector")
        .and_then(|v| v.as_object())
        .and_then(|sel| {
            let map: std::collections::BTreeMap<String, String> = sel
                .get("matchLabels")
                .and_then(|v| v.as_object())?
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
            if map.is_empty() { None } else { Some(map) }
        });

    RouteNamespaces { from, selector }
}

/// Determine whether a ListenerSet in `ls_ns` is allowed to attach to `gw`.
pub fn listener_set_allowed(
    ls_ns: &str,
    gw: &Gateway,
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> bool {
    let gw_ns = gw.metadata.namespace.as_deref().unwrap_or("default");
    let allowed = parse_allowed_listeners(gw);
    namespace_allowed(&allowed, ls_ns, gw_ns, namespace_labels)
}

/// Find the parent Gateway referenced by a ListenerSet.
pub fn find_parent_gateway<'a>(
    ls: &ListenerSet,
    gateways: &'a [Gateway],
) -> Option<(usize, &'a Gateway)> {
    let target_ns = ls
        .spec
        .parent_ref
        .namespace
        .as_deref()
        .or(ls.metadata.namespace.as_deref())
        .unwrap_or("default");
    let target_name = ls.spec.parent_ref.name.as_str();
    gateways.iter().enumerate().find(|(_, g)| {
        g.metadata.namespace.as_deref().unwrap_or("default") == target_ns
            && g.metadata.name.as_deref().unwrap_or("") == target_name
    })
}

/// Build a map from `(listenerset_namespace, listenerset_name, listener_name)`
/// to the parsed `AllowedRoutes` for that listener.
pub fn build_listener_set_allowed_map(
    raw_listener_sets: &[ListenerSet],
    listener_set_states: &[ListenerSetState],
) -> HashMap<(String, String, String), AllowedRoutes> {
    let mut map = HashMap::new();
    for ls in listener_set_states {
        let raw = match raw_listener_sets.iter().find(|r| {
            r.metadata.namespace.as_deref().unwrap_or("default") == ls.namespace.as_ref()
                && r.metadata.name.as_deref().unwrap_or("") == ls.name.as_ref()
        }) {
            Some(r) => r,
            None => continue,
        };
        for (idx, listener) in ls.listeners.iter().enumerate() {
            if ls.conflicts.contains_key(listener.name.as_ref()) {
                continue;
            }
            let allowed = raw
                .spec
                .listeners
                .get(idx)
                .map(|entry| {
                    let obj = serde_json::to_value(entry)
                        .ok()
                        .and_then(|v| v.as_object().cloned())
                        .unwrap_or_default();
                    parse_allowed_routes(&obj)
                })
                .unwrap_or_default();
            map.insert(
                build_listener_allowed_map_key(
                    ls.namespace.as_ref(),
                    ls.name.as_ref(),
                    listener.name.as_ref(),
                ),
                allowed,
            );
        }
    }
    map
}

/// Build a `ListenerSetState` from a raw ListenerSet and parent Gateway context.
pub async fn build_listener_set_state(
    ls: &ListenerSet,
    gateways: &[Gateway],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    client: &Client,
    grant_index: &GrantIndex,
) -> ListenerSetState {
    let namespace: Arc<str> = ls.metadata.namespace.as_deref().unwrap_or("default").into();
    let name: Arc<str> = ls.metadata.name.as_deref().unwrap_or("").into();
    let generation = ls.metadata.generation.unwrap_or(0).max(1);
    let created_at = ls
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0.as_second())
        .unwrap_or(0);
    let parent_ref = ParentRef {
        group: Arc::from(
            ls.spec
                .parent_ref
                .group
                .as_deref()
                .unwrap_or("gateway.networking.k8s.io"),
        ),
        kind: Arc::from(ls.spec.parent_ref.kind.as_deref().unwrap_or("Gateway")),
        namespace: ls.spec.parent_ref.namespace.as_deref().map(Arc::from),
        name: Arc::from(ls.spec.parent_ref.name.as_str()),
        section_name: None,
        port: None,
    };

    let parent = find_parent_gateway(ls, gateways);
    let allowed = parent
        .map(|(_, gw)| listener_set_allowed(&namespace, gw, namespace_labels))
        .unwrap_or(false);

    let listeners = if allowed {
        ls.spec.listeners.iter().map(build_listener_state).collect()
    } else {
        vec![]
    };

    let mut listener_cert_errors: Vec<Option<Arc<str>>> = Vec::new();
    let mut listener_kind_errors: Vec<Option<Arc<str>>> = Vec::new();
    if allowed {
        for entry in &ls.spec.listeners {
            let obj = match serde_json::to_value(entry)
                .ok()
                .and_then(|v| v.as_object().cloned())
            {
                Some(o) => o,
                None => {
                    listener_cert_errors.push(Some(Arc::from("InvalidCertificateRef")));
                    listener_kind_errors.push(None);
                    continue;
                }
            };
            let (_kinds, resolved_status, resolved_reason, _message) =
                validate_listener_kinds(&obj);
            if resolved_status == "False" {
                listener_kind_errors.push(Some(Arc::from(resolved_reason)));
            } else {
                listener_kind_errors.push(None);
            }
            let err = crate::gateway::reconcile::gateway::validate_listener_certificates(
                client,
                &namespace,
                "ListenerSet",
                &obj,
                grant_index,
            )
            .await;
            listener_cert_errors.push(err.map(|cv| Arc::from(cv.reason)));
        }
    }

    let listeners_valid = listener_cert_errors
        .iter()
        .zip(&listener_kind_errors)
        .all(|(c, k)| c.is_none() && k.is_none());
    let accepted = allowed && listeners_valid;
    let programmed = accepted;
    let reason = if !allowed {
        Arc::from("NotAllowed")
    } else if !listeners_valid {
        Arc::from("ListenersNotValid")
    } else {
        Arc::from("Accepted")
    };

    ListenerSetState {
        namespace,
        name,
        generation,
        created_at,
        parent_ref,
        listeners,
        conflicts: BTreeMap::new(),
        accepted,
        programmed,
        reason,
        listener_cert_errors,
        listener_kind_errors,
    }
}

/// Count the ListenerSets that are accepted and attached to a given Gateway.
pub fn count_attached_listener_sets(
    gw_ns: &str,
    gw_name: &str,
    listener_set_states: &[ListenerSetState],
) -> i64 {
    listener_set_states
        .iter()
        .filter(|ls| {
            ls.parent_ref.namespace.as_deref().unwrap_or(gw_ns) == gw_ns
                && ls.parent_ref.name.as_ref() == gw_name
                && ls.accepted
                && ls.programmed
        })
        .count() as i64
}

/// Resolve hostname/protocol conflicts between a Gateway's own listeners and
/// the listeners of all ListenerSets attached to that Gateway.
///
/// Gateway listeners have the highest precedence, followed by ListenerSet
/// listeners ordered deterministically by (namespace, name). Within a
/// ListenerSet, listeners keep their spec order. Listeners that overlap with
/// an already-accepted listener are marked as conflicted.
pub fn resolve_listener_set_conflicts(
    listener_sets: &mut [ListenerSetState],
    gateways: &[GatewayState],
) {
    struct ActiveListener<'a> {
        port: u16,
        protocol: &'a str,
        hostname: Option<&'a str>,
        owner: Owner<'a>,
    }

    #[derive(Clone, Copy)]
    enum Owner<'a> {
        Gateway { namespace: &'a str, name: &'a str },
        ListenerSet { idx: usize },
    }

    fn same_parent_gateway<'a>(
        active: &ActiveListener<'a>,
        listener_sets: &'a [ListenerSetState],
        parent_gw_ns: &'a str,
        parent_gw_name: &'a str,
    ) -> bool {
        match active.owner {
            Owner::Gateway { namespace, name } => {
                namespace == parent_gw_ns && name == parent_gw_name
            }
            Owner::ListenerSet { idx } => {
                let other = &listener_sets[idx];
                let other_gw_ns = other
                    .parent_ref
                    .namespace
                    .as_deref()
                    .unwrap_or(other.namespace.as_ref());
                let other_gw_name = other.parent_ref.name.as_ref();
                other_gw_ns == parent_gw_ns && other_gw_name == parent_gw_name
            }
        }
    }

    fn hostname_matches(a: Option<&str>, b: Option<&str>) -> bool {
        let a_match = a
            .map(crate::gateway::translate::parse_listener_hostname)
            .unwrap_or(HostnameMatch::Any);
        let b_match = b
            .map(crate::gateway::translate::parse_listener_hostname)
            .unwrap_or(HostnameMatch::Any);
        crate::gateway::translate::hostname_intersects(&a_match, &b_match)
    }

    let mut accepted: Vec<ActiveListener> = Vec::new();

    for gw in gateways {
        for l in &gw.listeners {
            accepted.push(ActiveListener {
                port: l.port,
                protocol: l.protocol.as_ref(),
                hostname: l.hostname.as_deref(),
                owner: Owner::Gateway {
                    namespace: gw.namespace.as_ref(),
                    name: gw.name.as_ref(),
                },
            });
        }
    }

    let mut order: Vec<usize> = (0..listener_sets.len()).collect();
    order.sort_by_key(|i| {
        (
            listener_sets[*i].created_at,
            &listener_sets[*i].namespace,
            &listener_sets[*i].name,
        )
    });

    let mut conflicts_to_add: Vec<(usize, Arc<str>, Arc<str>)> = Vec::new();

    for ls_idx in order {
        let ls = &listener_sets[ls_idx];
        let parent_gw_ns = ls
            .parent_ref
            .namespace
            .as_deref()
            .unwrap_or(ls.namespace.as_ref());
        let parent_gw_name = ls.parent_ref.name.as_ref();

        for l in &ls.listeners {
            let mut conflict_reason: Option<&'static str> = None;
            for active in &accepted {
                if !same_parent_gateway(active, listener_sets, parent_gw_ns, parent_gw_name) {
                    continue;
                }
                if active.port != l.port {
                    continue;
                }
                if !hostname_matches(active.hostname, l.hostname.as_deref()) {
                    continue;
                }
                conflict_reason = if active.protocol.eq_ignore_ascii_case(l.protocol.as_ref()) {
                    Some("HostnameConflict")
                } else {
                    Some("ProtocolConflict")
                };
                break;
            }

            if let Some(reason) = conflict_reason {
                conflicts_to_add.push((ls_idx, Arc::clone(&l.name), Arc::from(reason)));
            } else {
                accepted.push(ActiveListener {
                    port: l.port,
                    protocol: l.protocol.as_ref(),
                    hostname: l.hostname.as_deref(),
                    owner: Owner::ListenerSet { idx: ls_idx },
                });
            }
        }
    }

    for (idx, name, reason) in conflicts_to_add {
        listener_sets[idx].conflicts.insert(name, reason);
    }

    for ls in listener_sets.iter_mut() {
        if !ls.accepted {
            continue;
        }
        let has_valid = ls
            .listeners
            .iter()
            .any(|l| !ls.conflicts.contains_key(l.name.as_ref()));
        if !has_valid {
            ls.accepted = false;
            ls.programmed = false;
            ls.reason = Arc::from("ListenersNotValid");
        }
    }
}

/// Build the status object for a ListenerSet as raw JSON.
pub fn build_listener_set_status(
    ls_state: &ListenerSetState,
    attached_routes: &[i64],
    supported_features: &std::collections::HashSet<String>,
) -> serde_json::Value {
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let accepted_reason = if ls_state.accepted {
        "Accepted"
    } else {
        ls_state.reason.as_ref()
    };
    let accepted_message = match accepted_reason {
        "NotAllowed" => "ListenerSet namespace is not allowed by Gateway",
        "ListenersNotValid" => "ListenerSet listeners are not valid",
        _ => "ListenerSet accepted",
    };

    let conditions = vec![
        condition_json(
            "Accepted",
            if ls_state.accepted { "True" } else { "False" },
            accepted_reason,
            accepted_message,
            ls_state.generation,
            &now,
        ),
        condition_json(
            "Programmed",
            if ls_state.programmed { "True" } else { "False" },
            if ls_state.programmed {
                "Programmed"
            } else {
                accepted_reason
            },
            if ls_state.programmed {
                "ListenerSet programmed"
            } else {
                accepted_message
            },
            ls_state.generation,
            &now,
        ),
    ];

    let mut listeners = Vec::new();
    let features = supported_features.clone();
    for (idx, listener) in ls_state.listeners.iter().enumerate() {
        let supported_kinds =
            listener_supported_kinds(listener.protocol.as_ref(), listener.tls_mode, &features);
        if let Some(reason) = ls_state.conflicts.get(listener.name.as_ref()) {
            let message = "Listener conflicts with a higher-precedence listener";
            let conditions = vec![
                condition_json(
                    "Accepted",
                    "False",
                    reason.as_ref(),
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "Programmed",
                    "False",
                    reason.as_ref(),
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "Conflicted",
                    "True",
                    reason.as_ref(),
                    message,
                    ls_state.generation,
                    &now,
                ),
            ];
            listeners.push(listener_status_json(
                listener.name.as_ref(),
                &supported_kinds,
                attached_routes.get(idx).copied().unwrap_or(0),
                &conditions,
            ));
        } else if let Some(reason) = ls_state.listener_kind_errors.get(idx).cloned().flatten() {
            let message = match reason.as_ref() {
                "InvalidRouteKinds" => "Listener contains unsupported route kinds",
                _ => "Listener references are not valid",
            };
            let conditions = vec![
                condition_json(
                    "Accepted",
                    "False",
                    "ListenersNotValid",
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "Programmed",
                    "False",
                    "ListenersNotValid",
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "ResolvedRefs",
                    "False",
                    reason.as_ref(),
                    message,
                    ls_state.generation,
                    &now,
                ),
            ];
            listeners.push(listener_status_json(
                listener.name.as_ref(),
                &supported_kinds,
                attached_routes.get(idx).copied().unwrap_or(0),
                &conditions,
            ));
        } else if let Some(reason) = ls_state.listener_cert_errors.get(idx).cloned().flatten() {
            let message = match reason.as_ref() {
                "RefNotPermitted" => {
                    "Cross-namespace CertificateRef is not permitted by ReferenceGrant"
                }
                _ => "CertificateRef is not valid",
            };
            let conditions = vec![
                condition_json(
                    "Accepted",
                    "False",
                    "ListenersNotValid",
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "Programmed",
                    "False",
                    "ListenersNotValid",
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "ResolvedRefs",
                    "False",
                    reason.as_ref(),
                    message,
                    ls_state.generation,
                    &now,
                ),
            ];
            listeners.push(listener_status_json(
                listener.name.as_ref(),
                &supported_kinds,
                attached_routes.get(idx).copied().unwrap_or(0),
                &conditions,
            ));
        } else if ls_state.accepted {
            let conditions = standard_listener_conditions(
                ("True", "Accepted", "Listener accepted"),
                ("True", "Programmed", "Listener programmed"),
                ("True", "ResolvedRefs", "Listener references resolved"),
                ls_state.generation,
                &now,
            );
            listeners.push(listener_status_json(
                listener.name.as_ref(),
                &supported_kinds,
                attached_routes.get(idx).copied().unwrap_or(0),
                &conditions,
            ));
        } else {
            let reason = ls_state.reason.as_ref();
            let message = match reason {
                "NotAllowed" => "ListenerSet namespace is not allowed by Gateway",
                "ListenersNotValid" => "ListenerSet listeners are not valid",
                _ => "ListenerSet is not accepted",
            };
            let conditions = vec![
                condition_json(
                    "Accepted",
                    "False",
                    reason,
                    message,
                    ls_state.generation,
                    &now,
                ),
                condition_json(
                    "Programmed",
                    "False",
                    reason,
                    message,
                    ls_state.generation,
                    &now,
                ),
            ];
            listeners.push(listener_status_json(
                listener.name.as_ref(),
                &supported_kinds,
                attached_routes.get(idx).copied().unwrap_or(0),
                &conditions,
            ));
        }
    }

    serde_json::json!({
        "conditions": conditions,
        "listeners": serde_json::Value::Array(listeners),
    })
}

/// Count attached HTTPRoutes per ListenerSet listener.
///
/// A route attaches to a listener when its parentRef selects the ListenerSet
/// (matching group, kind, namespace, and name), the listener's allowedRoutes
/// permit the route's namespace and kind, and the hostnames intersect.
pub fn attached_routes_per_listener(
    ls_state: &ListenerSetState,
    httproutes: &[HTTPRoute],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_set_allowed: &HashMap<(String, String, String), AllowedRoutes>,
) -> Vec<i64> {
    let ls_group = "gateway.networking.k8s.io";
    let ls_kind = "ListenerSet";
    let ls_ns = ls_state.namespace.as_ref();
    let ls_name = ls_state.name.as_ref();

    let mut counts = vec![0i64; ls_state.listeners.len()];
    for route in httproutes {
        let route_ns = route.metadata.namespace.as_deref().unwrap_or(ls_ns);
        let route_hostnames = parse_route_hostnames(route);
        let refs = parse_parent_refs(route);
        for parsed in refs {
            if parsed.kind != ls_kind || parsed.group != ls_group {
                continue;
            }
            let parent_ns = parsed.namespace.as_deref().unwrap_or(ls_ns);
            if parent_ns != ls_ns || parsed.name != ls_name {
                continue;
            }

            let matching_indices: Vec<usize> = ls_state
                .listeners
                .iter()
                .enumerate()
                .filter(|(_idx, l)| {
                    if ls_state.conflicts.contains_key(l.name.as_ref()) {
                        return false;
                    }
                    let section_matches = parsed
                        .section_name
                        .as_deref()
                        .map(|s| s == l.name.as_ref())
                        .unwrap_or(true);
                    if !section_matches {
                        return false;
                    }
                    let allowed = listener_set_allowed
                        .get(&(ls_ns.to_string(), ls_name.to_string(), l.name.to_string()))
                        .cloned()
                        .unwrap_or_default();
                    if !listener_allows_kind(&allowed, "gateway.networking.k8s.io", "HTTPRoute") {
                        return false;
                    }
                    if !namespace_allowed(&allowed.namespaces, route_ns, ls_ns, namespace_labels) {
                        return false;
                    }
                    listener_hostname_intersects(l.hostname.as_deref(), &route_hostnames)
                })
                .map(|(idx, _)| idx)
                .collect();

            for idx in matching_indices {
                counts[idx] += 1;
            }
        }
    }
    counts
}
