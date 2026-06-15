// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ListenerSet reconciler helpers.
//!
//! This module parses ListenerSet resources, validates them against the parent
//! Gateway's `allowedListeners`, and produces the model state used by the
//! translation layer.  It is also used by the status-writeback controller.

use crate::gateway::api::listenerset::{ListenerSet, ListenerSetListeners};
use crate::gateway::api::Gateway;
use crate::gateway::api::HTTPRoute;
use crate::gateway::api::ReferenceGrant;
use crate::gateway::model::{
    AllowedRoutes, GatewayState, HostnameMatch, ListenerSetState, ListenerState, NamespaceFrom,
    ParentRef, RouteNamespaces, TlsMode,
};
use crate::gateway::reconcile::gateway::parse_allowed_routes;
use crate::gateway::reconcile::gatewayclass::supported_features;
use crate::gateway::reconcile::httproute::parse_parent_refs;
use crate::gateway::reconcile::refgrant::{reconcile_reference_grants, GrantIndex};
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Parse the TLS termination mode from a ListenerSet listener entry.
fn parse_tls_mode(
    obj: &serde_json::Map<String, serde_json::Value>,
    protocol: &str,
) -> Option<TlsMode> {
    match protocol {
        "HTTPS" => Some(TlsMode::Terminate),
        "TLS" => {
            let explicit = obj
                .get("tls")
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("mode"))
                .and_then(|v| v.as_str());
            match explicit {
                Some("Terminate") => Some(TlsMode::Terminate),
                Some("Passthrough") => Some(TlsMode::Passthrough),
                _ => Some(TlsMode::Passthrough),
            }
        }
        _ => None,
    }
}

/// Build a [`ListenerState`] from a raw ListenerSet listener entry.
pub fn build_listener_state(entry: &ListenerSetListeners) -> ListenerState {
    // The strongly-typed entry already exposes name/protocol/port/hostname as
    // strings, but allowedRoutes/tls are stored as raw JSON.  Convert to a JSON
    // object so we can reuse the Gateway listener parsing helpers.
    let obj = match serde_json::to_value(entry) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    let name: Arc<str> = entry.name.clone().into();
    let protocol: Arc<str> = entry.protocol.clone().into();
    let port = entry.port as u16;
    let hostname = entry.hostname.as_deref().map(Arc::from);
    let tls_mode = parse_tls_mode(&obj, protocol.as_ref());
    ListenerState {
        name,
        protocol,
        port,
        hostname,
        tls_mode,
        frontend_validation: None,
        programmed: true,
    }
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
            if map.is_empty() {
                None
            } else {
                Some(map)
            }
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
    crate::gateway::reconcile::httproute::namespace_allowed(
        &allowed,
        ls_ns,
        gw_ns,
        namespace_labels,
    )
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
                (
                    ls.namespace.to_string(),
                    ls.name.to_string(),
                    listener.name.to_string(),
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
                crate::gateway::reconcile::gateway::validate_listener_kinds(&obj);
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
        serde_json::json!({
            "type": "Accepted",
            "status": if ls_state.accepted { "True" } else { "False" },
            "reason": accepted_reason,
            "message": accepted_message,
            "observedGeneration": ls_state.generation,
            "lastTransitionTime": now,
        }),
        serde_json::json!({
            "type": "Programmed",
            "status": if ls_state.programmed { "True" } else { "False" },
            "reason": if ls_state.programmed { "Programmed" } else { accepted_reason },
            "message": if ls_state.programmed { "ListenerSet programmed" } else { accepted_message },
            "observedGeneration": ls_state.generation,
            "lastTransitionTime": now,
        }),
    ];

    let mut listeners = Vec::new();
    let features = supported_features.clone();
    for (idx, listener) in ls_state.listeners.iter().enumerate() {
        let supported_kinds = crate::gateway::reconcile::gateway::listener_supported_kinds(
            listener.protocol.as_ref(),
            listener.tls_mode,
            &features,
        );
        if let Some(reason) = ls_state.conflicts.get(listener.name.as_ref()) {
            listeners.push(serde_json::json!({
                "name": listener.name.as_ref(),
                "supportedKinds": supported_kinds,
                "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "reason": reason.as_ref(),
                        "message": "Listener conflicts with a higher-precedence listener",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Programmed",
                        "status": "False",
                        "reason": reason.as_ref(),
                        "message": "Listener conflicts with a higher-precedence listener",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Conflicted",
                        "status": "True",
                        "reason": reason.as_ref(),
                        "message": "Listener conflicts with a higher-precedence listener",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                ],
            }));
        } else if let Some(reason) = ls_state.listener_kind_errors.get(idx).cloned().flatten() {
            let message = match reason.as_ref() {
                "InvalidRouteKinds" => "Listener contains unsupported route kinds",
                _ => "Listener references are not valid",
            };
            listeners.push(serde_json::json!({
                "name": listener.name.as_ref(),
                "supportedKinds": supported_kinds,
                "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "reason": "ListenersNotValid",
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Programmed",
                        "status": "False",
                        "reason": "ListenersNotValid",
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": "False",
                        "reason": reason.as_ref(),
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                ],
            }));
        } else if let Some(reason) = ls_state.listener_cert_errors.get(idx).cloned().flatten() {
            let message = match reason.as_ref() {
                "RefNotPermitted" => {
                    "Cross-namespace CertificateRef is not permitted by ReferenceGrant"
                }
                _ => "CertificateRef is not valid",
            };
            listeners.push(serde_json::json!({
                "name": listener.name.as_ref(),
                "supportedKinds": supported_kinds,
                "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "reason": "ListenersNotValid",
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Programmed",
                        "status": "False",
                        "reason": "ListenersNotValid",
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": "False",
                        "reason": reason.as_ref(),
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                ],
            }));
        } else if ls_state.accepted {
            listeners.push(serde_json::json!({
                "name": listener.name.as_ref(),
                "supportedKinds": supported_kinds,
                "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "Listener accepted",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Programmed",
                        "status": "True",
                        "reason": "Programmed",
                        "message": "Listener programmed",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "ResolvedRefs",
                        "status": "True",
                        "reason": "ResolvedRefs",
                        "message": "Listener references resolved",
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                ],
            }));
        } else {
            let reason = ls_state.reason.as_ref();
            let message = match reason {
                "NotAllowed" => "ListenerSet namespace is not allowed by Gateway",
                "ListenersNotValid" => "ListenerSet listeners are not valid",
                _ => "ListenerSet is not accepted",
            };
            listeners.push(serde_json::json!({
                "name": listener.name.as_ref(),
                "supportedKinds": supported_kinds,
                "attachedRoutes": attached_routes.get(idx).copied().unwrap_or(0),
                "conditions": [
                    {
                        "type": "Accepted",
                        "status": "False",
                        "reason": reason,
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                    {
                        "type": "Programmed",
                        "status": "False",
                        "reason": reason,
                        "message": message,
                        "observedGeneration": ls_state.generation,
                        "lastTransitionTime": now,
                    },
                ],
            }));
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
pub(crate) fn attached_routes_per_listener(
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
        let route_hostnames = crate::gateway::reconcile::httproute::parse_route_hostnames(route);
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
                    if !crate::gateway::reconcile::httproute::listener_allows_kind(
                        &allowed,
                        "gateway.networking.k8s.io",
                        "HTTPRoute",
                    ) {
                        return false;
                    }
                    if !crate::gateway::reconcile::httproute::namespace_allowed(
                        &allowed.namespaces,
                        route_ns,
                        ls_ns,
                        namespace_labels,
                    ) {
                        return false;
                    }
                    crate::gateway::reconcile::httproute::listener_hostname_intersects(
                        l.hostname.as_deref(),
                        &route_hostnames,
                    )
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

/// Context shared across ListenerSet reconcile invocations.
#[derive(Clone)]
pub struct ListenerSetContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Reconcile a single ListenerSet: validate against parent Gateway and patch status.
pub async fn reconcile_listenerset(
    ls: Arc<ListenerSet>,
    ctx: Arc<ListenerSetContext>,
) -> Result<Action, kube::Error> {
    let ns = ls.metadata.namespace.clone().unwrap_or_default();
    let name = ls.metadata.name.clone().unwrap_or_default();

    let gateways: Api<Gateway> = Api::all(ctx.client.clone());
    let listenersets: Api<ListenerSet> = Api::all(ctx.client.clone());
    let httproutes: Api<HTTPRoute> = Api::all(ctx.client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());
    let referencegrants: Api<ReferenceGrant> = Api::all(ctx.client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let listenerset_list = match listenersets.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ListenerSets for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let httproute_list = match httproutes.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list HTTPRoutes for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let referencegrant_list = match referencegrants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for ListenerSet reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let grant_index = GrantIndex::new(reconcile_reference_grants(&referencegrant_list.items));

    let namespace_labels: HashMap<String, HashMap<String, String>> = namespace_list
        .iter()
        .map(|ns| {
            let name = ns.metadata.name.clone().unwrap_or_default();
            let labels: HashMap<String, String> = ns
                .metadata
                .labels
                .clone()
                .unwrap_or_default()
                .into_iter()
                .collect();
            (name, labels)
        })
        .collect();

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();
    let mut listener_set_states: Vec<ListenerSetState> = Vec::new();
    for ls in &listenerset_list.items {
        listener_set_states.push(
            build_listener_set_state(
                ls,
                &gateway_list.items,
                &namespace_labels,
                &ctx.client,
                &grant_index,
            )
            .await,
        );
    }
    resolve_listener_set_conflicts(&mut listener_set_states, &gateway_states);

    let listener_set_allowed =
        build_listener_set_allowed_map(&listenerset_list.items, &listener_set_states);
    let ls_state = match listener_set_states
        .iter()
        .find(|s| s.namespace.as_ref() == ns && s.name.as_ref() == name)
    {
        Some(s) => s.clone(),
        None => {
            build_listener_set_state(
                &ls,
                &gateway_list.items,
                &namespace_labels,
                &ctx.client,
                &grant_index,
            )
            .await
        }
    };
    let attached = attached_routes_per_listener(
        &ls_state,
        &httproute_list.items,
        &namespace_labels,
        &listener_set_allowed,
    );

    if ctx.is_leader.load(Ordering::Relaxed) {
        let features: HashSet<String> = supported_features().into_iter().collect();
        let new_status = build_listener_set_status(&ls_state, &attached, &features);

        let old_status_json = ls
            .status
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);

        if old_stripped == new_stripped {
            tracing::debug!(
                name,
                namespace = ns,
                "ListenerSet status unchanged, skipping patch"
            );
        } else {
            let patch_body = serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "ListenerSet",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "status": new_status,
            });

            let api: Api<ListenerSet> = Api::namespaced(ctx.client.clone(), &ns);
            let pp = PatchParams::apply("sunbeam-proxy");
            if let Err(e) = api
                .patch_status(&name, &pp, &Patch::Apply(&patch_body))
                .await
            {
                tracing::warn!(error = %e, name, namespace = ns, "ListenerSet status patch failed");
            } else {
                tracing::debug!(name, namespace = ns, "ListenerSet status patched");
            }
        }
    }

    crate::gateway::reconcile::trigger::trigger();
    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy_listenerset(
    _ls: Arc<ListenerSet>,
    _error: &kube::Error,
    _ctx: Arc<ListenerSetContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Patch ListenerSet statuses from the reconcile tick.
///
/// This keeps status writeback out of the event-driven controller path so that
/// a burst of ListenerSet creations does not overload the API server.
pub(crate) async fn patch_listener_set_statuses(
    client: &Client,
    listener_sets: &[ListenerSet],
    states: &[ListenerSetState],
    httproutes: &[HTTPRoute],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    is_leader: bool,
) {
    if !is_leader {
        return;
    }

    let features: HashSet<String> = supported_features().into_iter().collect();
    let pp = PatchParams::apply("sunbeam-proxy");
    let listener_set_allowed = build_listener_set_allowed_map(listener_sets, states);

    for state in states {
        let Some(raw) = listener_sets.iter().find(|ls| {
            ls.metadata.namespace.as_deref().unwrap_or("default") == state.namespace.as_ref()
                && ls.metadata.name.as_deref().unwrap_or("") == state.name.as_ref()
        }) else {
            continue;
        };

        let attached = attached_routes_per_listener(
            state,
            httproutes,
            namespace_labels,
            &listener_set_allowed,
        );
        let new_status = build_listener_set_status(state, &attached, &features);

        let old_status_json = raw
            .status
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or(serde_json::Value::Null);
        let old_stripped = crate::gateway::reconcile::strip_last_transition_time(&old_status_json);
        let new_stripped = crate::gateway::reconcile::strip_last_transition_time(&new_status);
        if old_stripped == new_stripped {
            continue;
        }

        let ns = state.namespace.to_string();
        let name = state.name.to_string();
        let patch_body = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": &name, "namespace": &ns },
            "status": new_status,
        });

        let api: Api<ListenerSet> = Api::namespaced(client.clone(), &ns);
        if let Err(e) = api
            .patch_status(&name, &pp, &Patch::Apply(&patch_body))
            .await
        {
            tracing::warn!(error = %e, name, namespace = ns, "ListenerSet status patch failed");
        } else {
            tracing::debug!(name, namespace = ns, "ListenerSet status patched");
        }
    }
}

/// Start the ListenerSet controller.
pub fn run_listenerset_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(ListenerSetContext {
        client: client.clone(),
        is_leader,
    });
    tokio::spawn(async move {
        let routes = Api::<ListenerSet>::all(client);
        Controller::new(routes, kube::runtime::watcher::Config::default())
            .run(reconcile_listenerset, error_policy_listenerset, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("ListenerSet controller error: {e}"),
                }
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::api::Gateway;
    use crate::gateway::model::RouteGroupKind;

    fn sample_listener(name: &str, protocol: &str, port: u16) -> ListenerState {
        ListenerState {
            name: Arc::from(name),
            protocol: Arc::from(protocol),
            port,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
            programmed: true,
        }
    }

    fn sample_gateway_state(name: &str, listeners: Vec<ListenerState>) -> GatewayState {
        GatewayState {
            namespace: Arc::from("default"),
            name: Arc::from(name),
            generation: 1,
            listeners,
            backend_client_cert_id: None,
        }
    }

    fn sample_listener_set_state(
        name: &str,
        listeners: Vec<ListenerState>,
        accepted: bool,
    ) -> ListenerSetState {
        ListenerSetState {
            namespace: Arc::from("default"),
            name: Arc::from(name),
            generation: 1,
            created_at: 1,
            parent_ref: ParentRef {
                group: Arc::from("gateway.networking.k8s.io"),
                kind: Arc::from("Gateway"),
                namespace: None,
                name: Arc::from("gw"),
                section_name: None,
                port: None,
            },
            listeners,
            conflicts: BTreeMap::new(),
            accepted,
            programmed: accepted,
            reason: Arc::from("Accepted"),
            listener_cert_errors: vec![],
            listener_kind_errors: vec![],
        }
    }

    #[test]
    fn parse_tls_mode_https_terminates() {
        let obj = serde_json::Map::new();
        assert_eq!(parse_tls_mode(&obj, "HTTPS"), Some(TlsMode::Terminate));
    }

    #[test]
    fn parse_tls_mode_tls_respects_mode() {
        let mut obj = serde_json::Map::new();
        obj.insert("tls".into(), serde_json::json!({"mode": "Terminate"}));
        assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Terminate));

        obj.insert("tls".into(), serde_json::json!({"mode": "Passthrough"}));
        assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Passthrough));

        obj.insert("tls".into(), serde_json::json!({"mode": "Unknown"}));
        assert_eq!(parse_tls_mode(&obj, "TLS"), Some(TlsMode::Passthrough));
    }

    #[test]
    fn parse_tls_mode_http_returns_none() {
        let obj = serde_json::Map::new();
        assert_eq!(parse_tls_mode(&obj, "HTTP"), None);
    }

    #[test]
    fn build_listener_state_parses_entry() {
        let entry = ListenerSetListeners {
            name: "https".into(),
            port: 8443,
            protocol: "HTTPS".into(),
            hostname: Some("example.com".into()),
            tls: None,
            allowed_routes: None,
        };
        let state = build_listener_state(&entry);
        assert_eq!(state.name.as_ref(), "https");
        assert_eq!(state.port, 8443);
        assert_eq!(state.protocol.as_ref(), "HTTPS");
        assert_eq!(state.hostname.as_deref(), Some("example.com"));
        assert_eq!(state.tls_mode, Some(TlsMode::Terminate));
        assert!(state.programmed);
    }

    #[test]
    fn parse_allowed_listeners_defaults() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
        }))
        .unwrap();
        let ns = parse_allowed_listeners(&gw);
        assert_eq!(ns.from, NamespaceFrom::None);
        assert!(ns.selector.is_none());
    }

    #[test]
    fn parse_allowed_listeners_all_and_selector() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": {
                    "namespaces": { "from": "All" }
                }
            }
        }))
        .unwrap();
        assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::All);

        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": {
                    "namespaces": {
                        "from": "Selector",
                        "selector": { "matchLabels": { "team": "gateway" } }
                    }
                }
            }
        }))
        .unwrap();
        let ns = parse_allowed_listeners(&gw);
        assert_eq!(ns.from, NamespaceFrom::Selector);
        assert_eq!(
            ns.selector.unwrap().get("team"),
            Some(&"gateway".to_string())
        );
    }

    #[test]
    fn listener_set_allowed_by_same_namespace() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": { "from": "Same" } }
            }
        }))
        .unwrap();
        let labels = HashMap::new();
        assert!(listener_set_allowed("default", &gw, &labels));
        assert!(!listener_set_allowed("other", &gw, &labels));
    }

    #[test]
    fn listener_set_allowed_by_selector() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": {
                    "namespaces": {
                        "from": "Selector",
                        "selector": { "matchLabels": { "team": "gateway" } }
                    }
                }
            }
        }))
        .unwrap();
        let mut labels = HashMap::new();
        labels.insert(
            "other".into(),
            [("team".into(), "gateway".into())].into_iter().collect(),
        );
        assert!(listener_set_allowed("other", &gw, &labels));
        labels.clear();
        assert!(!listener_set_allowed("other", &gw, &labels));
    }

    fn sample_listener_set(name: &str, listeners: Vec<ListenerSetListeners>) -> ListenerSet {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": name, "namespace": "default" },
            "spec": {
                "parentRef": { "name": "gw" },
                "listeners": listeners
            }
        }))
        .unwrap()
    }

    #[test]
    fn find_parent_gateway_matches() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
        }))
        .unwrap();
        let ls = sample_listener_set("ls", vec![]);
        let gateways = [gw];
        let (idx, found) = find_parent_gateway(&ls, &gateways).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(found.metadata.name.as_deref().unwrap(), "gw");
    }

    #[test]
    fn find_parent_gateway_not_found() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "other", "namespace": "default" },
            "spec": { "gatewayClassName": "sunbeam", "listeners": [] }
        }))
        .unwrap();
        let ls = sample_listener_set("ls", vec![]);
        let gateways = [gw];
        assert!(find_parent_gateway(&ls, &gateways).is_none());
    }

    #[test]
    fn resolve_listener_set_conflicts_prefers_gateway() {
        let gw = sample_gateway_state("gw", vec![sample_listener("http", "HTTP", 80)]);
        let ls = sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        let mut slice = [ls];
        resolve_listener_set_conflicts(&mut slice, &[gw]);
        let ls = slice.into_iter().next().unwrap();
        assert_eq!(
            ls.conflicts.get("http").map(|r| r.as_ref()),
            Some("HostnameConflict")
        );

        // When all listeners conflict, the ListenerSet is no longer accepted.
        let mut slice = [ls];
        resolve_listener_set_conflicts(&mut slice, &[]);
        let ls = slice.into_iter().next().unwrap();
        assert!(!ls.accepted);
    }

    #[test]
    fn resolve_listener_set_conflicts_detects_protocol_conflict() {
        let gw = sample_gateway_state(
            "gw",
            vec![ListenerState {
                name: Arc::from("http"),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: Some(Arc::from("example.com")),
                tls_mode: None,
                frontend_validation: None,
                programmed: true,
            }],
        );
        let ls = sample_listener_set_state(
            "ls",
            vec![ListenerState {
                name: Arc::from("https"),
                protocol: Arc::from("HTTPS"),
                port: 80,
                hostname: Some(Arc::from("example.com")),
                tls_mode: Some(TlsMode::Terminate),
                frontend_validation: None,
                programmed: true,
            }],
            true,
        );
        let mut slice = [ls];
        resolve_listener_set_conflicts(&mut slice, &[gw]);
        let ls = slice.into_iter().next().unwrap();
        assert_eq!(
            ls.conflicts.get("https").map(|r| r.as_ref()),
            Some("ProtocolConflict")
        );
    }

    #[test]
    fn count_attached_listener_sets_filters_accepted() {
        let mut accepted = sample_listener_set_state("ls1", vec![], true);
        accepted.accepted = true;
        accepted.programmed = true;
        let mut rejected = sample_listener_set_state("ls2", vec![], false);
        rejected.accepted = false;
        rejected.programmed = false;
        assert_eq!(
            count_attached_listener_sets("default", "gw", &[accepted, rejected]),
            1
        );
    }

    #[test]
    fn build_listener_set_status_accepted() {
        let state =
            sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        let features = std::collections::HashSet::new();
        let status = build_listener_set_status(&state, &[1], &features);
        let listeners = status.get("listeners").unwrap().as_array().unwrap();
        assert_eq!(listeners.len(), 1);
        let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
        assert!(conditions
            .iter()
            .any(|c| c.get("type").unwrap() == "Accepted"));
    }

    #[test]
    fn build_listener_set_status_not_allowed() {
        let mut state = sample_listener_set_state("ls", vec![], false);
        state.reason = Arc::from("NotAllowed");
        let status = build_listener_set_status(&state, &[], &std::collections::HashSet::new());
        let conditions = status.get("conditions").unwrap().as_array().unwrap();
        assert!(conditions
            .iter()
            .any(|c| c.get("reason").unwrap() == "NotAllowed"));
    }

    #[test]
    fn build_listener_set_status_conflicted_listener() {
        let mut state =
            sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        state
            .conflicts
            .insert(Arc::from("http"), Arc::from("HostnameConflict"));
        let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
        let listeners = status.get("listeners").unwrap().as_array().unwrap();
        assert!(listeners[0]
            .get("conditions")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.get("type").unwrap() == "Conflicted"));
    }

    #[test]
    fn build_listener_set_status_kind_error() {
        let mut state =
            sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        state.listener_kind_errors = vec![Some(Arc::from("InvalidRouteKinds"))];
        let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
        let listeners = status.get("listeners").unwrap().as_array().unwrap();
        let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
        assert!(conditions
            .iter()
            .any(|c| c.get("type").unwrap() == "ResolvedRefs"));
    }

    #[test]
    fn build_listener_set_status_cert_error() {
        let mut state =
            sample_listener_set_state("ls", vec![sample_listener("https", "HTTPS", 443)], true);
        state.listener_cert_errors = vec![Some(Arc::from("RefNotPermitted"))];
        let status = build_listener_set_status(&state, &[0], &std::collections::HashSet::new());
        let listeners = status.get("listeners").unwrap().as_array().unwrap();
        let conditions = listeners[0].get("conditions").unwrap().as_array().unwrap();
        assert!(conditions
            .iter()
            .any(|c| c.get("reason").unwrap() == "RefNotPermitted"));
    }

    #[test]
    fn build_listener_set_allowed_map_skips_conflicts() {
        let raw = sample_listener_set(
            "ls",
            vec![ListenerSetListeners {
                name: "http".into(),
                port: 80,
                protocol: "HTTP".into(),
                hostname: None,
                tls: None,
                allowed_routes: None,
            }],
        );
        let mut state =
            sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        state
            .conflicts
            .insert(Arc::from("http"), Arc::from("HostnameConflict"));
        let map = build_listener_set_allowed_map(&[raw], &[state]);
        assert!(map.is_empty());
    }

    #[test]
    fn attached_routes_per_listener_counts_matches() {
        let ls_state =
            sample_listener_set_state("ls", vec![sample_listener("http", "HTTP", 80)], true);
        let httproute: HTTPRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "group": "gateway.networking.k8s.io", "kind": "ListenerSet", "name": "ls", "sectionName": "http" }],
                "hostnames": ["example.com"],
                "rules": [{ "backendRefs": [{ "name": "svc", "port": 80 }] }]
            }
        })).unwrap();
        let mut allowed = HashMap::new();
        allowed.insert(
            ("default".into(), "ls".into(), "http".into()),
            AllowedRoutes {
                kinds: vec![RouteGroupKind {
                    group: Arc::from("gateway.networking.k8s.io"),
                    kind: Arc::from("HTTPRoute"),
                }],
                namespaces: RouteNamespaces {
                    from: NamespaceFrom::All,
                    selector: None,
                },
            },
        );
        let counts =
            attached_routes_per_listener(&ls_state, &[httproute], &HashMap::new(), &allowed);
        assert_eq!(counts, vec![1]);
    }

    #[test]
    fn parse_allowed_listeners_invalid_and_missing_namespaces() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": "not-an-object"
            }
        }))
        .unwrap();
        assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::Same);

        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": "not-an-object" }
            }
        }))
        .unwrap();
        assert_eq!(parse_allowed_listeners(&gw).from, NamespaceFrom::Same);
    }

    fn fake_client() -> kube::Client {
        kube::Client::new(
            tower::service_fn(|req: http::Request<kube::client::Body>| async move {
                let path = req.uri().path();
                let body = if path.contains("/namespaces") {
                    serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []})
                } else if path.ends_with("/status") && req.method() == "PATCH" {
                    serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ListenerSet", "metadata": {"name": "ls-1", "namespace": "default"}, "status": {}})
                } else {
                    serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "List", "items": []})
                };
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body.to_string().into_bytes()))
                        .unwrap(),
                )
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn build_listener_set_state_allowed_http_listener() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": { "from": "All" } }
            }
        }))
        .unwrap();
        let ls = sample_listener_set(
            "ls",
            vec![ListenerSetListeners {
                name: "http".into(),
                port: 80,
                protocol: "HTTP".into(),
                hostname: None,
                tls: None,
                allowed_routes: None,
            }],
        );
        let state = build_listener_set_state(
            &ls,
            &[gw],
            &HashMap::new(),
            &fake_client(),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.accepted);
        assert!(state.programmed);
        assert_eq!(state.listeners.len(), 1);
        assert!(state.listener_cert_errors.iter().all(|e| e.is_none()));
    }

    #[tokio::test]
    async fn build_listener_set_state_not_allowed() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": { "from": "Same" } }
            }
        }))
        .unwrap();
        let ls: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls", "namespace": "other" },
            "spec": { "parentRef": { "name": "gw" }, "listeners": [] }
        }))
        .unwrap();
        let state = build_listener_set_state(
            &ls,
            &[gw],
            &HashMap::new(),
            &fake_client(),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(!state.accepted);
        assert_eq!(state.reason.as_ref(), "NotAllowed");
    }

    #[tokio::test]
    async fn build_listener_set_state_invalid_kind() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": { "from": "All" } }
            }
        }))
        .unwrap();
        let ls: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls", "namespace": "default" },
            "spec": {
                "parentRef": { "name": "gw" },
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": { "kinds": [{ "group": "gateway.networking.k8s.io", "kind": "TCPRoute" }] }
                }]
            }
        }))
        .unwrap();
        let state = build_listener_set_state(
            &ls,
            &[gw],
            &HashMap::new(),
            &fake_client(),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listener_kind_errors.iter().any(|e| e.is_some()));
    }

    #[tokio::test]
    async fn build_listener_set_state_cert_error() {
        let gw: Gateway = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": "gw", "namespace": "default" },
            "spec": {
                "gatewayClassName": "sunbeam",
                "listeners": [],
                "allowedListeners": { "namespaces": { "from": "All" } }
            }
        }))
        .unwrap();
        let ls: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls", "namespace": "default" },
            "spec": {
                "parentRef": { "name": "gw" },
                "listeners": [{
                    "name": "https",
                    "port": 443,
                    "protocol": "HTTPS",
                    "tls": { "certificateRefs": [{ "name": "missing-secret" }] }
                }]
            }
        }))
        .unwrap();
        let state = build_listener_set_state(
            &ls,
            &[gw],
            &HashMap::new(),
            &fake_client(),
            &GrantIndex::new(vec![]),
        )
        .await;
        assert!(state.listener_cert_errors.iter().any(|e| e.is_some()));
    }

    #[tokio::test]
    async fn reconcile_listenerset_patches_status_when_leader() {
        let ls: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
        }))
        .unwrap();
        let ctx = Arc::new(ListenerSetContext {
            client: fake_client(),
            is_leader: Arc::new(AtomicBool::new(true)),
        });
        let action = reconcile_listenerset(Arc::new(ls), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn error_policy_listenerset_requeues_after_5s() {
        let ls = Arc::new(sample_listener_set("ls", vec![]));
        let ctx = Arc::new(ListenerSetContext {
            client: fake_client(),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = error_policy_listenerset(
            ls,
            &kube::Error::Service(std::io::Error::other("test").into()),
            ctx,
        );
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn run_listenerset_controller_returns_handle() {
        let ctx = Arc::new(AtomicBool::new(false));
        let handle = run_listenerset_controller(fake_client(), ctx);
        handle.abort();
    }

    #[tokio::test]
    async fn reconcile_listenerset_non_leader_skips_patch() {
        let ls: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
        }))
        .unwrap();
        let ctx = Arc::new(ListenerSetContext {
            client: fake_client(),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_listenerset(Arc::new(ls), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn patch_listener_set_statuses_leader_patches() {
        let raw: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
        }))
        .unwrap();
        let state = sample_listener_set_state("ls-1", vec![], true);
        patch_listener_set_statuses(&fake_client(), &[raw], &[state], &[], &HashMap::new(), true)
            .await;
    }

    #[tokio::test]
    async fn patch_listener_set_statuses_non_leader_returns() {
        let raw: ListenerSet = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": "ls-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRef": { "name": "gw-1" }, "listeners": [] }
        }))
        .unwrap();
        let state = sample_listener_set_state("ls-1", vec![], true);
        patch_listener_set_statuses(
            &fake_client(),
            &[raw],
            &[state],
            &[],
            &HashMap::new(),
            false,
        )
        .await;
    }
}
