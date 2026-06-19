// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared parentRef parsing and resolution for Gateway API routes.

use crate::gateway::model::{AllowedRoutes, NamespaceFrom, ParentRef, RouteNamespaces};
use crate::gateway::status::{ConditionStatus, StatusCondition, conditions};
use std::collections::HashMap;
use std::sync::Arc;

/// A parsed Gateway API parentRef in a route-independent form.
#[derive(Clone, Debug)]
pub struct ParsedParentRef {
    pub group: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub name: String,
    pub section_name: Option<String>,
    pub port: Option<i32>,
}

/// Generate a parentRef parser for a route CRD whose `spec.parentRefs`
/// items have `group`, `kind`, `namespace`, `name`, `section_name`, and `port`.
#[macro_export]
macro_rules! impl_parse_parent_refs {
    ($fn_name:ident, $Route:ty, $ParentRef:ty) => {
        pub fn $fn_name(
            route: &$Route,
        ) -> ::std::vec::Vec<$crate::gateway::reconcile::parent::ParsedParentRef> {
            use $crate::gateway::reconcile::parent::ParsedParentRef;
            route
                .spec
                .parent_refs
                .as_ref()
                .map(|refs| {
                    refs.iter()
                        .filter_map(|value: &$ParentRef| {
                            Some(ParsedParentRef {
                                group: value
                                    .group
                                    .as_deref()
                                    .unwrap_or("gateway.networking.k8s.io")
                                    .to_string(),
                                kind: value.kind.as_deref().unwrap_or("Gateway").to_string(),
                                namespace: value.namespace.clone(),
                                name: value.name.clone(),
                                section_name: value.section_name.clone(),
                                port: value.port,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
    };
}

/// Check whether a listener's allowed-route kinds include the given group/kind.
pub fn listener_allows_kind(allowed: &AllowedRoutes, group: &str, kind: &str) -> bool {
    allowed.kinds.is_empty()
        || allowed
            .kinds
            .iter()
            .any(|k| k.group.as_ref() == group && k.kind.as_ref() == kind)
}

/// Check whether a listener's namespace scope allows routes from `route_ns`.
pub fn namespace_allowed(
    namespaces: &RouteNamespaces,
    route_ns: &str,
    gateway_ns: &str,
    namespace_labels: &HashMap<String, HashMap<String, String>>,
) -> bool {
    match namespaces.from {
        NamespaceFrom::All => true,
        NamespaceFrom::Same => route_ns == gateway_ns,
        NamespaceFrom::None => false,
        NamespaceFrom::Selector => {
            let labels = match namespace_labels.get(route_ns) {
                Some(l) => l,
                None => return false,
            };
            namespaces
                .selector
                .as_ref()
                .is_some_and(|sel| sel.iter().all(|(k, v)| labels.get(k) == Some(v)))
        }
    }
}

/// Check whether a listener hostname intersects any of the route hostnames.
pub fn listener_hostname_intersects(
    listener_hostname: Option<&str>,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
) -> bool {
    if route_hostnames.is_empty() {
        return true;
    }
    let Some(listener_hostname) = listener_hostname else {
        return true;
    };
    let listener_match = crate::gateway::translate::parse_listener_hostname(listener_hostname);
    route_hostnames
        .iter()
        .any(|rh| crate::gateway::translate::hostname_intersects(rh, &listener_match))
}

/// Resolve a parentRef against a Gateway listener set.
#[allow(clippy::too_many_arguments)]
pub fn resolve_listener_parent(
    parsed: &ParsedParentRef,
    route_ns: &str,
    observed_generation: i64,
    route_hostnames: &[crate::gateway::model::HostnameMatch],
    listeners: &[crate::gateway::model::ListenerState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    allowed_map: &HashMap<(String, String, String), AllowedRoutes>,
    target_ns: &str,
    owner_name: &str,
    owner_kind: &str,
    conflicts: &std::collections::BTreeMap<Arc<str>, Arc<str>>,
    route_kind: &str,
    expected_protocols: Option<&[&str]>,
) -> (Option<ParentRef>, Vec<StatusCondition>) {
    let matching_listeners: Vec<&crate::gateway::model::ListenerState> = listeners
        .iter()
        .filter(|l| {
            if !l.programmed || conflicts.contains_key(l.name.as_ref()) {
                return false;
            }
            let section_matches = parsed
                .section_name
                .as_deref()
                .map(|s| s == l.name.as_ref())
                .unwrap_or(true);
            let port_matches = parsed.port.map(|p| p == l.port as i32).unwrap_or(true);
            section_matches && port_matches
        })
        .collect();

    if let Some(ref section) = parsed.section_name {
        let listener_exists = listeners
            .iter()
            .any(|l| l.name.as_ref() == section.as_str());
        if !listener_exists {
            return (
                None,
                vec![conditions::accepted_condition(
                    ConditionStatus::False,
                    "NoMatchingParent",
                    &format!(
                        "listener {} not found on {} {}/{}",
                        section, owner_kind, target_ns, owner_name
                    ),
                    observed_generation,
                )],
            );
        }
    }

    if let Some(port) = parsed.port
        && matching_listeners.is_empty()
    {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NoMatchingParent",
                &format!(
                    "no listener matching port {} on {} {}/{}",
                    port, owner_kind, target_ns, owner_name
                ),
                observed_generation,
            )],
        );
    }

    let mut kind_allowed = false;
    let mut protocol_allowed = expected_protocols.is_none();
    let mut namespace_allowed_flag = false;
    let mut hostname_intersects = false;

    for listener in matching_listeners {
        let allowed = allowed_map
            .get(&(
                target_ns.to_string(),
                owner_name.to_string(),
                listener.name.to_string(),
            ))
            .cloned()
            .unwrap_or_default();
        let kind_ok = listener_allows_kind(&allowed, "gateway.networking.k8s.io", route_kind);
        let protocol_ok = expected_protocols
            .map(|protocols| {
                protocols
                    .iter()
                    .any(|p| p.eq_ignore_ascii_case(listener.protocol.as_ref()))
            })
            .unwrap_or(true);
        let ns_ok = namespace_allowed(&allowed.namespaces, route_ns, target_ns, namespace_labels);
        let hostname_ok =
            listener_hostname_intersects(listener.hostname.as_deref(), route_hostnames);

        kind_allowed |= kind_ok;
        protocol_allowed |= protocol_ok;
        namespace_allowed_flag |= ns_ok;
        hostname_intersects |= hostname_ok;

        let _ = listener;
    }

    if !kind_allowed || !protocol_allowed || !namespace_allowed_flag {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NotAllowedByListeners",
                &format!(
                    "Route is not allowed by any listener of {} {}/{}",
                    owner_kind, target_ns, owner_name
                ),
                observed_generation,
            )],
        );
    }

    if !hostname_intersects {
        return (
            None,
            vec![conditions::accepted_condition(
                ConditionStatus::False,
                "NoMatchingListenerHostname",
                &format!(
                    "Route hostnames do not intersect with any listener of {} {}/{}",
                    owner_kind, target_ns, owner_name
                ),
                observed_generation,
            )],
        );
    }

    let parent_ref = ParentRef {
        group: Arc::from(parsed.group.clone()),
        kind: Arc::from(parsed.kind.clone()),
        namespace: Some(Arc::from(target_ns)),
        name: Arc::from(parsed.name.clone()),
        section_name: parsed.section_name.as_ref().map(|s| Arc::from(s.as_str())),
        port: parsed.port.map(|p| p as u16),
    };

    let conditions = vec![conditions::accepted_condition(
        ConditionStatus::True,
        "Accepted",
        "Route accepted by parent",
        observed_generation,
    )];

    (Some(parent_ref), conditions)
}
