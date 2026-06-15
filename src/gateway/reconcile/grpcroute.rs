// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute reconciler.
//!
//! Watches GRPCRoute resources, resolves parentRefs against Gateway
//! listeners, computes `Accepted` / `ResolvedRefs` conditions on
//! `.status.parents[]`, and emits `GRPCRouteState` for the reconciled view.

use crate::gateway::api::GRPCRoute;
use crate::gateway::model::{
    GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, GatewayState, HeaderMatch, HeaderMatchValue,
    HostnameMatch, ListenerSetState, MethodMatch, MethodMatchType, ParentRef, RouteFilter,
    RouteState, WeightedBackend,
};
use crate::gateway::reconcile::httproute::{resolve_parent_ref, ParsedParentRef};
use crate::gateway::reconcile::httproute::{
    BackendResolution, BackendResolutionStatus, RuleBackendResolution,
};
use crate::gateway::reconcile::refgrant::GrantIndex;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition};
use gateway_api::grpcroutes::{
    GrpcRouteRules, GrpcRouteRulesBackendRefs, GrpcRouteRulesFilters,
    GrpcRouteRulesFiltersRequestHeaderModifier, GrpcRouteRulesFiltersResponseHeaderModifier,
    GrpcRouteRulesFiltersType, GrpcRouteRulesMatches, GrpcRouteRulesMatchesHeaders,
    GrpcRouteRulesMatchesHeadersType, GrpcRouteRulesMatchesMethod, GrpcRouteRulesMatchesMethodType,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Result of reconciling a single GRPCRoute.
#[derive(Clone, Debug)]
pub struct ReconciledGRPCRoute {
    pub route_state: RouteState,
    pub parent_statuses: Vec<GRPCRouteParentStatus>,
    /// True only when the route is accepted and all backend references resolve.
    pub programmed: bool,
}

/// Status conditions for a single parentRef entry.
#[derive(Clone, Debug)]
pub struct GRPCRouteParentStatus {
    pub parent_ref: ParentRef,
    pub conditions: Vec<StatusCondition>,
}

/// Reconcile a slice of GRPCRoute CRDs against the current Gateway set.
///
/// This is the test-friendly entry point that uses default listener
/// permissions (same-namespace, GRPCRoute allowed) and no namespace labels.
pub fn reconcile_grpcroutes(
    routes: &[GRPCRoute],
    gateways: &[GatewayState],
    grant_index: &GrantIndex,
) -> Vec<ReconciledGRPCRoute> {
    let namespace_labels = HashMap::<String, HashMap<String, String>>::new();
    let listener_allowed =
        HashMap::<(String, String, String), crate::gateway::model::AllowedRoutes>::new();
    let listener_sets = Vec::<ListenerSetState>::new();
    let listener_set_allowed =
        HashMap::<(String, String, String), crate::gateway::model::AllowedRoutes>::new();
    reconcile_grpcroutes_with_context(
        routes,
        gateways,
        &listener_sets,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        grant_index,
    )
}

/// Reconcile GRPCRoutes with full listener permission context.
pub fn reconcile_grpcroutes_with_context(
    routes: &[GRPCRoute],
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), crate::gateway::model::AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), crate::gateway::model::AllowedRoutes>,
    grant_index: &GrantIndex,
) -> Vec<ReconciledGRPCRoute> {
    routes
        .iter()
        .map(|route| {
            let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
            let backend_resolution = resolve_backend_refs(route, route_ns, grant_index);
            reconcile_single(
                route,
                gateways,
                listener_sets,
                namespace_labels,
                listener_allowed,
                listener_set_allowed,
                grant_index,
                backend_resolution,
            )
        })
        .collect()
}

fn check_backend_permitted(
    backend: &GrpcRouteRulesBackendRefs,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> Result<(), BackendResolutionStatus> {
    let group = backend.group.as_deref().unwrap_or("");
    let kind = backend.kind.as_deref().unwrap_or("Service");
    let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);

    if !group.is_empty() || kind != "Service" {
        return Err(BackendResolutionStatus::Unsupported(format!(
            "backendRef group {} kind {} is not supported",
            group, kind
        )));
    }

    let permitted = grant_index.is_permitted(
        route_ns,
        "gateway.networking.k8s.io",
        "GRPCRoute",
        target_ns,
        group,
        kind,
        &backend.name,
    );

    if !permitted {
        return Err(BackendResolutionStatus::RefNotPermitted(format!(
            "cross-namespace backend reference from {} to {}/{} is not permitted",
            route_ns, target_ns, backend.name
        )));
    }

    Ok(())
}

fn resolve_backend_refs(
    route: &GRPCRoute,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.spec.rules.as_ref() {
        Some(r) => r,
        None => return BackendResolution::ok(),
    };

    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, grant_index) {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
}

/// Async variant that also validates that referenced backend Services exist.
pub async fn resolve_backend_refs_async(
    client: &kube::Client,
    route: &GRPCRoute,
    route_ns: &str,
    grant_index: &GrantIndex,
) -> BackendResolution {
    let rules = match route.spec.rules.as_ref() {
        Some(r) => r,
        None => return BackendResolution::ok(),
    };

    let mut overall = BackendResolutionStatus::Ok;
    let mut rule_results = Vec::with_capacity(rules.len());

    for rule in rules {
        let backends = match rule.backend_refs.as_ref() {
            Some(b) => b,
            None => {
                rule_results.push(RuleBackendResolution {
                    ok: true,
                    message: String::new(),
                });
                continue;
            }
        };

        let mut rule_ok = true;
        let mut rule_message = String::new();
        for backend in backends {
            if let Err(status) = check_backend_permitted(backend, route_ns, grant_index) {
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::Unsupported(msg)
                        | BackendResolutionStatus::RefNotPermitted(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
                continue;
            }

            let target_ns = backend.namespace.as_deref().unwrap_or(route_ns);
            let services: kube::Api<k8s_openapi::api::core::v1::Service> =
                kube::Api::namespaced(client.clone(), target_ns);
            if services.get(&backend.name).await.is_err() {
                let status = BackendResolutionStatus::BackendNotFound(format!(
                    "backend Service {}/{} not found",
                    target_ns, backend.name
                ));
                if matches!(overall, BackendResolutionStatus::Ok) {
                    overall = status.clone();
                }
                rule_ok = false;
                if rule_message.is_empty() {
                    rule_message = match &status {
                        BackendResolutionStatus::BackendNotFound(msg) => msg.clone(),
                        _ => String::new(),
                    };
                }
            }
        }
        rule_results.push(RuleBackendResolution {
            ok: rule_ok,
            message: rule_message,
        });
    }

    BackendResolution {
        overall,
        rules: rule_results,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn reconcile_single(
    route: &GRPCRoute,
    gateways: &[GatewayState],
    listener_sets: &[ListenerSetState],
    namespace_labels: &HashMap<String, HashMap<String, String>>,
    listener_allowed: &HashMap<(String, String, String), crate::gateway::model::AllowedRoutes>,
    listener_set_allowed: &HashMap<(String, String, String), crate::gateway::model::AllowedRoutes>,
    _grant_index: &GrantIndex,
    backend_resolution: BackendResolution,
) -> ReconciledGRPCRoute {
    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let route_name = route.metadata.name.as_deref().unwrap_or("");
    let generation = route.metadata.generation.unwrap_or(0);
    let route_hostnames = parse_route_hostnames(route);

    let parsed_refs = parse_parent_refs(route);
    let mut parent_refs = Vec::with_capacity(parsed_refs.len());
    let mut parent_statuses = Vec::with_capacity(parsed_refs.len());

    for parsed in &parsed_refs {
        let (resolved, mut conditions) = resolve_parent_ref(
            parsed,
            route_ns,
            generation,
            &route_hostnames,
            gateways,
            listener_sets,
            namespace_labels,
            listener_allowed,
            listener_set_allowed,
            "GRPCRoute",
        );
        let status_parent_ref = resolved.clone().unwrap_or_else(|| ParentRef {
            group: Arc::from(parsed.group.clone()),
            kind: Arc::from(parsed.kind.clone()),
            namespace: Some(Arc::from(parsed.namespace.as_deref().unwrap_or(route_ns))),
            name: Arc::from(parsed.name.clone()),
            section_name: parsed.section_name.clone().map(Arc::from),
            port: parsed.port.map(|p| p as u16),
        });
        let accepted = resolved.is_some();
        if let Some(pr) = resolved {
            parent_refs.push(pr);
        }

        // Merge backend ref resolution into the parent status.
        let resolved_refs = match &backend_resolution.overall {
            crate::gateway::reconcile::httproute::BackendResolutionStatus::Ok => {
                resolved_refs_true(generation)
            }
            crate::gateway::reconcile::httproute::BackendResolutionStatus::RefNotPermitted(msg) => {
                StatusCondition {
                    condition_type: ConditionType::ResolvedRefs,
                    status: ConditionStatus::False,
                    reason: "RefNotPermitted".to_string(),
                    message: msg.clone(),
                    observed_generation: generation,
                }
            }
            crate::gateway::reconcile::httproute::BackendResolutionStatus::Unsupported(msg) => {
                StatusCondition {
                    condition_type: ConditionType::ResolvedRefs,
                    status: ConditionStatus::False,
                    reason: "InvalidKind".to_string(),
                    message: msg.clone(),
                    observed_generation: generation,
                }
            }
            crate::gateway::reconcile::httproute::BackendResolutionStatus::BackendNotFound(msg) => {
                StatusCondition {
                    condition_type: ConditionType::ResolvedRefs,
                    status: ConditionStatus::False,
                    reason: "BackendNotFound".to_string(),
                    message: msg.clone(),
                    observed_generation: generation,
                }
            }
        };
        conditions.push(resolved_refs);

        let programmed = if matches!(
            &backend_resolution.overall,
            crate::gateway::reconcile::httproute::BackendResolutionStatus::Ok
        ) && accepted
        {
            StatusCondition {
                condition_type: ConditionType::Programmed,
                status: ConditionStatus::True,
                reason: "Programmed".to_string(),
                message: "Route programmed into proxy".to_string(),
                observed_generation: generation,
            }
        } else {
            StatusCondition {
                condition_type: ConditionType::Programmed,
                status: ConditionStatus::False,
                reason: "NotProgrammed".to_string(),
                message: "Route not programmed into proxy".to_string(),
                observed_generation: generation,
            }
        };
        conditions.push(programmed);

        parent_statuses.push(GRPCRouteParentStatus {
            parent_ref: status_parent_ref,
            conditions,
        });
    }

    let route_state = RouteState {
        namespace: Arc::from(route_ns),
        name: Arc::from(route_name),
        kind: Arc::from("GRPCRoute"),
        generation,
        parent_refs,
    };
    let programmed = !route_state.parent_refs.is_empty()
        && matches!(
            backend_resolution.overall,
            crate::gateway::reconcile::httproute::BackendResolutionStatus::Ok
        );

    ReconciledGRPCRoute {
        route_state,
        parent_statuses,
        programmed,
    }
}

fn resolved_refs_true(observed_generation: i64) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status: ConditionStatus::True,
        reason: "ResolvedRefs".to_string(),
        message: "All references resolved".to_string(),
        observed_generation,
    }
}

fn parse_parent_refs(route: &GRPCRoute) -> Vec<ParsedParentRef> {
    route
        .spec
        .parent_refs
        .as_ref()
        .map(|refs| refs.iter().filter_map(parse_parent_ref).collect())
        .unwrap_or_default()
}

fn parse_parent_ref(
    value: &gateway_api::grpcroutes::GrpcRouteParentRefs,
) -> Option<ParsedParentRef> {
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
}

/// Parse hostnames from a GRPCRoute spec into the model's HostnameMatch types.
pub(crate) fn parse_route_hostnames(route: &GRPCRoute) -> Vec<HostnameMatch> {
    route
        .spec
        .hostnames
        .as_ref()
        .map(|h| {
            h.iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a GRPCRoute CRD into the full `GRPCRouteState` model.
pub fn parse_grpcroute_state(route: &GRPCRoute) -> GRPCRouteState {
    let ns: Arc<str> = Arc::from(route.metadata.namespace.as_deref().unwrap_or("default"));
    let name: Arc<str> = Arc::from(route.metadata.name.as_deref().unwrap_or(""));
    let generation = route.metadata.generation.unwrap_or(0);

    let hostnames: Vec<HostnameMatch> = route
        .spec
        .hostnames
        .as_ref()
        .map(|h| {
            h.iter()
                .map(|s| {
                    if let Some(rest) = s.strip_prefix("*.") {
                        HostnameMatch::Wildcard(Arc::from(rest))
                    } else {
                        HostnameMatch::Exact(Arc::from(s.as_str()))
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let route_ns_str: &str = ns.as_ref();
    let rules: Vec<GRPCRouteRule> = route
        .spec
        .rules
        .as_ref()
        .map(|r| {
            r.iter()
                .filter_map(|rule| parse_rule(rule, route_ns_str))
                .collect()
        })
        .unwrap_or_default();

    GRPCRouteState {
        namespace: ns,
        name,
        generation,
        hostnames,
        rules,
        parent_refs: vec![],
        programmed: false,
    }
}

fn parse_rule(value: &GrpcRouteRules, route_ns: &str) -> Option<GRPCRouteRule> {
    let matches: Vec<GRPCRouteMatch> = value
        .matches
        .as_ref()
        .map(|arr| arr.iter().filter_map(parse_match).collect())
        .unwrap_or_default();

    let backends: Vec<WeightedBackend> = value
        .backend_refs
        .as_ref()
        .map(|arr| {
            arr.iter()
                .filter_map(|b| parse_backend_ref(b, route_ns))
                .collect()
        })
        .unwrap_or_default();

    let filters: Vec<RouteFilter> = value
        .filters
        .as_ref()
        .map(|arr| arr.iter().flat_map(|f| parse_filter(f, route_ns)).collect())
        .unwrap_or_default();

    let name = value.name.as_deref().map(Arc::from);

    Some(GRPCRouteRule {
        name,
        matches,
        backends,
        filters,
        programmed: true,
    })
}

fn parse_match(value: &GrpcRouteRulesMatches) -> Option<GRPCRouteMatch> {
    let method = value.method.as_ref().and_then(parse_method_match);
    let headers = value
        .headers
        .as_ref()
        .map(|arr| arr.iter().filter_map(parse_header_match).collect())
        .unwrap_or_default();
    Some(GRPCRouteMatch { method, headers })
}

fn parse_method_match(value: &GrpcRouteRulesMatchesMethod) -> Option<MethodMatch> {
    let match_type = match value.r#type.as_ref() {
        Some(GrpcRouteRulesMatchesMethodType::RegularExpression) => MethodMatchType::Regular,
        _ => MethodMatchType::Exact,
    };
    let service = value.service.as_deref().unwrap_or("");
    let method = value.method.as_deref();
    if service.is_empty() && method.is_none() {
        return None;
    }
    Some(MethodMatch {
        match_type,
        service: Arc::from(service),
        method: method.map(Arc::from),
        case_sensitive: true,
    })
}

fn parse_header_match(value: &GrpcRouteRulesMatchesHeaders) -> Option<HeaderMatch> {
    let value_match = match value
        .r#type
        .as_ref()
        .unwrap_or(&GrpcRouteRulesMatchesHeadersType::Exact)
    {
        GrpcRouteRulesMatchesHeadersType::Exact => {
            HeaderMatchValue::Exact(Arc::from(value.value.as_str()))
        }
        GrpcRouteRulesMatchesHeadersType::RegularExpression => {
            HeaderMatchValue::Regex(Arc::from(value.value.as_str()))
        }
    };
    Some(HeaderMatch {
        name: Arc::from(value.name.as_str()),
        value: value_match,
    })
}

fn parse_backend_ref(value: &GrpcRouteRulesBackendRefs, route_ns: &str) -> Option<WeightedBackend> {
    let name = &value.name;
    let ns = value.namespace.as_deref().unwrap_or(route_ns);
    let port = value.port.unwrap_or(80);
    let weight = value.weight.unwrap_or(1) as u32;

    let filters = value
        .filters
        .as_ref()
        .map(|arr| {
            arr.iter()
                .flat_map(|f| parse_backend_filter(f, route_ns))
                .collect()
        })
        .unwrap_or_default();

    let backend = format!("{}.{}.svc.cluster.local.:{}", name, ns, port);
    Some(WeightedBackend {
        backend: Arc::from(backend),
        weight,
        filters,
        protocol: crate::ir::BackendProtocol::Http,
        tls: None,
    })
}

fn parse_filter(value: &GrpcRouteRulesFilters, _route_ns: &str) -> Vec<RouteFilter> {
    match value.r#type {
        GrpcRouteRulesFiltersType::RequestHeaderModifier => {
            let Some(modifier) = value.request_header_modifier.as_ref() else {
                return vec![];
            };
            parse_request_header_modifier(modifier)
        }
        GrpcRouteRulesFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            parse_response_header_modifier(modifier)
        }
        _ => vec![],
    }
}

fn parse_backend_filter(
    value: &gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFilters,
    _route_ns: &str,
) -> Vec<RouteFilter> {
    match value.r#type {
        gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFiltersType::RequestHeaderModifier => {
            let Some(modifier) = value.request_header_modifier.as_ref() else {
                return vec![];
            };
            parse_backend_request_header_modifier(modifier)
        }
        gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            parse_backend_response_header_modifier(modifier)
        }
        _ => vec![],
    }
}

fn parse_backend_request_header_modifier(
    modifier: &gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFiltersRequestHeaderModifier,
) -> Vec<RouteFilter> {
    let mut out = Vec::new();
    if let Some(set) = &modifier.set {
        for h in set {
            out.push(RouteFilter::RequestHeaderSet {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(add) = &modifier.add {
        for h in add {
            out.push(RouteFilter::RequestHeaderAdd {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(remove) = &modifier.remove {
        for h in remove {
            out.push(RouteFilter::RequestHeaderRemove {
                name: Arc::from(h.as_str()),
            });
        }
    }
    out
}

fn parse_backend_response_header_modifier(
    modifier: &gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFiltersResponseHeaderModifier,
) -> Vec<RouteFilter> {
    let mut out = Vec::new();
    if let Some(set) = &modifier.set {
        for h in set {
            out.push(RouteFilter::ResponseHeaderSet {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(add) = &modifier.add {
        for h in add {
            out.push(RouteFilter::ResponseHeaderAdd {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(remove) = &modifier.remove {
        for h in remove {
            out.push(RouteFilter::ResponseHeaderRemove {
                name: Arc::from(h.as_str()),
            });
        }
    }
    out
}

fn parse_request_header_modifier(
    modifier: &GrpcRouteRulesFiltersRequestHeaderModifier,
) -> Vec<RouteFilter> {
    let mut out = Vec::new();
    if let Some(set) = &modifier.set {
        for h in set {
            out.push(RouteFilter::RequestHeaderSet {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(add) = &modifier.add {
        for h in add {
            out.push(RouteFilter::RequestHeaderAdd {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(remove) = &modifier.remove {
        for h in remove {
            out.push(RouteFilter::RequestHeaderRemove {
                name: Arc::from(h.as_str()),
            });
        }
    }
    out
}

fn parse_response_header_modifier(
    modifier: &GrpcRouteRulesFiltersResponseHeaderModifier,
) -> Vec<RouteFilter> {
    let mut out = Vec::new();
    if let Some(set) = &modifier.set {
        for h in set {
            out.push(RouteFilter::ResponseHeaderSet {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(add) = &modifier.add {
        for h in add {
            out.push(RouteFilter::ResponseHeaderAdd {
                name: Arc::from(h.name.as_str()),
                value: Arc::from(h.value.as_str()),
            });
        }
    }
    if let Some(remove) = &modifier.remove {
        for h in remove {
            out.push(RouteFilter::ResponseHeaderRemove {
                name: Arc::from(h.as_str()),
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// GRPCRoute controller (kube::runtime::Controller)
// ---------------------------------------------------------------------------

use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Context shared across GRPCRoute reconcile invocations.
#[derive(Clone)]
pub struct GRPCRouteContext {
    pub client: Client,
    pub is_leader: Arc<AtomicBool>,
}

/// Reconcile a single GRPCRoute: resolve parentRefs, compute status,
/// and patch `.status.parents[]` when leader.
pub async fn reconcile_grpcroute(
    route: Arc<GRPCRoute>,
    ctx: Arc<GRPCRouteContext>,
) -> Result<Action, kube::Error> {
    let ns = route.metadata.namespace.clone().unwrap_or_default();
    let name = route.metadata.name.clone().unwrap_or_default();

    let gateways: Api<crate::gateway::api::Gateway> = Api::all(ctx.client.clone());
    let grants: Api<crate::gateway::api::ReferenceGrant> = Api::all(ctx.client.clone());
    let namespaces: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(ctx.client.clone());

    let gateway_list = match gateways.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Gateways for GRPCRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let grant_list = match grants.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list ReferenceGrants for GRPCRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };
    let namespace_list = match namespaces.list(&Default::default()).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list Namespaces for GRPCRoute reconcile");
            return Ok(Action::requeue(Duration::from_secs(5)));
        }
    };

    let gateway_states: Vec<GatewayState> = gateway_list
        .iter()
        .map(crate::gateway::reconcile::gateway::build_gateway_state)
        .collect();

    let grant_states =
        crate::gateway::reconcile::refgrant::reconcile_reference_grants(&grant_list.items);
    let grant_index = GrantIndex::new(grant_states);

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

    let parsed_refs = parse_parent_refs(&route);
    let needs_listener_sets = parsed_refs
        .iter()
        .any(|p| p.group == "gateway.networking.k8s.io" && p.kind == "ListenerSet");

    let (listener_set_list_items, mut listener_set_states) = if needs_listener_sets {
        let listener_sets: Api<crate::gateway::api::ListenerSet> = Api::all(ctx.client.clone());
        let listener_set_list = match listener_sets.list(&Default::default()).await {
            Ok(list) => list,
            Err(e) => {
                tracing::warn!(error = %e, "failed to list ListenerSets for GRPCRoute reconcile");
                return Ok(Action::requeue(Duration::from_secs(5)));
            }
        };
        let mut states = Vec::new();
        for ls in &listener_set_list.items {
            states.push(
                crate::gateway::reconcile::listenerset::build_listener_set_state(
                    ls,
                    &gateway_list.items,
                    &namespace_labels,
                    &ctx.client,
                    &grant_index,
                )
                .await,
            );
        }
        (listener_set_list.items, states)
    } else {
        (Vec::new(), Vec::new())
    };
    if !listener_set_states.is_empty() {
        crate::gateway::reconcile::listenerset::resolve_listener_set_conflicts(
            &mut listener_set_states,
            &gateway_states,
        );
    }
    let listener_allowed =
        crate::gateway::reconcile::gateway::build_listener_allowed_map(&gateway_list.items);
    let listener_set_allowed =
        crate::gateway::reconcile::listenerset::build_listener_set_allowed_map(
            &listener_set_list_items,
            &listener_set_states,
        );

    let route_ns = route.metadata.namespace.as_deref().unwrap_or("default");
    let backend_resolution =
        resolve_backend_refs_async(&ctx.client, &route, route_ns, &grant_index).await;
    let reconciled = reconcile_single(
        &route,
        &gateway_states,
        &listener_set_states,
        &namespace_labels,
        &listener_allowed,
        &listener_set_allowed,
        &grant_index,
        backend_resolution,
    );

    if ctx.is_leader.load(Ordering::Relaxed) {
        let parents: Vec<Value> = reconciled
            .parent_statuses
            .iter()
            .map(|ps| {
                let conditions: Vec<Value> = ps
                    .conditions
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "type": match c.condition_type {
                                ConditionType::Accepted => "Accepted",
                                ConditionType::Programmed => "Programmed",
                                ConditionType::ResolvedRefs => "ResolvedRefs",
                                ConditionType::Conflicted => "Conflicted",
                                ConditionType::Poison => "Poison",
                                ConditionType::NoMatchingParent => "NoMatchingParent",
                                ConditionType::RefNotPermitted => "RefNotPermitted",
                                ConditionType::UnsupportedFeature => "UnsupportedFeature",
                            },
                            "status": match c.status {
                                ConditionStatus::True => "True",
                                ConditionStatus::False => "False",
                                ConditionStatus::Unknown => "Unknown",
                            },
                            "reason": c.reason,
                            "message": c.message,
                            "observedGeneration": c.observed_generation,
                            "lastTransitionTime": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        })
                    })
                    .collect();

                let mut parent_ref = serde_json::Map::new();
                parent_ref.insert("group".into(), serde_json::json!(ps.parent_ref.group.as_ref()));
                parent_ref.insert("kind".into(), serde_json::json!(ps.parent_ref.kind.as_ref()));
                parent_ref.insert("name".into(), serde_json::json!(ps.parent_ref.name.as_ref()));
                parent_ref.insert("namespace".into(), serde_json::json!(ps.parent_ref.namespace.as_ref()));
                if let Some(section) = ps.parent_ref.section_name.as_deref() {
                    parent_ref.insert("sectionName".into(), serde_json::json!(section));
                }
                serde_json::json!({
                    "parentRef": parent_ref,
                    "controllerName": crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME,
                    "conditions": conditions,
                })
            })
            .collect();

        let new_status = serde_json::json!({ "parents": parents });

        let old_status_json = route
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
                "GRPCRoute status unchanged, skipping patch"
            );
        } else {
            let patch_body = serde_json::json!({
                "apiVersion": "gateway.networking.k8s.io/v1",
                "kind": "GRPCRoute",
                "metadata": {
                    "name": name,
                    "namespace": ns,
                },
                "status": new_status,
            });

            let api: Api<GRPCRoute> = Api::namespaced(ctx.client.clone(), &ns);
            let pp = PatchParams::apply("sunbeam-proxy");
            if let Err(e) = api
                .patch_status(&name, &pp, &Patch::Apply(&patch_body))
                .await
            {
                tracing::warn!(error = %e, name, namespace = ns, "GRPCRoute status patch failed");
            } else {
                tracing::debug!(name, namespace = ns, "GRPCRoute status patched");
            }
        }
    }

    Ok(Action::requeue(Duration::from_secs(30)))
}

fn error_policy_grpcroute(
    _route: Arc<GRPCRoute>,
    _error: &kube::Error,
    _ctx: Arc<GRPCRouteContext>,
) -> Action {
    Action::requeue(Duration::from_secs(5))
}

/// Start the GRPCRoute controller.
pub fn run_grpcroute_controller(
    client: Client,
    is_leader: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let ctx = Arc::new(GRPCRouteContext {
        client: client.clone(),
        is_leader,
    });
    let grpcroutes = Api::<GRPCRoute>::all(client);
    tokio::spawn(async move {
        Controller::new(grpcroutes, kube::runtime::watcher::Config::default())
            .run(reconcile_grpcroute, error_policy_grpcroute, ctx)
            .for_each(|res| async move {
                match res {
                    Ok(_) => {}
                    Err(e) => tracing::error!("GRPCRoute controller error: {e}"),
                }
            })
            .await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::model::ListenerState;

    fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                name: Arc::from(listener),
                protocol: Arc::from("HTTP"),
                port: 80,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            }],
            backend_client_cert_id: None,
        }
    }

    fn sample_route(parent_refs: Vec<Value>) -> GRPCRoute {
        let json = serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": {
                "name": "route-1",
                "namespace": "default",
                "generation": 1
            },
            "spec": {
                "parentRefs": parent_refs
            }
        });
        serde_json::from_value(json).expect("valid GRPCRoute")
    }

    #[test]
    fn accepted_when_parent_matches_same_namespace() {
        let route = sample_route(vec![serde_json::json!({
            "name": "gw-1",
            "sectionName": "http"
        })]);
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_grpcroutes(&[route], &gateways, &grant_index);
        assert_eq!(results.len(), 1);
        let result = &results[0];
        assert_eq!(result.route_state.parent_refs.len(), 1);

        let accepted = result.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        assert_eq!(accepted.reason, "Accepted");
    }

    #[test]
    fn denied_when_gateway_not_found() {
        let route = sample_route(vec![serde_json::json!({"name": "missing-gw"})]);
        let gateways: Vec<GatewayState> = vec![];
        let grant_index = GrantIndex::new(vec![]);

        let results = reconcile_grpcroutes(&[route], &gateways, &grant_index);
        let status = &results[0].parent_statuses[0];
        let accepted = status
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "NoMatchingParent");
    }

    #[test]
    fn parse_method_match_to_exact_path() {
        let yaml = r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: GRPCRoute
            metadata:
              name: grpc
              namespace: default
              generation: 1
            spec:
              parentRefs:
                - name: gw
              hostnames:
                - example.com
              rules:
                - matches:
                    - method:
                        service: foo.bar
                        method: Baz
                        type: Exact
                  backendRefs:
                    - name: svc
                      port: 50051
        "#;
        let route: GRPCRoute = serde_yaml::from_str(yaml).unwrap();
        let state = parse_grpcroute_state(&route);
        assert_eq!(state.hostnames.len(), 1);
        assert_eq!(state.rules.len(), 1);
        let m = state.rules[0].matches[0].method.as_ref().unwrap();
        assert_eq!(m.service.as_ref(), "foo.bar");
        assert_eq!(m.method.as_deref(), Some("Baz"));
        assert!(matches!(m.match_type, MethodMatchType::Exact));
        assert_eq!(m.exact_path().as_deref(), Some("/foo.bar/Baz"));
    }
}
