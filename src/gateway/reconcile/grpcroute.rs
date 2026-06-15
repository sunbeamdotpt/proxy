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
                                ConditionType::InsecureFrontendValidationMode => {
                                    "InsecureFrontendValidationMode"
                                }
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

    crate::gateway::reconcile::trigger::trigger();
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
    use crate::gateway::api::grpcroute::GRPCRouteStatus;
    use crate::gateway::model::ListenerState;
    use kube::runtime::controller::Action;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    fn gw_with_listener(ns: &str, name: &str, listener: &str) -> GatewayState {
        GatewayState {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            generation: 1,
            listeners: vec![ListenerState {
                programmed: true,
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

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn route_from_value(value: serde_json::Value) -> GRPCRoute {
        serde_json::from_value(value).expect("valid GRPCRoute")
    }

    fn route_with_backends(parent_refs: Vec<Value>, backends: Vec<Value>) -> GRPCRoute {
        route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": parent_refs, "rules": [{ "backendRefs": backends }] }
        }))
    }

    fn route_with_rules(rules: Vec<Value>) -> GRPCRoute {
        route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "rules": rules }
        }))
    }

    fn gateway_json(name: &str, ns: &str, listeners: Vec<Value>) -> Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "Gateway",
            "metadata": { "name": name, "namespace": ns, "generation": 1 },
            "spec": { "gatewayClassName": "sunbeam", "listeners": listeners }
        })
    }

    fn listener_set_json(name: &str, ns: &str, parent: Value, listeners: Vec<Value>) -> Value {
        serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "ListenerSet",
            "metadata": { "name": name, "namespace": ns, "generation": 1 },
            "spec": { "parentRef": parent, "listeners": listeners }
        })
    }

    fn mock_client<F>(responder: F) -> kube::Client
    where
        F: Fn(&str, &str) -> (u16, Value) + Clone + Send + Sync + 'static,
    {
        kube::Client::new(
            tower::service_fn(move |req: http::Request<kube::client::Body>| {
                let path = req.uri().path().to_string();
                let method = req.method().to_string();
                let responder = responder.clone();
                async move {
                    let (status, body) = responder(&path, &method);
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        )
    }

    // -----------------------------------------------------------------------
    // Backend reference resolution
    // -----------------------------------------------------------------------

    #[test]
    fn check_backend_permitted_rejects_unsupported_group() {
        let backend = GrpcRouteRulesBackendRefs {
            group: Some("example.com".to_string()),
            kind: None,
            namespace: None,
            name: "svc".to_string(),
            port: None,
            weight: None,
            filters: None,
        };
        let err =
            check_backend_permitted(&backend, "default", &GrantIndex::new(vec![])).unwrap_err();
        assert!(matches!(err, BackendResolutionStatus::Unsupported(_)));
    }

    #[test]
    fn resolve_backend_refs_no_rules() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default", "generation": 1 },
            "spec": {}
        }));
        let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
        assert!(matches!(res.overall, BackendResolutionStatus::Ok));
        assert!(res.rules.is_empty());
    }

    #[test]
    fn resolve_backend_refs_rule_without_backends_ok() {
        let route = route_with_rules(vec![serde_json::json!({})]);
        let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
        assert!(matches!(res.overall, BackendResolutionStatus::Ok));
        assert_eq!(res.rules.len(), 1);
        assert!(res.rules[0].ok);
    }

    #[test]
    fn resolve_backend_refs_rejects_unsupported_kind() {
        let route = route_with_backends(
            vec![],
            vec![serde_json::json!({
                "group": "example.com",
                "kind": "Foo",
                "name": "svc"
            })],
        );
        let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
        assert!(matches!(
            res.overall,
            BackendResolutionStatus::Unsupported(_)
        ));
        assert!(!res.rules[0].ok);
    }

    #[test]
    fn resolve_backend_refs_rejects_cross_namespace_without_grant() {
        let route = route_with_backends(
            vec![],
            vec![serde_json::json!({
                "name": "svc",
                "namespace": "other"
            })],
        );
        let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
        assert!(matches!(
            res.overall,
            BackendResolutionStatus::RefNotPermitted(_)
        ));
        assert!(!res.rules[0].ok);
    }

    #[test]
    fn resolve_backend_refs_allows_same_namespace_service() {
        let route = route_with_backends(vec![], vec![serde_json::json!({ "name": "svc" })]);
        let res = resolve_backend_refs(&route, "default", &GrantIndex::new(vec![]));
        assert!(matches!(res.overall, BackendResolutionStatus::Ok));
        assert!(res.rules[0].ok);
    }

    #[tokio::test]
    async fn resolve_backend_refs_async_finds_service() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"name": "svc-1", "port": 50051})],
        );
        let client = mock_client(|path, _method| {
            if path.contains("/services/svc-1") {
                (
                    200,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Service",
                        "metadata": { "name": "svc-1", "namespace": "default" }
                    }),
                )
            } else {
                (
                    200,
                    serde_json::json!({"apiVersion": "v1", "kind": "List", "items": []}),
                )
            }
        });
        let res =
            resolve_backend_refs_async(&client, &route, "default", &GrantIndex::new(vec![])).await;
        assert!(matches!(res.overall, BackendResolutionStatus::Ok));
    }

    #[tokio::test]
    async fn resolve_backend_refs_async_missing_service() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"name": "missing-svc", "port": 50051})],
        );
        let client = mock_client(|_path, _method| (404, serde_json::json!({})));
        let res =
            resolve_backend_refs_async(&client, &route, "default", &GrantIndex::new(vec![])).await;
        assert!(
            matches!(res.overall, BackendResolutionStatus::BackendNotFound(ref m) if m.contains("missing-svc")),
            "unexpected result: {res:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Reconcile status branches
    // -----------------------------------------------------------------------

    #[test]
    fn reconciled_programmed_false_when_backend_ref_not_permitted() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"name": "svc", "namespace": "other"})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
        assert!(!res.programmed);
        let cond = res.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(cond.status, ConditionStatus::False);
        assert_eq!(cond.reason, "RefNotPermitted");
    }

    #[test]
    fn reconciled_programmed_false_when_backend_unsupported() {
        let route = route_with_backends(
            vec![serde_json::json!({"name": "gw-1"})],
            vec![serde_json::json!({"group": "example.com", "kind": "Foo", "name": "svc"})],
        );
        let gateways = vec![gw_with_listener("default", "gw-1", "http")];
        let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
        assert!(!res.programmed);
        let cond = res.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::ResolvedRefs))
            .unwrap();
        assert_eq!(cond.status, ConditionStatus::False);
        assert_eq!(cond.reason, "InvalidKind");
    }

    #[test]
    fn reconciled_with_unsupported_parent_group() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [{ "group": "example.com", "kind": "Gateway", "name": "gw" }] }
        }));
        let gateways = vec![gw_with_listener("default", "gw", "http")];
        let res = &reconcile_grpcroutes(&[route], &gateways, &GrantIndex::new(vec![]))[0];
        let cond = res.parent_statuses[0]
            .conditions
            .iter()
            .find(|c| matches!(c.condition_type, ConditionType::Accepted))
            .unwrap();
        assert_eq!(cond.status, ConditionStatus::False);
        assert_eq!(cond.reason, "UnsupportedValue");
    }

    // -----------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_route_hostnames_exact_and_wildcard() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": { "hostnames": ["example.com", "*.example.com"] }
        }));
        let hostnames = parse_route_hostnames(&route);
        assert!(matches!(&hostnames[0], HostnameMatch::Exact(h) if h.as_ref() == "example.com"));
        assert!(matches!(&hostnames[1], HostnameMatch::Wildcard(h) if h.as_ref() == "example.com"));
    }

    #[test]
    fn parse_grpcroute_state_empty_rules() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default", "generation": 2 },
            "spec": {}
        }));
        let state = parse_grpcroute_state(&route);
        assert_eq!(state.namespace.as_ref(), "default");
        assert_eq!(state.name.as_ref(), "r");
        assert_eq!(state.generation, 2);
        assert!(state.hostnames.is_empty());
        assert!(state.rules.is_empty());
        assert!(state.parent_refs.is_empty());
    }

    #[test]
    fn parse_grpcroute_state_method_variations() {
        let route = route_with_rules(vec![
            serde_json::json!({ "matches": [{ "method": { "service": "foo.bar" } }] }),
            serde_json::json!({ "matches": [{ "method": { "method": "Baz" } }] }),
            serde_json::json!({ "matches": [{ "method": { "service": "foo.bar", "type": "RegularExpression" } }] }),
            serde_json::json!({ "matches": [{ "method": {} }] }),
        ]);
        let state = parse_grpcroute_state(&route);
        assert_eq!(state.rules.len(), 4);

        let m0 = state.rules[0].matches[0].method.as_ref().unwrap();
        assert_eq!(m0.service.as_ref(), "foo.bar");
        assert!(m0.method.is_none());
        assert!(matches!(m0.match_type, MethodMatchType::Exact));

        let m1 = state.rules[1].matches[0].method.as_ref().unwrap();
        assert_eq!(m1.service.as_ref(), "");
        assert_eq!(m1.method.as_deref(), Some("Baz"));

        let m2 = state.rules[2].matches[0].method.as_ref().unwrap();
        assert!(matches!(m2.match_type, MethodMatchType::Regular));

        assert!(state.rules[3].matches[0].method.is_none());
    }

    #[test]
    fn parse_grpcroute_state_header_matches() {
        let route = route_with_rules(vec![serde_json::json!({
            "matches": [{
                "headers": [
                    { "name": "X-V", "value": "1" },
                    { "name": "X-R", "type": "RegularExpression", "value": ".*" }
                ]
            }]
        })]);
        let state = parse_grpcroute_state(&route);
        let headers = &state.rules[0].matches[0].headers;
        assert_eq!(headers[0].name.as_ref(), "X-V");
        assert_eq!(headers[0].value, HeaderMatchValue::Exact(Arc::from("1")));
        assert_eq!(headers[1].name.as_ref(), "X-R");
        assert_eq!(headers[1].value, HeaderMatchValue::Regex(Arc::from(".*")));
    }

    #[test]
    fn parse_grpcroute_state_filters() {
        let route = route_with_rules(vec![serde_json::json!({
            "filters": [
                { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                    "set": [{ "name": "X-S", "value": "v" }],
                    "add": [{ "name": "X-A", "value": "v" }],
                    "remove": ["X-R"]
                }},
                { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                    "set": [{ "name": "Y-S", "value": "v" }]
                }},
                { "type": "RequestHeaderModifier" },
                { "type": "ExtensionRef" }
            ]
        })]);
        let state = parse_grpcroute_state(&route);
        let filters = &state.rules[0].filters;
        assert_eq!(filters.len(), 4);
        assert!(matches!(filters[0], RouteFilter::RequestHeaderSet { .. }));
        assert!(matches!(filters[1], RouteFilter::RequestHeaderAdd { .. }));
        assert!(matches!(
            filters[2],
            RouteFilter::RequestHeaderRemove { .. }
        ));
        assert!(matches!(filters[3], RouteFilter::ResponseHeaderSet { .. }));
    }

    #[test]
    fn parse_grpcroute_state_backend_filters() {
        let route = route_with_rules(vec![serde_json::json!({
            "backendRefs": [{
                "name": "svc",
                "filters": [
                    { "type": "RequestHeaderModifier", "requestHeaderModifier": {
                        "add": [{ "name": "B-A", "value": "v" }]
                    }},
                    { "type": "ResponseHeaderModifier", "responseHeaderModifier": {
                        "remove": ["B-R"]
                    }},
                    { "type": "ResponseHeaderModifier" }
                ]
            }]
        })]);
        let state = parse_grpcroute_state(&route);
        let backend = &state.rules[0].backends[0];
        assert_eq!(backend.filters.len(), 2);
        assert!(matches!(
            backend.filters[0],
            RouteFilter::RequestHeaderAdd { .. }
        ));
        assert!(matches!(
            backend.filters[1],
            RouteFilter::ResponseHeaderRemove { .. }
        ));
    }

    #[test]
    fn parse_grpcroute_state_backend_ref_defaults() {
        let route = route_with_rules(vec![serde_json::json!({
            "backendRefs": [{ "name": "svc" }]
        })]);
        let state = parse_grpcroute_state(&route);
        let b = &state.rules[0].backends[0];
        assert_eq!(b.backend.as_ref(), "svc.default.svc.cluster.local.:80");
        assert_eq!(b.weight, 1);
    }

    #[test]
    fn parse_grpcroute_state_backend_ref_explicit() {
        let route = route_with_rules(vec![serde_json::json!({
            "backendRefs": [{ "name": "svc", "namespace": "ns", "port": 50051, "weight": 5 }]
        })]);
        let state = parse_grpcroute_state(&route);
        let b = &state.rules[0].backends[0];
        assert_eq!(b.backend.as_ref(), "svc.ns.svc.cluster.local.:50051");
        assert_eq!(b.weight, 5);
    }

    #[test]
    fn parse_parent_refs_defaults() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": { "parentRefs": [{ "name": "gw" }] }
        }));
        let refs = parse_parent_refs(&route);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].group, "gateway.networking.k8s.io");
        assert_eq!(refs[0].kind, "Gateway");
        assert_eq!(refs[0].namespace, None);
        assert_eq!(refs[0].name, "gw");
    }

    #[test]
    fn parse_parent_refs_explicit() {
        let route = route_from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "r", "namespace": "default" },
            "spec": { "parentRefs": [{
                "group": "foo",
                "kind": "Bar",
                "name": "x",
                "namespace": "ns",
                "sectionName": "sec",
                "port": 8080
            }] }
        }));
        let refs = parse_parent_refs(&route);
        assert_eq!(refs[0].group, "foo");
        assert_eq!(refs[0].kind, "Bar");
        assert_eq!(refs[0].namespace, Some("ns".to_string()));
        assert_eq!(refs[0].section_name, Some("sec".to_string()));
        assert_eq!(refs[0].port, Some(8080));
    }

    // -----------------------------------------------------------------------
    // Controller
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn reconcile_grpcroute_non_leader_returns_requeue() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .unwrap();

        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

        let client = mock_client(move |path, _method| {
            if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else {
                (200, gateway_list.clone())
            }
        });

        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_leader_patches_status() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc-1", "port": 50051 }] }]
            }
        }))
        .unwrap();

        let gw = gateway_json(
            "gw-1",
            "default",
            vec![serde_json::json!({
                "name": "http",
                "protocol": "HTTP",
                "port": 80
            })],
        );
        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

        let patched = Arc::new(AtomicUsize::new(0));
        let patched_clone = patched.clone();
        let client = mock_client(move |path, method| {
            if method == "PATCH" && path.contains("/status") {
                patched_clone.fetch_add(1, Ordering::SeqCst);
                (
                    200,
                    serde_json::json!({
                        "apiVersion": "gateway.networking.k8s.io/v1",
                        "kind": "GRPCRoute",
                        "metadata": { "name": "route-1", "namespace": "default" },
                        "status": { "parents": [] }
                    }),
                )
            } else if path.contains("/services/svc-1") {
                (
                    200,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Service",
                        "metadata": { "name": "svc-1", "namespace": "default" }
                    }),
                )
            } else if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else {
                (200, gateway_list.clone())
            }
        });

        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        assert!(patched.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn reconcile_grpcroute_leader_skips_unchanged_status() {
        let mut route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .unwrap();
        route.status = Some(GRPCRouteStatus { parents: vec![] });

        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

        let patched = Arc::new(AtomicUsize::new(0));
        let patched_clone = patched.clone();
        let client = mock_client(move |path, method| {
            if method == "PATCH" && path.contains("/status") {
                patched_clone.fetch_add(1, Ordering::SeqCst);
                (200, serde_json::json!({}))
            } else if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else {
                (200, gateway_list.clone())
            }
        });

        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
        assert_eq!(patched.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reconcile_grpcroute_patch_failure_still_requeues() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": {
                "parentRefs": [{ "name": "gw-1" }],
                "rules": [{ "backendRefs": [{ "name": "svc-1" }] }]
            }
        }))
        .unwrap();

        let gw = gateway_json(
            "gw-1",
            "default",
            vec![serde_json::json!({
                "name": "http",
                "protocol": "HTTP",
                "port": 80
            })],
        );
        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});

        let client = mock_client(move |path, method| {
            let (status, body) = if method == "PATCH" && path.contains("/status") {
                (403, serde_json::json!({}))
            } else if path.contains("/services/svc-1") {
                (
                    200,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Service",
                        "metadata": { "name": "svc-1", "namespace": "default" }
                    }),
                )
            } else if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else {
                (200, gateway_list.clone())
            };
            (status, body)
        });

        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(true)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_gateway_list_error_requeues() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .unwrap();

        let client = mock_client(|_path, _method| (500, serde_json::json!({"message": "fail"})));
        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_grant_list_error_requeues() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .unwrap();

        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
        let client = mock_client(move |path, _method| {
            if path.contains("/gateways") {
                (200, gateway_list.clone())
            } else {
                (500, serde_json::json!({"message": "fail"}))
            }
        });
        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_namespace_list_error_requeues() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [] }
        }))
        .unwrap();

        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": []});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let client = mock_client(move |path, _method| {
            if path.contains("/gateways") {
                (200, gateway_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else {
                (500, serde_json::json!({"message": "fail"}))
            }
        });
        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_listenerset_list_error_requeues() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [{ "group": "gateway.networking.k8s.io", "kind": "ListenerSet", "name": "ls-1" }] }
        }))
        .unwrap();

        let gw = gateway_json(
            "gw-1",
            "default",
            vec![serde_json::json!({
                "name": "http",
                "protocol": "HTTP",
                "port": 80,
                "allowedListeners": { "namespaces": { "from": "All" } }
            })],
        );
        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});
        let client = mock_client(move |path, _method| {
            if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else if path.contains("/gateways") {
                (200, gateway_list.clone())
            } else {
                (500, serde_json::json!({"message": "fail"}))
            }
        });
        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn reconcile_grpcroute_with_listener_set_parent() {
        let route: GRPCRoute = serde_json::from_value(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "GRPCRoute",
            "metadata": { "name": "route-1", "namespace": "default", "generation": 1 },
            "spec": { "parentRefs": [{
                "group": "gateway.networking.k8s.io",
                "kind": "ListenerSet",
                "name": "ls-1",
                "sectionName": "http"
            }] }
        }))
        .unwrap();

        let gw = gateway_json(
            "gw-1",
            "default",
            vec![serde_json::json!({
                "name": "http",
                "protocol": "HTTP",
                "port": 80,
                "allowedListeners": { "namespaces": { "from": "All" } }
            })],
        );
        let ls = listener_set_json(
            "ls-1",
            "default",
            serde_json::json!({ "name": "gw-1" }),
            vec![serde_json::json!({ "name": "http", "protocol": "HTTP", "port": 80 })],
        );
        let gateway_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "GatewayList", "items": [gw]});
        let grant_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ReferenceGrantList", "items": []});
        let namespace_list =
            serde_json::json!({"apiVersion": "v1", "kind": "NamespaceList", "items": []});
        let listenerset_list = serde_json::json!({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "ListenerSetList", "items": [ls]});

        let client = mock_client(move |path, _method| {
            if path.contains("/namespaces") {
                (200, namespace_list.clone())
            } else if path.contains("/referencegrants") {
                (200, grant_list.clone())
            } else if path.contains("/listenersets") {
                (200, listenerset_list.clone())
            } else {
                (200, gateway_list.clone())
            }
        });
        let ctx = Arc::new(GRPCRouteContext {
            client,
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let action = reconcile_grpcroute(Arc::new(route), ctx).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }

    #[tokio::test]
    async fn error_policy_grpcroute_requeues_after_5s() {
        let route = Arc::new(sample_route(vec![]));
        let ctx = Arc::new(GRPCRouteContext {
            client: kube::Client::new(
                tower::service_fn(|_req| async {
                    Ok::<_, std::convert::Infallible>(http::Response::new(
                        kube::client::Body::empty(),
                    ))
                }),
                "default",
            ),
            is_leader: Arc::new(AtomicBool::new(false)),
        });
        let err = kube::Error::Service(std::io::Error::other("test").into());
        let action = error_policy_grpcroute(route, &err, ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(5)));
    }

    #[tokio::test]
    async fn run_grpcroute_controller_returns_handle() {
        let client = kube::Client::new(
            tower::service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "default",
        );
        let handle = run_grpcroute_controller(client, Arc::new(AtomicBool::new(false)));
        handle.abort();
    }
}
