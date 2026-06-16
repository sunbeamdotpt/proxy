// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute parsing helpers.

use crate::gateway::api::GRPCRoute;
use crate::gateway::model::{
    GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, HeaderMatch, HeaderMatchValue, HostnameMatch,
    MethodMatch, MethodMatchType, ParentRef, RouteFilter, RouteState, WeightedBackend,
};
use crate::gateway::reconcile::backend::RouteLike;
use crate::gateway::reconcile::parent::ParsedParentRef;
use crate::gateway::reconcile::route::RouteResource;
use gateway_api::grpcroutes::{
    GrpcRouteRules, GrpcRouteRulesBackendRefs, GrpcRouteRulesFilters, GrpcRouteRulesFiltersType,
    GrpcRouteRulesMatches, GrpcRouteRulesMatchesHeaders, GrpcRouteRulesMatchesHeadersType,
    GrpcRouteRulesMatchesMethod, GrpcRouteRulesMatchesMethodType,
};
use std::sync::Arc;

crate::impl_parse_parent_refs!(
    parse_parent_refs,
    GRPCRoute,
    gateway_api::grpcroutes::GrpcRouteParentRefs
);

/// Parse hostnames from a GRPCRoute spec into the model's HostnameMatch types.
pub fn parse_route_hostnames(route: &GRPCRoute) -> Vec<HostnameMatch> {
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
            crate::parse_request_header_modifier!(modifier)
        }
        GrpcRouteRulesFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            crate::parse_response_header_modifier!(modifier)
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
            crate::parse_request_header_modifier!(modifier)
        }
        gateway_api::grpcroutes::GrpcRouteRulesBackendRefsFiltersType::ResponseHeaderModifier => {
            let Some(modifier) = value.response_header_modifier.as_ref() else {
                return vec![];
            };
            crate::parse_response_header_modifier!(modifier)
        }
        _ => vec![],
    }
}

crate::impl_backend_ref_like!(GrpcRouteRulesBackendRefs);

impl crate::gateway::reconcile::backend::RuleLike for GrpcRouteRules {
    type BackendRef = GrpcRouteRulesBackendRefs;
    fn backend_refs(&self) -> Option<&[Self::BackendRef]> {
        self.backend_refs.as_deref()
    }
}

impl RouteLike for GRPCRoute {
    type Rule = GrpcRouteRules;
    fn rules(&self) -> Option<&[Self::Rule]> {
        self.spec.rules.as_deref()
    }
    fn kind() -> &'static str {
        "GRPCRoute"
    }
}

impl RouteResource for GRPCRoute {
    fn kind_str() -> &'static str {
        "GRPCRoute"
    }
    fn status_kind_str() -> &'static str {
        "GRPCRoute"
    }
    fn parse_hostnames(&self) -> Vec<HostnameMatch> {
        parse_route_hostnames(self)
    }
    fn parse_parent_refs(&self) -> Vec<ParsedParentRef> {
        parse_parent_refs(self)
    }
    fn route_state(&self, parent_refs: Vec<ParentRef>) -> RouteState {
        RouteState {
            namespace: Arc::from(self.metadata_namespace()),
            name: Arc::from(self.metadata_name()),
            kind: Arc::from(Self::kind_str()),
            generation: self.generation(),
            parent_refs,
        }
    }
    fn metadata_name(&self) -> &str {
        self.metadata.name.as_deref().unwrap_or("")
    }
    fn metadata_namespace(&self) -> &str {
        self.metadata.namespace.as_deref().unwrap_or("default")
    }
    fn generation(&self) -> i64 {
        self.metadata.generation.unwrap_or(0)
    }
}
