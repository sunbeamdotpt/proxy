// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::http::apply_header_filters;
use super::ir::unprogrammed_action;
use crate::gateway::model::{
    GRPCRouteMatch, GRPCRouteRule, MethodMatchType, PathMatch, RouteMatch,
};
use crate::ir;
use std::sync::Arc;

fn grpc_match_to_route_match(m: &GRPCRouteMatch) -> RouteMatch {
    let path = m
        .method
        .as_ref()
        .and_then(|method| match method.match_type {
            MethodMatchType::Exact => method.exact_path().map(PathMatch::Exact),
            MethodMatchType::Regular => {
                if method.service.is_empty() {
                    None
                } else {
                    Some(PathMatch::Prefix(Arc::from(format!(
                        "/{}/",
                        method.service
                    ))))
                }
            }
        });
    RouteMatch {
        path,
        headers: m.headers.clone(),
        query_params: vec![],
        method: None,
    }
}

pub(crate) fn translate_grpc_rule_to_ir(
    rule: &GRPCRouteRule,
    rule_idx: usize,
    programmed: bool,
    client_cert_id: Option<Arc<str>>,
) -> Vec<ir::Rule> {
    let mut result: Vec<ir::Rule> = Vec::new();

    if !programmed {
        let matches = if rule.matches.is_empty() {
            vec![ir::RequestMatch::default()]
        } else {
            rule.matches
                .iter()
                .map(|m| ir::RequestMatch::from(&grpc_match_to_route_match(m)))
                .collect()
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
        result.push(build_ir_rule_from_grpc(
            rule,
            ir::RequestMatch::default(),
            rule_idx,
            client_cert_id.clone(),
        ));
        return result;
    }

    for m in &rule.matches {
        let route_match = grpc_match_to_route_match(m);
        result.push(build_ir_rule_from_grpc(
            rule,
            ir::RequestMatch::from(&route_match),
            rule_idx,
            client_cert_id.clone(),
        ));
    }

    result
}

pub(crate) fn build_ir_rule_from_grpc(
    rule: &GRPCRouteRule,
    req_match: ir::RequestMatch,
    rule_idx: usize,
    client_cert_id: Option<Arc<str>>,
) -> ir::Rule {
    let mut request_filters: Vec<ir::RequestFilter> = Vec::new();
    let mut response_filters: Vec<ir::ResponseFilter> = Vec::new();

    apply_header_filters(&rule.filters, &mut request_filters, &mut response_filters);

    let action = ir::Action::Route(ir::RouteAction {
        backends: rule
            .backends
            .iter()
            .map(ir::WeightedBackend::from)
            .collect(),
        timeout: None,
        request_filters,
        response_filters,
        mirror_backends: vec![],
        mirror_fractions: vec![],
        cache: None,
        body_rewrites: vec![],
        auth: None,
        websocket: false,
        disable_https_redirect: true,
        client_cert_id,
    });

    ir::Rule {
        matches: vec![req_match],
        action,
        rule_order: rule_idx,
    }
}
