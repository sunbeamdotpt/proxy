// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::translate_view_to_ir;
use crate::gateway::model::{
    GRPCRouteMatch, GRPCRouteRule, GRPCRouteState, GatewayState, GatewayView, HeaderMatch,
    HeaderMatchValue, HostnameMatch, ListenerState, MethodMatch, MethodMatchType, ParentRef,
    WeightedBackend,
};
use std::sync::Arc;

#[test]
fn translate_view_to_ir_grpc_exact_method_match() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = GRPCRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("grpc-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("grpc.example.com"))],
        rules: vec![GRPCRouteRule {
            name: None,
            programmed: true,
            matches: vec![GRPCRouteMatch {
                method: Some(MethodMatch {
                    match_type: MethodMatchType::Exact,
                    service: Arc::from("foo.bar"),
                    method: Some(Arc::from("Baz")),
                    case_sensitive: true,
                }),
                headers: vec![],
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("grpc-svc:50051"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![],
        grpc_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    assert_eq!(table.hosts.len(), 1);
    let rule = &table.hosts[0].rules[0];
    if let crate::ir::Action::Route(action) = &rule.action {
        assert_eq!(action.backends[0].backend.as_ref(), "grpc-svc:50051");
    } else {
        panic!("expected Route action");
    }
    assert!(rule.matches.iter().any(|m| matches!(
        m.path,
        Some(crate::ir::PathMatch::Exact(ref p)) if p.as_ref() == "/foo.bar/Baz"
    )));
}
#[test]
fn translate_view_to_ir_grpc_header_match() {
    let gateway = GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let route = GRPCRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("grpc-route"),
        generation: 1,
        hostnames: vec![HostnameMatch::Exact(Arc::from("grpc.example.com"))],
        rules: vec![GRPCRouteRule {
            name: Some(Arc::from("named-rule")),
            programmed: true,
            matches: vec![GRPCRouteMatch {
                method: Some(MethodMatch {
                    match_type: MethodMatchType::Exact,
                    service: Arc::from("foo.bar"),
                    method: Some(Arc::from("Baz")),
                    case_sensitive: true,
                }),
                headers: vec![HeaderMatch {
                    name: Arc::from("x-version"),
                    value: HeaderMatchValue::Exact(Arc::from("v1")),
                }],
            }],
            backends: vec![WeightedBackend {
                backend: Arc::from("grpc-svc:50051"),
                weight: 1,
                protocol: crate::ir::BackendProtocol::Http,
                filters: vec![],
                tls: None,
            }],
            filters: vec![],
        }],
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),
            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        programmed: true,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![],
        grpc_routes: vec![route],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let table = translate_view_to_ir(&view);
    let rule = &table.hosts[0].rules[0];
    assert!(rule.matches.iter().any(|m| {
            m.headers.iter().any(|h| {
                h.name.as_ref() == "x-version"
                    && matches!(h.value, crate::ir::HeaderMatchValue::Exact(ref v) if v.as_ref() == "v1")
            })
        }));
}
