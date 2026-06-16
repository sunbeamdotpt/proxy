// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::l4::{add_l4_listener, listener_protocol_to_ir, translate_l4_routes};
use crate::gateway::model::{
    GatewayState, GatewayView, HostnameMatch, ListenerState, ParentRef, TCPRouteState,
    TLSRouteState, TlsMode, UDPRouteState, WeightedBackend,
};
use std::sync::Arc;

fn l4_gateway() -> GatewayState {
    GatewayState {
        namespace: Arc::from("default"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![
            ListenerState {
                programmed: true,
                name: Arc::from("tcp"),
                protocol: Arc::from("TCP"),
                port: 9001,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("udp"),
                protocol: Arc::from("UDP"),
                port: 9002,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            },
            ListenerState {
                programmed: true,
                name: Arc::from("tls"),
                protocol: Arc::from("TLS"),
                port: 9003,
                hostname: None,
                tls_mode: None,
                frontend_validation: None,
            },
        ],
        backend_client_cert_id: None,
    }
}

fn tcp_route(programmed: bool) -> TCPRouteState {
    TCPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("tcp-route"),
        generation: 1,
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        backends: vec![WeightedBackend {
            backend: Arc::from("10.0.0.1:8080"),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![],
            tls: None,
        }],
        programmed,
    }
}

fn udp_route(programmed: bool) -> UDPRouteState {
    UDPRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("udp-route"),
        generation: 1,
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        backends: vec![WeightedBackend {
            backend: Arc::from("10.0.0.2:8080"),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![],
            tls: None,
        }],
        programmed,
    }
}

fn tls_route(programmed: bool, hostnames: Vec<HostnameMatch>) -> TLSRouteState {
    TLSRouteState {
        namespace: Arc::from("default"),
        name: Arc::from("tls-route"),
        generation: 1,
        hostnames,
        parent_refs: vec![ParentRef {
            group: Arc::from("gateway.networking.k8s.io"),
            kind: Arc::from("Gateway"),

            namespace: None,
            name: Arc::from("gw-1"),
            section_name: None,
            port: None,
        }],
        backends: vec![WeightedBackend {
            backend: Arc::from("10.0.0.3:8443"),
            weight: 1,
            protocol: crate::ir::BackendProtocol::Http,
            filters: vec![],
            tls: None,
        }],
        programmed,
    }
}

#[test]
fn listener_protocol_to_ir_maps_protocols() {
    assert_eq!(
        listener_protocol_to_ir("HTTP"),
        Some(crate::ir::Protocol::Http)
    );
    assert_eq!(
        listener_protocol_to_ir("HTTPS"),
        Some(crate::ir::Protocol::Https)
    );
    assert_eq!(
        listener_protocol_to_ir("TCP"),
        Some(crate::ir::Protocol::Tcp)
    );
    assert_eq!(
        listener_protocol_to_ir("UDP"),
        Some(crate::ir::Protocol::Udp)
    );
    assert_eq!(
        listener_protocol_to_ir("TLS"),
        Some(crate::ir::Protocol::Tls)
    );
    assert_eq!(listener_protocol_to_ir("FTP"), None);
}
#[test]
fn add_l4_listener_skips_duplicates_and_unknown_protocols() {
    let gateway = l4_gateway();
    let mut listeners: std::collections::BTreeMap<Arc<str>, crate::ir::ListenerConfig> =
        std::collections::BTreeMap::new();
    add_l4_listener(&mut listeners, &gateway, &gateway.listeners[0]);
    assert_eq!(listeners.len(), 1);
    // duplicate is ignored
    add_l4_listener(&mut listeners, &gateway, &gateway.listeners[0]);
    assert_eq!(listeners.len(), 1);

    let unknown = ListenerState {
        programmed: true,
        name: Arc::from("weird"),
        protocol: Arc::from("SCTP"),
        port: 9004,
        hostname: None,
        tls_mode: None,
        frontend_validation: None,
    };
    add_l4_listener(&mut listeners, &gateway, &unknown);
    assert_eq!(listeners.len(), 1);
}
#[test]
fn translate_l4_routes_creates_listeners_and_routes() {
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![l4_gateway()],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![tcp_route(true)],
        udp_routes: vec![udp_route(true)],
        tls_routes: vec![tls_route(
            true,
            vec![HostnameMatch::Exact(Arc::from("foo.example.com"))],
        )],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert_eq!(listeners.len(), 3);
    assert_eq!(routes.len(), 3);
    let ids: Vec<_> = listeners.iter().map(|l| l.id.as_ref()).collect();
    assert!(ids.contains(&"default/gw-1/tcp"));
    assert!(ids.contains(&"default/gw-1/udp"));
    assert!(ids.contains(&"default/gw-1/tls"));
    assert!(routes
        .iter()
        .any(|r| matches!(r.action, crate::ir::L4Action::TcpRelay(_))));
    assert!(routes
        .iter()
        .any(|r| matches!(r.action, crate::ir::L4Action::UdpRelay(_))));
    assert!(routes
        .iter()
        .any(|r| matches!(r.action, crate::ir::L4Action::TlsPassthrough(_))));
    assert!(routes
        .iter()
        .any(|r| matches!(r.match_, crate::ir::L4Match::Sni(_))));
}

fn http_gateway() -> GatewayState {
    GatewayState {
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
    }
}

#[test]
fn translate_l4_routes_relays_http_with_any_match() {
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![http_gateway()],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert_eq!(listeners.len(), 1);
    assert_eq!(listeners[0].protocol, crate::ir::Protocol::Http);
    assert_eq!(routes.len(), 1);
    assert!(matches!(
        routes[0].action,
        crate::ir::L4Action::HttpRelay(_)
    ));
    assert_eq!(routes[0].match_, crate::ir::L4Match::Any);
}
#[test]
fn translate_l4_routes_skips_unprogrammed() {
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![l4_gateway()],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![tcp_route(false)],
        udp_routes: vec![udp_route(false)],
        tls_routes: vec![tls_route(false, vec![])],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert!(listeners.is_empty());
    assert!(routes.is_empty());
}
#[test]
fn translate_l4_routes_filters_by_section_name() {
    let mut route = tcp_route(true);
    route.parent_refs[0].section_name = Some(Arc::from("tls"));
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![l4_gateway()],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![route],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert!(listeners.is_empty());
    assert!(routes.is_empty());
}
#[test]
fn translate_l4_routes_skips_when_gateway_not_found() {
    let mut route = tcp_route(true);
    route.parent_refs[0].name = Arc::from("missing-gw");
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![l4_gateway()],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![route],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert!(listeners.is_empty());
    assert!(routes.is_empty());
}
#[test]
fn translate_l4_routes_inherits_parent_namespace() {
    let mut route = tcp_route(true);
    route.namespace = Arc::from("other");
    route.parent_refs[0].namespace = None;
    let gateway = GatewayState {
        namespace: Arc::from("other"),
        name: Arc::from("gw-1"),
        generation: 1,
        listeners: vec![ListenerState {
            programmed: true,
            name: Arc::from("tcp"),
            protocol: Arc::from("TCP"),
            port: 9001,
            hostname: None,
            tls_mode: None,
            frontend_validation: None,
        }],
        backend_client_cert_id: None,
    };
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![route],
        udp_routes: vec![],
        tls_routes: vec![],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert_eq!(listeners.len(), 1);
    assert_eq!(routes.len(), 1);
    assert_eq!(listeners[0].id.as_ref(), "other/gw-1/tcp");
}
#[test]
fn translate_l4_routes_uses_terminate_action_for_terminate_listener() {
    let mut gateway = l4_gateway();
    gateway.listeners.retain(|l| l.protocol.as_ref() == "TLS");
    gateway.listeners[0].tls_mode = Some(TlsMode::Terminate);
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![tls_route(true, vec![])],
        reference_grants: vec![],
        ..Default::default()
    };
    let (listeners, routes) = translate_l4_routes(&view);
    assert_eq!(listeners.len(), 1);
    assert_eq!(routes.len(), 1);
    assert!(matches!(
        listeners[0].tls,
        Some(crate::ir::TlsConfig::Registry { .. })
    ));
    assert!(matches!(
        routes[0].action,
        crate::ir::L4Action::TlsTerminate(_)
    ));
}
#[test]
fn translate_l4_routes_uses_passthrough_action_for_passthrough_listener() {
    let mut gateway = l4_gateway();
    gateway.listeners.retain(|l| l.protocol.as_ref() == "TLS");
    gateway.listeners[0].tls_mode = Some(TlsMode::Passthrough);
    let view = GatewayView {
        listener_sets: vec![],
        gateways: vec![gateway],
        routes: vec![],
        http_routes: vec![],
        tcp_routes: vec![],
        udp_routes: vec![],
        tls_routes: vec![tls_route(true, vec![])],
        reference_grants: vec![],
        ..Default::default()
    };
    let (_listeners, routes) = translate_l4_routes(&view);
    assert!(routes
        .iter()
        .any(|r| matches!(r.action, crate::ir::L4Action::TlsPassthrough(_))));
}
