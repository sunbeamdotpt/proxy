// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TCPRoute re-exports from the official `gateway-api` crate.

crate::gateway_api_route_alias!(
    "TCPRoute re-exports from the official `gateway-api` crate.",
    TCPRoute,
    TcpRouteSpec,
    TCPRouteStatus,
    gateway_api::experimental::tcproutes::TCPRoute,
    gateway_api::experimental::tcproutes::TcpRouteSpec,
    gateway_api::experimental::tcproutes::TcpRouteStatus,
    r#"
        apiVersion: gateway.networking.k8s.io/v1alpha2
        kind: TCPRoute
        metadata:
          name: example-route
          namespace: default
        spec:
          parentRefs:
            - name: example-gateway
          rules:
            - backendRefs:
                - name: svc
                  port: 8080
    "#
);
