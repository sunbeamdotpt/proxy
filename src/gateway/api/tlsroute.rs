// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLSRoute re-exports from the official `gateway-api` crate.

crate::gateway_api_route_alias!(
    "TLSRoute re-exports from the official `gateway-api` crate.",
    TLSRoute,
    TlsRouteSpec,
    TLSRouteStatus,
    gateway_api::tlsroutes::TLSRoute,
    gateway_api::tlsroutes::TlsRouteSpec,
    gateway_api::tlsroutes::TlsRouteStatus,
    r#"
        apiVersion: gateway.networking.k8s.io/v1alpha2
        kind: TLSRoute
        metadata:
          name: example-route
          namespace: default
        spec:
          parentRefs:
            - name: example-gateway
          hostnames:
            - example.com
          rules:
            - backendRefs:
                - name: svc
                  port: 443
    "#
);
