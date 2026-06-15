// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDPRoute re-exports from the official `gateway-api` crate.

crate::gateway_api_route_alias!(
    "UDPRoute re-exports from the official `gateway-api` crate.",
    UDPRoute,
    UdpRouteSpec,
    UDPRouteStatus,
    gateway_api::experimental::udproutes::UDPRoute,
    gateway_api::experimental::udproutes::UdpRouteSpec,
    gateway_api::experimental::udproutes::UdpRouteStatus,
    r#"
        apiVersion: gateway.networking.k8s.io/v1alpha2
        kind: UDPRoute
        metadata:
          name: example-route
          namespace: default
        spec:
          parentRefs:
            - name: example-gateway
          rules:
            - backendRefs:
                - name: svc
                  port: 53
    "#
);
