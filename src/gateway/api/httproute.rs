// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPRoute re-exports from the official `gateway-api` crate.

crate::gateway_api_route_alias!(
    "HTTPRoute re-exports from the official `gateway-api` crate.",
    HTTPRoute,
    HttpRouteSpec,
    HTTPRouteStatus,
    gateway_api::httproutes::HTTPRoute,
    gateway_api::httproutes::HttpRouteSpec,
    gateway_api::httproutes::HttpRouteStatus,
    r#"
        apiVersion: gateway.networking.k8s.io/v1
        kind: HTTPRoute
        metadata:
          name: example-route
          namespace: default
        spec:
          parentRefs:
            - name: example-gateway
          hostnames:
            - example.com
    "#
);
