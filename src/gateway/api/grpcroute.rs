// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute re-exports from the official `gateway-api` crate.

crate::gateway_api_route_alias!(
    "GRPCRoute re-exports from the official `gateway-api` crate.",
    GRPCRoute,
    GrpcRouteSpec,
    GRPCRouteStatus,
    gateway_api::grpcroutes::GRPCRoute,
    gateway_api::grpcroutes::GrpcRouteSpec,
    gateway_api::grpcroutes::GrpcRouteStatus,
    r#"
        apiVersion: gateway.networking.k8s.io/v1
        kind: GRPCRoute
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
