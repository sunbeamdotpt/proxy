// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! GRPCRoute re-exports from the official `gateway-api` crate.

/// GRPCRoute CRD re-exported from the official `gateway-api` crate.
pub type GRPCRoute = gateway_api::grpcroutes::GRPCRoute;
/// GRPCRouteSpec re-exported from the official `gateway-api` crate.
pub type GRPCRouteSpec = gateway_api::grpcroutes::GrpcRouteSpec;
/// GRPCRouteStatus re-exported from the official `gateway-api` crate.
pub type GRPCRouteStatus = gateway_api::grpcroutes::GrpcRouteStatus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_grpcroute() {
        let yaml = r#"
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
        "#;
        let route: GRPCRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(route.spec.hostnames, Some(vec!["example.com".to_string()]));
    }
}
