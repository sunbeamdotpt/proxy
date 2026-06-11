// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! HTTPRoute re-exports from the official `gateway-api` crate.

/// HTTPRoute CRD re-exported from the official `gateway-api` crate.
pub type HTTPRoute = gateway_api::httproutes::HTTPRoute;
/// HTTPRouteSpec re-exported from the official `gateway-api` crate.
pub type HTTPRouteSpec = gateway_api::httproutes::HttpRouteSpec;
/// HTTPRouteStatus re-exported from the official `gateway-api` crate.
pub type HTTPRouteStatus = gateway_api::httproutes::HttpRouteStatus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_httproute() {
        let yaml = r#"
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
        "#;
        let route: HTTPRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(
            route.spec.hostnames,
            Some(vec!["example.com".to_string()])
        );
    }
}
