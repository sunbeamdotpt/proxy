// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TCPRoute re-exports from the official `gateway-api` crate.

/// TCPRoute CRD re-exported from the official `gateway-api` crate.
pub type TCPRoute = gateway_api::experimental::tcproutes::TCPRoute;
/// TCPRouteSpec re-exported from the official `gateway-api` crate.
pub type TCPRouteSpec = gateway_api::experimental::tcproutes::TcpRouteSpec;
/// TCPRouteStatus re-exported from the official `gateway-api` crate.
pub type TCPRouteStatus = gateway_api::experimental::tcproutes::TcpRouteStatus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_tcproute() {
        let yaml = r#"
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
        "#;
        let route: TCPRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(route.spec.parent_refs.as_ref().unwrap().len(), 1);
    }
}
