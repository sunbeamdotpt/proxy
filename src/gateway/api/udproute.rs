// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDPRoute re-exports from the official `gateway-api` crate.

/// UDPRoute CRD re-exported from the official `gateway-api` crate.
pub type UDPRoute = gateway_api::experimental::udproutes::UDPRoute;
/// UDPRouteSpec re-exported from the official `gateway-api` crate.
pub type UDPRouteSpec = gateway_api::experimental::udproutes::UdpRouteSpec;
/// UDPRouteStatus re-exported from the official `gateway-api` crate.
pub type UDPRouteStatus = gateway_api::experimental::udproutes::UdpRouteStatus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_udproute() {
        let yaml = r#"
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
        "#;
        let route: UDPRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(route.spec.parent_refs.as_ref().unwrap().len(), 1);
    }
}
