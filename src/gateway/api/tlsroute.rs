// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! TLSRoute re-exports from the official `gateway-api` crate.

/// TLSRoute CRD re-exported from the official `gateway-api` crate.
pub type TLSRoute = gateway_api::tlsroutes::TLSRoute;
/// TLSRouteSpec re-exported from the official `gateway-api` crate.
pub type TLSRouteSpec = gateway_api::tlsroutes::TlsRouteSpec;
/// TLSRouteStatus re-exported from the official `gateway-api` crate.
pub type TLSRouteStatus = gateway_api::tlsroutes::TlsRouteStatus;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_tlsroute() {
        let yaml = r#"
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
        "#;
        let route: TLSRoute = serde_yaml::from_str(yaml).expect("deserializes");
        assert_eq!(route.spec.hostnames.len(), 1);
    }
}
