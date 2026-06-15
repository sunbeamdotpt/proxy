// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway API CRD bindings (v1.5.1).

pub mod gateway;
pub mod gatewayclass;
pub mod grpcroute;
pub mod httproute;
pub mod listenerset;
pub mod referencegrant;
pub mod tcproute;
pub mod tlsroute;
pub mod udproute;

pub use gateway::Gateway;
pub use gatewayclass::GatewayClass;
pub use grpcroute::GRPCRoute;
pub use httproute::HTTPRoute;
pub use listenerset::ListenerSet;
pub use referencegrant::ReferenceGrant;
pub use tcproute::TCPRoute;
pub use tlsroute::TLSRoute;
pub use udproute::UDPRoute;

/// Generate type aliases and a basic deserialization test for a Gateway API
/// route CRD re-exported from the official `gateway-api` crate.
#[macro_export]
macro_rules! gateway_api_route_alias {
    (
        $doc:literal,
        $Route:ident,
        $Spec:ident,
        $Status:ident,
        $SourceRoute:ty,
        $SourceSpec:ty,
        $SourceStatus:ty,
        $yaml:literal
    ) => {
        pub type $Route = $SourceRoute;
        pub type $Spec = $SourceSpec;
        pub type $Status = $SourceStatus;

        #[cfg(test)]
        mod tests {
            use super::*;

            #[test]
            fn test_deserialize() {
                let _: $Route = serde_yaml::from_str($yaml).expect("deserializes");
            }
        }
    };
}

pub use gateway_api::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicySpec, BackendTlsPolicyStatus,
    BackendTlsPolicyStatusAncestors, BackendTlsPolicyStatusAncestorsAncestorRef,
    BackendTlsPolicyTargetRefs, BackendTlsPolicyValidation,
    BackendTlsPolicyValidationCaCertificateRefs, BackendTlsPolicyValidationSubjectAltNames,
};
