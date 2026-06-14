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

pub use gateway_api::backendtlspolicies::{
    BackendTLSPolicy, BackendTlsPolicySpec, BackendTlsPolicyStatus,
    BackendTlsPolicyStatusAncestors, BackendTlsPolicyStatusAncestorsAncestorRef,
    BackendTlsPolicyTargetRefs, BackendTlsPolicyValidation,
    BackendTlsPolicyValidationCaCertificateRefs, BackendTlsPolicyValidationSubjectAltNames,
};
