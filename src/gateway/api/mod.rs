// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gateway API CRD bindings (v1.5.1).

pub mod gateway;
pub mod gatewayclass;
pub mod httproute;
pub mod referencegrant;

pub use gateway::Gateway;
pub use gatewayclass::GatewayClass;
pub use httproute::HTTPRoute;
pub use referencegrant::ReferenceGrant;
