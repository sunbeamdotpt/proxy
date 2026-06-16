// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stable canonical digest of a [`ReconciledView`].

pub use core::compute_digest;

pub(crate) mod common;
pub(crate) mod core;
pub(crate) mod http;
pub(crate) mod l4;

#[cfg(test)]
mod tests;

pub(crate) use super::routing::{HTTPRouteState, TCPRouteState, TLSRouteState, UDPRouteState};
pub(crate) use super::view::{
    AllowedRoutes, GatewayState, GrantSubject, ListenerSetState, ListenerState, NamespaceFrom,
    ParentRef, ReconciledView, ReferenceGrantState, RouteGroupKind, RouteNamespaces, RouteState,
};
