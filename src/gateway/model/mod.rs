// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust Gateway API model layer.

pub mod digest;
pub mod types;
pub mod view;

pub use digest::compute_digest;
pub use types::{
    BackendTarget, ListenerKey, RefResolution, ResolvedRoute, RouteTableDigest, StatusPatch,
};
pub use view::{
    GatewayState, GatewayView, GrantSubject, ListenerModel, ListenerState, ParentRef,
    ReferenceGrantState, ReconciledView, RouteState,
};
