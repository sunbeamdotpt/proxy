// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Reconciler submodule.
//!
//! Watches Gateway API CRDs in the configured namespace, validates
//! cross-references (RefGrant, parentRefs, backendRefs), and produces
//! a `GatewayView` that is handed off to `translate`.

pub mod gateway;
pub mod gatewayclass;
pub mod httproute;
pub mod leader;
pub mod refgrant;

pub use leader::run_reconcile_loop;

use crate::gateway::model::GatewayView;

/// Single reconcile tick: fetch all Gateway API objects and emit a view.
pub async fn reconcile_tick() -> Option<GatewayView> {
    tracing::trace!("reconcile tick stub");
    None
}
