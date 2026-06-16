// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! L4 route reconciler (TCPRoute / UDPRoute / TLSRoute).
//!
//! Watches L4 route resources, resolves parentRefs against Gateway listeners,
//! validates backendRefs, computes status conditions, and emits the L4 route
//! states consumed by `translate_view_to_ir`.

pub mod controller;
pub mod kinds;
pub mod model;
pub mod reconcile;

// Re-exports for existing callers at `crate::gateway::reconcile::l4route::*`.
pub use controller::{
    maybe_run_tcproute_controller, maybe_run_tlsroute_controller, maybe_run_udproute_controller,
    reconcile_tcproute, reconcile_tlsroute, reconcile_udproute, run_tcproute_controller,
    run_tlsroute_controller, run_udproute_controller,
};
pub use kinds::{parse_tcproute_state, parse_tlsroute_state, parse_udproute_state};
pub use model::{L4ParentStatus, L4RouteContext, ReconciledL4Route};
pub use reconcile::{reconcile_tcproutes, reconcile_tlsroutes, reconcile_udproutes};

pub use kinds::{parse_tcproute, parse_tlsroute, parse_udproute};
pub use reconcile::resolve_l4_backends_async;

pub use crate::gateway::reconcile::parent::ParsedParentRef;
pub use controller::{error_policy_l4, l4_crd_available, patch_l4_status};
pub use model::ParsedBackendRef;
pub use reconcile::resolve_l4_backends;
pub use reconcile::resolve_l4_parent_ref;
