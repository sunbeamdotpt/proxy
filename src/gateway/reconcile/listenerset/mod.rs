// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! ListenerSet reconciler helpers.
//!
//! This module parses ListenerSet resources, validates them against the parent
//! Gateway's `allowedListeners`, and produces the model state used by the
//! translation layer.  It is also used by the status-writeback controller.

pub mod controller;
pub mod state;

pub(crate) use controller::patch_listener_set_statuses;
pub use controller::{ListenerSetContext, reconcile_listenerset, run_listenerset_controller};
pub use state::{
    build_listener_set_allowed_map, build_listener_set_state, build_listener_set_status,
    build_listener_state, count_attached_listener_sets, find_parent_gateway, listener_set_allowed,
    parse_allowed_listeners, resolve_listener_set_conflicts,
};
