// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Listener integration.
//!
//! Bridges the reconciled `ListenerModel` list with the Pingora server
//! lifecycle (add/remove TLS listeners, SNI mapping, etc.).

use crate::gateway::model::ListenerModel;

/// Apply the desired listener set to the running Pingora instance.
pub fn apply_listeners(_listeners: &[ListenerModel]) {
    tracing::trace!("listener apply stub");
}
