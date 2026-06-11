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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn apply_listeners_empty_is_callable() {
        apply_listeners(&[]);
    }

    #[test]
    fn apply_listeners_with_model_is_callable() {
        let listener = ListenerModel {
            name: Arc::from("http"),
            protocol: Arc::from("HTTP"),
            port: 80,
            hostname: None,
        };
        apply_listeners(&[listener]);
    }
}
