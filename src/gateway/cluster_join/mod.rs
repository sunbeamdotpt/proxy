// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gossip mesh join for gateway-specific topics.
//!
//! On startup the gateway layer subscribes to:
//!   - `gateway-state`   — periodic `GatewayStateDigest` broadcasts
//!   - `gateway-notify`  — ad-hoc `GatewayResourceNotify` events
//!
//! Topics are derived deterministically via `blake3` (see `cluster::node::derive_topic`).

use iroh_gossip::proto::TopicId;

/// Return the gossip topic for gateway state digests.
pub fn gateway_state_topic(tenant: &str) -> TopicId {
    crate::cluster::node::derive_topic(tenant, "gateway-state")
}

/// Return the gossip topic for gateway resource notifications.
pub fn gateway_notify_topic(tenant: &str) -> TopicId {
    crate::cluster::node::derive_topic(tenant, "gateway-notify")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_state_topic_is_deterministic() {
        let a = gateway_state_topic("tenant-a");
        let b = gateway_state_topic("tenant-a");
        assert_eq!(a, b);
    }

    #[test]
    fn gateway_state_topic_differs_by_tenant() {
        let a = gateway_state_topic("tenant-a");
        let b = gateway_state_topic("tenant-b");
        assert_ne!(a, b);
    }

    #[test]
    fn gateway_notify_topic_differs_from_state_topic() {
        let state = gateway_state_topic("tenant-a");
        let notify = gateway_notify_topic("tenant-a");
        assert_ne!(state, notify);
    }
}
