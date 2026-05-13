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
