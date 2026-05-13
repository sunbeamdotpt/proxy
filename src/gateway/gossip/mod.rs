// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gossip digest publisher and resource notification receiver.
//!
//! Leader: periodically publishes `GatewayStateDigest` (blake3 hash of the
//! reconciled view) so followers can cross-validate their local state.
//!
//! Follower: listens to `GatewayResourceNotify` events and triggers an
//! early reconcile / cache invalidation when CRDs change.

pub mod digest_publisher;
pub mod resource_notify;

/// Publish a state digest to the gateway-state gossip topic.
pub async fn publish_digest(_digest: &crate::cluster::gateway_topics::GatewayStateDigest) {
    tracing::trace!("digest publish stub");
}

/// Handle an incoming resource notification.
pub async fn handle_notify(_notify: &crate::cluster::gateway_topics::GatewayResourceNotify) {
    tracing::trace!("resource notify stub");
}
