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

pub use digest_publisher::publish_digest;
pub use resource_notify::handle_notify;
