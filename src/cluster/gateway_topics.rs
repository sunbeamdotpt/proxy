// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gossip topic schemas for the Gateway API feature.
//!
//! Messages are serialized with bincode before broadcast.

use serde::{Deserialize, Serialize};

/// Periodic digest broadcast by the leader so followers can
/// cross-validate their local reconciled view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStateDigest {
    /// Topic schema version (bumped on breaking changes).
    pub topic_version: u32,
    /// Blake3 hash (256-bit) of the canonical serialized reconciled view.
    pub state_hash: [u8; 32],
    /// Monotonic term counter to detect stale digests.
    pub term: u64,
    /// Node that produced this digest.
    pub node_id: [u8; 32],
    /// UNIX timestamp (seconds) when the digest was computed.
    pub timestamp: u64,
}

/// Ad-hoc notification sent when a Gateway API CRD changes.
/// Followers use this to trigger early cache invalidation instead of
/// waiting for the next poll cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayResourceNotify {
    /// Topic schema version (bumped on breaking changes).
    pub topic_version: u32,
    /// Kind of the changed resource (e.g. "Gateway", "HTTPRoute").
    pub kind: String,
    /// Namespace of the changed resource.
    pub namespace: String,
    /// Name of the changed resource.
    pub name: String,
    /// Generation observed by the leader.
    pub generation: i64,
    /// UNIX timestamp (seconds) of the change.
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_state_digest_roundtrip() {
        let original = GatewayStateDigest {
            topic_version: 1,
            state_hash: [0xab; 32],
            term: 42,
            node_id: [0xcd; 32],
            timestamp: 1_700_000_000,
        };
        let bytes = bincode::serialize(&original).unwrap();
        let decoded: GatewayStateDigest = bincode::deserialize(&bytes).unwrap();
        assert_eq!(original.topic_version, decoded.topic_version);
        assert_eq!(original.state_hash, decoded.state_hash);
        assert_eq!(original.term, decoded.term);
        assert_eq!(original.node_id, decoded.node_id);
        assert_eq!(original.timestamp, decoded.timestamp);
    }

    #[test]
    fn gateway_resource_notify_roundtrip() {
        let original = GatewayResourceNotify {
            topic_version: 1,
            kind: "HTTPRoute".into(),
            namespace: "default".into(),
            name: "example".into(),
            generation: 7,
            timestamp: 1_700_000_000,
        };
        let bytes = bincode::serialize(&original).unwrap();
        let decoded: GatewayResourceNotify = bincode::deserialize(&bytes).unwrap();
        assert_eq!(original.kind, decoded.kind);
        assert_eq!(original.namespace, decoded.namespace);
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.generation, decoded.generation);
    }
}
