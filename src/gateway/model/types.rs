// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core types used by the Gateway API model layer.

use std::sync::Arc;

/// Identifies a listener within a specific gateway.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerKey {
    pub gateway_ns: Arc<str>,
    pub gateway_name: Arc<str>,
    pub listener_name: Arc<str>,
}

/// A resolved backend target: IP address, port, and weight.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BackendTarget {
    /// IPv6 address.  IPv4 addresses are stored as IPv4-mapped IPv6
    /// (e.g. `::ffff:192.0.2.1`).
    pub ip: [u8; 16],
    pub port: u16,
    pub weight: u32,
}

/// Result of resolving a `backendRef` or `parentRef`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RefResolution {
    /// Successfully resolved to a concrete backend target.
    Resolved(BackendTarget),
    /// The referenced resource does not exist.
    NotFound,
    /// A `ReferenceGrant` is missing or insufficient.
    RefNotPermitted,
    /// The reference is to a unsupported kind or group.
    Unsupported,
}

/// A pending status patch for a Kubernetes resource.
///
/// This is intentionally decoupled from `kube` so that the model layer
/// stays pure Rust.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StatusPatch {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub kind: Arc<str>,
    pub generation: i64,
    /// Opaque JSON blob representing the status sub-resource.
    pub json: Arc<str>,
}

/// A route whose backend references have been fully resolved.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedRoute {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub kind: Arc<str>,
    pub parent_refs: Vec<ListenerKey>,
    pub backends: Vec<(BackendTarget, RefResolution)>,
}

/// Compact digest gossiped on the `gateway_state` cluster topic.
///
/// Internally wraps a [`blake3::Hash`] so it remains fixed-size and
/// cheap to clone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RouteTableDigest {
    pub hash: blake3::Hash,
}

impl RouteTableDigest {
    /// Wrap a pre-computed hash.
    pub const fn from_hash(hash: blake3::Hash) -> Self {
        Self { hash }
    }

    /// Returns the raw bytes of the digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.hash.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_table_digest_from_hash() {
        let hash = blake3::hash(b"hello");
        let digest = RouteTableDigest::from_hash(hash);
        assert_eq!(digest.as_bytes(), hash.as_bytes());
    }

    #[test]
    fn backend_target_equality() {
        let a = BackendTarget {
            ip: [0; 16],
            port: 80,
            weight: 1,
        };
        let b = BackendTarget {
            ip: [0; 16],
            port: 80,
            weight: 1,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn listener_key_ordering() {
        let a = ListenerKey {
            gateway_ns: Arc::from("a"),
            gateway_name: Arc::from("b"),
            listener_name: Arc::from("c"),
        };
        let b = ListenerKey {
            gateway_ns: Arc::from("a"),
            gateway_name: Arc::from("b"),
            listener_name: Arc::from("d"),
        };
        assert!(a < b);
    }
}
