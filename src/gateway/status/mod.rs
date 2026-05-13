// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Status writeback.
//!
//! After each reconcile tick the leader writes status conditions back to
//! the Kubernetes API server.  Conditions follow the Gateway API standard
//! plus Sunbeam-specific extensions (`Poison`, `Conflicted`).

pub mod conditions;
pub mod writer;

pub use writer::StatusWriter;

/// Standard Gateway API status condition types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionType {
    Accepted,
    Programmed,
    ResolvedRefs,
    Conflicted,
    Poison,
    NoMatchingParent,
    RefNotPermitted,
    UnsupportedFeature,
}

/// Condition status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

/// A single status condition entry.
#[derive(Debug, Clone)]
pub struct StatusCondition {
    pub condition_type: ConditionType,
    pub status: ConditionStatus,
    pub reason: String,
    pub message: String,
    pub observed_generation: i64,
}

/// Write status conditions for a Gateway object.
///
/// This is a convenience wrapper around [`StatusWriter::write_gateway_status`].
/// It will be removed once all call-sites are migrated to the struct.
pub async fn write_gateway_status(
    _name: &str,
    _namespace: &str,
    _conditions: &[StatusCondition],
) {
    tracing::trace!("status writeback stub — use StatusWriter");
}
