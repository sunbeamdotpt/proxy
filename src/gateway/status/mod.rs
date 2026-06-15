// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Status writeback.
//!
//! After each reconcile tick the leader writes status conditions back to
//! the Kubernetes API server.  Conditions follow the Gateway API standard
//! plus Sunbeam-specific extensions (`Poison`, `Conflicted`).

pub mod conditions;
pub mod patch;

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
    InsecureFrontendValidationMode,
}

impl std::fmt::Display for ConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConditionType::Accepted => "Accepted",
            ConditionType::Programmed => "Programmed",
            ConditionType::ResolvedRefs => "ResolvedRefs",
            ConditionType::Conflicted => "Conflicted",
            ConditionType::Poison => "Poison",
            ConditionType::NoMatchingParent => "NoMatchingParent",
            ConditionType::RefNotPermitted => "RefNotPermitted",
            ConditionType::UnsupportedFeature => "UnsupportedFeature",
            ConditionType::InsecureFrontendValidationMode => "InsecureFrontendValidationMode",
        };
        f.write_str(s)
    }
}

/// Condition status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

impl std::fmt::Display for ConditionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConditionStatus::True => "True",
            ConditionStatus::False => "False",
            ConditionStatus::Unknown => "Unknown",
        };
        f.write_str(s)
    }
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

impl From<&StatusCondition> for k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition {
    fn from(c: &StatusCondition) -> Self {
        Self {
            last_transition_time: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::now(),
            ),
            message: c.message.clone(),
            observed_generation: Some(c.observed_generation),
            reason: c.reason.clone(),
            status: c.status.to_string(),
            type_: c.condition_type.to_string(),
        }
    }
}

