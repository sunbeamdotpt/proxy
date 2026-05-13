// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Condition builders for the Gateway API status writeback layer.
//!
//! Each function produces a [`StatusCondition`] aligned with the Gateway API
//! v1.5.1 specification.  Callers supply the observed generation so that
//! `observedGeneration` is always accurate.

use super::{ConditionStatus, ConditionType, StatusCondition};

// ---------------------------------------------------------------------------
// Standard Gateway API condition reasons (Gateway)
// ---------------------------------------------------------------------------

/// Reasons for the `Accepted` condition on a **Gateway**.
pub mod accepted_reason {
    pub const ACCEPTED: &str = "Accepted";
    pub const INVALID: &str = "Invalid";
    pub const NOT_RECONCILED: &str = "NotReconciled";
    pub const PENDING: &str = "Pending";
    pub const UNSUPPORTED_VALUE: &str = "UnsupportedValue";
}

/// Reasons for the `Programmed` condition on a **Gateway**.
pub mod programmed_reason {
    pub const PROGRAMMED: &str = "Programmed";
    pub const PENDING: &str = "Pending";
    pub const INVALID: &str = "Invalid";
}

/// Reasons for the `ResolvedRefs` condition.
pub mod resolved_refs_reason {
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    pub const INVALID_KIND: &str = "InvalidKind";
    pub const BACKEND_NOT_FOUND: &str = "BackendNotFound";
    pub const HOSTNAME_RESOLUTION_FAILED: &str = "HostnameResolutionFailed";
}

/// Reasons for route-level conditions.
pub mod route_reason {
    pub const NO_MATCHING_PARENT: &str = "NoMatchingParent";
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    pub const ACCEPTED: &str = "Accepted";
    pub const ROUTE_INVALID: &str = "RouteInvalid";
    pub const ROUTE_STATUS_UNSUPPORTED_VALUE: &str = "UnsupportedValue";
}

// ---------------------------------------------------------------------------
// Condition builders
// ---------------------------------------------------------------------------

/// Build an `Accepted` condition.
///
/// # Examples
///
/// ```
/// use sunbeam_proxy::gateway::status::conditions::accepted_condition;
/// use sunbeam_proxy::gateway::status::ConditionStatus;
/// let c = accepted_condition(ConditionStatus::True, "Accepted", "gateway accepted", 7);
/// assert_eq!(c.status, ConditionStatus::True);
/// ```
pub fn accepted_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::Accepted,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `Programmed` condition.
pub fn programmed_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::Programmed,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `ResolvedRefs` condition.
pub fn resolved_refs_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::ResolvedRefs,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `NoMatchingParent` condition (always **False**).
pub fn no_matching_parent_condition(message: &str, observed_generation: i64) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::NoMatchingParent,
        status: ConditionStatus::False,
        reason: route_reason::NO_MATCHING_PARENT.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `RefNotPermitted` condition (always **False**).
pub fn ref_not_permitted_condition(message: &str, observed_generation: i64) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::RefNotPermitted,
        status: ConditionStatus::False,
        reason: route_reason::REF_NOT_PERMITTED.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `Conflicted` condition (sunbeam-specific extension).
pub fn conflicted_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::Conflicted,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build a `Poison` condition (sunbeam-specific extension).
pub fn poison_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::Poison,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

/// Build an `UnsupportedFeature` condition.
pub fn unsupported_feature_condition(
    status: ConditionStatus,
    reason: &str,
    message: &str,
    observed_generation: i64,
) -> StatusCondition {
    StatusCondition {
        condition_type: ConditionType::UnsupportedFeature,
        status,
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_condition_fields() {
        let c = accepted_condition(
            ConditionStatus::True,
            accepted_reason::ACCEPTED,
            "all good",
            42,
        );
        assert_eq!(c.condition_type, ConditionType::Accepted);
        assert_eq!(c.status, ConditionStatus::True);
        assert_eq!(c.reason, "Accepted");
        assert_eq!(c.message, "all good");
        assert_eq!(c.observed_generation, 42);
    }

    #[test]
    fn programmed_condition_false() {
        let c = programmed_condition(
            ConditionStatus::False,
            programmed_reason::PENDING,
            "waiting for addresses",
            3,
        );
        assert_eq!(c.condition_type, ConditionType::Programmed);
        assert_eq!(c.status, ConditionStatus::False);
        assert_eq!(c.reason, "Pending");
    }

    #[test]
    fn resolved_refs_condition_unknown() {
        let c = resolved_refs_condition(
            ConditionStatus::Unknown,
            resolved_refs_reason::BACKEND_NOT_FOUND,
            "backend svc-1 not found",
            1,
        );
        assert_eq!(c.condition_type, ConditionType::ResolvedRefs);
        assert_eq!(c.status, ConditionStatus::Unknown);
        assert_eq!(c.reason, "BackendNotFound");
    }

    #[test]
    fn no_matching_parent_is_always_false() {
        let c = no_matching_parent_condition("no gateway matches parentRef", 5);
        assert_eq!(c.condition_type, ConditionType::NoMatchingParent);
        assert_eq!(c.status, ConditionStatus::False);
        assert_eq!(c.reason, "NoMatchingParent");
    }

    #[test]
    fn ref_not_permitted_is_always_false() {
        let c = ref_not_permitted_condition("missing ReferenceGrant", 2);
        assert_eq!(c.condition_type, ConditionType::RefNotPermitted);
        assert_eq!(c.status, ConditionStatus::False);
        assert_eq!(c.reason, "RefNotPermitted");
    }

    #[test]
    fn conflicted_condition_fields() {
        let c = conflicted_condition(
            ConditionStatus::True,
            "Conflicted",
            "listener port conflict",
            7,
        );
        assert_eq!(c.condition_type, ConditionType::Conflicted);
        assert_eq!(c.status, ConditionStatus::True);
        assert_eq!(c.reason, "Conflicted");
    }

    #[test]
    fn poison_condition_fields() {
        let c = poison_condition(
            ConditionStatus::False,
            "NotPoisoned",
            "within crash budget",
            9,
        );
        assert_eq!(c.condition_type, ConditionType::Poison);
        assert_eq!(c.status, ConditionStatus::False);
    }

    #[test]
    fn unsupported_feature_condition_fields() {
        let c = unsupported_feature_condition(
            ConditionStatus::False,
            "UnsupportedExtension",
            "TLSRoute not yet supported",
            1,
        );
        assert_eq!(c.condition_type, ConditionType::UnsupportedFeature);
        assert_eq!(c.status, ConditionStatus::False);
    }
}
