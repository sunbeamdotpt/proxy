// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway address parsing and status.

use crate::gateway::api::gateway::Gateway;
use crate::gateway::api::gatewayclass::GatewayClass;
use crate::gateway::reconcile::gateway::certificates::CertValidation;
use crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME;
use crate::gateway::status::{ConditionStatus, ConditionType, StatusCondition, conditions};

/// A Gateway address requested in `spec.addresses`.
#[derive(Clone, Debug)]
pub(crate) struct GatewaySpecAddress {
    pub(crate) type_: String,
    pub(crate) value: Option<String>,
}

/// Result of validating `spec.addresses` against what this implementation can
/// assign.
#[derive(Clone, Debug, Default)]
pub(crate) struct AddressValidation {
    pub(crate) unsupported: Vec<GatewaySpecAddress>,
    pub(crate) unusable: Vec<GatewaySpecAddress>,
    pub(crate) usable: Vec<GatewaySpecAddress>,
}

/// Parse the requested addresses from a Gateway spec.
pub(crate) fn parse_gateway_addresses(gw: &Gateway) -> Vec<GatewaySpecAddress> {
    let Some(addrs) = gw.spec.addresses.as_deref() else {
        return Vec::new();
    };
    addrs
        .iter()
        .filter_map(|v| v.as_object())
        .map(|obj| GatewaySpecAddress {
            type_: obj
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("IPAddress")
                .to_string(),
            value: obj.get("value").and_then(|v| v.as_str()).map(String::from),
        })
        .collect()
}

/// The implementation-defined address that can actually be assigned to a
/// Gateway. Read from `SUNBEAM_GATEWAY_ADDRESS` with a development default.
pub(crate) fn implementation_address() -> String {
    std::env::var("SUNBEAM_GATEWAY_ADDRESS").unwrap_or_else(|_| "192.168.252.19".into())
}

/// Validate requested addresses. Only `IPAddress` is supported; the assigned
/// value must match the implementation address unless the value is empty, in
/// which case it is filled in.
pub(crate) fn validate_gateway_addresses(addrs: &[GatewaySpecAddress]) -> AddressValidation {
    let impl_addr = implementation_address();
    let mut validation = AddressValidation::default();
    for addr in addrs {
        if addr.type_ != "IPAddress" {
            validation.unsupported.push(addr.clone());
            continue;
        }
        match &addr.value {
            Some(v) if v == &impl_addr => validation.usable.push(addr.clone()),
            Some(_) => validation.unusable.push(addr.clone()),
            None => validation.usable.push(GatewaySpecAddress {
                type_: addr.type_.clone(),
                value: Some(impl_addr.clone()),
            }),
        }
    }
    validation
}

/// Return the address(es) to publish in `Gateway.status.addresses`.
pub(crate) fn gateway_status_addresses(validation: &AddressValidation) -> Vec<serde_json::Value> {
    validation
        .usable
        .iter()
        .map(|a| {
            serde_json::json!({
                "type": a.type_,
                "value": a.value.as_deref().unwrap_or(""),
            })
        })
        .collect()
}

/// Compute the status conditions for a Gateway.
///
/// * `Accepted` — `True` when the referenced GatewayClass exists and is
///   managed by this controller and no unsupported addresses are requested.
/// * `Programmed` — `True` when the Gateway is accepted and all requested
///   addresses are usable.
pub(crate) fn compute_gateway_conditions(
    _gw: &Gateway,
    gateway_class: Option<&GatewayClass>,
    address_validation: &AddressValidation,
    backend_tls_error: Option<CertValidation>,
    insecure_frontend_mode: bool,
    observed_generation: i64,
) -> Vec<StatusCondition> {
    let mut conditions = Vec::new();

    // Accepted
    let accepted = if let Some(gc) = gateway_class {
        if gc.spec.controller_name != CONTROLLER_NAME {
            conditions::accepted_condition(
                ConditionStatus::False,
                "InvalidGatewayClass",
                &format!(
                    "GatewayClass controller '{}' does not match '{}'",
                    gc.spec.controller_name, CONTROLLER_NAME
                ),
                observed_generation,
            )
        } else if !address_validation.unsupported.is_empty() {
            let types: Vec<_> = address_validation
                .unsupported
                .iter()
                .map(|a| format!("{}={}", a.type_, a.value.as_deref().unwrap_or("")))
                .collect();
            conditions::accepted_condition(
                ConditionStatus::False,
                "UnsupportedAddress",
                &format!("Unsupported address type(s): {}", types.join(", ")),
                observed_generation,
            )
        } else {
            conditions::accepted_condition(
                ConditionStatus::True,
                "Accepted",
                "Gateway references an accepted GatewayClass",
                observed_generation,
            )
        }
    } else {
        conditions::accepted_condition(
            ConditionStatus::False,
            "GatewayClassNotFound",
            "Referenced GatewayClass does not exist",
            observed_generation,
        )
    };
    let accepted_true = accepted.status == ConditionStatus::True;
    conditions.push(accepted);

    // Programmed
    let programmed = if !accepted_true {
        conditions::programmed_condition(
            ConditionStatus::False,
            "Invalid",
            "Gateway is not accepted",
            observed_generation,
        )
    } else if !address_validation.unusable.is_empty() {
        let values: Vec<_> = address_validation
            .unusable
            .iter()
            .map(|a| a.value.as_deref().unwrap_or(""))
            .collect();
        conditions::programmed_condition(
            ConditionStatus::False,
            "AddressNotUsable",
            &format!("Address(es) not usable: {}", values.join(", ")),
            observed_generation,
        )
    } else {
        conditions::programmed_condition(
            ConditionStatus::True,
            "Programmed",
            "Gateway configuration programmed into proxy",
            observed_generation,
        )
    };
    conditions.push(programmed);

    // ResolvedRefs
    let resolved_refs = if let Some(err) = backend_tls_error {
        conditions::resolved_refs_condition(
            ConditionStatus::False,
            err.reason,
            err.message,
            observed_generation,
        )
    } else {
        conditions::resolved_refs_condition(
            ConditionStatus::True,
            "ResolvedRefs",
            "All references resolved",
            observed_generation,
        )
    };
    conditions.push(resolved_refs);

    if insecure_frontend_mode {
        conditions.push(conditions::condition(
            ConditionType::InsecureFrontendValidationMode,
            ConditionStatus::True,
            "ConfigurationChanged",
            "Frontend validation mode is AllowInsecureFallback",
            observed_generation,
        ));
    }

    conditions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::reconcile::gateway::test_helpers::{sample_gc, sample_gw};

    #[test]
    fn accepted_true_when_gatewayclass_matches() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        assert_eq!(accepted.reason, "Accepted");
    }

    #[test]
    fn accepted_false_when_gatewayclass_missing() {
        let gw = sample_gw("missing-gc");
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, None, &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "GatewayClassNotFound");
    }

    #[test]
    fn accepted_false_when_gatewayclass_mismatched() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc("other/controller");
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "InvalidGatewayClass");
    }

    #[test]
    fn programmed_is_true_when_accepted() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::True);
        assert_eq!(programmed.reason, "Programmed");
        assert!(programmed.message.contains("programmed into proxy"));
    }

    #[test]
    fn gateway_addresses_obeys_env_var_with_default() {
        // Ensure variable is absent for the default case.
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
        let validation = AddressValidation::default();
        let addresses = gateway_status_addresses(&validation);
        assert!(addresses.is_empty());
        assert_eq!(implementation_address(), "192.168.252.19");

        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.5");
        }
        let validation = AddressValidation {
            usable: vec![GatewaySpecAddress {
                type_: "IPAddress".into(),
                value: Some(implementation_address()),
            }],
            ..Default::default()
        };
        let addresses = gateway_status_addresses(&validation);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0]["type"], "IPAddress");
        assert_eq!(addresses[0]["value"], "10.0.0.5");

        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_marks_unsupported_type() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "test/fake".into(),
            value: Some("x".into()),
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.unsupported.len(), 1);
        assert!(v.usable.is_empty());
        assert!(v.unusable.is_empty());
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_marks_non_impl_address_unusable() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "IPAddress".into(),
            value: Some("10.0.0.2".into()),
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.unusable.len(), 1);
        assert!(v.usable.is_empty());
        assert!(v.unsupported.is_empty());
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn validate_addresses_fills_empty_ip_address() {
        unsafe {
            std::env::set_var("SUNBEAM_GATEWAY_ADDRESS", "10.0.0.1");
        }
        let addrs = vec![GatewaySpecAddress {
            type_: "IPAddress".into(),
            value: None,
        }];
        let v = validate_gateway_addresses(&addrs);
        assert_eq!(v.usable.len(), 1);
        assert_eq!(v.usable[0].value.as_deref(), Some("10.0.0.1"));
        unsafe {
            std::env::remove_var("SUNBEAM_GATEWAY_ADDRESS");
        }
    }

    #[test]
    fn unsupported_address_makes_accepted_false() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation {
            unsupported: vec![GatewaySpecAddress {
                type_: "Hostname".into(),
                value: Some("x".into()),
            }],
            ..Default::default()
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, "UnsupportedAddress");
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
    }

    #[test]
    fn unusable_address_leaves_accepted_true() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation {
            unusable: vec![GatewaySpecAddress {
                type_: "IPAddress".into(),
                value: Some("10.0.0.2".into()),
            }],
            ..Default::default()
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, false, 1);
        let accepted = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Accepted)
            .unwrap();
        assert_eq!(accepted.status, ConditionStatus::True);
        let programmed = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::Programmed)
            .unwrap();
        assert_eq!(programmed.status, ConditionStatus::False);
        assert_eq!(programmed.reason, "AddressNotUsable");
    }

    #[test]
    fn compute_gateway_conditions_adds_insecure_frontend_mode() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, None, true, 1);
        let cond = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::InsecureFrontendValidationMode)
            .unwrap();
        assert_eq!(cond.status, ConditionStatus::True);
        assert_eq!(cond.reason, "ConfigurationChanged");
    }

    #[test]
    fn parse_gateway_addresses_filters_and_defaults() {
        let gw: Gateway = serde_yaml::from_str(
            r#"
            apiVersion: gateway.networking.k8s.io/v1
            kind: Gateway
            metadata:
              name: gw
              namespace: default
            spec:
              gatewayClassName: test-gc
              addresses:
                - type: IPAddress
                  value: 10.0.0.1
                - not-an-object
                - value: 10.0.0.2
              listeners: []
        "#,
        )
        .unwrap();
        let addrs = parse_gateway_addresses(&gw);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].type_, "IPAddress");
        assert_eq!(addrs[0].value.as_deref(), Some("10.0.0.1"));
        assert_eq!(addrs[1].type_, "IPAddress");
        assert_eq!(addrs[1].value.as_deref(), Some("10.0.0.2"));
    }

    #[test]
    fn parse_gateway_addresses_missing_returns_empty() {
        let gw = sample_gw("test-gc");
        assert!(parse_gateway_addresses(&gw).is_empty());
    }

    #[test]
    fn compute_gateway_conditions_resolved_refs_false_on_backend_tls_error() {
        let gw = sample_gw("test-gc");
        let gc = sample_gc(crate::gateway::reconcile::gatewayclass::CONTROLLER_NAME);
        let validation = AddressValidation::default();
        let err = CertValidation {
            reason: "InvalidClientCertificateRef",
            message: "bad",
        };
        let conds = compute_gateway_conditions(&gw, Some(&gc), &validation, Some(err), false, 1);
        let resolved = conds
            .iter()
            .find(|c| c.condition_type == ConditionType::ResolvedRefs)
            .unwrap();
        assert_eq!(resolved.status, ConditionStatus::False);
        assert_eq!(resolved.reason, "InvalidClientCertificateRef");
    }
}
