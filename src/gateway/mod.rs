// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gateway API v1.5.1 reconciler and dataplane integration.
//!
//! This module implements the Kubernetes Gateway API control plane
//! as an in-process reconciler within the Sunbeam proxy.

pub mod api;
pub mod cert;
pub mod election;
pub mod gossip;
pub mod model;
pub mod reconcile;
pub mod status;
pub mod translate;
pub mod watchdog;

/// Gateway-specific runtime configuration.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct GatewayConfig {
    /// Enable the Gateway API reconciler.
    #[serde(default = "default_gateway_enabled")]
    pub enabled: bool,
}

fn default_gateway_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_config_deserializes_to_enabled() {
        let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(cfg.enabled);
    }
}
