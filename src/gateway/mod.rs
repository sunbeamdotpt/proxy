// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Gateway API v1.5.1 reconciler and dataplane integration.
//!
//! This module implements the Kubernetes Gateway API control plane
//! as an in-process reconciler within the Sunbeam proxy.

pub mod api;
pub mod cluster_join;
pub mod dataplane;
pub mod election;
pub mod gossip;
pub mod listeners;
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

fn default_gateway_enabled() -> bool { true }
