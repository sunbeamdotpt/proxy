// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Route / listener translation layer.
//!
//! Converts a `GatewayView` into Pingora-native configuration:
//!   - `pingora_proxy::http_proxy_service` upstream definitions
//!   - TLS certificate mapping
//!   - GAMMA service route iptables rules (delegated to `dataplane`)

use crate::gateway::model::GatewayView;

/// Translate a reconciled view into Pingora configuration updates.
pub fn translate_view(_view: &GatewayView) {
    tracing::trace!("translate stub");
}
