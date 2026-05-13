// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! iptables backend for GAMMA (Service mesh / east-west routing).
//!
//! Translates Gateway API Service routes into `iptables` / `nftables`
//! rules or eBPF redirects.  Stub for v1; real implementation gated
//! behind Linux build tags.

/// Apply GAMMA dataplane rules derived from the reconciled view.
pub fn apply_gamma_rules() {
    tracing::trace!("GAMMA dataplane stub");
}
