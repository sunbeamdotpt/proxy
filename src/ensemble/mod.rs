// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

/// CROWN-based certified adversarial robustness radius (scanner, generic).
pub mod crown;
/// DDoS ensemble inference.
pub mod ddos;
/// DDoS-specific CROWN certified radius wired to trained DDoS weights.
pub mod ddos_crown;
/// Empirical audit of DDoS monotonicity side conditions.
pub mod ddos_monotonicity_audit;
/// Compiled-in weight tables (auto-generated from training).
pub mod gen;
/// Scalar MLP forward shared by scanner and DDoS.
pub mod mlp;
/// Empirical audit of the scanner monotonicity proof's side conditions.
pub mod monotonicity_audit;
/// Verdict replay for offline evaluation.
pub mod replay;
/// Scanner ensemble inference.
pub mod scanner;
/// Decision-tree primitives (legacy gate; no longer in production verdict path).
pub mod tree;
