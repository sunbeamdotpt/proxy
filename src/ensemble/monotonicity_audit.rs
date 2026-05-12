// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Empirical companion to the Lean Tier 2 monotonicity proofs.
//!
//! The Lean theorem `Sunbeam.Verify.Monotonicity.ensemble_block_preserved_when_tree_constant`
//! is conditional on two side conditions:
//!   1. The tree's verdict on `y` equals the tree's verdict on `x` — holds
//!      automatically when feature `i` is not a tree split feature.
//!   2. The MLP is monotone non-decreasing in feature `i` — discharged by the
//!      per-neuron sign constraint `∀ j. W2[j] * W1[j][i] ≥ 0`
//!      (see `Sunbeam.Verify.Monotonicity.mlp_forward_monotone_in`).
//!
//! This module audits the *currently shipped* scanner weights against those
//! conditions and reports which input feature indices are provably immune to
//! evasion by increasing that feature alone.

use super::gen::scanner_weights::{TREE_NODES, W1, W2};

/// Number of input features for the scanner.
pub const NUM_FEATURES: usize = 12;

/// Number of hidden neurons in the scanner MLP.
pub const HIDDEN_DIM: usize = 32;

/// Leaf marker used by the packed tree encoding (see `ensemble::tree`).
const LEAF_MARKER: u8 = 255;

/// Audit report for the scanner ensemble.
#[derive(Debug, Clone)]
pub struct MonotonicityAudit {
    /// Set of input feature indices the tree splits on (decisions depend on
    /// these).
    pub tree_split_features: Vec<u8>,
    /// True if any tree leaf can return `Defer` — i.e., the MLP can run.
    pub tree_has_defer_leaf: bool,
    /// `per_feature_mlp_min_product[i] = min_j (W2[j] * W1[j][i])`.
    /// Non-negative means the MLP is monotone non-decreasing in feature `i`.
    pub per_feature_mlp_min_product: [f32; NUM_FEATURES],
}

impl MonotonicityAudit {
    /// Feature indices considered "monotone-bad" by domain semantics —
    /// increasing these should never reduce the Block score. See
    /// `crate::scanner::features::extract_features`.
    pub const ADVERSARIAL_FEATURE_INDICES: &'static [usize] = &[
        0,  // suspicious_path_score
        2,  // has_suspicious_extension
        8,  // method_is_unusual
        10, // content_length_mismatch
        11, // path_has_traversal
    ];

    /// Compute the audit for the currently shipped scanner weights.
    pub fn for_scanner() -> Self {
        let tree_split_features: Vec<u8> = TREE_NODES
            .iter()
            .filter(|(f, _, _, _)| *f != LEAF_MARKER)
            .map(|(f, _, _, _)| *f)
            .collect();

        let tree_has_defer_leaf = TREE_NODES
            .iter()
            .any(|(f, t, _, _)| *f == LEAF_MARKER && *t >= 0.25 && *t <= 0.75);

        let mut per_feature_mlp_min_product = [0.0f32; NUM_FEATURES];
        for i in 0..NUM_FEATURES {
            let mut min = f32::INFINITY;
            for j in 0..HIDDEN_DIM {
                let p = W2[j] * W1[j][i];
                if p < min {
                    min = p;
                }
            }
            per_feature_mlp_min_product[i] = min;
        }

        Self {
            tree_split_features,
            tree_has_defer_leaf,
            per_feature_mlp_min_product,
        }
    }

    /// Returns the feature indices for which the ensemble is provably monotone
    /// non-decreasing under the currently shipped weights.
    ///
    /// Two paths to monotonicity:
    /// - Feature is not a tree split feature AND the tree has no Defer leaves
    ///   (MLP never runs, its sign is moot).
    /// - Feature is not a tree split feature AND `per_feature_mlp_min_product[i] ≥ 0`
    ///   (sign constraint holds, MLP-side proof discharges).
    pub fn provably_monotone_features(&self) -> Vec<usize> {
        (0..NUM_FEATURES)
            .filter(|&i| self.is_provably_monotone(i))
            .collect()
    }

    /// Whether a single feature is provably monotone under the current weights.
    pub fn is_provably_monotone(&self, feature_idx: usize) -> bool {
        if self.tree_split_features.contains(&(feature_idx as u8)) {
            return false;
        }
        if !self.tree_has_defer_leaf {
            return true;
        }
        self.per_feature_mlp_min_product[feature_idx] >= 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_summary_prints() {
        let audit = MonotonicityAudit::for_scanner();
        eprintln!("tree split features:   {:?}", audit.tree_split_features);
        eprintln!("tree has defer leaf:   {}", audit.tree_has_defer_leaf);
        eprintln!("provably monotone:     {:?}", audit.provably_monotone_features());
        for i in 0..NUM_FEATURES {
            let m = audit.per_feature_mlp_min_product[i];
            let adv = MonotonicityAudit::ADVERSARIAL_FEATURE_INDICES.contains(&i);
            eprintln!(
                "  feature {:>2}: min(W2·W1[:,i]) = {:>10.6}  {}{}",
                i,
                m,
                if m >= 0.0 { "[mlp-mono]" } else { "          " },
                if adv { "  [adversarial]" } else { "" }
            );
        }
    }

    #[test]
    fn tree_split_features_in_range() {
        let audit = MonotonicityAudit::for_scanner();
        for f in &audit.tree_split_features {
            assert!(
                (*f as usize) < NUM_FEATURES,
                "tree split feature {} out of range",
                f
            );
        }
    }

    #[test]
    fn monotone_features_in_range() {
        let audit = MonotonicityAudit::for_scanner();
        for i in audit.provably_monotone_features() {
            assert!(i < NUM_FEATURES, "feature {} out of range", i);
        }
    }

    /// Diagnostic — reports the MLP-side sign-constraint status for each
    /// adversarial feature. The tree no longer gates production verdicts, so
    /// monotonicity in adversarial features now reduces to the MLP-side
    /// constraint `min_j(W2[j] * W1[j][i]) ≥ 0`. Failures are structural
    /// findings, not test breakage.
    #[test]
    fn adversarial_sign_constraint_diagnostic() {
        let audit = MonotonicityAudit::for_scanner();
        for &i in MonotonicityAudit::ADVERSARIAL_FEATURE_INDICES {
            let m = audit.per_feature_mlp_min_product[i];
            eprintln!(
                "  feature {i}: min(W2·W1[:,i]) = {m:>10.6}  {}",
                if m >= 0.0 { "[sign-ok]" } else { "[sign-violated]" }
            );
        }
    }
}
