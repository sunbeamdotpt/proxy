// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! DDoS specialization of `super::monotonicity_audit` at `inputDim = 14`.
//!
//! The adversarial catalog enumerates DDoS features where *increasing the
//! value should never decrease the Block score*. Inverted features (e.g.
//! `cookie_ratio`, where bots typically *lack* cookies) are out of scope —
//! they need a negative-direction argument or a sign-flip in the extractor.

use super::gen::ddos_weights::{TREE_NODES, W1, W2};

/// Number of input features for the DDoS ensemble.
pub const NUM_FEATURES: usize = 14;

/// Number of hidden neurons in the DDoS MLP (shared with scanner).
pub const HIDDEN_DIM: usize = 32;

/// Leaf marker used by the packed tree encoding.
const LEAF_MARKER: u8 = 255;

/// Audit report for the DDoS ensemble.
#[derive(Debug, Clone)]
pub struct DDoSMonotonicityAudit {
    /// Set of input feature indices the DDoS tree splits on.
    pub tree_split_features: Vec<u8>,
    /// True if any tree leaf can return `Defer` — i.e., the MLP can run.
    pub tree_has_defer_leaf: bool,
    /// `per_feature_mlp_min_product[i] = min_j (W2[j] * W1[j][i])`.
    /// Non-negative means the MLP is monotone non-decreasing in feature `i`.
    pub per_feature_mlp_min_product: [f32; NUM_FEATURES],
}

impl DDoSMonotonicityAudit {
    /// Feature indices considered "monotone-bad" by domain semantics —
    /// increasing these should never reduce the Block score. See
    /// `crate::ddos::features::IpState::extract_features` for definitions.
    ///
    /// - `0`: request_rate
    /// - `3`: error_rate
    /// - `6`: burst_score
    /// - `7`: path_repetition
    /// - `13`: suspicious_path_ratio
    pub const ADVERSARIAL_FEATURE_INDICES: &'static [usize] = &[0, 3, 6, 7, 13];

    /// Compute the audit for the currently shipped DDoS weights.
    pub fn for_ddos() -> Self {
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

    /// Returns the feature indices for which the DDoS ensemble is provably
    /// monotone non-decreasing under the currently shipped weights.
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

    /// Human-readable feature names for audit output.
    const FEATURE_NAMES: [&str; NUM_FEATURES] = [
        "request_rate",
        "unique_paths",
        "unique_hosts",
        "error_rate",
        "avg_duration_ms",
        "method_entropy",
        "burst_score",
        "path_repetition",
        "avg_content_length",
        "unique_user_agents",
        "cookie_ratio",
        "referer_ratio",
        "accept_language_ratio",
        "suspicious_path_ratio",
    ];

    #[test]
    fn ddos_audit_summary_prints() {
        let audit = DDoSMonotonicityAudit::for_ddos();
        eprintln!("DDoS tree split features:   {:?}", audit.tree_split_features);
        eprintln!("DDoS tree has defer leaf:   {}", audit.tree_has_defer_leaf);
        eprintln!(
            "DDoS provably monotone:     {:?}",
            audit.provably_monotone_features()
        );
        for i in 0..NUM_FEATURES {
            let m = audit.per_feature_mlp_min_product[i];
            let adv = DDoSMonotonicityAudit::ADVERSARIAL_FEATURE_INDICES.contains(&i);
            eprintln!(
                "  feature {:>2} ({:<22}): min(W2·W1[:,i]) = {:>10.6}  {}{}",
                i,
                FEATURE_NAMES[i],
                m,
                if m >= 0.0 { "[mlp-mono]" } else { "          " },
                if adv { "  [adversarial]" } else { "" }
            );
        }
    }

    #[test]
    fn ddos_tree_split_features_in_range() {
        let audit = DDoSMonotonicityAudit::for_ddos();
        for f in &audit.tree_split_features {
            assert!(
                (*f as usize) < NUM_FEATURES,
                "tree split feature {} out of range",
                f
            );
        }
    }

    #[test]
    fn ddos_monotone_features_in_range() {
        let audit = DDoSMonotonicityAudit::for_ddos();
        for i in audit.provably_monotone_features() {
            assert!(i < NUM_FEATURES, "feature {} out of range", i);
        }
    }

    /// Diagnostic test — reports which adversarial features satisfy the sign
    /// constraint and which don't. Does not assert; failures here become
    /// structural findings for the spec sheet rather than test breakage.
    #[test]
    fn ddos_adversarial_sign_constraint_diagnostic() {
        let audit = DDoSMonotonicityAudit::for_ddos();
        let mut satisfied = Vec::new();
        let mut violated = Vec::new();
        for &i in DDoSMonotonicityAudit::ADVERSARIAL_FEATURE_INDICES {
            let m = audit.per_feature_mlp_min_product[i];
            if m >= 0.0 {
                satisfied.push((i, FEATURE_NAMES[i], m));
            } else {
                violated.push((i, FEATURE_NAMES[i], m));
            }
        }
        eprintln!(
            "DDoS adversarial sign constraint: {} of {} satisfied",
            satisfied.len(),
            DDoSMonotonicityAudit::ADVERSARIAL_FEATURE_INDICES.len()
        );
        for (i, name, m) in &satisfied {
            eprintln!("  feature {i} ({name}): min product {m:>.6}  [sign-ok]");
        }
        for (i, name, m) in &violated {
            eprintln!("  feature {i} ({name}): min product {m:>.6}  [sign-violated]");
        }
    }
}
