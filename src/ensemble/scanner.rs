// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

use super::weights::scanner_weights;
use super::mlp::mlp_predict_32;
use super::tree::{tree_predict, TreeDecision};
use crate::scanner::model::{ScannerAction, ScannerVerdict};

/// Which path the ensemble took to reach its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsemblePath {
    /// Treeblock.
    TreeBlock,
    /// Treeallow.
    TreeAllow,
    /// Mlp.
    Mlp,
}

/// Result of the scanner ensemble: action + confidence score + explanation.
pub struct EnsembleVerdict {
    /// Action.
    pub action: ScannerAction,
    /// Score.
    pub score: f64,
    /// Reason.
    pub reason: &'static str,
    /// Path.
    pub path: EnsemblePath,
}

/// Normalize raw features using trained min/max constants.
#[inline]
fn normalize(raw: &[f32; 12]) -> [f32; 12] {
    let mut out = [0.0f32; 12];
    for i in 0..12 {
        let range = scanner_weights::NORM_MAXS[i] - scanner_weights::NORM_MINS[i];
        out[i] = if range > 0.0 {
            ((raw[i] - scanner_weights::NORM_MINS[i]) / range).clamp(0.0, 1.0)
        } else {
            0.0
        };
    }
    out
}

/// Full ensemble inference: decision tree first, MLP only on `Defer`.
///
/// Returns an [`EnsembleVerdict`] that can be converted into a
/// [`ScannerVerdict`] for the rest of the pipeline.
pub fn scanner_ensemble_predict(raw: &[f32; 12]) -> EnsembleVerdict {
    let input = normalize(raw);

    let tree_result = tree_predict(&scanner_weights::TREE_NODES, &input);
    match tree_result {
        TreeDecision::Block => EnsembleVerdict {
            action: ScannerAction::Block,
            score: 1.0,
            reason: "ensemble:tree_block",
            path: EnsemblePath::TreeBlock,
        },
        TreeDecision::Allow => EnsembleVerdict {
            action: ScannerAction::Allow,
            score: 0.0,
            reason: "ensemble:tree_allow",
            path: EnsemblePath::TreeAllow,
        },
        TreeDecision::Defer => {
            let mlp_score = mlp_predict_32::<12>(
                &scanner_weights::W1,
                &scanner_weights::B1,
                &scanner_weights::W2,
                scanner_weights::B2,
                &input,
            );
            let action = if mlp_score > scanner_weights::THRESHOLD {
                ScannerAction::Block
            } else {
                ScannerAction::Allow
            };
            EnsembleVerdict {
                action,
                score: mlp_score as f64,
                reason: "ensemble:mlp",
                path: EnsemblePath::Mlp,
            }
        }
    }
}

impl From<EnsembleVerdict> for ScannerVerdict {
    fn from(v: EnsembleVerdict) -> Self {
        ScannerVerdict {
            action: v.action,
            score: v.score,
            reason: v.reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_block_path() {
        // Tree: root splits on feature 7 (ua_category) at 0.75.
        // All zeros → ua_category normalized = 0.0 <= 0.75 → Block (node 1)
        let raw = [0.0f32; 12];
        let v = scanner_ensemble_predict(&raw);
        assert_eq!(v.action, ScannerAction::Block);
        assert_eq!(v.path, EnsemblePath::TreeBlock);
        assert_eq!(v.reason, "ensemble:tree_block");
    }

    #[test]
    fn test_tree_allow_path() {
        // Tree: root feature 7 > 0.75 → node 2, checks feature 3 (has_cookies) at 0.25.
        // raw[7] = 1.0 → normalized 1.0 > 0.75 → right.
        // raw[3] = 1.0 → normalized ~0.7 > 0.25 → right child node 6 → Allow leaf.
        let mut raw = [0.0f32; 12];
        raw[7] = 1.0; // ua_category = browser
        raw[3] = 1.0; // has_cookies = yes
        let v = scanner_ensemble_predict(&raw);
        assert_eq!(v.action, ScannerAction::Allow);
        assert_eq!(v.path, EnsemblePath::TreeAllow);
        assert_eq!(v.reason, "ensemble:tree_allow");
    }

    #[test]
    fn test_mlp_direct() {
        // Current tree has no Defer leaves, so test MLP inference directly.
        let input = [0.5f32; 12];
        let score = mlp_predict_32::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
        );
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_normalize_clamps() {
        // Values beyond max should be clamped to 1.0
        let mut raw = [0.0f32; 12];
        raw[0] = 100.0;
        let normed = normalize(&raw);
        assert!((normed[0] - 1.0).abs() < f64::EPSILON as f32);
    }

    #[test]
    fn test_normalize_negative_clamps() {
        let mut raw = [0.0f32; 12];
        raw[0] = -5.0; // min is 0.0
        let normed = normalize(&raw);
        assert!((normed[0] - 0.0).abs() < f64::EPSILON as f32);
    }

    #[test]
    fn test_verdict_into_scanner_verdict() {
        let v = EnsembleVerdict {
            action: ScannerAction::Block,
            score: 0.85,
            reason: "ensemble:mlp",
            path: EnsemblePath::Mlp,
        };
        let sv: ScannerVerdict = v.into();
        assert_eq!(sv.action, ScannerAction::Block);
        assert!((sv.score - 0.85).abs() < f64::EPSILON);
        assert_eq!(sv.reason, "ensemble:mlp");
    }
}
