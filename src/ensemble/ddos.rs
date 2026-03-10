// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::ddos::model::DDoSAction;
use super::gen::ddos_weights;
use super::mlp::mlp_predict_32;
use super::tree::{tree_predict, TreeDecision};

/// Which path the DDoS ensemble took to reach its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DDoSEnsemblePath {
    TreeBlock,
    TreeAllow,
    Mlp,
}

/// Result of the DDoS ensemble inference.
pub struct DDoSEnsembleVerdict {
    pub action: DDoSAction,
    pub score: f64,
    pub reason: &'static str,
    pub path: DDoSEnsemblePath,
}

/// Normalize raw features using trained min/max constants.
#[inline]
fn normalize(raw: &[f32; 14]) -> [f32; 14] {
    let mut out = [0.0f32; 14];
    for i in 0..14 {
        let range = ddos_weights::NORM_MAXS[i] - ddos_weights::NORM_MINS[i];
        out[i] = if range > 0.0 {
            ((raw[i] - ddos_weights::NORM_MINS[i]) / range).clamp(0.0, 1.0)
        } else {
            0.0
        };
    }
    out
}

/// Full DDoS ensemble inference: decision tree first, MLP only on `Defer`.
pub fn ddos_ensemble_predict(raw: &[f32; 14]) -> DDoSEnsembleVerdict {
    let input = normalize(raw);

    let tree_result = tree_predict(&ddos_weights::TREE_NODES, &input);
    match tree_result {
        TreeDecision::Block => DDoSEnsembleVerdict {
            action: DDoSAction::Block,
            score: 1.0,
            reason: "ensemble:tree_block",
            path: DDoSEnsemblePath::TreeBlock,
        },
        TreeDecision::Allow => DDoSEnsembleVerdict {
            action: DDoSAction::Allow,
            score: 0.0,
            reason: "ensemble:tree_allow",
            path: DDoSEnsemblePath::TreeAllow,
        },
        TreeDecision::Defer => {
            let mlp_score = mlp_predict_32::<14>(
                &ddos_weights::W1,
                &ddos_weights::B1,
                &ddos_weights::W2,
                ddos_weights::B2,
                &input,
            );
            let action = if mlp_score > ddos_weights::THRESHOLD {
                DDoSAction::Block
            } else {
                DDoSAction::Allow
            };
            DDoSEnsembleVerdict {
                action,
                score: mlp_score as f64,
                reason: "ensemble:mlp",
                path: DDoSEnsemblePath::Mlp,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_block_path() {
        // Tree: root splits on feature 10 (cookie_ratio) at 0.14.
        // All zeros → cookie_ratio normalized = 0.0 <= 0.14 → Block (node 1)
        let raw = [0.0f32; 14];
        let v = ddos_ensemble_predict(&raw);
        assert_eq!(v.action, DDoSAction::Block);
        assert_eq!(v.path, DDoSEnsemblePath::TreeBlock);
    }

    #[test]
    fn test_tree_allow_path() {
        // Tree: feature 10 (cookie_ratio) > 0.14 → node 2 (Allow leaf)
        // feature 10 range [0, 1], raw 0.5 → normalized 0.5 > 0.14 → Allow
        let mut raw = [0.0f32; 14];
        raw[10] = 0.5;
        let v = ddos_ensemble_predict(&raw);
        assert_eq!(v.action, DDoSAction::Allow);
        assert_eq!(v.path, DDoSEnsemblePath::TreeAllow);
        assert_eq!(v.reason, "ensemble:tree_allow");
    }

    #[test]
    fn test_mlp_direct() {
        // Current tree has no Defer leaves, so test MLP inference directly.
        let input = [0.5f32; 14];
        let score = mlp_predict_32::<14>(
            &ddos_weights::W1,
            &ddos_weights::B1,
            &ddos_weights::W2,
            ddos_weights::B2,
            &input,
        );
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_normalize_clamps_high() {
        // feature 0 max = 10000.0, raw 999999 → clamped to 1.0
        let mut raw = [0.0f32; 14];
        raw[0] = 999999.0;
        let normed = normalize(&raw);
        assert!((normed[0] - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_normalize_clamps_low() {
        let mut raw = [0.0f32; 14];
        raw[1] = -500.0; // min is 1.0
        let normed = normalize(&raw);
        assert!((normed[1] - 0.0).abs() < f32::EPSILON);
    }
}
