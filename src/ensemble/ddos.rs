// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! DDoS ensemble inference: MLP-only.
//!
//! The shipped tree was a single-feature classifier in practice (never
//! deferred to the MLP), so the tree path is no longer wired into the
//! verdict pipeline. Every request flows through `mlp_predict_32`, which is
//! the model that carries the CROWN / Interval32 IBP soundness story.

use crate::ddos::model::DDoSAction;
use super::gen::ddos_weights;
use super::mlp::mlp_predict_32;

/// Which path the DDoS ensemble took to reach its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DDoSEnsemblePath {
    /// MLP forward pass.
    Mlp,
}

/// Result of the DDoS ensemble inference.
pub struct DDoSEnsembleVerdict {
    /// Action.
    pub action: DDoSAction,
    /// Score.
    pub score: f64,
    /// Reason.
    pub reason: &'static str,
    /// Path.
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

/// Full DDoS ensemble inference: MLP forward + threshold.
pub fn ddos_ensemble_predict(raw: &[f32; 14]) -> DDoSEnsembleVerdict {
    let input = normalize(raw);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mlp_path_is_only_path() {
        let input = [0.5f32; 14];
        let v = ddos_ensemble_predict(&input);
        assert_eq!(v.path, DDoSEnsemblePath::Mlp);
        assert_eq!(v.reason, "ensemble:mlp");
    }

    #[test]
    fn mlp_score_in_unit_interval() {
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
        let mut raw = [0.0f32; 14];
        raw[0] = 999999.0;
        let normed = normalize(&raw);
        assert!((normed[0] - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_normalize_clamps_low() {
        let mut raw = [0.0f32; 14];
        raw[1] = -500.0;
        let normed = normalize(&raw);
        assert!((normed[1] - 0.0).abs() < f32::EPSILON);
    }
}
