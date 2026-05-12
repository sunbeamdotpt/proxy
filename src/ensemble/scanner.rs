// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Scanner ensemble inference: MLP-only.
//!
//! The shipped tree was a single-feature classifier in practice (never
//! deferred to the MLP), so the tree path is no longer wired into the
//! verdict pipeline. Every request flows through `mlp_predict_32`, which is
//! the model that carries the CROWN / Interval32 IBP soundness story.
//!
//! `EnsemblePath::Mlp` is the only path retained for downstream telemetry
//! that expected the enum.

use crate::scanner::model::{ScannerAction, ScannerVerdict};
use super::gen::scanner_weights;
use super::mlp::mlp_predict_32;

/// Which path the ensemble took to reach its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsemblePath {
    /// MLP forward pass.
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

/// Full ensemble inference: MLP forward + threshold.
pub fn scanner_ensemble_predict(raw: &[f32; 12]) -> EnsembleVerdict {
    let input = normalize(raw);
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
    fn mlp_path_is_only_path() {
        let input = [0.5f32; 12];
        let v = scanner_ensemble_predict(&input);
        assert_eq!(v.path, EnsemblePath::Mlp);
        assert_eq!(v.reason, "ensemble:mlp");
    }

    #[test]
    fn mlp_score_in_unit_interval() {
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
        let mut raw = [0.0f32; 12];
        raw[0] = 100.0;
        let normed = normalize(&raw);
        assert!((normed[0] - 1.0).abs() < f64::EPSILON as f32);
    }

    #[test]
    fn test_normalize_negative_clamps() {
        let mut raw = [0.0f32; 12];
        raw[0] = -5.0;
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
