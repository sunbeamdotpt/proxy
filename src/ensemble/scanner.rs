use crate::scanner::model::{ScannerAction, ScannerVerdict};
use super::gen::scanner_weights;
use super::mlp::mlp_predict_32;
use super::tree::{tree_predict, TreeDecision};

/// Which path the ensemble took to reach its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsemblePath {
    TreeBlock,
    TreeAllow,
    Mlp,
}

/// Result of the scanner ensemble: action + confidence score + explanation.
pub struct EnsembleVerdict {
    pub action: ScannerAction,
    pub score: f64,
    pub reason: &'static str,
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
    fn test_tree_allow_path() {
        // All features at zero → feature 3 (suspicious_ua) = 0.0 <= 0.65 → left (node 1)
        // feature 0 (path_depth) = 0.0 <= 0.40 → left (node 3) → Allow leaf
        let raw = [0.0f32; 12];
        let v = scanner_ensemble_predict(&raw);
        assert_eq!(v.action, ScannerAction::Allow);
        assert_eq!(v.path, EnsemblePath::TreeAllow);
        assert_eq!(v.reason, "ensemble:tree_allow");
        assert!((v.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_tree_block_path() {
        // Need: feature 3 (suspicious_ua) > 0.65 (normalized) → right (node 2)
        //   feature 7 (payload_entropy) > 0.72 (normalized) → right (node 6) → Block
        // feature 3 max = 1.0, so raw 0.8 → normalized 0.8 > 0.65 ✓
        // feature 7 max = 8.0, so raw 6.0 → normalized 0.75 > 0.72 ✓
        let mut raw = [0.0f32; 12];
        raw[3] = 0.8;  // suspicious_ua: normalized = 0.8/1.0 = 0.8 > 0.65
        raw[7] = 6.0;  // payload_entropy: normalized = 6.0/8.0 = 0.75 > 0.72
        let v = scanner_ensemble_predict(&raw);
        assert_eq!(v.action, ScannerAction::Block);
        assert_eq!(v.path, EnsemblePath::TreeBlock);
        assert_eq!(v.reason, "ensemble:tree_block");
    }

    #[test]
    fn test_mlp_path() {
        // Need: feature 3 > 0.65 normalized → right (node 2)
        //   feature 7 <= 0.72 normalized → left (node 5) → Defer
        // Then MLP runs on the normalized input.
        let mut raw = [0.0f32; 12];
        raw[3] = 0.8;  // normalized = 0.8 > 0.65
        raw[7] = 4.0;  // normalized = 4.0/8.0 = 0.5 <= 0.72
        // Also need feature 2 (query_param_count) to navigate node 5 correctly
        // node 5: split on feature 2, threshold 0.55 → left=9(Defer), right=10
        // normalized feature 2 = 0.0/20.0 = 0.0 <= 0.55 → left (node 9) → Defer
        let v = scanner_ensemble_predict(&raw);
        assert_eq!(v.path, EnsemblePath::Mlp);
        assert_eq!(v.reason, "ensemble:mlp");
        // MLP output is deterministic for these inputs
        assert!(v.score >= 0.0 && v.score <= 1.0);
    }

    #[test]
    fn test_normalize_clamps() {
        // Values beyond max should be clamped to 1.0
        let mut raw = [0.0f32; 12];
        raw[0] = 100.0; // max is 10.0
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
