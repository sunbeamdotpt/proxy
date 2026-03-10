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
    fn test_tree_allow_path() {
        // All zeros → feature 4 (request_rate) = 0.0 <= 0.70 → left (node 1)
        //   feature 10 (cookie_ratio) = 0.0 <= 0.30 → left (node 3) → Allow
        let raw = [0.0f32; 14];
        let v = ddos_ensemble_predict(&raw);
        assert_eq!(v.action, DDoSAction::Allow);
        assert_eq!(v.path, DDoSEnsemblePath::TreeAllow);
        assert_eq!(v.reason, "ensemble:tree_allow");
    }

    #[test]
    fn test_tree_block_path() {
        // Need: feature 4 (request_rate) > 0.70 normalized → right (node 2)
        //   feature 12 (accept_language_ratio) > 0.25 normalized → right (node 6) → Block
        // feature 4 max = 500, so raw 400 → normalized 0.8 > 0.70 ✓
        // feature 12 max = 1.0, so raw 0.5 → normalized 0.5 > 0.25 ✓
        let mut raw = [0.0f32; 14];
        raw[4] = 400.0;
        raw[12] = 0.5;
        let v = ddos_ensemble_predict(&raw);
        assert_eq!(v.action, DDoSAction::Block);
        assert_eq!(v.path, DDoSEnsemblePath::TreeBlock);
    }

    #[test]
    fn test_mlp_path() {
        // Need: feature 4 > 0.70 normalized → right (node 2)
        //   feature 12 <= 0.25 normalized → left (node 5) → Defer
        // feature 4 max = 500, raw 400 → 0.8 > 0.70 ✓
        // feature 12 max = 1.0, raw 0.1 → 0.1 <= 0.25 ✓
        let mut raw = [0.0f32; 14];
        raw[4] = 400.0;
        raw[12] = 0.1;
        let v = ddos_ensemble_predict(&raw);
        assert_eq!(v.path, DDoSEnsemblePath::Mlp);
        assert_eq!(v.reason, "ensemble:mlp");
        assert!(v.score >= 0.0 && v.score <= 1.0);
    }

    #[test]
    fn test_defer_then_mlp_allow() {
        // Same Defer path as above — verify the MLP produces a valid action
        let mut raw = [0.0f32; 14];
        raw[4] = 400.0;
        raw[12] = 0.1;
        let v = ddos_ensemble_predict(&raw);
        assert!(matches!(v.action, DDoSAction::Allow | DDoSAction::Block));
    }

    #[test]
    fn test_normalize_clamps_high() {
        let mut raw = [0.0f32; 14];
        raw[0] = 999.0; // max is 100
        let normed = normalize(&raw);
        assert!((normed[0] - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_normalize_clamps_low() {
        let mut raw = [0.0f32; 14];
        raw[1] = -500.0; // min is 0
        let normed = normalize(&raw);
        assert!((normed[1] - 0.0).abs() < f32::EPSILON);
    }
}
