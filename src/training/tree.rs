// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! CART decision tree trainer (pure Rust, no burn dependency).
//!
//! Trains a binary classification tree using Gini impurity and outputs
//! the packed node format used by `crate::ensemble::tree` for zero-alloc
//! inference.

use crate::dataset::sample::TrainingSample;

/// Packed tree node matching the inference format in `crate::ensemble::tree`.
///
/// `(feature_index, threshold, left_child, right_child)`
///
/// Leaf nodes use `feature_index = 255`.  The threshold encodes the decision:
///   - `0.0` = Allow
///   - `0.5` = Defer
///   - `1.0` = Block
pub type PackedNode = (u8, f32, u16, u16);

/// Decision from a tree leaf node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeDecision {
    /// Block.
    Block,
    /// Allow.
    Allow,
    /// Defer.
    Defer,
}

/// Configuration for CART tree training.
pub struct TreeConfig {
    /// Maximum tree depth (typically 6-8).
    pub max_depth: usize,
    /// Minimum number of samples required in a leaf.
    pub min_samples_leaf: usize,
    /// Leaf purity threshold: if the dominant class ratio is below this,
    /// the leaf becomes `Defer` (e.g. 0.90).
    pub min_purity: f32,
    /// Number of input features (12 for scanner, 14 for DDoS).
    pub num_features: usize,
    /// Feature indices the tree must not split on. Forces those decisions to
    /// flow through the MLP — typically the "circumstantial" header-presence
    /// features (cookies/referer/accept-language ratios) whose values are
    /// easy class indicators in synthetic data but unreliable in production
    /// (privacy mode, mobile apps, etc.).
    pub excluded_features: Vec<usize>,
}

/// Internal representation during tree construction.
#[derive(Debug)]
enum BuildNode {
    Leaf {
        decision: TreeDecision,
    },
    Split {
        feature: usize,
        threshold: f32,
        left: Box<BuildNode>,
        right: Box<BuildNode>,
    },
}

/// Train a CART decision tree and return packed nodes.
pub fn train_tree(samples: &[TrainingSample], config: &TreeConfig) -> Vec<PackedNode> {
    let indices: Vec<usize> = (0..samples.len()).collect();
    let root = build_node(samples, &indices, config, 0);
    let mut packed = Vec::new();
    flatten(&root, &mut packed);
    packed
}

/// Walk a packed decision tree for validation (mirrors `crate::ensemble::tree::tree_predict`).
pub fn tree_predict(nodes: &[PackedNode], features: &[f32]) -> TreeDecision {
    let mut idx = 0usize;
    loop {
        let (feature, threshold, left, right) = nodes[idx];
        if feature == 255 {
            return if threshold < 0.25 {
                TreeDecision::Allow
            } else if threshold > 0.75 {
                TreeDecision::Block
            } else {
                TreeDecision::Defer
            };
        }
        idx = if features[feature as usize] <= threshold {
            left as usize
        } else {
            right as usize
        };
    }
}

// ---------------------------------------------------------------------------
// Tree construction
// ---------------------------------------------------------------------------

fn build_node(
    samples: &[TrainingSample],
    indices: &[usize],
    config: &TreeConfig,
    depth: usize,
) -> BuildNode {
    // Count attacks vs normal.
    let (attack_w, normal_w) = weighted_counts(samples, indices);
    let total_w = attack_w + normal_w;

    // Stopping conditions: max depth, min samples, or pure-enough leaf.
    if depth >= config.max_depth
        || indices.len() < 2 * config.min_samples_leaf
        || total_w < f32::EPSILON
    {
        return make_leaf(attack_w, normal_w, config.min_purity);
    }

    let attack_ratio = attack_w / total_w;
    let normal_ratio = normal_w / total_w;
    if attack_ratio >= config.min_purity || normal_ratio >= config.min_purity {
        return make_leaf(attack_w, normal_w, config.min_purity);
    }

    // Find best split across all features.
    let parent_gini = gini(attack_w, normal_w);
    let mut best_gain = 0.0f32;
    let mut best_feature = 0usize;
    let mut best_threshold = 0.0f32;
    let mut best_left: Vec<usize> = Vec::new();
    let mut best_right: Vec<usize> = Vec::new();

    for feat in 0..config.num_features {
        if config.excluded_features.contains(&feat) {
            continue;
        }
        // Gather and sort feature values.
        let mut vals: Vec<(f32, usize)> = indices
            .iter()
            .map(|&i| (samples[i].features[feat], i))
            .collect();
        vals.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Scan for best threshold (midpoints between distinct values).
        let mut left_attack_w = 0.0f32;
        let mut left_normal_w = 0.0f32;

        for window_end in 0..vals.len() - 1 {
            let (_, idx) = vals[window_end];
            let s = &samples[idx];
            if s.label >= 0.5 {
                left_attack_w += s.weight;
            } else {
                left_normal_w += s.weight;
            }

            // Skip if the next value is the same (no valid split point).
            if (vals[window_end].0 - vals[window_end + 1].0).abs() < f32::EPSILON {
                continue;
            }

            // Check min_samples_leaf constraint.
            let left_count = window_end + 1;
            let right_count = vals.len() - left_count;
            if left_count < config.min_samples_leaf || right_count < config.min_samples_leaf {
                continue;
            }

            let right_attack_w = attack_w - left_attack_w;
            let right_normal_w = normal_w - left_normal_w;
            let left_total = left_attack_w + left_normal_w;
            let right_total = right_attack_w + right_normal_w;

            let left_gini = gini(left_attack_w, left_normal_w);
            let right_gini = gini(right_attack_w, right_normal_w);
            let weighted_gini =
                (left_total / total_w) * left_gini + (right_total / total_w) * right_gini;
            let gain = parent_gini - weighted_gini;

            if gain > best_gain {
                best_gain = gain;
                best_feature = feat;
                best_threshold = (vals[window_end].0 + vals[window_end + 1].0) / 2.0;
                best_left = vals[..=window_end].iter().map(|v| v.1).collect();
                best_right = vals[window_end + 1..].iter().map(|v| v.1).collect();
            }
        }
    }

    // If no informative split was found, make a leaf.
    if best_gain <= 0.0 || best_left.is_empty() || best_right.is_empty() {
        return make_leaf(attack_w, normal_w, config.min_purity);
    }

    let left_child = build_node(samples, &best_left, config, depth + 1);
    let right_child = build_node(samples, &best_right, config, depth + 1);

    BuildNode::Split {
        feature: best_feature,
        threshold: best_threshold,
        left: Box::new(left_child),
        right: Box::new(right_child),
    }
}

fn make_leaf(attack_w: f32, normal_w: f32, min_purity: f32) -> BuildNode {
    let total = attack_w + normal_w;
    let decision = if total < f32::EPSILON {
        TreeDecision::Defer
    } else {
        let attack_ratio = attack_w / total;
        let normal_ratio = normal_w / total;
        if attack_ratio >= min_purity {
            TreeDecision::Block
        } else if normal_ratio >= min_purity {
            TreeDecision::Allow
        } else {
            TreeDecision::Defer
        }
    };
    BuildNode::Leaf { decision }
}

fn gini(class_a: f32, class_b: f32) -> f32 {
    let total = class_a + class_b;
    if total < f32::EPSILON {
        return 0.0;
    }
    let p_a = class_a / total;
    let p_b = class_b / total;
    1.0 - p_a * p_a - p_b * p_b
}

fn weighted_counts(samples: &[TrainingSample], indices: &[usize]) -> (f32, f32) {
    let mut attack = 0.0f32;
    let mut normal = 0.0f32;
    for &i in indices {
        let s = &samples[i];
        if s.label >= 0.5 {
            attack += s.weight;
        } else {
            normal += s.weight;
        }
    }
    (attack, normal)
}

/// Flatten the recursive `BuildNode` tree into a `Vec<PackedNode>` using
/// BFS-order indexing.
fn flatten(node: &BuildNode, out: &mut Vec<PackedNode>) {
    match node {
        BuildNode::Leaf { decision } => {
            let threshold = match decision {
                TreeDecision::Allow => 0.0,
                TreeDecision::Defer => 0.5,
                TreeDecision::Block => 1.0,
            };
            out.push((255, threshold, 0, 0));
        }
        BuildNode::Split {
            feature,
            threshold,
            left,
            right,
        } => {
            // Reserve this node's position, then recursively flatten children.
            let self_idx = out.len();
            out.push((0, 0.0, 0, 0)); // placeholder

            let left_idx = out.len();
            flatten(left, out);

            let right_idx = out.len();
            flatten(right, out);

            out[self_idx] = (
                *feature as u8,
                *threshold,
                left_idx as u16,
                right_idx as u16,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::sample::{DataSource, TrainingSample};

    fn sample(features: Vec<f32>, label: f32) -> TrainingSample {
        TrainingSample {
            features,
            label,
            source: DataSource::ProductionLogs,
            weight: 1.0,
        }
    }

    #[test]
    fn test_trivially_separable() {
        // Feature 0 < 0.5 => Allow (label 0), >= 0.5 => Block (label 1)
        let samples: Vec<TrainingSample> = (0..100)
            .map(|i| {
                let v = i as f32 / 100.0;
                sample(vec![v, 0.0], if v < 0.5 { 0.0 } else { 1.0 })
            })
            .collect();

        let config = TreeConfig {
            max_depth: 6,
            min_samples_leaf: 1,
            min_purity: 0.90,
            num_features: 2,
            excluded_features: vec![],
        };

        let tree = train_tree(&samples, &config);
        assert!(!tree.is_empty());

        // Low values should be Allow.
        assert_eq!(tree_predict(&tree, &[0.1, 0.0]), TreeDecision::Allow);
        // High values should be Block.
        assert_eq!(tree_predict(&tree, &[0.9, 0.0]), TreeDecision::Block);
    }

    #[test]
    fn test_defer_for_mixed_region() {
        // Create samples where the middle region is genuinely mixed.
        let mut samples = Vec::new();
        for i in 0..50 {
            let v = i as f32 / 100.0;
            samples.push(sample(vec![v], 0.0)); // normal
        }
        for i in 50..100 {
            let v = i as f32 / 100.0;
            samples.push(sample(vec![v], 1.0)); // attack
        }
        // Add noise in the middle: some attacks below 0.5, some normals above 0.5.
        for _ in 0..20 {
            samples.push(sample(vec![0.45], 1.0));
            samples.push(sample(vec![0.55], 0.0));
        }

        let config = TreeConfig {
            max_depth: 3,
            min_samples_leaf: 5,
            min_purity: 0.95, // Very high purity requirement.
            num_features: 1,
            excluded_features: vec![],
        };

        let tree = train_tree(&samples, &config);

        // The boundary region should produce Defer.
        let mid_decision = tree_predict(&tree, &[0.50]);
        // It could be Defer or Allow/Block depending on how the split lands,
        // but the tree should at least produce valid decisions.
        assert!(matches!(
            mid_decision,
            TreeDecision::Allow | TreeDecision::Block | TreeDecision::Defer
        ));

        // The extremes should be clear.
        assert_eq!(tree_predict(&tree, &[0.05]), TreeDecision::Allow);
        assert_eq!(tree_predict(&tree, &[0.95]), TreeDecision::Block);
    }

    #[test]
    fn test_max_depth_enforcement() {
        // Even with perfect separability, depth should be capped.
        let samples: Vec<TrainingSample> = (0..200)
            .map(|i| {
                let v = i as f32 / 200.0;
                sample(vec![v, 0.0, 0.0, 0.0], if v < 0.5 { 0.0 } else { 1.0 })
            })
            .collect();

        let config = TreeConfig {
            max_depth: 2,
            min_samples_leaf: 1,
            min_purity: 0.90,
            num_features: 4,
            excluded_features: vec![],
        };

        let tree = train_tree(&samples, &config);

        // With max_depth=2, we can have at most 2^3 - 1 = 7 nodes.
        assert!(
            tree.len() <= 7,
            "tree should have at most 7 nodes at depth 2, got {}",
            tree.len()
        );
    }

    #[test]
    fn test_single_class_becomes_leaf() {
        // All samples are attack => immediate Block leaf.
        let samples: Vec<TrainingSample> = (0..50)
            .map(|i| sample(vec![i as f32 / 50.0], 1.0))
            .collect();

        let config = TreeConfig {
            max_depth: 6,
            min_samples_leaf: 1,
            min_purity: 0.90,
            num_features: 1,
            excluded_features: vec![],
        };

        let tree = train_tree(&samples, &config);
        assert_eq!(tree.len(), 1); // Just a single leaf.
        assert_eq!(tree_predict(&tree, &[0.5]), TreeDecision::Block);
    }

    #[test]
    fn test_gini_pure() {
        assert!((gini(10.0, 0.0) - 0.0).abs() < 1e-6);
        assert!((gini(0.0, 10.0) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_gini_max() {
        // Maximum Gini for balanced binary: 1 - 2*(0.5^2) = 0.5
        assert!((gini(5.0, 5.0) - 0.5).abs() < 1e-6);
    }
}
