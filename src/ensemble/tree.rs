// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Decision from a tree leaf node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeDecision {
    /// High-confidence block — overrides MLP.
    Block,
    /// High-confidence allow — overrides MLP.
    Allow,
    /// Low-confidence — defer to MLP for scoring.
    Defer,
}

/// Packed tree node: `(feature_index, threshold, left_child, right_child)`.
///
/// Leaf nodes are encoded with `feature_index = 255`.
/// For leaves the threshold encodes the decision:
///   - `< 0.25`  → Allow
///   - `> 0.75`  → Block
///   - otherwise → Defer
pub type PackedNode = (u8, f32, u16, u16);

/// Walk a packed decision tree.  O(depth), zero allocation.
#[inline(always)]
pub fn tree_predict(nodes: &[PackedNode], input: &[f32]) -> TreeDecision {
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
        idx = if input[feature as usize] <= threshold {
            left as usize
        } else {
            right as usize
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple tree:
    //   node 0: feature 0, threshold 0.5 → left=1, right=2
    //   node 1: leaf Allow  (threshold 0.0)
    //   node 2: leaf Block  (threshold 1.0)
    const SIMPLE_TREE: [PackedNode; 3] = [
        (0, 0.5, 1, 2),
        (255, 0.0, 0, 0), // Allow
        (255, 1.0, 0, 0), // Block
    ];

    #[test]
    fn test_tree_allow() {
        let input = [0.3]; // <= 0.5 → left → Allow
        assert_eq!(tree_predict(&SIMPLE_TREE, &input), TreeDecision::Allow);
    }

    #[test]
    fn test_tree_block() {
        let input = [0.8]; // > 0.5 → right → Block
        assert_eq!(tree_predict(&SIMPLE_TREE, &input), TreeDecision::Block);
    }

    #[test]
    fn test_tree_defer() {
        // Tree with a Defer leaf
        let tree: [PackedNode; 2] = [
            (0, 0.5, 1, 1),
            (255, 0.5, 0, 0), // Defer
        ];
        let input = [0.3];
        assert_eq!(tree_predict(&tree, &input), TreeDecision::Defer);
    }

    #[test]
    fn test_tree_boundary_allow() {
        // threshold exactly 0.25 is NOT < 0.25, so it should Defer
        let tree: [PackedNode; 1] = [(255, 0.25, 0, 0)];
        assert_eq!(tree_predict(&tree, &[]), TreeDecision::Defer);
    }

    #[test]
    fn test_tree_boundary_block() {
        // threshold exactly 0.75 is NOT > 0.75, so it should Defer
        let tree: [PackedNode; 1] = [(255, 0.75, 0, 0)];
        assert_eq!(tree_predict(&tree, &[]), TreeDecision::Defer);
    }

    #[test]
    fn test_deeper_tree() {
        // Depth-3 tree with 4 features
        let tree: [PackedNode; 7] = [
            (0, 0.5, 1, 2),   // root: feature 0
            (1, 0.3, 3, 4),   // left: feature 1
            (2, 0.7, 5, 6),   // right: feature 2
            (255, 0.0, 0, 0), // Allow
            (255, 0.5, 0, 0), // Defer
            (255, 1.0, 0, 0), // Block
            (255, 0.0, 0, 0), // Allow
        ];
        // feature 0=0.2 (<=0.5→left=1), feature 1=0.1 (<=0.3→left=3) → Allow
        assert_eq!(
            tree_predict(&tree, &[0.2, 0.1, 0.0, 0.0]),
            TreeDecision::Allow
        );
        // feature 0=0.2 (<=0.5→left=1), feature 1=0.5 (>0.3→right=4) → Defer
        assert_eq!(
            tree_predict(&tree, &[0.2, 0.5, 0.0, 0.0]),
            TreeDecision::Defer
        );
        // feature 0=0.8 (>0.5→right=2), feature 2=0.3 (<=0.7→left=5) → Block
        assert_eq!(
            tree_predict(&tree, &[0.8, 0.0, 0.3, 0.0]),
            TreeDecision::Block
        );
        // feature 0=0.8 (>0.5→right=2), feature 2=0.9 (>0.7→right=6) → Allow
        assert_eq!(
            tree_predict(&tree, &[0.8, 0.0, 0.9, 0.0]),
            TreeDecision::Allow
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Generate a valid packed tree (complete binary tree of given depth).
    /// All internal nodes split on feature 0 at threshold 0.5.
    /// Leaves cycle through Allow/Block/Defer.
    fn make_complete_tree(depth: u32) -> Vec<PackedNode> {
        let num_nodes = (1u32 << (depth + 1)) - 1;
        let num_internal = (1u32 << depth) - 1;
        let mut nodes = Vec::with_capacity(num_nodes as usize);
        let decisions = [0.0f32, 1.0, 0.5]; // Allow, Block, Defer
        for i in 0..num_nodes {
            if i < num_internal {
                let left = 2 * i + 1;
                let right = 2 * i + 2;
                nodes.push((0u8, 0.5f32, left as u16, right as u16));
            } else {
                let leaf_idx = (i - num_internal) as usize;
                nodes.push((255u8, decisions[leaf_idx % 3], 0u16, 0u16));
            }
        }
        nodes
    }

    proptest! {
        #[test]
        fn tree_always_terminates(val in 0.0f32..1.0, depth in 0u32..5) {
            let tree = make_complete_tree(depth);
            let input = [val; 16]; // enough features for any tree
            let result = tree_predict(&tree, &input);
            prop_assert!(matches!(
                result,
                TreeDecision::Allow | TreeDecision::Block | TreeDecision::Defer
            ));
        }
    }
}
