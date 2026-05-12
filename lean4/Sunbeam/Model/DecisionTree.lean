import Sunbeam.Model.Basic

open Classical

namespace Sunbeam

/-- A decision tree node (inductive = automatic termination for structural recursion).

This is an abstract specification of the Rust packed-array representation:
  `type PackedNode = (u8, f32, u16, u16)` — `(feature_index, threshold, left, right)`
Leaf nodes in Rust use `feature_index = 255`; the threshold encodes the decision:
  `< 0.25` → Allow, `> 0.75` → Block, otherwise → Defer.
Here we use an inductive type so that structural recursion gives automatic termination. -/
inductive TreeNode where
  | leaf (decision : Decision) : TreeNode
  | split (featureIdx : Nat) (threshold : ℝ) (left right : TreeNode) : TreeNode

/-- Tree prediction by structural recursion (termination is automatic).

Corresponds to `ensemble::tree::tree_predict` in Rust, which loops over a flat
packed-node array. The semantic behavior is identical: split nodes compare
`input[featureIdx]` against `threshold` and branch left/right. -/
noncomputable def treePredictAux {n : Nat} (input : Fin n → ℝ) : TreeNode → Decision
  | .leaf d => d
  | .split idx thr left right =>
    if h : idx < n then
      if input ⟨idx, h⟩ ≤ thr then
        treePredictAux input left
      else
        treePredictAux input right
    else
      Decision.defer

end Sunbeam
