import Mathlib.Algebra.BigOperators.Fin
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP
import Sunbeam.Model.DecisionTree
import Sunbeam.Model.Ensemble

namespace Sunbeam.Verify

open Sunbeam Classical

/-! # Tier 2: Shape properties (depend on weight sign constraints, not values)

This file proves *monotonicity* of the ensemble in designated input features.
Unlike Tier 1 (which is weight-independent), Tier 2 theorems are conditional
on a structural property of the trained weights: a sign-alignment constraint
on a single feature column.

The key shape claim: if the trained MLP weights satisfy a per-neuron sign
constraint with respect to feature `i`, the ensemble can never be evaded by
*increasing* that feature. Concretely:

- `mlp_forward_monotone_in`: trained MLP is monotone non-decreasing in feature
  `i` whenever every hidden neuron satisfies `w2[j] * w1[j][i] ≥ 0`.
- `ensemble_block_preserved_when_tree_constant`: if the tree's verdict does
  not depend on feature `i` (e.g. `i` is not a tree split feature), and the
  MLP is monotone in `i`, then increasing `i` never flips a Block to Allow.

Together these factor the ensemble's shape guarantee into a tree-side condition
(audit: which features does the tree split on?) and an MLP-side condition
(audit: do the trained weights satisfy the sign constraint?).
-/

/-- Two input vectors agree everywhere except possibly at coordinate `i`. -/
def AgreeOff {n : Nat} (i : Fin n) (x y : RealVec n) : Prop :=
  ∀ k, k ≠ i → x k = y k

/-! ## Linearity of the dot product under single-coordinate change -/

/-- If `x` and `y` agree off `i`, then `dot a y = dot a x + a i * (y i - x i)`. -/
lemma dot_agree_off {n : Nat} (a : RealVec n) {x y : RealVec n} (i : Fin n)
    (h_eq : AgreeOff i x y) :
    dot a y = dot a x + a i * (y i - x i) := by
  unfold dot
  have hsum : (∑ k : Fin n, a k * y k) - (∑ k : Fin n, a k * x k)
            = a i * (y i - x i) := by
    rw [← Finset.sum_sub_distrib]
    rw [Finset.sum_eq_single i]
    · ring
    · intro k _ hki
      have : x k = y k := h_eq k hki
      rw [this]; ring
    · intro h
      exact absurd (Finset.mem_univ i) h
  linarith

/-- Specialization to the linear layer: the j-th pre-activation differs by a
single multiple of `w1[j][i]` when only coordinate `i` changes. -/
lemma matVecMul_agree_off {inputDim hiddenDim : Nat}
    (mat : Fin hiddenDim → RealVec inputDim)
    {x y : RealVec inputDim} (i : Fin inputDim)
    (h_eq : AgreeOff i x y) (j : Fin hiddenDim) :
    matVecMul mat y j = matVecMul mat x j + mat j i * (y i - x i) := by
  unfold matVecMul
  exact dot_agree_off (mat j) i h_eq

/-! ## Per-neuron contribution monotonicity under sign constraint -/

/-- The j-th hidden contribution `w2[j] * relu((W1·x + b1)[j])` is non-decreasing
in `x[i]` whenever the sign constraint `0 ≤ w2[j] * w1[j][i]` holds.

The proof case-splits on the sign of `w1[j][i]`:
- If `w1[j][i] ≥ 0` then the pre-activation goes up, ReLU goes up, and
  `w2[j] ≥ 0` (forced by the sign constraint) preserves the order under
  multiplication.
- If `w1[j][i] < 0` then the pre-activation goes down, ReLU goes down, and
  `w2[j] ≤ 0` (forced by the sign constraint) flips the order back. -/
lemma per_neuron_mono {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim)
    (j : Fin hiddenDim) (i : Fin inputDim)
    (h_sign : 0 ≤ weights.w2 j * weights.w1 j i)
    {x y : RealVec inputDim}
    (h_eq : AgreeOff i x y) (h_le : x i ≤ y i) :
    weights.w2 j * relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
  ≤ weights.w2 j * relu (vecAdd (matVecMul weights.w1 y) weights.b1 j) := by
  -- Let `preX := (W1·x + b1)[j]`, `preY := (W1·y + b1)[j]`.
  -- Then `preY = preX + w1[j][i] * (y[i] - x[i])`.
  have h_pre_diff : vecAdd (matVecMul weights.w1 y) weights.b1 j
                  = vecAdd (matVecMul weights.w1 x) weights.b1 j
                    + weights.w1 j i * (y i - x i) := by
    unfold vecAdd
    have hmv := matVecMul_agree_off weights.w1 i h_eq j
    linarith
  have h_diff_nonneg : 0 ≤ y i - x i := by linarith
  by_cases hw1 : 0 ≤ weights.w1 j i
  · -- w1[j][i] ≥ 0: preY ≥ preX, relu preY ≥ relu preX.
    have h_pre_le : vecAdd (matVecMul weights.w1 x) weights.b1 j
                  ≤ vecAdd (matVecMul weights.w1 y) weights.b1 j := by
      rw [h_pre_diff]
      have : 0 ≤ weights.w1 j i * (y i - x i) := mul_nonneg hw1 h_diff_nonneg
      linarith
    have h_relu_le : relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
                   ≤ relu (vecAdd (matVecMul weights.w1 y) weights.b1 j) :=
      relu_monotone h_pre_le
    by_cases hw1pos : 0 < weights.w1 j i
    · -- w1[j][i] > 0 strictly: sign constraint forces w2[j] ≥ 0.
      have hw2 : 0 ≤ weights.w2 j := by
        by_contra hneg
        push_neg at hneg
        have : weights.w2 j * weights.w1 j i < 0 :=
          mul_neg_of_neg_of_pos hneg hw1pos
        linarith
      exact mul_le_mul_of_nonneg_left h_relu_le hw2
    · -- w1[j][i] = 0: pre-activations equal, hence relu equal.
      have hw1z : weights.w1 j i = 0 := le_antisymm (not_lt.mp hw1pos) hw1
      have h_pre_eq : vecAdd (matVecMul weights.w1 x) weights.b1 j
                    = vecAdd (matVecMul weights.w1 y) weights.b1 j := by
        rw [h_pre_diff, hw1z]; ring
      rw [h_pre_eq]
  · -- w1[j][i] < 0: preY ≤ preX, relu preY ≤ relu preX.
    push_neg at hw1
    have hw1_le_zero : weights.w1 j i ≤ 0 := le_of_lt hw1
    have h_pre_ge : vecAdd (matVecMul weights.w1 y) weights.b1 j
                  ≤ vecAdd (matVecMul weights.w1 x) weights.b1 j := by
      rw [h_pre_diff]
      have : weights.w1 j i * (y i - x i) ≤ 0 :=
        mul_nonpos_of_nonpos_of_nonneg hw1_le_zero h_diff_nonneg
      linarith
    have h_relu_ge : relu (vecAdd (matVecMul weights.w1 y) weights.b1 j)
                   ≤ relu (vecAdd (matVecMul weights.w1 x) weights.b1 j) :=
      relu_monotone h_pre_ge
    -- Sign constraint forces w2[j] ≤ 0.
    have hw2 : weights.w2 j ≤ 0 := by
      by_contra hpos
      push_neg at hpos
      have : weights.w2 j * weights.w1 j i < 0 := mul_neg_of_pos_of_neg hpos hw1
      linarith
    exact mul_le_mul_of_nonpos_left h_relu_ge hw2

/-! ## MLP-level monotonicity -/

/-- The MLP forward pass is monotone non-decreasing in feature `i` whenever
every hidden neuron satisfies the sign constraint `0 ≤ w2[j] * w1[j][i]`.

This is the Tier 2 shape theorem: it holds for any trained weight snapshot
that meets the constraint, independent of which dataset shaped the weights. -/
theorem mlp_forward_monotone_in {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (i : Fin inputDim)
    (h_sign : ∀ j : Fin hiddenDim, 0 ≤ weights.w2 j * weights.w1 j i)
    {x y : RealVec inputDim}
    (h_eq : AgreeOff i x y) (h_le : x i ≤ y i) :
    mlpForward weights x ≤ mlpForward weights y := by
  unfold mlpForward
  apply sigmoid_monotone
  have hsum :
      ∑ j : Fin hiddenDim,
        weights.w2 j * relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
    ≤ ∑ j : Fin hiddenDim,
        weights.w2 j * relu (vecAdd (matVecMul weights.w1 y) weights.b1 j) := by
    apply Finset.sum_le_sum
    intro j _
    exact per_neuron_mono weights j i (h_sign j) h_eq h_le
  -- `dot w2 (reluVec _) = ∑ j, w2 j * relu (_ j)` by definition.
  have heq_x :
      dot weights.w2 (reluVec (vecAdd (matVecMul weights.w1 x) weights.b1))
    = ∑ j : Fin hiddenDim,
        weights.w2 j * relu (vecAdd (matVecMul weights.w1 x) weights.b1 j) := rfl
  have heq_y :
      dot weights.w2 (reluVec (vecAdd (matVecMul weights.w1 y) weights.b1))
    = ∑ j : Fin hiddenDim,
        weights.w2 j * relu (vecAdd (matVecMul weights.w1 y) weights.b1 j) := rfl
  linarith

/-! ## Ensemble lift -/

/-- If the tree returns the same verdict on `x` and `y`, and the MLP is monotone
non-decreasing from `x` to `y`, then a Block verdict on `x` is preserved on `y`.

This is the "evasion-resistance" property: increasing feature `i` (under the
hypotheses) cannot turn a Block decision into Allow. The hypothesis
`h_tree_eq` is discharged when feature `i` is not a tree split feature, which
is checkable by inspecting the codegen'd `TREE_NODES` array. -/
theorem ensemble_block_preserved_when_tree_constant {inputDim hiddenDim : Nat}
    (tree : TreeNode)
    (weights : MLPWeights inputDim hiddenDim)
    (threshold : ℝ)
    {x y : RealVec inputDim}
    (h_tree_eq : treePredictAux x tree = treePredictAux y tree)
    (h_mlp_mono : mlpForward weights x ≤ mlpForward weights y)
    (h_block : ensemblePredict tree weights threshold x = Decision.block) :
    ensemblePredict tree weights threshold y = Decision.block := by
  unfold ensemblePredict at h_block ⊢
  rw [← h_tree_eq]
  -- Abstract the tree result so cases substitutes cleanly into both h_block and goal.
  generalize htree : treePredictAux x tree = t at h_block ⊢
  cases t with
  | block => rfl
  | allow =>
    -- h_block iota-reduces to `Decision.allow = Decision.block`, which is false.
    have h : Decision.allow = Decision.block := h_block
    exact absurd h (by decide)
  | defer =>
    -- h_block: (if mlpForward weights x > threshold then block else allow) = block
    -- Goal:    (if mlpForward weights y > threshold then block else allow) = block
    by_cases hx : mlpForward weights x > threshold
    · -- mlpForward y ≥ mlpForward x > threshold ⇒ ensemble(y) = Block.
      have hy : mlpForward weights y > threshold := lt_of_lt_of_le hx h_mlp_mono
      simp [hy]
    · -- ensemble(x) = Allow under this branch, contradicting h_block.
      simp [hx] at h_block

end Sunbeam.Verify
