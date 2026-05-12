import Mathlib.Analysis.SpecialFunctions.Sigmoid
import Mathlib.Analysis.Calculus.MeanValue
import Mathlib.Algebra.BigOperators.Fin
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP

namespace Sunbeam.Verify

open Sunbeam

/-! # Tier 3: Lipschitz (sensitivity) bound on `mlpForward`

For an MLP that is *not* monotone in a feature, monotonicity offers no
guarantee. The Lipschitz bound says: *no input perturbation, in any direction,
moves the output more than a known sensitivity constant times the perturbation
size.* This is the property that combines with the FP32 error bound (Tier 4)
into a deployment-soundness theorem of the form "the FP32 verdict matches the
ℝ verdict whenever the ℝ score is more than `ε(weights)` from the decision
threshold."

## Per-coordinate sensitivity

For the 2-layer MLP `sigmoid (W2 · relu (W1·x + b1) + b2)`:

```
|mlpForward w x - mlpForward w y| ≤ ∑_i sens_i(w) · |x_i - y_i|
```

where the per-coordinate sensitivity is

```
sens_i(w) = (1/4) · ∑_j |W2[j]| · |W1[j][i]|
```

For a 4KB model under a microscope, knowing per-feature sensitivity tells you
*which features the model is fragile in*, not just a global Lipschitz constant.
This is the load-bearing claim for sensitivity analysis at small scale.

## Trust base
Mathlib only: `Real.sigmoid_*`, `Real.deriv_sigmoid`, MVT (`norm_image_sub_le_of_norm_deriv_le_segment`),
`Finset.abs_sum_le_sum_abs`, abs/max lemmas.
-/

/-! ## Sigmoid is (1/4)-Lipschitz -/

/-- `|deriv sigmoid x| ≤ 1/4` everywhere.

`deriv sigmoid x = sigmoid x * (1 - sigmoid x)`, both factors in `[0, 1]`, and
AM-GM gives `t · (1 - t) ≤ 1/4` for `t ∈ [0, 1]`. -/
lemma deriv_sigmoid_le_quarter (x : ℝ) : |deriv Real.sigmoid x| ≤ 1/4 := by
  rw [Real.deriv_sigmoid]
  have hpos : 0 ≤ Real.sigmoid x * (1 - Real.sigmoid x) :=
    mul_nonneg (Real.sigmoid_nonneg x) (sub_nonneg.mpr (Real.sigmoid_le_one x))
  rw [abs_of_nonneg hpos]
  nlinarith [sq_nonneg (Real.sigmoid x - 1/2)]

/-- Our `Sunbeam.sigmoid` equals `Real.sigmoid` definitionally up to `one_div`. -/
lemma sigmoid_eq_real_sigmoid (x : ℝ) : sigmoid x = Real.sigmoid x := by
  unfold sigmoid
  rw [Real.sigmoid_def, one_div]

/-- Sigmoid is (1/4)-Lipschitz: `|sigmoid x - sigmoid y| ≤ (1/4) · |x - y|`. -/
theorem sigmoid_lipschitz (x y : ℝ) :
    |sigmoid x - sigmoid y| ≤ (1/4) * |x - y| := by
  rw [sigmoid_eq_real_sigmoid, sigmoid_eq_real_sigmoid]
  rcases le_total x y with hxy | hxy
  · -- x ≤ y
    have h_deriv : ∀ z ∈ Set.Icc x y,
        HasDerivWithinAt Real.sigmoid
          (Real.sigmoid z * (1 - Real.sigmoid z)) (Set.Icc x y) z :=
      fun z _ => (Real.hasDerivAt_sigmoid z).hasDerivWithinAt
    have h_bound : ∀ z ∈ Set.Ico x y, ‖Real.sigmoid z * (1 - Real.sigmoid z)‖ ≤ (1/4 : ℝ) := by
      intro z _
      rw [Real.norm_eq_abs]
      have hpos : 0 ≤ Real.sigmoid z * (1 - Real.sigmoid z) :=
        mul_nonneg (Real.sigmoid_nonneg z) (sub_nonneg.mpr (Real.sigmoid_le_one z))
      rw [abs_of_nonneg hpos]
      nlinarith [sq_nonneg (Real.sigmoid z - 1/2)]
    have h := norm_image_sub_le_of_norm_deriv_le_segment' h_deriv h_bound y
      (Set.right_mem_Icc.mpr hxy)
    rw [Real.norm_eq_abs] at h
    have h_abs_xy : |x - y| = y - x := by
      rw [abs_sub_comm, abs_of_nonneg (sub_nonneg.mpr hxy)]
    rw [h_abs_xy, abs_sub_comm]
    exact h
  · -- y ≤ x: symmetric
    have h_deriv : ∀ z ∈ Set.Icc y x,
        HasDerivWithinAt Real.sigmoid
          (Real.sigmoid z * (1 - Real.sigmoid z)) (Set.Icc y x) z :=
      fun z _ => (Real.hasDerivAt_sigmoid z).hasDerivWithinAt
    have h_bound : ∀ z ∈ Set.Ico y x, ‖Real.sigmoid z * (1 - Real.sigmoid z)‖ ≤ (1/4 : ℝ) := by
      intro z _
      rw [Real.norm_eq_abs]
      have hpos : 0 ≤ Real.sigmoid z * (1 - Real.sigmoid z) :=
        mul_nonneg (Real.sigmoid_nonneg z) (sub_nonneg.mpr (Real.sigmoid_le_one z))
      rw [abs_of_nonneg hpos]
      nlinarith [sq_nonneg (Real.sigmoid z - 1/2)]
    have h := norm_image_sub_le_of_norm_deriv_le_segment' h_deriv h_bound x
      (Set.right_mem_Icc.mpr hxy)
    rw [Real.norm_eq_abs] at h
    have h_abs_xy : |x - y| = x - y := abs_of_nonneg (sub_nonneg.mpr hxy)
    rw [h_abs_xy]
    exact h

/-! ## ReLU is 1-Lipschitz -/

theorem relu_lipschitz (x y : ℝ) : |relu x - relu y| ≤ |x - y| := by
  unfold relu
  exact abs_max_sub_max_le_abs x y 0

/-! ## Dot product per-coordinate Lipschitz -/

/-- Triangle bound: `|dot w x - dot w y| ≤ ∑ i, |w i| * |x i - y i|`. -/
theorem dot_lipschitz_per_coord {n : Nat} (w x y : RealVec n) :
    |dot w x - dot w y| ≤ ∑ i : Fin n, |w i| * |x i - y i| := by
  have h_diff : dot w x - dot w y = ∑ i : Fin n, w i * (x i - y i) := by
    unfold dot
    rw [← Finset.sum_sub_distrib]
    refine Finset.sum_congr rfl ?_
    intro i _
    ring
  rw [h_diff]
  calc |∑ i : Fin n, w i * (x i - y i)|
      ≤ ∑ i : Fin n, |w i * (x i - y i)| := Finset.abs_sum_le_sum_abs _ _
    _ = ∑ i : Fin n, |w i| * |x i - y i| := by
        refine Finset.sum_congr rfl ?_
        intro i _
        rw [abs_mul]

/-! ## Per-layer composition -/

/-- The `j`-th pre-activation `(W1·x + b1)_j` differs by at most a weighted sum
of input differences. -/
lemma preact_lipschitz_per_coord {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim)
    (x y : RealVec inputDim) (j : Fin hiddenDim) :
    |vecAdd (matVecMul weights.w1 x) weights.b1 j
   - vecAdd (matVecMul weights.w1 y) weights.b1 j|
   ≤ ∑ i : Fin inputDim, |weights.w1 j i| * |x i - y i| := by
  unfold vecAdd matVecMul
  have h_simp :
      dot (weights.w1 j) x + weights.b1 j - (dot (weights.w1 j) y + weights.b1 j)
    = dot (weights.w1 j) x - dot (weights.w1 j) y := by ring
  rw [h_simp]
  exact dot_lipschitz_per_coord _ _ _

/-- After ReLU, the `j`-th activation differs by at most the same weighted sum. -/
lemma relu_preact_lipschitz_per_coord {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim)
    (x y : RealVec inputDim) (j : Fin hiddenDim) :
    |relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
   - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j)|
   ≤ ∑ i : Fin inputDim, |weights.w1 j i| * |x i - y i| := by
  calc |relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
      - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j)|
      ≤ |vecAdd (matVecMul weights.w1 x) weights.b1 j
       - vecAdd (matVecMul weights.w1 y) weights.b1 j| :=
        relu_lipschitz _ _
    _ ≤ _ := preact_lipschitz_per_coord weights x y j

/-! ## Per-coordinate sensitivity constant -/

/-- Per-coordinate sensitivity: `sens_i(w) = (1/4) · ∑_j |W2[j]| · |W1[j][i]|`. -/
noncomputable def mlpSens {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (i : Fin inputDim) : ℝ :=
  (1/4) * ∑ j : Fin hiddenDim, |weights.w2 j| * |weights.w1 j i|

/-! ## Main Lipschitz theorem -/

/-- `mlpForward` is Lipschitz per-coordinate: small perturbations in any single
feature move the output by at most `sens_i · |Δx_i|`. The sum form generalises
to multi-coordinate perturbations. -/
theorem mlp_forward_lipschitz {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (x y : RealVec inputDim) :
    |mlpForward weights x - mlpForward weights y|
   ≤ ∑ i : Fin inputDim, mlpSens weights i * |x i - y i| := by
  unfold mlpForward
  -- Step 1: sigmoid is 1/4-Lipschitz, so reduce to bounding the pre-sigmoid difference.
  set zx := dot weights.w2 (reluVec (vecAdd (matVecMul weights.w1 x) weights.b1))
            + weights.b2 with hzx_def
  set zy := dot weights.w2 (reluVec (vecAdd (matVecMul weights.w1 y) weights.b1))
            + weights.b2 with hzy_def
  have h_sigmoid : |sigmoid zx - sigmoid zy| ≤ (1/4) * |zx - zy| := sigmoid_lipschitz zx zy
  -- Step 2: bound |zx - zy| by ∑_i (∑_j |w2 j| * |w1 j i|) * |x i - y i|.
  have h_inner : |zx - zy| ≤
      ∑ i : Fin inputDim, (∑ j : Fin hiddenDim, |weights.w2 j| * |weights.w1 j i|) * |x i - y i| := by
    have h_zx_minus_zy :
        zx - zy = ∑ j : Fin hiddenDim,
          weights.w2 j * (relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
                         - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j)) := by
      simp only [hzx_def, hzy_def, dot, reluVec]
      rw [add_sub_add_right_eq_sub, ← Finset.sum_sub_distrib]
      refine Finset.sum_congr rfl ?_
      intro j _
      ring
    rw [h_zx_minus_zy]
    calc |∑ j : Fin hiddenDim,
            weights.w2 j * (relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
                           - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j))|
        ≤ ∑ j : Fin hiddenDim,
            |weights.w2 j * (relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
                            - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j))| :=
          Finset.abs_sum_le_sum_abs _ _
      _ = ∑ j : Fin hiddenDim,
            |weights.w2 j| * |relu (vecAdd (matVecMul weights.w1 x) weights.b1 j)
                            - relu (vecAdd (matVecMul weights.w1 y) weights.b1 j)| := by
          refine Finset.sum_congr rfl ?_
          intro j _
          rw [abs_mul]
      _ ≤ ∑ j : Fin hiddenDim,
            |weights.w2 j| * (∑ i : Fin inputDim, |weights.w1 j i| * |x i - y i|) := by
          refine Finset.sum_le_sum ?_
          intro j _
          exact mul_le_mul_of_nonneg_left
            (relu_preact_lipschitz_per_coord weights x y j) (abs_nonneg _)
      _ = ∑ j : Fin hiddenDim, ∑ i : Fin inputDim,
            |weights.w2 j| * |weights.w1 j i| * |x i - y i| := by
          refine Finset.sum_congr rfl ?_
          intro j _
          rw [Finset.mul_sum]
          refine Finset.sum_congr rfl ?_
          intro i _
          ring
      _ = ∑ i : Fin inputDim, ∑ j : Fin hiddenDim,
            |weights.w2 j| * |weights.w1 j i| * |x i - y i| := Finset.sum_comm
      _ = ∑ i : Fin inputDim,
            (∑ j : Fin hiddenDim, |weights.w2 j| * |weights.w1 j i|) * |x i - y i| := by
          refine Finset.sum_congr rfl ?_
          intro i _
          rw [Finset.sum_mul]
  -- Step 3: combine.
  calc |sigmoid zx - sigmoid zy|
      ≤ (1/4) * |zx - zy| := h_sigmoid
    _ ≤ (1/4) * (∑ i : Fin inputDim,
                  (∑ j : Fin hiddenDim, |weights.w2 j| * |weights.w1 j i|)
                  * |x i - y i|) :=
        mul_le_mul_of_nonneg_left h_inner (by norm_num)
    _ = ∑ i : Fin inputDim, mlpSens weights i * |x i - y i| := by
        unfold mlpSens
        rw [Finset.mul_sum]
        refine Finset.sum_congr rfl ?_
        intro i _
        ring

end Sunbeam.Verify
