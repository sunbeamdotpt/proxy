import Sunbeam.Model.Basic
import Sunbeam.Model.F32
import Sunbeam.Verify.Lipschitz
import Sunbeam.Verify.F32ErrorBounds
import Sunbeam.Verify.Monotonicity

namespace Sunbeam.Verify

open Sunbeam

/-! # Deployment-soundness theorem (Tier 3 + Tier 4 combined)

This is the headline claim for a 4KB scanner at deployed precision:

> The FP32 runtime verdict matches the ℝ idealised verdict whenever the ℝ score
> is more than `mlpF32Error(w, x)` from the decision threshold.

Adding Tier 3 (Lipschitz): the verdict is also stable to any input perturbation
of size up to `(margin − ε) / L`.

Together: the model is sound at deployed precision *with a quantitative
ε-band of uncertainty around the threshold*, and outside that band the FP32
runtime is provably correct.

## Trust base
- `mlpForwardF32_error_bound` (Tier 4) — half-ULP per op, propagated.
- `mlp_forward_lipschitz` (Tier 3) — Lipschitz constant `mlpSens` per coord.
- Mathlib baseline.

No Sunbeam-local axioms.
-/

/-! ## FP32-vs-ℝ verdict agreement when ℝ has comfortable margin -/

/-- If the ℝ-ideal score is more than `ε(w, x)` above the threshold, then the
FP32 score is strictly above the threshold. -/
theorem fp32_above_threshold_when_real_above_margin
    {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (threshold : ℝ)
    (h_margin : threshold + mlpF32Error w x
              < mlpForward (weightsToReal w) (Sunbeam.F32.vecToReal x)) :
    threshold < Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) := by
  have h_bound := mlpForwardF32_error_bound w x
  -- abs_sub_le_iff: |a - b| ≤ c ↔ a - b ≤ c ∧ b - a ≤ c
  have h_abs := abs_sub_le_iff.mp h_bound
  -- h_abs.2 : real - F32 ≤ ε  ⇒  F32 ≥ real - ε > threshold
  linarith [h_abs.2]

/-- If the ℝ-ideal score is more than `ε(w, x)` below the threshold, then the
FP32 score is strictly below the threshold. -/
theorem fp32_below_threshold_when_real_below_margin
    {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (threshold : ℝ)
    (h_margin : mlpForward (weightsToReal w) (Sunbeam.F32.vecToReal x)
              < threshold - mlpF32Error w x) :
    Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) < threshold := by
  have h_bound := mlpForwardF32_error_bound w x
  have h_abs := abs_sub_le_iff.mp h_bound
  -- h_abs.1 : F32 - real ≤ ε  ⇒  F32 ≤ real + ε < threshold
  linarith [h_abs.1]

/-! ## Verdict stability under input perturbation (Tier 3 × Tier 4) -/

/-- If the ℝ-ideal score at input `x_R` is more than
`ε(w, x_F32) + ∑_i sens_i · |x_R[i] - y_R[i]|` above the threshold, then the FP32
score on `x_F32` is strictly above the threshold even after the ℝ-ideal input
is perturbed to `y_R`. Captures: "verdict survives any input perturbation up to
the implied L∞ radius." -/
theorem fp32_above_threshold_stable_under_perturbation
    {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (threshold : ℝ)
    (y_R : RealVec inputDim)
    (h_margin :
      threshold + mlpF32Error w x
      + ∑ i : Fin inputDim, mlpSens (weightsToReal w) i
                              * |Sunbeam.F32.vecToReal x i - y_R i|
      < mlpForward (weightsToReal w) y_R) :
    threshold < Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) := by
  -- Step 1: ‖mlpForward_R x - mlpForward_R y‖ ≤ ∑ sens_i · |x_i - y_i|  (Tier 3)
  have h_lip := mlp_forward_lipschitz (weightsToReal w) (Sunbeam.F32.vecToReal x) y_R
  -- Step 2: mlpForward_R x ≥ mlpForward_R y - ∑ sens_i · |x_i - y_i|
  have h_real_lower :
      mlpForward (weightsToReal w) y_R
      - ∑ i : Fin inputDim, mlpSens (weightsToReal w) i
                              * |Sunbeam.F32.vecToReal x i - y_R i|
      ≤ mlpForward (weightsToReal w) (Sunbeam.F32.vecToReal x) := by
    -- abs_sub_le_iff: |A - B| ≤ S → A - B ≤ S ∧ B - A ≤ S
    have h_abs := (abs_sub_le_iff.mp h_lip).2
    linarith
  -- Step 3: apply fp32_above_threshold_when_real_above_margin.
  apply fp32_above_threshold_when_real_above_margin w x threshold
  linarith

/-! ## Verdict stability under monotone adversarial perturbation (Tier 2 × Tier 4)

The Lipschitz-based perturbation theorem above bounds verdict drift by an
L∞-radius around the original input. For *adversarial* features (those an
attacker can move at will to evade detection), a stronger directional
guarantee is available: under the per-neuron sign constraint, the ℝ-ideal
score is *monotone non-decreasing* in the feature, so an attacker raising it
can only strengthen a Block verdict.

Combined with the Tier 4 FP32 error bound: if the ℝ-score at the *original*
input has comfortable margin above the threshold, then the FP32 score at
*any* monotone-upward perturbation of that input is also above the
threshold — regardless of perturbation magnitude in the adversarial
coordinate. This is the "one-way street" guarantee on real IEEE-754
hardware. -/

/-- If the ℝ-ideal score at the original real-valued input `x_R` is more than
`ε(w, y_F32)` above the threshold, the weights satisfy the per-neuron sign
constraint for feature `i`, and `y_F32` differs from `x_R` only at
coordinate `i` with `y_F32[i] ≥ x_R[i]`, then the FP32 score on `y_F32` is
strictly above the threshold.

Operational reading: a certified Block verdict on `x_R` survives any
adversary perturbing only feature `i` upward, regardless of how large the
perturbation is, on real IEEE-754 binary32 hardware.

Trust base: `mlp_forward_monotone_in` (Tier 2 over ℝ) +
`fp32_above_threshold_when_real_above_margin` (Tier 4). No new axioms. -/
theorem fp32_above_threshold_stable_under_monotone_perturbation
    {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (y_F32 : Sunbeam.F32.FP32Vec inputDim)
    (x_R : RealVec inputDim)
    (i : Fin inputDim)
    (threshold : ℝ)
    (h_sign : ∀ j : Fin hiddenDim,
       0 ≤ (weightsToReal w).w2 j * (weightsToReal w).w1 j i)
    (h_eq : AgreeOff i x_R (Sunbeam.F32.vecToReal y_F32))
    (h_le : x_R i ≤ Sunbeam.F32.vecToReal y_F32 i)
    (h_margin :
      threshold + mlpF32Error w y_F32 < mlpForward (weightsToReal w) x_R) :
    threshold < Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w y_F32) := by
  -- Tier 2: ℝ-monotonicity lifts the original-input score to the perturbed input.
  have h_mono := mlp_forward_monotone_in (weightsToReal w) i h_sign h_eq h_le
  -- The ℝ-score at y_R is at least the ℝ-score at x_R, which exceeds the margin.
  have h_y_real_above :
      threshold + mlpF32Error w y_F32
        < mlpForward (weightsToReal w) (Sunbeam.F32.vecToReal y_F32) := by
    linarith
  -- Tier 4: FP32 evaluation on y_F32 inherits the margin.
  exact fp32_above_threshold_when_real_above_margin w y_F32 threshold h_y_real_above

end Sunbeam.Verify
