import Sunbeam.Model.F32
import Sunbeam.Verify.CrownBound
import Sunbeam.Verify.CertifiedRadius
import Sunbeam.Verify.F32ErrorBounds

namespace Sunbeam.Verify

open Sunbeam

/-! # F32-side CROWN bounds and verdict stability

This file composes two pieces of the proof stack:

- `mlpForwardF32_error_bound` (Tier 4) — the FP32 forward-error bound via
  TorchLean's `neural_error_bound_ulp`, stating
  `|toReal (mlpForwardF32 w x) - mlpForward (weightsToReal w) (vecToReal x)|
     ≤ mlpF32Error w x`.

- `mlpForward_crown_bound` (Phase A2) — the CROWN soundness bound on
  `mlpForward` over ℝ, stating that for any input in the perturbation box the
  output lies in `[sigmoid(lo), sigmoid(hi)]`.

The composed result widens the ℝ-side certified interval by the FP32 forward
error on each side, lifting the soundness statement onto the FP32 deployment
surface that the Rust runtime actually executes.

## Scope and remaining gaps

The theorems below are stated at a **specific FP32 input** `x`, not uniformly
across the perturbation box. Lifting to "for all FP32 perturbations `x'` in the
box" requires a uniform upper bound on `mlpF32Error w x'` over the box; in
practice this is the supremum over the box magnitudes and is computable, but
the uniform-bound lemma is not yet proven.

A second gap: the Rust runtime computes IBP itself in `f32` arithmetic, which
introduces additional rounding error not captured by `mlpF32Error` (which
bounds only the forward pass). Closing that gap requires either soundness for
TorchLean's `boundIbpFloat` (not yet upstream) or outward-rounded IBP in the
runtime.

These gaps are deliberate scope limits — what is below is sound for the F32
center-input claim and uses only existing upstream tooling. -/

/-- **F32 CROWN bound** at a specific FP32 input.

Given an FP32 input `x` whose lifted-to-ℝ value lies in the perturbation box
`xB`, the F32 forward output is bounded by the sigmoid of the ℝ-side CROWN
coordinates widened by the FP32 forward error `mlpF32Error w x`. -/
theorem mlpForwardF32_crown_bound {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor (Sunbeam.F32.vecToReal x))) :
    sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).lo
        ⟨0, Nat.zero_lt_succ 0⟩) - mlpF32Error w x
      ≤ Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) ∧
    Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x)
      ≤ sigmoid (tensorGet
          (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).hi
          ⟨0, Nat.zero_lt_succ 0⟩) + mlpF32Error w x := by
  have herr := mlpForwardF32_error_bound w x
  rw [abs_le] at herr
  have hcrown := mlpForward_crown_bound (weightsToReal w) (Sunbeam.F32.vecToReal x) xB hx
  exact ⟨by linarith [herr.1, hcrown.1], by linarith [herr.2, hcrown.2]⟩

/-- **F32 verdict stability — block.** If the ℝ-side CROWN lower bound on the
sigmoid output exceeds `threshold + mlpF32Error w x`, then the F32 forward
output at `x` strictly exceeds `threshold`.

The widened margin (`+ mlpF32Error w x` on the threshold side) accounts for
the FP32 forward-error gap between `mlpForwardF32` and its ℝ-valued
counterpart. -/
theorem verdict_stable_block_f32 {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor (Sunbeam.F32.vecToReal x)))
    (threshold : ℝ)
    (hbound : threshold + mlpF32Error w x
            < sigmoid (tensorGet
                (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).lo
                ⟨0, Nat.zero_lt_succ 0⟩)) :
    threshold < Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) := by
  have ⟨h1, _⟩ := mlpForwardF32_crown_bound w x xB hx
  linarith

/-- **F32 verdict stability — allow.** If the ℝ-side CROWN upper bound on the
sigmoid output, widened by `mlpF32Error w x`, falls below `threshold`, then
the F32 forward output at `x` is strictly below `threshold`. -/
theorem verdict_stable_allow_f32 {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor (Sunbeam.F32.vecToReal x)))
    (threshold : ℝ)
    (hbound : sigmoid (tensorGet
                (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).hi
                ⟨0, Nat.zero_lt_succ 0⟩) + mlpF32Error w x
            < threshold) :
    Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) < threshold := by
  have ⟨_, h2⟩ := mlpForwardF32_crown_bound w x xB hx
  linarith

end Sunbeam.Verify
