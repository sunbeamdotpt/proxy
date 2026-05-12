import Sunbeam.Model.F32
import Sunbeam.Verify.CrownBound
import Sunbeam.Verify.CertifiedRadius
import Sunbeam.Verify.F32ErrorBounds

namespace Sunbeam.Verify

open Sunbeam

/-! # FP32-side CROWN bound and verdict stability

Composes `mlpForwardF32_error_bound` (Tier 4) with `mlpForward_crown_bound`
(Phase A2) to widen the ℝ-side certified interval by the FP32 forward error,
lifting the bound onto the deployment surface.

## Runtime soundness on IEEE-754 hardware

The Rust runtime (`src/ensemble/crown.rs`) computes IBP in outward-rounded f32:
each FP multiply and add applies `next_down` to the accumulating lower bound
and `next_up` to the upper bound. IEEE-754 round-to-nearest introduces at most
0.5 ULP error per op, so the 1-ULP outward shift guarantees the computed f32
interval is a sound over-approximation of the ℝ-IBP interval. The runtime
analog of this theorem's hypothesis (`threshold + mlpF32Error w x < sigmoid …`)
is therefore strictly more conservative than what's stated here — if the
runtime certifies a radius, the Lean hypothesis holds with margin.

The sigmoid evaluation in the runtime applies an 8-ULP slack via
`sigmoid_down`/`sigmoid_up` to absorb libm `expf` imprecision (typically ≤ 1
ULP per chained op; 8 is a margin).

## Scope

Stated at a specific FP32 input, not uniformly across the box. Lifting to all
`x' ∈ box` requires a uniform upper bound on `mlpF32Error w x'` over the box.
The runtime-side outward rounding addresses the FP32 IBP arithmetic gap but
does not by itself give the uniform-over-box statement. -/

/-- FP32 CROWN bound at a specific input: when `vecToReal x ∈ xB`, the FP32
forward output lies in the ℝ-side certified interval widened by
`mlpF32Error w x` on each side. -/
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

/-- FP32 verdict stability (block side): if the ℝ-CROWN lower bound exceeds
`threshold` by more than `mlpF32Error w x`, the FP32 forward output is
strictly above `threshold`. -/
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

/-- FP32 verdict stability (allow side): if the ℝ-CROWN upper bound plus
`mlpF32Error w x` falls below `threshold`, the FP32 forward output is
strictly below `threshold`. -/
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
