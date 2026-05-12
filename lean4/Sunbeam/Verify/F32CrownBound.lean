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
and `next_up` to the upper bound. The formal basis for FP32 directed-rounding
arithmetic is TorchLean's `Interval32` infrastructure (in
`NN/Floats/Interval/`), specifically:

- `IEEEExec32AddSoundness.add_sound` — `addDown`/`addUp` give a sound enclosure
  of real addition under IEEE-754 binary32 endpoints.
- `IEEEExec32MulSoundness.mul_sound` — `mulDown`/`mulUp` give the analogous
  enclosure for multiplication.

The Rust runtime's `next_down(round_to_nearest(a + b))` and `addDown(a, b)`
are both sound lower bounds on the real sum `a + b`: round-to-nearest has
≤ 0.5 ULP error and `next_down` shifts by 1 ULP, so the runtime's bound is at
least as wide as TorchLean's directed-rounding bound. The same holds for
multiplication. Composing through the MLP2 structure with these per-op
soundness lemmas gives runtime-level soundness: if the runtime certifies a
radius, the Lean hypothesis here holds with margin.

The sigmoid evaluation in the runtime applies an 8-ULP slack via
`sigmoid_down`/`sigmoid_up` to absorb libm `expf` imprecision (typically ≤ 1
ULP per chained op; 8 is a margin).

A formal `Interval32`-typed IBP theorem composing `add_sound`/`mul_sound`
through the scanner `MLP2` is left as a follow-up — it would tighten the
above paragraph into a single Lean theorem but does not change the runtime
behavior or the soundness argument.

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
