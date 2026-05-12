import Sunbeam.Verify.Structural
import Sunbeam.Verify.Monotonicity
import Sunbeam.Verify.Lipschitz
import Sunbeam.Verify.F32ErrorBounds
import Sunbeam.Verify.Deployment
import Sunbeam.Verify.CrownBound
import Sunbeam.Verify.CertifiedRadius
import Sunbeam.Verify.F32CrownBound

namespace Sunbeam.DDoS

open Sunbeam Sunbeam.Verify

/-! # DDoS ensemble — certified-robustness specialization

The DDoS ensemble has `inputDim = 14` (vs scanner's `12`) and the same
`hiddenDim = 32`. Every theorem in `Sunbeam.Verify.*` is polymorphic in
`inputDim`, so DDoS reuses the proof stack as-is — these aliases exist to
demonstrate the instantiation compiles and to give DDoS-named handles for the
spec sheet and runtime documentation. -/

/-- DDoS input dimension. -/
abbrev inputDim : Nat := 14

/-- DDoS hidden dimension (shared with scanner). -/
abbrev hiddenDim : Nat := 32

/-- DDoS-side ℝ-CROWN soundness: every `x ∈ xB` has `mlpForward w x` sandwiched
by `sigmoid` of the CROWN affine-bound endpoints. -/
theorem mlpForward_crown_bound
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor x)) :
    sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) xB).lo
        ⟨0, Nat.zero_lt_succ 0⟩)
      ≤ mlpForward w x ∧
    mlpForward w x
      ≤ sigmoid (tensorGet
          (NN.MLTheory.CROWN.boundAffine (toMLP2 w) xB).hi
          ⟨0, Nat.zero_lt_succ 0⟩) :=
  Sunbeam.Verify.mlpForward_crown_bound w x xB hx

/-- DDoS verdict stability (block side) at `inputDim = 14`. -/
theorem verdict_stable_block
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim) (ε threshold : ℝ)
    (hbound : threshold < sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) (epsBox x ε)).lo
        ⟨0, Nat.zero_lt_succ 0⟩)) :
    ∀ x' : RealVec inputDim,
      NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x') →
      threshold < mlpForward w x' :=
  Sunbeam.Verify.verdict_stable_block w x ε threshold hbound

/-- DDoS verdict stability (allow side) at `inputDim = 14`. -/
theorem verdict_stable_allow
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim) (ε threshold : ℝ)
    (hbound : sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) (epsBox x ε)).hi
        ⟨0, Nat.zero_lt_succ 0⟩) < threshold) :
    ∀ x' : RealVec inputDim,
      NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x') →
      mlpForward w x' < threshold :=
  Sunbeam.Verify.verdict_stable_allow w x ε threshold hbound

/-- DDoS FP32 verdict stability (block side): runtime-side check, composing the
FP32 forward-error bound with the ℝ-CROWN bound. -/
theorem verdict_stable_block_f32
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor (Sunbeam.F32.vecToReal x)))
    (threshold : ℝ)
    (hbound : threshold + mlpF32Error w x
            < sigmoid (tensorGet
                (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).lo
                ⟨0, Nat.zero_lt_succ 0⟩)) :
    threshold < Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) :=
  Sunbeam.Verify.verdict_stable_block_f32 w x xB hx threshold hbound

/-- DDoS FP32 verdict stability (allow side). -/
theorem verdict_stable_allow_f32
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor (Sunbeam.F32.vecToReal x)))
    (threshold : ℝ)
    (hbound : sigmoid (tensorGet
                (NN.MLTheory.CROWN.boundAffine (toMLP2 (weightsToReal w)) xB).hi
                ⟨0, Nat.zero_lt_succ 0⟩) + mlpF32Error w x
            < threshold) :
    Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x) < threshold :=
  Sunbeam.Verify.verdict_stable_allow_f32 w x xB hx threshold hbound

end Sunbeam.DDoS
