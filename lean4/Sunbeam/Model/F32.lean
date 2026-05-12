import NN.Floats.FP32.Core
import NN.Floats.NeuralFloat.NNOps
import Sunbeam.Model.Basic

/-!
# Sunbeam MLP, IEEE-754 binary32 surface

`FP32` is TorchLean's `NF binaryRadix fexp32 rnd32`: a real value constrained
to the binary32 grid, with arithmetic semantically defined as "compute in ℝ,
then round" using round-to-nearest-even.

Definitions only. The theorems are in:

- `Sunbeam.Verify.F32ErrorBounds` — per-op half-ULP rounding bounds plus the
  cumulative forward-error bound `mlpForwardF32_error_bound` (Tier 4).
- `Sunbeam.Verify.Deployment` — composes the FP32 error bound with the ℝ-side
  Lipschitz bound (Tier 3) for the deployment-soundness theorem.
- `Sunbeam.Verify.F32CrownBound` — composes the FP32 error bound with CROWN
  for the FP32-side verdict-stability theorem (Phase A).

Tier 1 / Tier 2 are not re-proved on `FP32`; instead the FP32-vs-ℝ gap is
bounded via TorchLean's `neural_error_bound_ulp` and propagated through the
Lipschitz constants. -/

namespace Sunbeam.F32

open TorchLean.Floats

/-- IEEE-754 binary32 in the round-to-grid model. Wraps `TorchLean.Floats.FP32`. -/
abbrev FP32 : Type := TorchLean.Floats.FP32

/-- A fixed-size vector of `FP32` values. -/
def FP32Vec (n : Nat) : Type := Fin n → FP32

/-- Lift an `FP32` to its underlying real value. -/
@[inline] noncomputable def toReal (x : FP32) : ℝ := NF.toReal x

/-- Round a real to the `FP32` grid. -/
@[inline] noncomputable def ofReal (x : ℝ) : FP32 := NF.ofReal x

/-- Pointwise lift of a `RealVec` onto the `FP32` grid. -/
noncomputable def vecOfReal {n : Nat} (v : Sunbeam.RealVec n) : FP32Vec n :=
  fun i => ofReal (v i)

/-- Pointwise projection from an `FP32Vec` back to `RealVec`. -/
noncomputable def vecToReal {n : Nat} (v : FP32Vec n) : Sunbeam.RealVec n :=
  fun i => toReal (v i)

/-! ## Rounded primitive operations

Each operation is "compute the ℝ-valued result, then round to the FP32 grid".
This is the standard `FP32` semantics for compositional rounding-error reasoning. -/

/-- Dot product on `FP32`: sum each `(a i * b i)` in ℝ, then round once at the end.

This is the "fused" semantics. The unfused alternative — round after each
`+ a i * b i` — is also definable but yields different rounding error
characteristics. -/
noncomputable def dotF32 {n : Nat} (a b : FP32Vec n) : FP32 :=
  ofReal (∑ i : Fin n, toReal (a i) * toReal (b i))

/-- Matrix-vector product on `FP32`. -/
noncomputable def matVecMulF32 {m n : Nat}
    (mat : Fin m → FP32Vec n) (v : FP32Vec n) : FP32Vec m :=
  fun i => dotF32 (mat i) v

/-- Vector addition on `FP32`. -/
noncomputable def vecAddF32 {n : Nat} (a b : FP32Vec n) : FP32Vec n :=
  fun i => ofReal (toReal (a i) + toReal (b i))

/-- ReLU on `FP32`: round after `max(x, 0)`. -/
noncomputable def reluF32 (x : FP32) : FP32 := ofReal (max (toReal x) 0)

/-- Pointwise ReLU on a vector. -/
noncomputable def reluVecF32 {n : Nat} (v : FP32Vec n) : FP32Vec n :=
  fun i => reluF32 (v i)

/-- Sigmoid on `FP32`: round after `1 / (1 + exp(-x))`. -/
noncomputable def sigmoidF32 (x : FP32) : FP32 :=
  ofReal (1 / (1 + Real.exp (- toReal x)))

/-! ## MLP and ensemble surface -/

/-- Weights for a 2-layer MLP at FP32 precision. Mirrors `Sunbeam.MLPWeights`. -/
structure MLPWeightsF32 (inputDim hiddenDim : Nat) where
  w1 : Fin hiddenDim → FP32Vec inputDim
  b1 : FP32Vec hiddenDim
  w2 : FP32Vec hiddenDim
  b2 : FP32

/-- Forward pass at FP32 precision: input → linear1 → ReLU → linear2 → sigmoid. -/
noncomputable def mlpForwardF32 {inputDim hiddenDim : Nat}
    (weights : MLPWeightsF32 inputDim hiddenDim) (input : FP32Vec inputDim) : FP32 :=
  let hidden := vecAddF32 (matVecMulF32 weights.w1 input) weights.b1
  let activated := reluVecF32 hidden
  let pre_out := dotF32 weights.w2 activated
  sigmoidF32 (ofReal (toReal pre_out + toReal weights.b2))

end Sunbeam.F32
