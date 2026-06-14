import NN.Spec.Core.Tensor
import NN.Spec.Core.TensorOps
import NN.Spec.Core.Tensor.Linalg
import NN.Spec.Layers.Linear
import NN.Spec.Layers.Activation
import NN.MLTheory.CROWN.Models.Mlp
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU

namespace Sunbeam

/-! # MLP forward pass

`mlpForward` is defined in scalar form (`matVecMul` / `dot` / `vecAdd`) and is
the representation used by Tier 1-4 + Deployment. The TorchLean view
(`vecToTensor`, `matToTensor`, `toMLP2`) is provided alongside for the CROWN
integration in `Verify/CrownBound.lean`; the bridge equation is proved there.
Tensor machinery stays off the critical path for the domain-specific proofs. -/

/-- Weights for a 2-layer MLP (input → hidden → scalar output).

Corresponds to `ensemble::mlp::mlp_predict_32` in Rust, which uses const generic
`INPUT` and a fixed hidden dimension of 32. Here `hiddenDim` is a parameter so
structural properties can be proved generically. -/
structure MLPWeights (inputDim hiddenDim : Nat) where
  w1 : Fin hiddenDim → RealVec inputDim
  b1 : RealVec hiddenDim
  w2 : RealVec hiddenDim
  b2 : ℝ

/-- Forward pass: input → linear1 → ReLU → linear2 → sigmoid. -/
noncomputable def mlpForward {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : RealVec inputDim) : ℝ :=
  let hidden := vecAdd (matVecMul weights.w1 input) weights.b1
  let activated := reluVec hidden
  let output := dot weights.w2 activated + weights.b2
  sigmoid output

/-- MLP output is bounded in (0, 1) — follows directly from sigmoid bounds. -/
theorem mlp_output_bounded {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : RealVec inputDim) :
    0 < mlpForward weights input ∧ mlpForward weights input < 1 := by
  constructor
  · exact sigmoid_pos _
  · exact sigmoid_lt_one _

/-! ## TorchLean views (CROWN integration only)

`abbrev` so unification reduces them automatically; this is what makes the
`matVecMulSpec` ↔ `matVecMul` bridge in `CrownBound` tractable. These views
are not referenced by Tier 1-4 + Deployment. -/

/-- Lift a `RealVec` to a 1-D `Spec.Tensor`. -/
abbrev vecToTensor {n : Nat} (v : RealVec n) : Spec.Tensor ℝ (.dim n .scalar) :=
  Spec.Tensor.dim (fun i => Spec.Tensor.scalar (v i))

/-- Lift a row-major matrix to a 2-D `Spec.Tensor`. -/
abbrev matToTensor {m n : Nat} (w : Fin m → RealVec n) :
    Spec.Tensor ℝ (.dim m (.dim n .scalar)) :=
  Spec.Tensor.dim (fun i => vecToTensor (w i))

/-- Project a 1-D tensor at index `i` to its scalar value. -/
abbrev tensorGet {n : Nat} (t : Spec.Tensor ℝ (.dim n .scalar)) (i : Fin n) : ℝ :=
  match t with
  | Spec.Tensor.dim f => match f i with | Spec.Tensor.scalar a => a

/-- View `MLPWeights` as a TorchLean `MLP2` with single-element output, so
CROWN bound propagation can be applied. -/
def toMLP2 {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) :
    NN.MLTheory.CROWN.MLP2 ℝ inputDim hiddenDim 1 where
  W1 := matToTensor w.w1
  b1 := vecToTensor w.b1
  W2 := matToTensor (fun _ : Fin 1 => w.w2)
  b2 := vecToTensor (fun _ : Fin 1 => w.b2)

end Sunbeam
