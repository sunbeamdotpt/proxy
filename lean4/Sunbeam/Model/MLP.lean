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

The MLP is defined as `sigmoid ∘ MLP2.forward ∘ vecToTensor`, where `MLP2` is
TorchLean's 2-layer ReLU MLP wrapper from `NN.MLTheory.CROWN.Models.Mlp`. This
gives us:

- A single source of truth for the forward computation (TorchLean's
  `Spec.linearSpec` and `Activation.reluSpec`).
- Direct compatibility with TorchLean's CROWN bound-propagation machinery.
- Composition with TorchLean's verified properties (monotonicity of `linearSpec`,
  half-ULP rounding bounds, etc.) rather than rebuilding from scratch.

`MLPWeights` retains the same scalar/`RealVec` shape — it matches the codegen'd
Rust constants (`scanner_weights::W1`, etc.) one-for-one. The conversion to
TorchLean's tensor representation happens inside `mlpForward` itself.
-/

/-- Weights for a 2-layer MLP (input → hidden → scalar output).

Corresponds to `ensemble::mlp::mlp_predict_32` in Rust, which uses const generic
`INPUT` and a fixed hidden dimension of 32. -/
structure MLPWeights (inputDim hiddenDim : Nat) where
  w1 : Fin hiddenDim → RealVec inputDim
  b1 : RealVec hiddenDim
  w2 : RealVec hiddenDim
  b2 : ℝ

/-! ## Conversions: scalar/`RealVec` ↔ TorchLean `Spec.Tensor` -/

/-- Lift a `RealVec` to a 1-D tensor. -/
def vecToTensor {n : Nat} (v : RealVec n) : Spec.Tensor ℝ (.dim n .scalar) :=
  Spec.Tensor.dim (fun i => Spec.Tensor.scalar (v i))

/-- Lift a row-major matrix `(Fin m → RealVec n)` to a 2-D tensor. -/
def matToTensor {m n : Nat} (w : Fin m → RealVec n) :
    Spec.Tensor ℝ (.dim m (.dim n .scalar)) :=
  Spec.Tensor.dim (fun i => vecToTensor (w i))

/-- Project a 1-D tensor at index `i` to its scalar value. -/
def tensorGet {n : Nat} (t : Spec.Tensor ℝ (.dim n .scalar)) (i : Fin n) : ℝ :=
  match t with
  | Spec.Tensor.dim f => match f i with | Spec.Tensor.scalar a => a

/-- View `MLPWeights` as a TorchLean `MLP2` with single-element output. -/
def toMLP2 {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) :
    NN.MLTheory.CROWN.MLP2 ℝ inputDim hiddenDim 1 where
  W1 := matToTensor w.w1
  b1 := vecToTensor w.b1
  W2 := matToTensor (fun _ : Fin 1 => w.w2)
  b2 := vecToTensor (fun _ : Fin 1 => w.b2)

/-! ## Forward pass -/

/-- Forward pass: input → linear1 → ReLU → linear2 → sigmoid.

The pre-sigmoid computation is delegated to TorchLean's `MLP2.forward`, which
implements `W2 · relu(W1 · x + b1) + b2` using `Spec.linearSpec` and
`Activation.reluSpec`. The final sigmoid wraps the single-element output. -/
noncomputable def mlpForward {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : RealVec inputDim) : ℝ :=
  let net := toMLP2 weights
  let output := NN.MLTheory.CROWN.forward net (vecToTensor input)
  sigmoid (tensorGet output ⟨0, Nat.zero_lt_succ _⟩)

/-- MLP output is bounded in (0, 1) — follows directly from sigmoid bounds. -/
theorem mlp_output_bounded {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : RealVec inputDim) :
    0 < mlpForward weights input ∧ mlpForward weights input < 1 := by
  unfold mlpForward
  exact ⟨sigmoid_pos _, sigmoid_lt_one _⟩

end Sunbeam
