import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU

namespace Sunbeam

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

end Sunbeam
