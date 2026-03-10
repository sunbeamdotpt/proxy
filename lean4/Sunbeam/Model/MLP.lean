import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU

namespace Sunbeam

/-- Weights for a 2-layer MLP (input → hidden → scalar output). -/
structure MLPWeights (inputDim hiddenDim : Nat) where
  w1 : Fin hiddenDim → FloatVec inputDim
  b1 : FloatVec hiddenDim
  w2 : FloatVec hiddenDim
  b2 : Float

/-- Forward pass: input → linear1 → ReLU → linear2 → sigmoid. -/
def mlpForward {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : FloatVec inputDim) : Float :=
  let hidden := vecAdd (matVecMul weights.w1 input) weights.b1
  let activated := reluVec hidden
  let output := dot weights.w2 activated + weights.b2
  sigmoid output

/-- MLP output is bounded in (0, 1) — follows directly from sigmoid bounds. -/
theorem mlp_output_bounded {inputDim hiddenDim : Nat}
    (weights : MLPWeights inputDim hiddenDim) (input : FloatVec inputDim) :
    0 < mlpForward weights input ∧ mlpForward weights input < 1 := by
  constructor
  · exact sigmoid_pos _
  · exact sigmoid_lt_one _

end Sunbeam
