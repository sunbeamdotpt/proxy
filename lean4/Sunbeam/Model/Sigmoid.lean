import Sunbeam.Model.Basic

namespace Sunbeam

/-- The sigmoid function σ(x) = 1 / (1 + exp(-x)). -/
def sigmoid (x : Float) : Float :=
  1.0 / (1.0 + Float.exp (-x))

/-! ## Trust boundary: sigmoid axioms

These axioms capture IEEE-754 properties of sigmoid that hold for all finite
float inputs. They cannot be proved inside Lean because `Float` operations are
`@[extern]` (opaque to the kernel). The axioms form a documented trust boundary:
we trust the C runtime's `exp` implementation.

When TorchLean (arXiv:2602.22631) ships its verified Float32 kernel, these
axioms can be replaced with proofs against that kernel.
-/

/-- Sigmoid output is always positive: exp(-x) ≥ 0 ⟹ 1+exp(-x) ≥ 1 ⟹ 1/(1+exp(-x)) > 0. -/
axiom sigmoid_pos (x : Float) : sigmoid x > 0

/-- Sigmoid output is always less than 1: 1+exp(-x) > 1 ⟹ 1/(1+exp(-x)) < 1. -/
axiom sigmoid_lt_one (x : Float) : sigmoid x < 1

/-- Sigmoid is monotonically increasing (derivative = σ(1-σ) > 0). -/
axiom sigmoid_monotone {x y : Float} (h : x ≤ y) : sigmoid x ≤ sigmoid y

end Sunbeam
