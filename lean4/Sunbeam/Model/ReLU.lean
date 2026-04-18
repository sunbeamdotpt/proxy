import Sunbeam.Model.Basic

namespace Sunbeam

/-- ReLU activation: max(0, x). -/
def relu (x : Float) : Float :=
  if x > 0.0 then x else 0.0

/-- Pointwise ReLU on a vector. -/
def reluVec {n : Nat} (v : FloatVec n) : FloatVec n :=
  fun i => relu (v i)

/-! ## Trust boundary: ReLU axioms -/

/-- ReLU output is non-negative. -/
axiom relu_nonneg (x : Float) : relu x ≥ 0.0

/-- ReLU is monotone. -/
axiom relu_monotone {x y : Float} (h : x ≤ y) : relu x ≤ relu y

end Sunbeam
