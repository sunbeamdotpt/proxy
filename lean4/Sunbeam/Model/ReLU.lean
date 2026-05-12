import Mathlib.Order.MinMax
import Sunbeam.Model.Basic

namespace Sunbeam

/-- ReLU activation: `max(x, 0)`. Stated over `ℝ`. -/
noncomputable def relu (x : ℝ) : ℝ := max x 0

/-- Pointwise ReLU on a vector. -/
noncomputable def reluVec {n : Nat} (v : RealVec n) : RealVec n :=
  fun i => relu (v i)

/-! ## ReLU bounds (Tier 1, axiom-free) -/

/-- ReLU output is non-negative. -/
theorem relu_nonneg (x : ℝ) : 0 ≤ relu x := le_max_right _ _

/-- ReLU is monotone. -/
theorem relu_monotone {x y : ℝ} (h : x ≤ y) : relu x ≤ relu y :=
  max_le_max h (le_refl 0)

end Sunbeam
