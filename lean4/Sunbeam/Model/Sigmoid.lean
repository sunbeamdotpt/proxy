import Mathlib.Analysis.SpecialFunctions.Exp
import Sunbeam.Model.Basic

namespace Sunbeam

/-- The sigmoid function σ(x) = 1 / (1 + exp(-x)).

Stated over `ℝ`. Equivalent to Mathlib's `Real.sigmoid` (which is defined as
`(1 + exp(-x))⁻¹`) via `one_div`, but we keep the explicit form here so the
proofs read naturally. -/
noncomputable def sigmoid (x : ℝ) : ℝ :=
  1 / (1 + Real.exp (-x))

/-! ## Sigmoid bounds (Tier 1, axiom-free)

Previously stated as `axiom` because Lean `Float` operations are opaque to the
kernel. With the spec lifted to `ℝ`, all three bounds follow from `Real.exp_pos`
and `Real.exp_le_exp`. No Sunbeam-local axioms.
-/

/-- Sigmoid output is always positive. -/
theorem sigmoid_pos (x : ℝ) : 0 < sigmoid x := by
  unfold sigmoid
  apply div_pos one_pos
  have hexp : 0 < Real.exp (-x) := Real.exp_pos _
  linarith

/-- Sigmoid output is always less than 1. -/
theorem sigmoid_lt_one (x : ℝ) : sigmoid x < 1 := by
  unfold sigmoid
  have hexp : 0 < Real.exp (-x) := Real.exp_pos _
  have hden_pos : 0 < 1 + Real.exp (-x) := by linarith
  rw [div_lt_one hden_pos]
  linarith

/-- Sigmoid is monotonically increasing. -/
theorem sigmoid_monotone {x y : ℝ} (h : x ≤ y) : sigmoid x ≤ sigmoid y := by
  unfold sigmoid
  have hexp_x : (0 : ℝ) < Real.exp (-x) := Real.exp_pos _
  have hexp_y : (0 : ℝ) < Real.exp (-y) := Real.exp_pos _
  have hden_y : (0 : ℝ) < 1 + Real.exp (-y) := by linarith
  have hexp_mono : Real.exp (-y) ≤ Real.exp (-x) :=
    Real.exp_le_exp.mpr (neg_le_neg h)
  have h_den_le : 1 + Real.exp (-y) ≤ 1 + Real.exp (-x) := by linarith
  exact one_div_le_one_div_of_le hden_y h_den_le

end Sunbeam
