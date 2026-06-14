import Mathlib.Data.Real.Basic
import Mathlib.Algebra.BigOperators.Fin

namespace Sunbeam

/-- Decisions that a model component can output. -/
inductive Decision where
  | block : Decision
  | allow : Decision
  | defer : Decision
  deriving Repr, DecidableEq

/-- A fixed-size vector of reals.

The Sunbeam Lean spec is stated over `ℝ` rather than Lean's `Float`. The runtime
uses `f32` (see `ensemble::mlp` in Rust); the Lean proofs apply to the mathematical
model that `f32` approximates. This trade is explicit: Tier 1 properties become
axiom-free at the cost of an informal `f32 ↔ ℝ` correspondence, which is the
standard convention in ML formal verification.

`abbrev` (not `def`) so unification automatically reduces `RealVec n` to
`Fin n → ℝ` — needed for proofs that mix our vector type with TorchLean's
tensor primitives. -/
abbrev RealVec (n : Nat) := Fin n → ℝ

/-- Dot product of two vectors. Uses `Finset.sum` so the standard algebraic
lemmas (linearity, sum-over-single-coord) apply directly. -/
noncomputable def dot {n : Nat} (a b : RealVec n) : ℝ :=
  ∑ i : Fin n, a i * b i

/-- Matrix-vector product. Matrix is row-major: m rows × n cols. -/
noncomputable def matVecMul {m n : Nat} (mat : Fin m → RealVec n) (v : RealVec n) : RealVec m :=
  fun i => dot (mat i) v

/-- Vector addition. -/
noncomputable def vecAdd {n : Nat} (a b : RealVec n) : RealVec n :=
  fun i => a i + b i

end Sunbeam
