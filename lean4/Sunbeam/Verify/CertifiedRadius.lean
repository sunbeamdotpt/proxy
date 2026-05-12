import NN.Spec.Core.Tensor
import NN.MLTheory.CROWN.Models.Mlp
import NN.MLTheory.CROWN.Core
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP
import Sunbeam.Verify.CrownBound

namespace Sunbeam.Verify

open Sunbeam

/-! # Certified per-input adversarial robustness radius

A **certified radius** for an input `x` is a value `ε` such that the model's
verdict is provably stable across the entire L∞ ε-ball around `x`. This is the
strongest formal guarantee available for adversarial robustness: not just
empirical robustness on a test set, but a proof that *no* perturbation within
the certified radius can flip the verdict.

The radius is per-input: inputs deep in their decision region certify with
large radii; inputs near a decision boundary certify with small radii (or none).

The runtime computes the largest ε satisfying these conditions via binary
search; the theorems here guarantee soundness for any such ε.

## API

- `epsBox`                       — L∞ ε-box around an input point
- `epsBox_contains_self`         — center is in its own ε-box (for `ε ≥ 0`)
- `epsBox_contains_of_linf_le`   — any L∞-close point lies in the ε-box
- `verdict_stable_block`         — block verdict stable when CROWN lower-bound
                                   sigmoid exceeds the threshold
- `verdict_stable_allow`         — allow verdict stable when CROWN upper-bound
                                   sigmoid is below the threshold -/

/-- L∞ ε-box around input vector `x`. The box is `[x - ε, x + ε]` per coordinate. -/
def epsBox {n : Nat} (x : RealVec n) (ε : ℝ) :
    NN.MLTheory.CROWN.Box ℝ (.dim n .scalar) where
  lo := vecToTensor (fun i => x i - ε)
  hi := vecToTensor (fun i => x i + ε)

/-- The center `x` is contained in its own ε-box, provided `ε ≥ 0`. -/
lemma epsBox_contains_self {n : Nat} (x : RealVec n) (ε : ℝ) (hε : 0 ≤ ε) :
    NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x) := by
  intro i
  show (x i - ε) ≤ x i ∧ x i ≤ (x i + ε)
  exact ⟨by linarith, by linarith⟩

/-- Any L∞-close point `x'` (with `|x' i - x i| ≤ ε` for all `i`) lies in
`epsBox x ε`. -/
lemma epsBox_contains_of_linf_le {n : Nat} (x x' : RealVec n) (ε : ℝ)
    (h : ∀ i, |x' i - x i| ≤ ε) :
    NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x') := by
  intro i
  show (x i - ε) ≤ x' i ∧ x' i ≤ (x i + ε)
  have hi := h i
  rw [abs_le] at hi
  exact ⟨by linarith, by linarith⟩

/-- **Verdict stability under block** — if the CROWN-certified lower bound on
the sigmoid output exceeds the threshold, the model emits a probability above
the threshold for every input in the ε-ball, not just the center.

This is the formal statement of "certified block within radius ε": no
adversarial perturbation up to L∞ radius ε can flip the verdict away from
block. -/
theorem verdict_stable_block {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim) (ε threshold : ℝ)
    (hbound : threshold < sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) (epsBox x ε)).lo
        ⟨0, Nat.zero_lt_succ 0⟩)) :
    ∀ x' : RealVec inputDim,
      NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x') →
      threshold < mlpForward w x' := by
  intro x' hx'
  have ⟨h1, _⟩ := mlpForward_crown_bound w x' (epsBox x ε) hx'
  linarith

/-- **Verdict stability under allow** — if the CROWN-certified upper bound on
the sigmoid output is below the threshold, the model emits a probability below
the threshold for every input in the ε-ball, not just the center.

This is the formal statement of "certified allow within radius ε": no
adversarial perturbation up to L∞ radius ε can flip the verdict away from
allow. -/
theorem verdict_stable_allow {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim) (ε threshold : ℝ)
    (hbound : sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) (epsBox x ε)).hi
        ⟨0, Nat.zero_lt_succ 0⟩) < threshold) :
    ∀ x' : RealVec inputDim,
      NN.MLTheory.CROWN.Box.contains (epsBox x ε) (vecToTensor x') →
      mlpForward w x' < threshold := by
  intro x' hx'
  have ⟨_, h2⟩ := mlpForward_crown_bound w x' (epsBox x ε) hx'
  linarith

end Sunbeam.Verify
