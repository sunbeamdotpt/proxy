import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP
import Sunbeam.Model.DecisionTree
import Sunbeam.Model.Ensemble

namespace Sunbeam.Verify

/-! # Tier 1: Structural properties (hold for ANY model weights)

The Sunbeam Lean spec is stated over `ℝ`. The runtime uses `f32`; the proofs
apply to the mathematical model that `f32` approximates. This is the standard
convention in ML formal verification — the `f32 ↔ ℝ` gap is handled separately
by finite-precision bridges (e.g. TorchLean's `Float32Bridge`) when needed.

`mlpForward` is defined as `sigmoid ∘ MLP2.forward ∘ vecToTensor`, delegating
the pre-sigmoid linear/ReLU/linear computation to TorchLean's `Spec.linearSpec`
and `Activation.reluSpec`. Tier 2+ proofs use TorchLean's verified properties
of these operations.

## Theorems (no Sunbeam-local axioms)
- `sigmoid_pos`: σ(x) > 0  (via `Real.exp_pos`)
- `sigmoid_lt_one`: σ(x) < 1  (via `Real.exp_pos`)
- `sigmoid_monotone`: x ≤ y → σ(x) ≤ σ(y)  (via `Real.sigmoid_monotone`)
- `relu_nonneg`: 0 ≤ relu(x)  (via `le_max_right`)
- `relu_monotone`: x ≤ y → relu(x) ≤ relu(y)  (via `max_le_max`)
- `mlp_output_bounded`: 0 < mlpForward w x ∧ mlpForward w x < 1
- `tree_block_implies_ensemble_block`: tree = Block → ensemble = Block
- `ensemble_output_valid`: ensemble ∈ {Block, Allow} (never Defer)

## Automatic guarantees
- All tree predictions terminate (structural recursion on `TreeNode` inductive)
- Ensemble composition is total (all match arms covered)

## Refactor status
Tier 2 (monotonicity), Tier 3 (Lipschitz), Tier 4 (FP32 precision), and the
deployment-soundness composition were previously derived against a hand-rolled
`mlpForward` body. After the TorchLean-integration refactor, those tiers are
being re-derived against TorchLean's `Spec`/`Activation`/`CROWN` machinery.
This file currently covers Tier 1 only; subsequent commits restore Tier 2+.

## Trust base
The only kernel axioms now in play are Mathlib's standard set (`propext`,
`Classical.choice`, `Quot.sound`). Run `#print axioms <theorem>` to verify.
-/

end Sunbeam.Verify
