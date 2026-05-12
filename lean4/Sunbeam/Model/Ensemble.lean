import Sunbeam.Model.Basic
import Sunbeam.Model.MLP
import Sunbeam.Model.DecisionTree

open Classical

namespace Sunbeam

/-- Ensemble: tree decides first; MLP handles only Defer cases. -/
noncomputable def ensemblePredict {inputDim hiddenDim : Nat}
    (tree : TreeNode) (mlpWeights : MLPWeights inputDim hiddenDim)
    (threshold : ℝ) (input : RealVec inputDim) : Decision :=
  match treePredictAux input tree with
  | Decision.block => Decision.block
  | Decision.allow => Decision.allow
  | Decision.defer =>
    let score := mlpForward mlpWeights input
    if score > threshold then Decision.block else Decision.allow

/-- If the tree says Block, the ensemble says Block. -/
theorem tree_block_implies_ensemble_block {inputDim hiddenDim : Nat}
    (tree : TreeNode) (mlpWeights : MLPWeights inputDim hiddenDim)
    (threshold : ℝ) (input : RealVec inputDim)
    (h : treePredictAux input tree = Decision.block) :
    ensemblePredict tree mlpWeights threshold input = Decision.block := by
  unfold ensemblePredict
  rw [h]

/-- Ensemble output is always Block or Allow (never Defer). -/
theorem ensemble_output_valid {inputDim hiddenDim : Nat}
    (tree : TreeNode) (mlpWeights : MLPWeights inputDim hiddenDim)
    (threshold : ℝ) (input : RealVec inputDim) :
    ensemblePredict tree mlpWeights threshold input = Decision.block ∨
    ensemblePredict tree mlpWeights threshold input = Decision.allow := by
  unfold ensemblePredict
  split
  · left; rfl
  · right; rfl
  · dsimp only []
    split
    · left; rfl
    · right; rfl

end Sunbeam
