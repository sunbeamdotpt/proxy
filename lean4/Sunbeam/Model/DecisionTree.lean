import Sunbeam.Model.Basic

namespace Sunbeam

/-- A decision tree node (inductive = automatic termination for structural recursion). -/
inductive TreeNode where
  | leaf (decision : Decision) : TreeNode
  | split (featureIdx : Nat) (threshold : Float) (left right : TreeNode) : TreeNode
  deriving Repr

/-- Tree prediction by structural recursion (termination is automatic). -/
def treePredictAux {n : Nat} (input : Fin n → Float) : TreeNode → Decision
  | .leaf d => d
  | .split idx thr left right =>
    if h : idx < n then
      if input ⟨idx, h⟩ ≤ thr then
        treePredictAux input left
      else
        treePredictAux input right
    else
      Decision.defer

end Sunbeam
