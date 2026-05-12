import NN.Spec.Core.Tensor
import NN.Spec.Core.TensorOps
import NN.Spec.Core.Tensor.Linalg
import NN.Spec.Layers.Linear
import NN.Spec.Layers.Activation
import NN.MLTheory.CROWN.Models.Mlp
import NN.Proofs.Tensor.Algebra
import NN.Proofs.Tensor.Basic
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP

namespace Sunbeam.Verify

open Sunbeam

/-! # CROWN bound integration — TorchLean ↔ scalar bridge

This file is the *single* place where TorchLean's tensor representation meets
our scalar `mlpForward`. We prove

  `mlpForward w x = sigmoid (tensorGet (MLP2.forward (toMLP2 w) (vecToTensor x)) 0)`

via coordinate-wise bridge lemmas composed with TorchLean's already-proven
`Spec.toVec_mat_vec_mul_spec` (the foldl-to-Finset.sum bridge for
`matVecMulSpec`). -/

/-- `tensorGet` is TorchLean's `Spec.toVec` under another name. -/
@[simp] lemma tensorGet_eq_toVec {n : Nat}
    (t : Spec.Tensor ℝ (.dim n .scalar)) (i : Fin n) :
    tensorGet t i = Spec.toVec t i := by
  cases t with
  | dim f =>
    cases h : f i with
    | scalar a =>
      simp [tensorGet, Spec.toVec, h]

/-- `Spec.toVec` undoes `vecToTensor`. -/
@[simp] lemma toVec_vecToTensor {n : Nat} (v : RealVec n) :
    Spec.toVec (vecToTensor v) = v :=
  Spec.toVec_ofVec v

/-- Entry-wise lookup of a lifted matrix matches the underlying scalar. -/
@[simp] lemma get2_matToTensor {m n : Nat}
    (W : Fin m → RealVec n) (i : Fin m) (k : Fin n) :
    Spec.get2 (matToTensor W) i k = W i k := rfl

/-- `Spec.Tensor.addSpec` is coordinate-wise addition under `Spec.toVec`. -/
lemma toVec_addSpec {n : Nat}
    (a b : Spec.Tensor ℝ (.dim n .scalar)) (i : Fin n) :
    Spec.toVec (Spec.Tensor.addSpec a b) i
      = Spec.toVec a i + Spec.toVec b i := by
  cases a with
  | dim fa =>
    cases b with
    | dim fb =>
      cases ha : fa i with
      | scalar x =>
        cases hb : fb i with
        | scalar y =>
          simp [Spec.Tensor.addSpec, Spec.Tensor.map2Spec, Spec.toVec, ha, hb]

/-- `Activation.reluSpec` is coordinate-wise ReLU under `Spec.toVec`. -/
lemma toVec_reluSpec {n : Nat}
    (t : Spec.Tensor ℝ (.dim n .scalar)) (i : Fin n) :
    Spec.toVec (Activation.reluSpec t) i
      = relu (Spec.toVec t i) := by
  cases t with
  | dim f =>
    cases h : f i with
    | scalar x =>
      simp [Activation.reluSpec, Spec.Tensor.mapSpec, Spec.toVec, h,
            Activation.Math.reluSpec, relu]

/-- Tensor extensionality for 1-D real tensors: pointwise-equal `Spec.toVec`
views imply equal tensors. -/
private lemma tensor_dim_ext {n : Nat}
    (t₁ t₂ : Spec.Tensor ℝ (.dim n .scalar))
    (h : ∀ i, Spec.toVec t₁ i = Spec.toVec t₂ i) :
    t₁ = t₂ := by
  rw [← Spec.ofVec_toVec t₁, ← Spec.ofVec_toVec t₂]
  congr 1
  exact funext h

/-- Coordinate formula for `Spec.linearSpec` on lifted weights/bias/input. -/
lemma toVec_linearSpec_lifted {inDim outDim : Nat}
    (W : Fin outDim → RealVec inDim) (b : RealVec outDim)
    (v : RealVec inDim) (i : Fin outDim) :
    Spec.toVec
        (Spec.linearSpec
          (⟨matToTensor W, vecToTensor b⟩ : Spec.LinearSpec ℝ inDim outDim)
          (vecToTensor v)) i
      = dot (W i) v + b i := by
  show Spec.toVec
        (Spec.Tensor.addSpec
            (Spec.matVecMulSpec (matToTensor W) (vecToTensor v))
            (vecToTensor b)) i
      = dot (W i) v + b i
  rw [toVec_addSpec,
      Spec.toVec_mat_vec_mul_spec (A := matToTensor W) (v := vecToTensor v) (i := i)]
  simp only [get2_matToTensor, toVec_vecToTensor]
  unfold dot
  rfl

/-- `Spec.linearSpec` of a lifted layer equals `vecToTensor` of our scalar
`vecAdd (matVecMul W _) b`. -/
lemma linearSpec_lifted_eq_vecToTensor {inDim outDim : Nat}
    (W : Fin outDim → RealVec inDim) (b : RealVec outDim) (v : RealVec inDim) :
    Spec.linearSpec
        (⟨matToTensor W, vecToTensor b⟩ : Spec.LinearSpec ℝ inDim outDim)
        (vecToTensor v)
      = vecToTensor (vecAdd (matVecMul W v) b) := by
  apply tensor_dim_ext
  intro i
  rw [toVec_linearSpec_lifted, toVec_vecToTensor]
  show dot (W i) v + b i = vecAdd (matVecMul W v) b i
  unfold vecAdd matVecMul
  rfl

/-- `Activation.reluSpec` on a lifted vector equals `vecToTensor` of `reluVec`. -/
lemma reluSpec_vecToTensor {n : Nat} (v : RealVec n) :
    Activation.reluSpec (vecToTensor v) = vecToTensor (reluVec v) := by
  apply tensor_dim_ext
  intro i
  rw [toVec_reluSpec, toVec_vecToTensor, toVec_vecToTensor]
  show relu (v i) = reluVec v i
  unfold reluVec
  rfl

/-- The main bridge: `mlpForward` equals the sigmoid of the first coordinate of
TorchLean's `MLP2.forward` on the lifted weights and input. -/
theorem mlpForward_eq_torchlean {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim) :
    mlpForward w x =
      sigmoid (tensorGet
        (NN.MLTheory.CROWN.forward (toMLP2 w) (vecToTensor x))
        ⟨0, Nat.zero_lt_succ _⟩) := by
  unfold mlpForward NN.MLTheory.CROWN.forward toMLP2
  simp only []
  rw [linearSpec_lifted_eq_vecToTensor,
      reluSpec_vecToTensor,
      linearSpec_lifted_eq_vecToTensor]
  congr 1

/-! ## CROWN soundness — certified output bounds on `mlpForward`

Given a perturbation box `xB` around an input and a witness `Box.contains xB x`,
TorchLean's `bound_affine_sound` produces an interval bound on the pre-sigmoid
tensor output. Composing with `mlpForward_eq_torchlean` and sigmoid monotonicity
gives a scalar interval bound on `mlpForward w x` itself.

This is the foundational lemma for per-input certified adversarial robustness:
if both the lower and upper sigmoid bounds fall on the same side of the
decision threshold (0.5), the verdict is provably stable across the entire
perturbation box.  Verdict stability and certified radii live in
`CertifiedRadius.lean` (task A3). -/

/-- Extract scalar `≤` bounds from a `Box.contains` predicate at output
shape `.dim 1 .scalar`, expressed via our `tensorGet` projection. -/
private lemma box_contains_dim1_extract
    (lo hi t : Spec.Tensor ℝ (.dim 1 .scalar))
    (h : NN.MLTheory.CROWN.Box.contains (⟨lo, hi⟩ : NN.MLTheory.CROWN.Box ℝ _) t) :
    tensorGet lo ⟨0, Nat.zero_lt_succ 0⟩ ≤ tensorGet t ⟨0, Nat.zero_lt_succ 0⟩ ∧
    tensorGet t ⟨0, Nat.zero_lt_succ 0⟩ ≤ tensorGet hi ⟨0, Nat.zero_lt_succ 0⟩ := by
  cases lo with
  | dim lof =>
    cases hi with
    | dim hif =>
      cases t with
      | dim tf =>
        have h0 := h ⟨0, Nat.zero_lt_succ 0⟩
        cases hlo : lof ⟨0, Nat.zero_lt_succ 0⟩ with
        | scalar a =>
          cases hhi : hif ⟨0, Nat.zero_lt_succ 0⟩ with
          | scalar b =>
            cases htf : tf ⟨0, Nat.zero_lt_succ 0⟩ with
            | scalar c =>
              rw [hlo, hhi, htf] at h0
              simp only [NN.MLTheory.CROWN.Box.contains] at h0
              -- h0 : a ≤ c ∧ c ≤ b
              simp only [tensorGet, hlo, hhi, htf]
              exact h0

/-- **CROWN soundness for `mlpForward`** (per-input certified output interval).

Given a perturbation box `xB` around the input and a witness that the input
lies in the box, the model output `mlpForward w x` is bounded by the sigmoid
of the affine-CROWN pre-sigmoid bounds. -/
theorem mlpForward_crown_bound {inputDim hiddenDim : Nat}
    (w : MLPWeights inputDim hiddenDim) (x : RealVec inputDim)
    (xB : NN.MLTheory.CROWN.Box ℝ (.dim inputDim .scalar))
    (hx : NN.MLTheory.CROWN.Box.contains xB (vecToTensor x)) :
    sigmoid (tensorGet
        (NN.MLTheory.CROWN.boundAffine (toMLP2 w) xB).lo
        ⟨0, Nat.zero_lt_succ 0⟩)
      ≤ mlpForward w x ∧
    mlpForward w x
      ≤ sigmoid (tensorGet
          (NN.MLTheory.CROWN.boundAffine (toMLP2 w) xB).hi
          ⟨0, Nat.zero_lt_succ 0⟩) := by
  -- TorchLean's affine bound is sound on the pre-sigmoid tensor.
  have hsound :=
    NN.MLTheory.CROWN.Theorems.bound_affine_sound
      (net := toMLP2 w) (xB := xB) (x := vecToTensor x) hx
  -- Extract the scalar bounds at output coordinate 0.
  have hbounds := box_contains_dim1_extract _ _ _ hsound
  -- Bridge to the scalar mlpForward and apply sigmoid monotonicity.
  rw [mlpForward_eq_torchlean]
  exact ⟨sigmoid_monotone hbounds.1, sigmoid_monotone hbounds.2⟩

end Sunbeam.Verify
