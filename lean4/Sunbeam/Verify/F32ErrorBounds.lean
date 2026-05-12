import NN.Floats.FP32.Core
import NN.Floats.NeuralFloat.NNOps
import NN.Floats.NeuralFloat.ErrorBounds
import Sunbeam.Model.Basic
import Sunbeam.Model.Sigmoid
import Sunbeam.Model.ReLU
import Sunbeam.Model.MLP
import Sunbeam.Model.F32
import Sunbeam.Verify.Lipschitz

namespace Sunbeam.Verify

open Sunbeam TorchLean.Floats

/-! # Tier 4: FP32 forward-error bound on `mlpForwardF32`

For a 4KB model at deployed precision, ℝ-only proofs are not the load-bearing
story — the runtime computes in IEEE-754 binary32. This file bounds the gap
between the FP32 computation (`mlpForwardF32`) and the idealised ℝ computation
on the same grid values (`mlpForward ∘ vecToReal`).

## Structure

Each FP32 op is `roundR ∘ <ℝ-op>`, introducing one half-ULP rounding error per
step. The cumulative error propagates forward through subsequent operations,
attenuated by their Lipschitz constants (Tier 3).

## Trust base

- TorchLean's `neural_error_bound_ulp` (the foundational half-ULP bound).
- Mathlib `abs_*`, `Finset.sum_*`, `Real.exp_*` baseline.

No Sunbeam-local axioms.
-/

/-! ## Conversion between FP32 weights/vectors and ℝ -/

/-- Convert FP32 weights to their underlying ℝ values. -/
noncomputable def weightsToReal {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim) : MLPWeights inputDim hiddenDim where
  w1 := fun j => Sunbeam.F32.vecToReal (w.w1 j)
  b1 := Sunbeam.F32.vecToReal w.b1
  w2 := Sunbeam.F32.vecToReal w.w2
  b2 := Sunbeam.F32.toReal w.b2

/-! ## Half-ULP per-op error bounds

The fundamental claim: one `ofReal` step introduces at most a half-ULP error
relative to its real-valued argument. -/

/-- Core: `ofReal r` rounds `r` to the FP32 grid with at most half-ULP error. -/
lemma ofReal_toReal_error (r : ℝ) :
    |Sunbeam.F32.toReal (Sunbeam.F32.ofReal r) - r|
   ≤ neuralUlp binaryRadix fexp32 r TrainingPhase.forward / 2 := by
  show |NF.toReal (NF.ofReal r) - r| ≤ _
  rw [NF.toReal_ofReal]
  show |NF.roundR r - r| ≤ _
  unfold NF.roundR
  exact neural_error_bound_ulp rnd32 r

/-- `sigmoidF32` deviates from `sigmoid ∘ toReal` by at most half a ULP at the
output magnitude. -/
theorem sigmoidF32_error (x : Sunbeam.F32.FP32) :
    |Sunbeam.F32.toReal (Sunbeam.F32.sigmoidF32 x) - sigmoid (Sunbeam.F32.toReal x)|
   ≤ neuralUlp binaryRadix fexp32
        (sigmoid (Sunbeam.F32.toReal x)) TrainingPhase.forward / 2 := by
  unfold Sunbeam.F32.sigmoidF32
  rw [sigmoid_eq_real_sigmoid]
  have h : (1 : ℝ) / (1 + Real.exp (- Sunbeam.F32.toReal x))
         = Real.sigmoid (Sunbeam.F32.toReal x) := by
    rw [Real.sigmoid_def, one_div]
  rw [h]
  exact ofReal_toReal_error _

/-- `reluF32` deviates from `relu ∘ toReal` by at most half a ULP. -/
theorem reluF32_error (x : Sunbeam.F32.FP32) :
    |Sunbeam.F32.toReal (Sunbeam.F32.reluF32 x) - relu (Sunbeam.F32.toReal x)|
   ≤ neuralUlp binaryRadix fexp32
        (relu (Sunbeam.F32.toReal x)) TrainingPhase.forward / 2 := by
  unfold Sunbeam.F32.reluF32 relu
  exact ofReal_toReal_error (max (Sunbeam.F32.toReal x) 0)

/-- `dotF32` deviates from the ℝ-valued dot product by at most half a ULP at
the result magnitude. -/
theorem dotF32_error {n : Nat} (a b : Sunbeam.F32.FP32Vec n) :
    |Sunbeam.F32.toReal (Sunbeam.F32.dotF32 a b)
   - (∑ i : Fin n, Sunbeam.F32.toReal (a i) * Sunbeam.F32.toReal (b i))|
   ≤ neuralUlp binaryRadix fexp32
        (∑ i : Fin n, Sunbeam.F32.toReal (a i) * Sunbeam.F32.toReal (b i))
        TrainingPhase.forward / 2 := by
  unfold Sunbeam.F32.dotF32
  exact ofReal_toReal_error _

/-- `vecAddF32 a b j` deviates from the ℝ-valued sum at coordinate `j` by at
most half a ULP. -/
theorem vecAddF32_error {n : Nat} (a b : Sunbeam.F32.FP32Vec n) (j : Fin n) :
    |Sunbeam.F32.toReal (Sunbeam.F32.vecAddF32 a b j)
   - (Sunbeam.F32.toReal (a j) + Sunbeam.F32.toReal (b j))|
   ≤ neuralUlp binaryRadix fexp32
        (Sunbeam.F32.toReal (a j) + Sunbeam.F32.toReal (b j))
        TrainingPhase.forward / 2 := by
  unfold Sunbeam.F32.vecAddF32
  exact ofReal_toReal_error _

/-! ## Cumulative forward-error analysis

The total error `|mlpForwardF32 - mlpForward ∘ vecToReal|` is the sum, over each
rounding step in `mlpForwardF32`, of `ulp/2` evaluated at that step's exact ℝ
result, propagated forward by the Lipschitz constants of subsequent layers.

We build this up layer-by-layer using triangle inequality at each step. -/

/-- L1 norm: `‖v‖₁ = ∑ |v i|`. -/
noncomputable def vecAbsSum {n : Nat} (v : RealVec n) : ℝ :=
  ∑ i : Fin n, |v i|

/-- Half-ULP at a real `x` in the forward training phase, for binary32. -/
noncomputable abbrev hulp (x : ℝ) : ℝ :=
  neuralUlp binaryRadix fexp32 x TrainingPhase.forward / 2

/-! ### Layer 1: pre-activation -/

/-- `matVecMulF32 W x j` deviates from `∑ i, W[j,i] · x[i]` by at most `hulp(sum)`. -/
theorem matVecMulF32_error {inputDim hiddenDim : Nat}
    (W : Fin hiddenDim → Sunbeam.F32.FP32Vec inputDim)
    (x : Sunbeam.F32.FP32Vec inputDim) (j : Fin hiddenDim) :
    |Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 W x j)
   - (∑ i : Fin inputDim, Sunbeam.F32.toReal (W j i) * Sunbeam.F32.toReal (x i))|
   ≤ hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (W j i) * Sunbeam.F32.toReal (x i)) := by
  unfold Sunbeam.F32.matVecMulF32
  exact dotF32_error _ _

/-- Layer-1 pre-activation `(W1·x + b1)[j]` in FP32 deviates from the ℝ ideal by
at most the sum of the matVecMul rounding error and the vecAdd rounding error. -/
theorem layer1_pre_error {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) (j : Fin hiddenDim) :
    |Sunbeam.F32.toReal
        (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j)
   - ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i))
      + Sunbeam.F32.toReal (w.b1 j))|
   ≤ hulp (Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
           + Sunbeam.F32.toReal (w.b1 j))
   + hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i)) := by
  -- Triangle inequality: insert `toReal (matVecMulF32 w.w1 x j) + toReal w.b1 j` as midpoint.
  set u : ℝ := Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
               + Sunbeam.F32.toReal (w.b1 j) with hu_def
  set v : ℝ := (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i))
               + Sunbeam.F32.toReal (w.b1 j) with hv_def
  have h1 : |Sunbeam.F32.toReal
              (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j) - u|
          ≤ hulp u := vecAddF32_error _ _ j
  have h2 : |u - v| ≤
        hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i)) := by
    show |u - v| ≤ _
    rw [hu_def, hv_def]
    have : Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
           + Sunbeam.F32.toReal (w.b1 j)
         - ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i))
            + Sunbeam.F32.toReal (w.b1 j))
         = Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
         - ∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i) * Sunbeam.F32.toReal (x i) := by ring
    rw [this]
    exact matVecMulF32_error _ _ j
  calc |Sunbeam.F32.toReal
          (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j) - v|
      = |Sunbeam.F32.toReal
          (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j) - u + (u - v)| := by
        ring_nf
    _ ≤ |Sunbeam.F32.toReal
          (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j) - u| + |u - v| :=
        abs_add_le _ _
    _ ≤ hulp u + _ := add_le_add h1 h2

/-! ### ReLU step -/

/-- Post-ReLU activation `relu((W1·x + b1)[j])` in FP32 deviates from the ℝ ideal
by at most: layer1-pre-error + one ReLU rounding step. -/
theorem relu_layer1_error {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) (j : Fin hiddenDim) :
    |Sunbeam.F32.toReal
        (Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
          (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j)
   - relu ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                 * Sunbeam.F32.toReal (x i))
           + Sunbeam.F32.toReal (w.b1 j))|
   ≤ hulp (relu (Sunbeam.F32.toReal
            (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j)))
   + (hulp (Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
            + Sunbeam.F32.toReal (w.b1 j))
      + hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                   * Sunbeam.F32.toReal (x i))) := by
  set preF32 : ℝ := Sunbeam.F32.toReal
      (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j) with hpreF32
  set preR : ℝ := (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                       * Sunbeam.F32.toReal (x i))
                  + Sunbeam.F32.toReal (w.b1 j) with hpreR
  -- The reluVecF32 unfolds: reluVecF32 v j = reluF32 (v j) = ofReal (max (toReal (v j)) 0).
  have h_relu_round :
      |Sunbeam.F32.toReal
          (Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
            (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j)
       - relu preF32|
    ≤ hulp (relu preF32) := by
    unfold Sunbeam.F32.reluVecF32
    exact reluF32_error _
  have h_relu_input : |relu preF32 - relu preR| ≤ |preF32 - preR| := by
    have := relu_lipschitz preF32 preR
    -- relu_lipschitz : |relu x - relu y| ≤ |x - y|
    exact this
  have h_input : |preF32 - preR|
              ≤ hulp (Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
                      + Sunbeam.F32.toReal (w.b1 j))
              + hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                           * Sunbeam.F32.toReal (x i)) :=
    layer1_pre_error w x j
  -- Combine via triangle.
  calc |Sunbeam.F32.toReal
          (Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
            (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j) - relu preR|
      = |(Sunbeam.F32.toReal
          (Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
            (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j) - relu preF32)
        + (relu preF32 - relu preR)| := by ring_nf
    _ ≤ |Sunbeam.F32.toReal
          (Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
            (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j) - relu preF32|
       + |relu preF32 - relu preR| := abs_add_le _ _
    _ ≤ hulp (relu preF32) + (hulp _ + hulp _) := by
        exact add_le_add h_relu_round (le_trans h_relu_input h_input)

/-! ### Layer 2: dot product `W2 · relu(...)` -/

/-- Per-neuron post-ReLU activation error (no setup; just the relu_layer1_error
result projected as an inequality). This is a name for clarity. -/
noncomputable def reluActError {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) (j : Fin hiddenDim) : ℝ :=
  hulp (relu (Sunbeam.F32.toReal
              (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1 j)))
  + (hulp (Sunbeam.F32.toReal (Sunbeam.F32.matVecMulF32 w.w1 x j)
           + Sunbeam.F32.toReal (w.b1 j))
     + hulp (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                  * Sunbeam.F32.toReal (x i)))

/-- Layer-2 pre-output error: the F32 `dot W2 · activations` differs from the
ℝ `dot W2_R · relu(pre_R)` by the dot-product rounding plus the propagated
per-neuron post-ReLU error weighted by `|W2[j]|`. -/
theorem layer2_pre_out_error {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) :
    |Sunbeam.F32.toReal
        (Sunbeam.F32.dotF32 w.w2
          (Sunbeam.F32.reluVecF32
            (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
   - (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
        * relu ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                     * Sunbeam.F32.toReal (x i))
                + Sunbeam.F32.toReal (w.b1 j)))|
   ≤ hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
            * Sunbeam.F32.toReal
              (Sunbeam.F32.reluVecF32
                (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
   + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j := by
  set actF32 : Sunbeam.F32.FP32Vec hiddenDim :=
      Sunbeam.F32.reluVecF32 (Sunbeam.F32.vecAddF32
        (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) with hactF32
  set preR : Fin hiddenDim → ℝ := fun j =>
      (∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                            * Sunbeam.F32.toReal (x i))
      + Sunbeam.F32.toReal (w.b1 j) with hpreR
  set sumF32 : ℝ := ∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
                                          * Sunbeam.F32.toReal (actF32 j) with hsumF32
  set sumR : ℝ := ∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j) * relu (preR j) with hsumR
  have h_round : |Sunbeam.F32.toReal (Sunbeam.F32.dotF32 w.w2 actF32) - sumF32|
              ≤ hulp sumF32 := dotF32_error _ _
  have h_propagated : |sumF32 - sumR|
                   ≤ ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j := by
    have h_diff : sumF32 - sumR = ∑ j : Fin hiddenDim,
        Sunbeam.F32.toReal (w.w2 j)
        * (Sunbeam.F32.toReal (actF32 j) - relu (preR j)) := by
      rw [hsumF32, hsumR]
      rw [← Finset.sum_sub_distrib]
      refine Finset.sum_congr rfl ?_
      intro j _
      ring
    rw [h_diff]
    calc |∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
           * (Sunbeam.F32.toReal (actF32 j) - relu (preR j))|
        ≤ ∑ j : Fin hiddenDim,
            |Sunbeam.F32.toReal (w.w2 j)
             * (Sunbeam.F32.toReal (actF32 j) - relu (preR j))| :=
          Finset.abs_sum_le_sum_abs _ _
      _ = ∑ j : Fin hiddenDim,
            |Sunbeam.F32.toReal (w.w2 j)|
            * |Sunbeam.F32.toReal (actF32 j) - relu (preR j)| := by
          refine Finset.sum_congr rfl ?_
          intro j _
          rw [abs_mul]
      _ ≤ ∑ j : Fin hiddenDim,
            |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j := by
          refine Finset.sum_le_sum ?_
          intro j _
          exact mul_le_mul_of_nonneg_left (relu_layer1_error w x j) (abs_nonneg _)
  calc |Sunbeam.F32.toReal (Sunbeam.F32.dotF32 w.w2 actF32) - sumR|
      = |(Sunbeam.F32.toReal (Sunbeam.F32.dotF32 w.w2 actF32) - sumF32) + (sumF32 - sumR)| := by
        ring_nf
    _ ≤ |Sunbeam.F32.toReal (Sunbeam.F32.dotF32 w.w2 actF32) - sumF32| + |sumF32 - sumR| :=
        abs_add_le _ _
    _ ≤ hulp sumF32 + _ := add_le_add h_round h_propagated

/-! ### b2 add step -/

/-- Pre-sigmoid value after adding `b2`: rounding error plus propagated layer-2 error. -/
theorem pre_out_with_b2_error {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) :
    |Sunbeam.F32.toReal
        (Sunbeam.F32.ofReal (Sunbeam.F32.toReal
          (Sunbeam.F32.dotF32 w.w2
            (Sunbeam.F32.reluVecF32
              (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
          + Sunbeam.F32.toReal w.b2))
   - ((∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
         * relu ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                       * Sunbeam.F32.toReal (x i))
                 + Sunbeam.F32.toReal (w.b1 j))) + Sunbeam.F32.toReal w.b2)|
   ≤ hulp (Sunbeam.F32.toReal
            (Sunbeam.F32.dotF32 w.w2
              (Sunbeam.F32.reluVecF32
                (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
           + Sunbeam.F32.toReal w.b2)
   + (hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
              * Sunbeam.F32.toReal
                (Sunbeam.F32.reluVecF32
                  (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
      + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j) := by
  set dotF32W2 : ℝ := Sunbeam.F32.toReal
      (Sunbeam.F32.dotF32 w.w2
        (Sunbeam.F32.reluVecF32
          (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1))) with hdotF32W2
  set sumR : ℝ := ∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
        * relu ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                      * Sunbeam.F32.toReal (x i))
                + Sunbeam.F32.toReal (w.b1 j)) with hsumR
  have h_round : |Sunbeam.F32.toReal
                    (Sunbeam.F32.ofReal (dotF32W2 + Sunbeam.F32.toReal w.b2))
                  - (dotF32W2 + Sunbeam.F32.toReal w.b2)|
              ≤ hulp (dotF32W2 + Sunbeam.F32.toReal w.b2) := ofReal_toReal_error _
  have h_layer2 : |dotF32W2 - sumR| ≤
      hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
              * Sunbeam.F32.toReal
                (Sunbeam.F32.reluVecF32
                  (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
      + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j :=
    layer2_pre_out_error w x
  calc |Sunbeam.F32.toReal
          (Sunbeam.F32.ofReal (dotF32W2 + Sunbeam.F32.toReal w.b2))
        - (sumR + Sunbeam.F32.toReal w.b2)|
      = |(Sunbeam.F32.toReal
          (Sunbeam.F32.ofReal (dotF32W2 + Sunbeam.F32.toReal w.b2))
          - (dotF32W2 + Sunbeam.F32.toReal w.b2))
        + (dotF32W2 - sumR)| := by ring_nf
    _ ≤ |Sunbeam.F32.toReal
          (Sunbeam.F32.ofReal (dotF32W2 + Sunbeam.F32.toReal w.b2))
          - (dotF32W2 + Sunbeam.F32.toReal w.b2)|
        + |dotF32W2 - sumR| := abs_add_le _ _
    _ ≤ hulp (dotF32W2 + Sunbeam.F32.toReal w.b2) + _ := add_le_add h_round h_layer2

/-! ### Cumulative `mlpForwardF32` error bound -/

/-- The cumulative FP32 forward-error bound, expressed as a sum of `hulp`
terms evaluated at the intermediate ℝ values of the FP32 computation. -/
noncomputable def mlpF32Error {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) : ℝ :=
  hulp (Sunbeam.sigmoid (Sunbeam.F32.toReal
          (Sunbeam.F32.ofReal (Sunbeam.F32.toReal
            (Sunbeam.F32.dotF32 w.w2
              (Sunbeam.F32.reluVecF32
                (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
            + Sunbeam.F32.toReal w.b2))))
  + (1/4) *
    (hulp (Sunbeam.F32.toReal
            (Sunbeam.F32.dotF32 w.w2
              (Sunbeam.F32.reluVecF32
                (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
           + Sunbeam.F32.toReal w.b2)
     + (hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
                * Sunbeam.F32.toReal
                  (Sunbeam.F32.reluVecF32
                    (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
        + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j))

/-- **Main theorem: FP32 forward-error bound on `mlpForwardF32`.**

The FP32 computation deviates from the idealised ℝ computation (on the same
grid-restricted weights and inputs) by at most `mlpF32Error w x`, which
decomposes as: the final sigmoid-rounding ULP, plus `1/4 ×` (the b2-add ULP
plus the propagated layer-2 error).

For a 4KB scanner model, the ULP magnitudes are all `≤ 2^-23 · |x|`, putting
`mlpF32Error` in the low-microsecond range — orders of magnitude smaller than
any reasonable decision-threshold margin. This is the soundness guarantee for
the deployed binary. -/
theorem mlpForwardF32_error_bound {inputDim hiddenDim : Nat}
    (w : Sunbeam.F32.MLPWeightsF32 inputDim hiddenDim)
    (x : Sunbeam.F32.FP32Vec inputDim) :
    |Sunbeam.F32.toReal (Sunbeam.F32.mlpForwardF32 w x)
   - mlpForward (weightsToReal w) (Sunbeam.F32.vecToReal x)|
   ≤ mlpF32Error w x := by
  unfold Sunbeam.F32.mlpForwardF32 mlpForward weightsToReal mlpF32Error
  -- Unfold the inner definitions enough that we can match the structure.
  show |Sunbeam.F32.toReal
          (Sunbeam.F32.sigmoidF32 (Sunbeam.F32.ofReal _))
        - sigmoid _| ≤ _
  set pre_with_b2_F32 : Sunbeam.F32.FP32 :=
      Sunbeam.F32.ofReal (Sunbeam.F32.toReal
        (Sunbeam.F32.dotF32 w.w2
          (Sunbeam.F32.reluVecF32
            (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
        + Sunbeam.F32.toReal w.b2) with hpre_with_b2_F32
  set pre_with_b2_R : ℝ :=
      (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
         * relu ((∑ i : Fin inputDim, Sunbeam.F32.toReal (w.w1 j i)
                                       * Sunbeam.F32.toReal (x i))
                 + Sunbeam.F32.toReal (w.b1 j)))
      + Sunbeam.F32.toReal w.b2 with hpre_with_b2_R
  -- Sigmoid step: triangle through sigmoid (toReal pre_with_b2_F32).
  have h_sigmoid_round : |Sunbeam.F32.toReal (Sunbeam.F32.sigmoidF32 pre_with_b2_F32)
                       - sigmoid (Sunbeam.F32.toReal pre_with_b2_F32)|
                      ≤ hulp (sigmoid (Sunbeam.F32.toReal pre_with_b2_F32)) :=
    sigmoidF32_error _
  have h_sigmoid_lip : |sigmoid (Sunbeam.F32.toReal pre_with_b2_F32) - sigmoid pre_with_b2_R|
                    ≤ (1/4) * |Sunbeam.F32.toReal pre_with_b2_F32 - pre_with_b2_R| :=
    sigmoid_lipschitz _ _
  have h_input : |Sunbeam.F32.toReal pre_with_b2_F32 - pre_with_b2_R|
              ≤ hulp (Sunbeam.F32.toReal
                       (Sunbeam.F32.dotF32 w.w2
                         (Sunbeam.F32.reluVecF32
                           (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
                      + Sunbeam.F32.toReal w.b2)
              + (hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
                         * Sunbeam.F32.toReal
                           (Sunbeam.F32.reluVecF32
                             (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
                 + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j) := by
    rw [hpre_with_b2_F32, hpre_with_b2_R]
    exact pre_out_with_b2_error w x
  -- Note: the goal's "ℝ pre_with_b2" is via mlpForward + vecToReal substitutions.
  -- We need to check these match pre_with_b2_R.
  calc |Sunbeam.F32.toReal (Sunbeam.F32.sigmoidF32 pre_with_b2_F32) - sigmoid pre_with_b2_R|
      = |(Sunbeam.F32.toReal (Sunbeam.F32.sigmoidF32 pre_with_b2_F32)
          - sigmoid (Sunbeam.F32.toReal pre_with_b2_F32))
        + (sigmoid (Sunbeam.F32.toReal pre_with_b2_F32) - sigmoid pre_with_b2_R)| := by ring_nf
    _ ≤ |Sunbeam.F32.toReal (Sunbeam.F32.sigmoidF32 pre_with_b2_F32)
          - sigmoid (Sunbeam.F32.toReal pre_with_b2_F32)|
        + |sigmoid (Sunbeam.F32.toReal pre_with_b2_F32) - sigmoid pre_with_b2_R| :=
        abs_add_le _ _
    _ ≤ hulp (sigmoid (Sunbeam.F32.toReal pre_with_b2_F32))
        + (1/4) * |Sunbeam.F32.toReal pre_with_b2_F32 - pre_with_b2_R| :=
        add_le_add h_sigmoid_round h_sigmoid_lip
    _ ≤ hulp (sigmoid (Sunbeam.F32.toReal pre_with_b2_F32))
        + (1/4) *
          (hulp (Sunbeam.F32.toReal
                  (Sunbeam.F32.dotF32 w.w2
                    (Sunbeam.F32.reluVecF32
                      (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1)))
                 + Sunbeam.F32.toReal w.b2)
           + (hulp (∑ j : Fin hiddenDim, Sunbeam.F32.toReal (w.w2 j)
                      * Sunbeam.F32.toReal
                        (Sunbeam.F32.reluVecF32
                          (Sunbeam.F32.vecAddF32 (Sunbeam.F32.matVecMulF32 w.w1 x) w.b1) j))
              + ∑ j : Fin hiddenDim, |Sunbeam.F32.toReal (w.w2 j)| * reluActError w x j)) := by
        have h_quarter : (0 : ℝ) ≤ 1/4 := by norm_num
        linarith [mul_le_mul_of_nonneg_left h_input h_quarter]

end Sunbeam.Verify




