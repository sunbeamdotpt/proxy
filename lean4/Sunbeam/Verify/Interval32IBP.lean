import NN.Floats.Interval.IEEEExec32
import NN.Floats.Interval.IEEEExec32AddSoundness
import NN.Floats.IEEEExec.DirectedRoundingSoundness
import NN.Floats.IEEEExec.BridgeFP32Total
import Sunbeam.Model.Basic

namespace Sunbeam.Verify.Interval32IBP

open TorchLean.Floats.IEEE754
open TorchLean.Floats.IEEE754.IEEE32Exec

/-! # Interval32 IBP soundness — IEEE-754 binary32 hardware guarantee

This module proves that an interval-bound-propagation algorithm computed in
TorchLean's executable `Interval32` arithmetic (directed-rounded f32 endpoints)
gives a sound enclosure of the corresponding real-valued forward pass.

The runtime in `src/ensemble/crown.rs` implements outward-rounded f32 IBP
using `next_down`/`next_up` shifts after round-to-nearest. Those shifts cover
the same half-ULP error window that TorchLean's `addDown`/`mulDown` cover via
directed rounding from the start, so the runtime's bounds are at least as
wide as the bounds proven sound here.

End-to-end claim: the certified radii reported by the runtime are sound on
**any** IEEE-754 binary32 implementation (CPU, GPU, FPGA, software libm),
modulo the explicit finiteness side condition on the IBP result.

Hypotheses use endpoint-finiteness pairs (`isFinite x.lo = true ∧
isFinite x.hi = true`) rather than the stronger `Interval32.Valid` (which
also requires the order `le x.lo x.hi`). The order is unused in our proofs;
weakening lets ReLU outputs flow into the next layer without proving an
intermediate IEEE-754 order condition. -/

/-- Lower-side scalar multiplication of an `IEEE32Exec` point weight by an
`Interval32` input. The `wPos` flag selects which endpoint to use: when the
weight is non-negative, `x.lo` is the right endpoint for the lower bound;
otherwise, `x.hi`. -/
@[inline] def scalarMulDown (w : IEEE32Exec) (x : Interval32) (wPos : Bool) : IEEE32Exec :=
  if wPos then mulDown w x.lo else mulDown w x.hi

/-- Upper-side scalar multiplication of an `IEEE32Exec` point weight by an
`Interval32` input. Mirror of `scalarMulDown`. -/
@[inline] def scalarMulUp (w : IEEE32Exec) (x : Interval32) (wPos : Bool) : IEEE32Exec :=
  if wPos then mulUp w x.hi else mulUp w x.lo

/-- Soundness of `scalarMulDown`/`scalarMulUp`: for any real `z` inside the
input interval `x`, and given the caller's `wPos` selection matches the
real-valued sign of the weight, the real product `(toReal w) * z` is enclosed
by `[toEReal (scalarMulDown w x wPos), toEReal (scalarMulUp w x wPos)]`. -/
theorem scalarMul_sound (w : IEEE32Exec) (x : Interval32) (wPos : Bool)
    (hw : isFinite w = true)
    (hxLoFin : isFinite x.lo = true) (hxHiFin : isFinite x.hi = true)
    (hwSign : if wPos then (0 : ℝ) ≤ toReal w else toReal w ≤ 0)
    {z : ℝ} (hz : toReal x.lo ≤ z ∧ z ≤ toReal x.hi) :
    toEReal (scalarMulDown w x wPos) ≤ ((toReal w * z : ℝ) : EReal) ∧
    ((toReal w * z : ℝ) : EReal) ≤ toEReal (scalarMulUp w x wPos) := by
  cases wPos with
  | true =>
    simp only [if_true] at hwSign
    have hzlo : toReal w * toReal x.lo ≤ toReal w * z :=
      mul_le_mul_of_nonneg_left hz.1 hwSign
    have hzhi : toReal w * z ≤ toReal w * toReal x.hi :=
      mul_le_mul_of_nonneg_left hz.2 hwSign
    have hmdLo : toEReal (mulDown w x.lo) ≤ ((toReal w * toReal x.lo : ℝ) : EReal) :=
      toEReal_mulDown_le (x := w) (y := x.lo) hw hxLoFin
    have hmuHi : ((toReal w * toReal x.hi : ℝ) : EReal) ≤ toEReal (mulUp w x.hi) :=
      toEReal_mulUp_ge (x := w) (y := x.hi) hw hxHiFin
    refine ⟨?_, ?_⟩
    · simp only [scalarMulDown, if_true]
      exact le_trans hmdLo ((EReal.coe_le_coe_iff).2 hzlo)
    · simp only [scalarMulUp, if_true]
      exact le_trans ((EReal.coe_le_coe_iff).2 hzhi) hmuHi
  | false =>
    have hzlo : toReal w * toReal x.hi ≤ toReal w * z :=
      mul_le_mul_of_nonpos_left hz.2 hwSign
    have hzhi : toReal w * z ≤ toReal w * toReal x.lo :=
      mul_le_mul_of_nonpos_left hz.1 hwSign
    have hmdHi : toEReal (mulDown w x.hi) ≤ ((toReal w * toReal x.hi : ℝ) : EReal) :=
      toEReal_mulDown_le (x := w) (y := x.hi) hw hxHiFin
    have hmuLo : ((toReal w * toReal x.lo : ℝ) : EReal) ≤ toEReal (mulUp w x.lo) :=
      toEReal_mulUp_ge (x := w) (y := x.lo) hw hxLoFin
    refine ⟨?_, ?_⟩
    · simp only [scalarMulDown]
      exact le_trans hmdHi ((EReal.coe_le_coe_iff).2 hzlo)
    · simp only [scalarMulUp]
      exact le_trans ((EReal.coe_le_coe_iff).2 hzhi) hmuLo

/-! ## IBP step and linear-layer composition

`stepIBP` extends an accumulator with one weighted-input term using
outward-rounded f32 arithmetic. The soundness theorem `stepIBP_sound`
composes `scalarMul_sound` with TorchLean's `toEReal_addDown_le` /
`toEReal_addUp_ge` to show the new accumulator soundly encloses the extended
real-valued partial sum.

Linear-layer soundness follows by induction: instantiate `stepIBP_sound` for
each input dimension, starting from `Interval32.point bias` and folding over
`Fin inputDim`. -/

/-- One IBP step: extend the accumulator with `scalarMul w xB` term. -/
@[inline] def stepIBP (acc : Interval32) (w : IEEE32Exec) (xB : Interval32)
    (wPos : Bool) : Interval32 :=
  ⟨addDown acc.lo (scalarMulDown w xB wPos),
   addUp acc.hi (scalarMulUp w xB wPos)⟩

/-- Bridge: an EReal upper bound by a finite-coercion lifts to a real upper
bound when the value is finite. -/
private lemma toReal_le_of_toEReal_le {x : IEEE32Exec} {S : ℝ}
    (hxFin : isFinite x = true) (h : toEReal x ≤ (S : EReal)) :
    toReal x ≤ S := by
  have hcoe : toEReal x = ((toReal x : ℝ) : EReal) :=
    toEReal_eq_coe_toReal_of_isFinite (x := x) hxFin
  rw [hcoe] at h
  exact (EReal.coe_le_coe_iff).1 h

/-- Bridge: an EReal lower bound by a finite-coercion lifts to a real lower
bound when the value is finite. -/
private lemma le_toReal_of_le_toEReal {x : IEEE32Exec} {S : ℝ}
    (hxFin : isFinite x = true) (h : (S : EReal) ≤ toEReal x) :
    S ≤ toReal x := by
  have hcoe : toEReal x = ((toReal x : ℝ) : EReal) :=
    toEReal_eq_coe_toReal_of_isFinite (x := x) hxFin
  rw [hcoe] at h
  exact (EReal.coe_le_coe_iff).1 h

/-- Soundness of one IBP step: extending the accumulator with `scalarMul w xB`
in directed-rounded f32 produces a new accumulator that soundly encloses the
real-valued partial sum `S + toReal w * z` for any `z ∈ xB`. -/
theorem stepIBP_sound (acc : Interval32) (w : IEEE32Exec) (xB : Interval32)
    (wPos : Bool)
    (hAccLoFin : isFinite acc.lo = true) (hAccHiFin : isFinite acc.hi = true)
    (hw : isFinite w = true)
    (hxLoFin : isFinite xB.lo = true) (hxHiFin : isFinite xB.hi = true)
    (hSmDownFin : isFinite (scalarMulDown w xB wPos) = true)
    (hSmUpFin : isFinite (scalarMulUp w xB wPos) = true)
    (hwSign : if wPos then (0 : ℝ) ≤ toReal w else toReal w ≤ 0)
    {S : ℝ} {z : ℝ} (hz : toReal xB.lo ≤ z ∧ z ≤ toReal xB.hi)
    (hAccBoundLo : toEReal acc.lo ≤ (S : EReal))
    (hAccBoundHi : (S : EReal) ≤ toEReal acc.hi) :
    toEReal (stepIBP acc w xB wPos).lo ≤ ((S + toReal w * z : ℝ) : EReal) ∧
    ((S + toReal w * z : ℝ) : EReal) ≤ toEReal (stepIBP acc w xB wPos).hi := by
  have hsm := scalarMul_sound w xB wPos hw hxLoFin hxHiFin hwSign hz
  have hAccLoR : toReal acc.lo ≤ S :=
    toReal_le_of_toEReal_le hAccLoFin hAccBoundLo
  have hAccHiR : S ≤ toReal acc.hi :=
    le_toReal_of_le_toEReal hAccHiFin hAccBoundHi
  have hSmDownR : toReal (scalarMulDown w xB wPos) ≤ toReal w * z :=
    toReal_le_of_toEReal_le hSmDownFin hsm.1
  have hSmUpR : toReal w * z ≤ toReal (scalarMulUp w xB wPos) :=
    le_toReal_of_le_toEReal hSmUpFin hsm.2
  have hAddDownLe :
      toEReal (addDown acc.lo (scalarMulDown w xB wPos))
        ≤ ((toReal acc.lo + toReal (scalarMulDown w xB wPos) : ℝ) : EReal) :=
    toEReal_addDown_le (x := acc.lo) (y := scalarMulDown w xB wPos) hAccLoFin hSmDownFin
  have hAddUpGe :
      ((toReal acc.hi + toReal (scalarMulUp w xB wPos) : ℝ) : EReal)
        ≤ toEReal (addUp acc.hi (scalarMulUp w xB wPos)) :=
    toEReal_addUp_ge (x := acc.hi) (y := scalarMulUp w xB wPos) hAccHiFin hSmUpFin
  have hLoR : toReal acc.lo + toReal (scalarMulDown w xB wPos) ≤ S + toReal w * z :=
    add_le_add hAccLoR hSmDownR
  have hHiR : S + toReal w * z ≤ toReal acc.hi + toReal (scalarMulUp w xB wPos) :=
    add_le_add hAccHiR hSmUpR
  refine ⟨?_, ?_⟩
  · exact le_trans hAddDownLe ((EReal.coe_le_coe_iff).2 hLoR)
  · exact le_trans ((EReal.coe_le_coe_iff).2 hHiR) hAddUpGe

/-! ## Linear-layer accumulator -/

/-- Recursive linear-layer accumulator: starts at `Interval32.point b` and
extends with `n` weighted-input terms via `stepIBP`. Mirrors the runtime's
per-output-coordinate inner loop in `crown::ibp_linear`. -/
def linearAccum : (n : Nat) → IEEE32Exec → (Fin n → IEEE32Exec) →
    (Fin n → Interval32) → (Fin n → Bool) → Interval32
  | 0, b, _, _, _ => Interval32.point b
  | n+1, b, W, xB, wPos =>
    stepIBP
      (linearAccum n b
        (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc))
      (W (Fin.last n)) (xB (Fin.last n)) (wPos (Fin.last n))

/-- All-intermediates-finite predicate: the accumulator endpoints and each
scalar-mul term remain in the finite f32 range through the full recursion.
This is the natural side condition under which the directed-rounding
soundness lemmas apply at every step. -/
def AllFinite : (n : Nat) → IEEE32Exec → (Fin n → IEEE32Exec) →
    (Fin n → Interval32) → (Fin n → Bool) → Prop
  | 0, b, _, _, _ => isFinite b = true
  | n+1, b, W, xB, wPos =>
    AllFinite n b
      (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc) ∧
    isFinite (linearAccum n b
        (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc)).lo = true ∧
    isFinite (linearAccum n b
        (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc)).hi = true ∧
    isFinite (scalarMulDown (W (Fin.last n)) (xB (Fin.last n)) (wPos (Fin.last n))) = true ∧
    isFinite (scalarMulUp (W (Fin.last n)) (xB (Fin.last n)) (wPos (Fin.last n))) = true

/-- Soundness of the recursive linear-layer accumulator: for any real input
`x` inside the input box, the f32 accumulator endpoints soundly enclose the
real-valued linear forward `(∑ i, W i * x i) + b`. -/
theorem linearAccum_sound : ∀ (n : Nat) (b : IEEE32Exec)
    (W : Fin n → IEEE32Exec) (xB : Fin n → Interval32) (wPos : Fin n → Bool)
    (x : Fin n → ℝ)
    (_hb : isFinite b = true)
    (_hW : ∀ i, isFinite (W i) = true)
    (_hxLoFin : ∀ i, isFinite (xB i).lo = true)
    (_hxHiFin : ∀ i, isFinite (xB i).hi = true)
    (_hwSign : ∀ i, if wPos i then (0 : ℝ) ≤ toReal (W i) else toReal (W i) ≤ 0)
    (_hxRange : ∀ i, toReal (xB i).lo ≤ x i ∧ x i ≤ toReal (xB i).hi)
    (_hAllFin : AllFinite n b W xB wPos),
    toEReal (linearAccum n b W xB wPos).lo ≤
        ((((∑ i : Fin n, toReal (W i) * x i) + toReal b : ℝ) : EReal)) ∧
    (((∑ i : Fin n, toReal (W i) * x i) + toReal b : ℝ) : EReal) ≤
        toEReal (linearAccum n b W xB wPos).hi := by
  intro n
  induction n with
  | zero =>
    intro b _W _xB _wPos _x hb _hW _hxLoFin _hxHiFin _hwSign _hxRange _hAllFin
    simp only [linearAccum, Interval32.point, Fin.sum_univ_zero, zero_add]
    rw [toEReal_eq_coe_toReal_of_isFinite (x := b) hb]
    exact ⟨le_refl _, le_refl _⟩
  | succ k ih =>
    intro b W xB wPos x hb hW hxLoFin hxHiFin hwSign hxRange hAllFin
    obtain ⟨hAllFinPrev, hAccLoFin, hAccHiFin, hSmDownFin, hSmUpFin⟩ := hAllFin
    have ihPrev := ih b
      (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc)
      (fun i => x i.castSucc)
      hb (fun i => hW i.castSucc)
      (fun i => hxLoFin i.castSucc) (fun i => hxHiFin i.castSucc)
      (fun i => hwSign i.castSucc) (fun i => hxRange i.castSucc) hAllFinPrev
    set Sprev : ℝ := (∑ i : Fin k, toReal (W i.castSucc) * x i.castSucc) + toReal b
    have hStep := stepIBP_sound
      (linearAccum k b
        (fun i => W i.castSucc) (fun i => xB i.castSucc) (fun i => wPos i.castSucc))
      (W (Fin.last k)) (xB (Fin.last k)) (wPos (Fin.last k))
      hAccLoFin hAccHiFin
      (hW (Fin.last k))
      (hxLoFin (Fin.last k)) (hxHiFin (Fin.last k))
      hSmDownFin hSmUpFin
      (hwSign (Fin.last k))
      (hxRange (Fin.last k))
      (S := Sprev) (z := x (Fin.last k))
      ihPrev.1 ihPrev.2
    have hsumExpand :
        (∑ i : Fin (k+1), toReal (W i) * x i) + toReal b
          = Sprev + toReal (W (Fin.last k)) * x (Fin.last k) := by
      simp only [Fin.sum_univ_castSucc, Sprev]
      ring
    rw [hsumExpand]
    exact hStep

/-! ## ReLU on Interval32

`reluInterval32` applies pointwise `max(·, 0)` to both endpoints. The
IEEE-754 `maximum` operation is bit-exact on finite inputs (no rounding), so
soundness reduces to `max` monotonicity on ℝ.

We track endpoint finiteness only — the IEEE-754 order condition is
unnecessary for downstream `linearAccum_sound`. -/

/-- ReLU on an `Interval32`: pointwise `max(·, posZero)` on each endpoint. -/
@[inline] def reluInterval32 (x : Interval32) : Interval32 :=
  ⟨maximum x.lo posZero, maximum x.hi posZero⟩

/-- The IEEE-754 binary32 `posZero` is finite. -/
private lemma isFinite_posZero : isFinite (posZero : IEEE32Exec) = true := by
  have hnan : isNaN (posZero : IEEE32Exec) = false := by decide
  have hinf : isInf (posZero : IEEE32Exec) = false := by decide
  exact isFinite_eq_true_of_isNaN_eq_false_of_isInf_eq_false (x := posZero) hnan hinf

/-- ReLU on `Interval32` preserves finiteness of both endpoints. -/
lemma isFinite_reluInterval32 (x : Interval32)
    (hxLoFin : isFinite x.lo = true) (hxHiFin : isFinite x.hi = true) :
    isFinite (reluInterval32 x).lo = true ∧
    isFinite (reluInterval32 x).hi = true := by
  refine ⟨?_, ?_⟩
  · exact isFinite_maximum_of_isFinite (x := x.lo) (y := posZero) hxLoFin isFinite_posZero
  · exact isFinite_maximum_of_isFinite (x := x.hi) (y := posZero) hxHiFin isFinite_posZero

/-- Soundness of `reluInterval32`: for any real `z` enclosed by `x`, the
ReLU-applied endpoints enclose `max(z, 0)`. -/
theorem reluInterval32_sound (x : Interval32)
    (hxLoFin : isFinite x.lo = true) (hxHiFin : isFinite x.hi = true)
    {z : ℝ} (hz : toReal x.lo ≤ z ∧ z ≤ toReal x.hi) :
    toReal (reluInterval32 x).lo ≤ max z 0 ∧
    max z 0 ≤ toReal (reluInterval32 x).hi := by
  have hMaxLo : toReal (maximum x.lo posZero) = max (toReal x.lo) (toReal posZero) :=
    toReal_maximum_eq_max_of_isFinite (x := x.lo) (y := posZero) hxLoFin isFinite_posZero
  have hMaxHi : toReal (maximum x.hi posZero) = max (toReal x.hi) (toReal posZero) :=
    toReal_maximum_eq_max_of_isFinite (x := x.hi) (y := posZero) hxHiFin isFinite_posZero
  refine ⟨?_, ?_⟩
  · simp only [reluInterval32]
    rw [hMaxLo, toReal_posZero]
    exact max_le_max hz.1 le_rfl
  · simp only [reluInterval32]
    rw [hMaxHi, toReal_posZero]
    exact max_le_max hz.2 le_rfl

/-! ## Full 2-layer MLP composition

`mlpInterval32` computes the pre-sigmoid `Interval32` output of a 2-layer MLP
in directed-rounded f32 arithmetic: `linear → relu → linear → scalar output`.
`mlpInterval32_sound` is the trophy theorem: the certified output interval
soundly encloses the real-valued MLP forward on any IEEE-754 binary32
hardware. -/

/-- Real-valued 2-layer MLP pre-sigmoid forward, the comparison target for
`mlpInterval32_sound`. Identical in shape to `Sunbeam.mlpForward` but
operating on `IEEE32Exec`-lifted weights through `toReal`. -/
noncomputable def mlpRealPreSigmoid {inDim hiddenDim : Nat}
    (b1 : Fin hiddenDim → IEEE32Exec) (W1 : Fin hiddenDim → Fin inDim → IEEE32Exec)
    (b2 : IEEE32Exec) (W2 : Fin hiddenDim → IEEE32Exec)
    (x : Fin inDim → ℝ) : ℝ :=
  let preact : Fin hiddenDim → ℝ :=
    fun j => (∑ i : Fin inDim, toReal (W1 j i) * x i) + toReal (b1 j)
  (∑ j : Fin hiddenDim, toReal (W2 j) * max (preact j) 0) + toReal b2

/-- 2-layer MLP forward pass in directed-rounded `Interval32` arithmetic.
Returns the pre-sigmoid scalar output as an `Interval32`. -/
def mlpInterval32 {inDim hiddenDim : Nat}
    (b1 : Fin hiddenDim → IEEE32Exec) (W1 : Fin hiddenDim → Fin inDim → IEEE32Exec)
    (b2 : IEEE32Exec) (W2 : Fin hiddenDim → IEEE32Exec)
    (xB : Fin inDim → Interval32)
    (wPos1 : Fin hiddenDim → Fin inDim → Bool) (wPos2 : Fin hiddenDim → Bool) : Interval32 :=
  let layer1 : Fin hiddenDim → Interval32 :=
    fun j => linearAccum inDim (b1 j) (W1 j) xB (wPos1 j)
  let activated : Fin hiddenDim → Interval32 :=
    fun j => reluInterval32 (layer1 j)
  linearAccum hiddenDim b2 W2 activated wPos2

/-- Soundness of `mlpInterval32`: for any real input `x` inside the input box,
the f32 output interval soundly encloses the real-valued MLP pre-sigmoid
forward. Finite-side conditions track that no intermediate FP operation
overflows; they hold by construction for typical small-weight networks (e.g.
our scanner/DDoS ensembles) and can be checked at runtime by inspecting the
computed `Interval32` endpoints. -/
theorem mlpInterval32_sound {inDim hiddenDim : Nat}
    (b1 : Fin hiddenDim → IEEE32Exec) (W1 : Fin hiddenDim → Fin inDim → IEEE32Exec)
    (b2 : IEEE32Exec) (W2 : Fin hiddenDim → IEEE32Exec)
    (xB : Fin inDim → Interval32)
    (wPos1 : Fin hiddenDim → Fin inDim → Bool) (wPos2 : Fin hiddenDim → Bool)
    (x : Fin inDim → ℝ)
    (hb1 : ∀ j, isFinite (b1 j) = true)
    (hW1 : ∀ j i, isFinite (W1 j i) = true)
    (_hb2 : isFinite b2 = true)
    (_hW2 : ∀ j, isFinite (W2 j) = true)
    (hxLoFin : ∀ i, isFinite (xB i).lo = true)
    (hxHiFin : ∀ i, isFinite (xB i).hi = true)
    (hwSign1 : ∀ j i,
       if wPos1 j i then (0 : ℝ) ≤ toReal (W1 j i) else toReal (W1 j i) ≤ 0)
    (hwSign2 : ∀ j,
       if wPos2 j then (0 : ℝ) ≤ toReal (W2 j) else toReal (W2 j) ≤ 0)
    (hxRange : ∀ i, toReal (xB i).lo ≤ x i ∧ x i ≤ toReal (xB i).hi)
    (hLayer1AllFin : ∀ j, AllFinite inDim (b1 j) (W1 j) xB (wPos1 j))
    (hLayer1OutLoFin :
       ∀ j, isFinite (linearAccum inDim (b1 j) (W1 j) xB (wPos1 j)).lo = true)
    (hLayer1OutHiFin :
       ∀ j, isFinite (linearAccum inDim (b1 j) (W1 j) xB (wPos1 j)).hi = true)
    (hLayer2AllFin :
       AllFinite hiddenDim b2 W2
         (fun j => reluInterval32 (linearAccum inDim (b1 j) (W1 j) xB (wPos1 j)))
         wPos2) :
    toEReal (mlpInterval32 b1 W1 b2 W2 xB wPos1 wPos2).lo
        ≤ ((mlpRealPreSigmoid b1 W1 b2 W2 x : ℝ) : EReal) ∧
    ((mlpRealPreSigmoid b1 W1 b2 W2 x : ℝ) : EReal)
        ≤ toEReal (mlpInterval32 b1 W1 b2 W2 xB wPos1 wPos2).hi := by
  -- Define abbreviated terms for readability
  set layer1 : Fin hiddenDim → Interval32 :=
    fun j => linearAccum inDim (b1 j) (W1 j) xB (wPos1 j) with hlayer1
  set activated : Fin hiddenDim → Interval32 :=
    fun j => reluInterval32 (layer1 j) with hactivated
  set preactReal : Fin hiddenDim → ℝ :=
    fun j => (∑ i : Fin inDim, toReal (W1 j i) * x i) + toReal (b1 j) with hpreact
  set actReal : Fin hiddenDim → ℝ := fun j => max (preactReal j) 0 with hact
  -- Layer 1 EReal-valued soundness for each hidden coord
  have hLayer1 : ∀ j,
      toEReal (layer1 j).lo ≤ ((preactReal j : ℝ) : EReal) ∧
      ((preactReal j : ℝ) : EReal) ≤ toEReal (layer1 j).hi := fun j =>
    linearAccum_sound inDim (b1 j) (W1 j) xB (wPos1 j) x
      (hb1 j) (hW1 j) hxLoFin hxHiFin (hwSign1 j) hxRange (hLayer1AllFin j)
  -- Bridge to real-valued bounds using layer-1 endpoint finiteness
  have hLayer1Real : ∀ j, toReal (layer1 j).lo ≤ preactReal j ∧
                          preactReal j ≤ toReal (layer1 j).hi := fun j =>
    ⟨toReal_le_of_toEReal_le (hLayer1OutLoFin j) (hLayer1 j).1,
     le_toReal_of_le_toEReal (hLayer1OutHiFin j) (hLayer1 j).2⟩
  -- ReLU soundness on each layer-1 output
  have hRelu : ∀ j,
      toReal (activated j).lo ≤ actReal j ∧
      actReal j ≤ toReal (activated j).hi := fun j =>
    reluInterval32_sound (layer1 j) (hLayer1OutLoFin j) (hLayer1OutHiFin j) (hLayer1Real j)
  -- Layer-2 input box (activated) has finite endpoints
  have hActLoFin : ∀ j, isFinite (activated j).lo = true := fun j =>
    (isFinite_reluInterval32 (layer1 j) (hLayer1OutLoFin j) (hLayer1OutHiFin j)).1
  have hActHiFin : ∀ j, isFinite (activated j).hi = true := fun j =>
    (isFinite_reluInterval32 (layer1 j) (hLayer1OutLoFin j) (hLayer1OutHiFin j)).2
  -- Layer 2 EReal-valued soundness via linearAccum_sound on the activated box
  have hLayer2 :=
    linearAccum_sound hiddenDim b2 W2 activated wPos2 actReal
      _hb2 _hW2 hActLoFin hActHiFin hwSign2 hRelu hLayer2AllFin
  -- The result equals mlpRealPreSigmoid by definition; conclude.
  have hSumEq : (∑ j : Fin hiddenDim, toReal (W2 j) * actReal j) + toReal b2
              = mlpRealPreSigmoid b1 W1 b2 W2 x := by
    simp only [mlpRealPreSigmoid, hact, hpreact]
  rw [show mlpInterval32 b1 W1 b2 W2 xB wPos1 wPos2
        = linearAccum hiddenDim b2 W2 activated wPos2 from rfl]
  rw [← hSumEq]
  exact hLayer2

end Sunbeam.Verify.Interval32IBP
