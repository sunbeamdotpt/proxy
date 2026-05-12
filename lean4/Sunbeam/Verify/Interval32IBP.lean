import NN.Floats.Interval.IEEEExec32
import NN.Floats.Interval.IEEEExec32AddSoundness
import NN.Floats.IEEEExec.DirectedRoundingSoundness
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

The kernel theorem is `scalarMul_sound`: multiplying an `IEEE32Exec` point
weight by an `Interval32`-valued input gives a sound enclosure of the real
product. The sign of the weight is passed in as a `Bool` parameter so the
proof avoids bridging IEEE-754 order semantics to ℝ; the caller establishes
the matching real-sign condition once and discharges both branches at the
call site. -/

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
    (hw : isFinite w = true) (hxValid : Interval32.Valid x)
    (hwSign : if wPos then (0 : ℝ) ≤ toReal w else toReal w ≤ 0)
    {z : ℝ} (hz : toReal x.lo ≤ z ∧ z ≤ toReal x.hi) :
    toEReal (scalarMulDown w x wPos) ≤ ((toReal w * z : ℝ) : EReal) ∧
    ((toReal w * z : ℝ) : EReal) ≤ toEReal (scalarMulUp w x wPos) := by
  obtain ⟨hxloFin, hxhiFin, _⟩ := hxValid
  cases wPos with
  | true =>
    simp only [if_true] at hwSign
    have hzlo : toReal w * toReal x.lo ≤ toReal w * z :=
      mul_le_mul_of_nonneg_left hz.1 hwSign
    have hzhi : toReal w * z ≤ toReal w * toReal x.hi :=
      mul_le_mul_of_nonneg_left hz.2 hwSign
    have hmdLo : toEReal (mulDown w x.lo) ≤ ((toReal w * toReal x.lo : ℝ) : EReal) :=
      toEReal_mulDown_le (x := w) (y := x.lo) hw hxloFin
    have hmuHi : ((toReal w * toReal x.hi : ℝ) : EReal) ≤ toEReal (mulUp w x.hi) :=
      toEReal_mulUp_ge (x := w) (y := x.hi) hw hxhiFin
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
      toEReal_mulDown_le (x := w) (y := x.hi) hw hxhiFin
    have hmuLo : ((toReal w * toReal x.lo : ℝ) : EReal) ≤ toEReal (mulUp w x.lo) :=
      toEReal_mulUp_ge (x := w) (y := x.lo) hw hxloFin
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
    (hw : isFinite w = true) (hxValid : Interval32.Valid xB)
    (hSmDownFin : isFinite (scalarMulDown w xB wPos) = true)
    (hSmUpFin : isFinite (scalarMulUp w xB wPos) = true)
    (hwSign : if wPos then (0 : ℝ) ≤ toReal w else toReal w ≤ 0)
    {S : ℝ} {z : ℝ} (hz : toReal xB.lo ≤ z ∧ z ≤ toReal xB.hi)
    (hAccBoundLo : toEReal acc.lo ≤ (S : EReal))
    (hAccBoundHi : (S : EReal) ≤ toEReal acc.hi) :
    toEReal (stepIBP acc w xB wPos).lo ≤ ((S + toReal w * z : ℝ) : EReal) ∧
    ((S + toReal w * z : ℝ) : EReal) ≤ toEReal (stepIBP acc w xB wPos).hi := by
  have hsm := scalarMul_sound w xB wPos hw hxValid hwSign hz
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

end Sunbeam.Verify.Interval32IBP
