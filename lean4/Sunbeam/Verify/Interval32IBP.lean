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

end Sunbeam.Verify.Interval32IBP
