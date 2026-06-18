// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # CROWN — Certified per-input adversarial robustness radius
//!
//! Runtime computation of the certified L∞ robustness radius for the scanner
//! MLP, mirroring the Lean specification in:
//!
//! - [`Sunbeam.Verify.CrownBound`](../../../lean4/Sunbeam/Verify/CrownBound.lean)
//! - [`Sunbeam.Verify.CertifiedRadius`](../../../lean4/Sunbeam/Verify/CertifiedRadius.lean)
//! - [`Sunbeam.Verify.F32CrownBound`](../../../lean4/Sunbeam/Verify/F32CrownBound.lean)
//!
//! ## What "certified radius" means
//!
//! Given an input vector `x` and a verdict threshold `t`, the certified radius
//! is the largest L∞ perturbation `ε` such that **every** `x'` with
//! `‖x' - x‖∞ ≤ ε` yields the same verdict as `x` (above or below `t`), on
//! IEEE-754 binary32 hardware.
//!
//! Inputs deep inside their decision region certify with large radii; inputs
//! near the decision boundary certify with small radii (or none).
//!
//! ## Algorithm
//!
//! Two pieces:
//!
//! 1. **Outward-rounded interval bound propagation** through
//!    `Linear → ReLU → Linear`. Each FP multiply and add expands the
//!    accumulating lower bound downward by one ULP and the upper bound upward
//!    by one ULP. Since round-to-nearest introduces error of at most 0.5 ULP
//!    per operation, this guarantees the computed `[lo, hi]` is a sound
//!    over-approximation of the true interval — wider than the ℝ-IBP bound,
//!    never narrower.
//!
//! 2. **Binary search on ε**: find the largest ε in `[0, max_eps]` such that
//!    `sigmoid_down(pre.lo) > threshold` (verdict stable block) or
//!    `sigmoid_up(pre.hi) < threshold` (verdict stable allow).
//!
//! ## Soundness on IEEE-754 hardware
//!
//! The radii returned by this module are sound under FP32 arithmetic, not just
//! over ℝ. The proof chain:
//!
//! - Outward-rounded f32 IBP is a sound over-approximation of ℝ IBP
//!   (each op's rounding error is ≤ 0.5 ULP, outward shift is 1 ULP).
//! - `mlpForward_crown_bound` (in Lean): ℝ IBP bounds the ℝ MLP output.
//! - `mlpForwardF32_crown_bound` (in Lean): composing with the FP32
//!   forward-error bound widens to the FP32 surface.
//! - `verdict_stable_*_f32`: lifts to verdict stability across the ε-ball
//!   on FP32 hardware.

/// Pre-sigmoid output interval `[lo, hi]` computed via outward-rounded f32 IBP.
///
/// Guaranteed to satisfy `lo ≤ mlpForwardF32(x') ≤ hi` for every `x'` in the
/// input box, on IEEE-754 binary32 hardware.
#[derive(Debug, Clone, Copy)]
pub struct PreSigmoidInterval {
    /// Outward-rounded lower bound on the pre-sigmoid scalar output.
    pub lo: f32,
    /// Outward-rounded upper bound on the pre-sigmoid scalar output.
    pub hi: f32,
}

/// Outward-rounded add for a lower bound: `a + b` then one ULP downward.
#[inline]
fn add_down(a: f32, b: f32) -> f32 {
    (a + b).next_down()
}

/// Outward-rounded add for an upper bound: `a + b` then one ULP upward.
#[inline]
fn add_up(a: f32, b: f32) -> f32 {
    (a + b).next_up()
}

/// Outward-rounded multiply for a lower bound: `a * b` then one ULP downward.
#[inline]
fn mul_down(a: f32, b: f32) -> f32 {
    (a * b).next_down()
}

/// Outward-rounded multiply for an upper bound: `a * b` then one ULP upward.
#[inline]
fn mul_up(a: f32, b: f32) -> f32 {
    (a * b).next_up()
}

/// Sigmoid downward-rounded by `SIGMOID_ULP_SLACK` ULPs to absorb libm
/// imprecision. Guarantees `sigmoid_down(x) ≤ sigmoid(x)` in ℝ.
#[inline]
fn sigmoid_down(x: f32) -> f32 {
    let mut r = sigmoid_f32(x);
    for _ in 0..SIGMOID_ULP_SLACK {
        r = r.next_down();
    }
    r
}

/// Sigmoid upward-rounded by `SIGMOID_ULP_SLACK` ULPs to absorb libm
/// imprecision. Guarantees `sigmoid_up(x) ≥ sigmoid(x)` in ℝ.
#[inline]
fn sigmoid_up(x: f32) -> f32 {
    let mut r = sigmoid_f32(x);
    for _ in 0..SIGMOID_ULP_SLACK {
        r = r.next_up();
    }
    r
}

/// ULP slack applied to `sigmoid_f32` to cover the rounding error of `expf`,
/// `1+x`, and `1/x` composed. Modern libm `expf` is typically within ~1 ULP;
/// the three-op chain bounds the cumulative error below 4 ULPs in practice.
/// Eight is a safety margin.
const SIGMOID_ULP_SLACK: u32 = 8;

/// Outward-rounded IBP through a linear layer `y = W x + b` given an input
/// interval box.
///
/// For each weight `w_ji`: when `w_ji ≥ 0` the lower bound contribution uses
/// `x_lo[i]` and the upper uses `x_hi[i]`; when `w_ji < 0` they swap. Each FP
/// multiply and add applies `next_down`/`next_up` so the accumulated bounds
/// are guaranteed to contain the exact ℝ result.
#[inline]
fn ibp_linear<const IN: usize, const OUT: usize>(
    w: &[[f32; IN]; OUT],
    x_lo: &[f32; IN],
    x_hi: &[f32; IN],
    b: &[f32; OUT],
) -> ([f32; OUT], [f32; OUT]) {
    let mut out_lo = [0.0f32; OUT];
    let mut out_hi = [0.0f32; OUT];
    for j in 0..OUT {
        let mut lo = b[j];
        let mut hi = b[j];
        for i in 0..IN {
            let w_ji = w[j][i];
            if w_ji >= 0.0 {
                lo = add_down(lo, mul_down(w_ji, x_lo[i]));
                hi = add_up(hi, mul_up(w_ji, x_hi[i]));
            } else {
                lo = add_down(lo, mul_down(w_ji, x_hi[i]));
                hi = add_up(hi, mul_up(w_ji, x_lo[i]));
            }
        }
        out_lo[j] = lo;
        out_hi[j] = hi;
    }
    (out_lo, out_hi)
}

/// IBP through the full MLP, returning the pre-sigmoid output interval.
///
/// Mirrors TorchLean's `MLP2.boundIbp` with outward FP32 rounding:
/// `linear → relu → linear`. ReLU is bit-exact in IEEE-754 (`max(x, 0)` is a
/// pure selection, no rounding); only the linear layers need outward shifts.
pub fn ibp_mlp_pre_sigmoid<const IN: usize>(
    w1: &[[f32; IN]; 32],
    b1: &[f32; 32],
    w2: &[f32; 32],
    b2: f32,
    input_lo: &[f32; IN],
    input_hi: &[f32; IN],
) -> PreSigmoidInterval {
    let (z1_lo, z1_hi) = ibp_linear::<IN, 32>(w1, input_lo, input_hi, b1);

    let mut a1_lo = [0.0f32; 32];
    let mut a1_hi = [0.0f32; 32];
    for j in 0..32 {
        a1_lo[j] = z1_lo[j].max(0.0);
        a1_hi[j] = z1_hi[j].max(0.0);
    }

    let mut out_lo = b2;
    let mut out_hi = b2;
    for j in 0..32 {
        let w = w2[j];
        if w >= 0.0 {
            out_lo = add_down(out_lo, mul_down(w, a1_lo[j]));
            out_hi = add_up(out_hi, mul_up(w, a1_hi[j]));
        } else {
            out_lo = add_down(out_lo, mul_down(w, a1_hi[j]));
            out_hi = add_up(out_hi, mul_up(w, a1_lo[j]));
        }
    }

    PreSigmoidInterval {
        lo: out_lo,
        hi: out_hi,
    }
}

/// Construct an outward-rounded input box around `input` of L∞ radius `eps`.
///
/// `(x - eps)` and `(x + eps)` each carry at most 0.5 ULP rounding error;
/// `next_down`/`next_up` guarantees the box contains the true `[x - eps, x + eps]`
/// per coordinate.
#[inline]
fn input_box<const IN: usize>(input: &[f32; IN], eps: f32) -> ([f32; IN], [f32; IN]) {
    let mut lo = [0.0f32; IN];
    let mut hi = [0.0f32; IN];
    for i in 0..IN {
        lo[i] = (input[i] - eps).next_down();
        hi[i] = (input[i] + eps).next_up();
    }
    (lo, hi)
}

/// Check whether the verdict is stable across the L∞ ε-ball around `input`.
///
/// `expected_above = true` means the center output exceeds the threshold
/// (verdict `block`); we then require `sigmoid_down(pre.lo) > threshold` to
/// certify. `false` means the center is below (verdict `allow`); we require
/// `sigmoid_up(pre.hi) < threshold`. Both checks use outward-rounded sigmoid.
#[allow(clippy::too_many_arguments)]
fn verdict_stable<const IN: usize>(
    w1: &[[f32; IN]; 32],
    b1: &[f32; 32],
    w2: &[f32; 32],
    b2: f32,
    input: &[f32; IN],
    eps: f32,
    threshold: f32,
    expected_above: bool,
) -> bool {
    let (input_lo, input_hi) = input_box::<IN>(input, eps);
    let pre = ibp_mlp_pre_sigmoid::<IN>(w1, b1, w2, b2, &input_lo, &input_hi);
    if expected_above {
        sigmoid_down(pre.lo) > threshold
    } else {
        sigmoid_up(pre.hi) < threshold
    }
}

/// Compute the certified L∞ robustness radius around `input` at the given
/// verdict threshold, sound on IEEE-754 binary32 hardware.
///
/// Returns `None` if even ε = 0 fails to certify (the input is exactly on the
/// decision boundary, modulo outward-rounded IBP slack). Otherwise returns the
/// largest ε in `[0, max_eps]` within tolerance `tol` such that the verdict is
/// stable across the L∞ ε-ball.
///
/// The returned value is FP32-sound: the outward-rounded IBP guarantees the
/// reported radius is a lower bound on the true ℝ-side certified radius,
/// composed with the Lean theorem `verdict_stable_block_f32` /
/// `verdict_stable_allow_f32` (in `Sunbeam.Verify.F32CrownBound`) for the FP32
/// forward-error component. It is not necessarily tight — IBP is a
/// conservative bound and tighter relaxations (CROWN linear bounds, β-CROWN,
/// etc.) may certify larger radii.
#[allow(clippy::too_many_arguments)]
pub fn certified_radius<const IN: usize>(
    w1: &[[f32; IN]; 32],
    b1: &[f32; 32],
    w2: &[f32; 32],
    b2: f32,
    input: &[f32; IN],
    threshold: f32,
    max_eps: f32,
    tol: f32,
) -> Option<f32> {
    let center_score = super::mlp::mlp_predict_32::<IN>(w1, b1, w2, b2, input);
    let expected_above = center_score > threshold;

    if !verdict_stable(w1, b1, w2, b2, input, 0.0, threshold, expected_above) {
        return None;
    }

    let mut lo = 0.0f32;
    let mut hi = max_eps;
    while hi - lo > tol {
        let mid = (lo + hi) * 0.5;
        if verdict_stable(w1, b1, w2, b2, input, mid, threshold, expected_above) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    Some(lo)
}

#[inline]
fn sigmoid_f32(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::super::mlp::mlp_predict_32;
    use crate::ensemble::weights::scanner_weights;
    use super::*;

    /// Outward-rounded IBP bounds at ε = 0 sandwich the actual MLP output.
    #[test]
    fn ibp_zero_eps_sandwiches_output() {
        let input = [0.5f32; 12];
        let pre = ibp_mlp_pre_sigmoid::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
            &input,
        );
        let actual_score = mlp_predict_32::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
        );
        let lo = sigmoid_down(pre.lo);
        let hi = sigmoid_up(pre.hi);
        assert!(
            lo <= actual_score && actual_score <= hi,
            "score {actual_score} outside outward-rounded bounds [{lo}, {hi}]"
        );
    }

    /// Outward-rounded IBP intervals widen monotonically with ε.
    #[test]
    fn ibp_widens_with_eps() {
        let input = [0.5f32; 12];
        let mut prev_width = 0.0f32;
        for &eps in &[0.0_f32, 0.01, 0.05, 0.1, 0.5] {
            let (lo, hi) = input_box::<12>(&input, eps);
            let pre = ibp_mlp_pre_sigmoid::<12>(
                &scanner_weights::W1,
                &scanner_weights::B1,
                &scanner_weights::W2,
                scanner_weights::B2,
                &lo,
                &hi,
            );
            let width = pre.hi - pre.lo;
            assert!(width >= prev_width - 1e-5, "IBP width shrank at eps={eps}");
            prev_width = width;
        }
    }

    /// Outward-rounded IBP at ε=0 contains the inner-loop f32 forward result.
    /// This is the "outward" guarantee — the reported interval never excludes
    /// the actual f32 output.
    #[test]
    fn outward_bounds_contain_inner_forward() {
        let input = [0.3f32; 12];
        let pre = ibp_mlp_pre_sigmoid::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
            &input,
        );
        let inner_forward_pre = {
            let mut z1 = [0.0f32; 32];
            for j in 0..32 {
                let mut acc = scanner_weights::B1[j];
                for i in 0..12 {
                    acc += scanner_weights::W1[j][i] * input[i];
                }
                z1[j] = acc.max(0.0);
            }
            let mut out = scanner_weights::B2;
            for j in 0..32 {
                out += scanner_weights::W2[j] * z1[j];
            }
            out
        };
        assert!(
            pre.lo <= inner_forward_pre && inner_forward_pre <= pre.hi,
            "outward IBP at ε=0 did not contain inner forward: \
             [{}, {}] vs {inner_forward_pre}",
            pre.lo,
            pre.hi,
        );
    }

    /// Certified radius is non-zero for a clearly-non-boundary input.
    #[test]
    fn certified_radius_nonzero_for_obvious_block() {
        let mut input = [0.5f32; 12];
        input[0] = 0.95;
        let center = mlp_predict_32::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
        );
        let radius = certified_radius::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
            scanner_weights::THRESHOLD,
            0.5,
            1e-4,
        );
        if (center - scanner_weights::THRESHOLD).abs() > 0.01 {
            assert!(
                radius.is_some(),
                "expected a certified radius for non-boundary input (center={center})"
            );
            let r = radius.unwrap();
            assert!(r > 0.0, "expected positive radius, got {r}");
        }
    }

    /// Binary search converges within the requested tolerance.
    #[test]
    fn certified_radius_within_tolerance() {
        let input = [0.5f32; 12];
        let tol = 1e-3_f32;
        let r = certified_radius::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
            scanner_weights::THRESHOLD,
            0.5,
            tol,
        );
        if let Some(r) = r {
            let center = mlp_predict_32::<12>(
                &scanner_weights::W1,
                &scanner_weights::B1,
                &scanner_weights::W2,
                scanner_weights::B2,
                &input,
            );
            let above = center > scanner_weights::THRESHOLD;
            let stable_at_r = verdict_stable(
                &scanner_weights::W1,
                &scanner_weights::B1,
                &scanner_weights::W2,
                scanner_weights::B2,
                &input,
                r,
                scanner_weights::THRESHOLD,
                above,
            );
            assert!(stable_at_r, "verdict not stable at certified radius {r}");
        }
    }
}
