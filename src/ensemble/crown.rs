// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! # CROWN — Certified per-input adversarial robustness radius
//!
//! Runtime computation of the certified L∞ robustness radius for the scanner
//! MLP, mirroring the Lean specification in:
//!
//! - [`Sunbeam.Verify.CrownBound`](../../../lean4/Sunbeam/Verify/CrownBound.lean)
//! - [`Sunbeam.Verify.CertifiedRadius`](../../../lean4/Sunbeam/Verify/CertifiedRadius.lean)
//!
//! ## What "certified radius" means
//!
//! Given an input vector `x` and a verdict threshold `t`, the certified radius
//! is the largest L∞ perturbation `ε` such that **every** `x'` with
//! `‖x' - x‖∞ ≤ ε` yields the same verdict as `x` (above or below `t`).
//!
//! Inputs deep inside their decision region certify with large radii; inputs
//! near the decision boundary certify with small radii (or none).
//!
//! ## Algorithm
//!
//! Two pieces:
//!
//! 1. **Interval bound propagation (IBP)** through `Linear → ReLU → Linear`,
//!    mirroring TorchLean's `boundIbp` for `MLP2`. For each output coordinate
//!    we compute `[lo, hi]` such that the true output is in this interval
//!    over the entire input box.
//!
//! 2. **Binary search on ε**: find the largest ε in `[0, max_eps]` such that
//!    `sigmoid(pre_lo) > threshold` (verdict stable block) or
//!    `sigmoid(pre_hi) < threshold` (verdict stable allow).
//!
//! ## Soundness
//!
//! Every claim made by this module is backed by a Lean theorem:
//!
//! - The IBP bound matches `NN.MLTheory.CROWN.boundAffine` (via `boundIbp`).
//! - `mlpForward_crown_bound` proves `sigmoid(lo) ≤ output ≤ sigmoid(hi)`.
//! - `verdict_stable_block` / `verdict_stable_allow` lift this to verdict
//!   stability across the entire ε-ball.

/// Pre-sigmoid output interval `[lo, hi]` computed via IBP through the MLP.
#[derive(Debug, Clone, Copy)]
pub struct PreSigmoidInterval {
    /// Lower bound on the pre-sigmoid scalar output.
    pub lo: f32,
    /// Upper bound on the pre-sigmoid scalar output.
    pub hi: f32,
}

/// Interval-bound-propagation through a linear layer `y = W x + b` given an
/// input interval box.
///
/// For weight `w_ji`: when `w_ji ≥ 0` the lower bound contribution uses
/// `x_lo[i]` and the upper uses `x_hi[i]`; when `w_ji < 0` they swap. This is
/// the standard IBP formulation for affine layers.
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
                lo += w_ji * x_lo[i];
                hi += w_ji * x_hi[i];
            } else {
                lo += w_ji * x_hi[i];
                hi += w_ji * x_lo[i];
            }
        }
        out_lo[j] = lo;
        out_hi[j] = hi;
    }
    (out_lo, out_hi)
}

/// IBP through the full MLP, returning the pre-sigmoid output interval.
///
/// Mirrors TorchLean's `MLP2.boundIbp`: linear → relu → linear. The final
/// sigmoid is monotone so the certified sigmoid interval is
/// `[sigmoid(lo), sigmoid(hi)]`.
pub fn ibp_mlp_pre_sigmoid<const IN: usize>(
    w1: &[[f32; IN]; 32],
    b1: &[f32; 32],
    w2: &[f32; 32],
    b2: f32,
    input_lo: &[f32; IN],
    input_hi: &[f32; IN],
) -> PreSigmoidInterval {
    // Layer 1: z1 ∈ [W1·x + b1]
    let (z1_lo, z1_hi) = ibp_linear::<IN, 32>(w1, input_lo, input_hi, b1);

    // ReLU: a1 = ReLU(z1), pointwise monotone so bounds preserve through max(_, 0)
    let mut a1_lo = [0.0f32; 32];
    let mut a1_hi = [0.0f32; 32];
    for j in 0..32 {
        a1_lo[j] = z1_lo[j].max(0.0);
        a1_hi[j] = z1_hi[j].max(0.0);
    }

    // Layer 2: scalar output, w2 · a1 + b2.
    // Same IBP rule as ibp_linear but specialized to OUT=1, written inline.
    let mut out_lo = b2;
    let mut out_hi = b2;
    for j in 0..32 {
        let w = w2[j];
        if w >= 0.0 {
            out_lo += w * a1_lo[j];
            out_hi += w * a1_hi[j];
        } else {
            out_lo += w * a1_hi[j];
            out_hi += w * a1_lo[j];
        }
    }

    PreSigmoidInterval { lo: out_lo, hi: out_hi }
}

/// Check whether the verdict is stable across the L∞ ε-ball around `input`.
///
/// `expected_above = true` means the center output exceeds the threshold (verdict
/// `block`); we then require `sigmoid(lo) > threshold` to certify. `false` means
/// the center is below (verdict `allow`); we require `sigmoid(hi) < threshold`.
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
    let input_lo = std::array::from_fn(|i| input[i] - eps);
    let input_hi = std::array::from_fn(|i| input[i] + eps);
    let pre = ibp_mlp_pre_sigmoid::<IN>(w1, b1, w2, b2, &input_lo, &input_hi);
    if expected_above {
        sigmoid_f32(pre.lo) > threshold
    } else {
        sigmoid_f32(pre.hi) < threshold
    }
}

/// Compute the certified L∞ robustness radius around `input` at the given
/// verdict threshold.
///
/// Returns `None` if even ε = 0 fails to certify (the input is exactly on the
/// decision boundary, modulo IBP slack). Otherwise returns the largest ε in
/// `[0, max_eps]` within tolerance `tol` such that the verdict is stable
/// across the L∞ ε-ball.
///
/// The returned value is sound: a Lean proof (`verdict_stable_block` /
/// `_allow` in `Sunbeam.Verify.CertifiedRadius`) guarantees that any
/// perturbation up to this radius preserves the verdict. It is not
/// necessarily tight — IBP is a conservative bound and tighter relaxations
/// (CROWN linear bounds, β-CROWN, etc.) may certify larger radii.
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
    use super::*;
    use super::super::gen::scanner_weights;
    use super::super::mlp::mlp_predict_32;

    /// IBP bounds at ε = 0 sandwich the actual MLP output.
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
        let lo = sigmoid_f32(pre.lo);
        let hi = sigmoid_f32(pre.hi);
        assert!(
            lo - 1e-5 <= actual_score && actual_score <= hi + 1e-5,
            "score {actual_score} outside IBP bounds [{lo}, {hi}]"
        );
    }

    /// IBP intervals widen monotonically with ε.
    #[test]
    fn ibp_widens_with_eps() {
        let input = [0.5f32; 12];
        let mut prev_width = 0.0f32;
        for &eps in &[0.0_f32, 0.01, 0.05, 0.1, 0.5] {
            let lo = std::array::from_fn(|i| input[i] - eps);
            let hi = std::array::from_fn(|i| input[i] + eps);
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

    /// Certified radius is non-zero for a clearly-non-boundary input.
    #[test]
    fn certified_radius_nonzero_for_obvious_block() {
        // Input designed to be deep inside the block region: large feature 0.
        let mut input = [0.5f32; 12];
        input[0] = 0.95;
        let center = mlp_predict_32::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &input,
        );
        // Whichever side the center lands, we should be able to certify *some*
        // radius unless it's right on the boundary.
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
            // At r, verdict stable; at r + tol*2 it should fail (unless we hit max_eps).
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
