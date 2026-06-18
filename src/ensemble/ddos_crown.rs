// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # DDoS CROWN — Certified per-input adversarial robustness radius (inputDim=14)
//!
//! Thin DDoS-specific wrapper over the polymorphic `crown` module, wired to
//! the trained DDoS weights and threshold. The underlying IBP and binary
//! search are shared with the scanner ensemble at `inputDim = 12`; only the
//! input dimension and weight constants differ.
//!
//! Soundness on IEEE-754 binary32 hardware is identical to scanner: the
//! outward-rounded f32 IBP in `crown::ibp_mlp_pre_sigmoid` produces a sound
//! over-approximation of the ℝ-IBP bound, and the verdict check uses
//! outward-rounded sigmoid. See [`Sunbeam.DDoS.verdict_stable_block_f32`]
//! and [`Sunbeam.DDoS.verdict_stable_allow_f32`] for the Lean specialization
//! at `inputDim = 14`.

use super::crown::{certified_radius, ibp_mlp_pre_sigmoid, PreSigmoidInterval};
use super::weights::ddos_weights;

/// Pre-sigmoid output interval for the DDoS MLP over the L∞ ε-box around the
/// given normalized input.
///
/// The bounds are outward-rounded in f32: `lo ≤ mlpForwardF32(x') ≤ hi` for
/// every `x'` in the box, on IEEE-754 hardware.
pub fn ddos_pre_sigmoid_interval(input_lo: &[f32; 14], input_hi: &[f32; 14]) -> PreSigmoidInterval {
    ibp_mlp_pre_sigmoid::<14>(
        &ddos_weights::W1,
        &ddos_weights::B1,
        &ddos_weights::W2,
        ddos_weights::B2,
        input_lo,
        input_hi,
    )
}

/// Compute the certified L∞ robustness radius around `input` for the DDoS
/// verdict.
///
/// `input` must already be normalized (min/max-scaled with `ddos_weights`
/// constants). Returns `None` if even ε = 0 fails to certify; otherwise
/// returns the largest ε in `[0, max_eps]` within `tol` such that the verdict
/// is stable.
pub fn ddos_certified_radius(input: &[f32; 14], max_eps: f32, tol: f32) -> Option<f32> {
    certified_radius::<14>(
        &ddos_weights::W1,
        &ddos_weights::B1,
        &ddos_weights::W2,
        ddos_weights::B2,
        input,
        ddos_weights::THRESHOLD,
        max_eps,
        tol,
    )
}

#[cfg(test)]
mod tests {
    use super::super::mlp::mlp_predict_32;
    use super::*;

    /// Outward-rounded IBP bounds at ε = 0 contain the inner pre-sigmoid value.
    #[test]
    fn ddos_outward_bounds_contain_inner_forward() {
        let input = [0.5f32; 14];
        let pre = ddos_pre_sigmoid_interval(&input, &input);
        let inner_pre_sigmoid = {
            let mut z1 = [0.0f32; 32];
            for j in 0..32 {
                let mut acc = ddos_weights::B1[j];
                for i in 0..14 {
                    acc += ddos_weights::W1[j][i] * input[i];
                }
                z1[j] = acc.max(0.0);
            }
            let mut out = ddos_weights::B2;
            for j in 0..32 {
                out += ddos_weights::W2[j] * z1[j];
            }
            out
        };
        assert!(
            pre.lo <= inner_pre_sigmoid && inner_pre_sigmoid <= pre.hi,
            "inner pre-sigmoid {inner_pre_sigmoid} outside outward bounds [{}, {}]",
            pre.lo,
            pre.hi,
        );
    }

    /// IBP intervals widen monotonically with ε.
    #[test]
    fn ddos_ibp_widens_with_eps() {
        let input = [0.5f32; 14];
        let mut prev_width = 0.0f32;
        for &eps in &[0.0_f32, 0.01, 0.05, 0.1, 0.5] {
            let lo = std::array::from_fn(|i| (input[i] - eps).next_down());
            let hi = std::array::from_fn(|i| (input[i] + eps).next_up());
            let pre = ddos_pre_sigmoid_interval(&lo, &hi);
            let width = pre.hi - pre.lo;
            assert!(width >= prev_width - 1e-5, "IBP width shrank at eps={eps}");
            prev_width = width;
        }
    }

    /// Certified radius is non-zero for an obviously-blocked input.
    #[test]
    fn ddos_certified_radius_nonzero() {
        let input = [0.5f32; 14];
        let center = mlp_predict_32::<14>(
            &ddos_weights::W1,
            &ddos_weights::B1,
            &ddos_weights::W2,
            ddos_weights::B2,
            &input,
        );
        let radius = ddos_certified_radius(&input, 0.5, 1e-4);
        if (center - ddos_weights::THRESHOLD).abs() > 0.01 {
            assert!(
                radius.is_some(),
                "expected a certified radius for non-boundary input (center={center})"
            );
            let r = radius.unwrap();
            assert!(r > 0.0, "expected positive radius, got {r}");
        }
    }
}
