// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Two-layer MLP forward pass with a fixed hidden size of 32:
///
///   hidden = ReLU(W1 @ input + b1)
///   output = sigmoid(w2 · hidden + b2)
///
/// Zero allocation — the 32-element hidden layer lives on the stack.
#[inline(always)]
pub fn mlp_predict_32<const INPUT: usize>(
    w1: &[[f32; INPUT]; 32],
    b1: &[f32; 32],
    w2: &[f32; 32],
    b2: f32,
    input: &[f32; INPUT],
) -> f32 {
    let mut hidden = [0.0f32; 32];

    // Hidden layer: h_j = ReLU(sum_i(w1[j][i] * input[i]) + b1[j])
    for j in 0..32 {
        let mut sum = b1[j];
        for i in 0..INPUT {
            sum += w1[j][i] * input[i];
        }
        hidden[j] = relu_f32(sum);
    }

    // Output layer: sigmoid(sum_j(w2[j] * hidden[j]) + b2)
    let mut out = b2;
    for j in 0..32 {
        out += w2[j] * hidden[j];
    }
    sigmoid_f32(out)
}

#[inline(always)]
fn sigmoid_f32(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[inline(always)]
fn relu_f32(x: f32) -> f32 {
    if x > 0.0 {
        x
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid_boundaries() {
        assert!((sigmoid_f32(0.0) - 0.5).abs() < 1e-6);
        assert!(sigmoid_f32(10.0) > 0.999);
        assert!(sigmoid_f32(-10.0) < 0.001);
    }

    #[test]
    fn test_relu() {
        assert_eq!(relu_f32(0.0), 0.0);
        assert_eq!(relu_f32(1.5), 1.5);
        assert_eq!(relu_f32(-3.0), 0.0);
    }

    #[test]
    fn test_mlp_zero_weights() {
        // All weights zero, bias2 = 0 → sigmoid(0) = 0.5
        let w1 = [[0.0f32; 2]; 32];
        let b1 = [0.0f32; 32];
        let w2 = [0.0f32; 32];
        let b2 = 0.0f32;
        let input = [1.0f32, 2.0];
        let result = mlp_predict_32::<2>(&w1, &b1, &w2, b2, &input);
        assert!((result - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_mlp_known_output() {
        // Single active hidden unit: w1[0] = [1, 0], b1[0] = 0, w2[0] = 2, b2 = -1
        // input = [3, 0]
        // hidden[0] = ReLU(1*3 + 0*0 + 0) = 3.0, rest = 0
        // output = sigmoid(2*3 + (-1)) = sigmoid(5) ≈ 0.9933
        let mut w1 = [[0.0f32; 2]; 32];
        w1[0] = [1.0, 0.0];
        let b1 = [0.0f32; 32];
        let mut w2 = [0.0f32; 32];
        w2[0] = 2.0;
        let b2 = -1.0f32;
        let input = [3.0f32, 0.0];
        let result = mlp_predict_32::<2>(&w1, &b1, &w2, b2, &input);
        let expected = sigmoid_f32(5.0);
        assert!(
            (result - expected).abs() < 1e-6,
            "expected {expected}, got {result}"
        );
    }

    #[test]
    fn test_mlp_relu_clips_negative() {
        // w1[0] = [1, 0], b1[0] = -10 → hidden[0] = ReLU(-10 + input) clips to 0
        // Everything zero → sigmoid(b2) = sigmoid(0) = 0.5
        let mut w1 = [[0.0f32; 2]; 32];
        w1[0] = [1.0, 0.0];
        let mut b1 = [0.0f32; 32];
        b1[0] = -10.0;
        let w2 = [1.0f32; 32]; // doesn't matter, hidden is all 0
        let b2 = 0.0f32;
        let input = [3.0f32, 0.0]; // hidden[0] = ReLU(3-10) = 0
        let result = mlp_predict_32::<2>(&w1, &b1, &w2, b2, &input);
        assert!((result - 0.5).abs() < 1e-6);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn output_bounded_0_1(
            x0 in -10.0f32..10.0,
            x1 in -10.0f32..10.0,
            b2 in -5.0f32..5.0,
        ) {
            let w1 = [[0.1f32, -0.2]; 32];
            let b1 = [0.0f32; 32];
            let w2 = [0.05f32; 32];
            let input = [x0, x1];
            let result = mlp_predict_32::<2>(&w1, &b1, &w2, b2, &input);
            prop_assert!(result >= 0.0 && result <= 1.0,
                "output {result} outside [0,1]");
        }
    }
}
