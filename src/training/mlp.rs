// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! burn-rs MLP model definition for ensemble training.
//!
//! A two-layer network (linear -> ReLU -> linear -> sigmoid) used as the
//! "uncertain region" classifier in the tree+MLP ensemble.

use crate::training::batch::TrainingBatch;

use burn::module::Module;
use burn::nn::{Linear, LinearConfig};
use burn::prelude::*;
use burn::tensor::backend::AutodiffBackend;
use burn::tensor::{Int, TensorData};
use burn::train::{ClassificationOutput, InferenceStep, TrainOutput, TrainStep};

/// Two-layer MLP: input -> hidden (ReLU) -> output (sigmoid).
///
/// `adv_indices` and `sign_lambda` carry the Tier 2 sign-constraint config:
/// the loss includes a `relu(-W1[i,j] * W2[j])` penalty summed over (i ∈
/// adv_indices, j ∈ hidden), pushing weights toward `W1[i,j] * W2[j] ≥ 0`
/// for every adversarial feature `i`. Empty `adv_indices` or zero `lambda`
/// disables the penalty.
#[derive(Module, Debug)]
pub struct MlpModel<B: Backend> {
    /// Linear1.
    pub linear1: Linear<B>,
    /// Linear2.
    pub linear2: Linear<B>,
    /// Adversarial feature indices for sign-constraint penalty (non-trainable).
    pub adv_indices: Tensor<B, 1, Int>,
    /// Sign-constraint penalty coefficient as a 1-element tensor (non-trainable).
    pub sign_lambda: Tensor<B, 1>,
}

/// Configuration for the MLP architecture.
#[derive(Config, Debug)]
pub struct MlpConfig {
    /// Number of input features (12 for scanner, 14 for DDoS).
    pub input_dim: usize,
    /// Hidden layer width (typically 32).
    pub hidden_dim: usize,
    /// Adversarial feature indices. Empty disables the sign-constraint penalty.
    #[config(default = "Vec::new()")]
    pub adversarial_indices: Vec<usize>,
    /// Penalty coefficient (multiplier on the sign-constraint penalty term).
    /// Zero disables the penalty entirely.
    #[config(default = "0.0")]
    pub sign_constraint_lambda: f32,
}

impl MlpConfig {
    /// Initialize a new MLP model on the given device.
    pub fn init<B: Backend>(&self, device: &B::Device) -> MlpModel<B> {
        let adv_data: Vec<i64> = self.adversarial_indices.iter().map(|&i| i as i64).collect();
        let adv_indices = Tensor::<B, 1, Int>::from_data(
            TensorData::new(adv_data, [self.adversarial_indices.len()]),
            device,
        );
        let sign_lambda = Tensor::<B, 1>::from_data(
            TensorData::new(vec![self.sign_constraint_lambda], [1]),
            device,
        );
        MlpModel {
            linear1: LinearConfig::new(self.input_dim, self.hidden_dim).init(device),
            linear2: LinearConfig::new(self.hidden_dim, 1).init(device),
            adv_indices,
            sign_lambda,
        }
    }
}

impl<B: Backend> MlpModel<B> {
    /// Forward pass returning raw logits (pre-sigmoid).
    ///
    /// Input shape: `[batch, input_dim]`
    /// Output shape: `[batch, 1]`
    pub fn forward_logits(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let h = self.linear1.forward(x);
        let h = burn::tensor::activation::relu(h);
        self.linear2.forward(h)
    }

    /// Forward pass with sigmoid activation for inference/export.
    ///
    /// Input shape: `[batch, input_dim]`
    /// Output shape: `[batch, 1]`  (values in [0, 1])
    pub fn forward(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        burn::tensor::activation::sigmoid(self.forward_logits(x))
    }

    /// Forward pass returning a `ClassificationOutput` for burn's training loop.
    ///
    /// Uses raw logits for BCE (which applies sigmoid internally) and converts
    /// to two-column format `[1-p, p]` for AccuracyMetric (which uses argmax).
    /// Adds the Tier 2 sign-constraint penalty (see `sign_constraint_penalty`).
    pub fn forward_classification(
        &self,
        batch: TrainingBatch<B>,
    ) -> ClassificationOutput<B> {
        let logits = self.forward_logits(batch.features); // [batch, 1]
        let logits_1d = logits.clone().squeeze::<1>(); // [batch]

        // Numerically stable BCE from logits:
        //   loss = max(logits, 0) - logits * targets + log(1 + exp(-|logits|))
        // This avoids log(0) and exp(large) overflow.
        let targets_float = batch.labels.clone().float(); // [batch]
        let zeros = Tensor::zeros_like(&logits_1d);
        let relu_logits = logits_1d.clone().max_pair(zeros); // max(logits, 0)
        let neg_abs = logits_1d.clone().abs().neg(); // -|logits|
        let log_term = neg_abs.exp().log1p(); // log(1 + exp(-|logits|))
        let per_sample = relu_logits - logits_1d.clone() * targets_float + log_term;
        let bce = per_sample.mean(); // scalar [1]

        // Tier 2 sign-constraint penalty (zero when adv_indices empty or lambda=0).
        let penalty = self.sign_constraint_penalty();
        let loss = bce + penalty;

        // AccuracyMetric expects [batch, num_classes] and uses argmax.
        let neg_logits = logits.clone().neg();
        let output_2col = Tensor::cat(vec![neg_logits, logits], 1); // [batch, 2]

        ClassificationOutput::new(loss, output_2col, batch.labels)
    }

    /// Tier 2 sign-constraint penalty:
    /// `lambda * Σ_{i ∈ adv} Σ_j relu(-W1[j,i] * W2[j])`.
    ///
    /// Pushes weights toward `W1[j,i] * W2[j] ≥ 0` for every adversarial
    /// feature `i` and hidden neuron `j`, which makes the MLP monotone
    /// non-decreasing in those features.
    ///
    /// Burn's `Linear` stores weight as `[d_out, d_in]` (the docstring claims
    /// `[d_in, d_out]` but the actual math is `y = x @ W^T`). So:
    /// - `linear1.weight` has shape `[hidden, in]`; select on dim 1 to pick
    ///   adversarial input features.
    /// - `linear2.weight` has shape `[1, hidden]`; squeeze to a per-neuron
    ///   vector for the element-wise product.
    pub fn sign_constraint_penalty(&self) -> Tensor<B, 1> {
        let w1 = self.linear1.weight.val(); // [hidden, in]
        let w2 = self.linear2.weight.val(); // [1, hidden]
        // Columns of W1 corresponding to adversarial features: [hidden, num_adv].
        let w1_adv = w1.select(1, self.adv_indices.clone());
        // Broadcast W2 down rows: [hidden, 1] so each row gets its W2[j].
        let w2_col = w2.swap_dims(0, 1);
        // Element-wise product: [hidden, num_adv].
        let products = w1_adv * w2_col;
        // Penalty: relu(-products) per (j, i), summed and scaled by lambda.
        // Empty adv_indices makes products empty, sum=0.
        let penalty_sum = products.neg().clamp_min(0.0).sum();
        penalty_sum * self.sign_lambda.clone()
    }
}

impl<B: AutodiffBackend> TrainStep for MlpModel<B> {
    type Input = TrainingBatch<B>;
    type Output = ClassificationOutput<B>;

    fn step(&self, batch: Self::Input) -> TrainOutput<Self::Output> {
        let item = self.forward_classification(batch);
        TrainOutput::new(self, item.loss.backward(), item)
    }
}

impl<B: Backend> InferenceStep for MlpModel<B> {
    type Input = TrainingBatch<B>;
    type Output = ClassificationOutput<B>;

    fn step(&self, batch: Self::Input) -> Self::Output {
        self.forward_classification(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burn::backend::Wgpu;

    type TestBackend = Wgpu<f32, i32>;

    #[test]
    fn test_forward_pass_shape() {
        let device = Default::default();
        let config = MlpConfig {
            input_dim: 12,
            hidden_dim: 32,
            adversarial_indices: Vec::new(),
            sign_constraint_lambda: 0.0,
        };
        let model = config.init::<TestBackend>(&device);

        let batch_size = 8;
        let input = Tensor::<TestBackend, 2>::zeros([batch_size, 12], &device);
        let output = model.forward(input);
        let shape = output.shape();

        assert_eq!(shape.dims[0], batch_size);
        assert_eq!(shape.dims[1], 1);
    }

    #[test]
    fn test_output_bounded() {
        let device = Default::default();
        let config = MlpConfig {
            input_dim: 4,
            hidden_dim: 16,
            adversarial_indices: Vec::new(),
            sign_constraint_lambda: 0.0,
        };
        let model = config.init::<TestBackend>(&device);

        let input = Tensor::<TestBackend, 2>::from_data(
            [[1.0, -2.0, 0.5, 3.0], [0.0, 0.0, 0.0, 0.0]],
            &device,
        );
        let output = model.forward(input);
        let data = output.to_data();
        let values: Vec<f32> = data.to_vec().expect("flat vec");

        for &v in &values {
            assert!(
                v >= 0.0 && v <= 1.0,
                "sigmoid output should be in [0, 1], got {v}"
            );
        }
    }

    #[test]
    fn test_ddos_input_dim() {
        let device = Default::default();
        let config = MlpConfig {
            input_dim: 14,
            hidden_dim: 32,
            adversarial_indices: Vec::new(),
            sign_constraint_lambda: 0.0,
        };
        let model = config.init::<TestBackend>(&device);

        let input = Tensor::<TestBackend, 2>::zeros([4, 14], &device);
        let output = model.forward(input);
        assert_eq!(output.shape().dims[1], 1);
    }
}
