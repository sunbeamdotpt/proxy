// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! burn-rs MLP model definition for ensemble training.
//!
//! A two-layer network (linear -> ReLU -> linear -> sigmoid) used as the
//! "uncertain region" classifier in the tree+MLP ensemble.

use crate::training::batch::TrainingBatch;

use burn::module::{Module, Param, ParamId};
use burn::nn::{Linear, LinearConfig};
use burn::prelude::*;
use burn::tensor::backend::AutodiffBackend;
use burn::tensor::{Int, IndexingUpdateOp, TensorData};
use burn::train::{ClassificationOutput, InferenceStep, TrainOutput, TrainStep};

/// Two-layer MLP: input -> hidden (ReLU) -> output (sigmoid).
///
/// **Hard reparameterization for monotonicity** (see `docs/TIERS.md`). For
/// each adversarial feature `i`, the effective row of W1 is
/// `softplus(adv_gamma[i, :]) * W2`, so
/// `W1_eff[i, j] * W2[j] = softplus(adv_gamma[i, j]) * W2[j]² ≥ 0` by
/// construction and the MLP is monotone non-decreasing in every adversarial
/// feature. `linear1.weight` rows at `adv_indices` are unused at forward
/// time (their gradients cancel); the export path bakes the effective rows
/// back in so the gen file reflects what the forward pass computes.
///
/// `sign_lambda` is the soft-penalty knob retained for ablation; redundant
/// when `adv_indices` is non-empty.
#[derive(Module, Debug)]
pub struct MlpModel<B: Backend> {
    pub linear1: Linear<B>,
    pub linear2: Linear<B>,
    /// Reparameterization parameter, shape `[max(num_adv, 1), hidden]`.
    /// Effective adversarial weight: `softplus(adv_gamma[i, j]) * W2[j]`.
    pub adv_gamma: Param<Tensor<B, 2>>,
    /// Adversarial feature indices (non-trainable).
    pub adv_indices: Tensor<B, 1, Int>,
    /// Soft sign-constraint penalty coefficient (non-trainable).
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
        // adv_gamma initial values: zeros → softplus(0) = ln(2) ≈ 0.693, a
        // reasonable starting magnitude for the adversarial weights. Shape
        // [max(num_adv, 1), hidden] — at least 1 row so the Param is non-empty
        // even when no adversarial features are configured (in which case
        // adv_gamma is unused by the forward pass).
        let gamma_rows = self.adversarial_indices.len().max(1);
        let adv_gamma_tensor = Tensor::<B, 2>::zeros([gamma_rows, self.hidden_dim], device);
        let adv_gamma = Param::initialized(ParamId::new(), adv_gamma_tensor);
        MlpModel {
            linear1: LinearConfig::new(self.input_dim, self.hidden_dim).init(device),
            linear2: LinearConfig::new(self.hidden_dim, 1).init(device),
            adv_gamma,
            adv_indices,
            sign_lambda,
        }
    }
}

impl<B: Backend> MlpModel<B> {
    /// Forward pass returning raw logits (pre-sigmoid).
    ///
    /// Applies the hard reparameterization for adversarial input features:
    /// the effective first-layer weight is
    /// `softplus(adv_gamma[i, j]) * W2[j]` instead of `linear1.weight[i, j]`.
    /// Implementation uses subtract-wrong-add-correct to avoid materializing a
    /// modified W1 tensor (and to keep `linear1.forward` carrying the bias).
    ///
    /// Input shape: `[batch, input_dim]`
    /// Output shape: `[batch, 1]`
    pub fn forward_logits(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let z = self.linear1_with_reparam(x);
        let h = burn::tensor::activation::relu(z);
        self.linear2.forward(h)
    }

    /// Linear1 forward with the adversarial-feature rows replaced by the
    /// reparameterized form. Returns the pre-activation `[batch, hidden]`.
    fn linear1_with_reparam(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let normal = self.linear1.forward(x.clone());
        if self.adv_indices.dims()[0] == 0 {
            return normal;
        }
        let w1 = self.linear1.weight.val(); // [in, hidden]
        let w2 = self.linear2.weight.val(); // [hidden, 1]
        let x_adv = x.select(1, self.adv_indices.clone()); // [batch, num_adv]
        let w1_adv = w1.select(0, self.adv_indices.clone()); // [num_adv, hidden]
        let wrong = x_adv.clone().matmul(w1_adv); // [batch, hidden]
        let alpha = burn::tensor::activation::softplus(self.adv_gamma.val(), 1.0);
        let w2_row = w2.swap_dims(0, 1); // [1, hidden]
        let adv_eff = alpha * w2_row; // [num_adv, hidden]
        let correct = x_adv.matmul(adv_eff); // [batch, hidden]
        normal - wrong + correct
    }

    /// Effective first-layer weight matrix with the reparameterization
    /// baked in: rows corresponding to adversarial features are replaced by
    /// `softplus(adv_gamma[i, :]) * W2`. Used at export time so the gen file
    /// reflects what the forward pass actually computes.
    pub fn effective_w1(&self) -> Tensor<B, 2> {
        let w1 = self.linear1.weight.val();
        if self.adv_indices.dims()[0] == 0 {
            return w1;
        }
        let w2 = self.linear2.weight.val();
        let alpha = burn::tensor::activation::softplus(self.adv_gamma.val(), 1.0);
        let w2_row = w2.swap_dims(0, 1); // [1, hidden]
        let adv_eff = alpha * w2_row; // [num_adv, hidden]
        let w1_adv_old = w1.clone().select(0, self.adv_indices.clone()); // [num_adv, hidden]
        let delta = adv_eff - w1_adv_old; // what to add to w1 at adv rows
        let num_adv = self.adv_indices.dims()[0];
        let hidden = w1.dims()[1];
        // [num_adv] -> [num_adv, 1] -> [num_adv, hidden] so each (i, j) cell holds adv_indices[i].
        let indices_2d = self.adv_indices.clone().unsqueeze_dim::<2>(1).expand([num_adv, hidden]);
        w1.scatter(0, indices_2d, delta, IndexingUpdateOp::Add)
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
    /// Adds the sign-constraint penalty (see `sign_constraint_penalty`).
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

        // Soft sign-constraint penalty (zero when adv_indices empty or lambda=0).
        let penalty = self.sign_constraint_penalty();
        let loss = bce + penalty;

        // AccuracyMetric expects [batch, num_classes] and uses argmax.
        let neg_logits = logits.clone().neg();
        let output_2col = Tensor::cat(vec![neg_logits, logits], 1); // [batch, 2]

        ClassificationOutput::new(loss, output_2col, batch.labels)
    }

    /// Soft sign-constraint penalty
    /// `lambda * Σ_{i ∈ adv} Σ_j relu(-W1[i,j] * W2[j])`.
    /// Pushes weights toward `W1[i,j] * W2[j] ≥ 0`. The hard reparameterization
    /// makes this redundant when `adv_indices` is non-empty; kept for ablation.
    ///
    /// Burn's `Linear` is row-major `[d_input, d_output]`: `linear1.weight` is
    /// `[in, hidden]` (select rows by input index), `linear2.weight` is
    /// `[hidden, 1]` (transpose to broadcast across rows).
    pub fn sign_constraint_penalty(&self) -> Tensor<B, 1> {
        let w1 = self.linear1.weight.val(); // [in, hidden]
        let w2 = self.linear2.weight.val(); // [hidden, 1]
        // Rows of W1 corresponding to adversarial features: [num_adv, hidden].
        let w1_adv = w1.select(0, self.adv_indices.clone());
        // Broadcast W2 across rows: [1, hidden] so each col gets its W2[j].
        let w2_row = w2.swap_dims(0, 1);
        // Element-wise product: [num_adv, hidden].
        let products = w1_adv * w2_row;
        // Penalty: relu(-products) per (i, j), summed and scaled by lambda.
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

    /// With adversarial indices set and `lambda > 0`, a randomly-initialised
    /// MLP should produce a strictly positive sign-constraint penalty (because
    /// random weights almost surely include some violations).
    #[test]
    fn test_sign_constraint_penalty_fires() {
        let device = Default::default();
        let config = MlpConfig {
            input_dim: 14,
            hidden_dim: 32,
            adversarial_indices: vec![0, 3, 6, 7, 13],
            sign_constraint_lambda: 1.0,
        };
        let model = config.init::<TestBackend>(&device);
        let penalty = model.sign_constraint_penalty();
        let data = penalty.to_data();
        let values: Vec<f32> = data.to_vec().expect("flat vec");
        assert_eq!(values.len(), 1);
        assert!(
            values[0] > 0.0,
            "expected positive penalty for random MLP, got {}",
            values[0]
        );
    }

    /// Lambda=0 → penalty is zero regardless of weights/indices. (Empty
    /// `adversarial_indices` would also disable, but the WGPU backend rejects
    /// the broadcast with a 0-size dim, so the lambda flag is the practical
    /// kill switch.)
    #[test]
    fn test_sign_constraint_penalty_zero_when_lambda_zero() {
        let device = Default::default();
        let config = MlpConfig {
            input_dim: 14,
            hidden_dim: 32,
            adversarial_indices: vec![0, 3, 6, 7, 13],
            sign_constraint_lambda: 0.0,
        };
        let model = config.init::<TestBackend>(&device);
        let penalty = model.sign_constraint_penalty();
        let data = penalty.to_data();
        let values: Vec<f32> = data.to_vec().expect("flat vec");
        assert!(
            values[0].abs() < 1e-6,
            "expected zero penalty for lambda=0, got {}",
            values[0]
        );
    }
}
