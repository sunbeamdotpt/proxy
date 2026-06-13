// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! burn-rs MLP model definition for ensemble training.
//!
//! A two-layer network (linear -> ReLU -> linear -> sigmoid) used as the
//! "uncertain region" classifier in the tree+MLP ensemble.

use crate::training::batch::TrainingBatch;

use burn::module::Module;
use burn::nn::{Linear, LinearConfig};
use burn::prelude::*;
use burn::tensor::backend::AutodiffBackend;
use burn::train::{ClassificationOutput, InferenceStep, TrainOutput, TrainStep};

/// Two-layer MLP: input -> hidden (ReLU) -> output (sigmoid).
#[derive(Module, Debug)]
pub struct MlpModel<B: Backend> {
    /// Linear1.
    pub linear1: Linear<B>,
    /// Linear2.
    pub linear2: Linear<B>,
}

/// Configuration for the MLP architecture.
#[derive(Config, Debug)]
pub struct MlpConfig {
    /// Number of input features (12 for scanner, 14 for DDoS).
    pub input_dim: usize,
    /// Hidden layer width (typically 32).
    pub hidden_dim: usize,
}

impl MlpConfig {
    /// Initialize a new MLP model on the given device.
    pub fn init<B: Backend>(&self, device: &B::Device) -> MlpModel<B> {
        MlpModel {
            linear1: LinearConfig::new(self.input_dim, self.hidden_dim).init(device),
            linear2: LinearConfig::new(self.hidden_dim, 1).init(device),
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
    pub fn forward_classification(&self, batch: TrainingBatch<B>) -> ClassificationOutput<B> {
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
        let loss = per_sample.mean(); // scalar [1]

        // AccuracyMetric expects [batch, num_classes] and uses argmax.
        let neg_logits = logits.clone().neg();
        let output_2col = Tensor::cat(vec![neg_logits, logits], 1); // [batch, 2]

        ClassificationOutput::new(loss, output_2col, batch.labels)
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
        };
        let model = config.init::<TestBackend>(&device);

        let input = Tensor::<TestBackend, 2>::zeros([4, 14], &device);
        let output = model.forward(input);
        assert_eq!(output.shape().dims[1], 1);
    }
}
