//! burn-rs MLP model definition for ensemble training.
//!
//! A two-layer network (linear -> ReLU -> linear -> sigmoid) used as the
//! "uncertain region" classifier in the tree+MLP ensemble.

use burn::module::Module;
use burn::nn::{Linear, LinearConfig};
use burn::prelude::*;

/// Two-layer MLP: input -> hidden (ReLU) -> output (sigmoid).
#[derive(Module, Debug)]
pub struct MlpModel<B: Backend> {
    pub linear1: Linear<B>,
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
    /// Forward pass: ReLU hidden activation, sigmoid output.
    ///
    /// Input shape: `[batch, input_dim]`
    /// Output shape: `[batch, 1]`
    pub fn forward(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let h = self.linear1.forward(x);
        let h = burn::tensor::activation::relu(h);
        let out = self.linear2.forward(h);
        burn::tensor::activation::sigmoid(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use burn::backend::NdArray;

    type TestBackend = NdArray<f32>;

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

        // Random-ish input values.
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
