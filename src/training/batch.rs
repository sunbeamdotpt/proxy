// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared training infrastructure: Dataset adapter, Batcher, and batch types
//! for use with burn's SupervisedTraining.

use crate::dataset::sample::TrainingSample;

use burn::data::dataloader::batcher::Batcher;
use burn::data::dataloader::Dataset;
use burn::prelude::*;

/// A single normalized training item ready for batching.
#[derive(Clone, Debug)]
pub struct TrainingItem {
    /// Features.
    pub features: Vec<f32>,
    /// Label.
    pub label: i32,
    /// Weight.
    pub weight: f32,
}

/// A batch of training items as tensors.
#[derive(Clone, Debug)]
pub struct TrainingBatch<B: Backend> {
    /// Features.
    pub features: Tensor<B, 2>,
    /// Labels.
    pub labels: Tensor<B, 1, Int>,
    /// Weights.
    pub weights: Tensor<B, 2>,
}

/// Wraps a `Vec<TrainingSample>` as a burn `Dataset`, applying min-max
/// normalization to features at construction time.
#[derive(Clone)]
pub struct SampleDataset {
    items: Vec<TrainingItem>,
}

impl SampleDataset {
    pub fn new(samples: &[TrainingSample], mins: &[f32], maxs: &[f32]) -> Self {
        let items = samples
            .iter()
            .map(|s| {
                let features: Vec<f32> = s
                    .features
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| {
                        let range = maxs[i] - mins[i];
                        if range > f32::EPSILON {
                            ((v - mins[i]) / range).clamp(0.0, 1.0)
                        } else {
                            0.0
                        }
                    })
                    .collect();
                TrainingItem {
                    features,
                    label: if s.label >= 0.5 { 1 } else { 0 },
                    weight: s.weight,
                }
            })
            .collect();
        Self { items }
    }
}

impl Dataset<TrainingItem> for SampleDataset {
    fn get(&self, index: usize) -> Option<TrainingItem> {
        self.items.get(index).cloned()
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

/// Converts a `Vec<TrainingItem>` into a `TrainingBatch` of tensors.
#[derive(Clone)]
pub struct SampleBatcher;

impl SampleBatcher {
    pub fn new() -> Self {
        Self
    }
}

impl<B: Backend> Batcher<B, TrainingItem, TrainingBatch<B>> for SampleBatcher {
    fn batch(&self, items: Vec<TrainingItem>, device: &B::Device) -> TrainingBatch<B> {
        let batch_size = items.len();
        let num_features = items[0].features.len();

        let flat_features: Vec<f32> = items
            .iter()
            .flat_map(|item| item.features.iter().copied())
            .collect();

        let labels: Vec<i32> = items.iter().map(|item| item.label).collect();
        let weights: Vec<f32> = items.iter().map(|item| item.weight).collect();

        let features = Tensor::<B, 1>::from_floats(flat_features.as_slice(), device)
            .reshape([batch_size, num_features]);

        let labels = Tensor::<B, 1, Int>::from_ints(labels.as_slice(), device);

        let weights =
            Tensor::<B, 1>::from_floats(weights.as_slice(), device).reshape([batch_size, 1]);

        TrainingBatch {
            features,
            labels,
            weights,
        }
    }
}
