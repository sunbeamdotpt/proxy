// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! DDoS MLP+tree training loop using burn's SupervisedTraining.
//!
//! Loads a `DatasetManifest`, trains a CART decision tree and a burn-rs MLP
//! with cosine annealing + early stopping, then exports the combined ensemble
//! weights as a Rust source file for `src/ensemble/gen/ddos_weights.rs`.

use anyhow::{Context, Result};
use std::path::Path;

use burn::backend::Autodiff;
use burn::backend::Wgpu;
use burn::data::dataloader::DataLoaderBuilder;
use burn::lr_scheduler::cosine::CosineAnnealingLrSchedulerConfig;
use burn::optim::AdamConfig;
use burn::prelude::*;
use burn::record::CompactRecorder;
use burn::train::metric::{AccuracyMetric, LossMetric};
use burn::train::{Learner, SupervisedTraining};

use crate::dataset::sample::{load_dataset, TrainingSample};
use crate::training::batch::{SampleBatcher, SampleDataset};
use crate::training::export::{export_to_file, ExportedModel};
use crate::training::mlp::MlpConfig;
use crate::training::tree::{train_tree, tree_predict, TreeConfig, TreeDecision};

/// Number of DDoS features (matches `crate::ddos::features::NUM_FEATURES`).
const NUM_FEATURES: usize = 14;

type TrainBackend = Autodiff<Wgpu<f32, i32>>;

/// Arguments for the DDoS MLP training command.
pub struct TrainDdosMlpArgs {
    /// Path to an rkyv `DatasetManifest` file.
    pub dataset_path: String,
    /// Directory to write output files (Rust source, model record).
    pub output_dir: String,
    /// Hidden layer width (default 32).
    pub hidden_dim: usize,
    /// Number of training epochs (default 100).
    pub epochs: usize,
    /// Adam learning rate (default 0.001).
    pub learning_rate: f64,
    /// Mini-batch size (default 64).
    pub batch_size: usize,
    /// CART max depth (default 8).
    pub tree_max_depth: usize,
    /// CART leaf purity threshold (default 0.98).
    pub tree_min_purity: f32,
    /// Minimum samples in a leaf node (default 2).
    pub min_samples_leaf: usize,
    /// Weight for cookie feature (feature 10: cookie_ratio). 0.0 = ignore, 1.0 = full weight.
    pub cookie_weight: f32,
}

impl Default for TrainDdosMlpArgs {
    fn default() -> Self {
        Self {
            dataset_path: String::new(),
            output_dir: ".".into(),
            hidden_dim: 32,
            epochs: 100,
            learning_rate: 0.0001,
            batch_size: 64,
            tree_max_depth: 8,
            tree_min_purity: 0.98,
            min_samples_leaf: 2,
            cookie_weight: 1.0,
        }
    }
}

/// Index of the cookie_ratio feature in the DDoS feature vector.
const COOKIE_FEATURE_IDX: usize = 10;

/// Entry point: train DDoS ensemble and export weights.
pub fn run(args: TrainDdosMlpArgs) -> Result<()> {
    // 1. Load dataset.
    let manifest =
        load_dataset(Path::new(&args.dataset_path)).context("loading dataset manifest")?;

    let samples = &manifest.ddos_samples;
    anyhow::ensure!(!samples.is_empty(), "no DDoS samples in dataset");

    for s in samples {
        anyhow::ensure!(
            s.features.len() == NUM_FEATURES,
            "expected {} features, got {}",
            NUM_FEATURES,
            s.features.len()
        );
    }

    println!(
        "[ddos] loaded {} samples ({} attack, {} normal)",
        samples.len(),
        samples.iter().filter(|s| s.label >= 0.5).count(),
        samples.iter().filter(|s| s.label < 0.5).count(),
    );

    // 2. Compute normalization params from training data.
    let (norm_mins, norm_maxs) = compute_norm_params(samples);

    if args.cookie_weight < 1.0 - f32::EPSILON {
        println!(
            "[ddos] cookie_weight={:.2} (feature {} influence reduced)",
            args.cookie_weight, COOKIE_FEATURE_IDX,
        );
    }

    // MLP norm adjustment: scale cookie feature's normalization range.
    let mut mlp_norm_maxs = norm_maxs.clone();
    if args.cookie_weight < 1.0 - f32::EPSILON {
        let range = mlp_norm_maxs[COOKIE_FEATURE_IDX] - norm_mins[COOKIE_FEATURE_IDX];
        if range > f32::EPSILON && args.cookie_weight > f32::EPSILON {
            mlp_norm_maxs[COOKIE_FEATURE_IDX] =
                range / args.cookie_weight + norm_mins[COOKIE_FEATURE_IDX];
        }
    }

    // 3. Stratified 80/20 split.
    let (train_set, val_set) = stratified_split(samples, 0.8);
    println!("[ddos] train={}, val={}", train_set.len(), val_set.len());

    // 4. Train CART tree (with cookie feature masking for reduced weight).
    let tree_train_set = mask_cookie_feature(&train_set, COOKIE_FEATURE_IDX, args.cookie_weight);
    let tree_config = TreeConfig {
        max_depth: args.tree_max_depth,
        min_samples_leaf: args.min_samples_leaf,
        min_purity: args.tree_min_purity,
        num_features: NUM_FEATURES,
    };
    let tree_nodes = train_tree(&tree_train_set, &tree_config);
    println!(
        "[ddos] CART tree: {} nodes (max_depth={})",
        tree_nodes.len(),
        args.tree_max_depth
    );

    // Evaluate tree on validation set.
    let (tree_correct, tree_deferred) = eval_tree(&tree_nodes, &val_set, &norm_mins, &norm_maxs);
    println!(
        "[ddos] tree validation: {:.2}% correct (of decided), {:.1}% deferred",
        tree_correct * 100.0,
        tree_deferred * 100.0,
    );

    // 5. Train MLP with SupervisedTraining (uses mlp_norm_maxs for cookie scaling).
    let device = Default::default();
    let mlp_config = MlpConfig {
        input_dim: NUM_FEATURES,
        hidden_dim: args.hidden_dim,
    };

    let artifact_dir = Path::new(&args.output_dir).join("ddos_artifacts");
    std::fs::create_dir_all(&artifact_dir).ok();

    let model = train_mlp(
        &train_set,
        &val_set,
        &mlp_config,
        &norm_mins,
        &mlp_norm_maxs,
        args.epochs,
        args.learning_rate,
        args.batch_size,
        &device,
        &artifact_dir,
    );

    // 6. Extract weights from trained model.
    let exported = extract_weights(
        &model,
        "ddos",
        &tree_nodes,
        0.5,
        &norm_mins,
        &mlp_norm_maxs,
        &device,
    );

    // 7. Write output.
    let out_dir = Path::new(&args.output_dir);
    std::fs::create_dir_all(out_dir).context("creating output directory")?;

    let rust_path = out_dir.join("ddos_weights.rs");
    export_to_file(&exported, &rust_path)?;
    println!("[ddos] exported Rust weights to {}", rust_path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Cookie feature masking for CART trees
// ---------------------------------------------------------------------------

fn mask_cookie_feature(
    samples: &[TrainingSample],
    cookie_idx: usize,
    cookie_weight: f32,
) -> Vec<TrainingSample> {
    if cookie_weight >= 1.0 - f32::EPSILON {
        return samples.to_vec();
    }
    samples
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut s2 = s.clone();
            if cookie_weight < f32::EPSILON {
                s2.features[cookie_idx] = 0.5;
            } else {
                let hash = (i as u64)
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(42);
                let r = (hash >> 33) as f32 / (u32::MAX >> 1) as f32;
                if r > cookie_weight {
                    s2.features[cookie_idx] = 0.5;
                }
            }
            s2
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

fn compute_norm_params(samples: &[TrainingSample]) -> (Vec<f32>, Vec<f32>) {
    let dim = samples[0].features.len();
    let mut mins = vec![f32::MAX; dim];
    let mut maxs = vec![f32::MIN; dim];
    for s in samples {
        for i in 0..dim {
            mins[i] = mins[i].min(s.features[i]);
            maxs[i] = maxs[i].max(s.features[i]);
        }
    }
    (mins, maxs)
}

// ---------------------------------------------------------------------------
// Stratified split
// ---------------------------------------------------------------------------

fn stratified_split(
    samples: &[TrainingSample],
    train_ratio: f64,
) -> (Vec<TrainingSample>, Vec<TrainingSample>) {
    let mut attacks: Vec<&TrainingSample> = samples.iter().filter(|s| s.label >= 0.5).collect();
    let mut normals: Vec<&TrainingSample> = samples.iter().filter(|s| s.label < 0.5).collect();

    deterministic_shuffle(&mut attacks);
    deterministic_shuffle(&mut normals);

    let attack_split = (attacks.len() as f64 * train_ratio) as usize;
    let normal_split = (normals.len() as f64 * train_ratio) as usize;

    let mut train = Vec::new();
    let mut val = Vec::new();

    for (i, s) in attacks.iter().enumerate() {
        if i < attack_split {
            train.push((*s).clone());
        } else {
            val.push((*s).clone());
        }
    }
    for (i, s) in normals.iter().enumerate() {
        if i < normal_split {
            train.push((*s).clone());
        } else {
            val.push((*s).clone());
        }
    }

    (train, val)
}

fn deterministic_shuffle<T>(items: &mut [T]) {
    let mut rng = 42u64;
    for i in (1..items.len()).rev() {
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (rng >> 33) as usize % (i + 1);
        items.swap(i, j);
    }
}

// ---------------------------------------------------------------------------
// Tree evaluation
// ---------------------------------------------------------------------------

fn eval_tree(
    nodes: &[(u8, f32, u16, u16)],
    val_set: &[TrainingSample],
    mins: &[f32],
    maxs: &[f32],
) -> (f64, f64) {
    let mut decided = 0usize;
    let mut correct = 0usize;
    let mut deferred = 0usize;

    for s in val_set {
        let normed = normalize_features(&s.features, mins, maxs);
        let decision = tree_predict(nodes, &normed);
        match decision {
            TreeDecision::Defer => deferred += 1,
            TreeDecision::Block => {
                decided += 1;
                if s.label >= 0.5 {
                    correct += 1;
                }
            }
            TreeDecision::Allow => {
                decided += 1;
                if s.label < 0.5 {
                    correct += 1;
                }
            }
        }
    }

    let accuracy = if decided > 0 {
        correct as f64 / decided as f64
    } else {
        0.0
    };
    let defer_rate = deferred as f64 / val_set.len() as f64;
    (accuracy, defer_rate)
}

fn normalize_features(features: &[f32], mins: &[f32], maxs: &[f32]) -> Vec<f32> {
    features
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
        .collect()
}

// ---------------------------------------------------------------------------
// MLP training via SupervisedTraining
// ---------------------------------------------------------------------------

fn train_mlp(
    train_set: &[TrainingSample],
    val_set: &[TrainingSample],
    config: &MlpConfig,
    mins: &[f32],
    maxs: &[f32],
    epochs: usize,
    learning_rate: f64,
    batch_size: usize,
    device: &<TrainBackend as Backend>::Device,
    artifact_dir: &Path,
) -> crate::training::mlp::MlpModel<Wgpu<f32, i32>> {
    let model = config.init::<TrainBackend>(device);

    let train_dataset = SampleDataset::new(train_set, mins, maxs);
    let val_dataset = SampleDataset::new(val_set, mins, maxs);

    let dataloader_train = DataLoaderBuilder::new(SampleBatcher::new())
        .batch_size(batch_size)
        .shuffle(42)
        .num_workers(1)
        .build(train_dataset);

    let dataloader_valid = DataLoaderBuilder::new(SampleBatcher::new())
        .batch_size(batch_size)
        .num_workers(1)
        .build(val_dataset);

    // Cosine annealing: initial_lr must be in (0.0, 1.0].
    let lr = learning_rate.min(1.0);
    let lr_scheduler = CosineAnnealingLrSchedulerConfig::new(lr, epochs)
        .init()
        .expect("valid cosine annealing config");

    let learner = Learner::new(model, AdamConfig::new().init(), lr_scheduler);

    let result = SupervisedTraining::new(artifact_dir, dataloader_train, dataloader_valid)
        .metric_train_numeric(AccuracyMetric::new())
        .metric_valid_numeric(AccuracyMetric::new())
        .metric_train_numeric(LossMetric::new())
        .metric_valid_numeric(LossMetric::new())
        .with_file_checkpointer(CompactRecorder::new())
        .num_epochs(epochs)
        .summary()
        .launch(learner);

    result.model
}

// ---------------------------------------------------------------------------
// Weight extraction
// ---------------------------------------------------------------------------

fn extract_weights(
    model: &crate::training::mlp::MlpModel<Wgpu<f32, i32>>,
    name: &str,
    tree_nodes: &[(u8, f32, u16, u16)],
    threshold: f32,
    norm_mins: &[f32],
    norm_maxs: &[f32],
    _device: &<Wgpu<f32, i32> as Backend>::Device,
) -> ExportedModel {
    let w1_tensor = model.linear1.weight.val();
    let b1_tensor = model.linear1.bias.as_ref().expect("linear1 has bias").val();
    let w2_tensor = model.linear2.weight.val();
    let b2_tensor = model.linear2.bias.as_ref().expect("linear2 has bias").val();

    let w1_data: Vec<f32> = w1_tensor.to_data().to_vec().expect("w1 flat");
    let b1_data: Vec<f32> = b1_tensor.to_data().to_vec().expect("b1 flat");
    let w2_data: Vec<f32> = w2_tensor.to_data().to_vec().expect("w2 flat");
    let b2_data: Vec<f32> = b2_tensor.to_data().to_vec().expect("b2 flat");

    let hidden_dim = b1_data.len();
    let input_dim = w1_data.len() / hidden_dim;

    let w1: Vec<Vec<f32>> = (0..hidden_dim)
        .map(|h| w1_data[h * input_dim..(h + 1) * input_dim].to_vec())
        .collect();

    ExportedModel {
        model_name: name.to_string(),
        input_dim,
        hidden_dim,
        w1,
        b1: b1_data,
        w2: w2_data,
        b2: b2_data[0],
        tree_nodes: tree_nodes.to_vec(),
        threshold,
        norm_mins: norm_mins.to_vec(),
        norm_maxs: norm_maxs.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::sample::{DataSource, TrainingSample};

    fn make_ddos_sample(features: [f32; 14], label: f32) -> TrainingSample {
        TrainingSample {
            features: features.to_vec(),
            label,
            source: DataSource::ProductionLogs,
            weight: 1.0,
        }
    }

    #[test]
    fn test_stratified_split_preserves_ratio() {
        let mut samples = Vec::new();
        for _ in 0..80 {
            samples.push(make_ddos_sample([0.0; 14], 0.0));
        }
        for _ in 0..20 {
            samples.push(make_ddos_sample([1.0; 14], 1.0));
        }

        let (train, val) = stratified_split(&samples, 0.8);

        let train_attacks = train.iter().filter(|s| s.label >= 0.5).count();
        let val_attacks = val.iter().filter(|s| s.label >= 0.5).count();

        assert_eq!(train_attacks, 16);
        assert_eq!(val_attacks, 4);
        assert_eq!(train.len() + val.len(), 100);
    }

    #[test]
    fn test_norm_params_14_features() {
        let samples = vec![
            make_ddos_sample([0.0; 14], 0.0),
            make_ddos_sample([1.0; 14], 1.0),
        ];
        let (mins, maxs) = compute_norm_params(&samples);
        assert_eq!(mins.len(), 14);
        assert_eq!(maxs.len(), 14);
        assert_eq!(mins[0], 0.0);
        assert_eq!(maxs[0], 1.0);
    }
}
