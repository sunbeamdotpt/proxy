// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Scanner MLP+tree training loop using burn's SupervisedTraining.
//!
//! Loads a `DatasetManifest`, trains a CART decision tree and a burn-rs MLP
//! with cosine annealing + early stopping, then exports the combined ensemble
//! weights as a Rust source file for `src/ensemble/gen/scanner_weights.rs`.

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

/// Number of scanner features (matches `crate::scanner::features::NUM_SCANNER_FEATURES`).
const NUM_FEATURES: usize = 12;

type TrainBackend = Autodiff<Wgpu<f32, i32>>;

/// Arguments for the scanner MLP training command.
pub struct TrainScannerMlpArgs {
    /// Path to a bincode `DatasetManifest` file.
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
    /// Weight for cookie feature (feature 3: has_cookies). 0.0 = ignore, 1.0 = full weight.
    pub cookie_weight: f32,
    /// Feature indices the tree must not split on. Defaults to the circumstantial
    /// header-presence features (has_cookies/has_referer/has_accept_language/
    /// accept_quality), forcing those decisions through the MLP where the
    /// certified-radius story applies. Content features like has_suspicious_extension
    /// and path_has_traversal stay tree-eligible.
    pub tree_excluded_features: Vec<usize>,
    /// Tier 2 sign-constraint penalty coefficient. Adds
    /// `λ · Σ_{i ∈ adv} Σ_j relu(-W1[i,j] * W2[j])` to the loss, encouraging
    /// MLP monotonicity in adversarial features. 0.0 disables the penalty.
    pub sign_constraint_lambda: f32,
}

impl Default for TrainScannerMlpArgs {
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
            tree_excluded_features: vec![3, 4, 5, 6],
            sign_constraint_lambda: 0.0,
        }
    }
}

/// Index of the has_cookies feature in the scanner feature vector.
const COOKIE_FEATURE_IDX: usize = 3;

/// Entry point: train scanner ensemble and export weights.
pub fn run(args: TrainScannerMlpArgs) -> Result<()> {
    // 1. Load dataset.
    let manifest = load_dataset(Path::new(&args.dataset_path))
        .context("loading dataset manifest")?;

    let samples = &manifest.scanner_samples;
    anyhow::ensure!(!samples.is_empty(), "no scanner samples in dataset");

    for s in samples {
        anyhow::ensure!(
            s.features.len() == NUM_FEATURES,
            "expected {} features, got {}",
            NUM_FEATURES,
            s.features.len()
        );
    }

    println!(
        "[scanner] loaded {} samples ({} attack, {} normal)",
        samples.len(),
        samples.iter().filter(|s| s.label >= 0.5).count(),
        samples.iter().filter(|s| s.label < 0.5).count(),
    );

    // 2. Compute normalization params from training data.
    let (norm_mins, norm_maxs) = compute_norm_params(samples);

    // Apply cookie_weight: for the MLP, we scale the normalization range so
    // the feature contributes less gradient signal. For the CART tree, scaling
    // doesn't help (the tree just adjusts its threshold), so we mask the feature
    // to a constant on a fraction of training samples to degrade its Gini gain.
    if args.cookie_weight < 1.0 - f32::EPSILON {
        println!(
            "[scanner] cookie_weight={:.2} (feature {} influence reduced)",
            args.cookie_weight, COOKIE_FEATURE_IDX,
        );
    }

    // MLP norm adjustment: scale the cookie feature's normalization range.
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
    println!(
        "[scanner] train={}, val={}",
        train_set.len(),
        val_set.len()
    );

    // 4. Train CART tree (with cookie feature masking for reduced weight).
    let tree_train_set = mask_cookie_feature(&train_set, COOKIE_FEATURE_IDX, args.cookie_weight);
    let tree_config = TreeConfig {
        max_depth: args.tree_max_depth,
        min_samples_leaf: args.min_samples_leaf,
        min_purity: args.tree_min_purity,
        num_features: NUM_FEATURES,
        excluded_features: args.tree_excluded_features.clone(),
    };
    let tree_nodes = train_tree(&tree_train_set, &tree_config);
    println!("[scanner] CART tree: {} nodes (max_depth={})", tree_nodes.len(), args.tree_max_depth);

    // Evaluate tree on validation set (use original norms — tree learned on masked features).
    let (tree_correct, tree_deferred) = eval_tree(&tree_nodes, &val_set, &norm_mins, &norm_maxs);
    println!(
        "[scanner] tree validation: {:.2}% correct (of decided), {:.1}% deferred",
        tree_correct * 100.0,
        tree_deferred * 100.0,
    );

    // 5. Train MLP with SupervisedTraining (uses mlp_norm_maxs for cookie scaling).
    let device = Default::default();
    // Adversarial features for scanner (domain-monotone-bad):
    // suspicious_path_score (0), has_suspicious_extension (2),
    // method_is_unusual (8), content_length_mismatch (10), path_has_traversal (11).
    let mlp_config = MlpConfig {
        input_dim: NUM_FEATURES,
        hidden_dim: args.hidden_dim,
        adversarial_indices: vec![0, 2, 8, 10, 11],
        sign_constraint_lambda: args.sign_constraint_lambda,
    };

    let artifact_dir = Path::new(&args.output_dir).join("scanner_artifacts");
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

    // 6. Extract weights from trained model (export mlp_norm_maxs so inference
    //    automatically applies the same cookie scaling).
    let exported = extract_weights(
        &model,
        "scanner",
        &tree_nodes,
        0.5,
        &norm_mins,
        &mlp_norm_maxs,
        &device,
    );

    // 7. Write output.
    let out_dir = Path::new(&args.output_dir);
    std::fs::create_dir_all(out_dir).context("creating output directory")?;

    let rust_path = out_dir.join("scanner_weights.rs");
    export_to_file(&exported, &rust_path)?;
    println!("[scanner] exported Rust weights to {}", rust_path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Cookie feature masking for CART trees
// ---------------------------------------------------------------------------

/// Mask the cookie feature to reduce its influence on CART tree training.
///
/// Scaling a binary feature doesn't reduce its Gini gain — the tree just adjusts
/// the split threshold. Instead, we mask (set to 0.5) a fraction of samples so
/// the feature's apparent class-separation degrades.
///
/// - `cookie_weight = 0.0` → fully masked (feature is constant 0.5, zero info gain)
/// - `cookie_weight = 0.5` → 50% of samples masked (noisy, reduced gain)
/// - `cookie_weight = 1.0` → no masking (full feature)
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
                let hash = (i as u64).wrapping_mul(6364136223846793005).wrapping_add(42);
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

fn stratified_split(samples: &[TrainingSample], train_ratio: f64) -> (Vec<TrainingSample>, Vec<TrainingSample>) {
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
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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

    let learner = Learner::new(
        model,
        AdamConfig::new().init(),
        lr_scheduler,
    );

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

    fn make_scanner_sample(features: [f32; 12], label: f32) -> TrainingSample {
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
            samples.push(make_scanner_sample([0.0; 12], 0.0));
        }
        for _ in 0..20 {
            samples.push(make_scanner_sample([1.0; 12], 1.0));
        }

        let (train, val) = stratified_split(&samples, 0.8);

        let train_attacks = train.iter().filter(|s| s.label >= 0.5).count();
        let val_attacks = val.iter().filter(|s| s.label >= 0.5).count();

        assert_eq!(train_attacks, 16);
        assert_eq!(val_attacks, 4);
        assert_eq!(train.len() + val.len(), 100);
    }

    #[test]
    fn test_norm_params() {
        let samples = vec![
            make_scanner_sample([0.0, 10.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 0.0),
            make_scanner_sample([1.0, 20.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0], 1.0),
        ];
        let (mins, maxs) = compute_norm_params(&samples);
        assert_eq!(mins[0], 0.0);
        assert_eq!(maxs[0], 1.0);
        assert_eq!(mins[1], 10.0);
        assert_eq!(maxs[1], 20.0);
    }
}
