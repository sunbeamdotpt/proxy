//! DDoS MLP+tree training loop.
//!
//! Loads a `DatasetManifest`, trains a CART decision tree and a burn-rs MLP,
//! then exports the combined ensemble weights as a Rust source file that can
//! be dropped into `src/ensemble/gen/ddos_weights.rs`.

use anyhow::{Context, Result};
use std::path::Path;

use burn::backend::ndarray::NdArray;
use burn::backend::Autodiff;
use burn::module::AutodiffModule;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::prelude::*;

use crate::dataset::sample::{load_dataset, TrainingSample};
use crate::training::export::{export_to_file, ExportedModel};
use crate::training::mlp::MlpConfig;
use crate::training::tree::{train_tree, tree_predict, TreeConfig, TreeDecision};

/// Number of DDoS features (matches `crate::ddos::features::NUM_FEATURES`).
const NUM_FEATURES: usize = 14;

type TrainBackend = Autodiff<NdArray<f32>>;

/// Arguments for the DDoS MLP training command.
pub struct TrainDdosMlpArgs {
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
    /// CART max depth (default 6).
    pub tree_max_depth: usize,
    /// CART leaf purity threshold (default 0.90).
    pub tree_min_purity: f32,
}

impl Default for TrainDdosMlpArgs {
    fn default() -> Self {
        Self {
            dataset_path: String::new(),
            output_dir: ".".into(),
            hidden_dim: 32,
            epochs: 100,
            learning_rate: 0.001,
            batch_size: 64,
            tree_max_depth: 6,
            tree_min_purity: 0.90,
        }
    }
}

/// Entry point: train DDoS ensemble and export weights.
pub fn run(args: TrainDdosMlpArgs) -> Result<()> {
    // 1. Load dataset.
    let manifest = load_dataset(Path::new(&args.dataset_path))
        .context("loading dataset manifest")?;

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

    // 3. Stratified 80/20 split.
    let (train_set, val_set) = stratified_split(samples, 0.8);
    println!(
        "[ddos] train={}, val={}",
        train_set.len(),
        val_set.len()
    );

    // 4. Train CART tree.
    let tree_config = TreeConfig {
        max_depth: args.tree_max_depth,
        min_samples_leaf: 5,
        min_purity: args.tree_min_purity,
        num_features: NUM_FEATURES,
    };
    let tree_nodes = train_tree(&train_set, &tree_config);
    println!("[ddos] CART tree: {} nodes", tree_nodes.len());

    // Evaluate tree on validation set.
    let (tree_correct, tree_deferred) = eval_tree(&tree_nodes, &val_set, &norm_mins, &norm_maxs);
    println!(
        "[ddos] tree validation: {:.2}% correct (of decided), {:.1}% deferred",
        tree_correct * 100.0,
        tree_deferred * 100.0,
    );

    // 5. Train MLP on the full training set.
    let device = Default::default();
    let mlp_config = MlpConfig {
        input_dim: NUM_FEATURES,
        hidden_dim: args.hidden_dim,
    };

    let model = train_mlp(
        &train_set,
        &val_set,
        &mlp_config,
        &norm_mins,
        &norm_maxs,
        args.epochs,
        args.learning_rate,
        args.batch_size,
        &device,
    );

    // 6. Extract weights from trained model.
    let exported = extract_weights(
        &model,
        "ddos",
        &tree_nodes,
        0.5, // threshold
        &norm_mins,
        &norm_maxs,
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

// ---------------------------------------------------------------------------
// MLP training
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
) -> crate::training::mlp::MlpModel<NdArray<f32>> {
    let mut model = config.init::<TrainBackend>(device);
    let mut optim = AdamConfig::new().init();

    // Pre-normalize all training data.
    let train_features: Vec<Vec<f32>> = train_set
        .iter()
        .map(|s| normalize_features(&s.features, mins, maxs))
        .collect();
    let train_labels: Vec<f32> = train_set.iter().map(|s| s.label).collect();
    let train_weights: Vec<f32> = train_set.iter().map(|s| s.weight).collect();

    let n = train_features.len();

    for epoch in 0..epochs {
        let mut epoch_loss = 0.0f32;
        let mut batches = 0usize;

        let mut offset = 0;
        while offset < n {
            let end = (offset + batch_size).min(n);
            let batch_n = end - offset;

            // Build input tensor [batch, features].
            let flat: Vec<f32> = train_features[offset..end]
                .iter()
                .flat_map(|f| f.iter().copied())
                .collect();
            let x = Tensor::<TrainBackend, 1>::from_floats(flat.as_slice(), device)
                .reshape([batch_n, NUM_FEATURES]);

            // Labels [batch, 1].
            let y = Tensor::<TrainBackend, 1>::from_floats(
                &train_labels[offset..end],
                device,
            )
            .reshape([batch_n, 1]);

            // Sample weights [batch, 1].
            let w = Tensor::<TrainBackend, 1>::from_floats(
                &train_weights[offset..end],
                device,
            )
            .reshape([batch_n, 1]);

            // Forward pass.
            let pred = model.forward(x);

            // Binary cross-entropy with sample weights.
            let eps = 1e-7;
            let pred_clamped = pred.clone().clamp(eps, 1.0 - eps);
            let bce = (y.clone() * pred_clamped.clone().log()
                + (y.clone().neg().add_scalar(1.0))
                    * pred_clamped.neg().add_scalar(1.0).log())
            .neg();
            let weighted_bce = bce * w;
            let loss = weighted_bce.mean();

            epoch_loss += loss.clone().into_scalar().elem::<f32>();
            batches += 1;

            // Backward + optimizer step.
            let grads = loss.backward();
            let grads = GradientsParams::from_grads(grads, &model);
            model = optim.step(learning_rate, model, grads);

            offset = end;
        }

        if (epoch + 1) % 10 == 0 || epoch == 0 {
            let avg_loss = epoch_loss / batches as f32;
            let val_acc = eval_mlp_accuracy(&model, val_set, mins, maxs, device);
            println!(
                "[ddos]   epoch {:>4}/{}: loss={:.6}, val_acc={:.4}",
                epoch + 1,
                epochs,
                avg_loss,
                val_acc,
            );
        }
    }

    model.valid()
}

fn eval_mlp_accuracy(
    model: &crate::training::mlp::MlpModel<TrainBackend>,
    val_set: &[TrainingSample],
    mins: &[f32],
    maxs: &[f32],
    device: &<TrainBackend as Backend>::Device,
) -> f64 {
    let flat: Vec<f32> = val_set
        .iter()
        .flat_map(|s| normalize_features(&s.features, mins, maxs))
        .collect();
    let x = Tensor::<TrainBackend, 1>::from_floats(flat.as_slice(), device)
        .reshape([val_set.len(), NUM_FEATURES]);

    let pred = model.forward(x);
    let pred_data: Vec<f32> = pred.to_data().to_vec().expect("flat vec");

    let mut correct = 0usize;
    for (i, s) in val_set.iter().enumerate() {
        let p = pred_data[i];
        let predicted_label = if p >= 0.5 { 1.0 } else { 0.0 };
        if (predicted_label - s.label).abs() < 0.1 {
            correct += 1;
        }
    }
    correct as f64 / val_set.len() as f64
}

// ---------------------------------------------------------------------------
// Weight extraction
// ---------------------------------------------------------------------------

fn extract_weights(
    model: &crate::training::mlp::MlpModel<NdArray<f32>>,
    name: &str,
    tree_nodes: &[(u8, f32, u16, u16)],
    threshold: f32,
    norm_mins: &[f32],
    norm_maxs: &[f32],
    _device: &<NdArray<f32> as Backend>::Device,
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
