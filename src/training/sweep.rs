// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! Cookie weight sweep: trains full tree+MLP ensembles (GPU via wgpu) across a
//! range of cookie_weight values and reports accuracy metrics for each.

use anyhow::{Context, Result};
use std::path::Path;

use crate::dataset::sample::load_dataset;
use crate::training::train_scanner::TrainScannerMlpArgs;
use crate::training::train_ddos::TrainDdosMlpArgs;

/// Run a sweep across cookie_weight values for either scanner or ddos.
///
/// Each trial does a full GPU training run (tree + MLP) with the specified
/// cookie_weight, writing artifacts to a temp directory.
pub fn run_cookie_sweep(
    dataset_path: &str,
    detector: &str,
    weights_csv: Option<&str>,
    tree_max_depth: usize,
    tree_min_purity: f32,
    min_samples_leaf: usize,
) -> Result<()> {
    // Validate dataset exists and has samples.
    let manifest = load_dataset(Path::new(dataset_path))
        .context("loading dataset manifest")?;

    let (cookie_idx, sample_count) = match detector {
        "scanner" => (3usize, manifest.scanner_samples.len()),
        "ddos" => (10usize, manifest.ddos_samples.len()),
        other => anyhow::bail!("unknown detector '{}', expected 'scanner' or 'ddos'", other),
    };

    anyhow::ensure!(sample_count > 0, "no {} samples in dataset", detector);
    drop(manifest); // Free memory before training loop.

    let weights: Vec<f32> = if let Some(csv) = weights_csv {
        csv.split(',')
            .map(|s| s.trim().parse::<f32>())
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing --weights as comma-separated floats")?
    } else {
        (0..=10).map(|i| i as f32 / 10.0).collect()
    };

    println!(
        "[sweep] {} detector, {} samples, cookie feature index: {}",
        detector, sample_count, cookie_idx,
    );
    println!("[sweep] training {} trials with full tree+MLP (wgpu)\n", weights.len());

    let sweep_dir = tempfile::tempdir().context("creating temp dir for sweep")?;

    for (trial, &cw) in weights.iter().enumerate() {
        let trial_dir = sweep_dir.path().join(format!("trial_{}", trial));
        std::fs::create_dir_all(&trial_dir)?;
        let trial_dir_str = trial_dir.to_string_lossy().to_string();

        println!("━━━ Trial {}/{}: cookie_weight={:.2} ━━━", trial + 1, weights.len(), cw);

        match detector {
            "scanner" => {
                crate::training::train_scanner::run(TrainScannerMlpArgs {
                    dataset_path: dataset_path.to_string(),
                    output_dir: trial_dir_str,
                    hidden_dim: 32,
                    epochs: 100,
                    learning_rate: 0.0001,
                    batch_size: 64,
                    tree_max_depth,
                    tree_min_purity,
                    min_samples_leaf,
                    cookie_weight: cw,
                    tree_excluded_features: vec![3, 4, 5, 6],
                    sign_constraint_lambda: 0.0,
                })?;
            }
            "ddos" => {
                crate::training::train_ddos::run(TrainDdosMlpArgs {
                    dataset_path: dataset_path.to_string(),
                    output_dir: trial_dir_str,
                    hidden_dim: 32,
                    epochs: 100,
                    learning_rate: 0.0001,
                    batch_size: 64,
                    tree_max_depth,
                    tree_min_purity,
                    min_samples_leaf,
                    cookie_weight: cw,
                    tree_excluded_features: vec![10, 11, 12],
                    sign_constraint_lambda: 0.0,
                })?;
            }
            _ => unreachable!(),
        }

        println!();
    }

    println!("[sweep] All {} trials complete.", weights.len());
    println!("[sweep] Tip: compare tree structures and validation accuracy above.");
    println!("[sweep] Look for a cookie_weight where FP rate drops without FN rate spiking.");

    Ok(())
}
