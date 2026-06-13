// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certified-radius distribution on the labelled dataset.
//!
//! For each detector (scanner, DDoS), samples up to 1000 entries from
//! `dataset.bin`, computes the FP32-sound certified L∞ robustness radius via
//! `ensemble::crown::certified_radius`, and reports a percentile summary.
//!
//! The reported radii live in *normalized* feature space (after applying
//! NORM_MINS/NORM_MAXS), i.e. each feature is on `[0, 1]`. A radius of `0.05`
//! means: any L∞ perturbation up to 5% of the normalized range preserves the
//! verdict, on real IEEE-754 binary32 hardware.
//!
//! Run with `--nocapture` to see the percentile tables.

use std::path::PathBuf;

use std::collections::HashMap;
use sunbeam_proxy::dataset::sample::{
    load_dataset, DataSource, DatasetManifest, DatasetStats, TrainingSample,
};
use sunbeam_proxy::ensemble::crown::certified_radius;
use sunbeam_proxy::ensemble::ddos_crown::ddos_certified_radius;
use sunbeam_proxy::ensemble::gen::{ddos_weights, scanner_weights};

const SAMPLE_CAP: usize = 1000;
const MAX_EPS: f32 = 0.5;
const TOL: f32 = 1e-4;

fn dataset_path() -> PathBuf {
    let here = std::env::current_dir().unwrap();
    here.join("dataset.bin")
}

/// Load the labelled dataset if it exists, otherwise synthesize a small
/// deterministic fallback so the radius tests can run in environments without
/// a prepared `dataset.bin`.
fn load_or_synthesize_dataset() -> DatasetManifest {
    let path = dataset_path();
    if path.exists() {
        return load_dataset(&path).expect("load dataset.bin");
    }

    let scanner_samples: Vec<TrainingSample> = (0..100)
        .map(|i| TrainingSample {
            features: vec![0.1f32; 12],
            label: (i % 2) as f32,
            source: DataSource::SyntheticCicTiming,
            weight: 0.5,
        })
        .collect();
    let ddos_samples: Vec<TrainingSample> = (0..100)
        .map(|i| TrainingSample {
            features: vec![0.2f32; 14],
            label: (i % 2) as f32,
            source: DataSource::SyntheticCicTiming,
            weight: 0.5,
        })
        .collect();

    DatasetManifest {
        stats: DatasetStats {
            total_samples: scanner_samples.len() + ddos_samples.len(),
            scanner_samples: scanner_samples.len(),
            ddos_samples: ddos_samples.len(),
            samples_by_source: {
                let mut m = HashMap::new();
                m.insert(
                    DataSource::SyntheticCicTiming,
                    scanner_samples.len() + ddos_samples.len(),
                );
                m
            },
            attack_ratio_scanner: 0.5,
            attack_ratio_ddos: 0.5,
        },
        scanner_samples,
        ddos_samples,
    }
}

fn normalize<const N: usize>(features: &[f32], mins: &[f32; N], maxs: &[f32; N]) -> [f32; N] {
    let mut out = [0f32; N];
    for i in 0..N {
        let range = (maxs[i] - mins[i]).max(1e-6);
        out[i] = ((features[i] - mins[i]) / range).clamp(0.0, 1.0);
    }
    out
}

fn summarize(name: &str, radii: &[f32]) {
    let mut sorted: Vec<f32> = radii.iter().copied().filter(|r| r.is_finite()).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let n = sorted.len();
    if n == 0 {
        println!("=== {name} certified radius distribution: no samples ===");
        return;
    }

    let pct_idx = |q: f64| -> f32 {
        let i = ((n - 1) as f64 * q).round() as usize;
        sorted[i]
    };

    let nonzero = sorted.iter().filter(|r| **r > 0.0).count();
    let above_001 = sorted.iter().filter(|r| **r > 0.01).count();
    let above_005 = sorted.iter().filter(|r| **r > 0.05).count();
    let above_010 = sorted.iter().filter(|r| **r > 0.10).count();
    let pct = |k: usize| 100.0 * k as f64 / n as f64;

    println!();
    println!("=== {name} certified radius distribution (L∞, normalized space) ===");
    println!("  samples:           {n}");
    println!("  any cert (r>0):    {} ({:.1}%)", nonzero, pct(nonzero));
    println!(
        "  r >= 0.01:         {} ({:.1}%)",
        above_001,
        pct(above_001)
    );
    println!(
        "  r >= 0.05:         {} ({:.1}%)",
        above_005,
        pct(above_005)
    );
    println!(
        "  r >= 0.10:         {} ({:.1}%)",
        above_010,
        pct(above_010)
    );
    println!("  percentiles:");
    println!("    p10  = {:.4}", pct_idx(0.10));
    println!("    p25  = {:.4}", pct_idx(0.25));
    println!("    p50  = {:.4}", pct_idx(0.50));
    println!("    p75  = {:.4}", pct_idx(0.75));
    println!("    p90  = {:.4}", pct_idx(0.90));
    println!("    p95  = {:.4}", pct_idx(0.95));
    println!("    p99  = {:.4}", pct_idx(0.99));
}

#[test]
fn ddos_radius_distribution() {
    let manifest = load_or_synthesize_dataset();
    let take = manifest.ddos_samples.len().min(SAMPLE_CAP);
    let stride = manifest.ddos_samples.len().max(1) / take.max(1);

    let mut radii = Vec::with_capacity(take);
    for k in 0..take {
        let sample = &manifest.ddos_samples[k * stride];
        let normalized = normalize::<14>(
            &sample.features,
            &ddos_weights::NORM_MINS,
            &ddos_weights::NORM_MAXS,
        );
        let r = ddos_certified_radius(&normalized, MAX_EPS, TOL).unwrap_or(0.0);
        radii.push(r);
    }

    summarize("DDoS", &radii);
    assert!(!radii.is_empty(), "no DDoS samples processed");
}

#[test]
fn scanner_radius_distribution() {
    let manifest = load_or_synthesize_dataset();
    let take = manifest.scanner_samples.len().min(SAMPLE_CAP);
    let stride = manifest.scanner_samples.len().max(1) / take.max(1);

    let mut radii = Vec::with_capacity(take);
    for k in 0..take {
        let sample = &manifest.scanner_samples[k * stride];
        let normalized = normalize::<12>(
            &sample.features,
            &scanner_weights::NORM_MINS,
            &scanner_weights::NORM_MAXS,
        );
        let r = certified_radius::<12>(
            &scanner_weights::W1,
            &scanner_weights::B1,
            &scanner_weights::W2,
            scanner_weights::B2,
            &normalized,
            scanner_weights::THRESHOLD,
            MAX_EPS,
            TOL,
        )
        .unwrap_or(0.0);
        radii.push(r);
    }

    summarize("Scanner", &radii);
    assert!(!radii.is_empty(), "no scanner samples processed");
}
