// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::ddos::audit_log::{AuditLog, AuditFields};
use crate::scanner::features::{
    self, fx_hash_bytes, ScannerFeatureVector, ScannerNormParams, NUM_SCANNER_FEATURES,
    NUM_SCANNER_WEIGHTS,
};
use serde::{Deserialize, Serialize};

/// Legacy linear scanner model — kept for the `train-scanner` CLI command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerModel {
    /// Weights.
    pub weights: [f64; NUM_SCANNER_WEIGHTS],
    /// Threshold.
    pub threshold: f64,
    /// Norm params.
    pub norm_params: ScannerNormParams,
    /// Fragments.
    pub fragments: Vec<String>,
}

impl ScannerModel {
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self).context("serializing scanner model")?;
        std::fs::write(path, data)
            .with_context(|| format!("writing scanner model to {}", path.display()))?;
        Ok(())
    }
}
use anyhow::{Context, Result};
use rustc_hash::FxHashSet;
use std::io::BufRead;
use std::path::Path;

/// Trainscannerargs.
pub struct TrainScannerArgs {
    /// Input.
    pub input: String,
    /// Output.
    pub output: String,
    /// Wordlists.
    pub wordlists: Option<String>,
    /// Threshold.
    pub threshold: f64,
    /// Csic.
    pub csic: bool,
}

/// Default suspicious fragments — matches the DDoS feature list plus extras.
pub const DEFAULT_FRAGMENTS: &[&str] = &[
    ".env", ".git", ".bak", ".sql", ".tar", ".zip",
    "wp-admin", "wp-login", "wp-includes", "wp-content", "xmlrpc",
    "phpinfo", "phpmyadmin", "php-info",
    "cgi-bin", "shell", "eval-stdin",
    ".htaccess", ".htpasswd",
    "config.", "admin",
    "yarn.lock", "package.json", "composer.json",
    "telescope", "actuator", "debug",
];

const ATTACK_EXTENSIONS: &[&str] = &[".env", ".sql", ".bak", ".git/config"];
const TRAVERSAL_MARKERS: &[&str] = &["..", "%00", "%0a"];

/// Labeledsample.
pub struct LabeledSample {
    /// Features.
    pub features: ScannerFeatureVector,
    /// Label.
    pub label: f64, // 1.0 = attack, 0.0 = normal
}

/// Scannertrainresult.
pub struct ScannerTrainResult {
    /// Model.
    pub model: ScannerModel,
    /// Train metrics.
    pub train_metrics: Metrics,
    /// Test metrics.
    pub test_metrics: Metrics,
}

/// Core training pipeline: parse logs, label, train, evaluate. Returns the trained model and metrics.
pub fn train_and_evaluate(
    args: &TrainScannerArgs,
    learning_rate: f64,
    epochs: usize,
    class_weight_multiplier: f64,
) -> Result<ScannerTrainResult> {
    let mut fragments: Vec<String> = DEFAULT_FRAGMENTS.iter().map(|s| s.to_string()).collect();
    let fragment_hashes: FxHashSet<u64> = fragments
        .iter()
        .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
        .collect();
    let extension_hashes: FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();

    let mut samples: Vec<LabeledSample> = Vec::new();
    let file = std::fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);
    let mut log_hosts: FxHashSet<u64> = FxHashSet::default();
    let mut parsed_entries: Vec<(AuditFields, String)> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let host_prefix = entry
            .fields
            .host
            .split('.')
            .next()
            .unwrap_or("")
            .to_string();
        log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
        parsed_entries.push((entry.fields, host_prefix));
    }

    for (fields, host_prefix) in &parsed_entries {
        let has_cookies = fields.has_cookies;
        let has_referer = !fields.referer.is_empty() && fields.referer != "-";
        let has_accept_language = !fields.accept_language.is_empty() && fields.accept_language != "-";

        let feats = features::extract_features(
            &fields.method,
            &fields.path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            "-",
            &fields.user_agent,
            fields.content_length,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        );

        let label = if let Some(ref gt) = fields.label {
            match gt.as_str() {
                "attack" | "anomalous" => Some(1.0),
                "normal" => Some(0.0),
                _ => None,
            }
        } else {
            label_request(
                &fields.path,
                has_cookies,
                has_referer,
                has_accept_language,
                &fields.user_agent,
                host_prefix,
                fields.status,
                &log_hosts,
                &fragment_hashes,
            )
        };

        if let Some(l) = label {
            samples.push(LabeledSample {
                features: feats,
                label: l,
            });
        }
    }

    if args.csic {
        let csic_entries = crate::scanner::csic::fetch_csic_dataset()?;
        for (_, host_prefix) in &csic_entries {
            log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
        }
        for (fields, host_prefix) in &csic_entries {
            let has_cookies = fields.has_cookies;
            let has_referer = !fields.referer.is_empty() && fields.referer != "-";
            let has_accept_language = !fields.accept_language.is_empty() && fields.accept_language != "-";

            let feats = features::extract_features(
                &fields.method,
                &fields.path,
                host_prefix,
                has_cookies,
                has_referer,
                has_accept_language,
                "-",
                &fields.user_agent,
                fields.content_length,
                &fragment_hashes,
                &extension_hashes,
                &log_hosts,
            );

            let label = match fields.label.as_deref() {
                Some("attack" | "anomalous") => 1.0,
                Some("normal") => 0.0,
                _ => continue,
            };

            samples.push(LabeledSample {
                features: feats,
                label,
            });
        }
    }

    if let Some(wordlist_dir) = &args.wordlists {
        ingest_wordlists(
            wordlist_dir,
            &mut samples,
            &mut fragments,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        )?;
    }

    if samples.is_empty() {
        anyhow::bail!("no training samples found");
    }

    // Stratified 80/20 train/test split
    let (train_samples, test_samples) = stratified_split(&mut samples, 0.8, 42);

    // Compute normalization params from training set only
    let train_feature_vecs: Vec<ScannerFeatureVector> =
        train_samples.iter().map(|s| s.features).collect();
    let norm_params = ScannerNormParams::from_data(&train_feature_vecs);

    let train_normalized: Vec<ScannerFeatureVector> =
        train_feature_vecs.iter().map(|v| norm_params.normalize(v)).collect();

    // Train logistic regression with configurable params
    let weights = train_logistic_regression_weighted(
        &train_normalized,
        &train_samples,
        epochs,
        learning_rate,
        class_weight_multiplier,
    );

    let model = ScannerModel {
        weights,
        threshold: args.threshold,
        norm_params: norm_params.clone(),
        fragments,
    };

    let train_metrics = evaluate(&train_normalized, &train_samples, &weights, args.threshold);

    let test_feature_vecs: Vec<ScannerFeatureVector> =
        test_samples.iter().map(|s| s.features).collect();
    let test_normalized: Vec<ScannerFeatureVector> =
        test_feature_vecs.iter().map(|v| norm_params.normalize(v)).collect();
    let test_metrics = evaluate(&test_normalized, &test_samples, &weights, args.threshold);

    Ok(ScannerTrainResult {
        model,
        train_metrics,
        test_metrics,
    })
}

/// Run.
pub fn run(args: TrainScannerArgs) -> Result<()> {
    let mut fragments: Vec<String> = DEFAULT_FRAGMENTS.iter().map(|s| s.to_string()).collect();
    let fragment_hashes: FxHashSet<u64> = fragments
        .iter()
        .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
        .collect();
    let extension_hashes: FxHashSet<u64> = features::SUSPICIOUS_EXTENSIONS_LIST
        .iter()
        .map(|e| fx_hash_bytes(e.as_bytes()))
        .collect();
    // Populated below from observed log hosts.
    let _configured_hosts: FxHashSet<u64> = FxHashSet::default();

    // 1. Parse JSONL audit logs and label each request
    let mut samples: Vec<LabeledSample> = Vec::new();
    let file = std::fs::File::open(&args.input)
        .with_context(|| format!("opening {}", args.input))?;
    let reader = std::io::BufReader::new(file);
    let mut log_hosts: FxHashSet<u64> = FxHashSet::default();
    let mut parsed_entries: Vec<(AuditFields, String)> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditLog = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let host_prefix = entry
            .fields
            .host
            .split('.')
            .next()
            .unwrap_or("")
            .to_string();
        log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
        parsed_entries.push((entry.fields, host_prefix));
    }

    for (fields, host_prefix) in &parsed_entries {
        let has_cookies = fields.has_cookies;
        let has_referer = !fields.referer.is_empty() && fields.referer != "-";
        let has_accept_language = !fields.accept_language.is_empty() && fields.accept_language != "-";

        let feats = features::extract_features(
            &fields.method,
            &fields.path,
            host_prefix,
            has_cookies,
            has_referer,
            has_accept_language,
            "-", // accept not in audit log, use default
            &fields.user_agent,
            fields.content_length,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts, // treat all observed hosts as configured during training
        );

        // Use ground-truth label if present (external datasets like CSIC 2010),
        // otherwise fall back to heuristic labeling.
        let label = if let Some(ref gt) = fields.label {
            match gt.as_str() {
                "attack" | "anomalous" => Some(1.0),
                "normal" => Some(0.0),
                _ => None,
            }
        } else {
            label_request(
                &fields.path,
                has_cookies,
                has_referer,
                has_accept_language,
                &fields.user_agent,
                host_prefix,
                fields.status,
                &log_hosts,
                &fragment_hashes,
            )
        };

        if let Some(l) = label {
            samples.push(LabeledSample {
                features: feats,
                label: l,
            });
        }
    }

    // 1b. Optionally fetch CSIC 2010 dataset and add labeled entries
    if args.csic {
        let csic_entries = crate::scanner::csic::fetch_csic_dataset()?;
        for (_, host_prefix) in &csic_entries {
            log_hosts.insert(fx_hash_bytes(host_prefix.as_bytes()));
        }
        for (fields, host_prefix) in &csic_entries {
            let has_cookies = fields.has_cookies;
            let has_referer = !fields.referer.is_empty() && fields.referer != "-";
            let has_accept_language = !fields.accept_language.is_empty() && fields.accept_language != "-";

            let feats = features::extract_features(
                &fields.method,
                &fields.path,
                host_prefix,
                has_cookies,
                has_referer,
                has_accept_language,
                "-",
                &fields.user_agent,
                fields.content_length,
                &fragment_hashes,
                &extension_hashes,
                &log_hosts,
            );

            // CSIC entries always have a ground-truth label.
            let label = match fields.label.as_deref() {
                Some("attack" | "anomalous") => 1.0,
                Some("normal") => 0.0,
                _ => continue,
            };

            samples.push(LabeledSample {
                features: feats,
                label,
            });
        }
    }

    let log_sample_count = samples.len();
    let log_attack_count = samples.iter().filter(|s| s.label > 0.5).count();
    eprintln!(
        "log samples: {} ({} attack, {} normal)",
        log_sample_count,
        log_attack_count,
        log_sample_count - log_attack_count,
    );

    // 2. Ingest wordlist files for synthetic attack samples
    if let Some(wordlist_dir) = &args.wordlists {
        let wordlist_count = ingest_wordlists(
            wordlist_dir,
            &mut samples,
            &mut fragments,
            &fragment_hashes,
            &extension_hashes,
            &log_hosts,
        )?;
        eprintln!("synthetic attack samples from wordlists: {wordlist_count}");
    }

    if samples.is_empty() {
        anyhow::bail!("no training samples found");
    }

    let attack_total = samples.iter().filter(|s| s.label > 0.5).count();
    let normal_total = samples.len() - attack_total;
    eprintln!(
        "total samples: {} ({} attack, {} normal)",
        samples.len(),
        attack_total,
        normal_total,
    );

    // 3. Stratified 80/20 train/test split (deterministic shuffle via simple LCG)
    let (train_samples, test_samples) = stratified_split(&mut samples, 0.8, 42);
    eprintln!(
        "train: {} ({} attack, {} normal)",
        train_samples.len(),
        train_samples.iter().filter(|s| s.label > 0.5).count(),
        train_samples.iter().filter(|s| s.label <= 0.5).count(),
    );
    eprintln!(
        "test:  {} ({} attack, {} normal)",
        test_samples.len(),
        test_samples.iter().filter(|s| s.label > 0.5).count(),
        test_samples.iter().filter(|s| s.label <= 0.5).count(),
    );

    // 4. Compute normalization params from training set only
    let train_feature_vecs: Vec<ScannerFeatureVector> =
        train_samples.iter().map(|s| s.features).collect();
    let norm_params = ScannerNormParams::from_data(&train_feature_vecs);

    // 5. Normalize training features
    let train_normalized: Vec<ScannerFeatureVector> =
        train_feature_vecs.iter().map(|v| norm_params.normalize(v)).collect();

    // 6. Train logistic regression
    let weights = train_logistic_regression(&train_normalized, &train_samples, 1000, 0.01);

    eprintln!("\nlearned weights:");
    let feature_names = [
        "suspicious_path_score",
        "path_depth",
        "has_suspicious_extension",
        "has_cookies",
        "has_referer",
        "has_accept_language",
        "accept_quality",
        "ua_category",
        "method_is_unusual",
        "host_is_configured",
        "content_length_mismatch",
        "path_has_traversal",
        "interaction:path*no_cookies",
        "interaction:no_host*no_lang",
        "bias",
    ];
    for (i, name) in feature_names.iter().enumerate() {
        eprintln!("  w[{i:2}] {name:>35} = {:.4}", weights[i]);
    }

    // 7. Save model
    let model = ScannerModel {
        weights,
        threshold: args.threshold,
        norm_params: norm_params.clone(),
        fragments,
    };
    model.save(Path::new(&args.output))?;
    eprintln!("\nmodel saved to {}", args.output);

    // 8. Evaluate on training set
    let train_metrics = evaluate(&train_normalized, &train_samples, &weights, args.threshold);
    eprintln!("\n--- training set ---");
    train_metrics.print(train_samples.len());

    // 9. Evaluate on held-out test set
    let test_feature_vecs: Vec<ScannerFeatureVector> =
        test_samples.iter().map(|s| s.features).collect();
    let test_normalized: Vec<ScannerFeatureVector> =
        test_feature_vecs.iter().map(|v| norm_params.normalize(v)).collect();
    let test_metrics = evaluate(&test_normalized, &test_samples, &weights, args.threshold);
    eprintln!("\n--- test set (held-out 20%) ---");
    test_metrics.print(test_samples.len());

    Ok(())
}

/// Metrics.
pub struct Metrics {
    /// Tp.
    pub tp: u32,
    /// Fp.
    pub fp: u32,
    /// Tn.
    pub tn: u32,
    /// Fn .
    pub fn_: u32,
}

impl Metrics {
    pub fn precision(&self) -> f64 {
        if self.tp + self.fp > 0 { self.tp as f64 / (self.tp + self.fp) as f64 } else { 0.0 }
    }
    pub fn recall(&self) -> f64 {
        if self.tp + self.fn_ > 0 { self.tp as f64 / (self.tp + self.fn_) as f64 } else { 0.0 }
    }
    pub fn f1(&self) -> f64 {
        self.fbeta(1.0)
    }
    pub fn fbeta(&self, beta: f64) -> f64 {
        let p = self.precision();
        let r = self.recall();
        let b2 = beta * beta;
        if p + r > 0.0 { (1.0 + b2) * p * r / (b2 * p + r) } else { 0.0 }
    }
    fn print(&self, total: usize) {
        let acc = (self.tp + self.tn) as f64 / total as f64 * 100.0;
        eprintln!(
            "accuracy: {acc:.1}% (tp={} fp={} tn={} fn={})",
            self.tp, self.fp, self.tn, self.fn_,
        );
        eprintln!(
            "precision={:.3} recall={:.3} f1={:.3}",
            self.precision(), self.recall(), self.f1(),
        );
    }
}

fn evaluate(
    normalized: &[ScannerFeatureVector],
    samples: &[LabeledSample],
    weights: &[f64; NUM_SCANNER_WEIGHTS],
    threshold: f64,
) -> Metrics {
    let mut m = Metrics { tp: 0, fp: 0, tn: 0, fn_: 0 };
    for (i, sample) in samples.iter().enumerate() {
        let f = &normalized[i];
        let mut score = weights[NUM_SCANNER_FEATURES + 2];
        for j in 0..NUM_SCANNER_FEATURES {
            score += weights[j] * f[j];
        }
        score += weights[12] * f[0] * (1.0 - f[3]);
        score += weights[13] * (1.0 - f[9]) * (1.0 - f[5]);
        let predicted = score > threshold;
        let actual = sample.label > 0.5;
        match (predicted, actual) {
            (true, true) => m.tp += 1,
            (true, false) => m.fp += 1,
            (false, false) => m.tn += 1,
            (false, true) => m.fn_ += 1,
        }
    }
    m
}

/// Deterministic stratified split: separates attack/normal, shuffles each with
/// a simple LCG, then takes `train_frac` from each class.
fn stratified_split(
    samples: &mut Vec<LabeledSample>,
    train_frac: f64,
    seed: u64,
) -> (Vec<LabeledSample>, Vec<LabeledSample>) {
    // Partition into two classes
    let mut attacks: Vec<LabeledSample> = Vec::new();
    let mut normals: Vec<LabeledSample> = Vec::new();
    for s in samples.drain(..) {
        if s.label > 0.5 { attacks.push(s); } else { normals.push(s); }
    }

    // Deterministic Fisher-Yates shuffle using LCG
    fn lcg_shuffle(v: &mut [LabeledSample], seed: u64) {
        let mut state = seed;
        for i in (1..v.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state >> 33) as usize % (i + 1);
            v.swap(i, j);
        }
    }
    lcg_shuffle(&mut attacks, seed);
    lcg_shuffle(&mut normals, seed.wrapping_add(1));

    let attack_train_n = (attacks.len() as f64 * train_frac) as usize;
    let normal_train_n = (normals.len() as f64 * train_frac) as usize;

    let attack_test: Vec<_> = attacks.split_off(attack_train_n);
    let normal_test: Vec<_> = normals.split_off(normal_train_n);

    let mut train = attacks;
    train.extend(normals);
    let mut test = attack_test;
    test.extend(normal_test);

    (train, test)
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

fn train_logistic_regression(
    normalized: &[ScannerFeatureVector],
    samples: &[LabeledSample],
    epochs: usize,
    learning_rate: f64,
) -> [f64; NUM_SCANNER_WEIGHTS] {
    let mut weights = [0.0f64; NUM_SCANNER_WEIGHTS];
    let n = samples.len() as f64;

    // Class weighting: give the minority class proportionally stronger gradients
    // so the model doesn't collapse to always-predict-majority.
    let n_attack = samples.iter().filter(|s| s.label > 0.5).count() as f64;
    let n_normal = n - n_attack;
    let (w_attack, w_normal) = if n_attack > 0.0 && n_normal > 0.0 {
        (n / (2.0 * n_attack), n / (2.0 * n_normal))
    } else {
        (1.0, 1.0)
    };
    eprintln!("class weights: attack={w_attack:.2} normal={w_normal:.2}");

    for _epoch in 0..epochs {
        let mut gradients = [0.0f64; NUM_SCANNER_WEIGHTS];

        for (i, sample) in samples.iter().enumerate() {
            let f = &normalized[i];

            // Compute prediction
            let mut z = weights[NUM_SCANNER_FEATURES + 2]; // bias
            for j in 0..NUM_SCANNER_FEATURES {
                z += weights[j] * f[j];
            }
            z += weights[12] * f[0] * (1.0 - f[3]);
            z += weights[13] * (1.0 - f[9]) * (1.0 - f[5]);

            let prediction = sigmoid(z);
            let error = prediction - sample.label;

            // Apply class weight
            let cw = if sample.label > 0.5 { w_attack } else { w_normal };
            let weighted_error = error * cw;

            // Accumulate gradients
            for j in 0..NUM_SCANNER_FEATURES {
                gradients[j] += weighted_error * f[j];
            }
            gradients[12] += weighted_error * f[0] * (1.0 - f[3]);
            gradients[13] += weighted_error * (1.0 - f[9]) * (1.0 - f[5]);
            gradients[14] += weighted_error;
        }

        // Update weights
        for j in 0..NUM_SCANNER_WEIGHTS {
            weights[j] -= learning_rate * gradients[j] / n;
        }
    }

    weights
}

/// Like `train_logistic_regression` but with configurable class_weight_multiplier.
/// A multiplier > 1.0 increases the weight of the minority (attack) class further.
fn train_logistic_regression_weighted(
    normalized: &[ScannerFeatureVector],
    samples: &[LabeledSample],
    epochs: usize,
    learning_rate: f64,
    class_weight_multiplier: f64,
) -> [f64; NUM_SCANNER_WEIGHTS] {
    let mut weights = [0.0f64; NUM_SCANNER_WEIGHTS];
    let n = samples.len() as f64;

    let n_attack = samples.iter().filter(|s| s.label > 0.5).count() as f64;
    let n_normal = n - n_attack;
    let (w_attack, w_normal) = if n_attack > 0.0 && n_normal > 0.0 {
        (n / (2.0 * n_attack) * class_weight_multiplier, n / (2.0 * n_normal))
    } else {
        (1.0, 1.0)
    };

    for _epoch in 0..epochs {
        let mut gradients = [0.0f64; NUM_SCANNER_WEIGHTS];

        for (i, sample) in samples.iter().enumerate() {
            let f = &normalized[i];
            let mut z = weights[NUM_SCANNER_FEATURES + 2];
            for j in 0..NUM_SCANNER_FEATURES {
                z += weights[j] * f[j];
            }
            z += weights[12] * f[0] * (1.0 - f[3]);
            z += weights[13] * (1.0 - f[9]) * (1.0 - f[5]);

            let prediction = sigmoid(z);
            let error = prediction - sample.label;
            let cw = if sample.label > 0.5 { w_attack } else { w_normal };
            let weighted_error = error * cw;

            for j in 0..NUM_SCANNER_FEATURES {
                gradients[j] += weighted_error * f[j];
            }
            gradients[12] += weighted_error * f[0] * (1.0 - f[3]);
            gradients[13] += weighted_error * (1.0 - f[9]) * (1.0 - f[5]);
            gradients[14] += weighted_error;
        }

        for j in 0..NUM_SCANNER_WEIGHTS {
            weights[j] -= learning_rate * gradients[j] / n;
        }
    }

    weights
}

#[allow(clippy::too_many_arguments)]
fn label_request(
    path: &str,
    has_cookies: bool,
    has_referer: bool,
    has_accept_language: bool,
    user_agent: &str,
    host_prefix: &str,
    status: u16,
    configured_hosts: &FxHashSet<u64>,
    fragment_hashes: &FxHashSet<u64>,
) -> Option<f64> {
    let lower_path = path.to_ascii_lowercase();
    let host_hash = fx_hash_bytes(host_prefix.as_bytes());
    let host_known = configured_hosts.contains(&host_hash);

    let path_suspicious = is_path_suspicious(&lower_path, fragment_hashes);
    let has_traversal = TRAVERSAL_MARKERS
        .iter()
        .any(|m| lower_path.contains(m));

    // Attack if:
    // - Path matches 2+ suspicious fragments AND (no cookies OR no referer)
    if path_suspicious >= 2 && (!has_cookies || !has_referer) {
        return Some(1.0);
    }
    // - Path ends in known-bad extension
    for ext in ATTACK_EXTENSIONS {
        if lower_path.ends_with(ext) && !has_cookies {
            return Some(1.0);
        }
    }
    // - Path contains traversal chars
    if has_traversal {
        return Some(1.0);
    }
    // - Unknown host AND no cookies AND no accept-language
    if !host_known && !has_cookies && !has_accept_language {
        // Only if UA is also suspicious
        let ua_lower = user_agent.to_ascii_lowercase();
        if ua_lower.is_empty()
            || ua_lower == "-"
            || ua_lower.starts_with("curl/")
            || ua_lower.starts_with("python")
            || ua_lower.starts_with("go-http")
        {
            return Some(1.0);
        }
    }
    // - Empty UA AND path has suspicious fragments
    if (user_agent.is_empty() || user_agent == "-") && path_suspicious >= 1 {
        return Some(1.0);
    }

    // Normal if:
    // - Configured host AND has cookies
    if host_known && has_cookies {
        return Some(0.0);
    }
    // - Status 2xx AND has cookies AND has referer
    if (200..300).contains(&status) && has_cookies && has_referer {
        return Some(0.0);
    }

    // Ambiguous — skip
    None
}

fn is_path_suspicious(lower_path: &str, fragment_hashes: &FxHashSet<u64>) -> u32 {
    let mut count = 0u32;
    for segment in lower_path.split('/') {
        if segment.is_empty() {
            continue;
        }
        let hash = fx_hash_bytes(segment.as_bytes());
        if fragment_hashes.contains(&hash) {
            count += 1;
        }
    }
    count
}

fn ingest_wordlists(
    dir_path: &str,
    samples: &mut Vec<LabeledSample>,
    fragments: &mut Vec<String>,
    fragment_hashes: &FxHashSet<u64>,
    extension_hashes: &FxHashSet<u64>,
    configured_hosts: &FxHashSet<u64>,
) -> Result<usize> {
    let dir = Path::new(dir_path);
    if !dir.exists() {
        anyhow::bail!("wordlist directory not found: {dir_path}");
    }

    let mut count = 0usize;
    let mut new_fragment_hashes = fragment_hashes.clone();

    let entries: Vec<_> = if dir.is_file() {
        vec![dir.to_path_buf()]
    } else {
        std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false))
            .collect()
    };

    for path in &entries {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening wordlist {}", path.display()))?;
        let reader = std::io::BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Normalize: ensure leading /
            let normalized_path = if line.starts_with('/') {
                line.to_string()
            } else {
                format!("/{line}")
            };

            // Add path segments as fragments
            for segment in normalized_path.split('/') {
                if segment.is_empty() || segment.len() < 3 {
                    continue;
                }
                let lower = segment.to_ascii_lowercase();
                let hash = fx_hash_bytes(lower.as_bytes());
                if !new_fragment_hashes.contains(&hash) {
                    new_fragment_hashes.insert(hash);
                    fragments.push(lower);
                }
            }

            // Generate synthetic attack sample
            let feats = features::extract_features(
                "GET",
                &normalized_path,
                "unknown-host",
                false, // no cookies
                false, // no referer
                false, // no accept-language
                "*/*",
                "curl/7.0",
                0,
                &new_fragment_hashes,
                extension_hashes,
                configured_hosts,
            );

            samples.push(LabeledSample {
                features: feats,
                label: 1.0,
            });
            count += 1;
        }
    }

    eprintln!("fragment vocabulary size: {}", fragments.len());
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigmoid() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-10);
        assert!(sigmoid(10.0) > 0.99);
        assert!(sigmoid(-10.0) < 0.01);
    }

    #[test]
    fn test_label_request_env_probe() {
        let hosts = FxHashSet::default();
        let frags: FxHashSet<u64> = DEFAULT_FRAGMENTS
            .iter()
            .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
            .collect();

        let label = label_request(
            "/.env",
            false, false, false,
            "curl/7.0", "unknown", 404,
            &hosts, &frags,
        );
        assert_eq!(label, Some(1.0));
    }

    #[test]
    fn test_label_request_normal_browser() {
        let mut hosts = FxHashSet::default();
        hosts.insert(fx_hash_bytes(b"app"));
        let frags: FxHashSet<u64> = DEFAULT_FRAGMENTS
            .iter()
            .map(|f| fx_hash_bytes(f.to_ascii_lowercase().as_bytes()))
            .collect();

        let label = label_request(
            "/blog/hello",
            true, true, true,
            "Mozilla/5.0", "app", 200,
            &hosts, &frags,
        );
        assert_eq!(label, Some(0.0));
    }

    #[test]
    fn test_label_request_traversal() {
        let hosts = FxHashSet::default();
        let frags = FxHashSet::default();
        let label = label_request(
            "/../../etc/passwd",
            false, false, false,
            "", "unknown", 404,
            &hosts, &frags,
        );
        assert_eq!(label, Some(1.0));
    }

    #[test]
    fn test_logistic_regression_converges() {
        // Simple separable dataset: attack features have high f[0], normal have low
        let mut samples = Vec::new();
        let mut features = Vec::new();
        for _ in 0..50 {
            let f = [0.9, 0.5, 0.8, 0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.8];
            features.push(f);
            samples.push(LabeledSample { features: f, label: 1.0 });
        }
        for _ in 0..50 {
            let f = [0.1, 0.2, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0, 0.0, 1.0, 0.0, 0.0];
            features.push(f);
            samples.push(LabeledSample { features: f, label: 0.0 });
        }

        let weights = train_logistic_regression(&features, &samples, 500, 0.1);

        // Verify attack weight is positive, cookie weight is negative
        assert!(weights[0] > 0.0, "suspicious_path weight should be positive");
        assert!(weights[3] < 0.0, "has_cookies weight should be negative");
    }
}
