// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

//! CIC-IDS2017 timing profile extractor.
//!
//! Parses CIC-IDS2017 CSV files and extracts statistical timing profiles
//! per attack type.  These profiles are NOT training samples themselves —
//! they feed the synthetic data generator (`synthetic.rs`) which samples
//! from the learned distributions to produce DDoS training features.

use anyhow::{Context, Result};
use std::path::Path;

/// Statistical timing profile for one attack type from CIC-IDS2017.
#[derive(Debug, Clone)]
pub struct TimingProfile {
    /// Attack type.
    pub attack_type: String,
    /// Inter arrival mean.
    pub inter_arrival_mean: f64,
    /// Inter arrival std.
    pub inter_arrival_std: f64,
    /// Burst duration mean.
    pub burst_duration_mean: f64,
    /// Burst duration std.
    pub burst_duration_std: f64,
    /// Flow bytes per sec mean.
    pub flow_bytes_per_sec_mean: f64,
    /// Flow bytes per sec std.
    pub flow_bytes_per_sec_std: f64,
    /// Sample count.
    pub sample_count: usize,
}

/// Accumulator for computing mean and variance in a single pass (Welford's algorithm).
#[derive(Default)]
struct StatsAccumulator {
    count: usize,
    mean: f64,
    m2: f64,
}

impl StatsAccumulator {
    fn push(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    fn mean(&self) -> f64 {
        self.mean
    }

    fn std_dev(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f64).sqrt()
        }
    }
}

/// Per-label accumulator for timing statistics.
struct LabelAccumulator {
    label: String,
    inter_arrival: StatsAccumulator,
    burst_duration: StatsAccumulator,
    flow_bytes_per_sec: StatsAccumulator,
    count: usize,
}

impl LabelAccumulator {
    fn new(label: String) -> Self {
        Self {
            label,
            inter_arrival: StatsAccumulator::default(),
            burst_duration: StatsAccumulator::default(),
            flow_bytes_per_sec: StatsAccumulator::default(),
            count: 0,
        }
    }

    fn into_profile(self) -> TimingProfile {
        TimingProfile {
            attack_type: self.label,
            inter_arrival_mean: self.inter_arrival.mean(),
            inter_arrival_std: self.inter_arrival.std_dev(),
            burst_duration_mean: self.burst_duration.mean(),
            burst_duration_std: self.burst_duration.std_dev(),
            flow_bytes_per_sec_mean: self.flow_bytes_per_sec.mean(),
            flow_bytes_per_sec_std: self.flow_bytes_per_sec.std_dev(),
            sample_count: self.count,
        }
    }
}

/// Find a column index by name (case-insensitive, trimmed).
fn find_column(headers: &[String], name: &str) -> Option<usize> {
    let lower = name.to_ascii_lowercase();
    headers
        .iter()
        .position(|h| h.trim().to_ascii_lowercase() == lower)
}

/// Extract timing profiles from all CSV files in the given directory.
///
/// Each CSV is expected to have CIC-IDS2017 columns including at minimum:
/// `Flow Duration`, `Flow IAT Mean`, `Flow IAT Std`, `Flow Bytes/s`, `Label`.
///
/// Returns one `TimingProfile` per unique label value.
pub fn extract_timing_profiles(csv_dir: &Path) -> Result<Vec<TimingProfile>> {
    let entries: Vec<std::path::PathBuf> = if csv_dir.is_file() {
        vec![csv_dir.to_path_buf()]
    } else {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(csv_dir)
            .with_context(|| format!("reading directory {}", csv_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|e| e.eq_ignore_ascii_case("csv"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        files
    };

    if entries.is_empty() {
        anyhow::bail!("no CSV files found in {}", csv_dir.display());
    }

    let mut accumulators: std::collections::HashMap<String, LabelAccumulator> =
        std::collections::HashMap::new();

    for csv_path in &entries {
        parse_csv_file(csv_path, &mut accumulators)
            .with_context(|| format!("parsing {}", csv_path.display()))?;
    }

    let mut profiles: Vec<TimingProfile> = accumulators
        .into_values()
        .filter(|a| a.count > 0)
        .map(|a| a.into_profile())
        .collect();
    profiles.sort_by(|a, b| a.attack_type.cmp(&b.attack_type));

    Ok(profiles)
}

fn parse_csv_file(
    path: &Path,
    accumulators: &mut std::collections::HashMap<String, LabelAccumulator>,
) -> Result<()> {
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(path)?;

    let headers: Vec<String> = rdr.headers()?.iter().map(|h| h.to_string()).collect();

    // Locate required columns.
    let col_label = find_column(&headers, "Label")
        .with_context(|| format!("missing 'Label' column in {}", path.display()))?;
    let col_flow_duration = find_column(&headers, "Flow Duration");
    let col_iat_mean = find_column(&headers, "Flow IAT Mean");
    let col_iat_std = find_column(&headers, "Flow IAT Std");
    let col_bytes_per_sec = find_column(&headers, "Flow Bytes/s");

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let label = match record.get(col_label) {
            Some(l) => l.trim().to_string(),
            None => continue,
        };
        if label.is_empty() {
            continue;
        }

        let acc = accumulators
            .entry(label.clone())
            .or_insert_with(|| LabelAccumulator::new(label));
        acc.count += 1;

        // Flow Duration (microseconds in CIC-IDS2017) → we treat as burst duration.
        if let Some(col) = col_flow_duration {
            if let Some(val) = record.get(col).and_then(|v| v.trim().parse::<f64>().ok()) {
                // Convert microseconds to seconds.
                acc.burst_duration.push(val / 1_000_000.0);
            }
        }

        // Flow IAT Mean (microseconds) → inter-arrival time.
        if let Some(col) = col_iat_mean {
            if let Some(val) = record.get(col).and_then(|v| v.trim().parse::<f64>().ok()) {
                acc.inter_arrival.push(val / 1_000_000.0);
            }
        }

        // Flow IAT Std → used as inter_arrival_std contribution.
        if let Some(col) = col_iat_std {
            if let Some(_val) = record.get(col).and_then(|v| v.trim().parse::<f64>().ok()) {
                // The per-flow IAT std contributes to the overall std via Welford above.
                // We use the IAT Mean values; std is computed from those.
            }
        }

        // Flow Bytes/s.
        if let Some(col) = col_bytes_per_sec {
            if let Some(val) = record.get(col).and_then(|v| v.trim().parse::<f64>().ok()) {
                acc.flow_bytes_per_sec.push(val);
            }
        }
    }

    Ok(())
}

/// Convert CIC-IDS2017 flow records directly into DDoS training samples.
///
/// Maps network-layer flow features to our 14-dimensional HTTP-layer feature vector.
/// Non-BENIGN labels → attack (1.0), BENIGN → normal (0.0).
/// Uses a deterministic RNG seeded per-row to fill HTTP-only features (cookies, etc.)
/// that don't exist in the network-layer data.
pub fn extract_ddos_samples(csv_dir: &Path) -> Result<Vec<crate::dataset::sample::TrainingSample>> {
    use crate::dataset::sample::TrainingSample;
    use rand::prelude::*;
    use rand::rngs::StdRng;

    let entries: Vec<std::path::PathBuf> = if csv_dir.is_file() {
        vec![csv_dir.to_path_buf()]
    } else {
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(csv_dir)
            .with_context(|| format!("reading directory {}", csv_dir.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|e| e.eq_ignore_ascii_case("csv"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        files
    };

    if entries.is_empty() {
        anyhow::bail!("no CSV files found in {}", csv_dir.display());
    }

    let mut samples = Vec::new();
    let mut rng = StdRng::seed_from_u64(0xC1C1D5);

    for csv_path in &entries {
        let file_samples = extract_ddos_samples_from_csv(csv_path, &mut rng)
            .with_context(|| format!("extracting DDoS samples from {}", csv_path.display()))?;
        let filename = csv_path.file_name().unwrap_or_default().to_string_lossy();
        let attack_count = file_samples.iter().filter(|s| s.label > 0.5).count();
        let normal_count = file_samples.len() - attack_count;
        eprintln!(
            "  {}: {} samples ({} attack, {} normal)",
            filename,
            file_samples.len(),
            attack_count,
            normal_count
        );
        samples.extend(file_samples);
    }

    // Subsample if too large — cap at 500K to keep training tractable.
    let max_samples = 500_000;
    if samples.len() > max_samples {
        // Stratified subsample: keep attack ratio balanced.
        let mut attacks: Vec<TrainingSample> =
            samples.iter().filter(|s| s.label > 0.5).cloned().collect();
        let mut normals: Vec<TrainingSample> =
            samples.iter().filter(|s| s.label <= 0.5).cloned().collect();

        // Shuffle both
        attacks.shuffle(&mut rng);
        normals.shuffle(&mut rng);

        // Take equal parts, favoring attacks if underrepresented
        let attack_cap = max_samples / 2;
        let normal_cap = max_samples - attack_cap.min(attacks.len());
        attacks.truncate(attack_cap);
        normals.truncate(normal_cap);

        eprintln!(
            "  subsampled to {} ({} attack, {} normal)",
            attacks.len() + normals.len(),
            attacks.len(),
            normals.len()
        );
        samples = attacks;
        samples.extend(normals);
        samples.shuffle(&mut rng);
    }

    Ok(samples)
}

fn extract_ddos_samples_from_csv(
    path: &Path,
    rng: &mut rand::rngs::StdRng,
) -> Result<Vec<crate::dataset::sample::TrainingSample>> {
    use crate::dataset::sample::{DataSource, TrainingSample};
    use crate::ddos::features::NUM_FEATURES;
    use rand::prelude::*;

    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .trim(csv::Trim::All)
        .from_path(path)?;

    let headers: Vec<String> = rdr.headers()?.iter().map(|h| h.to_string()).collect();

    let col_label = find_column(&headers, "Label")
        .with_context(|| format!("missing 'Label' in {}", path.display()))?;
    let col_flow_duration = find_column(&headers, "Flow Duration");
    let col_total_fwd_pkts = find_column(&headers, "Total Fwd Packets");
    let col_total_bwd_pkts = find_column(&headers, "Total Backward Packets");
    let col_flow_pkts_s = find_column(&headers, "Flow Packets/s");
    let col_flow_iat_mean = find_column(&headers, "Flow IAT Mean");
    let col_avg_pkt_size = find_column(&headers, "Average Packet Size");
    let col_pkt_len_std = find_column(&headers, "Packet Length Std");
    let col_syn_flag = find_column(&headers, "SYN Flag Count");

    let mut samples = Vec::new();

    for result in rdr.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let label_str = match record.get(col_label) {
            Some(l) => l.trim().to_string(),
            None => continue,
        };
        if label_str.is_empty() {
            continue;
        }

        let is_attack = label_str != "BENIGN";
        let label_f32 = if is_attack { 1.0f32 } else { 0.0f32 };

        // Parse numeric columns (0.0 fallback for missing/malformed).
        let get_f64 = |col: Option<usize>| -> f64 {
            col.and_then(|c| record.get(c))
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0)
        };

        let flow_duration_us = get_f64(col_flow_duration); // microseconds
        let total_fwd_pkts = get_f64(col_total_fwd_pkts);
        let total_bwd_pkts = get_f64(col_total_bwd_pkts);
        let flow_pkts_s = get_f64(col_flow_pkts_s);
        let flow_iat_mean = get_f64(col_flow_iat_mean); // microseconds
        let avg_pkt_size = get_f64(col_avg_pkt_size);
        let pkt_len_std = get_f64(col_pkt_len_std);
        let syn_flag = get_f64(col_syn_flag);

        let flow_duration_s = (flow_duration_us / 1_000_000.0).max(0.001);
        let total_pkts = total_fwd_pkts + total_bwd_pkts;

        // Map to our 14 HTTP-layer DDoS features:
        let mut features = vec![0.0f32; NUM_FEATURES];

        // 0: request_rate — packets/sec as proxy for requests/sec
        features[0] = flow_pkts_s.clamp(0.0, 10000.0) as f32;

        // 1: unique_paths — approximate from packet diversity (std/mean ratio)
        let diversity = if avg_pkt_size > 0.0 {
            (pkt_len_std / avg_pkt_size).min(10.0)
        } else {
            0.0
        };
        features[1] = (diversity * 5.0 + 1.0) as f32;

        // 2: unique_hosts — infer from port (attack traffic often targets one host)
        features[2] = if is_attack {
            1.0
        } else {
            rng.random_range(1.0..5.0) as f32
        };

        // 3: error_rate — SYN-heavy flows suggest connection errors
        let error_signal = if total_pkts > 0.0 {
            (syn_flag / total_pkts.max(1.0)).min(1.0)
        } else {
            0.0
        };
        features[3] = if is_attack {
            (error_signal + rng.random_range(0.1..0.5)).min(1.0) as f32
        } else {
            (error_signal * 0.3) as f32
        };

        // 4: avg_duration_ms — flow duration / total packets, in ms
        features[4] = if total_pkts > 0.0 {
            ((flow_duration_s * 1000.0) / total_pkts).min(5000.0) as f32
        } else {
            0.0
        };

        // 5: method_entropy — low for attacks (single method), moderate for normal
        features[5] = if is_attack {
            rng.random_range(0.0..0.3) as f32
        } else {
            rng.random_range(0.2..1.5) as f32
        };

        // 6: burst_score — inverse of inter-arrival time
        let iat_s = (flow_iat_mean / 1_000_000.0).max(0.001);
        features[6] = (1.0 / iat_s).min(500.0) as f32;

        // 7: path_repetition — attacks repeat paths heavily
        features[7] = if is_attack {
            rng.random_range(0.6..1.0) as f32
        } else {
            rng.random_range(0.05..0.4) as f32
        };

        // 8: avg_content_length — from average packet size
        features[8] = avg_pkt_size.clamp(0.0, 10000.0) as f32;

        // 9: unique_user_agents — low for attacks
        features[9] = if is_attack {
            rng.random_range(1.0..2.0) as f32
        } else {
            rng.random_range(1.0..4.0) as f32
        };

        // 10: cookie_ratio — bots don't send cookies
        features[10] = if is_attack {
            rng.random_range(0.0..0.1) as f32
        } else {
            rng.random_range(0.6..1.0) as f32
        };

        // 11: referer_ratio — bots rarely send referer
        features[11] = if is_attack {
            rng.random_range(0.0..0.1) as f32
        } else {
            rng.random_range(0.3..1.0) as f32
        };

        // 12: accept_language_ratio — bots don't send this
        features[12] = if is_attack {
            rng.random_range(0.0..0.1) as f32
        } else {
            rng.random_range(0.6..1.0) as f32
        };

        // 13: suspicious_path_ratio — attacks may probe paths
        let is_web_attack = label_str.contains("Web Attack")
            || label_str.contains("Bot")
            || label_str.contains("Infiltration");
        features[13] = if is_web_attack {
            rng.random_range(0.2..0.7) as f32
        } else if is_attack {
            rng.random_range(0.0..0.3) as f32
        } else {
            rng.random_range(0.0..0.05) as f32
        };

        samples.push(TrainingSample {
            features,
            label: label_f32,
            source: DataSource::SyntheticCicTiming,
            weight: 0.7, // higher than pure synthetic (0.5), lower than prod (1.0)
        });
    }

    Ok(samples)
}

/// Parse timing profiles from an in-memory CSV string (useful for tests).
pub fn extract_timing_profiles_from_str(csv_content: &str) -> Result<Vec<TimingProfile>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("test.csv");
    std::fs::write(&path, csv_content)?;
    extract_timing_profiles(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_inline_csv() {
        let csv = "\
Flow Duration,Total Fwd Packets,Flow Bytes/s,Flow IAT Mean,Flow IAT Std,Label
1000000,10,5000.0,100000,50000,BENIGN
2000000,20,10000.0,200000,100000,BENIGN
500000,100,50000.0,5000,2000,DDoS
300000,200,80000.0,3000,1000,DDoS
100000,50,30000.0,10000,5000,DDoS
";
        let profiles = extract_timing_profiles_from_str(csv).unwrap();
        assert_eq!(profiles.len(), 2, "should have BENIGN and DDoS profiles");

        let benign = profiles.iter().find(|p| p.attack_type == "BENIGN").unwrap();
        assert_eq!(benign.sample_count, 2);
        // IAT mean: mean of [0.1, 0.2] = 0.15 seconds
        assert!(
            (benign.inter_arrival_mean - 0.15).abs() < 1e-6,
            "benign iat mean: {}",
            benign.inter_arrival_mean
        );
        // Burst duration mean: mean of [1.0, 2.0] = 1.5 seconds
        assert!(
            (benign.burst_duration_mean - 1.5).abs() < 1e-6,
            "benign burst mean: {}",
            benign.burst_duration_mean
        );

        let ddos = profiles.iter().find(|p| p.attack_type == "DDoS").unwrap();
        assert_eq!(ddos.sample_count, 3);
        // Flow bytes/s mean: mean of [50000, 80000, 30000] = 53333.33
        let expected_bps = (50000.0 + 80000.0 + 30000.0) / 3.0;
        assert!(
            (ddos.flow_bytes_per_sec_mean - expected_bps).abs() < 1.0,
            "ddos bps mean: {}",
            ddos.flow_bytes_per_sec_mean
        );
    }

    #[test]
    fn test_stats_accumulator() {
        let mut acc = StatsAccumulator::default();
        acc.push(2.0);
        acc.push(4.0);
        acc.push(6.0);
        assert!((acc.mean() - 4.0).abs() < 1e-10);
        // std_dev of [2,4,6] = 2.0
        assert!((acc.std_dev() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_empty_csv_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = extract_timing_profiles(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_find_column_case_insensitive() {
        let headers: Vec<String> = vec![" Flow Duration ".to_string(), "label".to_string()];
        assert_eq!(find_column(&headers, "Flow Duration"), Some(0));
        assert_eq!(find_column(&headers, "Label"), Some(1));
        assert_eq!(find_column(&headers, "LABEL"), Some(1));
        assert_eq!(find_column(&headers, "missing"), None);
    }

    #[test]
    fn test_extract_timing_profiles_from_directory() {
        let dir = tempfile::tempdir().unwrap();
        let csv = "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s,Label\n1000000,100000,50000,5000,BENIGN\n500000,5000,2000,50000,DDoS\n";
        std::fs::write(dir.path().join("a.csv"), csv).unwrap();
        let profiles = extract_timing_profiles(dir.path()).unwrap();
        assert_eq!(profiles.len(), 2);
    }

    #[test]
    fn test_extract_timing_profiles_missing_label_column() {
        let dir = tempfile::tempdir().unwrap();
        let csv =
            "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s\n1000000,100000,50000,5000\n";
        std::fs::write(dir.path().join("bad.csv"), csv).unwrap();
        let result = extract_timing_profiles(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_timing_profiles_empty_label_skipped() {
        let csv = "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s,Label\n1000000,100000,50000,5000,\n";
        let profiles = extract_timing_profiles_from_str(csv).unwrap();
        assert!(profiles.is_empty());
    }

    #[test]
    fn test_stats_accumulator_non_finite_ignored() {
        let mut acc = StatsAccumulator::default();
        acc.push(2.0);
        acc.push(f64::NAN);
        acc.push(4.0);
        assert!((acc.mean() - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_stats_accumulator_std_dev_single_value() {
        let mut acc = StatsAccumulator::default();
        acc.push(5.0);
        assert_eq!(acc.std_dev(), 0.0);
    }

    #[test]
    fn test_label_accumulator_into_profile() {
        let mut acc = LabelAccumulator::new("BENIGN".to_string());
        acc.count = 2;
        acc.inter_arrival.push(0.1);
        acc.inter_arrival.push(0.2);
        acc.burst_duration.push(1.0);
        acc.burst_duration.push(2.0);
        acc.flow_bytes_per_sec.push(100.0);
        acc.flow_bytes_per_sec.push(200.0);
        let profile = acc.into_profile();
        assert_eq!(profile.attack_type, "BENIGN");
        assert_eq!(profile.sample_count, 2);
        assert!((profile.inter_arrival_mean - 0.15).abs() < 1e-10);
    }

    fn make_ddos_csv() -> String {
        "Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Packets/s,Flow IAT Mean,Average Packet Size,Packet Length Std,SYN Flag Count,Label\n\
         1000000,10,10,20.0,100000,500,50,5,BENIGN\n\
         500000,100,100,400.0,5000,100,10,50,DDoS\n"
            .to_string()
    }

    #[test]
    fn test_extract_ddos_samples_from_str() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ddos.csv");
        std::fs::write(&path, make_ddos_csv()).unwrap();
        let samples = extract_ddos_samples(&path).unwrap();
        assert_eq!(samples.len(), 2);
        let attack_count = samples.iter().filter(|s| s.label > 0.5).count();
        let normal_count = samples.len() - attack_count;
        assert_eq!(attack_count, 1);
        assert_eq!(normal_count, 1);
        assert_eq!(
            samples[0].source,
            crate::dataset::sample::DataSource::SyntheticCicTiming
        );
    }

    #[test]
    fn test_extract_ddos_samples_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = extract_ddos_samples(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_ddos_samples_from_csv_web_attack_label() {
        let csv = "Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Packets/s,Flow IAT Mean,Average Packet Size,Packet Length Std,SYN Flag Count,Label\n\
                   500000,100,100,400.0,5000,100,10,50,Web Attack XSS\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.csv");
        std::fs::write(&path, csv).unwrap();
        let samples = extract_ddos_samples(&path).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].label > 0.5);
    }

    #[test]
    fn test_extract_ddos_samples_from_csv_missing_columns() {
        let csv = "Flow Duration,Label\n\
                   500000,BENIGN\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("minimal.csv");
        std::fs::write(&path, csv).unwrap();
        let samples = extract_ddos_samples(&path).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].label < 0.5);
    }

    #[test]
    fn test_extract_ddos_samples_from_csv_bot_label() {
        let csv = "Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Packets/s,Flow IAT Mean,Average Packet Size,Packet Length Std,SYN Flag Count,Label\n\
                   500000,100,100,400.0,5000,100,10,50,Bot\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bot.csv");
        std::fs::write(&path, csv).unwrap();
        let samples = extract_ddos_samples(&path).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].label > 0.5);
    }

    #[test]
    fn test_extract_ddos_samples_from_csv_infiltration_label() {
        let csv = "Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Packets/s,Flow IAT Mean,Average Packet Size,Packet Length Std,SYN Flag Count,Label\n\
                   500000,100,100,400.0,5000,100,10,50,Infiltration\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("infiltration.csv");
        std::fs::write(&path, csv).unwrap();
        let samples = extract_ddos_samples(&path).unwrap();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].label > 0.5);
    }

    #[test]
    fn test_extract_timing_profiles_sorts_by_attack_type() {
        let csv = "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s,Label\n\
                   1000000,100000,50000,5000,DDoS\n\
                   1000000,100000,50000,5000,BENIGN\n\
                   1000000,100000,50000,5000,PortScan\n";
        let profiles = extract_timing_profiles_from_str(csv).unwrap();
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].attack_type, "BENIGN");
        assert_eq!(profiles[1].attack_type, "DDoS");
        assert_eq!(profiles[2].attack_type, "PortScan");
    }

    #[test]
    fn test_extract_timing_profiles_aggregates_multiple_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("a.csv"),
            "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s,Label\n1000000,100000,50000,5000,BENIGN\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("b.csv"),
            "Flow Duration,Flow IAT Mean,Flow IAT Std,Flow Bytes/s,Label\n500000,5000,2000,50000,BENIGN\n",
        )
        .unwrap();
        let profiles = extract_timing_profiles(dir.path()).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].attack_type, "BENIGN");
        assert_eq!(profiles[0].sample_count, 2);
    }

    #[test]
    fn test_stats_accumulator_infinity_ignored() {
        let mut acc = StatsAccumulator::default();
        acc.push(1.0);
        acc.push(f64::INFINITY);
        acc.push(3.0);
        assert!((acc.mean() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_stats_accumulator_neg_infinity_ignored() {
        let mut acc = StatsAccumulator::default();
        acc.push(1.0);
        acc.push(f64::NEG_INFINITY);
        acc.push(3.0);
        assert!((acc.mean() - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_label_accumulator_zero_count_filtered() {
        let mut accumulators: std::collections::HashMap<String, LabelAccumulator> =
            std::collections::HashMap::new();
        accumulators.insert(
            "EMPTY".to_string(),
            LabelAccumulator::new("EMPTY".to_string()),
        );
        let profiles: Vec<TimingProfile> = accumulators
            .into_values()
            .filter(|a| a.count > 0)
            .map(|a| a.into_profile())
            .collect();
        assert!(profiles.is_empty());
    }
}
