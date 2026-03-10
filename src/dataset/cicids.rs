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
    pub attack_type: String,
    pub inter_arrival_mean: f64,
    pub inter_arrival_std: f64,
    pub burst_duration_mean: f64,
    pub burst_duration_std: f64,
    pub flow_bytes_per_sec_mean: f64,
    pub flow_bytes_per_sec_std: f64,
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
                    .map(|e| e.to_ascii_lowercase() == "csv")
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

    let headers: Vec<String> = rdr
        .headers()?
        .iter()
        .map(|h| h.to_string())
        .collect();

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
        let headers: Vec<String> = vec![
            " Flow Duration ".to_string(),
            "label".to_string(),
        ];
        assert_eq!(find_column(&headers, "Flow Duration"), Some(0));
        assert_eq!(find_column(&headers, "Label"), Some(1));
        assert_eq!(find_column(&headers, "LABEL"), Some(1));
        assert_eq!(find_column(&headers, "missing"), None);
    }
}
