// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};

/// Provenance of a training sample.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataSource {
    /// Productionlogs.
    ProductionLogs,
    /// Csic2010.
    Csic2010,
    /// Owaspmodsec.
    OwaspModSec,
    /// Syntheticcictiming.
    SyntheticCicTiming,
    /// Syntheticwordlist.
    SyntheticWordlist,
}

impl std::fmt::Display for DataSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataSource::ProductionLogs => write!(f, "ProductionLogs"),
            DataSource::Csic2010 => write!(f, "Csic2010"),
            DataSource::OwaspModSec => write!(f, "OwaspModSec"),
            DataSource::SyntheticCicTiming => write!(f, "SyntheticCicTiming"),
            DataSource::SyntheticWordlist => write!(f, "SyntheticWordlist"),
        }
    }
}

/// A single labeled training sample with its feature vector, label, provenance,
/// and weight (used during training to down-weight synthetic/external data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingSample {
    /// Features.
    pub features: Vec<f32>,
    /// 0.0 = normal, 1.0 = attack
    pub label: f32,
    /// Source.
    pub source: DataSource,
    /// Sample weight: 1.0 for production, 0.8 for external datasets, 0.5 for synthetic.
    pub weight: f32,
}

/// Aggregate statistics about a prepared dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetStats {
    /// Total samples.
    pub total_samples: usize,
    /// Scanner samples.
    pub scanner_samples: usize,
    /// Ddos samples.
    pub ddos_samples: usize,
    /// Samples by source.
    pub samples_by_source: HashMap<DataSource, usize>,
    /// Attack ratio scanner.
    pub attack_ratio_scanner: f64,
    /// Attack ratio ddos.
    pub attack_ratio_ddos: f64,
}

/// The full serializable dataset: scanner samples, DDoS samples, and stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManifest {
    /// Scanner samples.
    pub scanner_samples: Vec<TrainingSample>,
    /// Ddos samples.
    pub ddos_samples: Vec<TrainingSample>,
    /// Stats.
    pub stats: DatasetStats,
}

/// Serialize a `DatasetManifest` to a bincode file.
pub fn save_dataset(manifest: &DatasetManifest, path: &Path) -> Result<()> {
    let encoded = bincode::serialize(manifest).context("serializing dataset manifest")?;
    std::fs::write(path, &encoded)
        .with_context(|| format!("writing dataset to {}", path.display()))?;
    Ok(())
}

/// Deserialize a `DatasetManifest` from a bincode file.
pub fn load_dataset(path: &Path) -> Result<DatasetManifest> {
    let data =
        std::fs::read(path).with_context(|| format!("reading dataset from {}", path.display()))?;
    let manifest: DatasetManifest =
        bincode::deserialize(&data).context("deserializing dataset manifest")?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sample(
        features: Vec<f32>,
        label: f32,
        source: DataSource,
        weight: f32,
    ) -> TrainingSample {
        TrainingSample {
            features,
            label,
            source,
            weight,
        }
    }

    #[test]
    fn test_bincode_roundtrip() {
        let manifest = DatasetManifest {
            scanner_samples: vec![
                make_sample(vec![0.1, 0.2, 0.3], 0.0, DataSource::ProductionLogs, 1.0),
                make_sample(vec![0.9, 0.8, 0.7], 1.0, DataSource::Csic2010, 0.8),
            ],
            ddos_samples: vec![
                make_sample(vec![0.5; 14], 1.0, DataSource::SyntheticCicTiming, 0.5),
                make_sample(vec![0.1; 14], 0.0, DataSource::ProductionLogs, 1.0),
            ],
            stats: DatasetStats {
                total_samples: 4,
                scanner_samples: 2,
                ddos_samples: 2,
                samples_by_source: {
                    let mut m = HashMap::new();
                    m.insert(DataSource::ProductionLogs, 2);
                    m.insert(DataSource::Csic2010, 1);
                    m.insert(DataSource::SyntheticCicTiming, 1);
                    m
                },
                attack_ratio_scanner: 0.5,
                attack_ratio_ddos: 0.5,
            },
        };

        let encoded = bincode::serialize(&manifest).unwrap();
        let decoded: DatasetManifest = bincode::deserialize(&encoded).unwrap();

        assert_eq!(decoded.scanner_samples.len(), 2);
        assert_eq!(decoded.ddos_samples.len(), 2);
        assert_eq!(decoded.stats.total_samples, 4);
        assert_eq!(
            decoded.stats.samples_by_source[&DataSource::ProductionLogs],
            2
        );

        // Verify feature values survive the roundtrip.
        assert!((decoded.scanner_samples[0].features[0] - 0.1).abs() < 1e-6);
        assert_eq!(decoded.scanner_samples[1].label, 1.0);
        assert_eq!(
            decoded.ddos_samples[0].source,
            DataSource::SyntheticCicTiming
        );
    }

    #[test]
    fn test_save_load_roundtrip() {
        let manifest = DatasetManifest {
            scanner_samples: vec![make_sample(
                vec![1.0, 2.0],
                0.0,
                DataSource::ProductionLogs,
                1.0,
            )],
            ddos_samples: vec![make_sample(
                vec![3.0, 4.0],
                1.0,
                DataSource::OwaspModSec,
                0.8,
            )],
            stats: DatasetStats {
                total_samples: 2,
                scanner_samples: 1,
                ddos_samples: 1,
                samples_by_source: HashMap::new(),
                attack_ratio_scanner: 0.0,
                attack_ratio_ddos: 1.0,
            },
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_dataset.bin");

        save_dataset(&manifest, &path).unwrap();
        let loaded = load_dataset(&path).unwrap();

        assert_eq!(loaded.scanner_samples.len(), 1);
        assert_eq!(loaded.ddos_samples.len(), 1);
        assert!((loaded.scanner_samples[0].features[0] - 1.0).abs() < 1e-6);
        assert_eq!(loaded.ddos_samples[0].source, DataSource::OwaspModSec);
    }
}
