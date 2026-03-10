use crate::scanner::features::{ScannerNormParams, NUM_SCANNER_WEIGHTS};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerAction {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct ScannerVerdict {
    pub action: ScannerAction,
    pub score: f64,
    /// Why this decision was made: "model", "allowlist", etc.
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerModel {
    pub weights: [f64; NUM_SCANNER_WEIGHTS],
    pub threshold: f64,
    pub norm_params: ScannerNormParams,
    /// Suspicious path fragments used during training — kept for reproducibility.
    pub fragments: Vec<String>,
}

impl ScannerModel {
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self).context("serializing scanner model")?;
        std::fs::write(path, data)
            .with_context(|| format!("writing scanner model to {}", path.display()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading scanner model from {}", path.display()))?;
        bincode::deserialize(&data).context("deserializing scanner model")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::features::NUM_SCANNER_FEATURES;

    #[test]
    fn test_serialization_roundtrip() {
        let model = ScannerModel {
            weights: [0.1; NUM_SCANNER_WEIGHTS],
            threshold: 0.5,
            norm_params: ScannerNormParams {
                mins: [0.0; NUM_SCANNER_FEATURES],
                maxs: [1.0; NUM_SCANNER_FEATURES],
            },
            fragments: vec![".env".into(), "wp-admin".into()],
        };
        let data = bincode::serialize(&model).unwrap();
        let loaded: ScannerModel = bincode::deserialize(&data).unwrap();
        assert_eq!(loaded.weights, model.weights);
        assert_eq!(loaded.threshold, model.threshold);
        assert_eq!(loaded.fragments, model.fragments);
    }

    #[test]
    fn test_save_load_file() {
        let dir = std::env::temp_dir().join("scanner_model_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_model.bin");

        let model = ScannerModel {
            weights: [0.5; NUM_SCANNER_WEIGHTS],
            threshold: 0.42,
            norm_params: ScannerNormParams {
                mins: [0.0; NUM_SCANNER_FEATURES],
                maxs: [1.0; NUM_SCANNER_FEATURES],
            },
            fragments: vec!["phpinfo".into()],
        };
        model.save(&path).unwrap();
        let loaded = ScannerModel::load(&path).unwrap();
        assert_eq!(loaded.threshold, 0.42);
        assert_eq!(loaded.fragments, vec!["phpinfo"]);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
