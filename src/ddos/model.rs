// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Ddosaction.
pub enum DDoSAction {
    /// Allow.
    Allow,
    /// Block.
    Block,
}

impl TrainedModel {
    pub fn load(path: &Path, k_override: Option<usize>, threshold_override: Option<f64>) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("reading model from {}", path.display()))?;
        let model: SerializedModel =
            bincode::deserialize(&data).context("deserializing model")?;
        Ok(Self {
            points: model.points,
            labels: model.labels,
            norm_params: model.norm_params,
            k: k_override.unwrap_or(model.k),
            threshold: threshold_override.unwrap_or(model.threshold),
        })
    }

    /// Create an empty model (no training points). Used when the ensemble
    /// path is active and the KNN model is not needed.
    pub fn empty(k: usize, threshold: f64) -> Self {
        Self {
            points: vec![],
            labels: vec![],
            norm_params: NormParams {
                mins: [0.0; NUM_FEATURES],
                maxs: [1.0; NUM_FEATURES],
            },
            k,
            threshold,
        }
    }

    pub fn from_serialized(model: SerializedModel) -> Self {
        Self {
            points: model.points,
            labels: model.labels,
            norm_params: model.norm_params,
            k: model.k,
            threshold: model.threshold,
        }
    }

    pub fn classify(&self, features: &FeatureVector) -> DDoSAction {
        let normalized = self.norm_params.normalize(features);

        if self.points.is_empty() {
            return DDoSAction::Allow;
        }

        // Build tree on-the-fly for query. In production with many queries,
        // we'd cache this, but the tree build is fast for <100K points.
        // fnntw::Tree borrows data, so we build it here.
        let tree = match fnntw::Tree::<'_, f64, NUM_FEATURES>::new(&self.points, 32) {
            Ok(t) => t,
            Err(_) => return DDoSAction::Allow,
        };

        let k = self.k.min(self.points.len());
        let result = tree.query_nearest_k(&normalized, k);
        match result {
            Ok((_distances, indices)) => {
                let attack_count = indices
                    .iter()
                    .filter(|&&idx| self.labels[idx as usize] == TrafficLabel::Attack)
                    .count();
                let attack_frac = attack_count as f64 / k as f64;
                if attack_frac >= self.threshold {
                    DDoSAction::Block
                } else {
                    DDoSAction::Allow
                }
            }
            Err(_) => DDoSAction::Allow,
        }
    }

    pub fn norm_params(&self) -> &NormParams {
        &self.norm_params
    }

    pub fn point_count(&self) -> usize {
        self.points.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_empty_model() {
        let model = TrainedModel {
            points: vec![],
            labels: vec![],
            norm_params: NormParams {
                mins: [0.0; NUM_FEATURES],
                maxs: [1.0; NUM_FEATURES],
            },
            k: 5,
            threshold: 0.6,
        };
        assert_eq!(model.classify(&[0.5; NUM_FEATURES]), DDoSAction::Allow);
    }

    fn make_test_points(n: usize) -> Vec<FeatureVector> {
        (0..n)
            .map(|i| {
                let mut v = [0.0; NUM_FEATURES];
                for d in 0..NUM_FEATURES {
                    v[d] = ((i * (d + 1)) as f64 / n as f64) % 1.0;
                }
                v
            })
            .collect()
    }

    #[test]
    fn test_classify_all_attack() {
        let points = make_test_points(100);
        let labels = vec![TrafficLabel::Attack; 100];
        let model = TrainedModel {
            points,
            labels,
            norm_params: NormParams {
                mins: [0.0; NUM_FEATURES],
                maxs: [1.0; NUM_FEATURES],
            },
            k: 5,
            threshold: 0.6,
        };
        assert_eq!(model.classify(&[0.5; NUM_FEATURES]), DDoSAction::Block);
    }

    #[test]
    fn test_classify_all_normal() {
        let points = make_test_points(100);
        let labels = vec![TrafficLabel::Normal; 100];
        let model = TrainedModel {
            points,
            labels,
            norm_params: NormParams {
                mins: [0.0; NUM_FEATURES],
                maxs: [1.0; NUM_FEATURES],
            },
            k: 5,
            threshold: 0.6,
        };
        assert_eq!(model.classify(&[0.5; NUM_FEATURES]), DDoSAction::Allow);
    }
}
