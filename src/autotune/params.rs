// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;

#[derive(Debug, Clone)]
/// Paramtype.
pub enum ParamType {
    /// Continuous.
    Continuous { min: f64, max: f64 },
    /// Integer.
    Integer { min: i64, max: i64 },
    /// Logscale.
    LogScale { min: f64, max: f64 },
}

#[derive(Debug, Clone)]
/// Paramdef.
pub struct ParamDef {
    /// Name.
    pub name: String,
    /// Param type.
    pub param_type: ParamType,
}

#[derive(Debug, Clone)]
/// Paramspace.
pub struct ParamSpace {
    /// Params.
    pub params: Vec<ParamDef>,
}

impl ParamSpace {
    pub fn new(params: Vec<ParamDef>) -> Self {
        Self { params }
    }

    pub fn dim(&self) -> usize {
        self.params.len()
    }

    /// Map from unit cube [0,1]^d to actual parameter values.
    pub fn from_unit_cube(&self, unit: &[f64]) -> Vec<f64> {
        self.params
            .iter()
            .zip(unit.iter())
            .map(|(p, &u)| {
                let u = u.clamp(0.0, 1.0);
                match &p.param_type {
                    ParamType::Continuous { min, max } => min + u * (max - min),
                    ParamType::Integer { min, max } => {
                        let v = *min as f64 + u * (*max - *min) as f64;
                        v.round()
                    }
                    ParamType::LogScale { min, max } => {
                        let log_min = min.ln();
                        let log_max = max.ln();
                        (log_min + u * (log_max - log_min)).exp()
                    }
                }
            })
            .collect()
    }

    /// Map from actual parameter values to unit cube [0,1]^d.
    pub fn to_unit_cube(&self, values: &[f64]) -> Vec<f64> {
        self.params
            .iter()
            .zip(values.iter())
            .map(|(p, &v)| match &p.param_type {
                ParamType::Continuous { min, max } => {
                    if (max - min).abs() < 1e-15 { 0.5 } else { (v - min) / (max - min) }
                }
                ParamType::Integer { min, max } => {
                    let range = (*max - *min) as f64;
                    if range.abs() < 1e-15 { 0.5 } else { (v - *min as f64) / range }
                }
                ParamType::LogScale { min, max } => {
                    let log_min = min.ln();
                    let log_max = max.ln();
                    let log_range = log_max - log_min;
                    if log_range.abs() < 1e-15 { 0.5 } else { (v.ln() - log_min) / log_range }
                }
            })
            .collect()
    }

    /// Generate a random point in [0,1]^d.
    pub fn random_unit_point(&self, rng: &mut impl Rng) -> Vec<f64> {
        (0..self.dim()).map(|_| rng.random::<f64>()).collect()
    }

    /// Generate Latin Hypercube samples in [0,1]^d.
    pub fn latin_hypercube(&self, n: usize, rng: &mut impl Rng) -> Vec<Vec<f64>> {
        let d = self.dim();
        let mut samples = vec![vec![0.0; d]; n];
        for j in 0..d {
            let mut perm: Vec<usize> = (0..n).collect();
            // Fisher-Yates shuffle
            for i in (1..n).rev() {
                let k = rng.random_range(0..=i);
                perm.swap(i, k);
            }
            for i in 0..n {
                let u: f64 = rng.random();
                samples[i][j] = (perm[i] as f64 + u) / n as f64;
            }
        }
        samples
    }

    /// Get parameter names.
    pub fn names(&self) -> Vec<&str> {
        self.params.iter().map(|p| p.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_space() -> ParamSpace {
        ParamSpace::new(vec![
            ParamDef { name: "x".into(), param_type: ParamType::Continuous { min: 0.0, max: 10.0 } },
            ParamDef { name: "n".into(), param_type: ParamType::Integer { min: 1, max: 20 } },
            ParamDef { name: "lr".into(), param_type: ParamType::LogScale { min: 0.001, max: 0.1 } },
        ])
    }

    #[test]
    fn test_unit_cube_roundtrip() {
        let space = test_space();
        let unit = vec![0.0, 0.5, 1.0];
        let actual = space.from_unit_cube(&unit);
        assert!((actual[0] - 0.0).abs() < 1e-10);
        // Integer: min=1, max=20, u=0.5 → 1 + 0.5*19 = 10.5, round = 11
        assert!((actual[1] - 11.0).abs() < 1e-10);
        assert!((actual[2] - 0.1).abs() < 1e-10);

        let back = space.to_unit_cube(&actual);
        assert!((back[0] - 0.0).abs() < 1e-10);
        assert!((back[2] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_boundaries() {
        let space = test_space();
        let low = space.from_unit_cube(&[0.0, 0.0, 0.0]);
        let high = space.from_unit_cube(&[1.0, 1.0, 1.0]);
        assert!((low[0] - 0.0).abs() < 1e-10);
        assert!((low[1] - 1.0).abs() < 1e-10);
        assert!((low[2] - 0.001).abs() < 1e-6);
        assert!((high[0] - 10.0).abs() < 1e-10);
        assert!((high[1] - 20.0).abs() < 1e-10);
        assert!((high[2] - 0.1).abs() < 1e-6);
    }

    #[test]
    fn test_latin_hypercube_coverage() {
        let space = test_space();
        let mut rng = rand::rng();
        let samples = space.latin_hypercube(10, &mut rng);
        assert_eq!(samples.len(), 10);
        for s in &samples {
            assert_eq!(s.len(), 3);
            for &v in s {
                assert!(v >= 0.0 && v <= 1.0);
            }
        }
    }
}
