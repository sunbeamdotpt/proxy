// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use crate::autotune::gp::GaussianProcess;
use crate::autotune::params::ParamSpace;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
/// Trial.
pub struct Trial {
    /// Trial num.
    pub trial_num: usize,
    /// Params.
    pub params: Vec<f64>,
    /// Param names.
    pub param_names: Vec<String>,
    /// Objective.
    pub objective: f64,
    /// Duration secs.
    pub duration_secs: f64,
}

/// Bayesianoptimizer.
pub struct BayesianOptimizer {
    gp: GaussianProcess,
    space: ParamSpace,
    trials: Vec<Trial>,
    n_initial_random: usize,
    kappa: f64,
    kappa_decay: f64,
    rng: rand::rngs::ThreadRng,
}

impl BayesianOptimizer {
    pub fn new(space: ParamSpace) -> Self {
        let dim = space.dim();
        let n_initial_random = (2 * dim).max(10);
        Self {
            gp: GaussianProcess::new(0.5, 1e-6),
            space,
            trials: Vec::new(),
            n_initial_random,
            kappa: 2.0,
            kappa_decay: 0.95,
            rng: rand::rng(),
        }
    }

    /// Suggest the next set of parameters to evaluate.
    /// Returns actual parameter values (not unit cube).
    pub fn suggest(&mut self) -> Vec<f64> {
        let trial_count = self.trials.len();

        if trial_count < self.n_initial_random {
            // Latin Hypercube for initial exploration
            let unit = self.space.random_unit_point(&mut self.rng);
            return self.space.from_unit_cube(&unit);
        }

        // GP-UCB: generate random candidates, pick the one with highest UCB
        let n_candidates = 1000;
        let mut best_ucb = f64::NEG_INFINITY;
        let mut best_unit = vec![0.0; self.space.dim()];

        // Decay kappa over rounds
        let rounds_past_init = trial_count - self.n_initial_random;
        let kappa = self.kappa * self.kappa_decay.powi(rounds_past_init as i32);

        for _ in 0..n_candidates {
            let unit = self.space.random_unit_point(&mut self.rng);
            let (mean, var) = self.gp.predict(&unit);
            let ucb = mean + kappa * var.sqrt();
            if ucb > best_ucb {
                best_ucb = ucb;
                best_unit = unit;
            }
        }

        self.space.from_unit_cube(&best_unit)
    }

    /// Record the result of evaluating a parameter configuration.
    pub fn observe(&mut self, params: Vec<f64>, objective: f64, duration: Duration) {
        let unit = self.space.to_unit_cube(&params);
        self.gp.observe(unit, objective);

        let trial = Trial {
            trial_num: self.trials.len() + 1,
            params,
            param_names: self.space.names().into_iter().map(String::from).collect(),
            objective,
            duration_secs: duration.as_secs_f64(),
        };
        self.trials.push(trial);
    }

    /// Return the best trial observed so far.
    pub fn best(&self) -> Option<&Trial> {
        self.trials.iter().max_by(|a, b| {
            a.objective.partial_cmp(&b.objective).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    pub fn trials(&self) -> &[Trial] {
        &self.trials
    }

    pub fn trial_count(&self) -> usize {
        self.trials.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autotune::params::{ParamDef, ParamType};

    #[test]
    fn test_optimizer_suggest_returns_valid_params() {
        let space = ParamSpace::new(vec![
            ParamDef { name: "x".into(), param_type: ParamType::Continuous { min: 0.0, max: 1.0 } },
            ParamDef { name: "y".into(), param_type: ParamType::Continuous { min: -5.0, max: 5.0 } },
        ]);
        let mut opt = BayesianOptimizer::new(space);

        let params = opt.suggest();
        assert_eq!(params.len(), 2);
        assert!(params[0] >= 0.0 && params[0] <= 1.0);
        assert!(params[1] >= -5.0 && params[1] <= 5.0);
    }

    #[test]
    fn test_optimizer_converges_1d() {
        // Optimize f(x) = -(x - 0.7)^2, max at x=0.7
        let space = ParamSpace::new(vec![
            ParamDef { name: "x".into(), param_type: ParamType::Continuous { min: 0.0, max: 1.0 } },
        ]);
        let mut opt = BayesianOptimizer::new(space);

        for _ in 0..30 {
            let params = opt.suggest();
            let x = params[0];
            let obj = -(x - 0.7) * (x - 0.7);
            opt.observe(params, obj, Duration::from_millis(1));
        }

        let best = opt.best().unwrap();
        assert!(
            (best.params[0] - 0.7).abs() < 0.2,
            "best x={}, expected ~0.7",
            best.params[0]
        );
    }

    #[test]
    fn test_optimizer_best_tracks_maximum() {
        let space = ParamSpace::new(vec![
            ParamDef { name: "x".into(), param_type: ParamType::Continuous { min: 0.0, max: 1.0 } },
        ]);
        let mut opt = BayesianOptimizer::new(space);

        opt.observe(vec![0.2], 0.5, Duration::from_millis(1));
        opt.observe(vec![0.8], 0.9, Duration::from_millis(1));
        opt.observe(vec![0.5], 0.7, Duration::from_millis(1));

        assert!((opt.best().unwrap().objective - 0.9).abs() < 1e-10);
    }
}
