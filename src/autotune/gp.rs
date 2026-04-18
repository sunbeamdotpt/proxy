// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

/// Gaussian Process surrogate with RBF kernel and Cholesky solver.
/// Designed for <200 observations in 4-10 dimensions.

/// RBF (squared exponential) kernel: k(x1, x2) = exp(-||x1-x2||^2 / (2 * l^2))
fn rbf_kernel(x1: &[f64], x2: &[f64], length_scale: f64) -> f64 {
    let sq_dist: f64 = x1.iter().zip(x2.iter()).map(|(a, b)| (a - b).powi(2)).sum();
    (-sq_dist / (2.0 * length_scale * length_scale)).exp()
}

pub struct GaussianProcess {
    xs: Vec<Vec<f64>>,
    ys: Vec<f64>,
    length_scale: f64,
    noise: f64,
    // Cached: K^{-1} * y, computed via Cholesky
    alpha: Vec<f64>,
    // Cached: Cholesky factor L (lower triangular, stored row-major)
    chol_l: Vec<f64>,
    n: usize,
}

impl GaussianProcess {
    pub fn new(length_scale: f64, noise: f64) -> Self {
        Self {
            xs: Vec::new(),
            ys: Vec::new(),
            length_scale,
            noise,
            alpha: Vec::new(),
            chol_l: Vec::new(),
            n: 0,
        }
    }

    pub fn observe(&mut self, x: Vec<f64>, y: f64) {
        self.xs.push(x);
        self.ys.push(y);
        self.n = self.xs.len();
        self.recompute();
    }

    pub fn observe_batch(&mut self, xs: Vec<Vec<f64>>, ys: Vec<f64>) {
        self.xs.extend(xs);
        self.ys.extend(ys);
        self.n = self.xs.len();
        self.recompute();
    }

    /// Predict mean and variance at point x.
    pub fn predict(&self, x: &[f64]) -> (f64, f64) {
        if self.n == 0 {
            return (0.0, 1.0);
        }

        // k_star = [k(x, x_i) for i in 0..n]
        let k_star: Vec<f64> = self.xs.iter()
            .map(|xi| rbf_kernel(x, xi, self.length_scale))
            .collect();

        // mean = k_star^T * alpha
        let mean: f64 = k_star.iter().zip(self.alpha.iter()).map(|(k, a)| k * a).sum();

        // variance = k(x, x) - k_star^T * K^{-1} * k_star
        // K^{-1} * k_star is solved via L: v = L^{-1} * k_star (forward sub)
        let v = self.forward_solve(&k_star);
        let var_reduction: f64 = v.iter().map(|vi| vi * vi).sum();
        let k_xx = rbf_kernel(x, x, self.length_scale) + self.noise;
        let variance = (k_xx - var_reduction).max(1e-10);

        (mean, variance)
    }

    pub fn len(&self) -> usize {
        self.n
    }

    fn recompute(&mut self) {
        let n = self.n;
        // Build kernel matrix K + noise * I
        let mut k = vec![0.0; n * n];
        for i in 0..n {
            for j in 0..=i {
                let kij = rbf_kernel(&self.xs[i], &self.xs[j], self.length_scale);
                k[i * n + j] = kij;
                k[j * n + i] = kij;
            }
            k[i * n + i] += self.noise;
        }

        // Cholesky decomposition: K = L * L^T
        self.chol_l = cholesky(&k, n);

        // Solve L * L^T * alpha = y
        let z = self.forward_solve(&self.ys);
        self.alpha = self.backward_solve(&z);
    }

    /// Forward substitution: solve L * z = b
    fn forward_solve(&self, b: &[f64]) -> Vec<f64> {
        let n = self.n;
        let l = &self.chol_l;
        let mut z = vec![0.0; n];
        for i in 0..n {
            let mut sum = b[i];
            for j in 0..i {
                sum -= l[i * n + j] * z[j];
            }
            z[i] = sum / l[i * n + i];
        }
        z
    }

    /// Backward substitution: solve L^T * x = z
    fn backward_solve(&self, z: &[f64]) -> Vec<f64> {
        let n = self.n;
        let l = &self.chol_l;
        let mut x = vec![0.0; n];
        for i in (0..n).rev() {
            let mut sum = z[i];
            for j in (i + 1)..n {
                sum -= l[j * n + i] * x[j];
            }
            x[i] = sum / l[i * n + i];
        }
        x
    }
}

/// In-place Cholesky decomposition of symmetric positive-definite matrix.
/// Returns L such that A = L * L^T. Stored row-major in flat vec.
fn cholesky(a: &[f64], n: usize) -> Vec<f64> {
    let mut l = vec![0.0; n * n];
    for i in 0..n {
        for j in 0..=i {
            let mut sum = a[i * n + j];
            for k in 0..j {
                sum -= l[i * n + k] * l[j * n + k];
            }
            if i == j {
                // Numerical safety: clamp to small positive before sqrt
                l[i * n + j] = sum.max(1e-15).sqrt();
            } else {
                l[i * n + j] = sum / l[j * n + j];
            }
        }
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predict_no_observations() {
        let gp = GaussianProcess::new(0.5, 1e-6);
        let (mean, var) = gp.predict(&[0.5]);
        assert!((mean - 0.0).abs() < 1e-10);
        assert!(var > 0.0);
    }

    #[test]
    fn test_predict_single_observation() {
        let mut gp = GaussianProcess::new(0.5, 1e-6);
        gp.observe(vec![0.0], 1.0);
        let (mean, var) = gp.predict(&[0.0]);
        // Mean should be close to 1.0 at the observed point
        assert!((mean - 1.0).abs() < 0.01, "mean={mean}");
        // Variance should be small at the observed point
        assert!(var < 0.01, "var={var}");
    }

    #[test]
    fn test_mean_converges_to_observations() {
        let mut gp = GaussianProcess::new(0.5, 1e-6);
        gp.observe(vec![0.0], 0.0);
        gp.observe(vec![1.0], 1.0);

        let (m0, _) = gp.predict(&[0.0]);
        let (m1, _) = gp.predict(&[1.0]);
        assert!((m0 - 0.0).abs() < 0.01, "m0={m0}");
        assert!((m1 - 1.0).abs() < 0.01, "m1={m1}");
    }

    #[test]
    fn test_variance_decreases_near_observations() {
        let mut gp = GaussianProcess::new(0.5, 1e-6);
        gp.observe(vec![0.5], 1.0);

        let (_, var_near) = gp.predict(&[0.5]);
        let (_, var_far) = gp.predict(&[5.0]);
        assert!(var_near < var_far, "var_near={var_near}, var_far={var_far}");
    }

    #[test]
    fn test_predict_known_1d_function() {
        // f(x) = sin(x), sample at a few points, verify interpolation
        let mut gp = GaussianProcess::new(0.5, 1e-6);
        for i in 0..10 {
            let x = i as f64 * 0.3;
            gp.observe(vec![x], x.sin());
        }
        // Check at a mid-point
        let x_test = 0.75;
        let (mean, _) = gp.predict(&[x_test]);
        assert!(
            (mean - x_test.sin()).abs() < 0.15,
            "mean={mean}, expected={}",
            x_test.sin()
        );
    }

    #[test]
    fn test_predict_2d() {
        let mut gp = GaussianProcess::new(0.5, 1e-6);
        // f(x,y) = x + y
        gp.observe(vec![0.0, 0.0], 0.0);
        gp.observe(vec![1.0, 0.0], 1.0);
        gp.observe(vec![0.0, 1.0], 1.0);
        gp.observe(vec![1.0, 1.0], 2.0);

        let (mean, _) = gp.predict(&[0.5, 0.5]);
        assert!((mean - 1.0).abs() < 0.2, "mean={mean}");
    }

    #[test]
    fn test_cholesky_identity() {
        let a = vec![1.0, 0.0, 0.0, 1.0];
        let l = cholesky(&a, 2);
        assert!((l[0] - 1.0).abs() < 1e-10);
        assert!((l[3] - 1.0).abs() < 1e-10);
        assert!((l[1]).abs() < 1e-10);
        assert!((l[2]).abs() < 1e-10);
    }
}
