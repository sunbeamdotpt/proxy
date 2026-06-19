// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Benchmarks for CROWN certified-radius computation.
//!
//! Three layers of cost:
//!
//! 1. `ibp_mlp_pre_sigmoid` — single pass IBP through Linear → ReLU → Linear.
//!    This is the inner kernel and dominates wall time at small tolerances.
//! 2. `certified_radius @ 1e-3` — production tolerance, ~10 binary-search
//!    iterations.
//! 3. `certified_radius @ 1e-5` — high-precision tolerance, ~17 iterations.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use sunbeam_proxy::ensemble::crown::{certified_radius, ibp_mlp_pre_sigmoid};
use sunbeam_proxy::ensemble::weights::scanner_weights;

/// Representative production input: 12 normalized features for the scanner.
const SCANNER_INPUT: [f32; 12] = [0.8, 0.3, 1.0, 0.0, 0.0, 0.0, 0.0, 0.25, 0.0, 0.0, 0.0, 1.0];

fn bench_ibp_pre_sigmoid(c: &mut Criterion) {
    let eps = 0.05f32;
    let lo: [f32; 12] = std::array::from_fn(|i| SCANNER_INPUT[i] - eps);
    let hi: [f32; 12] = std::array::from_fn(|i| SCANNER_INPUT[i] + eps);
    c.bench_function("crown::ibp_mlp_pre_sigmoid", |b| {
        b.iter(|| {
            ibp_mlp_pre_sigmoid::<12>(
                black_box(&scanner_weights::W1),
                black_box(&scanner_weights::B1),
                black_box(&scanner_weights::W2),
                black_box(scanner_weights::B2),
                black_box(&lo),
                black_box(&hi),
            )
        })
    });
}

fn bench_certified_radius_loose(c: &mut Criterion) {
    c.bench_function("crown::certified_radius tol=1e-3", |b| {
        b.iter(|| {
            certified_radius::<12>(
                black_box(&scanner_weights::W1),
                black_box(&scanner_weights::B1),
                black_box(&scanner_weights::W2),
                black_box(scanner_weights::B2),
                black_box(&SCANNER_INPUT),
                black_box(scanner_weights::THRESHOLD),
                black_box(0.5),
                black_box(1e-3),
            )
        })
    });
}

fn bench_certified_radius_tight(c: &mut Criterion) {
    c.bench_function("crown::certified_radius tol=1e-5", |b| {
        b.iter(|| {
            certified_radius::<12>(
                black_box(&scanner_weights::W1),
                black_box(&scanner_weights::B1),
                black_box(&scanner_weights::W2),
                black_box(scanner_weights::B2),
                black_box(&SCANNER_INPUT),
                black_box(scanner_weights::THRESHOLD),
                black_box(0.5),
                black_box(1e-5),
            )
        })
    });
}

fn bench_certified_radius_uniform_input(c: &mut Criterion) {
    // Uniform 0.5 input — sits near the decision boundary, exercises the worst-case
    // search where the certifiable radius is small.
    let input = [0.5f32; 12];
    c.bench_function("crown::certified_radius uniform_input", |b| {
        b.iter(|| {
            certified_radius::<12>(
                black_box(&scanner_weights::W1),
                black_box(&scanner_weights::B1),
                black_box(&scanner_weights::W2),
                black_box(scanner_weights::B2),
                black_box(&input),
                black_box(scanner_weights::THRESHOLD),
                black_box(0.5),
                black_box(1e-4),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_ibp_pre_sigmoid,
    bench_certified_radius_loose,
    bench_certified_radius_tight,
    bench_certified_radius_uniform_input,
);
criterion_main!(benches);
