// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Benchmarks for DDoS CROWN certified-radius computation.
//!
//! Mirrors `crown_bench.rs` at `inputDim = 14` for the DDoS ensemble. The
//! underlying outward-rounded IBP kernel is shared with scanner; only the
//! input dimension and weight constants differ.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sunbeam_proxy::ensemble::crown::{certified_radius, ibp_mlp_pre_sigmoid};
use sunbeam_proxy::ensemble::gen::ddos_weights;

/// Representative DDoS input: 14 normalized features mid-range with some
/// spread to avoid sitting exactly on the decision boundary.
const DDOS_INPUT: [f32; 14] = [
    0.3, 0.2, 0.5, 0.4, 0.1, 0.0, 0.0, 0.25, 0.0, 0.5, 0.0, 0.0, 0.0, 1.0,
];

fn bench_ibp_pre_sigmoid(c: &mut Criterion) {
    let eps = 0.05f32;
    let lo: [f32; 14] = std::array::from_fn(|i| DDOS_INPUT[i] - eps);
    let hi: [f32; 14] = std::array::from_fn(|i| DDOS_INPUT[i] + eps);
    c.bench_function("ddos_crown::ibp_mlp_pre_sigmoid", |b| {
        b.iter(|| {
            ibp_mlp_pre_sigmoid::<14>(
                black_box(&ddos_weights::W1),
                black_box(&ddos_weights::B1),
                black_box(&ddos_weights::W2),
                black_box(ddos_weights::B2),
                black_box(&lo),
                black_box(&hi),
            )
        })
    });
}

fn bench_certified_radius_loose(c: &mut Criterion) {
    c.bench_function("ddos_crown::certified_radius tol=1e-3", |b| {
        b.iter(|| {
            certified_radius::<14>(
                black_box(&ddos_weights::W1),
                black_box(&ddos_weights::B1),
                black_box(&ddos_weights::W2),
                black_box(ddos_weights::B2),
                black_box(&DDOS_INPUT),
                black_box(ddos_weights::THRESHOLD),
                black_box(0.5),
                black_box(1e-3),
            )
        })
    });
}

fn bench_certified_radius_tight(c: &mut Criterion) {
    c.bench_function("ddos_crown::certified_radius tol=1e-5", |b| {
        b.iter(|| {
            certified_radius::<14>(
                black_box(&ddos_weights::W1),
                black_box(&ddos_weights::B1),
                black_box(&ddos_weights::W2),
                black_box(ddos_weights::B2),
                black_box(&DDOS_INPUT),
                black_box(ddos_weights::THRESHOLD),
                black_box(0.5),
                black_box(1e-5),
            )
        })
    });
}

criterion_group!(
    benches,
    bench_ibp_pre_sigmoid,
    bench_certified_radius_loose,
    bench_certified_radius_tight,
);
criterion_main!(benches);
