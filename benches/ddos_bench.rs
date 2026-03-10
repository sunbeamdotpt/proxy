// Copyright Sunbeam Studios 2026
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sunbeam_proxy::ensemble::ddos::ddos_ensemble_predict;
use sunbeam_proxy::ensemble::gen::ddos_weights;
use sunbeam_proxy::ensemble::mlp::mlp_predict_32;
use sunbeam_proxy::ensemble::tree::tree_predict;

fn bench_ensemble_ddos_full(c: &mut Criterion) {
    let raw: [f32; 14] = [5.0, 10.0, 2.0, 0.1, 50.0, 0.5, 3.0, 0.3, 500.0, 2.0, 0.8, 0.7, 0.9, 0.1];
    c.bench_function("ensemble::ddos full predict", |b| {
        b.iter(|| ddos_ensemble_predict(black_box(&raw)))
    });
}

fn bench_ensemble_ddos_tree_only(c: &mut Criterion) {
    let input: [f32; 14] = [0.5; 14];
    c.bench_function("ensemble::ddos tree_only", |b| {
        b.iter(|| tree_predict(black_box(&ddos_weights::TREE_NODES), black_box(&input)))
    });
}

fn bench_ensemble_ddos_mlp_only(c: &mut Criterion) {
    let input: [f32; 14] = [0.5; 14];
    c.bench_function("ensemble::ddos mlp_only", |b| {
        b.iter(|| mlp_predict_32::<14>(
            black_box(&ddos_weights::W1),
            black_box(&ddos_weights::B1),
            black_box(&ddos_weights::W2),
            black_box(ddos_weights::B2),
            black_box(&input),
        ))
    });
}

criterion_group!(
    benches,
    bench_ensemble_ddos_full,
    bench_ensemble_ddos_tree_only,
    bench_ensemble_ddos_mlp_only,
);
criterion_main!(benches);
