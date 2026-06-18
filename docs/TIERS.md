---
title: Verification Tiers
description: The four-tier formal verification stack for ensemble models.
category: operator-guide
order: 4
parent: README.md
tags:
  - verification
  - lean
  - ml
status: published
visibility: public
related:
  - threat-detection.md
  - architecture.md
---

# Tiers

Sunbeam includes a four-tier formal verification stack for the scanner and DDoS ensembles. Each tier is a separate Lean theorem with a separate hypothesis on the weights or input; deployment-level claims compose them.

This document defines the four verification tiers referenced in code and commit messages.

## The four tiers

| Tier | What it proves | Hypothesis | Lean module |
|------|----------------|------------|-------------|
| **1 — Structural** | `mlp(x) ∈ (0, 1)`, ensemble verdict is total. | None (holds for any weights). | `Sunbeam.Verify.Structural` |
| **2 — Shape / Monotonicity** | MLP is monotone non-decreasing in feature `i`. | Per-neuron sign constraint `∀ j. W2[j] · W1[j][i] ≥ 0`. | `Sunbeam.Verify.Monotonicity` |
| **3 — Lipschitz** | Per-coordinate sensitivity bound on `mlpForward`. | None (the constant is computed from the weights). | `Sunbeam.Verify.Lipschitz` |
| **4 — FP32 error** | `|toReal(mlpForwardF32 w x) − mlpForward (weightsToReal w) (vecToReal x)|` is bounded by `mlpF32Error w x`. | Half-ULP per op, propagated; from TorchLean's `neural_error_bound_ulp`. | `Sunbeam.Verify.F32ErrorBounds` |

Tier 1 is weight-independent. Tiers 2–4 are conditional or quantitative properties of a specific trained snapshot.

## Composed (deployment) theorems

Tiers compose into operational claims that match how the runtime actually runs:

- **`fp32_above_threshold_when_real_above_margin`** (4) —
  if the ℝ-score has margin > `mlpF32Error` above the threshold, the FP32 score crosses the threshold too.
- **`fp32_above_threshold_stable_under_perturbation`** (3 × 4) —
  same, but survives an L∞ perturbation budget via the Lipschitz constant.
- **`fp32_above_threshold_stable_under_monotone_perturbation`** (2 × 4) —
  if the score has margin at the original input, no monotone-upward perturbation of an adversarial feature flips the verdict, regardless of magnitude. "One-way street" on f32 hardware.
- **`verdict_stable_block_f32` / `verdict_stable_allow_f32`** (Crown × 4) —
  per-input certified radius `r_x` such that no L∞ perturbation of size `≤ r_x` flips the verdict, sound on IEEE-754 binary32 hardware. Underlying IBP soundness is `Sunbeam.Verify.Interval32IBP.mlpInterval32_sound`.

All deployment theorems live in `Sunbeam.Verify.Deployment` and `Sunbeam.Verify.F32CrownBound`. None depend on Sunbeam-local axioms; only `propext`, `Classical.choice`, `Quot.sound` (Mathlib baseline).

## Discharging the hypotheses

Tier 2's sign-constraint hypothesis is what the training pipeline has to deliver and the audit verifies:

- **Training**: `src/training/mlp.rs` uses *hard reparameterization* —
  `W1[adv, j] = softplus(γ[adv, j]) · W2[j]`, so the product
  `W1[adv, j] · W2[j] = softplus(γ) · W2[j]² ≥ 0` is non-negative by
  construction. The optimizer cannot violate it.
- **Audit**: `src/ensemble/monotonicity_audit.rs` (scanner) and
  `src/ensemble/ddos_monotonicity_audit.rs` (DDoS) compute
  `min_j (W2[j] · W1[j][i])` over the shipped gen-file weights and report
  `[sign-ok]` for adversarial features.

Tier 3's Lipschitz constant and Tier 4's error bound are computed from the shipped weights with no extra hypothesis.

## Runtime endpoints

- **Per-input certified radius**:
  `ensemble::crown::certified_radius` (generic),
  `ensemble::ddos_crown::ddos_certified_radius` (DDoS, `inputDim = 14`).
- **Outward-rounded IBP forward**:
  `ensemble::crown::ibp_mlp_pre_sigmoid`.
- **Distribution test**: `tests/radius_distribution.rs`.
- **Audit tests**: `cargo test ensemble::monotonicity_audit` /
  `ensemble::ddos_monotonicity_audit`.
