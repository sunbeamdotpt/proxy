---
title: CLI Commands
description: Command-line reference for sunbeam-proxy.
category: operator-guide
order: 1
parent: README.md
tags:
  - cli
  - reference
status: published
visibility: public
related:
  - development.md
---

# CLI Commands

## Server

```sh
# Start the proxy server
sunbeam-proxy serve [--upgrade]
```

## Data and training

```sh
# Download upstream datasets (CIC-IDS2017, CSIC 2010)
sunbeam-proxy download-datasets

# Prepare training dataset from audit logs + external data
sunbeam-proxy prepare-dataset --input logs.jsonl --output dataset.bin     [--heuristics heuristics.toml] [--inject-csic]     [--inject-modsec modsec.log] [--wordlists ./wordlists]

# Train scanner ensemble (requires --features training)
sunbeam-proxy train-mlp-scanner --dataset dataset.bin     --output-dir src/ensemble/weights [--epochs 100] [--hidden-dim 32]

# Train DDoS ensemble (requires --features training)
sunbeam-proxy train-mlp-ddos --dataset dataset.bin     --output-dir src/ensemble/weights [--epochs 100] [--hidden-dim 32]

# Sweep cookie_weight hyperparameter
sunbeam-proxy sweep-cookie-weight --dataset dataset.bin --detector scanner

# Replay logs through compiled-in ensemble models
sunbeam-proxy replay --input logs.jsonl [--window-secs 60] [--min-events 5]
```
