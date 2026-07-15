---
title: Development
description: Build, test, and release instructions for contributors.
category: operator-guide
order: 2
parent: README.md
tags:
  - development
  - build
  - testing
status: published
visibility: public
related:
  - cli.md
  - architecture.md
---

# Development

```sh
cargo build                          # debug build
cargo build --features training      # includes burn-rs training pipeline
cargo test                           # run all tests (1300+)
cargo bench                          # ensemble inference benchmarks
cargo clippy -- -D warnings          # lint
```

The `training` feature enables GPU-accelerated training via burn-rs and wgpu. The default build omits these dependencies and uses the compiled-in model weights.

## Container-backed tests

`tests/otel.rs` starts a real OpenTelemetry collector via testcontainers, so it needs a Docker-compatible daemon. Testcontainers talks to the Docker API through `DOCKER_HOST` and does not honor docker CLI contexts — on lima/colima setups you must export the socket explicitly:

```sh
DOCKER_HOST=unix://$HOME/.lima/docker/sock/docker.sock cargo test
```

When the daemon is unreachable the test skips itself and prints this hint.

## Release builds

The release script bumps the version, regenerates the changelog, runs checks, and builds a release binary:

```sh
./scripts/release.sh 0.2.1
```

Multi-arch container images are built and pushed by the GitHub Actions release workflow on tag pushes.

### Container images

The single `Dockerfile` produces a static musl binary and copies it into a distroless final image. It supports `linux/amd64` and `linux/arm64`:

```sh
container build --platform linux/arm64 -t sunbeam-proxy:local-arm64 .
container build --platform linux/amd64 -t sunbeam-proxy:local-amd64 .
```

The release workflow pushes to:

```
ghcr.io/sunbeamdotpt/proxy:<tag>
```

### Gateway API conformance

Conformance tests run against a local k3s cluster in a Multipass VM. The suite can use a locally built image (default) or the published release image.

```sh
# Use the published release image (no local build)
DOCKER_TAG=ghcr.io/sunbeamdotpt/proxy:v0.2.1 ./scripts/conformance.sh run -p

# Local image build + conformance
DOCKER_TAG=ghcr.io/sunbeamdotpt/proxy:v0.2.1 ./scripts/conformance.sh run
```

The upstream conformance report is written to `target/conformance-report.yaml`, and a detailed per-test summary is written to `target/conformance-report-detailed.yaml`. The official report used for upstream submissions lives in `conformance/reports/v1.5/sunbeam-proxy/`.
