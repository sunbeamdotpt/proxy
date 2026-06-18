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

## Release builds

The release script bumps the version, regenerates the changelog, runs checks, and builds a release binary:

```sh
./scripts/release.sh 0.2.0
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

Conformance tests run against a local k3s cluster in a multipass VM. The suite can use a locally built image (default) or the published release image.

```sh
# Local image build + conformance, tagged as the release image
DOCKER_TAG=ghcr.io/sunbeamdotpt/proxy:v0.2.0 ./scripts/conformance.sh run

# Use the published release image (after the workflow has pushed it)
DOCKER_TAG=ghcr.io/sunbeamdotpt/proxy:v0.2.0 ./scripts/conformance.sh run --pull
```

The suite writes reports to `target/conformance-report.yaml` and `target/conformance-report-detailed.yaml`.
