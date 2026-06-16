# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build from the WORKSPACE ROOT, not from platform/proxy. The proxy crate
# inherits deps from the root [workspace.dependencies] table and pulls
# pingora via `[patch.crates-io] pingora-proxy = { path = "forks/pingora/…" }`
# in the root Cargo.toml, so a standalone build context can't resolve its
# manifest.
#
#   docker buildx build -f platform/proxy/Dockerfile -t sunbeam-proxy:latest .
#
# Context pruning lives in `platform/proxy/Dockerfile.dockerignore` (BuildKit
# sidecar dockerignore). Keep that file narrow — anything a workspace path
# dep needs must NOT be excluded.

# ── Stage 1: build ──────────────────────────────────────────────
FROM rust:1.86-slim AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      musl-tools curl ca-certificates cmake pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      "amd64") RUST_TARGET="x86_64-unknown-linux-musl" ;; \
      "arm64") RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    echo "${RUST_TARGET}" > /rust-target && \
    rustup target add "${RUST_TARGET}" && \
    mkdir -p /root/.cargo && \
    printf '[target.%s]\nlinker = "musl-gcc"\n' "${RUST_TARGET}" \
      >> /root/.cargo/config.toml

ENV RUSTFLAGS="-C target-feature=+crt-static"
WORKDIR /build
COPY . .

ARG CARGO_BUILD_JOBS
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}

RUN cargo build \
      --release \
      --target "$(cat /rust-target)" \
      --package sunbeam-proxy \
      --bin sunbeam-proxy && \
    cp "target/$(cat /rust-target)/release/sunbeam-proxy" /sunbeam-proxy

# Pin tini to a released version and verify its checksum before copying into
# the final image.
RUN case "${TARGETARCH}" in \
      "amd64") TINI_ARCH="amd64" ;; \
      "arm64") TINI_ARCH="arm64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tini \
      "https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-${TINI_ARCH}" && \
    case "${TINI_ARCH}" in \
      "amd64") echo "c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee  /tini" ;; \
      "arm64") echo "eae1d3aa50c48fb23b8cbdf4e369d0910dfc538566bfd09df89a774aa84a48b9  /tini" ;; \
    esac | sha256sum -c - && \
    chmod +x /tini

# ── Stage 2: distroless final ────────────────────────────────────
# Pinned digest for gcr.io/distroless/static-debian12:nonroot (multi-arch index).
FROM gcr.io/distroless/static-debian12@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=builder --chown=65532:65532 /tini                       /tini
COPY --from=builder --chown=65532:65532 /sunbeam-proxy              /usr/local/bin/sunbeam-proxy

USER 65532:65532

EXPOSE 8080 8443 9090

ENTRYPOINT ["/tini", "--", "/usr/local/bin/sunbeam-proxy"]
