# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build from the project root. The proxy crate inherits deps from the root
# [workspace.dependencies] table and uses path-patched crates, so a standalone
# build context cannot resolve its manifest.
#
#   container build -f Dockerfile -t sunbeam-proxy:latest .
#
# Context pruning lives in `.dockerignore`. Keep it narrow — anything a
# workspace path dependency needs must NOT be excluded.

# ── Stage 1: build ──────────────────────────────────────────────
FROM rust:1.96-slim-bookworm AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc g++ curl ca-certificates cmake pkg-config make && \
    rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
      "amd64") TRIPLE="x86_64-linux-gnu" ; echo "x86_64-unknown-linux-gnu" > /rust-target ;; \
      "arm64") TRIPLE="aarch64-linux-gnu" ; echo "aarch64-unknown-linux-gnu" > /rust-target ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    rustup target add "$(cat /rust-target)" && \
    ln -sf "$(which gcc)" "/usr/local/bin/${TRIPLE}-gcc" && \
    ln -sf "$(which g++)" "/usr/local/bin/${TRIPLE}-g++" && \
    mkdir -p /root/.cargo && \
    printf '[target.%s]\nlinker = "gcc"\n' "$(cat /rust-target)" >> /root/.cargo/config.toml && \
    mkdir -p /runtime-libs && \
    cp "/usr/lib/${TRIPLE}/libgcc_s.so.1" /runtime-libs/libgcc_s.so.1 || \
    cp "/lib/${TRIPLE}/libgcc_s.so.1" /runtime-libs/libgcc_s.so.1

ENV CC_x86_64_unknown_linux_gnu="gcc" \
    CXX_x86_64_unknown_linux_gnu="g++" \
    CC_aarch64_unknown_linux_gnu="gcc" \
    CXX_aarch64_unknown_linux_gnu="g++" \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="gcc" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="gcc"
WORKDIR /build
COPY . .

ARG CARGO_BUILD_JOBS=default
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
# Pinned digest for gcr.io/distroless/cc-debian12:nonroot (multi-arch index).
FROM gcr.io/distroless/cc-debian12@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985

LABEL org.opencontainers.image.source="https://github.com/sunbeamdotpt/proxy"

COPY --from=builder --chown=65532:65532 /tini                       /tini
COPY --from=builder --chown=65532:65532 /sunbeam-proxy              /usr/local/bin/sunbeam-proxy
COPY --from=builder --chown=65532:65532 /runtime-libs/libgcc_s.so.1 /lib/libgcc_s.so.1

USER 65532:65532

EXPOSE 8080 8443 9090

ENTRYPOINT ["/tini", "--", "/usr/local/bin/sunbeam-proxy"]
