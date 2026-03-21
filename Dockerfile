# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: Apache-2.0

# ── Stage 1: build ──────────────────────────────────────────────
FROM rust:slim AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y musl-tools curl cmake pkg-config && rm -rf /var/lib/apt/lists/*

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

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src benches && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    echo 'fn main() {}' > benches/scanner_bench.rs && \
    echo 'fn main() {}' > benches/ddos_bench.rs && \
    cargo build --release --target "$(cat /rust-target)" ; \
    rm -rf src benches

COPY src/ ./src/
COPY benches/ ./benches/
RUN touch src/main.rs && \
    cargo build --release --target "$(cat /rust-target)" && \
    cp "target/$(cat /rust-target)/release/sunbeam-proxy" /sunbeam-proxy

RUN case "${TARGETARCH}" in \
      "amd64") TINI_ARCH="amd64" ;; \
      "arm64") TINI_ARCH="arm64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tini \
      "https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-${TINI_ARCH}" && \
    chmod +x /tini

# ── Stage 2: distroless final ────────────────────────────────────
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /tini                       /tini
COPY --from=builder /sunbeam-proxy              /usr/local/bin/sunbeam-proxy

EXPOSE 80 443

ENTRYPOINT ["/tini", "--", "/usr/local/bin/sunbeam-proxy"]
