# ── Stage 1: build ──────────────────────────────────────────────
# rust:slim tracks the latest stable Rust release.
# Multi-arch image; Docker buildx selects the native platform image.
FROM rust:slim AS builder

ARG TARGETARCH

# musl-tools: musl-gcc for static linking.
# curl: download tini init binary.
# No cmake/go needed: we use the rustls feature flag (pure Rust TLS).
RUN apt-get update && apt-get install -y musl-tools curl cmake && rm -rf /var/lib/apt/lists/*

# Map Docker TARGETARCH to the appropriate Rust musl target,
# then configure Cargo to use musl-gcc as the linker for that target.
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

# Cache dependency compilation separately from source changes.
# RUSTFLAGS must match the real build or Cargo will recompile everything.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo 'fn main() {}' > src/main.rs && \
    cargo build --release --target "$(cat /rust-target)" ; \
    rm -rf src

# Build the real binary.
COPY src/ ./src/
RUN touch src/main.rs && \
    cargo build --release --target "$(cat /rust-target)" && \
    cp "target/$(cat /rust-target)/release/sunbeam-proxy" /sunbeam-proxy

# Download tini static init binary (musl, no glibc dependency).
# tini as PID 1 ensures the container stays alive when Pingora re-execs itself
# during a graceful upgrade: the new process is re-parented to tini, and tini
# correctly reaps the old process when it exits after draining connections.
RUN case "${TARGETARCH}" in \
      "amd64") TINI_ARCH="amd64" ;; \
      "arm64") TINI_ARCH="arm64" ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL -o /tini \
      "https://github.com/krallin/tini/releases/download/v0.19.0/tini-static-${TINI_ARCH}" && \
    chmod +x /tini

# ── Stage 2: distroless final ────────────────────────────────────
# cgr.dev/chainguard/static is multi-arch (amd64 + arm64).
# No shell, no package manager — minimal attack surface.
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /tini                       /tini
COPY --from=builder /sunbeam-proxy              /usr/local/bin/sunbeam-proxy

EXPOSE 80 443

# tini as PID 1 so Pingora's graceful-upgrade re-exec doesn't kill the container.
ENTRYPOINT ["/tini", "--", "/usr/local/bin/sunbeam-proxy"]
