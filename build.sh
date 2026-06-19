#!/usr/bin/env bash
# Cross-platform image build for sunbeam-proxy.
#
# This script builds the Rust binary on the host using cargo-zigbuild + zig,
# packages it with a static tini init into a distroless/cc-debian12 image, and
# pushes per-arch tags plus a multi-arch index using crane.
#
# It works on macOS (where the Apple `container` builder's OCI exporter is
# unreliable for long builds) and on Linux hosts with the same prerequisites.
#
# Prerequisites:
#   - rustup + nightly toolchain
#   - cargo-zigbuild
#   - zig
#   - crane
#
# Usage:
#   ./build.sh [VERSION]
#
# Environment overrides:
#   VERSION   default: v0.2.1
#   IMAGE     default: ghcr.io/sunbeamdotpt/proxy
#   PLATFORMS default: linux/amd64,linux/arm64
#   BASE_IMAGE default: pinned distroless/cc-debian12

set -euo pipefail

VERSION="${VERSION:-v0.2.1}"
IMAGE="${IMAGE:-ghcr.io/sunbeamdotpt/proxy}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
BASE_IMAGE="${BASE_IMAGE:-gcr.io/distroless/cc-debian12@sha256:b0ae8e989418b458e0f25489bc3be523718938a2b70864cc0f6a00af1ddbd985}"
TINI_VERSION="${TINI_VERSION:-v0.19.0}"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${REPO_ROOT}/build/image"

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        echo "       $2" >&2
        exit 1
    fi
}

need_cmd rustup   "https://rustup.rs/"
need_cmd cargo-zigbuild "cargo install cargo-zigbuild"
need_cmd zig      "brew install zig  (or see https://ziglang.org/download/)"
need_cmd crane    "brew install crane (or see https://github.com/google/go-containerregistry/blob/main/cmd/crane)"

CARGO_BIN="$(rustup which cargo)"
RUSTC_BIN="$(rustup which rustc)"

rust_triple_for_platform() {
    case "$1" in
        linux/amd64) echo "x86_64-unknown-linux-gnu" ;;
        linux/arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "ERROR: unsupported platform: $1" >&2; exit 1 ;;
    esac
}

arch_for_platform() {
    case "$1" in
        linux/amd64) echo "amd64" ;;
        linux/arm64) echo "arm64" ;;
        *) echo "ERROR: unsupported platform: $1" >&2; exit 1 ;;
    esac
}

build_binary() {
    local platform="$1"
    local target
    target="$(rust_triple_for_platform "$platform")"

    echo "==> Installing Rust target ${target} (if missing)"
    rustup target add "${target}"

    echo "==> Building release binary for ${platform}"
    RUSTC="${RUSTC_BIN}" \
        "${CARGO_BIN}" zigbuild \
            --release \
            --target "${target}" \
            --package sunbeam-proxy \
            --bin sunbeam-proxy

    echo "==> Built: target/${target}/release/sunbeam-proxy"
}

fetch_tini() {
    local arch="$1"
    local dest="${BUILD_DIR}/tini/tini-${arch}"
    local url="https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-${arch}"

    if [[ -x "${dest}" ]]; then
        echo "==> Using cached tini for ${arch}"
        return 0
    fi

    echo "==> Fetching tini-static-${arch} ${TINI_VERSION}"
    mkdir -p "$(dirname "${dest}")"
    curl -fsSL -o "${dest}" "${url}"
    chmod +x "${dest}"
}

build_layer_tar() {
    local platform="$1"
    local arch="$2"
    local target
    target="$(rust_triple_for_platform "$platform")"

    local binary="${REPO_ROOT}/target/${target}/release/sunbeam-proxy"
    local tini="${BUILD_DIR}/tini/tini-${arch}"
    local stage="${BUILD_DIR}/staging/${platform}"
    local layer="${BUILD_DIR}/layer-${arch}.tar"

    if [[ ! -x "${binary}" ]]; then
        echo "ERROR: binary not found: ${binary}" >&2
        exit 1
    fi

    echo "==> Staging layer for ${platform}"
    rm -rf "${stage}"
    mkdir -p "${stage}/usr/local/bin"
    cp "${binary}" "${stage}/usr/local/bin/sunbeam-proxy"
    cp "${tini}" "${stage}/tini"
    chmod +x "${stage}/usr/local/bin/sunbeam-proxy" "${stage}/tini"

    echo "==> Creating layer tarball: ${layer}"
    # COPYFILE_DISABLE avoids macOS tar adding AppleDouble/resource-fork files.
    COPYFILE_DISABLE=1 \
        tar --owner=65532 --group=65532 -cf "${layer}" -C "${stage}" .
}

build_image() {
    local platform="$1"
    local arch="$2"
    local layer="${BUILD_DIR}/layer-${arch}.tar"
    local tag="${IMAGE}:${VERSION}-${arch}"

    echo "==> Appending layer and pushing ${tag}"
    crane append -b "${BASE_IMAGE}" \
        --platform "${platform}" \
        -f "${layer}" \
        -t "${tag}"

    echo "==> Setting image config for ${tag}"
    crane mutate "${tag}" \
        -t "${tag}" \
        --entrypoint /tini \
        --entrypoint -- \
        --entrypoint /usr/local/bin/sunbeam-proxy \
        --user 65532:65532 \
        --workdir / \
        --exposed-ports 8080/tcp \
        --exposed-ports 8443/tcp \
        --exposed-ports 9090/tcp
}

push_index() {
    local manifests=()
    local platform arch
    IFS=',' read -ra PLATFORM_LIST <<< "${PLATFORMS}"
    for platform in "${PLATFORM_LIST[@]}"; do
        arch="$(arch_for_platform "$platform")"
        manifests+=("-m" "${IMAGE}:${VERSION}-${arch}")
    done

    echo "==> Creating multi-arch index: ${IMAGE}:${VERSION}"
    crane index append "${manifests[@]}" -t "${IMAGE}:${VERSION}"
}

main() {
    if [[ $# -gt 0 ]]; then
        VERSION="$1"
    fi

    echo "Building ${IMAGE}:${VERSION} for platforms: ${PLATFORMS}"

    mkdir -p "${BUILD_DIR}"

    local platform arch
    IFS=',' read -ra PLATFORM_LIST <<< "${PLATFORMS}"

    for platform in "${PLATFORM_LIST[@]}"; do
        echo
        echo "---- platform: ${platform} ----"
        arch="$(arch_for_platform "$platform")"
        build_binary "${platform}"
        fetch_tini "${arch}"
        build_layer_tar "${platform}" "${arch}"
        build_image "${platform}" "${arch}"
    done

    echo
    push_index

    echo
    echo "Done."
}

main "$@"
