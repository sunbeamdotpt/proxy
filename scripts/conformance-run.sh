#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Idempotent Gateway API v1.5.1 conformance runner for sunbeam-proxy.
#
# Usage:
#   KUBECONFIG=/tmp/k3s.yaml ./scripts/conformance-run.sh
#
# Environment:
#   KUBECONFIG              path to kubeconfig (default: /tmp/k3s.yaml)
#   GATEWAY_ADDR            node IP used as Gateway status address (default: 192.168.252.19)
#   MULTIPASS_VM            multipass VM name (default: sunbeam-proxy-dev)
#   DOCKER_TAG              local image tag (default: sunbeam-proxy:conformance)
#   GATEWAY_API_VERSION     upstream tag (default: v1.5.1)
#   SKIP_BUILD              set to skip cargo build + container image build
#   SUPPORTED_FEATURES      comma-separated feature names advertised to the suite
#   DEBUG_BUILD             set to 1 to build a debug binary instead of release

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=container-runtime.sh
source "${SCRIPT_DIR}/container-runtime.sh"

MANIFESTS_DIR="${PROJECT_ROOT}/tests/conformance/manifests"
FIXTURES_DIR="${PROJECT_ROOT}/tests/fixtures/gateway-integration"

KUBECONFIG="${KUBECONFIG:-/tmp/k3s.yaml}"
GATEWAY_ADDR="${GATEWAY_ADDR:-192.168.252.19}"
MULTIPASS_VM="${MULTIPASS_VM:-sunbeam-proxy-dev}"
DOCKER_TAG="${DOCKER_TAG:-}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"
GATEWAY_API_CHANNEL="${GATEWAY_API_CHANNEL:-experimental}"
SUPPORTED_FEATURES="${SUPPORTED_FEATURES:-Gateway,HTTPRoute,ReferenceGrant,GatewayPort8080,GatewayHTTPListenerIsolation,ListenerSet,TCPRoute,UDPRoute,TLSRoute,TLSRouteModeTerminate,TLSRouteModeMixed,HTTPRouteMethodMatching,HTTPRouteQueryParamMatching,HTTPRouteResponseHeaderModification,HTTPRouteBackendRequestHeaderModification,HTTPRoutePortRedirect,HTTPRouteSchemeRedirect,HTTPRoutePathRedirect,HTTPRoutePathRewrite,HTTPRouteHostRewrite,HTTPRouteCORS,HTTPRouteRequestMirror,HTTPRouteRequestMultipleMirrors,HTTPRouteRequestPercentageMirror,HTTPRouteRequestTimeout,HTTPRouteBackendTimeout,HTTPRouteBackendProtocolH2C,HTTPRouteBackendProtocolWebSocket,HTTPRoute303RedirectStatusCode,HTTPRoute307RedirectStatusCode,HTTPRoute308RedirectStatusCode}"
DEBUG_BUILD="${DEBUG_BUILD:-0}"

STABLE_TAG="sunbeam-proxy:conformance"

if [[ -z "${DOCKER_TAG}" ]]; then
    if [[ "${SKIP_BUILD:-}" == "1" ]]; then
        # When reusing an existing image, avoid generating a new timestamped tag
        # that does not exist in the cluster.
        DOCKER_TAG="${STABLE_TAG}"
    else
        COMMIT_SHORT="$(cd "${PROJECT_ROOT}" && git rev-parse --short HEAD)"
        if [[ -n "$(cd "${PROJECT_ROOT}" && git status --porcelain)" ]]; then
            DIRTY_ID="$(date +%s)"
            DOCKER_TAG="sunbeam-proxy:conformance-${COMMIT_SHORT}-dirty-${DIRTY_ID}"
        else
            DOCKER_TAG="sunbeam-proxy:conformance-${COMMIT_SHORT}"
        fi
    fi
fi

TAR_FILE="/tmp/sunbeam-proxy-conformance.tar"
REMOTE_TAR="/home/ubuntu/sunbeam-proxy-conformance.tar"
GATEWAY_API_DIR="${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}"

export KUBECONFIG

log() {
    echo "[conformance] $*"
}

kubectl_cmd() {
    kubectl "$@"
}

mp() {
    multipass exec "${MULTIPASS_VM}" -- "$@"
}

build_image() {
    log "using container runtime: ${CONTAINER_CMD}"
    if [[ "${DEBUG_BUILD}" == "1" ]]; then
        log "building debug binary"
        cargo build --target aarch64-unknown-linux-musl
        cp "${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/debug/sunbeam-proxy" \
            "${FIXTURES_DIR}/sunbeam-proxy"
    else
        log "building release binary"
        cargo build --release --target aarch64-unknown-linux-musl
        cp "${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release/sunbeam-proxy" \
            "${FIXTURES_DIR}/sunbeam-proxy"
    fi

    log "building container image ${DOCKER_TAG}"
    container_build -t "${DOCKER_TAG}" -t "${STABLE_TAG}" \
        -f "${FIXTURES_DIR}/Dockerfile" \
        "${FIXTURES_DIR}"

    log "saving image"
    container_image_save "${DOCKER_TAG}" -o "${TAR_FILE}"

    log "transferring image to ${MULTIPASS_VM}"
    multipass transfer "${TAR_FILE}" "${MULTIPASS_VM}:${REMOTE_TAR}"

    log "importing image into k3s"
    mp sudo k3s ctr images import "${REMOTE_TAR}"
    # k3s normalizes short image names to docker.io/library/... when resolving
    # pod specs, so make sure the imported tag is also available under that full
    # reference; otherwise the kubelet tries to pull from Docker Hub and fails.
    log "tagging imported image with docker.io/library prefix"
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${DOCKER_TAG}" || true

    log "tagging imported image with stable tag ${STABLE_TAG}"
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "${STABLE_TAG}" || true
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${STABLE_TAG}" || true
}

install_crds() {
    log "installing Gateway API CRDs (${GATEWAY_API_VERSION} ${GATEWAY_API_CHANNEL})"
    # Remove the safe-upgrades admission policy so that switching between
    # standard and experimental channel CRDs does not fail.
    kubectl_cmd delete validatingadmissionpolicybinding safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete validatingadmissionpolicy safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
    # Wipe any previously-installed Gateway API CRDs so that switching channels
    # or re-running after a partial install does not leave mixed channel/version
    # annotations that the conformance suite rejects.
    log "removing previously-installed Gateway API CRDs"
    kubectl_cmd delete crd --ignore-not-found=true \
        gatewayclasses.gateway.networking.k8s.io \
        gateways.gateway.networking.k8s.io \
        httproutes.gateway.networking.k8s.io \
        grpcroutes.gateway.networking.k8s.io \
        tlsroutes.gateway.networking.k8s.io \
        tcproutes.gateway.networking.k8s.io \
        udproutes.gateway.networking.k8s.io \
        listenersets.gateway.networking.k8s.io \
        backendtlspolicies.gateway.networking.k8s.io \
        referencegrants.gateway.networking.k8s.io \
        xbackendtrafficpolicies.gateway.networking.x-k8s.io \
        xmeshes.gateway.networking.x-k8s.io \
        >/dev/null 2>&1 || true
    kubectl_cmd apply --server-side --force-conflicts -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/${GATEWAY_API_CHANNEL}-install.yaml"
}

cleanup_leftovers() {
    # Previous conformance runs (especially failed or interrupted ones) can leave
    # HTTPRoutes behind. Those catch-all routes cause later runs to fail because
    # they shadow the routes the current test expects. Gateways and backends from
    # the base manifests are reapplied by the suite, so we only strip routes here.
    log "cleaning leftover Gateway API routes from previous runs"
    kubectl_cmd delete httproutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete grpcroutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete tlsroutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete referencegrants --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    # The conformance deployment namespace may also contain stale Gateways from
    # earlier manual tests; they will be recreated by the manifests below.
    kubectl_cmd delete gateways -n gateway-conformance --all --ignore-not-found=true >/dev/null 2>&1 || true
}

ensure_no_hostpath_binary() {
    # Older versions of the conformance deployment mounted /usr/local/bin from
    # a hostPath volume. That caused the pod to run a stale binary even when
    # the image was updated. Make sure any leftover volume/mount is removed so
    # the container uses the image contents.
    if kubectl_cmd get deployment -n gateway-conformance sunbeam-proxy -o jsonpath='{range .spec.template.spec.volumes[*]}{@.name}{"\n"}{end}' 2>/dev/null | grep -qx 'sunbeam-binary'; then
        log "removing stale sunbeam-binary hostPath volume from deployment"
        kubectl_cmd patch deployment -n gateway-conformance sunbeam-proxy --type=json -p='[
          {"op": "remove", "path": "/spec/template/spec/volumes/0"},
          {"op": "remove", "path": "/spec/template/spec/containers/0/volumeMounts/0"}
        ]'
    fi
}

deploy_proxy() {
    log "applying sunbeam-proxy conformance manifests"
    kubectl_cmd apply -f "${MANIFESTS_DIR}/"

    ensure_no_hostpath_binary

    log "setting deployment image to ${DOCKER_TAG}"
    kubectl_cmd set image -n gateway-conformance deployment/sunbeam-proxy "proxy=${DOCKER_TAG}"

    log "restarting deployment to ensure the new image is used"
    kubectl_cmd rollout restart -n gateway-conformance deployment/sunbeam-proxy

    log "waiting for deployment rollout"
    kubectl_cmd rollout status -n gateway-conformance deployment/sunbeam-proxy --timeout=120s

    log "waiting for GatewayClass to be accepted"
    for _ in {1..30}; do
        if kubectl_cmd get gatewayclass sunbeam -o jsonpath='{.status.conditions[?(@.type=="Accepted")].status}' 2>/dev/null | grep -q "True"; then
            return 0
        fi
        sleep 2
    done
    log "GatewayClass was not accepted in time"
    return 1
}

clone_upstream() {
    if [[ ! -d "${GATEWAY_API_DIR}" ]]; then
        log "cloning kubernetes-sigs/gateway-api ${GATEWAY_API_VERSION}"
        git clone --depth 1 --branch "${GATEWAY_API_VERSION}" \
            https://github.com/kubernetes-sigs/gateway-api.git "${GATEWAY_API_DIR}"
    else
        log "using existing upstream checkout ${GATEWAY_API_DIR}"
    fi
}

run_tests() {
    log "running conformance tests with features: ${SUPPORTED_FEATURES}"
    local skip_tests_arg=()
    if [[ -n "${SKIP_TESTS:-}" ]]; then
        skip_tests_arg=(-skip-tests "${SKIP_TESTS}")
    fi
    cd "${GATEWAY_API_DIR}/conformance"
    go test . -v \
        -gateway-class sunbeam \
        -supported-features "${SUPPORTED_FEATURES}" \
        -organization "Sunbeam" \
        -project "sunbeam-proxy" \
        -url "https://sunbeam.sh" \
        -version "v0.1.0" \
        -contact "conformance@sunbeam.sh" \
        -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
        -cleanup-base-resources=false \
        "${skip_tests_arg[@]}" \
        "$@"
}

main() {
    if [[ "${SKIP_BUILD:-}" != "1" ]]; then
        build_image
    else
        log "SKIP_BUILD=1, reusing existing image"
    fi

    install_crds
    cleanup_leftovers
    deploy_proxy
    clone_upstream
    run_tests "$@"
    log "done; report at ${PROJECT_ROOT}/target/conformance-report.yaml"
}

main "$@"
