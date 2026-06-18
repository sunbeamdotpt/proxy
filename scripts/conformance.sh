#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Gateway API conformance runner.
#
# Usage:
#   ./scripts/conformance.sh run [options]
#   ./scripts/conformance.sh coverage-diff [base-ref]
#
# The default flow uses the published multi-arch image from ghcr.io. No local
# container build is required.
#
# Run options:
#   -C, --skip-crds         Skip Gateway API CRD install/reinstall
#   -p, --pull              No-op kept for backwards compatibility (image is always pulled)
#   -T, --run-test <name>   Run a single upstream conformance test
#   -s, --skip-tests <list> Comma-separated list of tests to skip
#   -n, --dry-run           Print the computed command and exit
#   -h, --help              Show help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

MANIFESTS_DIR="${PROJECT_ROOT}/tests/conformance/manifests"

KUBECONFIG="${KUBECONFIG:-/tmp/k3s.yaml}"
MULTIPASS_VM="${MULTIPASS_VM:-sunbeam-proxy-dev}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"
GATEWAY_API_CHANNEL="${GATEWAY_API_CHANNEL:-experimental}"
PROJECT_VERSION="${PROJECT_VERSION:-$(grep -E '^version' "${PROJECT_ROOT}/Cargo.toml" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')}"
DOCKER_TAG="${DOCKER_TAG:-ghcr.io/sunbeamdotpt/proxy:v${PROJECT_VERSION}}"
CONFORMANCE_PROFILES="${CONFORMANCE_PROFILES:-GATEWAY-HTTP,GATEWAY-GRPC,GATEWAY-TLS}"
IMPLEMENTATION_ORG="${IMPLEMENTATION_ORG:-sunbeamdotpt}"
IMPLEMENTATION_PROJECT="${IMPLEMENTATION_PROJECT:-sunbeam-proxy}"
IMPLEMENTATION_URL="${IMPLEMENTATION_URL:-https://github.com/sunbeamdotpt/proxy}"
IMPLEMENTATION_CONTACT="${IMPLEMENTATION_CONTACT:-https://github.com/sunbeamdotpt/proxy/issues}"
DEFAULT_SKIP_TESTS="MeshBasic,MeshConsumerRoute,MeshFrontend,MeshFrontendHostname,MeshGRPCRouteWeight,MeshHTTPRoute303Redirect,MeshHTTPRoute307Redirect,MeshHTTPRoute308Redirect,MeshHTTPRouteBackendRequestHeaderModifier,MeshHTTPRouteMatching,MeshHTTPRouteNamedRule,MeshHTTPRouteQueryParamMatching,MeshHTTPRouteRedirectHostAndStatus,MeshHTTPRouteRedirectPath,MeshHTTPRouteRedirectPort,MeshHTTPRouteRequestHeaderModifier,MeshHTTPRouteRewritePath,MeshHTTPRouteSchemeRedirect,MeshHTTPRouteSimpleSameNamespace,MeshHTTPRouteWeight,MeshPorts,MeshTrafficSplit"
SKIP_CRDS="${SKIP_CRDS:-0}"

GATEWAY_API_DIR="${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}"

export KUBECONFIG

usage() {
    cat <<'EOF'
Usage: ./scripts/conformance.sh <command> [options]

Commands:
  run [options]                     Run the Gateway API conformance suite
  coverage-diff [base-ref]          Print line coverage for changed Rust files

Run options:
  -C, --skip-crds                   Skip Gateway API CRD install/reinstall
  -p, --pull                        No-op; the image is always pulled from ghcr.io
  -T, --run-test <name>             Run a single upstream conformance test
  -s, --skip-tests <list>           Comma-separated list of tests to skip
                                    (defaults to the mesh test suite)
  -n, --dry-run                     Print the computed command and exit
  -h, --help                        Show this help
EOF
}

log() {
    echo "[conformance] $*"
}

kubectl_cmd() {
    kubectl "$@"
}

mp() {
    multipass exec "${MULTIPASS_VM}" -- "$@"
}

resolve_gateway_addr() {
    if [[ -n "${GATEWAY_ADDR:-}" ]]; then
        echo "${GATEWAY_ADDR}"
        return 0
    fi
    if ! multipass info "${MULTIPASS_VM}" >/dev/null 2>&1; then
        log "error: Multipass VM '${MULTIPASS_VM}' not found and GATEWAY_ADDR is not set"
        return 1
    fi
    multipass info "${MULTIPASS_VM}" --format csv \
        | awk -F, -v vm="${MULTIPASS_VM}" '$1 == vm {print $3}'
}

pull_image() {
    log "using image: ${DOCKER_TAG}"
    log "pulling image into ${MULTIPASS_VM}"
    mp sudo k3s ctr images pull "${DOCKER_TAG}"
}

install_crds() {
    log "installing Gateway API CRDs (${GATEWAY_API_VERSION} ${GATEWAY_API_CHANNEL})"
    kubectl_cmd delete validatingadmissionpolicybinding safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete validatingadmissionpolicy safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
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
    log "cleaning leftover Gateway API routes from previous runs"
    kubectl_cmd delete httproutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete grpcroutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete tlsroutes --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete referencegrants --all --all-namespaces --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete gateways -n gateway-conformance --all --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete configmap -n gateway-conformance-infra \
        tls-checks-ca-certificate-reconcile-test \
        mismatch-ca-certificate \
        --ignore-not-found=true >/dev/null 2>&1 || true
}

deploy_proxy() {
    log "applying sunbeam-proxy conformance manifests"
    kubectl_cmd apply -f "${MANIFESTS_DIR}/"

    log "setting deployment image to ${DOCKER_TAG}"
    kubectl_cmd set image -n gateway-conformance deployment/sunbeam-proxy "proxy=${DOCKER_TAG}"

    log "setting Gateway address env to ${GATEWAY_ADDR}"
    kubectl_cmd set env -n gateway-conformance deployment/sunbeam-proxy "SUNBEAM_GATEWAY_ADDRESS=${GATEWAY_ADDR}"

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
    log "running conformance tests (profiles: ${CONFORMANCE_PROFILES}; mesh tests skipped by default)"
    local -a args=()
    args+=(-conformance-profiles "${CONFORMANCE_PROFILES}")
    if [[ -n "${SKIP_TESTS:-}" ]]; then
        args+=(-skip-tests "${SKIP_TESTS}")
    fi
    if [[ -n "${RUN_TEST:-}" ]]; then
        args+=(-run-test "${RUN_TEST}")
    fi

    cd "${GATEWAY_API_DIR}/conformance"
    go test . -v \
        -gateway-class sunbeam \
        -all-features \
        -usable-address "${GATEWAY_ADDR}" \
        -unusable-address "240.0.0.1" \
        -organization "${IMPLEMENTATION_ORG}" \
        -project "${IMPLEMENTATION_PROJECT}" \
        -url "${IMPLEMENTATION_URL}" \
        -version "v${PROJECT_VERSION}" \
        -contact "${IMPLEMENTATION_CONTACT}" \
        -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
        -cleanup-base-resources=false \
        "${args[@]}" 2>&1 | tee "${PROJECT_ROOT}/target/conformance-output.log"
}

coverage_diff_command() {
    local base_ref="${1:-}"
    cd "${PROJECT_ROOT}"

    if [[ -n "${base_ref}" ]]; then
        :
    elif git show-ref --verify --quiet refs/heads/main; then
        base_ref="main"
    elif git show-ref --verify --quiet refs/remotes/origin/main; then
        base_ref="origin/main"
    else
        base_ref="HEAD~1"
    fi

    local merge_base
    merge_base="$(git merge-base HEAD "${base_ref}")"
    echo "[coverage-diff] base: ${base_ref} (${merge_base})"

    mapfile -t changed_files < <(
        git diff --name-only "${merge_base}" HEAD \
            | grep '^src/.*\.rs$' \
            | sort
    )

    if [[ ${#changed_files[@]} -eq 0 ]]; then
        echo "[coverage-diff] no changed Rust source files"
        exit 0
    fi

    local cov_json cov_log
    cov_json="$(mktemp)"
    cov_log="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '${cov_json}' '${cov_log}'" EXIT

    echo "[coverage-diff] running cargo llvm-cov --lib ..."
    if ! cargo llvm-cov --lib --json --output-path "${cov_json}" >"${cov_log}" 2>&1; then
        echo "[coverage-diff] cargo llvm-cov failed" >&2
        tail -n 50 "${cov_log}" >&2
        exit 1
    fi

    python3 - "${cov_json}" "${merge_base}" "${changed_files[*]}" <<'PY'
import json, subprocess, sys

cov_path = sys.argv[1]
merge_base = sys.argv[2]
changed_files = sys.argv[3].split()

with open(cov_path) as f:
    cov = json.load(f)

files_data = cov["data"][0]["files"]
cov_by_path = {entry["filename"]: entry["summary"]["lines"] for entry in files_data}

repo_root = subprocess.check_output(
    ["git", "rev-parse", "--show-toplevel"], text=True
).strip()

print(f"{'file':<60} {'lines':>8} {'covered':>8} {'percent':>8}")
print("-" * 88)

for rel in changed_files:
    abs_path = f"{repo_root}/{rel}"
    summary = cov_by_path.get(abs_path)
    if summary is None:
        print(f"{rel:<60} {'?':>8} {'?':>8} {'?':>8}")
        continue
    pct = summary["percent"]
    marker = ""
    if pct < 90.0:
        marker = "  < 90%"
    print(f"{rel:<60} {summary['count']:>8} {summary['covered']:>8} {pct:>7.1f}%{marker}")
PY
}

run_command() {
    local run_test=""
    local user_skip_tests="${DEFAULT_SKIP_TESTS}"
    local dry_run=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -C|--skip-crds) SKIP_CRDS=1; shift;;
            -p|--pull) shift;;
            -T|--run-test)
                if [[ $# -lt 2 ]]; then echo "ERROR: --run-test requires a value" >&2; exit 1; fi
                run_test="$2"; shift 2;;
            -s|--skip-tests)
                if [[ $# -lt 2 ]]; then echo "ERROR: --skip-tests requires a value" >&2; exit 1; fi
                user_skip_tests="$2"; shift 2;;
            -n|--dry-run) dry_run=1; shift;;
            -h|--help) usage; exit 0;;
            -*) echo "ERROR: unknown option $1" >&2; usage; exit 1;;
            *) echo "ERROR: unknown positional argument $1" >&2; usage; exit 1;;
        esac
    done

    SKIP_TESTS="${user_skip_tests}"
    RUN_TEST="${run_test}"

    GATEWAY_ADDR="$(resolve_gateway_addr)"
    export GATEWAY_ADDR

    if [[ "${dry_run}" -eq 1 ]]; then
        printf 'SKIP_CRDS=%s DOCKER_TAG=%s GATEWAY_ADDR=%s %s/run -skip-tests %q' \
            "${SKIP_CRDS}" "${DOCKER_TAG}" "${GATEWAY_ADDR}" "${SCRIPT_DIR}" "${SKIP_TESTS}"
        if [[ -n "${RUN_TEST}" ]]; then
            printf ' -run-test %q' "${RUN_TEST}"
        fi
        printf '\n'
        exit 0
    fi

    pull_image

    if [[ "${SKIP_CRDS}" != "1" ]]; then
        install_crds
    fi

    cleanup_leftovers
    deploy_proxy
    clone_upstream
    run_tests
    log "done; report at ${PROJECT_ROOT}/target/conformance-report.yaml"
}

if [[ $# -eq 0 ]]; then
    usage
    exit 1
fi

COMMAND="$1"
shift

case "${COMMAND}" in
    run)
        run_command "$@"
        ;;
    coverage-diff)
        coverage_diff_command "$@"
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: unknown command '${COMMAND}'" >&2
        usage
        exit 1
        ;;
esac
