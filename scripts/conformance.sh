#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Unified Gateway API conformance and coverage helper.
#
# Usage:
#   ./scripts/conformance.sh run [options] [test1 test2 ...]
#   ./scripts/conformance.sh coverage-diff [base-ref]
#
# Run options:
#   -B, --skip-build        Skip cargo build + container image build
#   -C, --skip-crds         Skip Gateway API CRD install/reinstall
#   -d, --debug             Build a debug binary instead of release
#   -t, --target-set        Run the current feature target set
#   -T, --run-test <name>   Run a single upstream conformance test
#   -s, --skip-tests <list> Comma-separated list of tests to skip
#   -n, --dry-run           Print the computed command and exit
#   -h, --help              Show help

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
SUPPORTED_FEATURES="${SUPPORTED_FEATURES:-Gateway,HTTPRoute,GRPCRoute,ReferenceGrant,BackendTLSPolicy,GatewayPort8080,GatewayHTTPListenerIsolation,ListenerSet,TCPRoute,UDPRoute,TLSRoute,TLSRouteModeTerminate,TLSRouteModeMixed,HTTPRouteMethodMatching,HTTPRouteQueryParamMatching,HTTPRouteResponseHeaderModification,HTTPRouteBackendRequestHeaderModification,HTTPRoutePortRedirect,HTTPRouteSchemeRedirect,HTTPRoutePathRedirect,HTTPRoutePathRewrite,HTTPRouteHostRewrite,HTTPRouteCORS,HTTPRouteRequestMirror,HTTPRouteRequestMultipleMirrors,HTTPRouteRequestPercentageMirror,HTTPRouteRequestTimeout,HTTPRouteBackendTimeout,HTTPRouteBackendProtocolH2C,HTTPRouteBackendProtocolWebSocket,HTTPRoute303RedirectStatusCode,HTTPRoute307RedirectStatusCode,HTTPRoute308RedirectStatusCode,HTTPRouteParentRefPort,HTTPRouteDestinationPortMatching,HTTPRouteNamedRouteRule,GatewayStaticAddresses,GatewayAddressEmpty,GatewayInfrastructurePropagation,GatewayBackendClientCertificate,GatewayFrontendClientCertificateValidation,GatewayFrontendClientCertificateValidationInsecureFallback,GatewayInvalidFrontendClientCertificateValidation,GatewayFrontendInvalidDefaultClientCertificateValidation,GatewayInvalidTLSBackendConfiguration,GatewayHTTPSListenerDetectMisdirectedRequests,GRPCExactMethodMatching,GRPCRouteHeaderMatching,GRPCRouteListenerHostnameMatching,GRPCRouteNamedRouteRule,GRPCRouteWeight}"
DEBUG_BUILD="${DEBUG_BUILD:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_CRDS="${SKIP_CRDS:-0}"

TAR_FILE="/tmp/sunbeam-proxy-conformance.tar"
REMOTE_TAR="/home/ubuntu/sunbeam-proxy-conformance.tar"
GATEWAY_API_DIR="${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}"
CONFORMANCE_BINARY="${CONFORMANCE_BINARY:-${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}-conformance}"

STABLE_TAG="sunbeam-proxy:conformance"

DEFAULT_TARGET_TESTS=(
    BackendTLSPolicy
    BackendTLSPolicyConflictResolution
    BackendTLSPolicyInvalidCACertificateRef
    BackendTLSPolicyInvalidKind
    BackendTLSPolicyObservedGenerationBump
    BackendTLSPolicySANValidation
    GatewayInfrastructure
    GatewayOptionalAddressValue
    GatewayStaticAddresses
    GatewayFrontendClientCertificateValidation
    GatewayFrontendClientCertificateValidationInsecureFallback
    GatewayInvalidFrontendClientCertificateValidation
    GatewayFrontendInvalidDefaultClientCertificateValidation
    GatewayBackendClientCertificateFeature
    GatewayInvalidTLSBackendConfiguration
    GRPCExactMethodMatching
    GRPCRouteHeaderMatching
    GRPCRouteListenerHostnameMatching
    GRPCRouteNamedRule
    GRPCRouteWeight
    HTTPRouteHTTPSListenerDetectMisdirectedRequests
    HTTPRouteInvalidParentRefNotMatchingListenerPort
    HTTPRouteInvalidParentRefSectionNameNotMatchingPort
    HTTPRouteListenerPortMatching
    HTTPRouteNamedRule
)

export KUBECONFIG

usage() {
    cat <<'EOF'
Usage: ./scripts/conformance.sh <command> [options]

Commands:
  run [options] [test1 test2 ...]   Run the Gateway API conformance suite
  coverage-diff [base-ref]          Print line coverage for changed Rust files

Run options:
  -B, --skip-build                  Skip cargo build + container image build
  -C, --skip-crds                   Skip Gateway API CRD install/reinstall
  -d, --debug                       Build a debug binary instead of release
  -t, --target-set                  Run the current feature target set
  -T, --run-test <name>             Run a single upstream conformance test
  -s, --skip-tests <list>           Comma-separated list of tests to skip
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

resolve_docker_tag() {
    if [[ -n "${DOCKER_TAG}" ]]; then
        return
    fi
    if [[ "${SKIP_BUILD}" == "1" ]]; then
        DOCKER_TAG="${STABLE_TAG}"
        return
    fi
    local commit_short
    commit_short="$(cd "${PROJECT_ROOT}" && git rev-parse --short HEAD)"
    if [[ -n "$(cd "${PROJECT_ROOT}" && git status --porcelain)" ]]; then
        DOCKER_TAG="sunbeam-proxy:conformance-${commit_short}-dirty-$(date +%s)"
    else
        DOCKER_TAG="sunbeam-proxy:conformance-${commit_short}"
    fi
}

build_image() {
    resolve_docker_tag
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

    log "tagging imported image with docker.io/library prefix"
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${DOCKER_TAG}" || true

    log "tagging imported image with stable tag ${STABLE_TAG}"
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "${STABLE_TAG}" || true
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${STABLE_TAG}" || true
}

install_crds() {
    log "installing Gateway API CRDs (${GATEWAY_API_VERSION} ${GATEWAY_API_CHANNEL})"
    kubectl_cmd delete validatingadmissionpolicybinding safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
    kubectl_cmd delete validatingadmissionpolicy safe-upgrades.gateway.networking.k8s.io --ignore-not-found=true >/dev/null 2>&1 || true
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

ensure_no_hostpath_binary() {
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

build_conformance_binary() {
    if [[ -z "${CONFORMANCE_BINARY}" ]]; then
        log "CONFORMANCE_BINARY unset, will run via go test"
        return
    fi
    if [[ -x "${CONFORMANCE_BINARY}" && "${CONFORMANCE_BINARY}" -nt "${GATEWAY_API_DIR}/conformance/go.mod" ]]; then
        log "reusing conformance binary ${CONFORMANCE_BINARY}"
        return
    fi
    log "building conformance binary ${CONFORMANCE_BINARY}"
    (
        cd "${GATEWAY_API_DIR}/conformance"
        go test -c -o "${CONFORMANCE_BINARY}" .
    )
}

compute_target_skip_tests() {
    local -n targets="$1"
    local upstream_dir="${GATEWAY_API_DIR}/conformance"
    if [[ ! -d "${upstream_dir}" ]]; then
        echo "ERROR: upstream conformance suite not found at ${upstream_dir}" >&2
        exit 1
    fi
    mapfile -t all_tests < <(
        grep -Rh 'ShortName:' "${upstream_dir}/tests" \
            | sed -E 's/.*ShortName:[[:space:]]*"([^"]+)".*/\1/' \
            | sort -u
    )
    local -a skip=()
    for t in "${all_tests[@]}"; do
        local found=0
        for target in "${targets[@]}"; do
            if [[ "${t}" == "${target}" ]]; then
                found=1
                break
            fi
        done
        if [[ "${found}" -eq 0 ]]; then
            skip+=("${t}")
        fi
    done
    if [[ ${#skip[@]} -gt 0 ]]; then
        echo "$(IFS=,; echo "${skip[*]}")"
    fi
}

run_tests() {
    log "running conformance tests with features: ${SUPPORTED_FEATURES}"
    local -a args=()
    if [[ -n "${SKIP_TESTS:-}" ]]; then
        args+=(-skip-tests "${SKIP_TESTS}")
    fi
    if [[ -n "${RUN_TEST:-}" ]]; then
        args+=(-run-test "${RUN_TEST}")
    fi

    cd "${GATEWAY_API_DIR}/conformance"
    if [[ -n "${CONFORMANCE_BINARY:-}" && -x "${CONFORMANCE_BINARY}" ]]; then
        # shellcheck disable=SC2048
        "${CONFORMANCE_BINARY}" -test.v \
            -gateway-class sunbeam \
            -supported-features "${SUPPORTED_FEATURES}" \
            -usable-address "${GATEWAY_ADDR}" \
            -unusable-address "240.0.0.1" \
            -organization "Sunbeam" \
            -project "sunbeam-proxy" \
            -url "https://sunbeam.sh" \
            -version "v0.1.0" \
            -contact "conformance@sunbeam.sh" \
            -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
            -cleanup-base-resources=false \
            "${args[@]}"
    else
        # shellcheck disable=SC2048
        go test . -v \
            -gateway-class sunbeam \
            -supported-features "${SUPPORTED_FEATURES}" \
            -usable-address "${GATEWAY_ADDR}" \
            -unusable-address "240.0.0.1" \
            -organization "Sunbeam" \
            -project "sunbeam-proxy" \
            -url "https://sunbeam.sh" \
            -version "v0.1.0" \
            -contact "conformance@sunbeam.sh" \
            -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
            -cleanup-base-resources=false \
            "${args[@]}"
    fi
}

run_command() {
    local -a target_tests=()
    local target_set=0
    local run_test=""
    local user_skip_tests=""
    local dry_run=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -B|--skip-build) SKIP_BUILD=1; shift;;
            -C|--skip-crds) SKIP_CRDS=1; shift;;
            -d|--debug) DEBUG_BUILD=1; shift;;
            -t|--target-set) target_set=1; shift;;
            -T|--run-test)
                if [[ $# -lt 2 ]]; then echo "ERROR: --run-test requires a value" >&2; exit 1; fi
                run_test="$2"; shift 2;;
            -s|--skip-tests)
                if [[ $# -lt 2 ]]; then echo "ERROR: --skip-tests requires a value" >&2; exit 1; fi
                user_skip_tests="$2"; shift 2;;
            -n|--dry-run) dry_run=1; shift;;
            -h|--help) usage; exit 0;;
            --) shift; target_tests+=("$@"); break;;
            -*) echo "ERROR: unknown option $1" >&2; usage; exit 1;;
            *) target_tests+=("$1"); shift;;
        esac
    done

    if [[ ${#target_tests[@]} -eq 0 && "${target_set}" -eq 1 ]]; then
        target_tests=("${DEFAULT_TARGET_TESTS[@]}")
    fi

    SKIP_TESTS=""
    if [[ ${#target_tests[@]} -gt 0 ]]; then
        SKIP_TESTS="$(compute_target_skip_tests target_tests)"
    fi
    if [[ -n "${user_skip_tests}" ]]; then
        if [[ -n "${SKIP_TESTS}" ]]; then
            SKIP_TESTS="${SKIP_TESTS},${user_skip_tests}"
        else
            SKIP_TESTS="${user_skip_tests}"
        fi
    fi
    RUN_TEST="${run_test}"

    if [[ "${dry_run}" -eq 1 ]]; then
        echo "SKIP_BUILD=${SKIP_BUILD} SKIP_CRDS=${SKIP_CRDS} DEBUG_BUILD=${DEBUG_BUILD} \\"
        echo "  ${SCRIPT_DIR}/conformance.sh run \\"
        if [[ -n "${SKIP_TESTS}" ]]; then
            echo "    -skip-tests '${SKIP_TESTS}' \\"
        fi
        if [[ -n "${RUN_TEST}" ]]; then
            echo "    -run-test '${RUN_TEST}'"
        fi
        exit 0
    fi

    if [[ "${SKIP_BUILD}" != "1" ]]; then
        build_image
    else
        resolve_docker_tag
        log "SKIP_BUILD=1, reusing existing image"
    fi

    if [[ "${SKIP_CRDS}" != "1" ]]; then
        install_crds
    else
        log "SKIP_CRDS=1, skipping CRD install"
    fi

    cleanup_leftovers
    deploy_proxy
    clone_upstream
    build_conformance_binary
    run_tests
    log "done; report at ${PROJECT_ROOT}/target/conformance-report.yaml"
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
