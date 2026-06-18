#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Unified Gateway API conformance and coverage helper.
#
# Usage:
#   ./scripts/conformance.sh run [options]
#   ./scripts/conformance.sh coverage-diff [base-ref]
#
# Run options:
#   -B, --skip-build        Skip cargo build + container image build
#   -C, --skip-crds         Skip Gateway API CRD install/reinstall
#   -d, --debug             Build a debug binary instead of release
#   -p, --pull              Pull DOCKER_TAG from a registry instead of building locally
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
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"
GATEWAY_API_CHANNEL="${GATEWAY_API_CHANNEL:-experimental}"
PROJECT_VERSION="${PROJECT_VERSION:-$(grep -E '^version' "${PROJECT_ROOT}/Cargo.toml" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')}"
DOCKER_TAG="${DOCKER_TAG:-ghcr.io/sunbeamdotpt/proxy:v${PROJECT_VERSION}}"
# Mesh tests are unsupported and skipped by default. Use -s/--skip-tests to
# override or add additional skips.
DEFAULT_SKIP_TESTS="MeshBasic,MeshConsumerRoute,MeshFrontend,MeshFrontendHostname,MeshGRPCRouteWeight,MeshHTTPRoute303Redirect,MeshHTTPRoute307Redirect,MeshHTTPRoute308Redirect,MeshHTTPRouteBackendRequestHeaderModifier,MeshHTTPRouteMatching,MeshHTTPRouteNamedRule,MeshHTTPRouteQueryParamMatching,MeshHTTPRouteRedirectHostAndStatus,MeshHTTPRouteRedirectPath,MeshHTTPRouteRedirectPort,MeshHTTPRouteRequestHeaderModifier,MeshHTTPRouteRewritePath,MeshHTTPRouteSchemeRedirect,MeshHTTPRouteSimpleSameNamespace,MeshHTTPRouteWeight,MeshPorts,MeshTrafficSplit"
DEBUG_BUILD="${DEBUG_BUILD:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_CRDS="${SKIP_CRDS:-0}"
PULL_IMAGE="${PULL_IMAGE:-0}"

TAR_FILE="/tmp/sunbeam-proxy-conformance.tar"
REMOTE_TAR="/home/ubuntu/sunbeam-proxy-conformance.tar"
GATEWAY_API_DIR="${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}"
CONFORMANCE_BINARY="${CONFORMANCE_BINARY:-${PROJECT_ROOT}/target/gateway-api-${GATEWAY_API_VERSION}-conformance}"

STABLE_TAG="sunbeam-proxy:conformance"

export KUBECONFIG

usage() {
    cat <<'EOF'
Usage: ./scripts/conformance.sh <command> [options]

Commands:
  run [options]                     Run the Gateway API conformance suite
  coverage-diff [base-ref]          Print line coverage for changed Rust files

Run options:
  -B, --skip-build                  Skip cargo build + container image build
  -C, --skip-crds                   Skip Gateway API CRD install/reinstall
  -d, --debug                       Build a debug binary instead of release
  -p, --pull                        Pull DOCKER_TAG from a registry instead of building locally
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

resolve_docker_tag() {
    if [[ -n "${DOCKER_TAG}" ]]; then
        return
    fi
    DOCKER_TAG="ghcr.io/sunbeamdotpt/proxy:v${PROJECT_VERSION}"
}

build_image() {
    resolve_docker_tag
    log "using container runtime: ${CONTAINER_CMD}"
    log "using image: ${DOCKER_TAG}"

    if [[ "${PULL_IMAGE}" == "1" ]]; then
        log "pulling remote image ${DOCKER_TAG} locally"
        container_image_pull "${DOCKER_TAG}"
    else
        log "building container image ${DOCKER_TAG}"
        container_build -t "${DOCKER_TAG}" -t "${STABLE_TAG}" \
            -f "${PROJECT_ROOT}/Dockerfile" \
            "${PROJECT_ROOT}"
    fi

    log "saving image"
    container_image_save "${DOCKER_TAG}" -o "${TAR_FILE}"

    log "transferring image to ${MULTIPASS_VM}"
    multipass transfer "${TAR_FILE}" "${MULTIPASS_VM}:${REMOTE_TAR}"

    log "importing image into k3s"
    mp sudo k3s ctr images import "${REMOTE_TAR}"

    if [[ "${DOCKER_TAG}" != *"/"* ]]; then
        log "tagging imported image with docker.io/library prefix"
        mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${DOCKER_TAG}" || true
    fi

    log "tagging imported image with stable tag ${STABLE_TAG}"
    mp sudo k3s ctr images tag "${DOCKER_TAG}" "${STABLE_TAG}" || true
    if [[ "${DOCKER_TAG}" != *"/"* ]]; then
        mp sudo k3s ctr images tag "${DOCKER_TAG}" "docker.io/library/${STABLE_TAG}" || true
    fi
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

run_tests() {
    log "running conformance tests (all features; mesh tests skipped by default)"
    local -a args=()
    if [[ -n "${SKIP_TESTS:-}" ]]; then
        args+=(-skip-tests "${SKIP_TESTS}")
    fi
    if [[ -n "${RUN_TEST:-}" ]]; then
        args+=(-run-test "${RUN_TEST}")
    fi

    local output_log="${PROJECT_ROOT}/target/conformance-output.log"
    local detailed_report="${PROJECT_ROOT}/target/conformance-report-detailed.yaml"

    cd "${GATEWAY_API_DIR}/conformance"
    if [[ -n "${CONFORMANCE_BINARY:-}" && -x "${CONFORMANCE_BINARY}" ]]; then
        # shellcheck disable=SC2048
        "${CONFORMANCE_BINARY}" -test.v \
            -gateway-class sunbeam \
            -all-features \
            -usable-address "${GATEWAY_ADDR}" \
            -unusable-address "240.0.0.1" \
            -organization "Sunbeam Studios" \
            -project "sunbeam-proxy" \
            -url "https://github.com/sunbeamdotpt/proxy" \
            -version "v${PROJECT_VERSION}" \
            -contact "hello@sunbeam.pt" \
            -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
            -cleanup-base-resources=false \
            "${args[@]}" 2>&1 | tee "${output_log}"
    else
        # shellcheck disable=SC2048
        go test . -v \
            -gateway-class sunbeam \
            -all-features \
            -usable-address "${GATEWAY_ADDR}" \
            -unusable-address "240.0.0.1" \
            -organization "Sunbeam Studios" \
            -project "sunbeam-proxy" \
            -url "https://github.com/sunbeamdotpt/proxy" \
            -version "v${PROJECT_VERSION}" \
            -contact "hello@sunbeam.pt" \
            -report-output "${PROJECT_ROOT}/target/conformance-report.yaml" \
            -cleanup-base-resources=false \
            "${args[@]}" 2>&1 | tee "${output_log}"
    fi

    generate_detailed_report "${output_log}" "${detailed_report}"
}

generate_detailed_report() {
    local log_file="$1"
    local report_file="$2"

    python3 - "${log_file}" "${report_file}" "${GATEWAY_API_VERSION}" "${PROJECT_VERSION}" <<'PY'
import re
import sys
from datetime import datetime, timezone

log_file, report_file, gw_version, project_version = sys.argv[1:5]

status_re = re.compile(r'^\s*--- (PASS|FAIL|SKIP):\s+(.+?)\s*(?:\(([^)]+)\))?\s*$')

records = []
with open(log_file) as f:
    for line in f:
        line = line.rstrip('\n')
        m = status_re.match(line)
        if not m:
            continue
        raw_status, name, duration = m.groups()
        status = {'PASS': 'passed', 'FAIL': 'failed', 'SKIP': 'skipped'}.get(raw_status, raw_status.lower())
        records.append({
            'name': name,
            'status': status,
            'duration': duration or '',
        })

summary = {'passed': 0, 'failed': 0, 'skipped': 0}
for r in records:
    if r['status'] == 'passed':
        summary['passed'] += 1
    elif r['status'] == 'failed':
        summary['failed'] += 1
    elif r['status'] == 'skipped':
        summary['skipped'] += 1
summary['total'] = len(records)

def esc(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')

with open(report_file, 'w') as out:
    out.write('apiVersion: gateway.networking.k8s.io/v1\n')
    out.write(f'kind: DetailedConformanceReport\n')
    out.write(f'date: "{datetime.now(timezone.utc).isoformat()}"\n')
    out.write(f'gatewayAPIVersion: {gw_version}\n')
    out.write('implementation:\n')
    out.write('  organization: Sunbeam Studios\n')
    out.write('  project: sunbeam-proxy\n')
    out.write('  url: https://sunbeam.pt\n')
    out.write(f'  version: v{project_version}\n')
    out.write(f'  contact: "hello@sunbeam.pt"\n')
    out.write(f'supportedFeatures: "all"\n')
    out.write('summary:\n')
    out.write(f'  total: {summary["total"]}\n')
    out.write(f'  passed: {summary["passed"]}\n')
    out.write(f'  failed: {summary["failed"]}\n')
    out.write(f'  skipped: {summary["skipped"]}\n')
    out.write('tests:\n')
    for r in records:
        out.write(f'  - name: {r["name"]}\n')
        out.write(f'    status: {r["status"]}\n')
        if r['duration']:
            out.write(f'    duration: {r["duration"]}\n')
PY
}

run_command() {
    local run_test=""
    local user_skip_tests="${DEFAULT_SKIP_TESTS}"
    local dry_run=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -B|--skip-build) SKIP_BUILD=1; shift;;
            -C|--skip-crds) SKIP_CRDS=1; shift;;
            -d|--debug) DEBUG_BUILD=1; shift;;
            -p|--pull) PULL_IMAGE=1; shift;;
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

    if [[ "${dry_run}" -eq 1 ]]; then
        echo "SKIP_BUILD=${SKIP_BUILD} SKIP_CRDS=${SKIP_CRDS} DEBUG_BUILD=${DEBUG_BUILD} PULL_IMAGE=${PULL_IMAGE} \\"
        echo "  ${SCRIPT_DIR}/conformance.sh run \\"
        echo "    -skip-tests '${SKIP_TESTS}' \\"
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
