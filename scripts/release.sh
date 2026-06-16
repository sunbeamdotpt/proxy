#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Release automation for sunbeam-proxy.
#
# Usage:
#   ./scripts/release.sh <version> [--dry-run] [--commit]
#
# Examples:
#   ./scripts/release.sh 0.2.0 --dry-run
#   ./scripts/release.sh 0.2.0
#   ./scripts/release.sh 0.2.0 --commit
#
# Without --commit the script updates Cargo.toml/Cargo.lock and CHANGELOG.md,
# runs checks, and builds a release binary, but does not commit or tag.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${PROJECT_ROOT}"

DRY_RUN=0
COMMIT=0

usage() {
    cat <<'EOF'
Usage: ./scripts/release.sh <version> [--dry-run] [--commit]

Options:
  --dry-run   Print the generated changelog and stop before mutating files.
  --commit    Commit the version/changelog changes and create an annotated tag.
EOF
}

log() {
    echo "[release] $*"
}

VERSION=""

for arg in "$@"; do
    case "$arg" in
        --dry-run)
            DRY_RUN=1
            ;;
        --commit)
            COMMIT=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $arg" >&2
            usage >&2
            exit 1
            ;;
        *)
            if [[ -n "${VERSION}" ]]; then
                echo "ERROR: only one version argument is allowed" >&2
                usage >&2
                exit 1
            fi
            VERSION="$arg"
            ;;
    esac
done

if [[ -z "${VERSION}" ]]; then
    usage >&2
    exit 1
fi

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    echo "ERROR: version must be a valid semver string (e.g. 0.2.0)" >&2
    exit 1
fi

CURRENT_VERSION="$(grep -E '^version\s*=' Cargo.toml | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')"
LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
LOG_RANGE="${LAST_TAG:+${LAST_TAG}..HEAD}"

log "Current version: ${CURRENT_VERSION}"
log "New version:     ${VERSION}"
log "Last tag:        ${LAST_TAG:-<none>}"

if [[ $DRY_RUN -eq 1 ]]; then
    log "Dry run: skipping file mutations"
fi

# ── Generate changelog section ───────────────────────────────────────────────

TMP_CHANGELOG="$(mktemp)"
trap 'rm -f "${TMP_CHANGELOG}"' EXIT

{
    echo "## [${VERSION}] - $(date -u +%Y-%m-%d)"
    echo ""

    declare -A LABELS=(
        [feat]="Features"
        [fix]="Bug Fixes"
        [perf]="Performance"
        [refactor]="Refactoring"
        [test]="Testing"
        [build]="Build & CI"
        [docs]="Documentation"
        [chore]="Chores"
        [style]="Styling"
        [revert]="Reverts"
    )

    for type in feat fix perf refactor test build docs chore style revert; do
        mapfile -t commits < <(git log "${LOG_RANGE:-HEAD}" --pretty=format:"%s" --no-merges | grep "^${type}" | awk '!seen[$0]++' || true)
        if [[ ${#commits[@]} -gt 0 && -n "${commits[0]}" ]]; then
            echo "### ${LABELS[$type]}"
            for c in "${commits[@]}"; do
                echo "- ${c}"
            done
            echo ""
        fi
    done

    # Catch anything that does not follow the conventional-commit prefix.
    mapfile -t other < <(git log "${LOG_RANGE:-HEAD}" --pretty=format:"%s" --no-merges | grep -vE '^(feat|fix|perf|refactor|test|build|docs|chore|style|revert)(\(|:)' | awk '!seen[$0]++' || true)
    if [[ ${#other[@]} -gt 0 && -n "${other[0]}" ]]; then
        echo "### Other"
        for c in "${other[@]}"; do
            echo "- ${c}"
        done
        echo ""
    fi
} > "${TMP_CHANGELOG}"

if [[ $DRY_RUN -eq 1 ]]; then
    log "Generated changelog section:"
    cat "${TMP_CHANGELOG}"
    exit 0
fi

# ── Mutate files ─────────────────────────────────────────────────────────────

log "Updating Cargo.toml version"
perl -pi -e "s/^version\s*=\s*\"[^\"]+\"/version = \"${VERSION}\"/" Cargo.toml

log "Updating Cargo.lock"
cargo update -p sunbeam-proxy >/dev/null

if [[ -f CHANGELOG.md ]]; then
    {
        echo "# Changelog"
        echo ""
        cat "${TMP_CHANGELOG}"
        # Drop the existing top-level "# Changelog" header if present.
        tail -n +3 CHANGELOG.md
    } > CHANGELOG.md.new
    mv CHANGELOG.md.new CHANGELOG.md
else
    {
        echo "# Changelog"
        echo ""
        cat "${TMP_CHANGELOG}"
    } > CHANGELOG.md
fi

log "Generated CHANGELOG.md section for ${VERSION}"

# ── Validation ───────────────────────────────────────────────────────────────

log "Running cargo fmt --check"
cargo fmt -- --check

log "Running cargo clippy"
cargo clippy -- -D warnings

log "Running cargo test"
cargo test

log "Building release binary"
cargo build --release

log "Release binary: target/release/sunbeam-proxy"

# ── Commit + tag ─────────────────────────────────────────────────────────────

if [[ $COMMIT -eq 1 ]]; then
    if [[ -n "$(git status --porcelain)" ]]; then
        git add Cargo.toml Cargo.lock CHANGELOG.md
        git commit -m "chore(release): prepare ${VERSION}"
        git tag -a "v${VERSION}" -m "Release ${VERSION}"
        log "Created commit and tag v${VERSION}"
    else
        log "No changes to commit"
    fi
else
    log "Skipping commit/tag. Run with --commit to create the release commit and tag."
fi
