#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Repeatability check for the Gateway API conformance runner.
#
# Runs the focused conformance suite twice in a row against the same cluster.
# A non-zero exit code from either run fails the check.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="${SCRIPT_DIR}/run.sh"

# Focus on a small, representative set of tests so this check finishes quickly.
FOCUS='TestConformance/HTTPRouteCrossNamespace|TestConformance/HTTPRouteHostnameIntersection'

run() {
    local n="$1"
    echo "[idempotent] conformance run ${n}"
    "${RUNNER}" -run "${FOCUS}"
}

run 1
run 2

echo "[idempotent] both runs succeeded"
