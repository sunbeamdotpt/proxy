#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Cross-platform image package script.
# On macOS this uses the native `container` CLI; on Linux it uses Docker buildx.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=container-runtime.sh
source "${SCRIPT_DIR}/container-runtime.sh"

TAG="${1:-src.${SUNBEAM_REGISTRY:-sunbeam.local}/studio/proxy:latest}"

if [[ "${CONTAINER_CMD}" == "container" ]]; then
    # `container` builds images natively for the host platform (linux/arm64 on Apple Silicon).
    # Multi-arch manifest lists are not yet supported, so we build and push a single-platform image.
    container build -t "${TAG}" .
    container image push "${TAG}"
else
    docker buildx build --push -t "${TAG}" .
fi
