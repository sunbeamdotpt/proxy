#!/usr/bin/env bash
# Copyright Sunbeam Studios 2026
# SPDX-License-Identifier: AGPL-3.0-or-later

# Select the local container CLI.
# On macOS we use the native `container` tool (https://github.com/olumide-ng/container)
# when available; everywhere else we fall back to Docker.

set -euo pipefail

if [[ "${CONTAINER_RUNTIME:-}" != "" ]]; then
    CONTAINER_CMD="${CONTAINER_RUNTIME}"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    if command -v container >/dev/null 2>&1; then
        CONTAINER_CMD="container"
    else
        echo "ERROR: running on macOS but the native 'container' CLI was not found." >&2
        echo "Install it with: brew install container" >&2
        echo "Or set CONTAINER_RUNTIME=docker to use Docker instead." >&2
        exit 1
    fi
else
    CONTAINER_CMD="docker"
fi

container_build() {
    if [[ "${CONTAINER_CMD}" == "container" ]]; then
        container build "$@"
    else
        docker build "$@"
    fi
}

container_image_save() {
    if [[ "${CONTAINER_CMD}" == "container" ]]; then
        container image save "$@"
    else
        docker save "$@"
    fi
}

container_image_push() {
    if [[ "${CONTAINER_CMD}" == "container" ]]; then
        container image push "$@"
    else
        docker push "$@"
    fi
}

container_image_pull() {
    if [[ "${CONTAINER_CMD}" == "container" ]]; then
        container image pull "$@"
    else
        docker pull "$@"
    fi
}

export CONTAINER_CMD
