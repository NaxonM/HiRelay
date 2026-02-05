#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/relayctl.sh"

echo "relayctl_remote.sh is deprecated. Use relayctl.sh instead." >&2
if [[ ! -f "${TARGET}" ]]; then
    echo "relayctl.sh not found at ${TARGET}" >&2
    exit 1
fi

exec "${TARGET}" "$@"
