#!/usr/bin/env bash
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "podman not found" >&2
  exit 1
fi

scriptDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repoRoot="$(cd "$scriptDir/.." && pwd)"
imageTag="${IPCP_INTEGRATION_IMAGE:-ipcp-integration:local}"

podman build -t "$imageTag" -f "$repoRoot/Dockerfile" "$repoRoot"
