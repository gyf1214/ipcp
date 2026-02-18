#!/usr/bin/env bash
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "podman not found" >&2
  exit 1
fi

scriptDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repoRoot="$(cd "$scriptDir/.." && pwd)"
imageTag="${IPCP_INTEGRATION_IMAGE:-ipcp-integration:local}"

if ! podman image exists "$imageTag"; then
  "$scriptDir/build_integration_container.sh"
fi

if ! podman run --rm --privileged --entrypoint /bin/bash "$imageTag" -lc "test -c /dev/net/tun"; then
  echo "podman cannot run privileged containers with /dev/net/tun access in this environment" >&2
  exit 1
fi

podman run --rm \
  --privileged \
  --device /dev/net/tun:/dev/net/tun \
  -v "$repoRoot:/work" \
  -w /work \
  "$imageTag" \
  bash -lc "make integration-test"
