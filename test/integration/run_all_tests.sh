#!/usr/bin/env bash
set -euo pipefail

scriptDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! compgen -G "$scriptDir/*_test.sh" >/dev/null; then
  echo "no integration test scripts found in $scriptDir" >&2
  exit 1
fi

for testScript in $(printf '%s\n' "$scriptDir"/*_test.sh | sort); do
  echo "running $(basename "$testScript")"
  bash "$testScript"
done

echo "all integration tests passed"
