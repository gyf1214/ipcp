#!/usr/bin/env bash
set -euo pipefail

tmpDir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmpDir"
}

trap cleanup EXIT

if [[ ! -x ./daemon/target/ipcpd ]]; then
  echo "missing daemon binary: ./daemon/target/ipcpd" >&2
  exit 1
fi

run_expect_exit_1() {
  local cfg="$1"
  local rc=0
  set +e
  ./daemon/target/ipcpd "$cfg" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "expected exit code 1, got $rc for $cfg" >&2
    exit 1
  fi
}

cat > "$tmpDir/missing-field.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000
}
JSON

cat > "$tmpDir/bad-port-type.json" <<JSON
{
  "mode": "client",
  "if_name": "tun0",
  "server_ip": "127.0.0.1",
  "server_port": "46000",
  "key_file": "/tmp/none.key"
}
JSON

cat > "$tmpDir/bad-mode.json" <<JSON
{
  "mode": "server2",
  "if_name": "tun0",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "key_file": "/tmp/none.key"
}
JSON

run_expect_exit_1 "$tmpDir/missing-field.json"
run_expect_exit_1 "$tmpDir/bad-port-type.json"
run_expect_exit_1 "$tmpDir/bad-mode.json"

echo "ipcpd config validation integration test passed"
