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

run_expect_invalid_config() {
  local cfg="$1"
  local rc=0
  local errFile="$tmpDir/stderr.log"
  set +e
  ./daemon/target/ipcpd "$cfg" >/dev/null 2>"$errFile"
  rc=$?
  set -e
  if [[ "$rc" -ne 1 ]]; then
    echo "expected exit code 1, got $rc for $cfg" >&2
    exit 1
  fi
  if ! grep -Fq "invalid config file" "$errFile"; then
    echo "expected 'invalid config file' on stderr for $cfg" >&2
    cat "$errFile" >&2
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

cat > "$tmpDir/bad-heartbeat-relationship.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "key_file": "/tmp/none.key",
  "heartbeat_interval_ms": 5000,
  "heartbeat_timeout_ms": 5000
}
JSON

run_expect_invalid_config "$tmpDir/missing-field.json"
run_expect_invalid_config "$tmpDir/bad-port-type.json"
run_expect_invalid_config "$tmpDir/bad-mode.json"
run_expect_invalid_config "$tmpDir/bad-heartbeat-relationship.json"

echo "ipcpd config validation integration test passed"
