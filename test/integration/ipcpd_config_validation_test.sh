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

run_expect_invalid_secret() {
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
  if ! grep -Fq "invalid secret file" "$errFile"; then
    echo "expected 'invalid secret file' on stderr for $cfg" >&2
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

cat > "$tmpDir/bad-if-mode-value.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "l2",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "key_file": "/tmp/none.key"
}
JSON

cat > "$tmpDir/bad-if-mode-type.json" <<JSON
{
  "mode": "client",
  "if_name": "tun0",
  "if_mode": 123,
  "server_ip": "127.0.0.1",
  "server_port": 46000,
  "key_file": "/tmp/none.key"
}
JSON

cat > "$tmpDir/missing-if-mode-defaults-to-tun.json" <<JSON
{
  "mode": "client",
  "if_name": "tun0",
  "tun_ip": "10.10.0.2",
  "server_ip": "127.0.0.1",
  "server_port": 46000,
  "key_file": "/tmp/nonexistent.key"
}
JSON

cat > "$tmpDir/server-old-key-file-only-hard-break.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "tun",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "key_file": "/tmp/none.key",
  "auth_timeout_ms": 5000
}
JSON

cat > "$tmpDir/server-missing-auth-timeout.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "tun",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "credentials": [
    { "tun_ip": "10.0.0.2", "key_file": "/tmp/none.key" }
  ]
}
JSON

cat > "$tmpDir/server-bad-auth-timeout.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "tap",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "auth_timeout_ms": 0,
  "credentials": [
    { "tap_mac": "02:11:22:33:44:55", "key_file": "/tmp/none.key" }
  ]
}
JSON

cat > "$tmpDir/server-tun-credentials-missing-ip.json" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "tun",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "auth_timeout_ms": 5000,
  "credentials": [
    { "tap_mac": "02:11:22:33:44:55", "key_file": "/tmp/none.key" }
  ]
}
JSON

cat > "$tmpDir/server-tap-credentials-missing-mac.json" <<JSON
{
  "mode": "server",
  "if_name": "tap0",
  "if_mode": "tap",
  "listen_ip": "0.0.0.0",
  "listen_port": 46000,
  "auth_timeout_ms": 5000,
  "credentials": [
    { "tun_ip": "10.0.0.2", "key_file": "/tmp/none.key" }
  ]
}
JSON

run_expect_invalid_config "$tmpDir/missing-field.json"
run_expect_invalid_config "$tmpDir/bad-port-type.json"
run_expect_invalid_config "$tmpDir/bad-mode.json"
run_expect_invalid_config "$tmpDir/bad-heartbeat-relationship.json"
run_expect_invalid_config "$tmpDir/bad-if-mode-value.json"
run_expect_invalid_config "$tmpDir/bad-if-mode-type.json"
run_expect_invalid_config "$tmpDir/server-old-key-file-only-hard-break.json"
run_expect_invalid_config "$tmpDir/server-missing-auth-timeout.json"
run_expect_invalid_config "$tmpDir/server-bad-auth-timeout.json"
run_expect_invalid_config "$tmpDir/server-tun-credentials-missing-ip.json"
run_expect_invalid_config "$tmpDir/server-tap-credentials-missing-mac.json"
run_expect_invalid_secret "$tmpDir/missing-if-mode-defaults-to-tun.json"

echo "ipcpd config validation integration test passed"
