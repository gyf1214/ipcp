#!/usr/bin/env bash
set -euo pipefail

tmpDir=""

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
}

ns_path() {
  local ns="$1"
  echo "/run/netns/$ns"
}

ns_exec() {
  local ns="$1"
  shift
  nsenter --net="$(ns_path "$ns")" -- "$@"
}

dump_logs() {
  local serverLog="$1"
  local clientLog="$2"
  if [[ -f "$serverLog" ]]; then
    echo "--- server log ---" >&2
    cat "$serverLog" >&2 || true
  fi
  if [[ -f "$clientLog" ]]; then
    echo "--- client log ---" >&2
    cat "$clientLog" >&2 || true
  fi
}

cleanup() {
  local status="$1"
  set +e

  if [[ -n "$tmpDir" ]]; then
    rm -rf "$tmpDir"
  fi

  exit "$status"
}

wait_for_interface() {
  local ns="$1"
  local ifName="$2"
  local deadline=$((SECONDS + 15))

  while (( SECONDS < deadline )); do
    if ns_exec "$ns" ip link show dev "$ifName" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  echo "timed out waiting for $ifName in namespace $ns" >&2
  return 1
}

run_case() {
  local ifMode="$1"
  local ifName="$2"
  local serverNs="ipcpd_srv_${ifMode}_$$"
  local clientNs="ipcpd_cli_${ifMode}_$$"
  local serverVeth="veth_srv_${ifMode}_$$"
  local clientVeth="veth_cli_${ifMode}_$$"
  local serverPid=""
  local clientPid=""
  local serverLog="$tmpDir/server_${ifMode}.log"
  local clientLog="$tmpDir/client_${ifMode}.log"
  local keyFile="$tmpDir/secret_${ifMode}.key"
  local serverConfig="$tmpDir/server_${ifMode}.json"
  local clientConfig="$tmpDir/client_${ifMode}.json"
  local result=0

  head -c 32 /dev/urandom > "$keyFile"

  cat > "$serverConfig" <<JSON
{
  "mode": "server",
  "if_name": "$ifName",
  "if_mode": "$ifMode",
  "listen_ip": "10.200.1.1",
  "listen_port": 46000,
  "key_file": "$keyFile"
}
JSON

  cat > "$clientConfig" <<JSON
{
  "mode": "client",
  "if_name": "$ifName",
  "if_mode": "$ifMode",
  "server_ip": "10.200.1.1",
  "server_port": 46000,
  "key_file": "$keyFile"
}
JSON

  ip netns add "$serverNs"
  ip netns add "$clientNs"

  ip link add "$serverVeth" type veth peer name "$clientVeth"
  ip link set "$serverVeth" netns "$serverNs"
  ip link set "$clientVeth" netns "$clientNs"

  ns_exec "$serverNs" ip link set lo up
  ns_exec "$clientNs" ip link set lo up

  ns_exec "$serverNs" ip addr add 10.200.1.1/24 dev "$serverVeth"
  ns_exec "$clientNs" ip addr add 10.200.1.2/24 dev "$clientVeth"
  ns_exec "$serverNs" ip link set "$serverVeth" up
  ns_exec "$clientNs" ip link set "$clientVeth" up

  ns_exec "$serverNs" ./daemon/target/ipcpd "$serverConfig" >"$serverLog" 2>&1 &
  serverPid="$!"

  sleep 1

  ns_exec "$clientNs" ./daemon/target/ipcpd "$clientConfig" >"$clientLog" 2>&1 &
  clientPid="$!"

  wait_for_interface "$serverNs" "$ifName"
  wait_for_interface "$clientNs" "$ifName"

  ns_exec "$serverNs" ip addr add 10.250.0.1/30 dev "$ifName"
  ns_exec "$clientNs" ip addr add 10.250.0.2/30 dev "$ifName"
  ns_exec "$serverNs" ip link set "$ifName" up
  ns_exec "$clientNs" ip link set "$ifName" up

  ns_exec "$clientNs" timeout 10 ping -c 3 -W 1 10.250.0.1 || result=$?

  if [[ -n "$clientPid" ]]; then
    kill "$clientPid" >/dev/null 2>&1 || true
    wait "$clientPid" >/dev/null 2>&1 || true
    clientPid=""
  fi
  if [[ -n "$serverPid" ]]; then
    kill "$serverPid" >/dev/null 2>&1 || true
    wait "$serverPid" >/dev/null 2>&1 || true
    serverPid=""
  fi

  ip netns del "$clientNs" >/dev/null 2>&1 || true
  ip netns del "$serverNs" >/dev/null 2>&1 || true

  if [[ "$result" -ne 0 ]]; then
    dump_logs "$serverLog" "$clientLog"
    return "$result"
  fi
}

trap 'cleanup $?' EXIT

require_cmd ip
require_cmd ping
require_cmd timeout
require_cmd nsenter

if [[ ! -c /dev/net/tun ]]; then
  echo "missing /dev/net/tun" >&2
  exit 1
fi
if [[ ! -x ./daemon/target/ipcpd ]]; then
  echo "missing daemon binary: ./daemon/target/ipcpd" >&2
  exit 1
fi

tmpDir="$(mktemp -d)"

run_case "tun" "tun0"
run_case "tap" "tap0"

echo "ipcpd direct integration test passed"
