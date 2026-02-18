#!/usr/bin/env bash
set -euo pipefail

serverNs="ipcpd_srv_$$"
clientNs="ipcpd_cli_$$"
serverVeth="veth_srv_$$"
clientVeth="veth_cli_$$"
serverPid=""
clientPid=""
tmpDir=""
serverLog=""
clientLog=""
keyFile=""

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

  if [[ -n "$clientPid" ]]; then
    kill "$clientPid" >/dev/null 2>&1 || true
    wait "$clientPid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$serverPid" ]]; then
    kill "$serverPid" >/dev/null 2>&1 || true
    wait "$serverPid" >/dev/null 2>&1 || true
  fi

  ip netns del "$clientNs" >/dev/null 2>&1 || true
  ip netns del "$serverNs" >/dev/null 2>&1 || true

  if [[ "$status" -ne 0 ]]; then
    dump_logs
  fi

  if [[ -n "$tmpDir" ]]; then
    rm -rf "$tmpDir"
  fi

  exit "$status"
}

wait_for_tun() {
  local ns="$1"
  local deadline=$((SECONDS + 15))

  while (( SECONDS < deadline )); do
    if ns_exec "$ns" ip link show dev tun0 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  echo "timed out waiting for tun0 in namespace $ns" >&2
  return 1
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
serverLog="$tmpDir/server.log"
clientLog="$tmpDir/client.log"
keyFile="$tmpDir/secret.key"
head -c 32 /dev/urandom > "$keyFile"

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

ns_exec "$serverNs" ./daemon/target/ipcpd tun0 10.200.1.1 46000 1 "$keyFile" >"$serverLog" 2>&1 &
serverPid="$!"

sleep 1

ns_exec "$clientNs" ./daemon/target/ipcpd tun0 10.200.1.1 46000 0 "$keyFile" >"$clientLog" 2>&1 &
clientPid="$!"

wait_for_tun "$serverNs"
wait_for_tun "$clientNs"

ns_exec "$serverNs" ip addr add 10.250.0.1/30 dev tun0
ns_exec "$clientNs" ip addr add 10.250.0.2/30 dev tun0
ns_exec "$serverNs" ip link set tun0 up
ns_exec "$clientNs" ip link set tun0 up

ns_exec "$clientNs" timeout 10 ping -c 3 -W 1 10.250.0.1

echo "ipcpd direct integration test passed"
