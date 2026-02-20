#!/usr/bin/env bash
set -euo pipefail

tmpDir=""
serverNs="ipcpd_srv_multi_$$"
clientNsA="ipcpd_clia_multi_$$"
clientNsB="ipcpd_clib_multi_$$"
clientNsC="ipcpd_clic_multi_$$"
serverVethA="veth_srv_a_$$"
clientVethA="veth_cli_a_$$"
serverVethB="veth_srv_b_$$"
clientVethB="veth_cli_b_$$"
serverVethC="veth_srv_c_$$"
clientVethC="veth_cli_c_$$"
serverPid=""
clientPidA=""
clientPidB=""
clientPidC=""

ns_path() {
  local ns="$1"
  echo "/run/netns/$ns"
}

ns_exec() {
  local ns="$1"
  shift
  nsenter --net="$(ns_path "$ns")" -- "$@"
}

kill_wait() {
  local pid="$1"
  if [[ -n "$pid" ]]; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

is_running() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 1
  fi
  kill -0 "$pid" >/dev/null 2>&1
}

assert_clients_running_for() {
  local seconds="$1"
  local pidA="$2"
  local pidB="$3"
  local logA="$4"
  local logB="$5"
  local logC="$6"
  local until=$((SECONDS + seconds))

  while (( SECONDS < until )); do
    if ! is_running "$pidA" || ! is_running "$pidB"; then
      echo "expected both client processes to remain connected" >&2
      dump_logs "$serverLog" "$logA" "$logB" "$logC"
      exit 1
    fi
    sleep 1
  done
}

dump_logs() {
  local serverLog="$1"
  local clientLogA="$2"
  local clientLogB="$3"
  local clientLogC="$4"
  if [[ -f "$serverLog" ]]; then
    echo "--- server log ---" >&2
    cat "$serverLog" >&2 || true
  fi
  if [[ -f "$clientLogA" ]]; then
    echo "--- client A log ---" >&2
    cat "$clientLogA" >&2 || true
  fi
  if [[ -f "$clientLogB" ]]; then
    echo "--- client B log ---" >&2
    cat "$clientLogB" >&2 || true
  fi
  if [[ -f "$clientLogC" ]]; then
    echo "--- client C log ---" >&2
    cat "$clientLogC" >&2 || true
  fi
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

cleanup() {
  local status="$1"
  set +e

  kill_wait "$clientPidC"
  kill_wait "$clientPidB"
  kill_wait "$clientPidA"
  kill_wait "$serverPid"

  ip netns del "$clientNsC" >/dev/null 2>&1 || true
  ip netns del "$clientNsB" >/dev/null 2>&1 || true
  ip netns del "$clientNsA" >/dev/null 2>&1 || true
  ip netns del "$serverNs" >/dev/null 2>&1 || true

  if [[ -n "$tmpDir" ]]; then
    rm -rf "$tmpDir"
  fi

  exit "$status"
}

trap 'cleanup $?' EXIT

if [[ ! -x ./daemon/target/ipcpd ]]; then
  echo "missing daemon binary: ./daemon/target/ipcpd" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "missing /dev/net/tun" >&2
  exit 1
fi

for cmd in ip nsenter timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd" >&2
    exit 1
  fi
done

tmpDir="$(mktemp -d)"
serverLog="$tmpDir/server.log"
clientLogA="$tmpDir/client_a.log"
clientLogB="$tmpDir/client_b.log"
clientLogC="$tmpDir/client_c.log"
keyFile="$tmpDir/secret.key"
serverConfig="$tmpDir/server.json"
clientConfigA="$tmpDir/client_a.json"
clientConfigB="$tmpDir/client_b.json"
clientConfigC="$tmpDir/client_c.json"

head -c 32 /dev/urandom > "$keyFile"

cat > "$serverConfig" <<JSON
{
  "mode": "server",
  "if_name": "tun0",
  "if_mode": "tun",
  "listen_ip": "0.0.0.0",
  "listen_port": 46100,
  "auth_timeout_ms": 5000,
  "credentials": [
    { "tun_ip": "10.250.1.2", "key_file": "$keyFile" },
    { "tun_ip": "10.250.2.2", "key_file": "$keyFile" },
    { "tun_ip": "10.250.3.2", "key_file": "$keyFile" }
  ]
}
JSON

cat > "$clientConfigA" <<JSON
{
  "mode": "client",
  "if_name": "tun0",
  "if_mode": "tun",
  "tun_ip": "10.250.1.2",
  "server_ip": "10.210.1.1",
  "server_port": 46100,
  "key_file": "$keyFile"
}
JSON

cat > "$clientConfigB" <<JSON
{
  "mode": "client",
  "if_name": "tun0",
  "if_mode": "tun",
  "tun_ip": "10.250.2.2",
  "server_ip": "10.210.2.1",
  "server_port": 46100,
  "key_file": "$keyFile"
}
JSON

cat > "$clientConfigC" <<JSON
{
  "mode": "client",
  "if_name": "tun1",
  "if_mode": "tun",
  "tun_ip": "10.250.3.2",
  "server_ip": "10.210.3.1",
  "server_port": 46100,
  "key_file": "$keyFile"
}
JSON

ip netns add "$serverNs"
ip netns add "$clientNsA"
ip netns add "$clientNsB"
ip netns add "$clientNsC"

ip link add "$serverVethA" type veth peer name "$clientVethA"
ip link add "$serverVethB" type veth peer name "$clientVethB"
ip link add "$serverVethC" type veth peer name "$clientVethC"

ip link set "$serverVethA" netns "$serverNs"
ip link set "$clientVethA" netns "$clientNsA"
ip link set "$serverVethB" netns "$serverNs"
ip link set "$clientVethB" netns "$clientNsB"
ip link set "$serverVethC" netns "$serverNs"
ip link set "$clientVethC" netns "$clientNsC"

ns_exec "$serverNs" ip link set lo up
ns_exec "$clientNsA" ip link set lo up
ns_exec "$clientNsB" ip link set lo up
ns_exec "$clientNsC" ip link set lo up

ns_exec "$serverNs" ip addr add 10.210.1.1/24 dev "$serverVethA"
ns_exec "$clientNsA" ip addr add 10.210.1.2/24 dev "$clientVethA"
ns_exec "$serverNs" ip addr add 10.210.2.1/24 dev "$serverVethB"
ns_exec "$clientNsB" ip addr add 10.210.2.2/24 dev "$clientVethB"
ns_exec "$serverNs" ip addr add 10.210.3.1/24 dev "$serverVethC"
ns_exec "$clientNsC" ip addr add 10.210.3.2/24 dev "$clientVethC"

ns_exec "$serverNs" ip link set "$serverVethA" up
ns_exec "$clientNsA" ip link set "$clientVethA" up
ns_exec "$serverNs" ip link set "$serverVethB" up
ns_exec "$clientNsB" ip link set "$clientVethB" up
ns_exec "$serverNs" ip link set "$serverVethC" up
ns_exec "$clientNsC" ip link set "$clientVethC" up

ns_exec "$serverNs" ./daemon/target/ipcpd "$serverConfig" >"$serverLog" 2>&1 &
serverPid="$!"

sleep 1

ns_exec "$clientNsA" ./daemon/target/ipcpd "$clientConfigA" >"$clientLogA" 2>&1 &
clientPidA="$!"

sleep 1

ns_exec "$clientNsB" ./daemon/target/ipcpd "$clientConfigB" >"$clientLogB" 2>&1 &
clientPidB="$!"

wait_for_interface "$serverNs" tun0
if ! wait_for_interface "$clientNsA" tun0; then
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi
if ! wait_for_interface "$clientNsB" tun0; then
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi

sleep 16
assert_clients_running_for 8 "$clientPidA" "$clientPidB" "$clientLogA" "$clientLogB" "$clientLogC"
if [[ "$(grep -c 'connected with' "$serverLog" || true)" -lt 2 ]]; then
  echo "expected server to accept at least two clients" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi

assert_clients_running_for 8 "$clientPidA" "$clientPidB" "$clientLogA" "$clientLogB" "$clientLogC"

kill_wait "$clientPidA"
clientPidA=""
sleep 16
if ! is_running "$clientPidB"; then
  echo "expected remaining client to stay connected after peer disconnect" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi

ns_exec "$clientNsC" ./daemon/target/ipcpd "$clientConfigC" >"$clientLogC" 2>&1 &
clientPidC="$!"
if ! wait_for_interface "$clientNsC" tun1; then
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi
sleep 2
if ! is_running "$clientPidC"; then
  echo "expected replacement client to stay connected" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi
if [[ "$(grep -c 'connected with' "$serverLog" || true)" -lt 3 ]]; then
  echo "expected server to accept replacement client" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB" "$clientLogC"
  exit 1
fi

echo "ipcpd multi-session server integration test passed"
