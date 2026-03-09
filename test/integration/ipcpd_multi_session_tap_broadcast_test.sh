#!/usr/bin/env bash
set -euo pipefail

tmpDir=""
serverNs="ipcpd_srv_tap_multi_$$"
clientNsA="ipcpd_clia_tap_multi_$$"
clientNsB="ipcpd_clib_tap_multi_$$"
serverVethA="svta_$$"
clientVethA="cvta_$$"
serverVethB="svtb_$$"
clientVethB="cvtb_$$"
serverPid=""
clientPidA=""
clientPidB=""

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

dump_logs() {
  local serverLog="$1"
  local clientLogA="$2"
  local clientLogB="$3"
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

read_rx_packets() {
  local ns="$1"
  local ifName="$2"
  local deadline=$((SECONDS + 10))
  local value=""

  while (( SECONDS < deadline )); do
    if value="$(
      ns_exec "$ns" sh -lc "ip -s link show dev '$ifName' 2>/dev/null | awk '/RX:/{getline; print \$1; exit}'"
    )" && [[ -n "$value" ]]; then
      echo "$value"
      return 0
    fi
    sleep 0.2
  done

  return 1
}

cleanup() {
  local status="$1"
  set +e

  kill_wait "$clientPidB"
  kill_wait "$clientPidA"
  kill_wait "$serverPid"

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
keyFile="$tmpDir/secret.key"
serverConfig="$tmpDir/server.json"
clientConfigA="$tmpDir/client_a.json"
clientConfigB="$tmpDir/client_b.json"

head -c 32 /dev/urandom > "$keyFile"

cat > "$serverConfig" <<JSON
{
  "mode": "server",
  "if_name": "tap0",
  "if_mode": "tap",
  "listen_ip": "0.0.0.0",
  "listen_port": 46200,
  "auth_timeout_ms": 5000,
  "max_pre_auth_sessions": 8,
  "tap_mac": "02:11:22:33:44:01",
  "credentials": [
    { "tap_mac": "02:11:22:33:44:55", "key_file": "$keyFile" },
    { "tap_mac": "02:11:22:33:44:66", "key_file": "$keyFile" }
  ]
}
JSON

cat > "$clientConfigA" <<JSON
{
  "mode": "client",
  "if_name": "tap0",
  "if_mode": "tap",
  "tap_mac": "02:11:22:33:44:55",
  "server_ip": "10.220.1.1",
  "server_port": 46200,
  "key_file": "$keyFile"
}
JSON

cat > "$clientConfigB" <<JSON
{
  "mode": "client",
  "if_name": "tap0",
  "if_mode": "tap",
  "tap_mac": "02:11:22:33:44:66",
  "server_ip": "10.220.2.1",
  "server_port": 46200,
  "key_file": "$keyFile"
}
JSON

ip netns add "$serverNs"
ip netns add "$clientNsA"
ip netns add "$clientNsB"

ip link add "$serverVethA" type veth peer name "$clientVethA"
ip link add "$serverVethB" type veth peer name "$clientVethB"
ip link set "$serverVethA" netns "$serverNs"
ip link set "$clientVethA" netns "$clientNsA"
ip link set "$serverVethB" netns "$serverNs"
ip link set "$clientVethB" netns "$clientNsB"

ns_exec "$serverNs" ip link set lo up
ns_exec "$clientNsA" ip link set lo up
ns_exec "$clientNsB" ip link set lo up

ns_exec "$serverNs" ip addr add 10.220.1.1/24 dev "$serverVethA"
ns_exec "$clientNsA" ip addr add 10.220.1.2/24 dev "$clientVethA"
ns_exec "$serverNs" ip addr add 10.220.2.1/24 dev "$serverVethB"
ns_exec "$clientNsB" ip addr add 10.220.2.2/24 dev "$clientVethB"
ns_exec "$serverNs" ip link set "$serverVethA" up
ns_exec "$clientNsA" ip link set "$clientVethA" up
ns_exec "$serverNs" ip link set "$serverVethB" up
ns_exec "$clientNsB" ip link set "$clientVethB" up

ns_exec "$serverNs" ./daemon/target/ipcpd "$serverConfig" >"$serverLog" 2>&1 &
serverPid="$!"
sleep 1
ns_exec "$clientNsA" ./daemon/target/ipcpd "$clientConfigA" >"$clientLogA" 2>&1 &
clientPidA="$!"
sleep 1
ns_exec "$clientNsB" ./daemon/target/ipcpd "$clientConfigB" >"$clientLogB" 2>&1 &
clientPidB="$!"

if ! wait_for_interface "$serverNs" tap0 || ! wait_for_interface "$clientNsA" tap0 || ! wait_for_interface "$clientNsB" tap0; then
  echo "timed out waiting for tap interfaces" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB"
  exit 1
fi

ns_exec "$serverNs" ip addr add 10.251.0.1/24 dev tap0
ns_exec "$clientNsA" ip addr add 10.251.0.2/24 dev tap0
ns_exec "$clientNsB" ip addr add 10.251.0.3/24 dev tap0
ns_exec "$clientNsA" ip link set dev tap0 address 02:11:22:33:44:55
ns_exec "$clientNsB" ip link set dev tap0 address 02:11:22:33:44:66
ns_exec "$serverNs" ip link set tap0 up
ns_exec "$clientNsA" ip link set tap0 up
ns_exec "$clientNsB" ip link set tap0 up

rxA0="$(read_rx_packets "$clientNsA" tap0)"
rxB0="$(read_rx_packets "$clientNsB" tap0)"
ns_exec "$serverNs" timeout 8 ping -I tap0 -c 3 -W 1 10.251.0.200 >/dev/null 2>&1 || true
sleep 1
rxA1="$(read_rx_packets "$clientNsA" tap0)"
rxB1="$(read_rx_packets "$clientNsB" tap0)"

if [[ "$rxA1" -le "$rxA0" ]]; then
  echo "expected client A rx counter to increase from server tap broadcast ingress" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB"
  exit 1
fi
if [[ "$rxB1" -le "$rxB0" ]]; then
  echo "expected client B rx counter to increase from server tap broadcast ingress" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB"
  exit 1
fi
if ! ns_exec "$clientNsA" pidof ipcpd >/dev/null 2>&1 || ! ns_exec "$clientNsB" pidof ipcpd >/dev/null 2>&1; then
  echo "expected both tap clients to remain connected" >&2
  dump_logs "$serverLog" "$clientLogA" "$clientLogB"
  exit 1
fi

echo "ipcpd multi-session tap broadcast integration test passed"
