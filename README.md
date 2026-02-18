# ipcp

`ipcp` is an IP tunnel over TCP: a Linux TUN-to-TCP tunnel daemon with a small custom framing protocol, authenticated encryption, and heartbeat-based liveness checks.

## Features

- Linux TUN integration for IP-layer tunneling
- Client and server modes in the same daemon (`ipcpd`)
- Moves IP packets between TUN and a TCP connection
- Wraps traffic in protocol frames with typed messages
- Authenticated encryption on every frame (nonce + ciphertext + MAC)
- Heartbeat-based liveness detection (request/ack)

## Typical Uses

- VPN-style private link between two hosts over TCP
- NAT/firewall bypass where direct IP routing is not possible
- Reverse tunnel setups where an inside host dials out to expose internal connectivity
- General-purpose encrypted L3 transport over existing TCP reachability

## Build

This project assumes a Linux host.
If you prefer containerized builds, this repository includes a `Dockerfile`.

### Required tools and libraries

- `gcc` / C toolchain
- `make`
- `python3`
- Python package: `mkmake`
- `libsodium` headers and static library (`libsodium.a`)

Install `mkmake`:

```bash
python3 -m pip install --user mkmake
```

Example package hints:

- RHEL/CentOS/Alma/Rocky: `libsodium`, `libsodium-devel`, `libsodium-static`
- Debian/Ubuntu: `libsodium-dev` (verify static archive availability for your distro)

### Build commands

```bash
make all
make test
```

### Unit tests in container

Use this route when the host is missing local build/test prerequisites (for example `mkmake` setup):

```bash
podman build -t ipcp-dev:local -f Dockerfile .
podman run --rm -v "$PWD:/work" -w /work ipcp-dev:local bash -lc "make test"
```

## Integration Test

Single-session end-to-end integration is available through a direct `ipcpd` test harness.

Native route:

```bash
make integration-test
```

Container route:

```bash
./scripts/build_integration_container.sh
./scripts/run_in_container.sh
```

Prerequisites:

- Linux with `/dev/net/tun`
- Podman able to run `--privileged` containers

Notes:

- The container route keeps namespace/TUN setup isolated from host networking by using the container runtime's default network namespace behavior.
- Integration scope is single-session only; multi-session/routing assertions are deferred.

## What Is Produced

After `make all`:

- `daemon/target/ipcpd` - daemon binary
- `generic/target/libgeneric.a` - generic utility static library
- `protocol/target/libprotocol.a` - protocol static library
- `io/target/libio.a` - fd-level I/O and poller static library
- `session/target/libsession.a` - per-connection runtime policy and bridge logic

After `make test`:

- `test/target/test` - unified test runner binary (executed by `make test`)

Manual subset examples:

- `./test/target/test protocol` - run protocol suite only
- `./test/target/test io` - run IO suite only
- `./test/target/test session` - run session suite only
- unknown suite names return a non-zero exit and usage message

## `ipcpd` Usage

CLI:

```text
ipcpd <ifName> <ip> <port> <serverFlag> <secretFile>
```

- `ifName`: TUN interface name (example: `tun0`)
- `ip`: bind IP (server) or remote IP (client)
- `port`: TCP port
- `serverFlag`: `1` for server, `0` for client
- `secretFile`: path to file containing exactly 32 raw bytes (no extra bytes)

### Secret file

Generate a 32-byte raw key:

```bash
head -c 32 /dev/urandom > secret.key
```

### Example

Server:

```bash
./daemon/target/ipcpd tun0 0.0.0.0 5000 1 secret.key
```

Client:

```bash
./daemon/target/ipcpd tun0 203.0.113.10 5000 0 secret.key
```

## Runtime Notes

- Requires Linux with `/dev/net/tun`
- `ipcpd` does not inherently require root; TUN create/manage operations require appropriate privileges (typically `CAP_NET_ADMIN`, often via root or pre-provisioned device ownership)
- Interface IP assignment and routing are environment-specific and should be configured separately with `ip` tooling

## Component Roles

- `io`: fd-level setup/poll/read/write primitives (TUN/TCP open + `epoll` + bounded reads/full writes)
- `protocol`: framing, typed messages, and secure message encode/decode (including crypto envelope)
- `session`: per-connection runtime policy and bridge logic (message routing, heartbeat, backpressure)
- `daemon`: process bootstrap and client/server orchestration
