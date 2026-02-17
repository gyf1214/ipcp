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

## What Is Produced

After `make all`:

- `daemon/target/ipcpd` - daemon binary
- `generic/target/libgeneric.a` - generic utility static library
- `protocol/target/libprotocol.a` - protocol static library

After `make test`:

- `test/target/test` - protocol test binary (also executed by `make test`)

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
