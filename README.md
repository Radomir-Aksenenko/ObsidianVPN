# Obsidian VPN Protocol (v2)

High-Performance Anti-Censorship Layer-3 Transport Protocol with Range-Based Framing, CPS Signatures, REALITY TLS Camouflage, and UDP Multiplexing.

Status: Beta / Open Specification & Reference Implementation

---

## Overview

Obsidian is an open layer-3 network protocol engineered specifically to defeat modern Deep Packet Inspection (DPI) systems, active probing, and state-level censors (such as TSPU). 

Unlike application-level proxies (VLESS, Shadowsocks, Trojan) which operate at stream level, Obsidian creates a full virtual network interface (TUN) with high throughput (350+ Mbps), low latency, and zero TCP-over-TCP degradation for gaming, streaming, and real-time communications.

---

## Core Architecture & Anti-Censorship Features

```
[ TUN Interface (L3 IP Packets) ]
               │
               ▼
[ Adaptive Padding & Framing Engine ]
  - Range-Based Type IDs (Dynamic 4-byte random headers)
  - Variable padding & bucket quantization
               │
               ▼
[ Cryptographic Layer ]
  - ChaCha20-Poly1305 AEAD
  - X25519 / Post-Quantum ML-KEM session key exchange
  - Replay protection sliding window
               │
       ┌───────┴────────┐
       ▼                ▼
[ Control & TCP ]     [ Fast UDP Datapath ]
- REALITY TLS 1.3     - Lock-Free Multi-Queue Pipeline
  ClientHello replay  - Port hopping & pooling
- CPS Signatures      - Keepalive & timing jitter
  (DNS/QUIC miming)   - Background noise injection
```

### 1. Range-Based Type IDs (Header Obfuscation)
Traditional protocols use fixed byte identifiers (e.g. WireGuard `0x01` handshake, `0x04` transport data), allowing DPI to block them with simple pattern matching.
Obsidian replaces static type bytes with 4-byte integer identifiers randomly chosen from configured, non-overlapping ranges:
- `Data Range`: `0x10000000` - `0x1FFFFFFF` (268M variants)
- `Keepalive Range`: `0x20000000` - `0x2FFFFFFF`
- `Noise Range`: `0x30000000` - `0x3FFFFFFF`
- `Handshake Range`: `0x40000000` - `0x4FFFFFFF`
- `Close Range`: `0x50000000` - `0x5FFFFFFF`

Every packet header is statistically indistinguishable from high-entropy cryptographic noise.

### 2. REALITY TLS 1.3 Camouflage
For environments with strict protocol whitelisting (where non-TLS traffic is throttled or dropped):
- The client encapsulates the handshake inside genuine TLS 1.3 ClientHello records.
- Reflects genuine certificates from target SNI domains (e.g. `www.microsoft.com`, `gateway.icloud.com`) without owning private keys or domain certificates.
- Unauthorized active DPI probes are forwarded directly to the authentic target server.

### 3. CPS (Composite Packet Signatures)
The handshake supports mimicking protocol signatures (CPS DSL):
- Generates valid initial protocol signatures (QUIC Initial, DNS query, etc.) to pass signature filters before switching into encrypted session state.

### 4. Lock-Free UDP Datapath & Adaptive Padding
- Packet padding min/max ranges eliminate packet size fingerprinting.
- Multi-queue lock-free packet processing sustains 350+ Mbps with MTU 1420-1500 and automated MSS clamping.

---

## Obsidian URI Specification

Obsidian defines a standardized URI scheme for configuration exchange, node sharing, and subscription management across different VPN client implementations.

### URI Format

```
obsidian://<server_public_key>@<server_host>:<server_port>?[parameters]#[server_name]
```

Also accepted aliases:
- `vpn://obsidian/<server_public_key>@<server_host>:<server_port>?[parameters]#[server_name]`
- `vpn://<server_public_key>@<server_host>:<server_port>?proto=obsidian&[parameters]#[server_name]`

### Query Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `udp_port` | integer | Dedicated UDP data channel port | Equal to `server_port` |
| `udp_data` | `0` or `1` | Enable UDP high-speed transport channel | `1` |
| `security` | string | Security disguise mode (`reality` or `none`) | `reality` |
| `sni` | string | Target domain for TLS / REALITY camouflage | `www.microsoft.com` |
| `auth_key` | hex string | Authentication key for REALITY server filter | Optional |
| `fp` | string | Client TLS fingerprint (`chrome`, `ios`, `firefox`) | `chrome` |
| `profile` | string | Obfuscation preset (`fast-secure`, `stealth`, `default`) | `fast-secure` |
| `mtu` | integer | Interface MTU size | `1420` |
| `dns` | string | Preferred DNS resolver for tunnel | `1.1.1.1` |
| `ipv6` | `0` or `1` | Enable IPv6 dual-stack routing | `0` |
| `noise_min` | float | Minimum interval for background noise packets (sec) | `10` |
| `noise_max` | float | Maximum interval for background noise packets (sec) | `40` |
| `keepalive` | float | Keepalive heartbeat interval (sec) | `20` |
| `junk` | integer | Number of dummy burst packets sent at start | `7` |
| `sig` | string (multi) | URL-encoded CPS signature packet string | Built-in defaults |
| `keyserver`| URL | Key server endpoint for subscription/device management | Optional |
| `token` | string | Client access token | Optional |
| `expires` | ISO 8601 | Access expiration timestamp | Optional |

### Example Link

```
obsidian://170a2fec63c53e4a0c6c866d9d08a3304602b3a9090101765af292a469ac1f27@198.51.100.1:8443?security=reality&sni=www.microsoft.com&auth_key=d859d03517492c93bbdf73a10bc10cf1&udp_port=8443#Frankfurt-01
```

### Subscriptions

Subscription endpoints should return:
1. Plain text with one `obsidian://` URI per line, OR
2. Standard Base64 encoding of the newline-delimited URI list.

---

## Integration Guide for Third-Party Clients

Obsidian is written in Go with zero CGO dependencies and can be integrated into any client application as a library, daemon subprocess, or via C-shared bindings.

### Embedding as Go Package

```go
package main

import (
    "log"
    "obsidian/obsidian"
)

func main() {
    uri := "obsidian://<key>@198.51.100.1:8443?security=reality&sni=www.microsoft.com#Node"
    
    // 1. Parse URI into client config
    cfg, err := obsidian.ParseURI(uri)
    if err != nil {
        log.Fatalf("invalid URI: %v", err)
    }

    // 2. Generate or load client session keypair
    clientKeys, _ := obsidian.GenerateKeypair()

    // 3. Establish encrypted tunnel session
    log.Printf("Connecting to %s:%s via %s...", cfg.ServerHost, cfg.ServerPort, cfg.Profile)
}
```

---

## Repository Structure

```
.
├── obsidian/             # Core protocol library (Go)
│   ├── protocol.go       # Wire format v2, Range-based Type IDs, framing
│   ├── handshake.go      # Key exchange and authentication state machine
│   ├── reality.go        # REALITY TLS 1.3 disguise and demuxing
│   ├── obfuscation.go    # Noise injection, padding, timing jitter
│   ├── transport.go      # TCP connection manager and session dials
│   ├── udp.go            # Lock-free multiplexed UDP pipeline
│   ├── uri.go            # obsidian:// and vpn:// codec & parser
│   ├── cps.go            # Composite packet signature parser
│   └── crypto.go         # ChaCha20-Poly1305 and X25519 primitives
├── cmd/
│   ├── server/           # Obsidian server daemon (TUN, DNS, routing)
│   ├── client/           # Reference CLI client daemon
│   └── probe/            # DPI simulation and active probe tool
├── docs/                 # Architecture documents & protocol specifications
├── examples/             # Sanitized configuration examples
├── go.mod
├── LICENSE
└── README.md
```

---

## Building from Source

### Prerequisites
- Go 1.22 or higher
- Linux (for server TUN router: `iproute2`, `iptables` or `nftables`)
- Windows / macOS / Linux (for client CLI)

### Build Server and Client

```bash
# Build server daemon (Linux)
go build -o bin/obsidian-server ./cmd/server

# Build client CLI (Windows / Linux / macOS)
go build -o bin/obsidian-client ./cmd/client
```

### Running

#### Server
```bash
sudo ./bin/obsidian-server --config examples/server.example.json
```

#### Client
```bash
# Connect directly via URI:
sudo ./bin/obsidian-client --uri "obsidian://<key>@<host>:8443?security=reality&sni=www.microsoft.com#Beta"

# Or connect using a config file:
sudo ./bin/obsidian-client --config examples/client.example.json

# Export an existing config to URI:
./bin/obsidian-client --config config.json --to-uri --label "MyServer"
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
