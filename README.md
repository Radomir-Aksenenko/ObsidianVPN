[Читать на русском](README.ru.md) | **English**

# Obsidian VPN Protocol (v2)

High-Performance Anti-Censorship Layer-3 Transport Protocol with Range-Based Framing, CPS Signatures, REALITY TLS Camouflage, UDP Multiplexing, and Cross-Platform Client Embedding SDK.

Status: Beta / Open Specification & Reference Implementation

---

## Overview

Obsidian is an open layer-3 network protocol engineered specifically to defeat modern Deep Packet Inspection (DPI) systems, active probing, and state-level censors (such as TSPU).

Unlike application-level proxies (VLESS, Shadowsocks, Trojan) which operate at stream level, Obsidian creates a full virtual network interface (TUN) with high throughput (350+ Mbps), low latency, and zero TCP-over-TCP degradation for gaming, streaming, and real-time communications.

The reference implementation is designed for easy embedding into third-party client apps across **iOS**, **Android**, **Linux**, **macOS**, and **Windows**.

---

## Supported Platforms

| Platform | Tunnel Mechanism | Integration Method | Status |
|:---|:---|:---|:---|
| **Android** | `VpnService` (`ParcelFileDescriptor`) | Go Mobile SDK (`.aar`) or C-ABI (`.so`) | Supported (`[OK]`) |
| **iOS** | `NetworkExtension` (`packetFlow`) | Go Mobile SDK (`.xcframework`) or C-ABI | Supported (`[OK]`) |
| **Linux** | Native `/dev/net/tun` (`IFF_TUN`) | Standalone CLI or Go package `obsidian/client` | Supported (`[OK]`) |
| **macOS** | Native `utun` (`com.apple.net.utun_control`) | Standalone CLI, Go package, or `.xcframework` | Supported (`[OK]`) |
| **Windows** | Native Wintun adapter driver | Standalone CLI or Go package | Supported (`[OK]`) |
| **Flutter / React Native** | FFI bindings or Local SOCKS5 Proxy | C-ABI `bindings/c/obsidian.h` (`dart:ffi`) | Supported (`[OK]`) |

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
  ClientHello replay  - Dynamic port hopping & pooling
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

## Client Developer Embedding SDK

Obsidian provides official integration options for client developers. Full integration documentation with Kotlin and Swift examples is available in [docs/CLIENT_INTEGRATION.md](docs/CLIENT_INTEGRATION.md).

### 1. Go Mobile SDK (`pkg/mobile`)
Optimized for `gomobile bind` to produce native `.aar` (Android) and `.xcframework` (iOS/macOS) libraries:
- `StartTunnelWithFd`: Pass Android `VpnService` file descriptor directly into Go engine.
- `StartPacketTunnel`: Pass raw IP packets in-memory for iOS `NEPacketTunnelProvider` `packetFlow`.
- `SocketProtector`: Callback to invoke `VpnService.protect(fd)` before sockets connect, preventing routing loops.
- `StartLocalProxy` / `StopLocalProxy`: Run a local SOCKS5 proxy server (`127.0.0.1:10808`).

### 2. C-ABI (`bindings/c`)
Standard C header [bindings/c/obsidian.h](bindings/c/obsidian.h) and shared library (`.so`, `.dylib`, `.dll`) for direct invocation from:
- Flutter (via `dart:ffi`)
- React Native (via C++ TurboModules or JNI)
- Rust, C++, C#, Python

### 3. Native TUN Layer (`obsidian/tun`)
Cross-platform virtual network interface abstraction:
- Linux: `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`)
- macOS: `utun` (`com.apple.net.utun_control`)
- Windows: Wintun adapter driver
- Universal: `OpenFD` for existing OS-level descriptors

---

## Obsidian URI Specification

Obsidian defines a standardized URI scheme for configuration exchange, node sharing, and subscription management.

### URI Format

```
obsidian://<server_public_key>@<server_host>:<server_port>?[parameters]#[server_name]
```

Also accepted aliases:
- `vpn://obsidian/<server_public_key>@<server_host>:<server_port>?[parameters]#[server_name]`
- `vpn://<server_public_key>@<server_host>:<server_port>?proto=obsidian&[parameters]#[server_name]`

### Query Parameters

| Parameter | Type | Description | Default |
|:---|:---|:---|:---|
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

---

## Repository Structure

```
.
├── bindings/             # C-ABI and headers for cross-platform clients
│   ├── c/obsidian.h      # C header declarations
│   └── c/obsidian_c.go   # CGO exported functions
├── cmd/
│   ├── server/           # Obsidian server daemon (TUN, DNS, routing)
│   ├── client/           # Reference CLI client daemon (cross-platform)
│   └── probe/            # DPI simulation and active probe tool
├── docs/                 # Architecture documents & developer guides
│   ├── CLIENT_INTEGRATION.md # Guide for iOS, Android, Linux, macOS developers
│   └── ...
├── obsidian/             # Core protocol library (Go)
│   ├── client/           # Reusable client session engine & SOCKS5 proxy
│   ├── tun/              # Cross-platform TUN driver (Linux, macOS, Windows, FD)
│   ├── protocol.go       # Wire format v2, Range-based Type IDs, framing
│   ├── handshake.go      # Key exchange and authentication state machine
│   ├── reality.go        # REALITY TLS 1.3 disguise and demuxing
│   ├── obfuscation.go    # Noise injection, padding, timing jitter
│   ├── transport.go      # TCP connection manager, socket protector
│   ├── udp.go            # Lock-free multiplexed UDP pipeline
│   ├── uri.go            # obsidian:// and vpn:// codec & parser
│   ├── cps.go            # Composite packet signature parser
│   └── crypto.go         # ChaCha20-Poly1305 and X25519 primitives
├── pkg/
│   └── mobile/           # Go Mobile SDK for Android (AAR) and iOS (XCFramework)
├── examples/             # Sanitized configuration examples
├── go.mod
├── LICENSE
└── README.md
```

---

## Building from Source

The client apps (iOS and Windows desktop) are not part of this repository. They live in the private ObsidianVPN-App repository, which consumes this repo as the `core/` git submodule. This repository contains only the VPN core: `obsidian/`, `pkg/`, `cmd/`, `bindings/`, `tools/`, `examples/` and `docs/`.

### Prerequisites
- Go 1.26.1 or higher (see [go.mod](go.mod))
- Linux (for server TUN router: `iproute2`, `iptables` or `nftables`)
- Windows / macOS / Linux (for client CLI)

### Build CLI Binaries

```bash
# Build server daemon (Linux)
go build -o bin/obsidian-server ./cmd/server

# Build client CLI (Windows / Linux / macOS)
go build -o bin/obsidian-client ./cmd/client
```

### Build Mobile SDK Packages

```bash
# Android AAR (requires gomobile)
gomobile bind -target=android -androidapi=21 -o obsidian.aar ./pkg/mobile
```

### Build C-Shared Libraries

```bash
# Linux
go build -buildmode=c-shared -o libobsidian.so ./bindings/c

# macOS
go build -buildmode=c-shared -o libobsidian.dylib ./bindings/c

# Windows
go build -buildmode=c-shared -o obsidian.dll ./bindings/c
```

---

## Server Options

### Exit IP (`egress_ip`, `egress_ip6`)

By default, client traffic leaves the server through its main public IP. Websites see that address, and the VPN port and SSH are open on it. VPN detectors scan the IP that reaches a site and report "open proxy ports".

`egress_ip` (IPv4) and `egress_ip6` (IPv6) set a separate public address for client traffic. The server rewrites the source address of outgoing traffic to this IP. Nothing listens on it, so a port scan comes back clean.

```json
{
  "egress_ip": "203.0.113.10",
  "egress_ip6": "2001:db8::10"
}
```

Leave both empty to keep the default MASQUERADE behaviour.

The provider must route this IP to your server, or return traffic never arrives. Assign it in the provider panel, or on the host:

```bash
ip addr add 203.0.113.10/32 dev eth0
```

The `ip addr` command does not survive a reboot. Make it permanent in your distribution's network config or in the provider panel. If the address is not on a local interface, the server logs a warning and keeps running. An invalid address stops the server at startup.

iptables rules stay in place when the server restarts. If you change or remove `egress_ip`, delete the old rule by hand:

```bash
iptables -t nat -D POSTROUTING -s <tun_address> -o <out_iface> -j SNAT --to-source <old_ip>
```

Here `<tun_address>` is the value of `tun_address` (for example `10.8.0.1/24`).

### Firewall

A separate exit IP does not protect the server itself. The main IP can still be scanned. Keep the VPN ports open to everyone, allow SSH only from your own address, and drop the rest:

```bash
ufw allow from <your_ip> to any port 22 proto tcp
ufw allow <vpn_port>/tcp
ufw allow <vpn_port>/udp
ufw default deny incoming
ufw enable
```

Replace `<vpn_port>` with the `port` and `udp_port` values from the server config. ufw also drops forwarded traffic by default (`DEFAULT_FORWARD_POLICY` in `/etc/default/ufw`). The tunnel needs forwarding, so check that clients still reach the internet after you enable ufw.

### MSS (`disable_mss_normalize`)

Tunnel packets are smaller than normal Ethernet packets. A website can read the MSS value in the TCP handshake and tell that a tunnel is in the path. By default the server hides this:

- It writes MSS 1460 (IPv4) or 1440 (IPv6) into outgoing SYN packets, the same values a plain Ethernet host sends.
- It splits the segments coming back from the internet to fit the client's MTU.

Set `"disable_mss_normalize": true` to go back to the old behaviour, where iptables clamps MSS with TCPMSS on the tunnel interface. The default is `false`.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
