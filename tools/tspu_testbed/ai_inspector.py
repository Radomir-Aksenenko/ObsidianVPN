"""
AI Forensic Inspector for TSPU DPI Deep Traffic Analysis.
Generates structured hex dumps, entropy maps, and evaluation prompts
for external neural networks / LLMs / subagents to perform forensic packet inspection.
"""

import sys
from typing import List, Tuple, Dict, Any
from features import calculate_entropy, parse_stun_header, parse_srtp_header
from generator import generate_flow_by_class, CLASS_NAMES, CLASS_OBSIDIAN, CLASS_WEBRTC, CLASS_WIREGUARD, CLASS_HTTPS


def format_hex_dump(data: bytes, max_bytes: int = 24) -> str:
    snippet = data[:max_bytes]
    hex_str = " ".join(f"{b:02x}" for b in snippet)
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in snippet)
    if len(data) > max_bytes:
        hex_str += f" ... (+{len(data)-max_bytes}B)"
    return f"{hex_str.ljust(64)} | {ascii_str}"


def build_forensic_dossier(flow: List[Tuple[float, int, bytes]], flow_label: str) -> str:
    """Builds an exhaustive DPI forensic dossier for AI analysis."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"TSPU DEEP PACKET FORENSIC DOSSIER — CAPTURED FLOW: {flow_label}")
    lines.append("=" * 80)

    total_bytes = sum(len(p[2]) for p in flow)
    up_pkts = sum(1 for p in flow if p[1] > 0)
    down_pkts = sum(1 for p in flow if p[1] < 0)
    entropies = [calculate_entropy(p[2]) for p in flow]
    mean_ent = sum(entropies) / len(entropies) if entropies else 0.0

    lines.append(f"Packets: {len(flow)} (Up: {up_pkts}, Down: {down_pkts})")
    lines.append(f"Total Volume: {total_bytes} bytes")
    lines.append(f"Mean Shannon Entropy: {mean_ent:.4f} bits/byte (Uniform random = 8.0)")
    lines.append("-" * 80)
    lines.append("PACKET-BY-PACKET TRACE (First 10 packets):")
    lines.append(f"{'#':<3} {'Time(s)':<8} {'Dir':<4} {'Size':<6} {'Entropy':<8} {'Hex Header (First 24B)':<40}")
    lines.append("-" * 80)

    for i, (ts, direction, raw) in enumerate(flow[:10]):
        dir_str = "-> UP" if direction > 0 else "<- DN"
        ent = calculate_entropy(raw)
        hex_str = " ".join(f"{b:02x}" for b in raw[:20])
        lines.append(f"{i+1:<3} {ts:<8.4f} {dir_str:<4} {len(raw):<6} {ent:<8.3f} {hex_str}")

        # Detail any known protocol markers in trace
        stun = parse_stun_header(raw)
        if stun["valid_stun"]:
            lines.append(f"    [STUN RFC5389] Type={stun['msg_type']} Length={stun['msg_len']} Cookie=0x2112A442")
        srtp = parse_srtp_header(raw)
        if srtp["valid_srtp"]:
            lines.append(f"    [SRTP RFC3550] V=2 PT={srtp['pt']} (Opus Media) RFC7983 Demuxed")

    lines.append("-" * 80)
    lines.append("ANALYST QUERY FOR NEURAL NETWORK / AI INSPECTOR:")
    lines.append(
        "Based on packet lengths, entropy, timing cadence, and header signatures,\n"
        "determine whether this flow represents:\n"
        "1. Legitimate WebRTC audio/video call (e.g. Discord, Zoom, WhatsApp)\n"
        "2. Obfuscated VPN Tunnel (e.g. STUN-mimicking ChaCha20 tunnel)\n"
        "3. Standard Unobfuscated VPN (e.g. WireGuard, OpenVPN)\n"
        "Provide your verdict [PASS: WEBRTC] or [BLOCK: VPN_TUNNEL] and explain why."
    )
    lines.append("=" * 80)

    return "\n".join(lines)


if __name__ == "__main__":
    cls = CLASS_OBSIDIAN
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if "webrtc" in arg:
            cls = CLASS_WEBRTC
        elif "wireguard" in arg:
            cls = CLASS_WIREGUARD
        elif "https" in arg:
            cls = CLASS_HTTPS

    flow = generate_flow_by_class(cls, num_packets=20)
    dossier = build_forensic_dossier(flow, CLASS_NAMES[cls])
    print(dossier)
