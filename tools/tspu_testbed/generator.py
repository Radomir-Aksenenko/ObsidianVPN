"""
Traffic Flow Generator for TSPU Simulation Testbed.
Generates realistic multi-class network flows:
0: Legitimate WebRTC (Discord/Zoom Opus audio calls with RFC 5389 STUN)
1: Unobfuscated WireGuard (Standard signatures 0x01, 0x02, 0x04)
2: ObsidianVPN (STUN RFC 5389 header, ChaCha20-Poly1305, bucket padding + random trailers)
3: Regular HTTPS/TLS (TLS 1.3 Handshake + Application Data)
"""

import os
import random
import time
from typing import List, Tuple, Dict, Any
import numpy as np

CLASS_WEBRTC = 0
CLASS_WIREGUARD = 1
CLASS_OBSIDIAN = 2
CLASS_HTTPS = 3

CLASS_NAMES = {
    CLASS_WEBRTC: "Legitimate_WebRTC",
    CLASS_WIREGUARD: "Unobfuscated_WireGuard",
    CLASS_OBSIDIAN: "ObsidianVPN_Tunnel",
    CLASS_HTTPS: "Standard_HTTPS"
}


def calculate_bucket_padding(payload_len: int, max_mtu: int = 1360, max_trailer: int = 64) -> int:
    """Replicates ObsidianVPN CalculateBucketPaddingWithTrailer logic."""
    if payload_len <= 0 or payload_len >= max_mtu:
        return 0
    buckets = [128, 256, 512, 1024, max_mtu]
    target = max_mtu
    for b in buckets:
        if payload_len <= b:
            target = b
            break

    base_pad = target - payload_len
    trailer = 0
    if max_trailer >= 4:
        max_steps = max_trailer // 4
        trailer = random.randint(0, max_steps) * 4

    pad = base_pad + trailer
    if payload_len + pad > max_mtu:
        pad = max_mtu - payload_len

    # Strict RFC 5389 requirement: ensure total length (payload_len + pad) is 4-byte aligned
    rem = (payload_len + pad) % 4
    if rem != 0:
        pad += (4 - rem)
        if payload_len + pad > max_mtu and max_mtu >= 4:
            pad -= 4
    return max(0, pad)


def generate_webrtc_flow(num_packets: int = 30) -> List[Tuple[float, int, bytes]]:
    """
    Simulates real WebRTC audio session (e.g. Discord/Zoom call):
    - Initial STUN Binding Request & Response (RFC 5389)
    - Followed by 20ms Opus RTP frames (120-280 bytes) with micro-jitter
    """
    flow = []
    current_time = 0.0

    # 1. STUN Binding Request (Client -> Server)
    # RFC 5389: Type 0x0001, Cookie 0x2112A442, 12-byte Transaction ID
    tx_id = os.urandom(12)
    stun_req = b"\x00\x01\x00\x00\x21\x12\xa4\x42" + tx_id
    flow.append((current_time, 1, stun_req))

    # 2. STUN Binding Success Response (Server -> Client)
    current_time += random.uniform(0.015, 0.035)  # RTT
    # XOR-MAPPED-ADDRESS attribute: Type 0x0020, Length 8 (padded to multiple of 4)
    xor_mapped = b"\x00\x20\x00\x08\x00\x01\x12\x34\x21\x12\xa4\x42"
    stun_resp = b"\x01\x01\x00\x0c\x21\x12\xa4\x42" + tx_id + xor_mapped
    flow.append((current_time, -1, stun_resp))

    # 3. RTP/SRTP Audio frames (Opus 20ms audio, VBR 100-260 bytes)
    for i in range(2, num_packets):
        current_time += random.gauss(0.020, 0.003)  # 20ms cadence with jitter
        direction = 1 if (i % 2 == 0 or random.random() < 0.6) else -1

        # RTP Header (12 bytes) + Opus Audio Payload + SRTP Auth Tag (4 bytes)
        rtp_header = b"\x80\x6f" + (i & 0xFFFF).to_bytes(2, "big") + os.urandom(8)
        # Opus compressed speech has entropy ~7.3-7.6
        raw_audio_len = random.randint(110, 250)
        # Generate semi-structured audio bytes (slightly lower entropy than raw crypto)
        base = os.urandom(raw_audio_len)
        mask = bytearray(base)
        for j in range(0, len(mask), 8):
            mask[j] = mask[j] & 0x7F  # subtle structure in voice codec
        srtp_packet = rtp_header + bytes(mask) + os.urandom(4)
        flow.append((current_time, direction, srtp_packet))

    return flow


def generate_wireguard_flow(num_packets: int = 30) -> List[Tuple[float, int, bytes]]:
    """
    Simulates standard unobfuscated WireGuard tunnel:
    - Packet 0: Handshake Initiation (148 bytes, Type 0x01)
    - Packet 1: Handshake Response (92 bytes, Type 0x02)
    - Packets 2..N: Data packets (Type 0x04, fixed sizes, heavy MTU 1420 / ACK 80)
    """
    flow = []
    current_time = 0.0

    # 1. Handshake Initiation: Type 0x01, sender_index (4), unencrypted ephemeral (32), encrypted static (48), encrypted timestamp (28), mac1 (16), mac2 (16) = 148 bytes
    initiation = b"\x01\x00\x00\x00" + os.urandom(144)
    flow.append((current_time, 1, initiation))

    # 2. Handshake Response: Type 0x02, sender_index (4), receiver_index (4), unencrypted ephemeral (32), encrypted nothing (16), mac1 (16), mac2 (16) = 92 bytes
    current_time += random.uniform(0.020, 0.040)
    response = b"\x02\x00\x00\x00" + os.urandom(88)
    flow.append((current_time, -1, response))

    # 3. Data Packets: Type 0x04 (32 bytes header + encrypted payload)
    # Heavy MTU transfers (1420 bytes) and small ACKs (80 bytes)
    for i in range(2, num_packets):
        current_time += random.uniform(0.001, 0.015)
        is_download = (random.random() < 0.7)
        if is_download:
            direction = -1
            payload_len = 1420 - 32  # Standard MTU data
        else:
            direction = 1
            payload_len = 80 if random.random() < 0.7 else 1420 - 32

        header = b"\x04\x00\x00\x00" + os.urandom(28)
        data = header + os.urandom(payload_len)
        flow.append((current_time, direction, data))

    return flow


def generate_obsidian_flow(num_packets: int = 30) -> List[Tuple[float, int, bytes]]:
    """
    Simulates ObsidianVPN encrypted tunnel:
    - STUN RFC 5389 Header:
      * Client -> Server: Type 0x0001 (Binding Request)
      * Server -> Client: Type 0x0101 (Binding Success Response)
      * Magic Cookie: 0x2112A442
      * 96-bit CSPRNG Transaction ID (fully random, no sequential leaks)
      * Message Length: always multiple of 4 (RFC 5389 alignment)
    - ChaCha20-Poly1305 encrypted payload (16 bytes tag)
    - Dynamic bucket padding (128, 256, 512, 1024, 1360) + random 4-byte trailer
    """
    flow = []
    current_time = 0.0
    magic_cookie = b"\x21\x12\xa4\x42"

    for i in range(num_packets):
        current_time += random.uniform(0.002, 0.025)
        direction = 1 if (random.random() < 0.55) else -1

        # Raw user data size (web traffic / ping / streaming)
        if random.random() < 0.4:
            raw_len = random.randint(40, 300)   # Interactive/ACK
        elif random.random() < 0.7:
            raw_len = random.randint(300, 900)  # Medium data
        else:
            raw_len = random.randint(900, 1300) # Heavy data

        # Add 16 bytes Poly1305 auth tag + bucket padding
        pad = calculate_bucket_padding(raw_len + 16, max_mtu=1360, max_trailer=64)
        encrypted_len = raw_len + 16 + pad

        # RFC 7983 WebRTC Multiplexing:
        # Packets 0..1 (and periodic every 128 pkts) use RFC 5389 STUN Binding
        # Packets 2..N use authentic RFC 3550 / RFC 7983 SRTP Opus frames (V=2, PT=111)
        is_stun = (i < 2) or (i % 128 == 0)

        if is_stun:
            # RFC 5389: Message Type (0x0001 request from client, 0x0101 response from server)
            msg_type = b"\x00\x01" if direction > 0 else b"\x01\x01"
            tx_id = os.urandom(12)
            header = (
                msg_type +
                encrypted_len.to_bytes(2, "big") +
                magic_cookie +
                tx_id
            )
        else:
            # RFC 3550 / RFC 7983: RTP/SRTP Header (12 bytes)
            # V=2 (0x80), PT=111 Opus (0x6F), 16-bit seq, 32-bit timestamp, 32-bit SSRC
            seq = (i & 0xFFFF).to_bytes(2, "big")
            ts = (i * 960).to_bytes(4, "big")
            ssrc = b"\x13\x37\xca\xfe"
            header = b"\x80\x6f" + seq + ts + ssrc

        ciphertext = os.urandom(encrypted_len)
        packet = header + ciphertext
        flow.append((current_time, direction, packet))

    return flow


def generate_https_flow(num_packets: int = 30) -> List[Tuple[float, int, bytes]]:
    """
    Simulates standard HTTPS/TLS 1.3 web traffic:
    - Packet 0: TLS ClientHello (Type 0x16 0x03 0x01, ~450 bytes)
    - Packet 1: TLS ServerHello (Type 0x16 0x03 0x03, ~1350 bytes)
    - Packets 2..N: TLS Application Data (Type 0x17 0x03 0x03, variable bursts)
    """
    flow = []
    current_time = 0.0

    # 1. TLS ClientHello
    client_hello_len = random.randint(400, 550)
    client_hello = b"\x16\x03\x01" + client_hello_len.to_bytes(2, "big") + b"\x01" + os.urandom(client_hello_len - 1)
    flow.append((current_time, 1, client_hello))

    # 2. TLS ServerHello
    current_time += random.uniform(0.025, 0.045)
    server_hello_len = random.randint(1200, 1400)
    server_hello = b"\x16\x03\x03" + server_hello_len.to_bytes(2, "big") + b"\x02" + os.urandom(server_hello_len - 1)
    flow.append((current_time, -1, server_hello))

    # 3. Application Data
    for i in range(2, num_packets):
        current_time += random.uniform(0.001, 0.030)
        direction = -1 if random.random() < 0.65 else 1
        app_len = random.randint(100, 1440)
        app_pkt = b"\x17\x03\x03" + app_len.to_bytes(2, "big") + os.urandom(app_len)
        flow.append((current_time, direction, app_pkt))

    return flow


def generate_flow_by_class(class_id: int, num_packets: int = 30) -> List[Tuple[float, int, bytes]]:
    if class_id == CLASS_WEBRTC:
        return generate_webrtc_flow(num_packets)
    elif class_id == CLASS_WIREGUARD:
        return generate_wireguard_flow(num_packets)
    elif class_id == CLASS_OBSIDIAN:
        return generate_obsidian_flow(num_packets)
    elif class_id == CLASS_HTTPS:
        return generate_https_flow(num_packets)
    else:
        raise ValueError(f"Unknown class_id: {class_id}")
