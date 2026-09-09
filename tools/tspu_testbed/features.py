"""
Traffic Feature Extractor for TSPU DPI & Neural Flow Classification.
Extracts Shannon entropy, packet length sequences, inter-arrival times (IAT),
and flow-level statistical metrics.
"""

import math
from typing import List, Tuple, Dict, Any
import numpy as np


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data in bits/byte [0.0 - 8.0]."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-np.sum(probs * np.log2(probs)))


def parse_stun_header(data: bytes) -> Dict[str, Any]:
    """Parse STUN header (RFC 5389) if present."""
    if len(data) < 20:
        return {"valid_stun": False, "reason": "too_short"}

    msg_type = int.from_bytes(data[0:2], "big")
    msg_len = int.from_bytes(data[2:4], "big")
    magic_cookie = data[4:8]

    # RFC 5389 Magic Cookie: 0x2112A442
    has_magic = magic_cookie == b"\x21\x12\xa4\x42"
    # First 2 bits of STUN message type must be 00
    valid_type = (msg_type & 0xC000) == 0

    return {
        "valid_stun": has_magic and valid_type,
        "msg_type": hex(msg_type),
        "is_binding_request": msg_type == 0x0001,
        "is_binding_response": msg_type == 0x0101,
        "msg_len": msg_len,
        "matches_payload_len": (msg_len + 20) <= len(data),
    }


def parse_srtp_header(data: bytes) -> Dict[str, Any]:
    """Parse RFC 7983 / RFC 3550 RTP/SRTP header if present."""
    if len(data) < 12:
        return {"valid_srtp": False}
    is_v2 = (data[0] & 0xC0) == 0x80
    pt = data[1] & 0x7F
    # Dynamic payload types (96-127 e.g. Opus 111, VP8 96) or standard audio (PCMU 0, PCMA 8)
    is_valid_pt = (96 <= pt <= 127) or pt in (0, 8)
    return {"valid_srtp": is_v2 and is_valid_pt, "pt": pt}



def extract_flow_features(
    packets: List[Tuple[float, int, bytes]],
    max_seq_len: int = 30
) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Extracts deep learning and statistical features from a packet flow.
    packets: List of (timestamp, direction, raw_bytes)
             direction is +1 for client->server, -1 for server->client.
    Returns:
      seq_vector: shape (max_seq_len,) normalized signed lengths
      stat_vector: shape (16,) normalized statistical features
      metadata: dict of raw diagnostic metrics
    """
    if not packets:
        return np.zeros(max_seq_len, dtype=np.float32), np.zeros(16, dtype=np.float32), {}

    lengths = []
    directions = []
    timestamps = []
    entropies = []
    stun_valid_count = 0
    srtp_valid_count = 0
    up_bytes = 0
    down_bytes = 0

    for ts, direction, raw in packets:
        pkt_len = len(raw)
        lengths.append(pkt_len)
        directions.append(direction)
        timestamps.append(ts)
        entropies.append(calculate_entropy(raw))

        if direction > 0:
            up_bytes += pkt_len
        else:
            down_bytes += pkt_len

        stun = parse_stun_header(raw)
        if stun["valid_stun"]:
            stun_valid_count += 1
        srtp = parse_srtp_header(raw)
        if srtp["valid_srtp"]:
            srtp_valid_count += 1

    lengths_arr = np.array(lengths, dtype=np.float32)
    entropies_arr = np.array(entropies, dtype=np.float32)
    timestamps_arr = np.array(timestamps, dtype=np.float32)

    # 1. Sequence vector: directional lengths normalized by 1500 (MTU)
    seq = np.zeros(max_seq_len, dtype=np.float32)
    n_seq = min(len(packets), max_seq_len)
    for i in range(n_seq):
        seq[i] = (directions[i] * lengths[i]) / 1500.0

    # 2. Inter-arrival times (IAT)
    if len(timestamps) > 1:
        iats = np.diff(timestamps_arr)
        iats = np.maximum(iats, 0.0)
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats))
    else:
        mean_iat = 0.0
        std_iat = 0.0

    # 3. Statistical features vector (16 dimensions)
    mean_len = float(np.mean(lengths_arr))
    std_len = float(np.std(lengths_arr))
    min_len = float(np.min(lengths_arr))
    max_len = float(np.max(lengths_arr))
    q25_len = float(np.percentile(lengths_arr, 25))
    q50_len = float(np.median(lengths_arr))
    q75_len = float(np.percentile(lengths_arr, 75))

    mean_ent = float(np.mean(entropies_arr))
    min_ent = float(np.min(entropies_arr))
    max_ent = float(np.max(entropies_arr))

    total_pkts = len(packets)
    mtu_heavy_ratio = float(np.sum(lengths_arr >= 1000) / total_pkts)
    voice_size_ratio = float(np.sum((lengths_arr >= 80) & (lengths_arr <= 350)) / total_pkts)

    total_bytes = up_bytes + down_bytes
    byte_asym = float((up_bytes - down_bytes) / total_bytes) if total_bytes > 0 else 0.0
    stun_ratio = float(stun_valid_count / total_pkts)
    srtp_ratio = float(srtp_valid_count / total_pkts)
    webrtc_ratio = float((stun_valid_count + srtp_valid_count) / total_pkts)

    # Normalized feature vector for neural network
    stats = np.array([
        mean_len / 1500.0,
        std_len / 1500.0,
        min_len / 1500.0,
        max_len / 1500.0,
        q25_len / 1500.0,
        q50_len / 1500.0,
        q75_len / 1500.0,
        mean_ent / 8.0,
        min_ent / 8.0,
        max_ent / 8.0,
        mtu_heavy_ratio,
        voice_size_ratio,
        min(mean_iat / 0.1, 1.0),
        min(std_iat / 0.1, 1.0),
        byte_asym,
        webrtc_ratio
    ], dtype=np.float32)

    metadata = {
        "packet_count": total_pkts,
        "mean_len": round(mean_len, 1),
        "std_len": round(std_len, 1),
        "mean_entropy": round(mean_ent, 3),
        "mtu_heavy_ratio": round(mtu_heavy_ratio, 2),
        "voice_size_ratio": round(voice_size_ratio, 2),
        "stun_ratio": round(stun_ratio, 2),
        "srtp_ratio": round(srtp_ratio, 2),
        "webrtc_ratio": round(webrtc_ratio, 2),
        "byte_asymmetry": round(byte_asym, 2),
    }

    return seq, stats, metadata
