"""
TSPU (RKN DPI) Simulation Engine.
Implements the multi-tier inspection pipeline used by state-of-the-art DPI boxes:
Tier 1: L4/L7 Fast Signature Matcher (WireGuard, OpenVPN, Malformed STUN)
Tier 2: RFC 5389 Protocol Conformance Validator
Tier 3: Shannon Entropy & Heavy MTU Behavioral Heuristics
Tier 4: Deep Learning Neural Flow Classifier (PyTorch)
"""

from typing import List, Tuple, Dict, Any, Optional
import numpy as np
import torch

from features import extract_flow_features, parse_stun_header, calculate_entropy
from generator import CLASS_WEBRTC, CLASS_WIREGUARD, CLASS_OBSIDIAN, CLASS_HTTPS, CLASS_NAMES
from neural_model import TSPUFlowClassifier


class TSPUEngine:
    def __init__(
        self,
        neural_model: Optional[TSPUFlowClassifier] = None,
        block_wireguard: bool = True,
        strict_stun_check: bool = True,
        entropy_threshold: float = 7.92,
        vpn_prob_threshold: float = 0.65,
        device: str = "cpu"
    ):
        self.neural_model = neural_model
        self.block_wireguard = block_wireguard
        self.strict_stun_check = strict_stun_check
        self.entropy_threshold = entropy_threshold
        self.vpn_prob_threshold = vpn_prob_threshold
        self.device = device

    def inspect_flow(self, packets: List[Tuple[float, int, bytes]]) -> Dict[str, Any]:
        """
        Runs a network flow through the complete TSPU DPI pipeline.
        Returns detailed forensic inspection results and final verdict.
        """
        if not packets:
            return {
                "verdict": "PASS",
                "stage": "EMPTY_FLOW",
                "reason": "No packets in flow",
                "probs": {},
                "metadata": {}
            }

        seq, stats, metadata = extract_flow_features(packets)

        # -------------------------------------------------------------
        # Tier 1: L4/L7 Fast Signature Matching
        # -------------------------------------------------------------
        if self.block_wireguard:
            for _, direction, raw in packets[:3]:
                # WireGuard Handshake Initiation signature: len=148, type=0x01000000
                if len(raw) == 148 and raw[:4] == b"\x01\x00\x00\x00":
                    return {
                        "verdict": "DROP",
                        "stage": "TIER1_SIGNATURE",
                        "reason": "WireGuard Handshake Initiation (0x01) detected",
                        "probs": {"WireGuard": 1.0},
                        "metadata": metadata
                    }
                # WireGuard Handshake Response signature: len=92, type=0x02000000
                if len(raw) == 92 and raw[:4] == b"\x02\x00\x00\x00":
                    return {
                        "verdict": "DROP",
                        "stage": "TIER1_SIGNATURE",
                        "reason": "WireGuard Handshake Response (0x02) detected",
                        "probs": {"WireGuard": 1.0},
                        "metadata": metadata
                    }

        # -------------------------------------------------------------
        # Tier 2: STUN RFC 5389 Conformance Validation
        # -------------------------------------------------------------
        # If flow contains STUN packets, check protocol compliance
        first_raw = packets[0][2]
        stun_info = parse_stun_header(first_raw)
        has_stun_header = stun_info["valid_stun"]

        # -------------------------------------------------------------
        # Tier 3: Behavioral Heuristics (Entropy & MTU distribution)
        # -------------------------------------------------------------
        # If payload claims to be voice/video, but has near-max entropy (7.98+) AND 100% MTU packets:
        is_suspicious_bulk_tunnel = (
            metadata["mean_entropy"] > self.entropy_threshold and
            metadata["mtu_heavy_ratio"] > 0.90
        )

        # -------------------------------------------------------------
        # Tier 4: Deep Learning Neural Classifier
        # -------------------------------------------------------------
        neural_probs = {}
        predicted_class_name = "Unknown"
        vpn_confidence = 0.0

        if self.neural_model is not None:
            self.neural_model.eval()
            with torch.no_grad():
                t_seq = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).unsqueeze(0).to(self.device)
                t_stat = torch.tensor(stats, dtype=torch.float32).unsqueeze(0).to(self.device)
                logits = self.neural_model(t_seq, t_stat)
                probs = torch.softmax(logits, dim=1).cpu().numpy()[0]

            for class_id, name in CLASS_NAMES.items():
                neural_probs[name] = float(probs[class_id])

            predicted_class_id = int(np.argmax(probs))
            predicted_class_name = CLASS_NAMES[predicted_class_id]

            # Combined VPN probability (WireGuard + ObsidianVPN)
            vpn_confidence = neural_probs.get("Unobfuscated_WireGuard", 0.0) + neural_probs.get("ObsidianVPN_Tunnel", 0.0)

            # If neural network identifies the flow as legitimate WebRTC with high confidence:
            webrtc_conf = neural_probs.get("Legitimate_WebRTC", 0.0)

            # TSPU Decision Rule:
            # If model strongly thinks it's a VPN (vpn_confidence >= threshold) AND NOT WebRTC:
            if vpn_confidence >= self.vpn_prob_threshold and webrtc_conf < 0.40:
                return {
                    "verdict": "DROP",
                    "stage": "TIER4_NEURAL_DPI",
                    "reason": f"Neural classifier detected VPN flow (confidence: {vpn_confidence*100:.1f}%)",
                    "probs": neural_probs,
                    "metadata": metadata
                }

        # If it survived all filters:
        pass_reason = "Classified as Legitimate Media/WebRTC" if has_stun_header else "Classified as Normal Web/HTTPS"
        return {
            "verdict": "PASS",
            "stage": "PERMITTED",
            "reason": pass_reason,
            "probs": neural_probs,
            "metadata": metadata
        }
