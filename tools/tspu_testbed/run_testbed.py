"""
TSPU Simulation Testbed Runner.
Orchestrates multi-class traffic generation, PyTorch neural network training,
multi-stage TSPU DPI evaluation, and comparative evasion reporting.
"""

import json
import os
import sys
import time
from typing import List, Tuple, Dict, Any
import numpy as np
import torch

from generator import (
    generate_flow_by_class,
    CLASS_WEBRTC,
    CLASS_WIREGUARD,
    CLASS_OBSIDIAN,
    CLASS_HTTPS,
    CLASS_NAMES
)
from features import extract_flow_features
from neural_model import (
    TSPUFlowClassifier,
    train_classifier,
    evaluate_classifier,
    save_model,
    load_model
)
from tspu_engine import TSPUEngine


def load_config(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_dataset(num_flows_per_class: int, packets_per_flow: int) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[Dict[str, Any]]]:
    X_seq = []
    X_stat = []
    y = []
    metadata_list = []

    for class_id in [CLASS_WEBRTC, CLASS_WIREGUARD, CLASS_OBSIDIAN, CLASS_HTTPS]:
        for _ in range(num_flows_per_class):
            flow = generate_flow_by_class(class_id, packets_per_flow)
            seq, stats, meta = extract_flow_features(flow)
            X_seq.append(seq)
            X_stat.append(stats)
            y.append(class_id)
            meta["class_id"] = class_id
            meta["class_name"] = CLASS_NAMES[class_id]
            metadata_list.append(meta)

    return (
        np.array(X_seq, dtype=np.float32),
        np.array(X_stat, dtype=np.float32),
        np.array(y, dtype=np.int64),
        metadata_list
    )


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.json")
    cfg = load_config(config_path)

    device = "cuda" if torch.cuda.is_available() else "cpu"

    print("=" * 80)
    print("TSPU DPI SIMULATION TESTBED: ADVERSARIAL NEURAL TRAFFIC ANALYSIS")
    print(f"Device: {device.upper()} | PyTorch: {torch.__version__}")
    print("=" * 80)

    train_n = cfg["traffic"]["num_train_flows_per_class"]
    test_n = cfg["traffic"]["num_test_flows_per_class"]
    pkts_n = cfg["traffic"]["packets_per_flow"]

    print(f"[1/5] Generating multi-class synthetic flows ({train_n * 4} train, {test_n * 4} test)...")
    X_seq_train, X_stat_train, y_train, _ = build_dataset(train_n, pkts_n)
    X_seq_test, X_stat_test, y_test, _ = build_dataset(test_n, pkts_n)

    # --------------------------------------------------------------------------
    # SCENARIO 1: Real-World "In-The-Wild" TSPU (Binary Media vs VPN Classifier)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 1: REAL-WORLD 'IN-THE-WILD' TSPU (Zero-Shot Detection of Novel Tunnel)")
    print("Description: TSPU only knows standard VPNs (WireGuard) and legitimate media (WebRTC).")
    print("             It has NEVER seen ObsidianVPN before. Does ObsidianVPN blend into WebRTC?")
    print("=" * 80)

    # Filter training data: only WebRTC (0 -> 0: Normal) and WireGuard (1 -> 1: VPN)
    mask_train = (y_train == CLASS_WEBRTC) | (y_train == CLASS_WIREGUARD)
    X_seq_bin_train = X_seq_train[mask_train]
    X_stat_bin_train = X_stat_train[mask_train]
    y_bin_train = np.where(y_train[mask_train] == CLASS_WEBRTC, 0, 1)

    bin_model = TSPUFlowClassifier(num_classes=2).to(device)
    train_classifier(bin_model, X_seq_bin_train, X_stat_bin_train, y_bin_train, epochs=12, device=device)

    bin_model.eval()
    t_seq_test = torch.tensor(X_seq_test, dtype=torch.float32).unsqueeze(1).to(device)
    t_stat_test = torch.tensor(X_stat_test, dtype=torch.float32).to(device)

    with torch.no_grad():
        bin_logits = bin_model(t_seq_test, t_stat_test)
        bin_probs = torch.softmax(bin_logits, dim=1).cpu().numpy()
        bin_preds = np.argmax(bin_probs, axis=1)  # 0: Normal Media, 1: Blocked VPN

    print(f"{'Traffic Class':<26} {'Tested':<8} {'Passed (Media)':<16} {'Blocked (VPN)':<14} {'Evasion Rate'}")
    print("-" * 80)

    scenario1_results = {}
    for cid, name in CLASS_NAMES.items():
        idx = np.where(y_test == cid)[0]
        preds_cls = bin_preds[idx]
        passed = int(np.sum(preds_cls == 0))
        blocked = int(np.sum(preds_cls == 1))
        evasion_rate = (passed / len(idx)) * 100.0 if len(idx) > 0 else 0.0
        scenario1_results[name] = {"passed": passed, "blocked": blocked, "evasion": evasion_rate}
        print(f"{name:<26} {len(idx):<8} {passed:<16} {blocked:<14} {evasion_rate:>5.1f}%")

    # --------------------------------------------------------------------------
    # SCENARIO 2: Targeted Multiclass DPI (TSPU specifically fingerprinted ObsidianVPN)
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SCENARIO 2: TARGETED ADVERSARIAL DPI (Fingerprint Classification)")
    print("Description: TSPU engineers acquired ObsidianVPN dumps and trained a 4-class model.")
    print("=" * 80)

    model = TSPUFlowClassifier(num_classes=4).to(device)
    train_classifier(
        model, X_seq_train, X_stat_train, y_train,
        epochs=cfg["model"]["epochs"],
        batch_size=cfg["model"]["batch_size"],
        lr=cfg["model"]["learning_rate"],
        device=device
    )

    eval_res = evaluate_classifier(model, X_seq_test, X_stat_test, y_test, device=device)
    conf = eval_res["confusion_matrix"]

    print("Confusion Matrix:")
    hdr = "True \\ Pred"
    print(f"{hdr:<24} {'WebRTC':<10} {'WireGuard':<10} {'Obsidian':<10} {'HTTPS':<10}")
    for cid, name in CLASS_NAMES.items():
        row_str = "  ".join(f"{conf[cid, j]:<8}" for j in range(4))
        print(f"{name:<24} {row_str}")

    # --------------------------------------------------------------------------
    # Summary Insights
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TECHNICAL INSIGHTS & ANALYSIS FOR OBSIDIAN PROTOCOL:")
    print("=" * 80)
    print("1. Against Real-World TSPU (In-The-Wild):")
    print(f"   - WireGuard Block Rate: {scenario1_results['Unobfuscated_WireGuard']['blocked']/test_n*100:.1f}%")
    print(f"   - ObsidianVPN Evasion Rate: {scenario1_results['ObsidianVPN_Tunnel']['evasion']:.1f}%")
    print("2. Why ObsidianVPN blends into WebRTC for Real-World TSPU:")
    print("   - RFC 5389 STUN Binding Request framing matches legitimate WebRTC voice/video handshakes.")
    print("   - Bucket padding (128, 256, 512, 1024, 1360) and random trailers conceal MTU packet size signatures.")
    print("3. Vulnerability in Targeted DPI:")
    print("   - If TSPU trains specifically on ObsidianVPN, it detects that STUN headers are present on 100%")
    print("     of packets (stun_ratio=1.0) instead of intermittently (like real WebRTC which uses RTP data).")
    print("=" * 80)

    # Save results
    report_data = {
        "scenario_1_real_world": scenario1_results,
        "scenario_2_targeted_accuracy": eval_res["accuracy"],
        "device": device,
        "pytorch_version": torch.__version__
    }
    output_json = os.path.join(script_dir, "benchmark_results.json")
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\nBenchmark results saved to: {output_json}\n")


if __name__ == "__main__":
    main()
