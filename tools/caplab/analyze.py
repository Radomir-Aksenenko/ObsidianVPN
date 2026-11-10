#!/usr/bin/env python3
"""Compare outer TLS record shapes of main and branch captures, per scenario phase."""
import collections
import glob
import json
import math
import os
import subprocess
import sys

PC = sys.argv[1]
MODES = sys.argv[2].split(",")
GREASE = {0x0a0a + 0x1010 * i for i in range(16)}


def phases(log):
    ph = {}
    for line in open(log):
        if line.startswith("PHASE "):
            _, name, ns = line.split()
            ph[name] = int(ns) / 1e9
    return ph


def records(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-d", "tcp.port==8443,tls", "-T", "fields", "-E", "separator=|",
         "-e", "frame.time_epoch", "-e", "tcp.dstport", "-e", "tls.record.length",
         "-e", "tls.record.content_type", "-e", "tls.handshake.type",
         "-e", "tls.handshake.extension.type", "-e", "tls.handshake.ciphersuite"],
        capture_output=True, text=True).stdout
    recs, hello = [], None
    for line in out.splitlines():
        t, dport, lens, ctypes, hs, ext, cs = (line.split("|") + [""] * 7)[:7]
        if not lens:
            continue
        up = dport == "8443"
        ct = ctypes.split(",")
        for k, L in enumerate(lens.split(",")):
            recs.append((float(t), up, int(L), ct[k] if k < len(ct) else ""))
        if up and hello is None and "1" in hs.split(","):
            e = [int(x) for x in ext.split(",") if x and int(x) not in GREASE]
            c = [int(x, 16) if x.startswith("0x") else int(x) for x in cs.split(",") if x]
            c = [x for x in c if x not in GREASE]
            hello = {"ext": sorted(e), "cs": c, "ch_len": int(lens.split(",")[0])}
    return recs, hello


def entropy(sizes):
    c = collections.Counter(sizes)
    n = len(sizes)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def stats(sizes):
    if not sizes:
        return {"n": 0}
    c = collections.Counter(sizes)
    top, topn = c.most_common(1)[0]
    return {"n": len(sizes), "bytes": sum(sizes), "distinct": len(c), "top": top,
            "top_share": round(topn / len(sizes), 3), "entropy": round(entropy(sizes), 2)}


def agg(runs):
    keys = ["n", "bytes", "distinct", "top_share", "entropy"]
    out = {}
    for k in keys:
        vals = [r[k] for r in runs if r.get("n")]
        if vals:
            out[k] = round(sum(vals) / len(vals), 3)
    tops = collections.Counter(r.get("top") for r in runs if r.get("n"))
    out["tops"] = dict(tops.most_common(3))
    return out


report = {}
for mode in MODES:
    for v in ("main", "branch"):
        per_phase = collections.defaultdict(list)
        first_up, first_down, hellos = [], [], []
        for pcap in sorted(glob.glob(f"{PC}/{mode}-{v}-*.pcap")):
            ph = phases(pcap.replace(".pcap", ".client.log"))
            if "end" not in ph:
                continue
            recs, hello = records(pcap)
            hellos.append(hello)
            order = ["connected", "tls", "small", "bulk", "idle", "end"]
            app = [r for r in recs if r[3] not in ("22", "20", "21")]
            first_up.append([r[2] for r in app if r[1]][:40])
            first_down.append([r[2] for r in app if not r[1]][:40])
            for a, b in zip(order, order[1:]):
                for up in (True, False):
                    s = [r[2] for r in app if r[1] == up and ph[a] <= r[0] < ph[b]]
                    per_phase[(a, "up" if up else "down")].append(stats(s))

        def const_positions(seqs):
            if len(seqs) < 2:
                return None
            m = min(len(s) for s in seqs)
            return sum(1 for i in range(m) if len({s[i] for s in seqs}) == 1), m

        report[f"{mode}/{v}"] = {
            "runs": len(first_up),
            "phases": {f"{a}/{d}": agg(r) for (a, d), r in sorted(per_phase.items())},
            "const_first_up": const_positions(first_up),
            "const_first_down": const_positions(first_down),
            "first_up_example": first_up[0][:16] if first_up else None,
            "client_hello": hellos[0] if hellos else None,
            "client_hello_same_in_all_runs": len({json.dumps(h, sort_keys=True) for h in hellos}) == 1,
            "ch_lens": sorted({h["ch_len"] for h in hellos if h}),
        }

json.dump(report, sys.stdout, indent=1)
