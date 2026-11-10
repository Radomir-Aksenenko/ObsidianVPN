#!/usr/bin/env python3
"""Shape metrics for netlab captures: record sizes per direction during bulk download and upload.

Usage: netanalyze.py <result dir> [<result dir> ...]
For each pcap the capture is cut into 1 s bins; a bin belongs to the download phase when the
server sends at least 5x the client bytes, to the upload phase in the opposite case.
"""
import collections
import glob
import os
import subprocess
import sys


def records(pcap, port):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-d", f"tcp.port=={port},tls", "-T", "fields", "-E", "separator=|",
         "-e", "frame.time_relative", "-e", "tcp.dstport", "-e", "tls.record.length",
         "-e", "tls.record.content_type"],
        capture_output=True, text=True).stdout
    recs = []
    for line in out.splitlines():
        t, dport, lens, ct = (line.split("|") + [""] * 4)[:4]
        if not lens:
            continue
        cts = ct.split(",")
        for k, L in enumerate(lens.split(",")):
            c = cts[k] if k < len(cts) else ""
            if c in ("22", "20", "21"):
                continue
            recs.append((float(t), dport == str(port), int(L)))
    return recs


def shape(sizes):
    if not sizes:
        return "none"
    c = collections.Counter(sizes)
    top, n = c.most_common(1)[0]
    s = sorted(sizes)
    return f"n={len(sizes)} top={top}({n / len(sizes):.0%}) distinct={len(c)} median={s[len(s) // 2]}"


def analyze(pcap):
    port = 9443 if "xray" in os.path.basename(pcap) else 8443
    recs = records(pcap, port)
    bins = collections.defaultdict(lambda: [0, 0])
    for t, up, L in recs:
        bins[int(t)][0 if up else 1] += L
    phase = {}
    for b, (u, d) in bins.items():
        if d > 5 * u and d > 100000:
            phase[b] = "down"
        elif u > 5 * d and u > 100000:
            phase[b] = "up"
    out = []
    for ph in ("down", "up"):
        bulk_up = ph == "up"
        bulk = [L for t, up, L in recs if phase.get(int(t)) == ph and up == bulk_up]
        rev = [L for t, up, L in recs if phase.get(int(t)) == ph and up != bulk_up]
        mb = sum(bulk) / 1e6
        rate = len(rev) / mb if mb else 0
        out.append(f"  {ph:4} bulk: {shape(bulk)}\n       reverse: {shape(rev)}  reverse records per MB: {rate:.0f}")
    return "\n".join(out)


for d in sys.argv[1:]:
    print("=" * 8, d)
    for pcap in sorted(glob.glob(os.path.join(d, "*.pcap"))):
        print(os.path.basename(pcap))
        print(analyze(pcap))
