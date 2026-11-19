#!/usr/bin/env python3
"""Summarise send-pool-stage0.toml results.

Usage: send-pool-stage0-report.py RESULTS_DIR [RESULTS_DIR ...]

Each RESULTS_DIR is an unpacked results.tgz (holding results/<n>-<label>/).
Prints one row per run, grouped by cell, arm and order: the probe's share of
requests not answered within --within-ms (cells with a probe), the slow
readers' bytes read in the window, the closed-loop class's throughput, the
batch class's rounds and stalls, and the server's cap_waits. A run whose
files cannot be read is printed as FAILED.
"""
import glob
import json
import os
import re
import sys
from collections import defaultdict


def rows(dirs):
    for top in dirs:
        base = os.path.join(top, "results") if os.path.isdir(os.path.join(top, "results")) else top
        for r in glob.glob(os.path.join(base, "[0-9]*-*")):
            label = os.path.basename(r).split("-", 1)[1]
            try:
                load = json.load(open(os.path.join(r, "load.json")))
            except (OSError, ValueError):
                yield label, top, None, None
                continue
            try:
                srv = json.load(open(os.path.join(r, "server-summary.json")))
            except (OSError, ValueError):
                srv = server_counters(os.path.join(r, "server.json"))
            yield label, top, load, srv


def server_counters(path):
    """The cap counters from the server's full output, for a run whose
    summary file is missing. The full output can be hundreds of MB, so the
    counters are found by pattern, not parsed."""
    srv = {}
    try:
        with open(path, "rb") as f:
            text = f.read()
    except OSError:
        return srv
    for key in ("cap_waits", "cap_wait_us"):
        m = re.search(rb'"%s":([0-9]+)' % key.encode(), text)
        if m:
            srv[key] = int(m.group(1))
    return srv


def fmt(label, load, srv):
    out = []
    if load.get("offered"):
        out.append(f"miss {load['not_within']}/{load['offered']} "
                   f"({100 * load['not_within'] / load['offered']:.2f}%) "
                   f"p99 {load['p99_ns'] / 1e6:.2f} ms")
    slow = load.get("slow") or {}
    if slow.get("bytes_read_window"):
        out.append(f"slow {slow['bytes_read_window'] / 1e6:.1f} MB")
    fast = load.get("fast") or {}
    if fast.get("conns"):
        out.append(f"fast {fast['replies_per_s']:.0f}/s {fast['bytes_per_s'] / 1e6:.0f} MB/s "
                   f"p99 {fast['p99_us'] / 1e3:.2f} ms")
    batch = load.get("batch") or {}
    if batch.get("conns"):
        st = batch.get("stalls") or []
        where = ",".join(f"{s['phase']}@{s['written']}/{s['read']}" for s in st)
        out.append(f"batch rounds {batch['rounds']} stalled {batch['stalled']} {where}")
    out.append(f"cap_waits {srv.get('cap_waits')}")
    return "  ".join(out)


def main():
    groups = defaultdict(list)
    for label, top, load, srv in rows(sys.argv[1:]):
        cell, arm, order = label.rsplit("-", 2)
        groups[(cell, order, arm)].append((top, load, srv))
    for key in sorted(groups):
        cell, order, arm = key
        for top, load, srv in groups[key]:
            text = "FAILED" if load is None else fmt(cell, load, srv)
            print(f"{cell:11} {order:6} {arm:5} {text}")


if __name__ == "__main__":
    main()
