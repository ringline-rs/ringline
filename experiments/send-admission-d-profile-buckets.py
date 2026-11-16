#!/usr/bin/env python3
"""Bucket CPU 0's cpu-clock samples from send-admission-d-profile.toml runs.

Usage: send-admission-d-profile-buckets.py <dir>...
Each <dir> holds one run's results.tgz (found recursively), and the run's
experiment name contains the arm.

Prints, per run and per arm (mean of runs), microseconds of CPU 0 per reply
in each bucket listed in docs/journal/2026-11-send-admission-d.md ("U
profile"), at 4000 Hz (250 us per sample), and the top leaf symbols of the
buckets that grew.
"""
import collections, gzip, io, os, re, sys, tarfile

US_PER_SAMPLE = 250.0
RECV = ("net_rx_action", "__netif_receive_skb", "process_backlog", "tcp_v4_rcv", "ip_rcv")
SEND = ("tcp_sendmsg", "tcp_push", "tcp_write_xmit", "__tcp_push_pending_frames")
POLL = ("io_poll", "io_arm_poll", "__io_arm_poll", "io_pollfree", "tcp_poll", "sock_poll")
MEMCPY = re.compile(r"(memcpy|memmove)", re.I)


def frames(block):
    out = []
    for l in block[1:]:
        m = re.match(r"\s*[0-9a-f]+\s+(.*?)\s+\((.*)\)\s*$", l)
        if m:
            out.append((m[1], m[2]))
    return out


def bucket(comm, fr):
    syms = [s for s, _ in fr]
    if any(s.startswith(RECV) for s in syms):
        return "loopback receive"
    if any(s.startswith(SEND) for s in syms):
        return "kernel send"
    if any(s.startswith(POLL) for s in syms):
        return "poll (gate, room)"
    if any(s.startswith(("io_", "__io_", "__do_sys_io_uring")) for s in syms):
        return "io_uring other"
    if fr and "admission-server" in fr[0][1]:
        return "user memcpy" if MEMCPY.search(fr[0][0]) else "user ringline"
    if fr and MEMCPY.search(fr[0][0]) and any("admission-server" in d for _, d in fr):
        return "user memcpy"
    if comm.startswith("swapper") or (fr and fr[0][0].startswith(("default_idle", "pv_native_safe_halt", "native_safe_halt", "cpuidle", "acpi_idle"))):
        return "idle"
    if any("admission-server" in d for _, d in fr):
        return "user other (libc etc.)"
    return "other kernel"


def run(path):
    tgz = None
    for root, _, files in os.walk(path):
        if "results.tgz" in files:
            tgz = os.path.join(root, "results.tgz")
    t = tarfile.open(tgz)
    raw = gzip.decompress(t.extractfile("results/perf-script.txt.gz").read()).decode(errors="replace")
    load = t.extractfile("results/load.json").read().decode()
    m = re.search(r'"completed":\s*(\d+)', load)
    w = re.search(r'"warmup":\s*(\d+)', load)
    replies = int(m[1]) + int(w[1])
    counts = collections.Counter()
    leaves = collections.defaultdict(collections.Counter)
    for block in raw.split("\n\n"):
        lines = [l for l in block.splitlines() if l.strip()]
        if not lines:
            continue
        comm = lines[0].split()[0]
        fr = frames(lines)
        b = bucket(comm, fr)
        counts[b] += 1
        if fr:
            leaves[b][fr[0][0]] += 1
    return replies, counts, leaves


def main():
    per_arm = collections.defaultdict(list)
    for d in sys.argv[1:]:
        name = next((f for f in os.listdir(d) if f.startswith("D profile")), os.path.basename(d))
        arm = re.sub(r" rep\d+$", "", name)
        replies, counts, leaves = run(d)
        tot = sum(counts.values())
        print(f"{name}: {replies} replies, {tot} samples, {tot*US_PER_SAMPLE/replies:.0f} us/reply")
        per_arm[arm].append((replies, counts, leaves))
    buckets = sorted({b for v in per_arm.values() for _, c, _ in v for b in c})
    arms = sorted(per_arm)
    print("\nus of CPU 0 per reply (mean of runs)")
    print(f"{'bucket':24}" + "".join(f"{a[-36:]:>38}" for a in arms))
    for b in buckets + ["TOTAL"]:
        row = []
        for a in arms:
            vals = [(sum(c.values()) if b == "TOTAL" else c[b]) * US_PER_SAMPLE / r for r, c, _ in per_arm[a]]
            row.append(f"{sum(vals)/len(vals):8.0f} [{min(vals):5.0f}-{max(vals):5.0f}]")
        print(f"{b:24}" + "".join(f"{x:>38}" for x in row))
    print("\ntop leaves per bucket, us per reply (mean of runs)")
    for b in buckets:
        print(f"== {b}")
        for a in arms:
            agg = collections.Counter()
            for r, _, lv in per_arm[a]:
                for s, n in lv[b].items():
                    agg[s] += n * US_PER_SAMPLE / r / len(per_arm[a])
            top = ", ".join(f"{s} {v:.0f}" for s, v in agg.most_common(6))
            print(f"   {a[-30:]:30} {top}")


main()
