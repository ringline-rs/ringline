#!/usr/bin/env python3
"""Run admission-model over Experiment D's arms and cells, and summarise each.

Experiment D's model sweep (docs/send-admission-design.md, section 4,
"Experiment D"). The model is single-threaded, so the runs go to parallel
processes, --jobs at a time. Each run's JSON is written to
OUTDIR/<cell>/seed-<n>.json, and an existing file is reused unless --force is
given, so a sweep can be resumed.

Every run uses N = 16, admit_ms = settle_ms = 1000, R = 32, stalled peers'
requests 40 us apart, free-slot samples every 10 ms, and the socket
parameters below for the cell's tcp_wmem T. The arms are O0 and O7w with
whole replies, O0 with ungated 128 KiB pieces, O0 with gated pieces of
64 KiB and 128 KiB, and O7w with gated 128 KiB pieces.

--cells picks the cells:
- "d" (the default): W1; W2 with six slow readers; W4 at T = 1 MiB with
  k = 4, 8, 16, 32, 48, 56, 63, 64, 72, 96 and 128 stalled peers, and at
  T = 256 KiB with k = 128; W5, four drainers of 3 MiB at 512 KiB/s with
  8 s episodes and 80 s.
- "sensitivity": W4 at 256 KiB, k = 128, under O0 with gated pieces of
  64 KiB and 128 KiB, with the stalled peers' segment size at 2, 4, 8, 16
  and 32 KiB and 65,483 B; the same cell and W2 with six slow readers under
  those two arms with an skb overhead of 1280 B; and W4 at 1 MiB under O0
  with whole replies at k = 4, 16 and 128, with the stalled peers' gap at 0,
  40 and 530 us and admit_ms at 999, 1000 and 1001.
- any other value: a JSON file holding a list of cells, each
  {"name": ..., "args": {...}}, where "args" maps a flag without its leading
  dashes to its value, true for a flag that takes none.

Socket parameters at tcp_wmem T (see the model's module docs, Truesize).
They are derived from Linux 6.12's source, not measured; Experiment D's
calibration run measures them:
- sk_sndbuf is T for every connection, as loopback raises it to the
  tcp_wmem maximum at the handshake.
- The skb overhead is 896 B per segment: SKB_TRUESIZE(320) for a head from
  skb_small_head_cache with MAX_TCP_HEADER of 320 B, sizeof(struct sk_buff)
  aligned to 256 B and skb_shared_info of 320 B.
- A segment carries the MSS, at most half the largest window the peer has
  advertised (tcp_bound_to_half_wnd in tcp_sync_mss and tcp_xmit_size_goal):
  65,483 B for fast readers, whose windows autotune; 32 KiB for stalled
  peers, which set SO_RCVBUF after the connect and so advertised a 64 KiB
  window at the handshake; 2 KiB for drainers and slow readers, which set
  SO_RCVBUF 4096 before the connect and advertise about 4 KiB.
- Stalled peers, drainers and slow readers take 4 KiB into their receive
  buffers (K = T + 4 KiB, as Experiment C's model has it); fast readers
  none (K = T).

For each cell the summary prints the median and [min-max] over the seeds of:
fast small replies' scheduled-to-admission p99 and their admission timeouts;
the 7 MiB replies completed of those requested, summed over the seeds, and
their completion time from request to last byte read, median and max over
the completed; the fewest free slots during any 7 MiB reply, at every change
and in the 10 ms samples (the lowest over the seeds); the drainers' replies
completed, summed; the sends of large replies and those that waited for room
in the socket, and the pieces that waited at the gate, by kind of
connection, summed; and the connections ended by each cause and kind,
summed. Then one table of the d cells by arm.

Usage: send-admission-d-model.py BINARY OUTDIR [--cells d|sensitivity|FILE]
       [--seeds 1-5] [--jobs N] [--force]
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median

MIB = 1 << 20
KIB = 1 << 10

ARMS = {
    "o0-whole": {"order": "o0"},
    "o7w-whole": {"order": "o7w"},
    "o0-p128": {"order": "o0", "stream-piece": 128 * KIB},
    "o0-g64": {"order": "o0", "stream-piece": 64 * KIB, "stream-gate": True},
    "o0-g128": {"order": "o0", "stream-piece": 128 * KIB, "stream-gate": True},
    "o7w-g128": {"order": "o7w", "stream-piece": 128 * KIB, "stream-gate": True},
}
GATED = ["o0-g64", "o0-g128", "o7w-g128"]

COMMON = {
    "pipeline": 16,
    "admit-ms": 1000,
    "settle-ms": 1000,
    "budget": 32,
    "stall-gap-us": 40,
    "sample-ms": 10,
    "skb-overhead": 896,
}

W4_K = [4, 8, 16, 32, 48, 56, 63, 64, 72, 96, 128]


def socket(tcp_wmem):
    """The kernel buffer arguments at tcp_wmem T (see the module docs)."""
    peer = tcp_wmem + 4 * KIB
    return {
        "kbuf": tcp_wmem,
        "seg": 65483,
        "stall-kbuf": peer,
        "stall-rwnd": 4 * KIB,
        "stall-seg": 32 * KIB,
        "slow-kbuf": peer,
        "slow-rwnd": 4 * KIB,
        "slow-seg": 2 * KIB,
        "drain-kbuf": peer,
        "drain-rwnd": 4 * KIB,
        "drain-seg": 2 * KIB,
    }


def workloads():
    """Experiment D's workloads, in the order the summary prints them."""
    w = [("w1", MIB, {})]
    w.append(
        (
            "w2-6slow",
            256 * KIB,
            {
                "stall-peers": 0,
                "drainers": 3,
                "drain-size": 2 * MIB,
                "drain-read-bps": 2 * MIB,
                "slow-conns": 6,
                "slow-rate": 100,
                "slow-size": 4096,
                "slow-read-bps": 128 * KIB,
            },
        )
    )
    for k in W4_K:
        w.append((f"w4-1m-k{k}", MIB, {"stall-peers": k}))
    w.append(("w4-256k-k128", 256 * KIB, {"stall-peers": 128}))
    w.append(
        (
            "w5",
            MIB,
            {
                "stall-peers": 0,
                "drainers": 4,
                "drain-size": 3 * MIB,
                "drain-read-bps": 512 * KIB,
                "episode-ms": 8000,
                "duration": 80,
            },
        )
    )
    return w


def cell(name, tcp_wmem, work, arm, **over):
    args = {**COMMON, **socket(tcp_wmem), **work, **ARMS[arm], **over}
    return {"name": name, "workload": name.rsplit("--", 1)[0], "arm": arm, "args": args}


def d_cells():
    return [cell(f"{w}--{arm}", t, a, arm) for w, t, a in workloads() for arm in ARMS]


def sensitivity_cells():
    w = {name: (t, a) for name, t, a in workloads()}
    cells = []
    t, a = w["w4-256k-k128"]
    for seg in (2, 4, 8, 16, 32, 64):
        size = 65483 if seg == 64 else seg * KIB
        for arm in GATED[:2]:
            cells.append(cell(f"w4-256k-k128-sseg{seg}k--{arm}", t, a, arm, **{"stall-seg": size}))
    for name in ("w4-256k-k128", "w2-6slow"):
        t, a = w[name]
        for arm in GATED[:2]:
            cells.append(cell(f"{name}-ov1280--{arm}", t, a, arm, **{"skb-overhead": 1280}))
    for k in (4, 16, 128):
        t, a = w[f"w4-1m-k{k}"]
        for gap in (0, 40, 530):
            for admit in (999, 1000, 1001):
                cells.append(
                    cell(
                        f"w4-1m-k{k}-gap{gap}-a{admit}--o0-whole",
                        t,
                        a,
                        "o0-whole",
                        **{"stall-gap-us": gap, "admit-ms": admit},
                    )
                )
    return cells


def seeds(spec):
    if "-" in spec:
        lo, hi = spec.split("-")
        return list(range(int(lo), int(hi) + 1))
    return [int(s) for s in spec.split(",")]


def command(binary, cell, seed):
    cmd = [binary]
    for flag, value in cell["args"].items():
        if value is True:
            cmd.append(f"--{flag}")
        elif value is not False:
            cmd += [f"--{flag}", str(value)]
    return cmd + ["--seed", str(seed)]


def run(binary, outdir, cell, seed, force):
    out = outdir / cell["name"] / f"seed-{seed}.json"
    if out.exists() and not force:
        return json.loads(out.read_text())
    out.parent.mkdir(parents=True, exist_ok=True)
    done = subprocess.run(command(binary, cell, seed), capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"{cell['name']} seed {seed}: exit {done.returncode}: {done.stderr.strip()}")
    out.write_text(done.stdout)
    return json.loads(done.stdout)


def ms(stat, key):
    """A percentile object's value in ms, or None when it has no values."""
    return None if stat is None else stat[key] / 1000


def row(d):
    fast, D = d["small"]["fast"], d["d"]
    large = D["large"]
    return {
        "fast_p99_ms": ms(fast["scheduled_to_admission_us"], "p99"),
        "fast_admit_to": fast["admit_timeouts"],
        "fast_not_within": d["small_e2e"]["not_within"],
        "large_req": large["requested"],
        "large_done": large["completed"],
        "large_us": [e["head_delivery_us"] for e in d["episodes"] if e["head_delivery_us"] is not None],
        "min_free": large["min_free"],
        "min_free_sampled": large["min_free_sampled"],
        "drain_req": D["drain"]["requested"],
        "drain_done": D["drain"]["completed"],
        "sends": D["sends"],
        "waited": D["sends_waited_for_room"],
        "gate": D["gate_waits"],
        "ends": D["ends"],
    }


def spread(values, fmt):
    v = [x for x in values if x is not None]
    if not v:
        return "-"
    missing = f" ({len(values) - len(v)} none)" if len(v) < len(values) else ""
    return f"{fmt.format(median(v))} [{fmt.format(min(v))}-{fmt.format(max(v))}]{missing}"


def summed(dicts):
    out = {}
    for d in dicts:
        for k, v in d.items():
            out[k] = out.get(k, 0) + v
    return out


def kinds(d):
    return ", ".join(f"{k} {v}" for k, v in sorted(d.items())) or "none"


def low(values):
    v = [x for x in values if x is not None]
    return min(v) if v else None


def summarise(rows):
    col = lambda k: [r[k] for r in rows]
    times = sorted(t for r in rows for t in r["large_us"])
    ends = {}
    for r in rows:
        for cause, by_kind in r["ends"].items():
            ends.setdefault(cause, []).append(by_kind)
    return {
        "fast": spread(col("fast_p99_ms"), "{:.2f}"),
        "fast_p99_max": max((x for x in col("fast_p99_ms") if x is not None), default=None),
        "fast_to": sum(col("fast_admit_to")),
        "large": f"{sum(col('large_done'))}/{sum(col('large_req'))}",
        "large_ms": f"{median(times) / 1000:.1f}, {times[-1] / 1000:.1f}" if times else "-",
        "min_free": low(col("min_free")),
        "min_free_sampled": low(col("min_free_sampled")),
        "drain": f"{sum(col('drain_done'))}/{sum(col('drain_req'))}",
        "sends": summed(col("sends")),
        "waited": summed(col("waited")),
        "gate": summed(col("gate")),
        "ends": {c: summed(v) for c, v in ends.items() if any(v)},
    }


def print_cell(cell, s, n):
    print(f"== {cell['name']}, n={n} seeds")
    print(f"  fast small p99 ms      {s['fast']}; admission timeouts {s['fast_to']}")
    print(f"  7 MiB completed        {s['large']}; completion ms median, max {s['large_ms']}")
    print(f"  fewest free slots      {s['min_free']} at every change, {s['min_free_sampled']} sampled")
    print(f"  drainers completed     {s['drain']}")
    print(f"  large sends            {kinds(s['sends'])}")
    print(f"  waited for room        {kinds(s['waited'])}")
    print(f"  waited at the gate     {kinds(s['gate'])}")
    for cause, by_kind in s["ends"].items():
        print(f"  ended, {cause:<15} {kinds(by_kind)}")


def table(cells, summaries):
    """One row per workload, one column per arm: fast p99 median (max) ms;
    7 MiB completed; fewest free slots; W5 drainers completed."""
    arms = list(dict.fromkeys(c["arm"] for c in cells))
    works = list(dict.fromkeys(c["workload"] for c in cells))
    by = {(c["workload"], c["arm"]): summaries[c["name"]] for c in cells}
    print()
    print("Per cell and arm: fast small p99 median (max over seeds) ms; 7 MiB replies completed;")
    print("fewest free slots during a 7 MiB reply; and in W5 the drainers' replies completed.")
    print()
    print("| cell | " + " | ".join(arms) + " |")
    print("| --- |" + " --- |" * len(arms))
    for w in works:
        out = []
        for a in arms:
            s = by.get((w, a))
            if s is None:
                out.append("")
                continue
            p50 = s["fast"].split(" ")[0]
            mx = s["fast_p99_max"]
            text = f"{p50} ({mx:.1f}); {s['large']}; {s['min_free']}"
            if w.startswith("w5"):
                text += f"; drains {s['drain']}"
            out.append(text)
        print(f"| {w} | " + " | ".join(out) + " |")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("binary")
    p.add_argument("outdir", type=Path)
    p.add_argument("--cells", default="d")
    p.add_argument("--seeds", default="1-5", help="a range a-b or a list a,b,c")
    p.add_argument("--jobs", type=int, default=os.cpu_count())
    p.add_argument("--force", action="store_true", help="rerun runs whose JSON exists")
    a = p.parse_args()

    if a.cells == "d":
        cells = d_cells()
    elif a.cells == "sensitivity":
        cells = sensitivity_cells()
    else:
        cells = json.loads(Path(a.cells).read_text())
        for c in cells:
            c.setdefault("workload", c["name"])
            c.setdefault("arm", "")
    names = [c["name"] for c in cells]
    if len(set(names)) != len(names):
        raise SystemExit("cell names repeat")
    jobs = [(c, s) for c in cells for s in seeds(a.seeds)]
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        results = list(pool.map(lambda j: run(a.binary, a.outdir, j[0], j[1], a.force), jobs))

    by_cell = {}
    for (cell, _), d in zip(jobs, results):
        by_cell.setdefault(cell["name"], []).append(row(d))
    summaries = {}
    for c in cells:
        rows = by_cell[c["name"]]
        summaries[c["name"]] = summarise(rows)
        print_cell(c, summaries[c["name"]], len(rows))
    table(cells, summaries)


if __name__ == "__main__":
    sys.exit(main())
