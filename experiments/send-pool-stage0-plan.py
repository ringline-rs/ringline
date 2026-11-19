#!/usr/bin/env python3
"""Write a plan for send-pool-stage0.toml, base64-encoded, to stdout.

Usage: send-pool-stage0-plan.py calibration
       send-pool-stage0-plan.py matrix REP
       send-pool-stage0-plan.py batchretest REP

The cells, arms and fixed arguments are those of
docs/journal/2026-11-send-pool-stage0.md. A matrix plan holds one run of
every cell under every arm and order, the arms interleaved within each cell
and their order rotated by REP; the first plan (REP 1) also holds the A/A
runs of idle and bulk.
"""
import base64
import sys

SERVER = ("--small-send admitted --admit-limit-ms 60000 --settle-limit-ms 60000 "
          "--pipeline 4096 --pool-slots 8192 --slot-size 16448")
LOAD = "--duration 30 --warmup 4 --within-ms 10 --stall-peers 0 --large-size 0"
PROBE = "--small-conns 16 --small-rate 2000 --small-size 1024"
NOPROBE = "--small-conns 0"
SLOW = ("--slow-rate 100 --slow-size 65536 --slow-read-bps 1000000 "
        "--slow-rcvbuf 4096")


def batch(k):
    return (f"{NOPROBE} --batch-conns 1 --batch-requests {k} --batch-size 1024 "
            "--batch-rcvbuf 4096 --batch-sndbuf 4096 --batch-round-limit-ms 10000")


CELLS = {
    "slow1": f"{PROBE} --slow-conns 1 {SLOW}",
    "slow4": f"{PROBE} --slow-conns 4 {SLOW}",
    "slow16": f"{PROBE} --slow-conns 16 {SLOW}",
    "mixed": f"{PROBE} --slow-conns 4 {SLOW} --fast-conns 4 --fast-size 122880 --fast-depth 4",
    "batch2000": batch(2000),
    "batch6000": batch(6000),
    "batch10000": batch(10000),
    "idle": f"{NOPROBE} --fast-conns 4 --fast-size 1024 --fast-depth 64",
    "bulk": f"{NOPROBE} --fast-conns 1 --fast-size 1048576 --fast-depth 4",
}
ARMS = {"cap0": "", "cap16": "--conn-slot-cap 16", "cap64": "--conn-slot-cap 64"}
ORDERS = ["budget", "strict"]


def line(cell, arm, order):
    return (f"{cell}-{arm}-{order}|{SERVER} --order {order} {ARMS[arm]}"
            f"|{LOAD} {CELLS[cell]}")


SMALLBUF = "net.ipv4.tcp_rmem=4096 8192 16384;net.ipv4.tcp_wmem=4096 8192 65536"


def batchretest(rep):
    """batch-K at K = 500, 2,000 and 10,000, unchanged and M = 16, budget
    order, with the server's socket buffers held small by the sysctls."""
    out = []
    arms = ["cap0", "cap16"]
    for i, k in enumerate([500, 2000, 10000]):
        a = arms if (rep + i) % 2 == 0 else arms[::-1]
        for arm in a:
            out.append(f"sbatch{k}-{arm}-budget|{SERVER} --order budget {ARMS[arm]}"
                       f"|{LOAD} {batch(k)}|{SMALLBUF}")
    return out


def calibration():
    return [
        line("slow4", "cap0", "budget"),
        line("slow4", "cap16", "budget"),
        line("batch10000", "cap0", "budget"),
        line("batch10000", "cap16", "budget"),
        line("batch2000", "cap16", "budget"),
        line("bulk", "cap0", "budget"),
        line("bulk", "cap16", "budget"),
        line("idle", "cap16", "budget"),
    ]


def matrix(rep):
    out = []
    if rep == 1:
        out += [line("idle", "cap0", "budget").replace("idle-cap0", "idle-aa", 1)
                for _ in range(4)]
        out += [line("bulk", "cap0", "budget").replace("bulk-cap0", "bulk-aa", 1)
                for _ in range(4)]
    arms = list(ARMS)
    for i, cell in enumerate(CELLS):
        for order in ORDERS:
            k = (rep + i) % len(arms)
            for arm in arms[k:] + arms[:k]:
                out.append(line(cell, arm, order))
    return out


def main():
    if sys.argv[1] == "calibration":
        lines = calibration()
    elif sys.argv[1] == "batchretest":
        lines = batchretest(int(sys.argv[2]))
    else:
        lines = matrix(int(sys.argv[2]))
    text = "\n".join(" ".join(l.split()) for l in lines) + "\n"
    sys.stdout.write(base64.b64encode(text.encode()).decode())


if __name__ == "__main__":
    main()
