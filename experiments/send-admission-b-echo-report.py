#!/usr/bin/env python3
"""Summarise send-admission-b-echo.toml runs.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run. Per cell, joins the server's `WORKER` line (the worker thread's
schedstat CPU over the window) with the client's JSON for that window:

    cpu_us_per_op = cpu_ns / (ops_per_sec * wall_ns / 1e9) / 1000

Prints one row per cell, then per run and arm the median and range over the
measured (non-warm-up) cells, and each arm's median against bytes-nowait's.
"""

import io
import json
import re
import sys
import tarfile
from pathlib import Path
from statistics import median

ARMS = [
    "bytes-nowait",
    "bytes-admitted",
    "bytes-admitted-timeout",
    "bytes-admitted-await",
    "bytes-nowait-defer",
]
WORKER = re.compile(
    r"WORKER cell=(\d+) tag=(\S+) arm=(\S+) window=(\S+) cpu_ns=(\d+) wall_ns=(\d+)"
)
SERVER = re.compile(r"SERVER cell=(\d+) .*bytes_send_failed=(\d+) admit_timeouts=(\d+) settle_timeouts=(\d+)")


def one_run(root: Path):
    server_logs = next(root.rglob("server/logs.json"))
    results = next(root.rglob("client/results.tgz"))
    workers, faults = {}, {}
    for e in json.loads(server_logs.read_text())["events"]:
        text = e.get("text", "")
        if m := WORKER.search(text):
            k, tag, arm, window, cpu, wall = m.groups()
            workers[(int(k), window)] = (tag, arm, int(cpu), int(wall))
        if m := SERVER.search(text):
            faults[int(m.group(1))] = tuple(int(x) for x in m.groups()[1:])
    client = {}
    with tarfile.open(results) as tar:
        for member in tar.getmembers():
            name = Path(member.name).name
            if m := re.match(r"c(\d+)-\S+-(closed|open)\.json$", name):
                data = json.load(io.TextIOWrapper(tar.extractfile(member)))
                client[(int(m.group(1)), m.group(2))] = data
    rows = []
    for (k, window), (tag, arm, cpu, wall) in sorted(workers.items()):
        c = client.get((k, window))
        if c is None:
            print(f"{root.name}: cell {k} {window}: no client result", file=sys.stderr)
            continue
        ops = c["ops_per_sec"] * wall / 1e9
        rows.append(
            dict(
                cell=k,
                tag=tag,
                arm=arm,
                window=window,
                ops_per_sec=c["ops_per_sec"],
                busy=cpu / wall,
                cpu_us_per_op=cpu / ops / 1000,
                p99_us=c["p99_ns"] / 1000,
                p999_us=c["p999_ns"] / 1000,
                faults=faults.get(k),
            )
        )
    return rows


def main():
    runs = [(Path(a).name, one_run(Path(a))) for a in sys.argv[1:]]
    for name, rows in runs:
        print(f"== {name}")
        print("cell tag     arm                     window  ops/s    busy   us/op  p99_us  p999_us faults")
        for r in rows:
            print(
                f"{r['cell']:>4} {r['tag']:<8} {r['arm']:<23} {r['window']:<7} {r['ops_per_sec']:>8.0f} "
                f"{r['busy']:>6.3f} {r['cpu_us_per_op']:>6.3f} {r['p99_us']:>7.0f} {r['p999_us']:>8.0f} {r['faults']}"
            )
    print("\n== median [min-max] over rep1..rep4, and the median against bytes-nowait's")
    for window, stat in (("closed", "cpu_us_per_op"), ("closed", "ops_per_sec"), ("open", "cpu_us_per_op"), ("open", "p99_us")):
        print(f"-- {window} {stat}")
        for name, rows in runs:
            base = None
            for arm in ARMS:
                v = [r[stat] for r in rows if r["arm"] == arm and r["window"] == window and r["tag"] != "warmup"]
                if not v:
                    continue
                m = median(v)
                base = m if arm == ARMS[0] else base
                rel = f"{(m / base - 1) * 100:+.1f}%" if base else ""
                print(f"   {name:<40} {arm:<23} n={len(v)} {m:>10.3f} [{min(v):.3f}-{max(v):.3f}] {rel}")


if __name__ == "__main__":
    main()
