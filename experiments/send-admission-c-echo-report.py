#!/usr/bin/env python3
"""Summarise send-admission-c-echo.toml runs.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run. Cells are parsed by send-admission-b-echo-report.py's `one_run`.

Per run, window and statistic, prints each arm's median and range over the
measured (non-warm-up) cells, its spread ((max - min) / median, the A-vs-A
floor of that arm), and its median against a base arm:

- the orders (budget-idle, split-pool, bounded-idle) against strict;
- send and strict against nowait. strict against nowait is Experiment B's
  bytes-admitted against bytes-nowait, the control shared with that run.

Then, over every run, as Experiment B's journal judged its arms: each arm
paired by round with its base arm (the change, how many rounds it was
higher, the median and range), and the base arm's floor, the median change
between its consecutive rounds within one boot.
"""

import importlib.util
import pathlib
import sys
from statistics import median

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("brep", here / "send-admission-b-echo-report.py")
brep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(brep)

GROUPS = [
    ("strict", ["budget-idle", "split-pool", "bounded-idle"]),
    ("nowait", ["send", "strict"]),
]
STATS = (
    ("closed", "cpu_us_per_op"),
    ("closed", "ops_per_sec"),
    ("open", "cpu_us_per_op"),
    ("open", "p99_us"),
)


def main():
    runs = [(pathlib.Path(a).name, brep.one_run(pathlib.Path(a))) for a in sys.argv[1:]]
    for name, rows in runs:
        faulted = [r for r in rows if r["faults"] and any(r["faults"])]
        for r in faulted:
            print(f"{name}: cell {r['cell']} {r['arm']} {r['window']}: faults {r['faults']}")
    for window, stat in STATS:
        print(f"\n-- {window} {stat}: median [min-max] spread, and against the base arm")
        for name, rows in runs:
            def values(arm):
                return [
                    r[stat]
                    for r in rows
                    if r["arm"] == arm and r["window"] == window and r["tag"] != "warmup"
                ]

            for base, arms in GROUPS:
                b = values(base)
                if not b:
                    print(f"   {name}: no {base} cells")
                    continue
                bm = median(b)
                for arm in [base, *arms]:
                    v = values(arm)
                    if not v:
                        print(f"   {name:<40} {arm:<13} no cells")
                        continue
                    m = median(v)
                    spread = (max(v) - min(v)) / m * 100
                    rel = "" if arm == base else f"{(m / bm - 1) * 100:+.1f}% vs {base}"
                    print(
                        f"   {name:<40} {arm:<13} n={len(v)} {m:>10.3f} "
                        f"[{min(v):.3f}-{max(v):.3f}] {spread:4.1f}% {rel}"
                    )
    paired(runs)


def by_round(rows, arm, window, stat):
    return {
        r["tag"]: r[stat]
        for r in rows
        if r["arm"] == arm and r["window"] == window and r["tag"] != "warmup"
    }


def paired(runs):
    print("\n== paired by round over every run: change against the base arm")
    for window, stat in STATS:
        print(f"-- {window} {stat}")
        for base, arms in GROUPS:
            steps = []
            for _, rows in runs:
                b = by_round(rows, base, window, stat)
                tags = sorted(b)
                steps += [abs(b[t1] / b[t0] - 1) * 100 for t0, t1 in zip(tags, tags[1:])]
            floor = f"{median(steps):.1f}% (n={len(steps)}, max {max(steps):.1f}%)" if steps else "-"
            print(f"   {base:<13} floor, consecutive rounds: {floor}")
            for arm in arms:
                d = []
                for _, rows in runs:
                    b = by_round(rows, base, window, stat)
                    a = by_round(rows, arm, window, stat)
                    d += [(a[t] / b[t] - 1) * 100 for t in sorted(b) if t in a]
                if not d:
                    continue
                higher = sum(x > 0 for x in d)
                print(
                    f"   {arm:<13} vs {base:<7} n={len(d)} higher in {higher}, "
                    f"median {median(d):+.1f}% [{min(d):+.1f}% to {max(d):+.1f}%]"
                )


if __name__ == "__main__":
    main()
