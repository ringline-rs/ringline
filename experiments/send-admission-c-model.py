#!/usr/bin/env python3
"""Run admission-model over a list of cells and seeds, and summarise each cell.

Experiment C's stage C1 (docs/send-admission-design.md, section 4). The model
is single-threaded, so the runs go to parallel processes, --jobs at a time.
Each run's JSON is written to OUTDIR/<cell>/seed-<n>.json, and an existing
file is reused unless --force is given, so a sweep can be resumed.

Cells come from --cells: "validation" (the default) is Experiment B's
contended case under o0 and o1 at admit_ms 500, 1000 and 2000 with
settle_ms 1000, the model's defaults otherwise. Any other value is a JSON
file holding a list of cells, each {"name": ..., "args": {...}}, where
"args" maps a flag without its leading dashes to its value, for example
{"name": "o3-slow", "args": {"order": "o3", "slow-conns": 8}}.

For each cell the summary prints the median and [min-max] over the seeds of:
small-reply end-to-end p99 and the small replies not delivered within
admit_ms (as admission-load counts them), for the fast readers;
scheduled-to-admission p99 of small replies to fast and to slow readers; small
replies' admission timeouts, settle aborts by reader, and O1 refusals; the
heads admitted, timed out and settle-aborted, of those requested; the head's
admission delay, median and max over the heads admitted; the head's delivery
time; and L, the slots small replies of fast and slow readers held,
time-averaged over each head's wait (the run's median over its episodes),
with L unsettled, the slots of their admitted replies not yet settled, which
is how admission-server counts it.

Usage: send-admission-c-model.py BINARY OUTDIR [--cells validation|FILE]
       [--seeds 1-20] [--jobs N] [--force]
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median


def validation_cells():
    cells = []
    for order in ("o0", "o1"):
        for admit in (500, 1000, 2000):
            cells.append(
                {
                    "name": f"{order}-admit{admit}",
                    "args": {"order": order, "admit-ms": admit, "settle-ms": 1000},
                }
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
    e2e, small, heads = d["small_e2e"], d["small"], d["heads"]
    return {
        "e2e_p99_ms": ms(e2e["latency_us"], "p99"),
        "not_within": e2e["not_within"],
        "offered": e2e["offered"],
        "sched_adm_fast_ms": ms(small["fast"]["scheduled_to_admission_us"], "p99"),
        "sched_adm_slow_ms": ms(small["slow"]["scheduled_to_admission_us"], "p99"),
        "small_adm_to": small["admit_timeouts"],
        "small_settle_fast": small["fast"]["settle_aborts"],
        "small_settle_slow": small["slow"]["settle_aborts"],
        "refused": small["refused"],
        "heads_req": heads["requested"],
        "heads_adm": heads["admitted"],
        "heads_to": heads["admit_timeouts"],
        "heads_abort": heads["settle_aborts"],
        "head_adm_p50_ms": ms(heads["admission_us"], "p50"),
        "head_adm_max_ms": ms(heads["admission_us"], "max"),
        "head_dlv_p50_ms": ms(heads["delivery_us"], "p50"),
        "l_fast": heads["l_fast_median"],
        "l_slow": heads["l_slow_median"],
        "lu_fast": heads["l_unsettled_fast_median"],
        "lu_slow": heads["l_unsettled_slow_median"],
    }


def spread(values, fmt):
    v = [x for x in values if x is not None]
    if not v:
        return "-"
    if len(v) < len(values):
        missing = f" ({len(values) - len(v)} none)"
    else:
        missing = ""
    return f"{fmt.format(median(v))} [{fmt.format(min(v))}-{fmt.format(max(v))}]{missing}"


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("binary")
    p.add_argument("outdir", type=Path)
    p.add_argument("--cells", default="validation")
    p.add_argument("--seeds", default="1-20", help="a range a-b or a list a,b,c")
    p.add_argument("--jobs", type=int, default=os.cpu_count())
    p.add_argument("--force", action="store_true", help="rerun runs whose JSON exists")
    a = p.parse_args()

    cells = validation_cells() if a.cells == "validation" else json.loads(Path(a.cells).read_text())
    names = [c["name"] for c in cells]
    if len(set(names)) != len(names):
        raise SystemExit("cell names repeat")
    jobs = [(c, s) for c in cells for s in seeds(a.seeds)]
    with ThreadPoolExecutor(max_workers=a.jobs) as pool:
        results = list(pool.map(lambda j: run(a.binary, a.outdir, j[0], j[1], a.force), jobs))

    by_cell = {}
    for (cell, _), d in zip(jobs, results):
        by_cell.setdefault(cell["name"], []).append(row(d))
    for cell in cells:
        rows = by_cell[cell["name"]]
        col = lambda k: [r[k] for r in rows]
        print(f"== {cell['name']}: {json.dumps(cell['args'])}, n={len(rows)} seeds")
        print(f"  small e2e p99 ms      {spread(col('e2e_p99_ms'), '{:.1f}')}")
        print(f"  small not within      {spread(col('not_within'), '{:.0f}')} of ~{median(col('offered')):.0f}")
        print(
            f"  small sched-adm p99   fast {spread(col('sched_adm_fast_ms'), '{:.1f}')} ms, "
            f"slow {spread(col('sched_adm_slow_ms'), '{:.1f}')} ms"
        )
        print(
            f"  small admit timeouts  {spread(col('small_adm_to'), '{:.0f}')}; settle aborts fast "
            f"{spread(col('small_settle_fast'), '{:.0f}')}, slow {spread(col('small_settle_slow'), '{:.0f}')}; "
            f"refused {spread(col('refused'), '{:.0f}')}"
        )
        print(
            f"  heads admitted        {sum(col('heads_adm'))}/{sum(col('heads_req'))}, timed out "
            f"{sum(col('heads_to'))}, settle-aborted {sum(col('heads_abort'))}"
        )
        print(
            f"  head admission ms     p50 {spread(col('head_adm_p50_ms'), '{:.1f}')}, "
            f"max {spread(col('head_adm_max_ms'), '{:.1f}')}"
        )
        print(f"  head delivery p50 ms  {spread(col('head_dlv_p50_ms'), '{:.1f}')}")
        print(
            f"  L fast / slow         {spread(col('l_fast'), '{:.1f}')} / "
            f"{spread(col('l_slow'), '{:.1f}')} slots"
        )
        print(
            f"  L unsettled f / s     {spread(col('lu_fast'), '{:.1f}')} / "
            f"{spread(col('lu_slow'), '{:.1f}')} slots"
        )


if __name__ == "__main__":
    sys.exit(main())
