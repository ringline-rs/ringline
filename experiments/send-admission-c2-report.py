#!/usr/bin/env python3
"""Summarise Experiment C2's runs and apply the design's decision rule.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run of send-admission-c0.toml. Runs are parsed by
send-admission-c0-report.py's `one`. A cell is a workload configuration
(workload, slow readers, admit_ms, pipeline, sends outside the FIFO); an arm
is an order (O1 is small_send=send).

Per cell and arm, over its repetitions:
- heads: admitted, timed out, the median of the per-run median admission
  delays, and the maximum over every admitted head;
- fast: the median and range of the per-run p99 of the fast small replies'
  delay from scheduled time to admission, and the fast small replies beyond
  admit_ms or not admitted, summed;
- L / S: the median of the per-run medians.

Decision (docs/send-admission-design.md, section 4, Experiment C):
- a W2 cell is contended if O1 timed out at least one head in it;
- an order passes when, in every W1 cell and every contended W2 cell, it has
  no more head timeouts than O0, its maximum head delay exceeds O0's by at
  most the larger of 10% and the spread of O0's per-run maxima, its count of
  fast small replies beyond admit_ms (or not admitted) is no more than O0's,
  and in W1 its fast small p99 (median over runs) is at most 10 ms; and it
  admits every head in the W2 cell with no slow readers.
The uncontended CPU condition comes from send-admission-c-echo.toml and is
not checked here.
"""

import importlib.util
import pathlib
import sys
from collections import defaultdict
from statistics import median

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("c0", here / "send-admission-c0-report.py")
c0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c0)

NAMES = {
    "strict": "O0",
    "first-fit": "O2",
    "bounded": "O3",
    "bounded-idle": "O4",
    "split-pool": "O5",
    "budget": "O7",
    "budget-idle": "O7w",
}
CELL_KEYS = ("workload", "slow_conns", "admit_ms", "pipeline", "outside_conns", "host")
ARM_ORDER = ["O0", "O1", "O2", "O3", "O4", "O5", "O7", "O7w"]


def arm(run):
    if run.get("small_send") == "send":
        return "O1"
    return NAMES.get(run.get("order", "strict"), run.get("order"))


def fmt(x, spec=".1f"):
    return "-" if x is None else format(x, spec)


def summarise(rows):
    heads_max = [r["head_max"] for r in rows if r["head_max"] is not None]
    meds = [r["head_med"] for r in rows if r["head_med"] is not None]
    p99 = [r["fast_p99"] for r in rows if r["fast_p99"] is not None]
    ls = [r["ls_med"] for r in rows if r["ls_med"] is not None]
    return dict(
        n=len(rows),
        heads=sum(r["heads"] for r in rows),
        timeouts=sum(r["head_to"] for r in rows),
        other_na=sum(r["head_na"] for r in rows),
        head_med=median(meds) if meds else None,
        head_max=max(heads_max) if heads_max else None,
        run_maxes=heads_max,
        fast_p99=median(p99) if p99 else None,
        fast_p99_range=(min(p99), max(p99)) if p99 else None,
        fast_bad=sum(r["fast_beyond"] + r["fast_na"] for r in rows),
        ls=median(ls) if ls else None,
        reconnects=sum(r["slow_reconnects"] for r in rows),
    )


def main():
    rows = []
    for a in sys.argv[1:]:
        p = pathlib.Path(a)
        try:
            rows.append(c0.one(p))
        except SystemExit as e:
            print(f"skipped: {e}", file=sys.stderr)
    cells = defaultdict(lambda: defaultdict(list))
    for r in rows:
        # Runs before the host parameter existed ran on hv03.
        key = tuple((k, r["run"].get(k, "hv03" if k == "host" else "-")) for k in CELL_KEYS)
        cells[key][arm(r["run"])].append(r)

    verdict = defaultdict(list)  # arm -> reasons it fails
    seen_arms = set()
    for key in sorted(cells):
        name = " ".join(f"{k}={v}" for k, v in key)
        arms = {a: summarise(rs) for a, rs in cells[key].items()}
        seen_arms |= set(arms)
        w1 = dict(key)["workload"] == "W1"
        no_slow = dict(key).get("slow_conns") == "0"
        o0 = arms.get("O0")
        o1 = arms.get("O1")
        contended = w1 or (o1 is not None and o1["timeouts"] > 0)
        print(f"\n== {name}  ({'W1' if w1 else ('contended' if contended else 'not contended')})")
        print("arm  runs heads  timeouts other | head med  head max | fast p99 [range]        fast bad | L/S  reconn")
        for a in sorted(arms, key=lambda x: ARM_ORDER.index(x) if x in ARM_ORDER else 99):
            s = arms[a]
            rng = s["fast_p99_range"]
            rng_s = f"[{fmt(rng[0])}-{fmt(rng[1])}]" if rng else "-"
            print(
                f"{a:4} {s['n']:>4} {s['heads']:>5} {s['timeouts']:>9} {s['other_na']:>5} | "
                f"{fmt(s['head_med']):>8} {fmt(s['head_max']):>9} | {fmt(s['fast_p99']):>8} {rng_s:<15} "
                f"{s['fast_bad']:>8} | {fmt(s['ls'], '.2f'):>4} {s['reconnects']:>6}"
            )
        if o0 is None:
            print("  no O0 runs: no decision for this cell")
            continue
        spread = (max(o0["run_maxes"]) - min(o0["run_maxes"])) if o0["run_maxes"] else 0.0
        allowance = 0.0
        if o0["head_max"] is not None:
            allowance = max(0.10 * o0["head_max"], spread)
            print(f"  O0 head max {fmt(o0['head_max'])} ms, spread of O0 run maxima {fmt(spread)} ms, allowance {fmt(allowance)} ms")
        for a, s in arms.items():
            if a in ("O0", "O1"):
                continue
            if no_slow and not w1 and s["timeouts"] + s["other_na"] > 0:
                verdict[a].append(f"{name}: a head not admitted with no slow readers")
            if not contended:
                continue
            if s["timeouts"] > o0["timeouts"]:
                verdict[a].append(f"{name}: {s['timeouts']} head timeouts against O0's {o0['timeouts']}")
            if s["head_max"] is not None and o0["head_max"] is not None and s["head_max"] > o0["head_max"] + allowance:
                verdict[a].append(f"{name}: head max {fmt(s['head_max'])} > {fmt(o0['head_max'] + allowance)} ms")
            if s["fast_bad"] > o0["fast_bad"]:
                verdict[a].append(f"{name}: {s['fast_bad']} fast replies beyond the limit against O0's {o0['fast_bad']}")
            if w1 and (s["fast_p99"] is None or s["fast_p99"] > 10.0):
                verdict[a].append(f"{name}: fast p99 {fmt(s['fast_p99'])} ms > 10 ms")

    w2_contended = any(
        dict(k)["workload"] == "W2" and "O1" in v and summarise(v["O1"])["timeouts"] > 0
        for k, v in cells.items()
    )
    print("\n== decision")
    if not w2_contended:
        print("no W2 cell is contended: the experiment stops here (design, Decision)")
    for a in sorted(seen_arms - {"O0", "O1"}, key=lambda x: ARM_ORDER.index(x) if x in ARM_ORDER else 99):
        reasons = verdict.get(a, [])
        print(f"{a:4} {'passes' if not reasons else 'fails'}")
        for reason in reasons:
            print(f"       {reason}")


if __name__ == "__main__":
    main()
