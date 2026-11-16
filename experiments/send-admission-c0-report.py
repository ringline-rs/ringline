#!/usr/bin/env python3
"""Summarise send-admission-c0.toml runs.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run. The RUN line comes from the job's logs.json. admission-load's
and admission-server's JSON come from results.tgz, or from the LOAD and
SERVER lines when the directory has no results.tgz.

Prints one row per run, then one line per cell: the runs whose RUN
parameters agree in everything but rep. Runs are labelled by the RUN
parameters that differ between the runs given.

Columns, per run (the server's figures count requests scheduled in the
load's measurement window):
- fast_p99 and fast_beyond: small replies to fast readers, the p99 of the
  delay from scheduled send time to admission in ms, and the count of those
  delays beyond admit_ms. fast_na counts the fast small requests not
  admitted (admission timeout, refusal, abort, failure).
- head_med, head_max, head_to, head_na: over the heads, the large replies
  tagged 0xffffffff, the median and maximum of the same delay in ms over the
  heads admitted, the heads whose admission timed out, and the heads not
  admitted for another reason.
- ls_med: per head, L / S, where L is the mean of the slots held by small
  replies to slow readers over the samples during the head's wait (from its
  scheduled time to its admission or removal) and S is pool_slots less the
  head's slots; the median over the heads with at least one sample. ls_max is
  the largest.
- slow: the slow readers' replies delivered within admit_ms of those offered,
  lost, and reconnects (from the load), and their small replies the server
  settle-aborted or did not admit. Replies a slow reader has not read when
  the load stops count as lost, and their connection's teardown can add
  settle aborts at the end of the run.
- drain: drainer replies read in full of those requested, and the median of
  their times in ms.
- contended: at least one head timed out.
- passed, B, hold_p99: under order=budget, the small replies (fast and slow)
  the runtime admitted past a waiting head; the mean over the window's
  samples of B, the slots held by sends admitted past a head; and the
  largest per-class p99, in ms, of how long a passing reply held its slots
  from admission to settlement. `-` for a server without these keys.

The RUN line gives order, budget and tls for runs of the current spec. For
older runs, each is taken from the server's JSON if it has the key, and
otherwise is strict, 32 and 0, the values those runs ran with, so runs
before and after the parameters existed fall in the same cell.

Per cell: the median [min-max] over repetitions of fast_p99, fast_beyond,
head_med, head_max and ls_med, the total of head_to over the heads, and the
contended runs.
"""

import io
import json
import math
import sys
import tarfile
from collections import defaultdict
from pathlib import Path
from statistics import median

HEAD_TAG = 0xFFFFFFFF
NOT_CELL = {"rep", "load_rc"}
# The value of a RUN parameter added to the spec after runs were made, for
# a run whose RUN line and server JSON both lack it.
RUN_DEFAULTS = {"order": "strict", "budget": "32", "tls": "0"}


def log_lines(root: Path):
    logs = next(root.rglob("logs.json"), None)
    if logs is None:
        raise SystemExit(f"{root}: no logs.json")
    return [e.get("text", "") for e in json.loads(logs.read_text())["events"]]


def from_tgz(root: Path):
    """load.json and server.json from the run's results.tgz, if it has one."""
    for tgz in root.rglob("results.tgz"):
        with tarfile.open(fileobj=io.BytesIO(tgz.read_bytes())) as t:
            files = {Path(m.name).name: m for m in t.getmembers() if m.isfile()}
            if "load.json" in files and "server.json" in files:
                read = lambda n: json.loads(t.extractfile(files[n]).read())
                return read("load.json"), read("server.json")
    return None


def parse_run(line: str):
    words = line.split("RUN ", 1)[1].split()
    return dict(w.split("=", 1) for w in words if "=" in w)


def ms(us):
    return None if us is None else us / 1000


def one(root: Path):
    run = load = server = None
    for text in log_lines(root):
        if text.startswith("RUN "):
            run = parse_run(text)
        elif text.startswith("LOAD "):
            load = json.loads(text[5:])
        elif text.startswith("SERVER "):
            server = json.loads(text[7:])
    raw = from_tgz(root)
    if raw:
        load, server = raw
    if not (run and load and server):
        raise SystemExit(f"{root}: missing RUN, LOAD or SERVER")
    raw_run = dict(run)
    for k, default in RUN_DEFAULTS.items():
        if k not in run:
            v = server.get(k, default)
            run[k] = ("1" if v else "0") if isinstance(v, bool) else str(v)
    st = server["statistics"]
    fast = st["classes"]["small_fast"]
    slow_c = st["classes"]["small_slow"]
    pool, slot = server["pool_slots"], server["slot_size"]
    heads = [r for r in st["large_replies"] if r["tag"] == HEAD_TAG]
    admitted = [ms(h["scheduled_us"]) for h in heads if h["scheduled_us"] is not None]
    ls = []
    for h in heads:
        s = pool - math.ceil(h["len"] / slot)
        l = h["held"]["small_slow"]
        if l is not None and s > 0:
            ls.append(l / s)
    drains = [x for ep in load["drainers"]["ms"] for x in ep]
    slow = load["slow"]
    small = (fast, slow_c)
    passed = sum(c["passed"] for c in small) if all("passed" in c for c in small) else None
    hold_p99 = [ms(c["passing_hold_us"]["p99"]) for c in small if "passing_hold_us" in c]
    hold_p99 = [x for x in hold_p99 if x is not None]
    window = st.get("held_window") or {}
    counters = st.get("admission_counters") or {}
    return dict(
        root=str(root),
        run=run,
        raw_run=raw_run,
        rc=int(run.get("load_rc", "-1")),
        fast_p99=ms(fast["scheduled_us"]["p99"]),
        fast_beyond=fast["beyond_admit_limit"],
        fast_na=sum(fast["not_admitted"].values()),
        heads=len(heads),
        head_med=median(admitted) if admitted else None,
        head_max=max(admitted) if admitted else None,
        head_to=sum(1 for h in heads if h["not_admitted"] == "admit_timeout"),
        head_na=sum(1 for h in heads if h["not_admitted"] not in (None, "admit_timeout")),
        ls_med=median(ls) if ls else None,
        ls_max=max(ls) if ls else None,
        slow_offered=slow["offered"],
        slow_within=slow["delivered_within"],
        slow_lost=slow["lost"],
        slow_reconnects=slow["reconnects"],
        slow_settle_aborts=slow_c["ended"]["settle_abort"],
        slow_na=sum(slow_c["not_admitted"].values()),
        drain_ok=sum(1 for x in drains if x is not None),
        drain_n=len(drains),
        drain_med=median([x for x in drains if x is not None]) if any(x is not None for x in drains) else None,
        load_not_within=load["not_within"],
        outside=load["outside"],
        passed=passed,
        b_mean=window.get("passing_held"),
        b_max=counters.get("passing_held_max"),
        hold_p99=max(hold_p99) if hold_p99 else None,
    )


def fmt(x, spec=".1f"):
    return "-" if x is None else format(x, spec)


def spread(xs, spec=".1f"):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    return f"{format(median(xs), spec)} [{format(min(xs), spec)}-{format(max(xs), spec)}]"


def main():
    rows = [one(Path(a)) for a in sys.argv[1:]]
    if not rows:
        raise SystemExit("usage: send-admission-c0-report.py RUN_DIR...")
    keys = sorted({k for r in rows for k in r["run"]} - NOT_CELL)
    varying = [k for k in keys if len({r["run"].get(k) for r in rows}) > 1]
    for r in rows:
        r["cell"] = tuple(r["run"].get(k) for k in keys)
        r["label"] = " ".join(f"{k}={r['run'].get(k)}" for k in varying) or "(one cell)"
    rows.sort(key=lambda r: (r["label"], r["run"].get("rep", "")))
    print(
        "label | rep rc | fast_p99 fast_beyond fast_na | heads head_med head_max head_to head_na "
        "| ls_med ls_max | slow within/offered lost reconn s_abort s_na | drain ok/n med | contended "
        "| passed B hold_p99"
    )
    for r in rows:
        print(
            f"{r['label']} | {r['run'].get('rep')} {r['rc']} | {fmt(r['fast_p99'])} {r['fast_beyond']} {r['fast_na']} "
            f"| {r['heads']} {fmt(r['head_med'])} {fmt(r['head_max'])} {r['head_to']} {r['head_na']} "
            f"| {fmt(r['ls_med'], '.2f')} {fmt(r['ls_max'], '.2f')} "
            f"| {r['slow_within']}/{r['slow_offered']} {r['slow_lost']} {r['slow_reconnects']} "
            f"{r['slow_settle_aborts']} {r['slow_na']} "
            f"| {r['drain_ok']}/{r['drain_n']} {fmt(r['drain_med'], '.0f')} | {r['head_to'] > 0} "
            f"| {fmt(r['passed'], 'd')} {fmt(r['b_mean'], '.2f')} {fmt(r['hold_p99'])}"
        )
    print("\n== per cell: median [min-max] over repetitions")
    cells = defaultdict(list)
    for r in rows:
        cells[r["cell"]].append(r)
    for _, rs in sorted(cells.items(), key=lambda kv: kv[1][0]["label"]):
        print(
            f"{rs[0]['label']}: n={len(rs)}; fast_p99 {spread([r['fast_p99'] for r in rs])} ms; "
            f"fast_beyond {spread([r['fast_beyond'] for r in rs], '.0f')}; "
            f"head_med {spread([r['head_med'] for r in rs])} ms; "
            f"head_max {spread([r['head_max'] for r in rs])} ms; "
            f"head timeouts {sum(r['head_to'] for r in rs)}/{sum(r['heads'] for r in rs)}; "
            f"L/S {spread([r['ls_med'] for r in rs], '.2f')}; "
            f"contended {sum(r['head_to'] > 0 for r in rs)}/{len(rs)}; "
            f"passed {spread([r['passed'] for r in rs], '.0f')}; "
            f"B {spread([r['b_mean'] for r in rs], '.2f')}"
        )


if __name__ == "__main__":
    main()
