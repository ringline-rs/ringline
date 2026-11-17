#!/usr/bin/env python3
"""Summarise Experiment D's runs and apply the design's decision rule.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run of send-admission-d.toml. The RUN and WORKER lines come from the
job's logs.json; admission-load's and admission-server's JSON, worker.txt,
ss.log and the nstat and sockstat files come from results.tgz.
send-admission-c0-report.py's logs.json reader and RUN parser are used.

A run whose logs.json has no RUN line is skipped. A run with a RUN line whose
results cannot be read is a failed run, counted in its cell and arm with its
reason: the server had no rl-work-0 thread (named from the job's "no
rl-work-0 thread" line), there is no results.tgz (the SERVER log line holds
only a summary), results.tgz is truncated or not a gzip tar, it has no
load.json or server.json, or they do not parse or lack a field. Every skip
and failed run is printed on stdout with its reason. A failed run's figures
are unknown, so every figure below is over the runs that did not fail.

An arm is (order, budget, stream_piece, stream_gate). A cell is (workload,
stall_peers, tcp_wmem_max, drainers, drain_read_bps, pipeline, admit_ms,
host). Runs are grouped by cell and arm and never merged across either. If
a cell's runs differ in any other RUN parameter (other than rep and
load_rc), the cell is split by those parameters, all its arms with it, and a
warning is printed; each part is then a cell of its own, in the decision
too.

Per cell and arm, over its runs:
- fast: the per-run p99 of the fast small replies' delay from scheduled time
  to admission, in ms, as median [min-max] and maximum; and the fast small
  replies beyond admit_ms or not admitted, summed and per run;
- 7 MiB: the heads (tag 0xffffffff) the client read in full, of those
  requested, and their time from request to last byte (median, max) over
  the completed ones, in ms; in U, the closed loop's replies;
- drain: the drainers' replies read in full, of those requested (in W5,
  the slow readers of large replies);
- free: the fewest free main-region slots during a head: the smaller of the
  server's 10 ms samples over the head and its reads just after each
  admission of the head or its pieces; the minimum over the runs, the median
  of the per-run minima, and the heads with neither figure;
- waited: pieces whose SendCompletion waited for room, of the pieces sent,
  by connection: stalled peers (tags below 0x80000000), drainers, and other
  (the head);
- aborts by cause, summed;
- U: per run the closed loop's median and p99 per reply in microseconds and
  the worker's CPU per byte (cpu_ns from the WORKER line over the bytes of
  every reply the loop read, its uncounted warmup included; a missing or
  zero cpu_ns counts as no figure); over the runs the median [min-max].

Per run, TcpExtTCPMemoryPressures after the run less before, and the TCP
memory pages in /proc/net/sockstat before and after.

Calibration runs (workloads CAL and CAL-DRAIN) also get, per run with no
drainer: the fewest free main-region slots over the load's window and,
divided over the stalled peers, the slots each held (h for whole replies,
h_p for pieces); and for every calibration run, from ss.log, the largest
sk_sndbuf (tb) and wmem_queued (w) seen for the first stalled peer and the
first drainer.

U's cost comes first: each arm's CPU per byte against O0 whole's, and the
difference in median time per reply and in CPU per reply divided by the
pieces per reply, the cost of one piece, with O0 whole's spread beside it.

Decision (docs/send-admission-design.md, section 4, Experiment D), for each
arm with the gate on:
- in W1, W2, W4 at tcp_wmem 1 MiB (every k run) and W5, it completes every
  7 MiB reply and every W5 slow reader's reply, keeps the fast small p99 at
  or below 10 ms in every run (the maximum over the cell's runs; the median
  is printed beside it), and has no more fast small replies beyond admit_ms
  than O0 whole (counted per run, since O0 whole has more runs). A cell the
  arm or O0 whole did not run, or in which a run of the arm failed, fails
  the condition.
- Among the passing arms, the larger stream_piece is named, with its CPU per
  byte in U against O0 whole's: above twice, the arm goes to the owner before
  it is chosen.
- The runs with memory pressure are listed beside it.

Then the prediction's refutation conditions, each printed with its result
for each gated arm and cell: the fast small p99 above 10 ms in a run, a
7 MiB reply (in U, a closed-loop reply) or a W5 slow reader's reply not
completed, fewer than 3/4 of the pool free during a 7 MiB reply in W4 (a
head measured below 3/4 refutes it even if other heads have no free-slot
figure; with none below, a head with no figure is reported as such, not as
holding), or a stalled peer's gated piece that waited for room in W4.
"""

import importlib.util
import io
import json
import pathlib
import re
import sys
import tarfile
import zlib
from collections import Counter, defaultdict
from statistics import median

here = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("c0", here / "send-admission-c0-report.py")
c0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c0)

HEAD_TAG = 0xFFFFFFFF
DRAIN_TAG = 0x80000000
ORDERS = {
    "strict": "O0",
    "first-fit": "O2",
    "bounded": "O3",
    "bounded-idle": "O4",
    "split-pool": "O5",
    "budget": "O7",
    "budget-idle": "O7w",
}
BUDGET_ORDERS = {"budget", "budget-idle"}
CELL_KEYS = (
    "workload",
    "stall_peers",
    "tcp_wmem_max",
    "drainers",
    "drain_read_bps",
    "pipeline",
    "admit_ms",
    "host",
)
ARM_KEYS = ("order", "budget", "stream_piece", "stream_gate")
ARM_DEFAULTS = {"order": "strict", "budget": "32", "stream_piece": "0", "stream_gate": "off"}
NOT_GROUPED = {"rep", "load_rc"}
DECISION_WORKLOADS = ("W1", "W2", "W4", "W5")


def arm_name(arm):
    order, budget, piece, gate = arm
    o = ORDERS.get(order, order)
    if order in BUDGET_ORDERS:
        o += f"(R={budget})"
    if piece in (None, "0"):
        return f"{o} whole"
    kib = int(piece) // 1024
    return f"{o} {'gated' if gate == 'on' else 'ungated'} {kib}K"


def is_o0_whole(arm):
    return arm[0] == "strict" and arm[2] in (None, "0")


def is_gated(arm):
    return arm[3] == "on"


def piece_of(arm):
    return int(arm[2] or 0)


def arm_sort(arm):
    order, _budget, _piece, gate = arm
    return (order != "strict", piece_of(arm) != 0, gate == "on", piece_of(arm), order)


def fmt(x, spec=".1f"):
    return "-" if x is None else format(x, spec)


def spread(xs, spec=".1f"):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    return f"{format(median(xs), spec)} [{format(min(xs), spec)}-{format(max(xs), spec)}]"


def tgz_files(root):
    """{name: bytes} of the files in the run's results.tgz, or None."""
    for tgz in root.rglob("results.tgz"):
        with tarfile.open(fileobj=io.BytesIO(tgz.read_bytes())) as t:
            return {
                pathlib.Path(m.name).name: t.extractfile(m).read()
                for m in t.getmembers()
                if m.isfile()
            }
    return None


def parse_worker(text):
    words = dict(w.split("=", 1) for w in text.split() if "=" in w)
    try:
        cpu = int(words["cpu_ns"])
    except (KeyError, ValueError):
        return None
    # A server whose worker thread was not found reads 0.
    return cpu if cpu > 0 else None


def nstat_value(data, name):
    if data is None:
        return None
    for line in data.decode(errors="replace").splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == name:
            try:
                return int(words[1])
            except ValueError:
                return None
    return None


def sockstat_mem(data):
    """The TCP line's mem field of /proc/net/sockstat, in pages."""
    if data is None:
        return None
    m = re.search(r"^TCP:.*\bmem (\d+)", data.decode(errors="replace"), re.M)
    return int(m.group(1)) if m else None


class RunFailed(Exception):
    """A run with a RUN line whose results cannot be read."""


def read_logs(root):
    """The RUN parameters, cpu_ns from the WORKER line, and the job's "no
    rl-work-0 thread" line if it printed one. SystemExit if there is no RUN
    line."""
    run = worker = no_thread = None
    try:
        lines = c0.log_lines(root)
    except (ValueError, KeyError, TypeError, OSError) as e:
        raise SystemExit(f"{root}: logs.json does not read: {e!r}")
    for text in lines:
        if text.startswith("RUN "):
            run = c0.parse_run(text)
        elif text.startswith("WORKER "):
            worker = parse_worker(text)
        elif text.startswith("no rl-work-0 thread"):
            no_thread = text.strip()
    if run is None:
        raise SystemExit(f"{root}: no RUN line" + (f" ({no_thread})" if no_thread else ""))
    return run, worker, no_thread


def read_files(root, worker):
    """cpu_ns, load.json, server.json and the run's files from results.tgz.
    RunFailed if they cannot be read."""
    try:
        files = tgz_files(root)
    except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
        raise RunFailed(f"results.tgz does not read: {e!r}")
    if files is None:
        raise RunFailed("no results.tgz (the SERVER line holds only a summary)")
    for name in ("load.json", "server.json"):
        if name not in files:
            raise RunFailed(f"results.tgz has no {name}")
    if "worker.txt" in files:
        worker = parse_worker(files["worker.txt"].decode(errors="replace"))
    try:
        load = json.loads(files["load.json"])
        server = json.loads(files["server.json"])
    except ValueError as e:
        raise RunFailed(f"load.json or server.json does not parse: {e}")
    return worker, load, server, files


def one(root):
    """A run's row: its summary, or, for a failed run, its RUN parameters
    and the reason in "failed"."""
    root = pathlib.Path(root)
    run, worker, no_thread = read_logs(root)
    try:
        if no_thread:
            raise RunFailed(no_thread)
        cpu_ns, load, server, files = read_files(root, worker)
        try:
            row = summarise_run(root, run, cpu_ns, load, server, files)
        except (KeyError, TypeError, ValueError, IndexError) as e:
            raise RunFailed(f"unexpected content: {e!r}")
    except RunFailed as e:
        return dict(root=str(root), run=run, failed=str(e))
    row["failed"] = None
    return row


def summarise_run(root, run, cpu_ns, load, server, files):
    st = server["statistics"]
    pool = server["pool_slots"]
    r = dict(root=str(root), run=run, rc=int(run.get("load_rc", "-1")), pool=pool)
    r["cpu_ns"] = cpu_ns
    r["aborts"] = server.get("aborts", {})
    before = nstat_value(files.get("nstat-before.txt"), "TcpExtTCPMemoryPressures")
    after = nstat_value(files.get("nstat-after.txt"), "TcpExtTCPMemoryPressures")
    r["mem_pressures"] = None if before is None or after is None else after - before
    r["sock_mem"] = (sockstat_mem(files.get("sockstat-before.txt")), sockstat_mem(files.get("sockstat-after.txt")))
    larges = st["large_replies"]
    heads = [l for l in larges if l["tag"] == HEAD_TAG]
    waited = defaultdict(lambda: [0, 0])
    for l in larges:
        kind = (
            "other"
            if l["tag"] == HEAD_TAG
            else ("drainer" if l["tag"] & DRAIN_TAG else "stalled")
        )
        waited[kind][0] += l.get("pieces_waited", 0)
        waited[kind][1] += l.get("pieces_sent", 0)
    r["waited"] = dict(waited)
    frees, none = [], 0
    for h in heads:
        figs = [x for x in (h.get("min_main_free"), h.get("admit_min_free")) if x is not None]
        if figs:
            frees.append(min(figs))
        else:
            none += 1
    r["head_min_free"] = min(frees) if frees else None
    r["heads_no_free"] = none
    lo, hi = load.get("window_ns", [0, 0])
    samples = [f for t, f in st.get("main_free_samples", []) if lo <= t * 1_000_000 <= hi]
    r["window_min_free"] = min(samples) if samples else None
    ss = defaultdict(lambda: [0, 0])
    for line in files.get("ss.log", b"").decode(errors="replace").splitlines():
        if not line.startswith("SS "):
            continue
        words = line.split()
        kind = words[2] if len(words) > 2 else "?"
        tb = re.search(r"\btb(\d+)", line)
        w = re.search(r",w(\d+)", line)
        if tb:
            ss[kind][0] = max(ss[kind][0], int(tb.group(1)))
        if w:
            ss[kind][1] = max(ss[kind][1], int(w.group(1)))
    r["ss"] = dict(ss)
    if "closed_loop" in load:
        cl = load["closed_loop"]
        r["u"] = cl
        replies = cl["warmup"] + cl["completed"]
        ok = cpu_ns is not None and replies > 0
        r["cpu_per_byte"] = cpu_ns / (replies * cl["size"]) if ok else None
        r["cpu_per_reply_us"] = cpu_ns / replies / 1000 if ok else None
        r["fast_p99"] = None
        r["fast_bad"] = 0
        r["heads_ok"] = cl["completed"]
        r["heads_n"] = cl["requests"]
        r["head_times"] = [u / 1000 for u in cl["us"]]
        r["slow_ok"] = r["slow_n"] = 0
        return r
    fast = st["classes"]["small_fast"]
    p99 = fast["scheduled_us"]["p99"]
    r["fast_p99"] = None if p99 is None else p99 / 1000
    r["fast_bad"] = fast["beyond_admit_limit"] + sum(fast["not_admitted"].values())
    done = load.get("large_completed")
    if done is None:  # a load from before D: a head counts if it has a time
        done = [x is not None for x in load.get("large_ms", [])]
    if int(run.get("large_size", "1")) == 0:
        done = []
    r["heads_ok"] = sum(1 for x in done if x)
    r["heads_n"] = len(done)
    times = load.get("large_us") or [None if x is None else x * 1000 for x in load.get("large_ms", [])]
    r["head_times"] = [t / 1000 for t, ok in zip(times, done) if ok and t is not None]
    dc = load["drainers"].get("completed")
    if dc is None:
        dc = [[x is not None for x in ep] for ep in load["drainers"]["ms"]]
    flat = [x for ep in dc for x in ep]
    r["slow_ok"] = sum(1 for x in flat if x)
    r["slow_n"] = len(flat)
    r["u"] = None
    return r


def group(rows):
    """{(cell, arm): [rows]}. A cell whose runs differ in a RUN parameter
    outside the cell and arm keys (other than rep and load_rc) is split by
    that parameter, across all its arms, so that no cell or arm is merged."""
    cells = defaultdict(list)
    for r in rows:
        cells[tuple((k, r["run"].get(k, "-")) for k in CELL_KEYS)].append(r)
    out = defaultdict(list)
    for cell, rs in cells.items():
        others = sorted(
            {k for r in rs for k in r["run"]} - set(CELL_KEYS) - set(ARM_KEYS) - NOT_GROUPED
        )
        differ = [k for k in others if len({r["run"].get(k) for r in rs}) > 1]
        if differ:
            print(f"warning: {cell_name(cell)}: runs differ in {differ}; split", file=sys.stderr)
        for r in rs:
            arm = tuple(r["run"].get(k, ARM_DEFAULTS[k]) for k in ARM_KEYS)
            extra = tuple((k, r["run"].get(k, "-")) for k in differ)
            out[(cell + extra, arm)].append(r)
    return dict(out)


def cell_name(cell):
    return " ".join(f"{k}={v}" for k, v in cell)


def workload(cell):
    return dict(cell)["workload"]


def failed_str(reasons):
    return "; ".join(f"{n} x {why}" if n > 1 else why for why, n in Counter(reasons).items())


def summarise(all_rs):
    """The arm's figures over its runs that did not fail; n counts those
    runs, and failed lists the reasons of the others."""
    rs = [r for r in all_rs if not r["failed"]]
    failed = [r["failed"] for r in all_rs if r["failed"]]
    if not rs:
        return dict(n=0, failed=failed)
    p99 = [r["fast_p99"] for r in rs if r["fast_p99"] is not None]
    times = [t for r in rs for t in r["head_times"]]
    frees = [r["head_min_free"] for r in rs if r["head_min_free"] is not None]
    waited = defaultdict(lambda: [0, 0])
    aborts = defaultdict(int)
    for r in rs:
        for k, (w, n) in r["waited"].items():
            waited[k][0] += w
            waited[k][1] += n
        for k, v in r["aborts"].items():
            aborts[k] += v
    u = [r["u"] for r in rs if r["u"]]
    return dict(
        n=len(rs),
        failed=failed,
        rc_bad=sum(1 for r in rs if r["rc"] != 0),
        fast_p99_med=median(p99) if p99 else None,
        fast_p99_max=max(p99) if p99 else None,
        fast_p99_runs=p99,
        fast_bad=sum(r["fast_bad"] for r in rs),
        fast_bad_per_run=sum(r["fast_bad"] for r in rs) / len(rs),
        heads_ok=sum(r["heads_ok"] for r in rs),
        heads_n=sum(r["heads_n"] for r in rs),
        head_med=median(times) if times else None,
        head_max=max(times) if times else None,
        slow_ok=sum(r["slow_ok"] for r in rs),
        slow_n=sum(r["slow_n"] for r in rs),
        free_min=min(frees) if frees else None,
        free_med=median(frees) if frees else None,
        heads_no_free=sum(r["heads_no_free"] for r in rs),
        pool=rs[0]["pool"],
        waited=dict(waited),
        aborts=dict(aborts),
        u_p50=[x["p50_us"] for x in u],
        u_p99=[x["p99_us"] for x in u],
        u_cpu_b=[r["cpu_per_byte"] for r in rs if r.get("cpu_per_byte") is not None],
        u_cpu_reply=[r["cpu_per_reply_us"] for r in rs if r.get("cpu_per_reply_us") is not None],
        u_cpu_missing=sum(1 for r in rs if r["u"] and r.get("cpu_per_byte") is None),
        u_rcvbuf=sorted({x["rcvbuf_reported"] for x in u}),
        u_size=u[0]["size"] if u else None,
        u_errors=[x["error"] for x in u if x.get("error")],
    )


def waited_str(w):
    return " ".join(f"{k} {w[k][0]}/{w[k][1]}" for k in ("stalled", "drainer", "other") if k in w) or "-"


def print_tables(groups):
    by_cell = defaultdict(dict)
    for (cell, arm), rs in groups.items():
        by_cell[cell][arm] = summarise(rs)
    for cell in sorted(by_cell):
        arms = by_cell[cell]
        print(f"\n== {cell_name(cell)}")
        u = workload(cell) == "U"
        if u:
            print("arm                  runs | p50 us [range]            p99 us [range]            | CPU ns/B [range]          CPU us/reply | rcvbuf   | completed")
        else:
            print("arm                  runs | fast p99 ms: median [range] max | fast bad (per run) | 7MiB ok/n  med ms  max ms | drain ok/n | free min med none | waited (w/sent) | aborts")
        for arm in sorted(arms, key=arm_sort):
            s = arms[arm]
            failed = f" | FAILED {len(s['failed'])}: {failed_str(s['failed'])}" if s["failed"] else ""
            if s["n"] == 0:
                print(f"{arm_name(arm):20} {0:>4} | no run produced results{failed}")
                continue
            if u:
                print(
                    f"{arm_name(arm):20} {s['n']:>4} | {spread(s['u_p50'], '.0f'):25} {spread(s['u_p99'], '.0f'):25} | "
                    f"{spread(s['u_cpu_b'], '.3f'):25} {spread(s['u_cpu_reply'], '.0f'):>12} | {s['u_rcvbuf']} | {s['heads_ok']}/{s['heads_n']}"
                    + (f" | no CPU figure in {s['u_cpu_missing']} runs" if s["u_cpu_missing"] else "")
                    + (f" | errors {s['u_errors']}" if s["u_errors"] else "")
                    + failed
                )
                continue
            ab = " ".join(f"{k}={v}" for k, v in sorted(s["aborts"].items()) if v) or "none"
            print(
                f"{arm_name(arm):20} {s['n']:>4} | {spread(s['fast_p99_runs']):20} {fmt(s['fast_p99_max']):>6} | "
                f"{s['fast_bad']:>4} ({s['fast_bad_per_run']:.1f}) | "
                f"{s['heads_ok']:>3}/{s['heads_n']:<3} {fmt(s['head_med']):>7} {fmt(s['head_max']):>7} | "
                f"{s['slow_ok']:>3}/{s['slow_n']:<3}  | {fmt(s['free_min'], '.0f'):>4} {fmt(s['free_med'], '.0f'):>4} {s['heads_no_free']:>4} | "
                f"{waited_str(s['waited'])} | {ab}"
                + (f" | load_rc!=0 in {s['rc_bad']}" if s["rc_bad"] else "")
                + failed
            )
    return by_cell


def memory(groups):
    """Print each run's memory figures; return the runs with pressure, and
    the number of runs that did not fail and have no pressure figure."""
    print("\n== TCP memory per run: TcpExtTCPMemoryPressures delta, sockstat TCP mem pages before -> after")
    pressured, no_figure = [], 0
    for (cell, arm), rs in sorted(groups.items(), key=lambda x: (x[0][0], arm_sort(x[0][1]))):
        for r in sorted(rs, key=lambda r: r["run"].get("rep", "")):
            if r["failed"]:
                print(f"{cell_name(cell)} | {arm_name(arm)} rep {r['run'].get('rep')}: failed ({r['failed']})")
                continue
            d = r["mem_pressures"]
            if d is None:
                no_figure += 1
            b, a = r["sock_mem"]
            print(f"{cell_name(cell)} | {arm_name(arm)} rep {r['run'].get('rep')}: pressures {fmt(d, 'd')}, mem {fmt(b, 'd')} -> {fmt(a, 'd')}")
            if d:
                pressured.append(f"{cell_name(cell)} | {arm_name(arm)} rep {r['run'].get('rep')} ({d})")
    return pressured, no_figure


def calibration(groups):
    cal = [(c, a, rs) for (c, a), rs in groups.items() if workload(c).startswith("CAL")]
    if not cal:
        return
    print("\n== calibration: slots held per stalled peer (runs with no drainer), and the sockets' buffers")
    for cell, arm, rs in sorted(cal, key=lambda x: (x[0], arm_sort(x[1]))):
        k = int(dict(cell)["stall_peers"])
        drainers = dict(cell)["drainers"]
        for r in sorted(rs, key=lambda r: r["run"].get("rep", "")):
            if r["failed"]:
                print(f"{workload(cell):9} {arm_name(arm):20} k={k} rep {r['run'].get('rep')}: failed ({r['failed']})")
                continue
            sock = "; ".join(
                f"{kind} tb {v[0]} w {v[1]}" for kind, v in sorted(r["ss"].items())
            ) or "no ss.log"
            if drainers == "0" and k > 0:
                held = None if r["window_min_free"] is None else r["pool"] - r["window_min_free"]
                per = None if held is None else held / k
                slots = (
                    f"fewest free {fmt(r['window_min_free'], '.0f')} of {r['pool']}, "
                    f"held {fmt(held, '.0f')}, per stalled peer {fmt(per, '.1f')}"
                )
            else:
                slots = f"{drainers} drainer(s): no h"
            print(f"{workload(cell):9} {arm_name(arm):20} k={k} rep {r['run'].get('rep')}: {slots} | {sock}")


def u_cost(by_cell):
    """Print U's cost of pieces; return {arm: [CPU per byte ratios to O0 whole]}."""
    print("\n== U: cost of pieces against O0 whole")
    ratios = defaultdict(list)
    ucells = [c for c in by_cell if workload(c) == "U"]
    if not ucells:
        print("no U cell ran")
    for cell in sorted(ucells):
        cells = by_cell[cell]
        o0 = next((v for a, v in cells.items() if is_o0_whole(a)), None)
        print(cell_name(cell))
        if o0 is None or not o0.get("u_cpu_b"):
            print("  no O0 whole runs with a CPU figure")
            continue
        base_b = median(o0["u_cpu_b"])
        base_t = median(o0["u_p50"])
        base_r = median(o0["u_cpu_reply"])
        print(
            f"  O0 whole: CPU {base_b:.3f} ns/B (spread {max(o0['u_cpu_b']) - min(o0['u_cpu_b']):.3f}), "
            f"p50 {base_t:.0f} us (spread {max(o0['u_p50']) - min(o0['u_p50']):.0f}), {len(o0['u_cpu_b'])} runs"
        )
        for arm in sorted(cells, key=arm_sort):
            if is_o0_whole(arm):
                continue
            s = cells[arm]
            if s["failed"]:
                print(f"  {arm_name(arm)}: {len(s['failed'])} runs failed ({failed_str(s['failed'])})")
            if not s.get("u_cpu_b"):
                print(f"  {arm_name(arm)}: no CPU figure")
                continue
            ratio = median(s["u_cpu_b"]) / base_b if base_b else None
            if ratio is not None:
                ratios[arm].append(ratio)
            line = f"  {arm_name(arm)}: CPU {median(s['u_cpu_b']):.3f} ns/B, x{fmt(ratio, '.2f')} O0 whole"
            if piece_of(arm) and s["u_size"]:
                pieces = -(-s["u_size"] // piece_of(arm))
                dt = (median(s["u_p50"]) - base_t) / pieces
                dc = (median(s["u_cpu_reply"]) - base_r) / pieces
                line += f"; per piece ({pieces} a reply): {dt:+.1f} us of reply time, {dc:+.1f} us of worker CPU"
            if is_gated(arm) and ratio is not None and ratio > 2:
                line += "  -> more than twice O0 whole per byte: to the owner before it is chosen"
            print(line)
    return ratios


def decision(by_cell, ratios, pressured, no_figure):
    print("\n== decision (design, Experiment D)")
    arms = sorted({a for cells in by_cell.values() for a in cells if is_gated(a)}, key=arm_sort)
    if not arms:
        print("no gated arm ran")
    required = [
        c for c in by_cell
        if workload(c) in DECISION_WORKLOADS
        and not (workload(c) == "W4" and dict(c)["tcp_wmem_max"] != "1048576")
    ]
    for w in DECISION_WORKLOADS:
        if not any(workload(c) == w for c in required):
            print(f"  no {w} cell ran: every gated arm fails for want of it")
    passing = []
    for arm in arms:
        reasons, checks = [], 0
        for w in DECISION_WORKLOADS:
            if not any(workload(c) == w for c in required):
                reasons.append(f"{w}: not run")
        for cell in sorted(required):
            cells = by_cell[cell]
            name = cell_name(cell)
            s = cells.get(arm)
            o0 = next((v for a, v in cells.items() if is_o0_whole(a)), None)
            if s is None:
                reasons.append(f"{name}: this arm did not run")
                continue
            if s["failed"]:
                print(f"  {arm_name(arm)} | {name}: FAILED runs {len(s['failed'])}: {failed_str(s['failed'])}")
                reasons.append(f"{name}: failed runs {len(s['failed'])}")
            if s["n"] == 0:
                continue
            checks += 1
            ok_heads = s["heads_n"] > 0 and s["heads_ok"] == s["heads_n"]
            print(f"  {arm_name(arm)} | {name}: 7 MiB {s['heads_ok']}/{s['heads_n']} {'ok' if ok_heads else 'FAIL'}", end="")
            if not ok_heads:
                reasons.append(f"{name}: 7 MiB replies completed {s['heads_ok']}/{s['heads_n']}")
            if workload(cell) == "W5":
                ok_slow = s["slow_n"] > 0 and s["slow_ok"] == s["slow_n"]
                print(f"; slow readers {s['slow_ok']}/{s['slow_n']} {'ok' if ok_slow else 'FAIL'}", end="")
                if not ok_slow:
                    reasons.append(f"{name}: slow readers' replies completed {s['slow_ok']}/{s['slow_n']}")
            ok_p99 = s["fast_p99_max"] is not None and s["fast_p99_max"] <= 10.0
            print(
                f"; fast p99 max {fmt(s['fast_p99_max'])} ms (median {fmt(s['fast_p99_med'])}) "
                f"{'ok' if ok_p99 else 'FAIL'}",
                end="",
            )
            if not ok_p99:
                reasons.append(f"{name}: fast p99 {fmt(s['fast_p99_max'])} ms in a run > 10 ms")
            if o0 is None or o0["n"] == 0:
                print("; O0 whole has no run with results: FAIL")
                reasons.append(f"{name}: no O0 whole runs to compare")
                continue
            ok_bad = s["fast_bad_per_run"] <= o0["fast_bad_per_run"]
            print(
                f"; fast beyond {s['fast_bad_per_run']:.1f}/run against O0 whole's "
                f"{o0['fast_bad_per_run']:.1f} {'ok' if ok_bad else 'FAIL'}"
            )
            if not ok_bad:
                reasons.append(
                    f"{name}: {s['fast_bad_per_run']:.1f} fast replies beyond admit_ms per run against O0 whole's {o0['fast_bad_per_run']:.1f}"
                )
        verdict = "passes" if not reasons and checks else "fails"
        print(f"{arm_name(arm)}: {verdict}")
        for reason in reasons:
            print(f"    {reason}")
        if verdict == "passes":
            passing.append(arm)
    if passing:
        best = max(passing, key=piece_of)
        r = ratios.get(best)
        if not r:
            cost = "no U run with a CPU figure: its cost per byte is unknown"
        elif max(r) > 2:
            cost = f"U CPU per byte x{max(r):.2f} O0 whole, more than twice: to the owner before it is chosen"
        else:
            cost = f"U CPU per byte x{max(r):.2f} O0 whole"
        print(f"larger passing p: {piece_of(best) // 1024} KiB ({arm_name(best)}); {cost}")
    else:
        print("no gated arm passes: the result goes to the owner, and Experiment C's outcome stands for plaintext")
    if pressured:
        print("runs with TCP memory pressure (TcpExtTCPMemoryPressures rose):")
        for p in pressured:
            print(f"    {p}")
    figured = sum(s["n"] for cells in by_cell.values() for s in cells.values()) - no_figure
    if not pressured and figured:
        print(f"no run recorded TCP memory pressure ({figured} runs with a figure)")
    if no_figure:
        print(f"no TCP memory-pressure figure in {no_figure} runs")


def prediction(by_cell):
    print("\n== prediction's refutation conditions, for each gated arm and cell")
    refuted = []
    for cell in sorted(by_cell):
        w = workload(cell)
        if w.startswith("CAL"):
            continue
        for arm in sorted(by_cell[cell], key=arm_sort):
            if not is_gated(arm):
                continue
            s = by_cell[cell][arm]
            name = f"{arm_name(arm)} | {cell_name(cell)}"
            if s["failed"]:
                print(f"{name}: FAILED runs {len(s['failed'])}: {failed_str(s['failed'])}")
            if s["n"] == 0:
                print(f"{name}\n    no run produced results: no figure for any condition")
                continue
            checks = []
            if w != "U":
                if s["fast_p99_max"] is None:
                    checks.append(("fast p99 <= 10 ms in every run", None, "no fast small replies"))
                else:
                    checks.append((
                        "fast p99 <= 10 ms in every run",
                        s["fast_p99_max"] <= 10.0,
                        f"max {fmt(s['fast_p99_max'])} ms, median {fmt(s['fast_p99_med'])}",
                    ))
            label = "every closed-loop reply completed" if w == "U" else "every 7 MiB reply completed"
            if s["heads_n"]:
                checks.append((label, s["heads_ok"] == s["heads_n"], f"{s['heads_ok']}/{s['heads_n']}"))
            else:
                checks.append((label, None, "none requested"))
            if w == "W5":
                checks.append((
                    "every slow reader's reply completed",
                    s["slow_n"] > 0 and s["slow_ok"] == s["slow_n"],
                    f"{s['slow_ok']}/{s['slow_n']}",
                ))
            if w == "W4":
                quarter = 0.75 * s["pool"]
                if s["free_min"] is not None and s["free_min"] < quarter:
                    checks.append((
                        "3/4 of the pool free during each 7 MiB reply",
                        False,
                        f"fewest {s['free_min']} of {s['pool']}"
                        + (f"; no free-slot figure for {s['heads_no_free']} heads" if s["heads_no_free"] else ""),
                    ))
                elif s["heads_no_free"] or s["free_min"] is None:
                    checks.append((
                        "3/4 of the pool free during each 7 MiB reply",
                        None,
                        f"no free-slot figure for {s['heads_no_free']} heads; fewest seen {fmt(s['free_min'], '.0f')}",
                    ))
                else:
                    checks.append((
                        "3/4 of the pool free during each 7 MiB reply",
                        s["free_min"] >= quarter,
                        f"fewest {s['free_min']} of {s['pool']}",
                    ))
                stalled = s["waited"].get("stalled", [0, 0])
                checks.append((
                    "no stalled peer's piece waited for room",
                    stalled[0] == 0,
                    f"{stalled[0]} of {stalled[1]}",
                ))
            print(name)
            for what, ok, detail in checks:
                result = "no figure" if ok is None else ("holds" if ok else "REFUTES")
                print(f"    {what}: {result} ({detail})")
                if ok is False:
                    refuted.append(f"{name}: {what} ({detail})")
    if refuted:
        print("refuted by:")
        for x in refuted:
            print(f"  {x}")
    else:
        print("no condition refutes the prediction in the cells run")


def main():
    if len(sys.argv) < 2:
        raise SystemExit("usage: send-admission-d-report.py RUN_DIR...")
    rows = []
    for a in sys.argv[1:]:
        try:
            rows.append(one(a))
        except SystemExit as e:
            print(f"skipped: {e}")
    failed = [r for r in rows if r["failed"]]
    if failed:
        print(f"failed runs, counted in their cell and arm: {len(failed)}")
        for r in failed:
            print(f"  {r['root']}: {r['failed']}")
    if not rows:
        raise SystemExit("no run has a RUN line")
    groups = group(rows)
    by_cell = print_tables(groups)
    pressured, no_figure = memory(groups)
    calibration(groups)
    ratios = u_cost(by_cell)
    decision(by_cell, ratios, pressured, no_figure)
    prediction(by_cell)


if __name__ == "__main__":
    main()
