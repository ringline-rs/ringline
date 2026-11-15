#!/usr/bin/env python3
"""Summarise send-admission-b-contended.toml runs.

Each argument is a directory made by `systemslab artifact download-all <id>`
for one run. Reads the `RUN`, `LOAD` and `SERVER` lines the job prints, and
prints one row per run, then per cell (small_send, admit_ms) the median and
range over its repetitions.

A run counts as contended when every episode's large reply either took at
least half of settle_ms - LARGE_DELAY_MS (the wait for the stalled peers'
abort), or was not delivered while the server counted one large-reply
admission timeout per episode.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import median

RUN = re.compile(r"RUN small_send=(\S+) admit_ms=(\d+) settle_ms=(\d+) rep=(\S+) load_rc=(\d+)")
LARGE_DELAY_MS = 200


def one(root: Path):
    logs = next(root.rglob("logs.json"))
    run = load = server = None
    for e in json.loads(logs.read_text())["events"]:
        text = e.get("text", "")
        if m := RUN.search(text):
            run = m.groups()
        elif text.startswith("LOAD "):
            load = json.loads(text[5:])
        elif text.startswith("SERVER "):
            server = json.loads(text[7:])
    if not (run and load and server):
        raise SystemExit(f"{root}: missing RUN, LOAD or SERVER line")
    small_send, admit, settle, rep, rc = run
    admit, settle = int(admit), int(settle)
    larges = load["large_ms"]
    floor = (settle - LARGE_DELAY_MS) / 2
    undelivered = sum(1 for x in larges if x is None)
    contended = undelivered == server["admit_timeouts"][1] and all(
        x is None or x >= floor for x in larges
    )
    return dict(
        small_send=small_send,
        admit=admit,
        settle=settle,
        rep=rep,
        rc=int(rc),
        offered=load["offered"],
        not_within=load["not_within"],
        late=load["delivered_late"],
        lost=load["lost"],
        reconnects=load["reconnects"],
        p50_ms=load["p50_ns"] / 1e6,
        p99_ms=load["p99_ns"] / 1e6,
        p999_ms=load["p999_ns"] / 1e6,
        large_ok=sum(1 for x in larges if x is not None),
        episodes=len(larges),
        large_med=median([x for x in larges if x is not None]) if any(x is not None for x in larges) else None,
        refused=server["refused"][0],
        small_admit_timeouts=server["admit_timeouts"][0],
        large_admit_timeouts=server["admit_timeouts"][1],
        settle_aborts=server["settle_aborts"],
        contended=contended,
    )


def main():
    rows = [one(Path(a)) for a in sys.argv[1:]]
    rows.sort(key=lambda r: (r["admit"], r["small_send"], r["rep"]))
    print("send     admit rep offered not_within late lost reconn p50_ms p99_ms p999_ms large_ok large_med refused s_adm_to l_adm_to settle_aborts contended")
    for r in rows:
        print(
            f"{r['small_send']:<8} {r['admit']:>5} {r['rep']:>3} {r['offered']:>7} {r['not_within']:>10} {r['late']:>4} {r['lost']:>4} "
            f"{r['reconnects']:>6} {r['p50_ms']:>6.1f} {r['p99_ms']:>6.1f} {r['p999_ms']:>7.1f} {r['large_ok']:>3}/{r['episodes']:<3} "
            f"{r['large_med']!s:>9} {r['refused']:>7} {r['small_admit_timeouts']:>8} {r['large_admit_timeouts']:>8} {r['settle_aborts']!s:>13} {r['contended']}"
        )
    print("\n== per cell: median [min-max] over repetitions")
    cells = defaultdict(list)
    for r in rows:
        cells[(r["admit"], r["small_send"])].append(r)
    for (admit, send), rs in sorted(cells.items()):
        ratio = admit / rs[0]["settle"]
        nw = [r["not_within"] for r in rs]
        p99 = [r["p99_ms"] for r in rs]
        print(
            f"ratio {ratio:.1f} {send:<8} n={len(rs)} not_within {median(nw):.0f} [{min(nw)}-{max(nw)}] "
            f"of ~{median([r['offered'] for r in rs]):.0f}; p99 {median(p99):.1f} ms [{min(p99):.1f}-{max(p99):.1f}]; "
            f"large delivered {sum(r['large_ok'] for r in rs)}/{sum(r['episodes'] for r in rs)}; "
            f"contended {sum(r['contended'] for r in rs)}/{len(rs)}"
        )


if __name__ == "__main__":
    main()
