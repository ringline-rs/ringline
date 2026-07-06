# 2026-05/06 — Benchmark infrastructure and the honest numbers

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-04-29 – 2026-06-08 · PRs #151–#209 · v0.2.0

## Goal

Give ringline a measured, reproducible performance story: hot-path
microbenchmarks, a multi-protocol ringline-vs-tokio harness, and a checked-in
`BENCHMARKS.md` baseline for future changes to beat or flag against. The
second goal, which the arc ended up being about: make sure the checked-in
numbers are actually *true*.

## What happened

**Microbenchmarks (late April – early May).** Criterion benches landed in #151
(37818b9), were rewritten around persistent connections in #152 (562fff8) so
they measured steady-state rather than connection setup, and were extended in
#157 (e488de8).

**Bench suite buildout (May).** `ringline-benchmarks` grew a protocol matrix:
UDP server/client with the full 2x2 runtime matrix in #162 (a6c860c), Redis in
#183 (e3d73ce), Memcache in #187 (228875a), HTTP/1.1 in #188 (ccdd5bc), HTTP/3
in #191 (ad595fb), plus a zero-allocation UDP echo recv path in #186 (7caed16).
#199 (5f26183) made the standalone `bench-client` runtime-selectable
(`--runtime ringline|tokio`) — it had been tokio-only, so distributed runs could
only measure the server side — and added an open-loop (`--open --rate`) mode
and send coalescing.

**First BENCHMARKS.md (2026-05-18).** #185 (95fd3c0) published ringline-vs-tokio
numbers for TCP/UDP/Redis, explicitly flagged as single-worker, localhost, with
protocol stubs still TODO.

**Methodology hardening (early June).** This is where the harness started
falsifying its own earlier output:

- #203 (a1da29f): the single-machine matrix's "ringline TCP server" was in fact
  a tokio `io::copy` echo behind a stale comment — the `ringline → ringline`
  column had only ever compared the *client* runtime. Replaced with a native
  `RinglineBuilder` echo server; the regenerated table flipped the 32 KiB cells,
  where ringline had appeared to trail 4–17% purely because of the tokio stand-in.
- #204 (e76c421): `PortManager` handed out ports with no bindability check, so
  transient TIME_WAIT collisions produced silent server-thread panics and
  scattered 0-ops/s cells in large sweeps. Fixed with bind-probing; all
  single-machine tables regenerated on one consistent rig.
- #201 (f5d5781): worker count now defaults to **physical** core count (the
  v0.2.0 breaking change in CHANGELOG.md) — the logical-CPU default had HT
  siblings contending. #202 (f77fbd1) documented worker-scaling and
  CPU-efficiency methodology.
- #206 (04b405d): open-loop latency decomposed into service time vs offer lag
  (send − scheduled), so coordinated-omission back-pressure is reported
  separately instead of silently inflating "response time".
- #207 (9e57fdf): `bench-server` shuts down gracefully on SIGINT/SIGTERM so the
  `[ringline diag]`/`[ringline stall]` diagnostics actually print at teardown.
  #208 (fbca4f8): `--cpu-list` tasksets the server process for bare-metal runs,
  disabling ringline's own absolute-core pinning so the two don't fight.

**The withdrawal (2026-06-06).** #205 (44889fb) deleted `BENCHMARKS.md`
outright — 740 lines — rather than patch it. Stated mechanism: the published
worker-scaling and distributed numbers came from a single-host (co-located)
configuration that did not reflect real network behavior. A clean two-machine
run produced materially different results — the commit's example: 1 worker, 512
connections, 256 B gave 264k ops/s with p99 ~1 ms on two machines, versus the
lab's 9k ops/s with p99 759 ms — and the lab's RTO-scale tail latency was a
shared-switch incast artifact. The commit preserved the re-measurement tooling
(`experiments/forge-tcp-worker-scaling.toml`, a `tcp-worker-scaling.toml` pinned
to guarantee two physical machines) and pointed README at it.

**Re-establishment (2026-06-08).** #209 (c77cfba) added a new `BENCHMARKS.md`
from a clean two-machine run: two EC2 Graviton4 (c8g) instances in a cluster
placement group, a real Segcache GET workload with zero-copy `ValueRef` serving,
coordinated-omission-free latency, and idle-baseline-subtracted server CPU.
Headline (best-vs-best at matched worker count): at 256 B / 1 KiB ringline
delivers ~+30% throughput, ~−25% p50, 15–18% lower p99, and ~+22% CPU
efficiency vs tokio; at 4 KiB throughput and median tie (bandwidth-bound) with
ringline −8% p99 and +14% efficiency; at open-loop saturation the runtimes are
a dead tie — the NIC/PPS ceiling, not the runtime, sets the peak. The withdrawn
single-host protocol matrix was deliberately *not* resurrected; scope is limited
to what was cleanly measured two-machine. v0.2.0 shipped the same day (4dc352b).

In parallel, an apparent ringline single-core throughput ceiling was
investigated off-repo on the SystemsLab rig; numbers are not checked in. It
proved to be an environment artifact (NIC flow-steering/IRQ placement and
CPU-isolation config on the load-gen host), not a code regression. The in-repo
residue of that lesson is the caution in CLAUDE.md's "Performance Work"
section: watch for environment artifacts before blaming the code.

## Outcome

- `BENCHMARKS.md` on `main` holds the two-machine segcache baseline — the bar
  future changes are measured against.
- The load generators are `ringline-bench/` (distributed echo/cache server
  comparison) and `ringline-benchmarks/` (single-machine multi-protocol matrix);
  both are workspace members and unpublished tooling. `experiments/` holds 22
  declarative SystemsLab specs (TCP sweeps, worker scaling, open/closed loop,
  fan-in decomposition, pcap captures).
- v0.2.0 released 2026-06-08 (4dc352b) with the physical-core-count worker
  default as the breaking change.

## Lessons / open questions

- **A wrong baseline is worse than no baseline.** The single-host numbers were
  internally consistent and wrong by ~30x on throughput and ~750x on p99 in the
  quoted cell (44889fb). Withdrawing them for two days beat annotating them.
- **Validate the harness before the numbers.** Two of the worst artifacts were
  harness bugs, not measurement noise: a tokio server labeled ringline (#203)
  and silent 0-ops cells from port collisions (#204).
- **Decompose open-loop latency.** Service time vs offer lag (#206) is the
  difference between "the server is slow" and "the client fell behind schedule".
- Open: the withdrawn protocol matrix (UDP/QUIC/HTTP/redis/memcache) was never
  re-measured two-machine — `BENCHMARKS.md` covers segcache TCP only; the 16 KiB
  tokio open-loop cell errored and remains excluded pending investigation; the
  `bench/fair-throughput` segcache harness has not landed on `main`.
