# Recv buffer geometry sweep — design

Note (2026-10-25): `with_segments` and `recv_owned_segment` were removed.

Note (2026-10-25): `forward_to` (Mode A) was removed.

Note (2026-10-25): the TCP provided-buffer ring was removed, with
`recv_buffer`, the fallback receive, `ConnectionState::recv_arm` and the
`recv_parked`, `recv_fallback` and `forward_throttled` counters. The
geometry this sweep measured no longer exists.

**Status:** **Phase A complete — the default stands.** Phase 0 landed (#417);
#415 merged as 282773b. Outcome below.

**Question:** ringline's provided recv ring defaults to `recv_buffer(256, 16384)`
— 256 buffers of 16 KiB, 4 MiB per worker. Is that the right default, and is one
default right for every delivery mode?

**Why now:** #415 measured a forwarding proxy at 11.2 Gbit/s with the default and
14.0 Gbit/s at `recv_buffer(64, 65536)` — same memory, a quarter as many buffers,
four times the size. That is a 25% throughput difference sitting behind a knob
nobody turns.

## Outcome (Phase A, 2026-09-17)

**Do not change the default.** `recv_buffer(256, 16384)` is minimax-optimal
across the measured space: it never wins a workload and never loses badly,
which is what a default is for.

Two saturated passes at 2 workers, identical but for fan-in — 64 and 1024
connections — 6 message shapes each, 108 arms. Worst-case deficit against the
best geometry that fits the same 4 MiB budget:

| geometry (≤4 MiB) | worst | median |
|---|---|---|
| **16 KiB × 256 (default)** | **−34%** | −6% |
| 64 KiB × 64 | −36% | −5% |
| 256 KiB × 16 | −59% | −8% |
| 4 KiB × 1024 | −70% | −24% |
| 1 MiB × 4 | −83% | −6% |

Every alternative is excellent somewhere and catastrophic elsewhere. 1 MiB × 4
wins four workloads outright and is 83% down on another (with a **1.03-second
p99** at 256 B × 1024 connections, from 137,895,774 ring starvations). 4 KiB ×
1024 wins small-message/high-fan-in and loses 70% on forwarding.

**Why no geometry wins: the optimum moves along two axes, in opposite
directions.** Six different geometries win the twelve workloads.

- **Message size** pulls toward *bigger* buffers — payload per completion
  amortises a fixed ~6,600-instruction per-completion cost (#415).
- **Fan-in** pulls toward *deeper* rings — depth bounds concurrent arrivals, and
  at a fixed memory budget depth and size trade directly.

At 64 connections the first dominates and 64 KiB × 64 is best; at 1024 the
second does, the same geometry falls 33% behind, and 4 KiB × 1024 wins. A
library cannot know either axis in advance, so a fixed default can only be
*mediocre everywhere*, which this one is: within ~6% of best on 9 of 12
workloads.

**The one exception is forwarding**, and it is systematic: the default is
**−34%** at 64 connections and **−18%** at 1024.

> **Superseded for forwarding.** That deficit was an artifact of Mode A writing
> one held buffer per write. Gathering (`docs/journal/2026-09-direct-forward-path.md`)
> takes the default from 11.23 to 14.60 Gbit/s, against 15.13 at 64 KiB and 14.22
> at 256 KiB — **within 3.5% of best**, the same order as every echo workload, and
> 256 KiB becomes *worse* than the default. Treat the forwarding rows below as a
> record of the pre-gathering runtime; the arms should be re-run on a gathered
> build before they are cited. `forward_to`'s sizing note is
therefore binding rather than advisory. Note the recommendation itself is
fan-in dependent — 1 MiB × 4 is best at c64 (17.07 Gbit/s vs 11.32) while 256
KiB × 16 is best at c1024 (11.96 vs 9.82) — so the note should give a range and
say why, not a number.

(That note was removed in 0.7.0-alpha.6. No plaintext connection receives
through the provided-buffer ring, so `forward_to` takes only TLS sources, and
these measurements do not apply to them.)

**Cross-validation.** The forward arms reproduce #415 on an independently built
harness: 11.32 Gbit/s at the default here vs 11.2 there, 14.26 at 64 KiB vs
14.0. Two harnesses, same operating point, within 2%.

**What this bounds for #416's remaining phases.** The tuning burden a
geometry-aware runtime could remove is ~6% median and ~11% worst for
request/response, and 18–34% for forwarding *before gathering* — ~3.5% after.
Phase B's refinement pass therefore has little left to chase on either path:
single-digit percentages that the fan-in axis swamps.

## The contradiction this has to resolve

Two measured results point opposite ways, and reconciling them *is* the
experiment.

| | workload | finding |
|---|---|---|
| #284 journal (2026-07-21, 200 GbE) | `with_data` materialize — the **copying** path | **16 KiB ≥ 256 KiB.** Bigger buffers "only add memcpy/cache/page overhead"; the buffer-size story *inverted* |
| #415 (2026-09-17, 40 GbE) | `forward_to_conn` — Mode A, the **zero-copy hold-and-write** path | **64 KiB > 16 KiB**, by 25% at equal memory |

The likely reconciliation, which the sweep must confirm or kill: **the optimum
follows the delivery mode, because the modes have different per-completion
costs.**

- On the copying path, a bigger provided buffer means a bigger `memcpy` into the
  accumulator, with worse cache behaviour. Per-completion overhead is small next
  to the copy, so growing the buffer buys little and costs cache.
- Mode A never copies into the accumulator. Its per-completion cost is pure
  bookkeeping — CQE decode, hold push, task wake, future poll, write SQE, write
  CQE, bid replenish — measured at **~6,600 instructions**, and it writes one
  buffer at a time per connection. Amortising that over 4× the bytes is close to
  free. Measured: 1.26 → 0.96 instructions/byte, with a floor of ~0.86 that is
  the kernel's own copy and TCP work.

If that holds, "what should the default be" is the wrong question and the right
one is "should the buffer geometry be chosen when a delivery mode is armed."

**This is not #284.** That was *adaptive* sizing — size classes reacting to
observed traffic — and it was retired with a measured NO-GO that stands. This is
a *static* choice keyed on which API the caller invokes, which the retired design
never covered. Do not re-open #284; cite it.

Re-evaluation criterion **D** in that journal ("a mandatory-hold zero-copy
consumer ... where a small ring genuinely starves") is the closest existing hook,
but Mode A does not starve here — it is slower for a different reason
(per-completion bookkeeping, not ring pressure). The sweep should end by either
adding a criterion **E** or recording that the modes simply want different
geometry.

## Phase 0 — prerequisite: make the ring observable

`metrics::POOL` already counts `BUFFER_RING_EMPTY`, `RECV_PARKED`,
`RECV_FALLBACK`, `FORWARD_THROTTLED`, and `metrics::RING` counts
`RECV_ARM_FAILURES` — but **nothing in the workspace reads them back out.** There
is no exporter and no dump. A sweep without them produces a throughput table with
no explanation: a small-buffer arm that loses could be losing to ring starvation,
to fallback-recv degradation, or to nothing of the sort, and the numbers cannot
tell you which.

Add `bench-server --metrics-out <path>`, dumping the metriken registry as JSON at
shutdown. Small, contained, in an unpublished crate, and it makes every future
sweep diagnostic rather than descriptive.

Gate: an arm run at a deliberately tiny ring (`recv_buffer(8, 4096)`) must show
non-zero `buffer_ring_empty` and `recv_parked`. If those stay zero the dump is
not wired to anything and the sweep is blind — fix before proceeding.

**The gate fired.** Its first run reported zero starvation on an 8 × 4 KiB ring,
which is only possible if the flags did nothing — and they did nothing: the echo
arm hardcoded `recv_buffer(256, msg_size-derived)` and read neither flag, so all
27 echo arms of Phase A would have run one configuration under 27 labels. Fixed
in #417, with the effective geometry now printed on the ready line so a log
proves what ran. After the fix, 8 × 4 KiB counts 11,950,066 `buffer_ring_empty`
and moves 12.4 GB, against 0 and 28.4 GB at 256 × 64 KiB.

## Axes

**1. Delivery mode** — the axis the contradiction says matters most.

| mode | API | per-completion work |
|---|---|---|
| copy | `with_data` / `with_bytes` (default) | memcpy into accumulator |
| forward (Mode A) | `forward_to_conn` | hold + one serialized write per buffer |
| segments (Mode B) | `with_segments` | borrow, no copy |
| owned (Mode C) | `recv_owned_segment` | copy out, bid returned at delivery |
| recv-forward | `enable_recv_forward` + `forward_held` | hold, scatter-gather echo |
| direct echo | `run_direct_echo` | hold, echo from the CQE handler |

**2. Message size** — what actually fills a buffer: **256 B, 4 KiB, 64 KiB,
256 KiB, 1 MiB**, plus **stream** (unbounded; always fills whatever you give it).
The stream case is the one where buffer size is unconstrained by the payload, and
the only one #415 measured.

**3. Buffer size** — coarse pass **4, 16, 64, 256 KiB, 1 MiB**; refinement pass
adds **8, 32, 128, 512 KiB** around whatever knee the coarse pass finds. Going
past 1 MiB is possible (`buffer_size` is `u32`) but at that point one buffer
exceeds most messages in the grid, so extend only if 1 MiB is still climbing.

**4. Ring geometry policy** — the axis that decides whether "bigger buffers" is
even affordable:

- **constant memory** (4 MiB/worker, today's default): `count = 4 MiB / size`, so
  1 MiB buffers means a **4-deep ring**. Fan-in above 4 concurrent arrivals then
  hits `ENOBUFS`, parks, and falls back. This is where a big default breaks, and
  the counters from Phase 0 are what will show it.
- **constant count** (256 buffers): memory scales with size — 1 MiB buffers is
  **256 MiB per worker**, 2 GiB across 8 workers. Records what the geometry would
  cost if depth were held.

Both, every arm. The interesting output is the frontier between them.

**5. Concurrency** — **64 and 1024+ connections**, as separate passes rather
than a matrix axis. Ring depth pressure is a function of concurrent arrivals, so
the constant-memory policy can only fail at fan-in, and 64 connections never
pressures a 256-deep ring at all.

High fan-in is also the *realistic* way to saturate a server — production runs
thousands of connections, not 64 — which matters because **an arm that is not
server-bound measures the harness.** The first Phase A run proved that the hard
way: at 8 workers and 64 connections the proxy guest sat at ~8 of 24 cores on
the echo arms and ~9 on the forward arms, with every forward arm from 16 KiB to
1 MiB pinned to the ~22 Gbit/s wire ceiling — including a 1 MiB × 4 arm that
starved 441,351 times and still tied the clean arms. That surface was flat
because the server had headroom, not because geometry is irrelevant, and the two
are indistinguishable in the data. Each pass must be checked for saturation
(server CPU, or throughput that moves when the geometry does) *before* its
numbers are read as a result.

**6. Reference lines** — mio, tokio multi-thread, tokio per-core at each message
size, at their own defaults. These do not vary with ringline's ring geometry; they
are there to answer the actual product question: *does io_uring win out of the box
across the board?* Without them a new default could win the sweep and still lose
to tokio.

## Metrics per arm

Throughput and p50/p99 latency are not enough to explain anything; collect all of:

- throughput (ops/s or Gbit/s), p50/p99/mean latency
- server CPU from rezolus, and **instructions per byte**
  (`cpu_instructions / network_bytes`) — the metric that made #415's analysis
  decisive, because it separates fixed per-completion cost from per-byte work
- ring counters from Phase 0: `buffer_ring_empty`, `recv_parked`, `recv_fallback`,
  `forward_throttled`, `recv_arm_failures`
- server RSS, sampled from `/proc/<pid>/status`, plus page-fault rate — #284 found
  big buffers cost virtual and not resident memory; that claim is load-dependent
  and should be re-measured at 512 connections rather than inherited
- syscalls per operation

## Method

Two X710 guests on the 40G LAG, server alone on one, load on the other — the
#415 shape, not loopback. Loopback has no NIC, no DMA and no interrupt path, and
lets the load generator compete with the server for cores.

Arms are generated into one job pair per chunk with a `barrier` per arm (server
exec → `arm-N-ready` → client exec → `arm-N-done`), ~15 arms per chunk, so a
chunk pays one guest boot instead of one per arm. Barriers, not a hand-rolled
handshake: a barrier is the only construct that propagates a peer's failure, and
a wedged rendezvous holds a hypervisor until timeout.

Arms interleaved (A B A B …), 3 reps, first discarded.

## Phasing

- **Phase 0** — metrics dump + its gate. Blocking.
- **Phase A (coarse)** — 5 buffer sizes × 6 message sizes × 2 policies × 64 conns,
  copy and forward modes only: 120 arms, 1 rep, to find the shape. Kill any
  (mode, size) region that is flat before spending reps on it.
- **Phase B (refine)** — 9 buffer sizes around the knee, the modes and message
  sizes Phase A showed to be live, both concurrencies, 3 reps interleaved.
- **Phase C (decide)** — candidate geometry vs today's default across the full
  `BENCHMARKS.md` grid including the tokio and mio reference lines. A default that
  wins the sweep but loses the published comparison is not a win.

## Decision rule — write this down before the data arrives

A change to the default requires, at equal memory:

- no workload regressing throughput by more than **2%** or p99 by more than **5%**
- a material gain (**>10%**) on at least one mode that is not exotic
- no new `buffer_ring_empty` / `recv_parked` at 512 connections that was not there
  before — trading throughput for starvation under fan-in is not a trade

Outcomes, in preference order:

1. **One better global default.** Change it; re-run the `BENCHMARKS.md` grid,
   because every published number was taken at the old one.
2. **Per-mode defaults.** The delivery-mode APIs (`forward_to`, `with_segments`,
   …) pick their own geometry when armed, the global default stays for the copy
   path. Costs an API decision: geometry becomes per-connection, not per-worker,
   which the single shared ring per worker may not permit — check before promising
   it.
3. **Neither.** Document per-workload recipes on `ConfigBuilder::recv_buffer` and
   in `forward_to`, and record why a single default cannot serve both. This is a
   real outcome, not a failure: it is what #415's docs already say locally.

## If the answer is "neither size nor depth, but both"

The two policies exist because size and depth are one knob at a fixed memory
budget. They need not be: `IOU_PBUF_RING_INC` (Linux 6.12) consumes one buffer
incrementally across many completions, which would let a ring be deep *and*
carry a large payload per completion. That is a recv-path rework rather than a
flag, and it has its own entry —
`docs/journal/2026-09-incremental-buffer-consumption.md` — whose GO criterion 1
is precisely what this sweep is measuring.

## What would make this worth re-running later

Faster NICs. #284's criterion A (400/800 GbE) applies here too, and more strongly:
per-completion cost is a fixed instruction count, so its share of the budget grows
with line rate. At 40 GbE the fixed cost is 32% of the forward path's work at
16 KiB. At 400 GbE it would dominate.
