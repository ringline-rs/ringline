# Incremental provided-buffer consumption (`IOU_PBUF_RING_INC`)

- **Status:** open — design chosen, not built. **2026-10-08, after
  "2026-10: measurements" and "2026-10: kernels, two rings, tiered caches":
  the owner decided that two shared buffer groups go into the
  implementation for kernels before 6.12. The author proposes the large
  group off by default on 6.12+ until measured further, and a 1 s demotion
  quiet period. The author also proposes 4096 × 64 KiB plus 256 × 1 MiB
  before 6.12, on by default pending landing step 6. Design: `docs/recv-incremental-ring-design.md` (#622).**
  Phase A (2026-09-17) had narrowed the case: see "What Phase A did to
  criterion 1".
- **Span:** 2026-09-17 → (open) · follows #415 (282773b), #416 Phase A ·
  measurements with a standalone program that is not in the repository

## Goal

Break the link between **payload per completion** and **ring depth**.

Today those are one knob. A provided buffer ring is `count × size` at a fixed
memory budget, so making buffers bigger makes the ring shallower, and ring depth
is what bounds concurrent arrivals. Every workload therefore gets to pick which
of the two it wants to be wrong about.

`IOU_PBUF_RING_INC` (Linux **6.12**) lets one buffer be consumed incrementally:
each completion for a given bid continues where the previous one left off, the
CQE carries `IORING_CQE_F_BUF_MORE` while the buffer is still live, and the bid
returns only when it is fully consumed or errors. One large buffer then serves
many small arrivals — large payload per completion *and* deep effective
concurrency, from the same memory.

## Background: why this is on the table now

**#415 (282773b) measured the size axis and found it worth 25%.** A forwarding
proxy across two X710 guests at 40 GbE, one worker pair so the proxy is the
bottleneck, arms interleaved, medians of three:

| arm | Gbit/s | instr/byte |
|---|---|---|
| io_uring, 16 KiB buffers (the default) | 11.2 | 1.26 |
| mio, copy path | 12.8 | 1.12 |
| io_uring, 64 KiB buffers | 14.0 | 0.96 |

Solving the two io_uring points for a fixed per-completion cost gives **~6,600
instructions per completion cycle** — CQE decode, hold push, task wake, future
poll, write SQE, write CQE, bid replenish — against a **~0.86 instr/byte** floor
that is the kernel's own copy and TCP work. At 16 KiB that fixed cost is 32% of
all work; at 64 KiB, 10%. Bigger buffers are how Mode A gets cheap.

**#416 Phase A, chunk 1 measured the depth axis and found the other edge.**
Experiment `01a0b0ac-f3c7-714b-fa95-51e1f8a0f3bf`, 256 B echo, 64 connections:

| geometry | MiB/worker | ops/s | `buffer_ring_empty` | `recv_parked` |
|---|---|---|---|---|
| 1 MiB × 4 (constant memory) | 4.0 | 279,265 | 3,066,467 | 3,066,467 |
| 1 MiB × 256 (constant count) | 256.0 | 297,888 | 0 | 0 |
| 16 KiB × 256 (today's default) | 4.0 | 290,769 | 0 | 0 |

The 1 MiB buffer is not what hurt — the same buffer with depth held starves zero
times and is the *fastest* arm in the group. What hurt was the **four-deep ring**
that 1 MiB implies at a 4 MiB budget. That is exactly the constraint INC removes,
and it is measured rather than argued.

(Those counters are readable at all only because of #417, which added
`bench-server --metrics-out`; nothing in the workspace had ever read
`BUFFER_RING_EMPTY` or `RECV_PARKED` back out.)

## The honest ledger: a prior negative result I cannot cite

I have a recollection of an earlier 200 GbE sweep that evaluated INC alongside
adaptive sizing and found **INC not a win**. That result is **not checked in
anywhere in this repo** — `grep -rn "IOU_PBUF_RING_INC" docs/` finds only two
forward references in `docs/tls-unbuffered-design.md:607` and the Mode C
ordering notes in `docs/segmented-recv-design.md`, none of them a measurement.
Per the journal's ground rules, an uncheckable figure is stated as such: treat
"INC was already tried and lost" as **unverified** until either the data is
found or it is re-measured here.

What *is* on the record is the adjacent NO-GO: **self-adaptive recv buffering**
(`docs/journal/2026-07-self-adaptive-recv-buffering.md`, 2026-07-21), which
measured that (1) big buffers cost virtual and not resident memory, (2) the
discard path runs at line rate on the default 16 KiB ring, and (3) on the
**copying** path 16 KiB ≥ 256 KiB, because there a bigger buffer means a bigger
`memcpy`. That entry retired *adaptive* sizing — geometry that reacts to
observed traffic — and its reasoning does not cover INC, which changes how one
buffer is consumed rather than how buffers are chosen.

Its re-evaluation criteria are A (faster NICs), B (resident memory pressure),
C (a mixed workload where a fixed size loses on a gather path), D (a
mandatory-hold zero-copy consumer that starves). **None of them is what #415
found.** Mode A is not starving and not memory-bound; it is paying a fixed
per-completion cost that only a larger payload per completion amortises. If this
effort proceeds, it should add a **criterion E** to that entry rather than
quietly contradict it.

## What Phase A did to criterion 1

Two saturated passes (#416, 2 workers, 64 vs 1024 connections, 108 arms)
measured the gap between the shipped default and the best geometry chosen with
hindsight at the same memory budget — the "tuning burden" criterion 1 asks
about. The homogeneous version of that gap is now known:

| workload | default vs best-with-hindsight |
|---|---|
| echo, 5 message sizes, both fan-ins | −4% to −11% (one −19%) |
| **forward stream, 64 conns** | **−34%** |
| **forward stream, 1024 conns** | **−18%** |

**This is narrower than the case this entry opened with, and the entry should
say so.** For request/response traffic the default is within ~6% of the best
tuned geometry, so there is little burden for INC to remove — criterion 1's
">10% throughput" bar is not met there. The case now rests on **forwarding and
streaming**, where the gap is 18–34% and systematic across both fan-ins.

What Phase A *did* confirm is the mechanism, in a stronger form than expected.
The optimum moves along **two** axes in opposite directions — message size pulls
toward bigger buffers (payload per completion), fan-in pulls toward deeper rings
(concurrent arrivals) — and at fixed memory those trade directly. Six different
geometries win the twelve workloads; 1 MiB × 4 is the outright winner on four of
them and 83% down on another, with a **1.03-second p99** at 256 B × 1024
connections. So "you cannot pick one geometry" is established. What is *not*
established is that the resulting loss is large enough to justify a recv-path
rework, except for forwarding.

Criterion 1 therefore stands, with its target changed: measure the oracle gap on
a **mixed** workload **on the forwarding path**, where the homogeneous gap is
already 18–34%, rather than on request/response where it is ~6%. If a mixture
does not exceed the worst of its components there, this should be recorded
NO-GO.

## Why this is not a flag flip

Ringline's provided-buffer model assumes **one bid is one discrete segment**,
and INC makes a bid live across many completions. The assumption is load-bearing
in at least these places:

- `pending_replenish` returns a bid on completion. Under INC that must not
  happen while `F_BUF_MORE` is set.
- `segment_hold` holds one `HeldRecvBuf::Pinned { bid, len }` per segment, and
  Mode A writes exactly one held buffer per serialized write
  (`ForwardToFuture::poll`).
- The "**exactly one replenish per bid**" invariant
  (`docs/segmented-recv-design.md:307`) is enforced by a single-release
  discriminant across guard drop, `into_owned`, the Mode A write CQE, and
  `close_connection`.
- `close_connection` drains held bids; a partially consumed bid has no current
  representation.
- The design doc already names the hazard in user space: force-replenishing a
  bid a consumer still holds is "kernel DMA over live consumer data — the INC
  bug in user code" (`docs/segmented-recv-design.md:223`).

So the work is a recv-path rework with a new bid state (*partially consumed,
not returnable*), not a register-flag change.

## Kernel floor: runtime probe, not a build gate

`ringline/build.rs` emits `has_io_uring` at **6.1+** (`SendMsgZc` and
`DEFER_TASKRUN`). Gating INC at build time would drop every 6.1–6.11 host, which
is not an acceptable trade for an optimisation. It has to be a **runtime probe**:
register the ring with `IOU_PBUF_RING_INC`, fall back to a plain ring on
`EINVAL`. One extra register call per worker at startup, and it tests the actual
capability rather than parsing a version string — the same reason the existing
`Error::RingSetup` path checks behaviour rather than `uname`.

The rack can measure this today: the anvil guests run **6.12.63**.

## The criteria this started with were framed wrong

The first version of this entry asked INC to win on peak throughput for a
**tuned, homogeneous** workload. That is the case INC is *least* likely to win:
if you know the message size and can pick the geometry for it, a fixed ring
already gets the payload-per-completion you want. Owner's framing, 2026-09-17,
and it is the right one: the value of INC is **robustness without tuning**, and
mixed traffic is where fixed geometry actually hurts.

The mechanism, stated so it can be falsified:

- Size the buffer for the large messages and, at a fixed memory budget, the ring
  gets shallow — so the *small* messages starve on depth. Measured: 3,066,467
  starvations at 4-deep (Phase A chunk 1).
- Size it for the small messages and the large ones fragment across many
  completions — so the per-completion cost multiplies. Measured: 4 KiB buffers
  cost 34% of the forward path's throughput against 16 KiB (14.52 vs 21.99
  Gbit/s, Phase A chunk 4), and #415 measured the same axis worth 25% between
  16 and 64 KiB.
- INC serves many small arrivals from one large buffer, which is both.

A homogeneous sweep cannot see this, because each arm gets to be tuned for its
own single size. **Phase A is entirely homogeneous** — one `--msg-size` per arm
— so its flat copy-path surface is evidence about tuned workloads only and says
nothing about the mixed case. The 2026-07 NO-GO's GO gate was itself "a mixed
small+huge workload showing fixed-buffer waste", and it went unmet in part
because nothing was measured there. Repeating that omission would reach the same
non-answer by the same route.

## GO / NO-GO — revised

Proceed to implementation only if **all** of:

1. **A mixed workload costs a fixed geometry something an oracle would not
   pay.** Run a size distribution (small + large) against: (a) the geometry an
   operator would pick *without* knowing the distribution — the shipped default;
   (b) the best fixed geometry chosen *with hindsight*, by sweeping it; and
   (c) the worst plausible misconfiguration. The gap between (a) and (b) is the
   tuning burden INC would remove, and it has to be worth removing — call it
   >10% throughput or >20% p99 — or there is nothing here.
2. **A prototype closes most of that gap without being tuned**: at the default
   memory budget, within a few percent of (b) while beating (a), on a
   distribution it was not configured for.
3. **Neither path regresses when homogeneous.** The copying path in particular:
   the 2026-07 entry measured bigger buffers hurting it, and Phase A measured
   buffer size as flat for it across a 64× range. INC should be neutral there —
   same bytes, same copies, fewer bids. If it is not, that is its own finding.
4. **The bid lifecycle rework passes the existing invariants**: no double
   replenish, no leak, correct close-drain with a partially consumed bid, and
   the Mode A hold cap still bounds one slow forward.

Abandon and record if (1) is small. A tuning burden nobody is paying is not a
problem, however elegant the mechanism that would remove it.

Abandon and record if the prototype cannot hold invariant 4 without making the
recv path materially harder to reason about. A 10% throughput win is not worth
re-opening the class of bug that #236–#244 and #415 spent their time closing.

## Plan

0. **Mixed traffic needs no new client code.** `bench-client` has no size
   distribution — `--msg-size` is scalar, and its op accounting counts bytes
   (`(recorded + 1) * msg_size <= total_read`), which only works for a uniform
   size — but the property that matters is *one ring serving two size
   populations at once*, and two concurrent client processes against one server
   produce exactly that. It is also the better experiment: each population
   reports its own throughput and p99, so the table shows **which** population
   pays. An aggregate would hide the failure mode worth finding, which is the
   small messages starving while the large ones hold the ring.

   What it does not exercise is *within-connection* size variation. The ring is
   shared per worker and sees arrivals from every connection, so across-connection
   mixing is what reaches it either way; a per-operation mix would test the
   consumer's framing, not the ring's geometry.
1. Land #416 Phase A; read the homogeneous surface, which bounds criterion 3 but
   cannot decide criterion 1.
2. Measure the oracle gap: default vs hindsight-best vs misconfigured, on a
   mixed distribution. **This is the go/no-go.**
3. Only if the gap is worth it: prototype behind a runtime probe, no config
   surface — INC ring, `F_BUF_MORE` handling, partially-consumed bid state,
   replenish only on final completion.
4. Either: design doc + criterion E in the 2026-07 entry + implementation PR; or
   NO-GO here with the mechanism and the measured gap recorded.

## Open questions

- **Does INC compose with Mode A at all?** A forward writes one held buffer per
  write. Under INC the "buffer" is a moving window inside one bid, so either
  Mode A writes sub-ranges of a live bid (and the bid outlives many writes), or
  it copies out. The second defeats the purpose.
- **What does the hold cap bound under INC?** `forward_hold_cap` counts held
  buffers as a proxy for pinned ring capacity. With one bid serving many
  arrivals the count stops meaning that.
- **Does `F_BUF_MORE` interact with the ENOBUFS park/fallback path?** The
  fallback recv (#274) exists because a small ring starves; INC changes what
  "small" means, and #415 had to exclude segmented connections from the fallback
  entirely.
- **Is the win just "bigger buffers" in disguise?** If a deep ring of large
  buffers (constant-count, 256 MiB/worker) is affordable in RSS terms, the cheap
  answer may be to raise the memory budget rather than rework the recv path.
  But the affordability claim needs re-testing rather than inheriting, and the
  mechanism matters:

  The provided ring's backing is a plain `vec![0u8; ring_size * buf_size]`
  (`backend/uring/provided.rs:54`) — **not** `mlock`ed, no `MAP_LOCKED`, no
  `MAP_POPULATE`, and not charged to `RLIMIT_MEMLOCK` (that limit covers
  *registered fixed buffers* from `ConfigBuilder::registered_regions`;
  `register_buf_ring` pins only the ring structure, entries × 16 B). So
  over-provisioning costs virtual address space up front, exactly as the
  2026-07 entry found.

  The catch is that `alloc_zeroed` pages become resident **when touched, and
  stay resident**. The 2026-07 measurement (~11 MB RSS for a 256 KiB-buffer
  ring) was taken on a steady workload: it is a statement about what that
  benchmark touched, not a guarantee about what production touches. A burst that
  reaches every buffer converts the whole ring to RSS — 256 MiB/worker, 2 GiB
  across 8 workers, permanently. Over-provisioning to avoid tuning is therefore
  cheap under steady load and expensive under bursty load, which is the case an
  operator cannot predict and the reason this question is not settled by the
  earlier number. Measure RSS *and* peak-touched pages under a bursty mixed
  workload before treating a deep ring as free.

## 2026-10: measurements

The recv redesign (#622) first proposed per-connection receive memory (each
connection's bytes land in memory it owns). Before deciding, the owner asked
for measurements of every candidate. This section records them and how they
were read.

### Method

`experiments/recv-strategies/`, which is not in the repository, is a standalone
io_uring program, not ringline: a single-threaded server pinned to one CPU,
`DEFER_TASKRUN`, length-prefixed messages, and a client that counts acked
messages and records latency. Each receive strategy is a small module
written directly against io_uring:

| Strategy | Receive model |
|---|---|
| `shared` (or `plain_*`) | ringline today: one plain provided-buffer ring per worker, parse in place when nothing is buffered, copy otherwise, fallback one-shot recv on `ENOBUFS` |
| `inc_*` | the same ring registered with `IOU_PBUF_RING_INC` |
| `ring` | a one-entry INC ring per connection over the connection's region; moves rewrite the posted entry in place |
| `ring_norewrite` | the same, never touching a posted entry |
| `oneshot` | one-shot `RECV` into the connection's region |

`--adapt` (added 2026-10-07) grows a per-connection region when its posted
range is used up while data flows, and shrinks it after it stays empty.
`--verify` stamps every message with its connection's sequence number and a
derived payload, and the server checks every byte. `--hold-every` /
`--hold-us` / `--lend-cap` make every second connection keep each received
range lent for a time, as a forward to a slow sink does, with a cap on how
much of the ring held lends may pin.

Two setups, both on Linux 7.1.13 (the backports image):

- **hv01**: one VM (`z2.c`, 56 vCPU), server and client in it over
  loopback, which delivers bytes in bursts at memory speed.
- **Two hosts**: server VM on hv02 (`z1.c`), client VM on hv01, over each
  guest's 4 × 10 GbE 802.3ad bond (layer3+4). A calibration run
  (`01a114e0-077e-7100-6a96-ee2f7660185b`) found NIC interrupts and NET_RX
  softirq spread over all 24 server vCPUs (5% on the server's CPU) and eight
  servers reaching 26.6 Gb/s, so one server's core is bounded by its own
  work: these numbers are one worker's steady-state cost at about 1.5 GB/s.

Five reps per cell, configurations interleaved within each rep; medians
below. An A/A pair (the same configuration twice) agreed within 1–2% on
hv01; the two-host experiments had no A/A pair, and their per-cell spreads
were 0–11%.

**Superseded.** The first loopback runs (v1 `01a1121f`, v2 `01a11274`, v2b
`01a112fc-f7ea`, the pool sweep `01a1134e-f20c`, the plain-ring and lend-cap
sweeps `01a114ba-bb57` and `01a114ba-bbf0`) ran on the validation host,
delta, which also runs frigate and the infra VMs. Their A/A spreads reached
19.5% and the same configuration moved 25% between experiments; two of
their findings did not reproduce on hv01 (today's ring starving at 10,000
connections, and today's ring winning streaming). They are not used below.
Two bugs in the benchmark also invalidated v2 cells (a CQ larger than
`IORING_MAX_CQ_ENTRIES`, and an accumulator that never compacted under
streaming), and its framing checked lengths only until `--verify` was added.

### Results

Core comparison, hv01 (`01a11520-5424-7143-8c86-731a6e6738bb`), msg/s:

| Workload (conns) | Today 256 × 16 KiB | INC 64 × 64 KiB | INC 64 × 1 MiB | `ring` | `oneshot` |
|---|---|---|---|---|---|
| 256 B (64 / 1000 / 10k) | 90k / 83k / 47k | 92k / 85k / 46k | 90k / 84k / 47k | 92k / 83k / — | 95k / 51k / 43k |
| 64 KiB (64) | 37.3k | 48.8k | 43.0k | 47.9k | 51.3k |
| 64 KiB (1000) | 32.0k | 44.5k | 38.1k | 38.0k | 28.8k |
| 64 KiB (10k) | 29.8k | 39.5k | 34.8k | — | 30.7k |
| 1 MiB (64) | 3.2k | 3.3k | 5.7k | 5.4k | 5.4k |
| mixed (1000) | 61.0k | 65.2k | 74.0k | 76.9k | 47.2k |
| pipelined mixed (1000) | 199k, p99 76 ms | 209k | 258k, p99 33 ms | 166k | 118k |
| stream, mixed sizes (1000) | 110k | 133k | 128k | 85k | 88k |

`ring` at 10k connections did not start: on 7.1 each one-entry ring is
charged a page of `RLIMIT_MEMLOCK`, and 2041 fit under the default 8 MiB.

Geometry, two hosts (`01a11520-54ad-71fa-9dce-bc7e913ed435`), msg/s:

| Workload (conns) | Today | INC 4 MiB / 64 KiB | INC 16 MiB / 1 MiB | INC 64 MiB / 1 MiB | `ring` |
|---|---|---|---|---|---|
| mixed (1000) | 79.2k | 80.2k | 85.0k | 85.7k | 84.6k |
| 64 KiB (1000) | 19.9k | 21.6k | 23.5k | 23.6k | 24.0k |
| 1 MiB (64) | 1.6k | 1.6k | 1.7k | 1.7k | 2.1k |
| 256 B (10k) | 106.7k | 107.0k | 107.1k | 107.0k | 105.8k |
| stream 16 KiB (64) | 109.6k | 108.6k | 110.5k | 114.2k | 83.1k |
| stream 16 KiB (1000) | 93.9k | 103.6k | 96.9k | 102.0k | 73.2k |

Geometry, hv01 (`01a11520-55d2-7179-7c79-b2a7536f50c1`): a 16 MiB pool of
1 MiB buffers did 6.3k at 1 MiB × 64 and 368k streaming at 64 connections
(64 MiB: 5.7k and 300k), and 214k streaming at 1000 (64 MiB: 234k).

Streaming alignment, hv01 (`01a11520-5543-7171-7461-ba465491f200`). INC
beat today's ring in every streaming cell, at 12000 B, 16384 B, 20000 B and
mixed sizes, 64 and 1000 connections: INC 64 × 1 MiB by 8–50% at 7–33% less
CPU per KiB, and INC 64 × 64 KiB by 10–43% at 9–30% less.
Today's ring parsed 99% of bytes in place only when the message size equalled
its 16 KiB buffer and the ring kept running dry (16384 B × 1000), and 0–4%
otherwise.

Plain rings for kernels without INC, hv01 and two hosts
(`01a11520-56b7-71f4-ce93-6f895c7992ed`, `01a11520-5644-7109-7752-ad578a83da4d`),
msg/s:

| Workload (conns) | 256 × 16 KiB | 1024 × 16 KiB | 4096 × 16 KiB | 1024 × 64 KiB | INC 64 × 1 MiB |
|---|---|---|---|---|---|
| hv01 mixed (1000) | 58.4k | 60.5k | 56.1k | 73.5k | 73.6k |
| hv01 64 KiB (1000) | 32.3k | 28.9k | 28.4k | 38.9k | 38.3k |
| hv01 64 KiB (10k) | 29.6k | 27.0k | 27.2k | 35.1k | 34.8k |
| hv01 1 MiB (64) | 3.3k | 2.7k | 2.2k | 2.9k | 5.7k |
| hv01 stream 16 KiB (1000) | 216.6k | 187.4k | 180.6k | 215.4k | 234.0k |
| two hosts mixed (1000) | 79.0k | 79.2k | 78.6k | 86.5k | 85.2k |
| two hosts 64 KiB (1000) | 20.0k | 19.8k | 20.0k | 23.6k | 23.5k |
| two hosts stream 16 KiB (1000) | 92.0k | 87.9k | 86.5k | 94.5k | 105.3k |

Small messages were the same in every column. Today's ring beat
1024 × 64 KiB at 1 MiB × 64 on hv01 (3.3k against 2.9k); across hosts the
two were level, and INC's 1 MiB gain disappeared there (1.6k in every
column).

Lend cap, INC 64 × 1 MiB, every second connection holding each range for
50 ms, 64 KiB × 1000 (hv01 `01a11520-57a3-7131-2c26-f10fce555c09`, two
hosts `01a11520-5730-7182-d5f0-6a93de5e30e7`): no cap 20.1k (19.9k); caps
0–0.75 between 36.6k and 38.0k (22.5–22.8k); no holds 38.2k (23.2k). Across
hosts, caps 0–0.75 were within 3% of each other on 4 KiB, 64 KiB and mixed
traffic; on hv01 mixed traffic they spread 68.3–76.8k, which its per-cell
spreads (±4–16%) cannot resolve. With 5 ms holds the pinned buffers peaked
at 19, so caps of 0.5 and above never engaged. Only 1000 connections were
measured.

Per-connection rings with adaptive regions, hv01
(`01a11649-5df3-7153-91b9-ff606706d842`), `ring_norewrite --adapt` (1 MiB
cap) against INC 64 × 1 MiB: streaming at 1000 connections +21% (16 KiB) and
+26% (mixed sizes); streaming at 64 connections −6%; pipelined mixed −8%;
mixed −13%; 64 KiB × 1000 −19%; 64 KiB × 10k −39%; 1 MiB × 64 −11%. Its
regions grew to the cap and stayed: RSS about 1 GiB at 1000 connections on
every workload, 6.1 GiB at 10k × 64 KiB. INC's own RSS streaming at 1000
connections was 737–891 MB, from accumulators grown by completions of up to
1 MiB. `ring --adapt` with a 256 KiB cap (the rewriting variant) stalled at
1 MiB messages, which cannot fit. These were measured on hv01 only; the
two-host run (`01a11649-5e78-717b-a0c8-434715ed6dd3`) had not finished when
this was written.

### Latency at fixed rate

The closed-loop client measured latency from the last byte written, and it
compared configurations at different loads: a faster server drew more
traffic and queued it. At 1 MiB × 64 on hv01 that read as p99 rising from
5.0 ms (today's ring, 3.2k msg/s) to 13.6 ms (INC, 5.7k msg/s). The
latency runs therefore use an open-loop client (`--rate`): each connection
sends on a fixed schedule whatever has been acked, and latency runs from
each message's scheduled time, so all configurations see the same traffic
and a server that falls behind is charged for the queueing. Rates are about
25, 50, 75 and 90% of today's ring's closed-loop capacity on each setup.
hv01 `01a11778-a253-7123-caea-635929d95ac9`, two hosts
`01a11778-a2d3-710c-2e87-72564e729f3c`; 400 runs each, none failed.

p50 / p99 / p999 in ms:

| Cell (rate) | Today 256 × 16 KiB | INC 64 × 1 MiB | plain 1024 × 64 KiB | plain 64 × 1 MiB |
|---|---|---|---|---|
| hv01 1 MiB × 64 (2400/s) | 2.4 / 3.7 / 3.9 | 2.1 / 3.3 / 3.8 | 2.5 / 3.9 / 4.5 | 2.0 / 3.0 / 3.3 |
| hv01 1 MiB × 64 (2900/s) | 268 / 1074 / 1208 (2.7k/s served) | 2.1 / 3.5 / 3.9 | 2.6 / 105 / 419 | 2.0 / 2.9 / 3.3 |
| hv01 256 KiB × 64 (11000/s) | 1.0 / 1.9 / 2.5 | 0.9 / 1.7 / 2.0 | 1.0 / 5.8 / 7.6 | 0.9 / 1.7 / 2.4 |
| hv01 64 KiB × 1000 (28500/s) | 0.9 / 1.6 / 2.4 | 0.7 / 1.6 / 1.9 | 0.7 / 1.6 / 1.8 | 0.7 / 1.6 / 1.8 |
| hv01 mixed × 1000 (54000/s) | 0.6 / 1.0 / 2.0 | 0.5 / 0.8 / 1.6 | 0.5 / 0.8 / 1.5 | 0.5 / 0.7 / 1.4 |
| hv01 4 KiB × 1000 (70000/s) | 0.6 / 1.0 / 1.8 | 0.6 / 1.3 / 2.4 | 0.6 / 1.2 / 1.8 | 0.6 / 1.2 / 1.6 |
| two hosts 1 MiB × 64 (1125/s) | 16.8 / 21.0 / 46.1 | 16.3 / 19.9 / 21.0 | 16.8 / 21.0 / 23.1 | 16.8 / 19.9 / 22.0 |
| two hosts 256 KiB × 64 (4850/s) | 3.0 / 5.2 / 11.0 | 2.6 / 4.5 / 10.5 | 2.6 / 5.0 / 10.5 | 2.4 / 4.5 / 10.0 |
| two hosts 64 KiB × 1000 (18000/s) | 2.2 / 4.2 / 5.8 | 2.0 / 3.1 / 4.7 | 1.9 / 3.1 / 4.2 | 2.0 / 3.1 / 5.2 |
| two hosts mixed × 1000 (72000/s) | 1.0 / 2.1 / 3.7 | 0.9 / 1.9 / 2.6 | 0.9 / 1.8 / 2.8 | 0.9 / 1.9 / 2.9 |
| two hosts 4 KiB × 1000 (67000/s) | 0.9 / 2.0 / 2.8 | 0.9 / 1.9 / 3.3 | 0.9 / 2.0 / 3.0 | 0.9 / 2.0 / 3.0 |

At the lower rates every configuration was within about 0.3 ms of the
others at p99. Near capacity INC kept its latency where today's ring fell
behind (hv01, 1 MiB at 2900/s). INC's p999 was higher than today's ring's
at 4 KiB near capacity on both setups (2.4 against 1.8 ms; 3.3 against
2.8 ms). Plain 1024 × 64 KiB had a large-message tail on hv01 near capacity
(p99 105 ms at 1 MiB, 5.8 ms at 256 KiB). Plain 64 × 1 MiB, a 64-deep
plain ring, matched the others at these connection counts; it was not
tested with more connections or bursts, where its depth is the risk.

### Correctness

Every byte verified (`--verify`), Linux 6.12 and 7.1, 1000–10,000
connections, mixed, pipelined and streaming traffic:

- INC on the shared ring (`01a114c0-d1a4`, `01a1150d-01a6`): clean in 144
  runs (174 with the bisect's small-queue runs), including a 64-entry CQ
  with a 32-entry SQ (inline submits recorded; CQ overflow not measured),
  SQPOLL, SQPOLL with the small queues, and held lends. A deliberate
  one-byte offset error in the INC strategy, tried locally, was caught at
  once.
- Per-connection rings (`01a11648-ef98`, `01a11648-f03c`, and the bisect
  `01a1166a-fbc5`, `01a1166a-fc47`): `ring`, which rewrites a posted entry in
  place to move its region, delivered wrong bytes with the small queues on
  both kernels, adaptive or not (up to 26 bad messages in five runs), with
  a 64-entry CQ and a 32-entry SQ; with default queues it was clean.
  `ring_norewrite` delivered no wrong byte in any run, including one where
  the kernel had written past the reaped bytes. Three of its small-queue
  streaming runs (two on 6.12, one on 7.1) lost one connection each, which
  is unexplained.

### Kernel facts on 7.1

`inc-probe` passed every fact on 7.1.13 as on 6.12: contiguous append, the
entry advanced in place, re-posting after `F_BUF_MORE` clears continues the
arm, a posted entry rewritten between enters is honoured, a stale arm writes
into a re-registered bgid, and unregister then data gives `-ENOBUFS`.
`ring-limit`: under the default 8 MiB `RLIMIT_MEMLOCK`, 2041 one-entry rings
registered before `ENOMEM`.

### Reading against GO / NO-GO

1. **Tuning burden on a mixed workload.** Not measured as an oracle gap. On
   mixed traffic INC 64 × 1 MiB beat today's ring by 21% on hv01 and 8%
   across hosts, and the best plain geometry (1024 × 64 KiB) matched it, so
   much of that is buffer size rather than INC.
2. **Closing the gap untuned.** INC 64 × 1 MiB beat today's ring or matched
   it on throughput in every measured cell on both setups. Other geometries
   beat it in some cells: INC 64 × 64 KiB at 64 KiB messages (13–17%) and on
   streaming at 64 connections (10–16%, three of four sizes) on hv01, INC 16 × 1 MiB at 1 MiB
   × 64 (11%) and streaming at 64 connections (23%) on hv01, and `ring` at
   1 MiB across hosts (24%).
3. **No homogeneous regression.** None on throughput. At equal offered load
   (see "Latency at fixed rate"), latency matched today's ring or was lower,
   except p999 at 4 KiB messages near capacity. On hv01, streaming at 64
   connections used up the 64 MiB ring in every run (about 30–42k
   `ENOBUFS` per run).
4. **The bid lifecycle.** Not tested; it is the design's subject.

**"Is the win just bigger buffers in disguise?"** Partly. A plain ring of
1024 × 64 KiB matches INC 64 × 1 MiB on 64 KiB, mixed and small traffic.
INC's own gains are at 1 MiB messages (5.7k against 2.9k on hv01) and on
streaming (234k against 215k on hv01, 105k against 95k across hosts). That
plain ring was the design's choice at the time; see "Decision and
proposals (2026-10-08)".

**Decision (owner, 2026-10-06 and 2026-10-07).** One shared ring per worker:
INC 64 × 1 MiB on 6.12+, plain 1024 × 64 KiB below. Measurements are taken
on hv01 and hv02, not on the validation host. Per-connection receive
memory was rebuilt with adaptive regions and still not chosen: the variant
that can move a live region corrupts data, and the one that cannot loses
request/response traffic and keeps its grown memory. A hybrid that gives
streaming and forwarding connections their own receive memory is a
follow-up.

**RSS.** The open question above about touched pages staying resident
stands, now with an answer for the ring: a 64 MiB pool is fully resident on
any worker that has received 64 MiB.

## 2026-10: kernels, two rings, tiered caches

The decision above left two things open: what to recommend on kernels
without INC, measured on such kernels rather than on 6.12 as a stand-in,
and whether a second, large-buffer group helps streaming and forwarding
connections. This section records those runs (2026-10-07 and 2026-10-08).

### Method changes

- **Bounded accumulator** (`--bounded-acc`): a completion copies into the
  accumulator only what completes the pending message and parses the rest in
  place. Every configuration below uses it. In the streaming cells it cut
  RSS from 2.3 GiB to 262 MiB (INC 64 × 1 MiB, hv01; with a 1 GiB plain
  ring only from 2.0 to 1.07 GiB) and bytes copied sevenfold, at 10–58% more
  throughput (hv01 `01a11885-c77f-7166-f3e7-a7c1f337c950`, two hosts
  `01a11885-c7f9-7178-4ae7-ccecdb8b4337`).
- **`--no-thp`** (`MADV_NOHUGEPAGE`) on plain rings: with transparent huge
  pages a 64 KiB or 1 MiB completion made its whole 2 MiB region resident
  (hv01 `01a11783-c258-719e-f54d-392e414d1312`, two hosts
  `01a11783-c2c8-7118-b7f6-30d77b83989c`).
- A kernel cap on bytes per multishot completion (`--recv-len`) was tried
  and dropped: 6.12 rejects a nonzero length on multishot `RECV` with
  `EINVAL`; 7.1 accepts it, and it lowered throughput.
- Stall statistics per connection (longest gap between deliveries, time from
  a first `ENOBUFS` to the next delivery), a second-client mode for mixed
  cells (16 streamers connected first, their bytes counted apart), and
  fixed-rate request clients.
- Setups: the 6.12 stand-in and the Amazon Linux 2023 runs are loopback on
  hv01 (the 6.12 stand-in also has a two-host run); every other run is
  two-host, server VM on hv02 and client VM on hv01 over a 4 × 10 GbE bond.
  Three reps per cell, configurations interleaved; medians. Statically
  linked binaries, so each guest image runs the same build.

### Linux 6.12 as a stand-in for older kernels

hv01 `01a119eb-faf8-713c-de38-4c872eeca62c`, two hosts
`01a11ab1-7eb9-719e-5777-3e5165b760fa`, Debian 13, 6.12.63. On 6.12 plain
rings return `ENOBUFS` in the millions at 10,000 connections, where 7.1
returns none; depth reduces it. On hv01, msg/s and `ENOBUFS`:

| Cell | 256 × 16 KiB | 1024 × 64 KiB | 4096 × 64 KiB | 1024 × 1 MiB | INC 64 × 1 MiB |
|---|---|---|---|---|---|
| 256 B × 10k | 32.4k (11.1M) | 40.7k (3.2M) | 42.7k (0.55M) | 40.4k (3.2M) | 47.6k (0) |
| 64 KiB × 10k | 13.5k (18.2M) | 28.4k (2.2M) | 30.5k (0.38M) | 28.7k (2.2M) | 29.4k (2.3M) |
| 1 MiB × 64 | 3.6k | 3.0k | 3.0k | 5.2k | 5.4k |
| stream-mix × 1000 | 115k | 142k | 141k | 183k (1.2 GB RSS) | 181k |
| 64 KiB × 1000 at 28.5k/s, p50 | 26.2 ms | 0.62 ms | 0.62 ms | 0.62 ms | 0.62 ms |

### Linux 6.1

**Loopback, hv01, Amazon Linux 2023, 6.1.159**
(`01a11be9-5f7e-71db-173b-1a9df0f897ba`). Registering a ring with
`IOU_PBUF_RING_INC` returned `EINVAL`, in the probe and in every INC cell.
msg/s, `ENOBUFS`, p50 / p999:

| Cell | 256 × 16 KiB | 1024 × 64 KiB | 4096 × 64 KiB | 1024 × 1 MiB |
|---|---|---|---|---|
| 256 B × 10k | 57k (19.6M), 168 / 176 ms | 84k (6.6M), 117 / 134 ms | 105k (25k), 21 ms / 2.7 s | 84k (6.6M), 117 / 134 ms |
| 64 KiB × 10k | 16k (20.7M), 604 / 638 ms | 44k (3.4M), 226 / 252 ms | 47k (28k), 67 ms / 5.1 s | 43k (3.4M), 226 / 252 ms |
| 64 KiB × 1000 at 28.5k/s, p50 / p999 | 0.79 / 1.97 ms | 0.75 / 1.77 ms | 0.75 / 1.77 ms | 0.72 / 1.77 ms |
| 1 MiB × 64 | 3.3k | 3.1k | 3.1k | 5.4k (1.1 GB resident) |
| stream-mix × 1000, MB/s | 3226 | 4117 | 3820 | 4677 |

The 2–6 s p999 at 4096 × 64 KiB held in all three reps and is unexplained.
It did not reproduce across two hosts on Debian 12's 6.1 (below), and
6.12 showed no such tail. The AL2023 guest ran about 1.4 times faster than
the Debian 13 guest in the same cells, so only ratios within a run compare.

**Two hosts, Debian 12, 6.1.0-53** (`01a11cbb-70d8-7181-ea9d-4d9adb77267d`).
`IOU_PBUF_RING_INC` returned `EINVAL`. 144 of 144 runs, no corrupt messages:

| Cell | 256 × 16 KiB | 1024 × 64 KiB | 2048 × 64 KiB | 4096 × 64 KiB | 1024 × 1 MiB |
|---|---|---|---|---|---|
| 256 B × 10k, msg/s (`ENOBUFS`) | 38k (12.9M) | 54k (4.3M) | 57k (2.0M) | 62k (0.83M) | 54k (4.3M) |
| ↳ p50 / p999 | 260 / 268 ms | 185 / 210 ms | 176 / 201 ms | 143 / 226 ms | 185 / 210 ms |
| 64 KiB × 10k, msg/s | 8.0k | 18.9k | 19.2k | 20.0k | 18.6k |
| ↳ p50 / p999 | 1141 / 1342 ms | 537 / 872 ms | 520 / 1275 ms | 436 / 1074 ms | 537 / 805 ms |
| 64 KiB × 1000 at 18k/s, p50 / p999 | 604 / 1946 ms | 67 / 168 ms | 92 / 243 ms | 63 / 134 ms | 71 / 143 ms |
| stream-mix × 1000, MB/s | 1068 | 1142 | 1056 | 1074 | 1440 (1.2 GB) |

Every connection hit `ENOBUFS` at least once in every plain configuration,
warmup included. The median wait from a first `ENOBUFS` to the next
delivery at 256 B × 10k fell with depth: 255 ms for 256 × 16 KiB, 170 ms
for 1024 × 64 KiB, 68 ms for 4096 × 64 KiB.

**Ubuntu 24.04, 6.8.0-142** (`01a11cbb-7154-7103-1bbb-e8e7af7f2928`): every
run failed to register its ring, plain or INC, with `EINVAL`. A probe showed
the kernel requires `resv[0]` set (#626, fixed for ringline in #627). The
6.8 numbers wait for a rerun with that fix.

### Linux 7.1 at 10,000 and 50,000 connections

Two hosts, Debian 13 backports kernel (`01a11962-e405-71fd-0f61-c5ac0d91fa86`).
No configuration returned `ENOBUFS`. INC 64 × 1 MiB and the plain rings tied
almost everywhere; at 50,000 connections INC's p99 at a fixed 72k/s mixed
load was 906 ms against 604–638 ms for the plain rings, and it was 3% lower
on 64 KiB closed loop. The 256 × 16 KiB ring was 15% lower at 10,000 and
33% lower at 50,000 on 64 KiB closed loop, could not hold 16k/s of 64 KiB
at 50,000 connections (p50 1.3 s), and used 2–3 GB RSS against 0.3–1 GB.

### Two rings

A second buffer group of 1 MiB buffers. Connections are promoted to it and
demoted back (`two_ring`, `two_ring_inc`); a move cancels the live
multishot receive and re-arms on the other group.

**First rule, four consecutive full completions** (6.1 Debian 12
`01a11cfc-3148-718b-a774-c670177d1490`, 6.12 Debian 13
`01a11cfc-30d3-71a6-9833-8ac3e633db4f`). On 6.1 two groups (4096 × 64 KiB
+ 256 × 1 MiB) beat the 4096 × 64 KiB group on streaming (1216 against
1030 MB/s) and cut request latency 4–5× with streamers present. 64 KiB
request/response messages fill a 64 KiB buffer exactly, so those
connections were promoted and stayed (median 833 promotions, 0–2 demotions
and 831 connections in the large group at the end, per run). They starved
the large group (147k `ENOBUFS`) and lost 5% throughput. On 6.12 two INC groups
tied one on streaming, 1 MiB and 64 KiB request/ack and the control. In the
mixed cells, p50 / p99 / p999 in ms:

| 6.12 cell, first rule | INC 64 × 1 MiB | two INC groups |
|---|---|---|
| 1000 at 20k/s + 16 streamers | 5.8 / 8.9 / 54.5 | 10.0 / 16.8 / 19.9 |
| same, streamers holding 10 ms | 6.0 / 9.4 / 54.5 | 4.5 / 7.6 / 54.5 |

**`SOCK_NONEMPTY` rule**: a full completion counts only when it carries
`IORING_CQE_F_SOCK_NONEMPTY` (6.12 `01a11d44-3a29-71f7-c1a9-244e24bdebd2`,
6.1 `01a11d44-3a9e-71f7-9019-7cc0a98b5d66`). The 256 B × 10k and 64 KiB ×
1000 control cells promoted no connection on either kernel. The tiered cells
are a RAM+disk cache: 1000 request/response connections at 20k requests/s
with a quarter of them holding each received range for 5 ms, alone and with
16 streamers. Request p50 / p99 / p999 in ms:

6.1 (Debian 12):

| Cell | 4096 × 64 KiB | two groups | two groups, at most 64 promoted |
|---|---|---|---|
| stream-mix × 1000, MB/s | 1006 | 1328 | 1137 |
| 1000 at 20k/s + 16 streamers | 185 / 369 / 369, streamers 813 MB/s | 65 / 134 / 151, 1001 MB/s | 50 / 352 / 419, 1130 MB/s |
| same, streamers holding 10 ms | 302 / 419 / 419, 791 MB/s | 33 / 61 / 67, 1224 MB/s | 29 / 71 / 84, 996 MB/s |
| tiered | 1.4 / 1.8 / 2.8 | 1.4 / 1.8 / 2.4 | 1.4 / 1.8 / 2.6 |
| tiered + 16 streamers | 319 / 436 / 453 | 13 / 117 / 151 | 403 / 570 / 570 |
| 1 MiB × 64 request/ack, MB/s | 1320 | 1376 (613 promotions, 567 demotions) | 1276 |
| peak RSS, mixed cells | 282 MiB | 580–583 MiB | 543 MiB |

6.12 (Debian 13):

| Cell | INC 64 × 1 MiB | two INC groups | two INC groups, promote on hold too |
|---|---|---|---|
| stream-mix × 1000, MB/s | 1715 | 1811 | 1734 |
| 1000 at 20k/s + 16 streamers | 8.1 / 13.6 / 37.8 | 4.5 / 7.6 / 54.5 | 4.2 / 7.3 / 54.5 |
| same, streamers holding 10 ms | 7.9 / 12.1 / 54.5 | 5.0 / 8.1 / 54.5 | 6.8 / 11.5 / 54.5 |
| tiered | 1.05 / 1.5 / 2.2 | 1.02 / 1.5 / 1.9 | 1.02 / 1.5 / 2.0 |
| tiered + 16 streamers | 19.9 / 33.6 / 35.7 (237 `ENOBUFS`) | 8.9 / 14.7 / 16.3 (0) | 9.4 / 15.2 / 17.8 (0) |
| peak RSS, mixed cells | 71 MiB | 135 MiB | 117–135 MiB |

In the 6.12 stream-mix cell a median of 88 of 1000 streaming connections
ended in the large group, and the small group still returned 122k
`ENOBUFS`.

**Heavy-tailed request sizes**: 64 B to 1 MiB, about half 64 B and 0.5%
1 MiB, mean about 12.5 KB, at 20k requests/s (6.12
`01a11d45-3f0a-71ba-dcfa-52bcf6190593`, 6.1
`01a11d45-3f7d-71bc-53b6-95a2526e0900`). p50 / p99 / p999 in ms:

| Cell | 6.12 INC | 6.12 two groups | 6.1 4096 × 64 KiB | 6.1 two groups |
|---|---|---|---|---|
| sizes | 1.11 / 2.49 / 3.41 | 1.05 / 2.49 / 3.54 | 1.44 / 3.93 / 5.50 | 1.44 / 3.80 / 5.77 |
| sizes, tiered | 1.11 / 2.49 / 3.28 | 1.05 / 2.49 / 3.67 | 1.44 / 3.80 / 5.24 | 1.44 / 4.06 / 6.55 |
| sizes, tiered + 16 streamers | 7.6 / 13.6 / 37.8 | 6.6 / 11.5 / 56.6 | 168 / 520 / 537 | 11 / 25 / 59 |

On 6.1 large requests promoted request/response connections: 649
promotions and 358 demotions per run in the sizes cell, about 290 of 1000
connections in the large group at the end. In the 6.1 64 KiB × 1000
request/response cell, two groups saw 102,678–104,001 completions of
64 KiB per run, none carrying `SOCK_NONEMPTY`, and promoted no connection;
in stream-mix every full completion carried it.

### What was measured and what was inferred

Measured:

- 6.1 rejects `IOU_PBUF_RING_INC` with `EINVAL` (Debian 12, AL2023).
- Plain rings on 6.1 and 6.12 run out at 10,000 connections; 7.1 does not.
- Among plain geometries on 6.1, 4096 × 64 KiB had the highest throughput
  at 10,000 connections and the lowest latency in the fixed-rate cell
  across hosts.
- The `SOCK_NONEMPTY` rule promoted no 64 KiB request/response connection
  on 6.1 or 6.12.
- On 6.1, in every cell with 16 streamers sharing the worker, two groups
  cut request p50 and p99 by 2.8× to 25×: 2.8× (mixed), 7–9× (streamers
  holding), 3.7–25× (tiered with streamers), 15–21× (heavy-tailed, tiered
  with streamers). In the tiered and heavy-tailed cells without streamers,
  p50 was the same with one or two groups. In the 1 MiB × 64 request/ack
  cell (`01a11d44-3a9e`), two groups lowered p50 from 46–48 to 36–38 ms
  and raised p99 from 92–96 to 117–126 ms; the reps did not overlap.
  Tiered p999 fell (2.75, 2.62, 3.15 ms per rep
  with one group; 2.36, 2.03, 2.49 ms with two;
  `01a11d44-3a9e-71f7-9019-7cc0a98b5d66`). Heavy-tailed tiered p99 rose
  (3.54, 3.80, 3.80 against 4.06, 4.19, 3.93 ms) and its p999 rose from
  5.2 to 6.6 ms in all three reps (`01a11d45-3f7d-71bc-53b6-95a2526e0900`).
- A cap on promoted connections was worse wherever more than 64 needed
  promoting.
- Two groups were not run on 7.1, nor on any kernel between 6.2 and 6.11.
  Only one large-group size (256 × 1 MiB before 6.12) was run.

Inferred, not measured:

- That the 6.1 gains come partly from fewer completions per byte, freeing
  the server's one CPU (97–100% utilised), not only from separating the
  buffers.
- Anything about two groups on 6.12. Each difference between one and two
  groups there was smaller than the rep-to-rep range of one of the two
  configurations (three reps). The sign changed between the run with the
  first promotion rule and the run with the `SOCK_NONEMPTY` rule (mixed
  cell p50 5.8 → 10.0 ms in one, 8.1 → 4.5 ms in the other; p999
  54.5 → 19.9 ms in one, 37.8 → 54.5 ms in the other). In the
  `SOCK_NONEMPTY` run's mixed cell the per-rep p99s did not overlap (one
  group 9.96, 13.6 and 28.3 ms; two groups 7.1, 7.6 and 9.4 ms).

Caveats:

- Streamers were not rate-limited. A configuration that let them move more
  bytes also used more of the server's CPU, which raises request latency in
  the same cell.
- p999 of 54.5 ms recurs across configurations in the mixed cells,
  suggesting a histogram bucket edge or one systemic stall.
- Demotion moves connections back and forth (about 600 times per run for
  1 MiB request/ack on 6.1, 58–91 on 6.12 streaming).

### Decision and proposals (2026-10-08)

Owner's decision: two groups go into the implementation for kernels before
6.12 (plain rings). The owner said they might make sense on 6.12+ too, if
they reduce latency or improve resilience with mixed traffic or slow
handlers.

The author's proposals, measured above but not decided by the owner:
before 6.12, plain 4096 × 64 KiB plus plain 256 × 1 MiB, both with
`MADV_NOHUGEPAGE`, two groups on by default (pending A/A pairs in landing
step 6). On 6.12+: INC 64 × 1 MiB, with the same two-group code
and an INC 64 × 1 MiB large group off by default until the design's
landing measurements (rate-limited streamers, A/A pairs) separate the
effect. The bounded accumulator on both. Promotion on
completions of at least 64 KiB carrying `SOCK_NONEMPTY`, and on held
lends, with no cap. Demotion hysteresis and migration timing were
measured next (below).

The owner's decision puts a second group into the implementation before
6.12; whether two groups replace one ring as the default there is decided
in landing step 6. If accepted, the proposed 4096 × 64 KiB small group
would replace the 1024 × 64 KiB ring. Whether the large group supersedes the per-connection
hybrid follow-up has not been decided.

### Demotion quiet period and migration time

Benchmark with the `recv-strategies` program: `--demote-quiet-ms` demotes a
connection only once that long has passed since its last completion that
counted toward promotion, and each move records the time from the decision to
the re-arm on the new group and to the first delivery there. Two hosts, three
reps, medians, 36 runs per kernel and none failed: 6.12 Debian 13
`01a11d87-5b5d-710a-210d-caee1b974dd2`, 6.1 Debian 12
`01a11d87-5bd5-7100-e089-358dd296381e`. Every cell is 1000 request/response
connections at 20k requests/s plus 16 streamers.

6.1, request p50 / p99 / p999 in ms, and streamer MB/s:

| Cell | 4096 × 64 KiB | two groups | two groups, 1 s quiet |
|---|---|---|---|
| mixed | 168 / 336 / 352, 814 | 57 / 369 / 403, 1139 | 25 / 44 / 71, 1054 |
| streamers holding | 176 / 352 / 369, 815 | 38 / 84 / 92, 1280 | 31 / 61 / 76, 1017 |
| tiered | 168 / 336 / 336, 797 | 13 / 34 / 67, 856 | 12 / 20 / 26, 888 |
| heavy-tailed, tiered | 352 / 1040 / 1476, 598 | 19 / 117 / 193, 805 | 13 / 34 / 57, 708 |

Median demotions per run without and with the quiet period: mixed 40 and
5, tiered 99 and 11, heavy-tailed 415 and 381, streamers holding 0 and 0.

6.12, request p50 / p99 / p999 in ms:

| Cell | INC 64 × 1 MiB | two groups | two groups, 1 s quiet |
|---|---|---|---|
| mixed | 4.98 / 8.39 / 54.5 | 4.46 / 7.34 / 54.5 | 9.44 / 16.25 / 17.83 |
| streamers holding | 8.91 / 15.2 / 23.1 | 6.03 / 9.44 / 54.5 | 7.34 / 11.5 / 26.2 |
| tiered | 7.86 / 12.6 / 16.8 | 5.24 / 8.39 / 16.8 | 12.6 / 22.0 / 24.1 |
| heavy-tailed, tiered | 7.08 / 12.6 / 56.6 | 7.60 / 14.2 / 56.6 | 8.91 / 16.25 / 54.5 |

Migration time, two groups without the quiet period, range of per-rep
medians:

| Kernel | Decision to re-arm | Decision to first delivery on the new group |
|---|---|---|
| 6.12 | 1.3–2.5 ms (streamers holding), 4–12 ms (other cells) | 8–21 ms (mixed, streamers holding), 49–53 ms (tiered, heavy-tailed) |
| 6.1 | 17–586 ms | 50 ms to 7.4 s (7.4 s in one rep of streamers holding) |

Timings cover the whole run including warmup. In the holding cell all 16
moves happen at startup, so each rep is one observation, and the 7.4 s
rests on one rep. A move reversed before its re-arm is not sampled. For
request/response connections, first delivery on the new group also waits
for the next request, which in these cells came every 50 ms.

Measured:

- On 6.1 the quiet period lowered the median demotions in the mixed (40 to
  5) and tiered (99 to 11) cells, but the per-rep counts overlapped (mixed
  62, 40, 0 against 2, 38, 5; tiered 115, 99, 13 against 23, 4, 11). Mixed
  p99 and p999 fell 8.4× and 5.6× and tiered p999 2.6× at the median, and
  the reps did not overlap. How much of the difference the rule causes is
  not established. In the streamers-holding cell the rule cannot act,
  because the streamers are the holders and had 0 demotions either way;
  that cell moved by 1.4× at p99 and −21% in streamer throughput. In the
  heavy-tailed cell the demotions (415 and 381) and the tails overlapped
  across reps.
- On 6.12 the rule changed median demotions only in the mixed cell (6 to
  0) and the heavy-tailed cell (4 to 1, reps overlapping). In the mixed
  cell p50 and p99 rose in every rep (4.5–6.8 to 9.4–10.5 ms; 7.1–11.0 to
  15.2–16.8 ms), and the p999 reps overlapped. How much of the difference
  the rule causes is not established. The tiered cell had at most one
  demotion per rep without the quiet period (0, 0, 1) and none with it;
  its p50 per rep was 5.2, 12.6 and 4.7 ms against 8.4, 14.2 and 12.6 ms.
- Per-rep medians without the quiet period: decision to re-arm 1.3–12 ms
  on 6.12 and 17–586 ms on 6.1; streamer first delivery 8–21 ms on 6.12
  and 130 ms–7.4 s on 6.1. With the 1 s quiet period: re-arm 0.4–25 ms on
  6.12 and 15–336 ms on 6.1; streamer first delivery 7–26 ms on 6.12 and
  96–150 ms on 6.1.
- In this run, two groups without the quiet period gave 6.1 mixed p99 reps
  of 168, 369 and 419 ms against 336, 336 and 352 ms with one group, and
  cut holding p50 and p99 4.2–4.7×. With the 1 s quiet period, two-group
  mixed p99 was 36–122 ms. In the earlier run (`01a11d44-3a9e`) two-group
  mixed p99 was 134 ms.
- The client reported 12.8–14.0k acks/s at 20k requests/s offered. The
  client counts acks for requests scheduled after its warmup, which begins
  1 s after the server starts (`--start-delay-ms 1000`) and lasts 2 s, so
  it counts from about server t=3 s. The server exits at t=10 s (2 s
  warmup + 8 s). About 7 s of requests are therefore divided by
  `--seconds` − warmup = 10 s. The lowest rates are one-group 6.1 runs,
  whose 0.17–0.35 s latencies leave more requests unacked at exit.
  Inferred from `main.rs`, `server.rs` and the spec, not separately
  measured.
- The single-group 6.12 results moved between this run and the previous
  one (streamers holding p999 23.1 ms here against 54.5 ms; mixed p50
  4.98 ms against 8.1 ms).

Not explained: the holding cell's 0.4–7.4 s first deliveries on 6.1.
Waiting for a free large-group buffer does not fit: the same cell with the
quiet period, where the rule cannot act, also pinned all 256 and had more
large-group `ENOBUFS` (1.6k–2.6k), and its first deliveries took
96–150 ms. In every rep the configuration without the quiet period was
the slower (417 vs 150, 486 vs 96, 7425 vs 143 ms). The order of
configurations rotated between reps (in rep 2 the quiet-period
configuration ran first).

Not explained: the 17–586 ms re-arm times on 6.1. In the benchmark the
re-arm does not wait on a large-group buffer, and the cell with the most
large-group `ENOBUFS` (heavy-tailed, 18k–83k) had the shortest re-arms
(17–20 ms). The benchmark's `settle` does not re-arm while a one-shot
fallback recv is outstanding (`fallback.is_none()`), and that recv
completes only when data arrives. On 6.12 the large group returned
`ENOBUFS` in two of the quiet-period runs (22 and 11). The server loop was
equally busy on both kernels (`main_util` 0.95–0.998).

**Proposals (author, 2026-10-08, later; not owner decisions).** Demotion
requires a 1 s quiet period (`recv_large_demote_quiet`) on both ring
kinds. With a plain ring two groups on is the proposed default, pending
A/A pairs in the landing measurements. With an INC ring the large group
stays off by default, and its demotion rule is decided with it there.

