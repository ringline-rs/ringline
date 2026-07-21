# Self-adaptive recv buffering: segmented delivery + adaptive size classes

- **Status:** **NO-GO / retired** (2026-07-21 — GO gate measured and not met; see Outcome)
- **Span:** 2026-07-20 → 2026-07-21

## Goal

Make recv buffer geometry **self-adaptive** so the runtime sizes itself to the
workload with zero caller tuning. Kill the recurring pattern of consumers
compensating for a fixed-size ring: cachecannon's `recv_buffer` auto-derive
(cachecannon #104), the accumulator regrowth fix (#279), and the manual
`buffer_size` tuning a validation has to remember so it doesn't accidentally
force-copy. If ringline observes traffic and sizes itself, all of that deletes.

The shape: combine **#286's segmented zero-copy delivery** (eliminate the
accumulator copy wherever bytes don't escape the runtime) with **#284's adaptive
size classes** (right-size buffers per connection from observed traffic), built
on the occupancy primitive #286 already landed.

## Background / how we got here

- **#284 (adaptive size-class recv buffering) — abandoned.** Static 16K/64K/256K
  provided rings + an EWMA per-connection class-selection policy
  (`recv/sizing.rs`). Reduced fragmentation by cutting the number of accumulator
  `memcpy` appends per large response. Footgun found in review: class-0 was
  parameterized off `config.recv_buffer.buffer_size`, guarded only by a
  `debug_assert` for ascending order — a caller setting `buffer_size >= 64K`
  (e.g. cachecannon's own 256K auto-derive) silently broke class selection in
  release builds (~88 MiB/worker, adaptivity defeated).
- **#286 (segmented zero-copy recv) — the current line.** A **single**
  `ProvidedBufRing` + a new `outstanding` occupancy counter
  (`recv/occupancy.rs::delivery_decision(free, reserve) -> ZeroCopyOk|ForceCopy`)
  + segmented delivery (Modes A/B/C). Solves ring **starvation** (reserve
  force-copy + Mode-A hold cap). Does **not** address buffer right-sizing — one
  fixed ring, no classes, no adaptivity.

**The key realization:** #286 largely *obviates* #284's fragmentation win rather
than competing with it. The expensive part of fragmentation was the per-fragment
`memcpy`; #286 eliminates the accumulator copy on the zero-copy paths, so N
zero-copy segments cost CQE-processing + occupancy bookkeeping, not `memcpy`.
What remains of #284's value is narrower:

1. **Mixed small+huge workloads** — a single fixed buffer size is wrong for part
   of the traffic (big buffers waste memory on small responses; small buffers
   fragment huge ones). Only adaptive per-connection sizing fixes *that*.
2. **The paths that still copy** — Mode C (a redis/valkey value the app keeps),
   h2/http `with_data` gather, TLS — right-sizing still cuts copy count there.

## The direction (a follow-on on #286, not a revival of #284's code)

- **Reuse** #284's sizing policy (EWMA of observed sizes + `NeedAtLeast` hints +
  hysteresis) — a pure function, largely portable.
- **Rebuild** the mechanism on #286's occupancy/segment model: add the *class*
  dimension so every hold / replenish / occupancy site becomes per-class, and
  thread a segment's **origin class** through the segmented-delivery lifecycle.
  This is the high-risk merge point — the origin-class-replenish bug is exactly
  what both #284 and #286 shipped and then fixed.
- **Make class geometry fully internal**, derived from observed traffic, with no
  caller-settable buffer size. Removes #284's ascending-order footgun by
  construction and lets cachecannon delete its `recv_buffer` auto-derive (#104).

## GO / NO-GO

- **GO gate:** a genuinely *mixed* small+huge workload must show fixed-buffer
  fragmentation/waste after #286 that adaptive sizing removes. If uniform-large
  or uniform-small are the only real targets, a single tunable `buffer_size`
  suffices and this stays retired (record the NO-GO, don't re-pay it).
- **Cost:** third rework of the hottest, most bug-prone path in the codebase;
  #284 and #286 each surfaced recv-lifecycle UAFs under adversarial review.
  Demands the same rigor. Only justified if the mixed-workload data demands it.

## Sequencing

Land #286 + its valkey/cachecannon Mode-B (borrow-and-discard GET) validation
first. Then, *if* a mixed-workload measurement justifies it, build the
adaptive-sizing layer on #286's foundation.

## Outcome

**NO-GO (measured 2026-07-21).** The GO gate — a mixed small+huge workload
showing fixed-buffer waste that adaptive sizing removes — was **not met on any
path**. Retired; do not re-pay without a re-eval trigger below. Evidence (ringline
`main` post-#286; 2× c8gn.16xlarge @ 200 GbE + loopback `ring_fill_bench`):

1. **The memory premise is false.** A 256 KiB-buffer ring serving 8 KB responses
   uses the *same* RSS (~11 MB) as a 16 KiB ring — big provided buffers cost
   virtual address space, not resident memory (demand paging faults in only the
   touched bytes). The core adaptive justification ("big buffers waste memory on
   small responses") does not hold. If big buffers are RSS-free, there is nothing
   to shrink toward → nothing for adaptive sizing to optimize.
2. **Discard path (`recv_meta` / segments): line rate regardless of geometry.**
   cachecannon's borrow-and-discard GET saturates 200 GbE at 64 MB with the
   *default 16 KiB* ring at high fan-in; fallback-recv (#274) rescues the (heavy)
   ring parking with no throughput loss. This answers the seed's open question:
   the discard path does *not* need bigger buffers.
3. **Copying path (`with_data` materialize — the real-consumer path): 16 K ≥ 256 K.**
   Isolated cross-host `ring_fill_bench MODE=whole`, 3 reps, fan-in 32/128/512,
   large + mixed: 256 KiB was consistently *slower* than 16 KiB (e.g. large /
   128 conns: 37 vs 30 Gbps). #274 + #286 eliminated the small-buffer starvation
   cliff that motivated #284; bigger buffers now only add memcpy/cache/page
   overhead. **The buffer-size story inverted.**
4. **cachecannon's override obsoleted.** cachecannon's `runner.rs` 256 KiB
   value-size-derived `recv_buffer` made *zero* difference vs ringline's default
   16 KiB at line rate against valkey 9.1.0 (io-threads=16): 201 Gbps, 3/3 reps
   byte-identical, at 1M/16M/64M. Removed downstream (cachecannon "perf: drop the
   recv-buffer override").

## Re-evaluation criteria (what would flip this to GO)

Revisit only if one of these is *measured*, not assumed:

- **A — Faster NICs (400/800 GbE):** at higher line rates the per-CQE processing
  rate of a 16 KiB ring (~4096 CQEs per 64 MB response) may become a
  single-core bottleneck, reviving "bigger buffers = fewer CQEs." Re-run the
  copying-path sweep at the new line rate.
- **B — Resident (not virtual) memory pressure:** a very-high-connection-count
  deployment where the demand-paging assumption breaks (buffers touched enough
  that big fixed rings cost real RSS / TLB / fault overhead). Measure RSS + fault
  rate at scale.
- **C — A mixed workload where a fixed size measurably loses on a still-copying /
  gather path** (h2/http body assembly, TLS): 16 KiB fragmenting huge responses
  below line rate *and* a fixed large size regressing the small ones. Neither was
  observed here; a new path could change it.
- **D — A mandatory-hold zero-copy consumer** that cannot force-copy/fallback
  under ring pressure, where a small ring genuinely starves at line rate.

Absent one of these, a single fixed default (ringline's 16 KiB) suffices and the
adaptive size-class machinery stays retired.

## Lessons / open questions

- #286 wires occupancy only to the reserve/force-copy decision, not to class
  selection (there are no classes). #284's own design doc identified this
  counter as the shared prerequisite for class selection — now landed, so the
  adaptive layer is a smaller delta than #284 was.
- Open: does a streaming borrow-and-discard consumer (cachecannon Mode B) even
  hit ring pressure at large values, or do segments release fast enough that a
  small ring stays zero-copy throughout? If the latter, buffer sizing matters
  less for the *discard* path and more for the retained/gather paths — which
  would further narrow the adaptive-sizing justification, possibly to a NO-GO.
