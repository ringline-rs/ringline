# ENOBUFS graceful degradation: fallback one-shot recv for jumbo payloads

- **Status:** open
- **Span:** started 2026-07-16

## Goal

When a multishot recv parks on `ENOBUFS` mid-message, degrade to a plain
one-shot recv into accumulator-owned memory instead of stalling until the
provided-buffer ring replenishes. Small payloads never touch the new path;
responses larger than the provided ring degrade to roughly one extra
syscall-shaped hop per ring's worth of data instead of a window-closing stall.

Motivating observation: a throughput dip on multi-MiB values (seen on the bench
rig after #267 removed the false 1 MiB value-size caps; numbers not checked in)
consistent with the provided ring emptying under a single jumbo response. A
parked receiver stops draining the socket, the kernel receive buffer fills, the
advertised TCP window closes, and the sender stalls — the recovery is gated on
buffer recycling rather than on the data that is already queued in the kernel.

## Prior art

- 022f1fa **#245** made ENOBUFS re-arm event-driven (replenish → pop
  `recv_starved` → re-arm) and added the pre-block replenish flush, killing a
  100% CPU spin. That work made parking *correct*; this effort makes it
  *graceful* when the ring is simply smaller than one response.
- The park/re-arm plumbing this builds on: `recv_starved`
  (`backend/uring/driver.rs:220`), park-on-ENOBUFS
  (`backend/uring/event_loop.rs:810`), `flush_replenish_and_rearm()`
  (`backend/uring/event_loop.rs:681`, called after each drain pass and before
  every blocking wait).

## Design sketch

Hook point: in `flush_replenish_and_rearm()`, when a parked connection cannot
be re-armed (no buffers) **and its accumulator already holds a partial
response**, submit a one-shot recv into the accumulator's spare capacity.
Connections parked with an empty accumulator keep waiting for replenish —
nothing is half-delivered, and the steady-state small-op path grows no branch.

Constraints checked against the domain invariants:

1. **New `OpTag` variant.** Every stream recv today is `OpTag::RecvMulti`;
   the fallback needs its own tag and generation-checked completion handling.
2. **No multishot/one-shot overlap.** io_uring does not order independent
   SQEs; two in-flight recvs on one stream could append out of order. State
   machine: parked → fallback-in-flight → (re-arm multishot if the ring has
   buffers, else another fallback), with the transition made only in the
   fallback's completion handler. `flush_replenish_and_rearm()` must skip
   connections with a fallback outstanding.
3. **SQE memory lifetime.** The recv target is `BytesMut` spare capacity in
   the `RecvAccumulator`: `reserve()` strictly before submit, no
   touch until the CQE. Single-writer holds while parked (the multishot is
   dead, the task is awaiting `NeedMore`). Note this path is one copy
   *cheaper* than steady state — no ProvidedBufRing → accumulator hop.
4. **Sizing.** `ParseResult::NeedMore` carries no length hint, so the first
   version recvs a fixed chunk (a few × recv buffer size) and loops. A
   `NeedMore`-with-hint variant across the proto crates is a follow-up, not
   part of this effort.
5. **FIN and short reads.** A fallback recv returning 0 routes through the
   same `eof_truncated` path as multishot; short reads append and continue.
6. **io_uring-only** (`cfg(has_io_uring)`). The mio backend has no provided
   ring and no ENOBUFS park; it needs nothing.

Observability, regardless of the fix: an ENOBUFS-park counter (and
fallback-recv bytes) in the runtime metrics, so this failure mode is
self-explanatory from run output instead of requiring a rig bisect.

## GO / NO-GO criteria

- Reproduce the dip on the rig with a value-size sweep (e.g. 64 KiB → 8 MiB)
  against a deliberately small provided ring, with the new park counter
  confirming the mechanism — *before* building the fallback. If parks don't
  correlate with the dip, this is a NO-GO on the fallback (land the counter
  anyway) and the investigation reopens.
- GO if the fallback removes the dip (jumbo-value throughput within ~10% of
  the large-ring configuration) with no regression on the small-op segcache
  workload vs `BENCHMARKS.md` baseline.
- Correctness bar: both-backend clippy/tests green, plus a
  `#[cfg(has_io_uring)]` test that drives a response larger than the provided
  ring through a small-ring config and asserts completion (today's behavior
  relies on cross-connection replenish timing).

## Plan

1. Land the ENOBUFS-park counter + fallback-recv metrics (small standalone PR
   — diagnostic value regardless of verdict).
2. Rig reproduction: value-size sweep, small vs large provided ring, counter
   correlation. Record numbers here.
3. Implement the fallback behind the state machine above; small-ring
   integration test.
4. Re-run the sweep + segcache baseline; close out this entry in the
   implementing PR.

## Step 2 results (2026-07-16, hv01, redis 8.0.2 loopback, GET-only 100% hit, 8 conns × pipeline 4, 4 workers)

Park counter (#273) correlated against the dip on the **default** ring —
and the correlation is **negative**: the dip reproduces exactly, with
`parks=0` on every worker in every cell.

| config | 16MB value | parks |
|---|---|---|
| default ring (256×16KiB) | 17 req/s, 2.36 Gbps, p50 1.21s | 0 |
| 4096×64KiB | 30 req/s, 4.10 Gbps, p50 692ms | 0 |

With 8 promptly-consuming connections the 256-bid ring never actually
runs dry — bids recycle within each drain pass. **The default-config
large-value dip is not the ENOBUFS park mechanism.** Per this entry's
own criteria that is a NO-GO for the fallback *as the fix for that
dip*, and the dip investigation reopens separately.

Two confounds in the original A/B are being pulled apart:

1. The "large ring" config changed bid count (256→4096) *and* buffer
   size (16KiB→64KiB). Diag arithmetic points at buffer size: in both
   configs throughput ≈ CQE rate × buffer size (~5.6k CQEs/s/worker ×
   16KiB ≈ 2.8 Gbps vs ~2.9k × 64KiB ≈ 5.7 Gbps), i.e. the gate looks
   like per-CQE delivery size, not buffer availability. A 2×2
   (entries × buffer size, 16MB values) is queued.
2. The reproduction here used the default ring rather than the
   deliberately small ring this entry's GO/NO-GO specified. The
   fallback's own validation — a 16×4KiB (64KiB) ring that any
   multi-MiB response exceeds by 64–256×, main vs the fallback branch —
   is queued; parks must appear on main and `fallbacks=` on the branch
   for the mechanism to be confirmed where it *does* apply (slow
   consumers, high connection counts, rings genuinely smaller than a
   response).

## Outcome

_(open — fallback implemented on `feat/enobufs-fallback-recv` (#274)
with pool-owned recv targets instead of accumulator spare capacity: the
sketch's accumulator recv is unsound across close/slot-reuse, see the
PR. Pending: small-ring validation + segcache baseline, and the
reopened default-config dip investigation.)_

## Lessons / open questions

- Open: `NeedMore` length hint in the proto crates would turn the chunked
  fallback into a single exact-size recv per parked remainder.
- Open: whether the fallback should also fire for parked connections with an
  *empty* accumulator under prolonged starvation (all buffers held by
  zero-copy RX holds), or whether that regime is rare enough to wait.
