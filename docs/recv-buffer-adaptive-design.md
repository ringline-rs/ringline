# Adaptive recv buffering design

Status: draft (design approved 2026-07-17, pending spec review)
Scope: io_uring + mio recv buffer geometry. Companion to `docs/send-completion-design.md`.

## Problem

Under concurrency with large responses, recv throughput collapses. Measured on
hv01 (kernel 6.12, single worker, 256 KB responses, in-process echo peer):

| Concurrency (default ring 256 × 16 KB = 4 MiB) | Throughput | Parked | Fallback bytes |
|---|---|---|---|
| 8 conns  | 3941 MiB/s | 0 | 0% |
| 16 conns | 2941 MiB/s | 1 | 7% |
| 32 conns | 1517 MiB/s | 158 | 53% |
| 128 conns | 1534 MiB/s | 65731 | ~45% |

The naive reading — "the ring is too small, enlarge `ring_size`" — is wrong and
counterproductive. At fixed concurrency (32 conns), sweeping ring size shows
throughput moving the **opposite** way:

| Ring (conns=32) | Throughput | Fallback |
|---|---|---|
| 64 buf (1 MiB)  | 1810 MiB/s | 84% |
| 128 buf (2 MiB) | 1851 MiB/s | 66% |
| 256 buf (4 MiB) | 1517 MiB/s | 51% |
| 1024 buf (16 MiB) | 1414 MiB/s | 0% |
| 4096 buf (64 MiB) | 1391 MiB/s | 0% |

The smallest rings — leaning hardest on the ENOBUFS fallback path — are the
**fastest**; eliminating exhaustion with a big ring is **slower**. So the
ENOBUFS/fallback machinery is not the penalty, and total ring bytes is
second-order.

**The actual lever is buffer *granularity* (fragmentation), not ring size.** At
conns=32, same 32 MiB total: `2048 × 16 KB` (16 buffers per 256 KB response →
16 CQEs + 16 accumulator appends) delivers 1394 MiB/s, while `128 × 256 KB`
(one buffer per response → **1 CQE + 1 append**) delivers **2768 MiB/s** —
nearly 2× from geometry alone. The mandatory provided-buffer→accumulator copy is
1× the bytes in both cases; the win is amortizing per-CQE/append overhead.

Small responses (8 KB) show no cliff at any concurrency. The residual decline
from 8→32 conns that remains even with a huge ring and zero parking is inherent
single-core cache/bandwidth scaling, not addressed here.

Reproduction harness: `ring_fill_bench` (scratch), swept on hv01. To be promoted
into the repo as a criterion/bench target (see Validation).

## Goals

- Recv buffering adapts to the workload with **no caller tuning** — "just works"
  by default. The existing `recv_buffer(ring_size, buffer_size)` builder becomes
  an explicit override / memory cap, not a required knob.
- Preserve or improve every recv API's copy-count (see Invariant). This is
  option **A**; true-zero-copy client recv (refcounted provided-buffer slices) is
  explicitly out of scope (option B, deferred).
- Bounded, predictable per-worker recv memory regardless of connection count.
- Correct on all supported kernels (io_uring floor is 6.0 per `build.rs`) and on
  the mio backend.

## Non-goals

- Removing the provided→accumulator copy for `with_bytes` clients (redis/
  memcache). That is option B; it requires refcount-driven buffer replenishment
  with a ring-pinning/backpressure tradeoff, and is a separate future design.
  Adaptive sizing here is a prerequisite for it if it is ever taken up.
- Changing the ENOBUFS park/fallback machinery. It stays as the safety net; the
  goal is to make it rare, not to remove it.
- The inherent single-core concurrency scaling ceiling.
- **Public typed connections** (e.g. a `ZeroCopyConn` vs `BufferedConn` that the
  API surface pins). The buffer-domain type introduced here is *internal only*.
  Exposing consumption mode in the type of `ConnCtx` would make `on_accept`'s
  RPITIT signature generic over mode (breaking every handler via
  `AsyncEventHandler`), remove the deliberate per-message flexibility of the
  current `ConnCtx`, and forbid legitimately-mixed usage (crucible's `with_data`
  + `set_recv_sink`). It is deferred to a future major release, to be revisited
  only if the internal domain type proves it wants to surface.

## Background: recv APIs and their copy behavior

Verified against the code at HEAD a7c52b6. The organizing fact for this design:
**whether an API holds the provided buffer determines whether incremental (INC)
buffers are safe and whether per-connection sizing is required.**

| API | Copy behavior | Holds provided buffer? |
|---|---|---|
| `with_data` in-place (`runtime/io.rs:1678`) | 0-copy: parser reads the provided buffer directly; spills to accumulator only if the message exceeds one buffer | No — consumed-or-flushed within one poll |
| `with_bytes` (redis/memcache, `runtime/io.rs:1837`) | 1 copy provided→accumulator (always), then 0-copy `Bytes::slice` value extraction | No — copied out and replenished within one poll |
| `set_recv_sink` (`event_loop.rs:1183`) | 1 copy provided→user sink (straight to final destination, skips accumulator) | No — copied out per CQE |
| `recv_forward` / `forward_held` | 0-copy end-to-end: provided buffer forwarded via scatter-gather ZC send | **Yes** — pinned until the forward send completes |

Consumers in the tree:
- **crucible server**: `with_data` in-place + `set_recv_sink` (large SET bodies).
  Heaviest true-ZC user.
- **crucible proxy**: `with_data` on the client leg; `ringline-redis` (`with_bytes`)
  on the backend leg.
- **ringline-redis / -memcache clients**: `with_bytes`. The provided→accumulator
  copy is the price of the owned-value `recv() -> CompletedOp` API, not the
  protocol; crucible avoids it by consuming inside the `with_data` callback.
- **cachecannon**: pure client of the above (recv = `with_bytes`); send side uses
  `fire_set_with_guard` (send-path ZC, unaffected here).

The true-zero-copy paths (`with_data` in-place, `recv_forward`) touch the
provided buffer directly, so there is **no accumulator to absorb a size
mismatch** — the buffer size itself must adapt to keep them zero-copy. This is
why adaptive sizing is the primary mechanism, not INC.

## io_uring mechanism: incremental provided buffers (INC)

`IOU_PBUF_RING_INC` (kernel 6.11+; exposed by io-uring 0.7.9;
`register_buf_ring_with_flags` already in use at `ring.rs:133`). The kernel
consumes a provided buffer **incrementally** across recvs, advancing an internal
offset, and only retires/recycles the buffer once fully consumed. Effect:

- A small trickle takes a small slice of one buffer (touches only what it fills;
  RSS ≈ bytes received, since the region is anonymous/lazy).
- A large burst fills a big contiguous region in a single recv → one CQE.

One generous buffer size therefore serves both ends of the size distribution —
the kernel does the adaptation. This removes the small-vs-large tradeoff that
forces size classes on older kernels. INC is **not** usable for the hold domain:
a held slice would pin a shared, incrementally-filled buffer (and its
cross-connection interleaving) from recycling.

Availability is detected at **runtime** (attempt the INC register at worker
startup; on `EINVAL` fall back), not at build time — `build.rs` only guarantees
6.0, and a 6.0–6.10 host must still work.

## Design

### Two buffer domains per worker, selected by API

**Domain 1 — default (copy/consume-out APIs): `with_data`, `with_bytes`,
`set_recv_sink`.** None hold the buffer across ticks.

- Kernel ≥ 6.11: **one INC ring**, single swept buffer size + ring depth. No
  per-connection sizing machinery — the kernel adapts. This is the common modern
  path and is deliberately simple.
- Kernel 6.0–6.10 and mio: **adaptive size-classes** (below).

**Domain 2 — hold API: `recv_forward`.** Entered when `enable_recv_forward` is
called (known up front). Always uses **classic, dedicated-per-recv,
adaptive-sized buffers** (size-class machinery) on all kernels — never INC.
Classic semantics mean one buffer per recv carrying one connection's data, safe
to hold, with the pin bounded by (in-flight forwards × class size).

Connections start in Domain 1 on their default ring; a connection that calls
`enable_recv_forward` migrates to Domain 2 at the next re-arm.

### Adaptive size-classes (Domain 1 fallback + all of Domain 2)

A small fixed set of **shared** provided-buffer rings at graduated buffer sizes
(e.g. small / medium / large — exact geometry TBD-by-sweep). Shared across all
connections of a class, so total memory is bounded by the sum of class ring
sizes, **independent of connection count**. Each connection is armed against one
class's `bgid`.

Per-connection class selection (the hybrid signal, confirmed):
- **`NeedAtLeast(n)`** — proactive and exact for length-prefixed protocols (RESP
  hands the bulk length). On seeing the header, bump the connection's target
  class immediately so the body lands in the right size. Already feeds the
  accumulator reservation; here it also feeds class selection.
- **EWMA of observed arrival/message sizes** — steady-state baseline, and the
  only signal for protocols/parsers that never emit `NeedAtLeast` (raw streams,
  echo, most `with_data` users).

A class change takes effect at the **next re-arm** (buffer size is fixed for the
lifetime of an armed multishot; change = cancel + re-arm on the new `bgid`),
gated by **hysteresis** so it cannot flap mid-stream. Migration happens at
message boundaries.

Ceiling: a message larger than the largest class degrades gracefully exactly as
today — `with_data` spills to the accumulator, `recv_forward` uses more segments.
The class set is chosen (by sweep) to cover the realistic range.

### mio (Domain 1 and 2)

mio has no provided ring; it reads into a single **worker-shared** scratch
buffer (`event_loop.rs:131`, currently a fixed `vec![0u8; 8192]`), reused across
all connections and copied out immediately (to the accumulator, or to the sink
for `set_recv_sink`). It is transient, so it carries no per-connection memory
cost. Today's fixed 8 KB fragments a 256 KB response into ~32 read+append
cycles — the same pathology, worse than io_uring's 16 KB.

The fix here is to **adaptively size that shared scratch** from the aggregate
signal (a high-water of recent `NeedAtLeast` / observed read sizes across the
worker's connections): grow toward the observed max so large responses land in
few reads, shrink back when traffic quiets. Because it is shared and transient,
per-connection sizing is neither needed nor beneficial on mio. The
`recv_forward` distinction does not apply (mio degrades ZC forwards to copies
regardless). The same sizing-policy unit produces the target; only what it sizes
differs (a ring class on io_uring, the shared scratch on mio).

### The `RecvBufferProvider` abstraction

A per-worker trait behind which the three implementations live (INC ring,
size-class ring set, mio read-buffer sizer), so `event_loop.rs` / `handler.rs`
do not branch on kernel version or API inline. Rough surface:

- `arm_recv(conn, class_hint)` — arm/re-arm the multishot (or size the mio read
  buffer) for a connection.
- `on_completion(conn, cqe) -> RecvView` — resolve a completion to a data view
  (bid + offset + len for INC; bid for classic; sink for mio), preserving the
  current copy-out / in-place semantics per API.
- `replenish(...)` — return consumed buffers (per-buffer for classic; INC's
  incremental-consumption commit for the INC ring).

Today's `ProvidedBufRing` becomes the classic size-class implementation. The
sizing policy (EWMA + `NeedAtLeast` + hysteresis → target size) is a small
standalone unit: the size-class provider applies it per-connection to pick a
class, the mio provider applies it in aggregate to size the shared scratch. The
INC provider does not use it.

### Connection buffer-domain (internal type)

A connection's buffer strategy is today *implied* by a scatter of per-connection
flags (`recv_forward: Vec<bool>`, `recv_sinks: Vec<Option<_>>`, `direct_echo`,
`pending_recv_bufs`, the `RecvMode` enum). This design promotes it to a single
**explicit internal per-connection buffer-domain value**, set once the domain is
known, that pins the provider and arming rather than being re-derived per CQE:

- `CopyOrConsume` (default) — `with_data`, `with_bytes`, `set_recv_sink`.
  INC-eligible on 6.11+, size-classes otherwise. No long hold.
- `Forward` — opt-in via `enable_recv_forward`. Classic dedicated buffers,
  never INC.

It is deliberately **coarse**: `with_data`, `with_bytes`, and `set_recv_sink` all
live in `CopyOrConsume`, so it does not forbid mixing them on one connection —
which crucible's server does (in-place `with_data` + `set_recv_sink` during a
streaming SET). The only hard boundary is `Forward`, the long-hold path, which is
already an explicit opt-in taken before recv.

This is internal only. It also resolves the "wrong first arm" open question: the
domain is known at accept time (default `CopyOrConsume`; `Forward` set before the
first recv), so the first arm is always correct with no discover-on-first-poll
ambiguity or mid-connection domain migration. The copy-count invariant becomes
enforceable at the domain boundary, and the hot paths specialize per domain.

### Copy-count invariant (option A)

The spec asserts, per path, that copy-count is preserved or improved:

- `with_data` in-place: stays 0-copy, and now **stays in-place on larger
  messages** (buffer sized to fit) instead of spilling to the accumulator at
  16 KB.
- `set_recv_sink`: stays 1-copy-to-final; fewer CQEs to fill a large sink.
- `with_bytes`: stays 1-copy-to-accumulator + 0-copy value slices; INC removes
  fragmentation on large values. redis/memcache memory pinning is the accumulator
  (unchanged), not the provided buffer.
- `recv_forward`: stays 0-copy end-to-end, with fewer iovec segments.

No API regresses.

### Config surface

Stays opaque; defaults to adaptive. `recv_buffer(ring_size, buffer_size)` is
reinterpreted as an explicit override / memory cap. New internal parameters (INC
buffer size + depth, size-class geometry) are opaquely configurable with
swept defaults. `recv_accumulator_max` default remains a separate concern (see
the NeedAtLeast DoS finding in the adversarial review — orthogonal but should be
bounded).

### Interactions

- The mandatory provided→accumulator copy for copy-out APIs is unchanged; only
  CQE/append **count** changes.
- The ENOBUFS park/fallback machinery is retained as the safety net for
  transient exhaustion. `fallback_eligible`'s use of `data()` (the O(N·K) merge,
  adversarial-review finding A6) should switch to `is_empty()` regardless of this
  work.
- Domain 2 (`recv_forward`) never shares buffers across connections, so the hold
  is safe.

## Parameters

### Size-class geometry (Phase 3 starting default — locked)

Chosen from the review sweeps (16 KB buffers fragment a 256 KB response into
~16 CQEs at ~1.5 GiB/s; a 256 KB buffer holds it in one CQE at ~2.8 GiB/s;
8 KB responses show no cliff). Three shared classes, bounded per worker:

| Class | Buffer size | Depth | Ring bytes |
|---|---|---|---|
| small  | 16 KiB  | 256 | 4 MiB |
| medium | 64 KiB  | 128 | 8 MiB |
| large  | 256 KiB | 64  | 16 MiB |

Total ≤ 28 MiB/worker, independent of connection count (shared rings). The
large ring stays lightly populated for small-traffic workloads. This is a
*starting* default refined by the Phase 6.3 validation sweep; it is not a
per-point winner but a robust spread covering the observed range.

### INC de-risk results (standalone prototype, hv01 6.12)

Prototype on branch `probe/inc-provided-buffers` (`inc_probe.rs`), semantics
proven by a byte-position verifier (0 mismatches over 128 MiB mixed traffic).

**Proven semantics (the reusable contract for any integration):**
- Register with flag literal `2` (`IOU_PBUF_RING_INC`; the crate's `sys`
  constants are private). `register_buf_ring_with_flags` and
  `cqueue::buffer_more`/`buffer_select` are public.
- The CQE does **not** carry the offset. Keep a **per-bid running offset**: for
  a recv CQE selecting `bid=b` with `result=n`, new bytes are at
  `buf[b] + offset[b]` for `n` bytes; then `offset[b] += n`.
- Recycle signal = `IORING_CQE_F_BUF_MORE` (bit 16, `cqueue::buffer_more`):
  **set** → buffer partially consumed, kernel keeps it, do NOT re-provide;
  **clear** (with `F_BUFFER`) → fully consumed, reset `offset[b]=0` and
  re-provide the bid (classic ring-entry write + tail commit). ENOBUFS
  terminates the multishot → re-arm.
- No ergonomic crate type — raw-drive like `ProvidedBufRing` plus the offset
  table + conditional replenish above.

**Measured:** ~3.9× fewer CQEs on 256 KiB responses (17.3k→4.4k); mixed
8K/256K **+24% vs classic-16K** and matches classic-256K throughput *without*
its 32× small-message memory waste. Fan-in could NOT be truly measured on
localhost (`max_concurrent_bufs` pinned at 1 — fast-drain artifact); ring-depth
sweep shows churn falls with depth, throughput peaks at depth 16–64. INC holds
a buffer per active connection longer than classic, so it needs
`ring_depth ≳ concurrent-active conns`; "several medium (~64 KiB) buffers" beats
"few large."

**Verdict: CONDITIONAL GO, marginal.** INC is real and fully characterized, and
it uniquely handles mixed sizes on one geometry (no per-connection class
compromise, no big-class memory waste). But the **adaptive size-class path
already captures most of the win** — INC's incremental advantage is the
mixed/unpredictable-size connection plus real-NIC memory-waste avoidance, at the
cost of: a per-bid offset table + conditional-replenish rework of the recv
completion path; a 6.11 kernel floor (must be opt-in / feature-detected, ringline
floor is 6.0); harder ring churn when under-provisioned; and a fan-in geometry
that localhost could not validate (needs a real-NIC retest before committing).

**Recommended geometry if integrated:** ~64 KiB buffers, depth 128–256.
**Integration guard:** the zero-copy hold/forward paths must never use INC (an
INC buffer can't recycle until fully consumed, so a retained slice pins it →
stall); ringline's copy-out-to-accumulator path is compatible.

## Validation

### Size-class path results (hv01, kernel 6.12, 1 worker, 256 KiB responses)

Adaptive size-class selection vs. the pre-adaptive single 16 KiB ring, same rig
and `ring_fill_bench`:

| Case | Baseline MiB/s (fallback frac) | Adaptive MiB/s (fallback frac) | Δ |
|---|---|---|---|
| whole, 8 conns   | ~3947 (0.00) | 3804 (0.00)  | ~flat |
| whole, 16 conns  | ~2941 (0.07) | 2907 (0.067) | ~flat |
| whole, 32 conns  | ~1527 (0.53) | **2323 (0.063)** | **+52%, fallback 8×↓** |
| whole, 64 conns  | ~1766 (0.49) | 1843 (0.115) | +4%, fallback 4×↓ |
| whole, 128 conns | ~1534 (0.45) | **1863 (0.179)** | **+21%, fallback 2.5×↓** |
| mixed 8K/256K, 32 conns | ~2079 (0.25) | 2120 (0.094) | ~flat, fallback 2.6×↓ |

The cliff flattens: connections migrate to the 256 KiB class after ENOBUFS
re-arms, so a large response lands in one buffer and ring pressure collapses
(fallback fraction drops 3–8×). Low-concurrency and mixed workloads are
neutral. Caveat: the ENOBUFS regime is genuinely noisy run-to-run (parked
counts swing widely at 32–64 conns); the throughput wins at 32/128 are robust,
64 conns is noisier. The mixed workload is where the one-class-per-connection
model is weakest (a bimodal distribution pulls the EWMA onto a large class that
wastes buffers on the frequent small message) — this is the case INC (Phase 4)
is expected to solve properly.

Memory is bounded by construction: three shared class rings (4 + 8 + 16 MiB)
= ≤ 28 MiB/worker regardless of connection count; the large ring stays lightly
populated under small-traffic workloads (anonymous pages, unfilled). A precise
RSS-isolation measurement is future work.

### Remaining validation (Phase 4 / 6)

- INC path: assert the cliff flattens AND the mixed workload no longer dips.
- Per-API copy-count regression tests (counter-instrumented accumulator /
  in-place path) enforcing the invariant that no recv API regresses.
- Both backends (io_uring on hv01/CI, mio on macOS), per project convention.

## Risks / open questions

- INC concurrent-region handout under fan-in (de-risked before finalizing).
- Re-arm cost of class migration on the size-class path; hysteresis tuning to
  avoid flapping without lagging real size shifts.
- Interaction of INC's incremental replenish with the existing
  `pending_recv_bufs` / `pending_replenish` bookkeeping — needs careful mapping
  in the INC provider.
- First-message sizing on the size-class path: the buffer-domain type fixes the
  *domain* first-arm (always correct), but the size *class* for a connection's
  very first message is still a guess before EWMA/`NeedAtLeast` have any signal.
  Expected to be absorbed within a message or two; the starter class is a small
  swept default.
