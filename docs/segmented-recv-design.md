# Segmented recv — design

**Status:** Draft / design (two adversarial passes; not yet planned or implemented)
**Date:** 2026-07-19
**Related:** `docs/recv-buffer-adaptive-design.md`, `docs/send-completion-design.md`, the 200 GbE 64 MB buffer-geometry sweep (project memory).

## Goal

Deliver received bytes to a consumer as a **stream of discontiguous, buffer-sized
segments**, avoiding the mandatory copy into the contiguous `RecvAccumulator`
**wherever the bytes never need to escape the runtime's control** — and make the
`RecvAccumulator` one opt-in gather strategy rather than a stage every read pays.

## The governing principle

A received provided buffer can stay zero-copy **only for as long as it never
escapes the runtime's ownership.** The moment application code can *retain* the
bytes (hold them across an await it controls, clone them, move them to another
thread), the buffer must be copied — a provided buffer is thread-affine,
ring-pinned, and released by the driver, and none of that survives being handed
to arbitrary user code. Three delivery modes follow:

| Mode | Bytes go to | Copies | Who owns hold-time | Consumers |
|---|---|---|---|---|
| **A — Forward** | another fd (driver-issued write) | 0 | the driver (released on the write CQE) | proxies (recv→socket), buffered-file sinks |
| **B — Borrow** | user code, *scoped, cannot retain* | 0 | the runtime (released at scope end) | h2/http/gRPC codecs, hashers, validators, load generators |
| **C — Own** | user code, freely holdable | 1 | the application (heap `Bytes`) | redis/memcache values an app keeps |

**This design deliberately does not offer a "zero-copy `Bytes` you can hold"** —
see *Rejected: user-held zero-copy*. Two adversarial passes reduced to one
invariant: **holdable ⇒ copied-at-delivery**, and zero-copy lives only where the
runtime keeps ownership (Mode A) or a `!Send` non-escaping borrow does (Mode B).

## Motivation

1. **Large-object recv is copy-bound.** On real 200 GbE (kernel 6.12), 64 MB
   throughput is bounded by the single copy kernel buffer → `RecvAccumulator`
   (~3.2 GiB/s/core). Removing it *where the consumer needn't hold* is the only
   lever.
2. **The copy is redundant for the HTTP/gRPC family.** `ringline-h2/-http/-grpc`
   each keep their own internal buffer and tolerate chunked input; they read via
   `with_data`, so today's path double-copies (accumulator, then codec buffer).
   Mode B drops ringline's copy for the everyday HTTP path.

### Contiguity map (survey result)

| Consumer | Needs contiguous from socket? | Notes |
|---|---|---|
| h2 / http / grpc | No | own internal buffer; Mode B eliminates ringline's copy |
| redis / memcache | Only if the app **holds** the value | copy is Mode C = the same copy paid today; benchmarks/proxies use Mode A/B and pay nothing |
| QUIC / h3 / UDP / ping | Already handled | separate path; UDP hands out per-datagram contiguous slices |
| TLS | Streamed, one copy | rustls owns its plaintext buffer; cannot be zero-copy |
| `ConnStream` `AsyncBufRead` | Yes — stays gathered | `poll_fill_buf` keeps returning all buffered bytes |

## Ring occupancy accounting (shared prerequisite)

Every mechanism below depends on one primitive the code does **not** have today:
`ProvidedBufRing` tracks only `tail`, with no free/outstanding count. Add a
**per-class `outstanding: u32`** to `SizeClassRings`, incremented when a bid is
handed out (any mode) and decremented at replenish. From it derive `free(class)`.
This counter is the shared dependency for class selection, the low-water reserve,
and the re-arm gate. Without it none of the backpressure fixes are implementable.

## Mode A — Forward to an fd (zero-copy, driver-owned)

Received buffers stay **driver-owned** and are handed to the kernel as the source
of a write to another descriptor; the bid releases on that write's completion.
The bytes never become a user-visible `Bytes`, so there is no lifetime,
replenish-on-drop, or cross-thread hazard.

This builds on `RecvDomain::Forward` + `recv_hold` + `forward_held` (today: a
single-shot scatter-gather `sendmsg` on the connection's own socket, released via
`release_recv_forward`, origin-class). Generalizing the sink to an arbitrary fd
is **new control flow, not a sink swap** — the review found four axes to specify:

```rust
impl ConnCtx {
    /// Forward the next `len` received bytes directly to `sink` (write/writev),
    /// held driver-side until each write CQE. Zero userspace copy.
    pub async fn forward_to(&self, sink: &SinkFd, len: usize) -> io::Result<usize>;
}
```

- **`len` spans many recv rounds.** `forward_to` loops: hold arriving buffers,
  issue writes, track `bytes_remaining`, keep receiving until `len` — a
  recv/write interleave, unlike single-shot `forward_held`.
- **File offset + opcode.** A seekable fd needs `pwrite`/`writev`-at-offset with
  a per-completion offset advance (a new field on the slab entry + a `Writev`
  path distinct from `SendMsg`); `sendmsg` carries no offset.
- **Short writes (Inv #5).** `MSG_WAITALL` is socket-only; a file write can
  short. Route through a completion handler that resubmits the remainder at the
  advanced offset (the existing `try_advance` loop, extended with the offset).
- **One write in flight (Inv #2).** Serialize writes to `sink` (like
  `send_queues.in_flight`); pipelining independent writes reorders bytes. This
  bounds a large object to serialized `MAX_IOVECS` rounds — so a *wider* writev
  is not a free "hold more" win.
- **Not a bare `RawFd`.** A raw fd the caller can close mid-forward is a
  use-after-close (an in-flight write lands on a recycled fd); generation guards
  *slots*, not caller fds. `SinkFd` is a borrowed/owned handle (or a registered-fd
  index) with a lifetime, not `RawFd`.
- **Mode-A hold cap.** `recv_hold` is an **unbounded `VecDeque`** today; a slow
  sink (congested socket, busy disk) would pin the whole class ring for the stall
  duration and ENOBUFS-park every other connection on it. Cap `recv_hold[conn]`
  at a small multiple of `MAX_IOVECS`; on reaching it, **stop re-arming that
  connection's multishot** so its own TCP window closes, and re-arm when its hold
  drains on a write CQE. `MAX_IOVECS` bounds one `sendmsg`, **not** the hold — do
  not conflate them.

Sinks: sockets (zero-copy proxy) and **buffered files** (crucible blob → file,
zero userspace copy). **NVMe / O_DIRECT is out of scope for zero-copy** — provided
buffers are mid-ring, unaligned, and unregistered, so `nvme_write`'s alignment/
lifetime contract cannot be met without an intermediate aligned copy (which
defeats the purpose). Gate any O_DIRECT sink on an alignment check and fall back
to Mode C there.

## Mode B — Borrow (zero-copy, runtime-scoped, cannot retain)

User code sees the bytes but **cannot retain them past a runtime-controlled
scope**. Two faces, both routed through a **non-`Copy` reader guard** so the
borrow checker enforces the contract structurally (a bare `Copy` `ConnCtx` cannot
— you could copy the handle and pull again).

### B1 — Callback (`with_segments`)

```rust
impl ConnCtx {
    pub async fn with_segments<F>(&self, f: F) -> usize
    where F: FnMut(&SegChain<'_>) -> SegConsumed;   // bytes consumed from the front
}
```

- `SegChain<'_>` borrows for the call only; escape is a compile error (like
  `with_data`).
- **It does not reuse `ParseResult`.** `with_data`'s `NeedMore` means "keep the
  whole message, grow the heap accumulator" (bounded by `recv_accumulator_max`,
  ring-independent); re-presenting segments is bounded by *ring depth*. So
  `with_segments` reports only *bytes consumed from the front*; a consumer that
  must accumulate a whole frame **copies into its own buffer** (h2/grpc do).
- **Under-drain is safe but honestly not free.** If the callback leaves bytes
  unconsumed, the runtime `extend_from_slice`s the remainder into the heap
  accumulator (bounded, conn-killed on breach) and replenishes those bids —
  degrading to today's `with_data` (copy-1), never a deadlock or leak. But the
  drain bound is **convention, not type-enforced**: a `SegConsumed(0)`-returning
  whole-frame parser makes the gather the always-taken path and can perform
  *worse* than `with_data`. After any carry-over, `SegChain` must present the
  accumulator-backed remainder **before** new provided-buffer segments (in-order
  heterogeneous backing). The reference h2 consumer (extend-each + consume-all)
  drains fully and pays nothing.

### B2 — Lending-iterator stream (the sound face)

```rust
impl ConnCtx {
    /// Borrow a non-Copy reader; segments are !Send, !Clone, and drop-before-next
    /// is enforced by &mut exclusivity.
    pub fn segments(&self) -> SegmentReader<'_>;
}
impl SegmentReader<'_> {
    pub async fn next(&mut self) -> io::Result<Option<RecvSegment<'_>>>;
}
```

- `SegmentReader::next(&mut self) -> RecvSegment<'_>` is an **async lending
  iterator**: `&mut self` on a non-`Copy` reader gives true exclusivity, so
  `while let Some(seg) = r.next().await? { … }` compiles, holding `seg` across an
  inner `.await` is fine, and calling `next` again while `seg` is alive is a
  **compile error** — drop-before-next and non-escape are structural, not
  documented. `!Send`/`!Clone` via `PhantomData<*const ()>`. (It cannot be a
  `futures::Stream`/`for` loop — that's inherent to lending iterators.)
- To *keep* a segment, `.into_owned() -> Bytes` (Mode C copy). No zero-copy retain.

Consumers: validators/checksummers, load generators, length-delimited value
bodies (`ValueStream` below is a `SegmentReader` bounded to a parsed length).

### Mode B lifetime: pin tracking + drop reachability (correctness-critical)

The earlier claim that a segment's drop "always runs inside a poll" is **false**.
A parked task holding a segment (e.g. awaiting a downstream send) can be dropped
by a **close/EOF CQE processed in the unguarded `drain_completions`**, where
`CURRENT_DRIVER` is `None` — so a naive replenish-on-drop either leaks the bid
(best-effort no-op) or panics the worker (`with_state`). Required machinery:

- **Driver-side pin tracking:** `segment_pinned[conn]: Option<PendingRecvBuf>`,
  set at delivery (like `pending_recv_bufs`).
- **`RecvSegment::drop` uses `try_with_state`:** `Some` (normal in-poll drop) →
  replenish (origin class) and clear the slot; `None` → no-op.
- **`close_connection` drains `segment_pinned[conn]`** under its `&mut Driver`
  (like it drains `recv_hold`).
- **Single-release discriminant.** Because `into_owned(self)`/`collect()` copy and
  replenish *then* let `self` drop, and close may drop a parked future whose
  segment already replenished, the guard carries a `released` flag (or
  `ManuallyDrop`): replenish happens exactly once. This closes the `into_owned`
  double-replenish seam and the close/normal-drop race together.

## Mode C — Own (one copy, freely holdable)

```rust
impl ConnCtx {
    pub async fn recv_owned_segment(&self) -> io::Result<Option<Bytes>>;
}
impl RecvSegment<'_> { pub fn into_owned(self) -> Bytes; } // copy + release-once
```

- Copy at delivery: `copy_nonoverlapping` from `buf_backing[bid]` into an owned
  buffer (or a reusable recv-copy pool, cf. `SendCopyPool`), **then**
  `pending_replenish.push((origin_class, bid))` — the INC copy-before-replenish
  ordering, origin class captured at receive time.
- The returned `Bytes` owns heap memory with **no** release-on-drop owner —
  identical in kind to today's `take_frozen`. Freely `Send`, retainable, no ring
  pin. The *same* one copy the accumulator pays today.
- Default for anything holdable, including redis/memcache values an app keeps.

## Rejected: user-held zero-copy (`Bytes` over a provided buffer)

An earlier draft returned a `Bytes::from_owner` over the provided buffer with
replenish-on-drop, plus a "spill valve." **Removed as unsound** (recorded so it
is not re-proposed):

- `Bytes` is `Send + Sync`; it can drop on a foreign thread or after the task
  ends → data race on the single-threaded `pending_replenish` / bid leak / panic.
- The spill valve is **unimplementable**: a handed-out `Bytes` cannot be
  repointed, so the runtime can neither reclaim the bid (deadlock) nor
  force-replenish it (kernel DMA over live consumer data — the INC bug in user
  code).
- Close with such a segment outstanding → double-replenish or bid leak;
  generation guards *slots*, not *bids*.

Every use it was meant to serve maps to Mode A, B, or C.

## Contiguity as opt-in gather (unchanged consumers)

`with_bytes` / `with_data` / `try_with_data` keep their signatures and copy
counts. Their implementation becomes "gather the held segments into the
accumulator, then hand out the contiguous view" — the same copy as today, now one
consumer's strategy. `ConnStream` **stays gathered**: `poll_fill_buf`
(`AsyncBufRead`) keeps returning *all* buffered bytes as one slice (segmenting it
would livelock the legal peek-`fill_buf`-for-a-delimiter-without-consuming
pattern); `poll_read` may drain segment-by-segment. It is the compat adapter; its
doc accepts copies — do not segment it.

## TLS

TLS is a copy-per-chunk source (rustls owns its decrypted plaintext buffer, so
TLS recv can never be zero-copy). Each `Reader::fill_buf` drain is an owned
segment. Corrections carried from review: the chunk is **not** "one ≤16 KiB
record" — `fill_buf` returns as much contiguous plaintext as rustls has buffered;
segment sizes are arbitrary. The decrypt copy *is* a release boundary (ciphertext
bid frees at feed), so TLS never pins the ring. **Keep the outstanding-plaintext
bound + connection-kill** (`recv_accumulator_max`, the current `#[must_use]`
`append` contract) — owned TLS segments must not drop it.

## Backend behavior

| Backend / mode | Segment source | Copies | Release |
|---|---|---|---|
| io_uring, Forward (A) | provided buffer (`recv_hold`) | 0 | on the write CQE |
| io_uring, Borrow (B) | provided buffer, scoped | 0 | on scoped drop (pin-tracked; see Mode B lifetime) |
| io_uring, Own (C) | provided buffer → owned copy | 1 | bid replenished at delivery |
| TLS (either backend) | rustls `Reader` chunk → owned | 1 | ciphertext bid freed at feed |
| mio, any | scratch → **fresh owned copy per delivery** | 1 | none (owned) |

mio has no provided-buffer ring: every holdable segment is a **fresh owned copy**
(the scratch is the copy *source*, never the segment backing). Modes A/B degrade
to owned copies on mio.

## Backpressure and ring safety

Rings are **per-worker, shared across all connections of a size class** (class 1 =
128×64 KiB, class 2 = 64×256 KiB). The prior pass proved a per-connection cap is
insufficient: at fan-in ≥ ring depth, connections each holding one buffer
collectively drain the ring and ENOBUFS-park a well-behaved connection holding
nothing. The mechanism is **aggregate**, built on the occupancy counter:

- **Aggregate low-water reserve (primary).** When `free(class)` drops below a
  reserve, **all** deliveries on that class are forced to Mode C (copy + immediate
  replenish) regardless of mode or per-connection state. This guarantees forward
  progress for connections that need only transient buffers (`discard()`, a fast
  Mode-B drainer) — they always get a buffer, at the cost of a copy under
  pressure. This is the mechanism the "rather than depleting the shared ring"
  intent actually needs.
- **Per-connection cap (secondary).** A per-connection-per-class outstanding cap
  bounds monopolization; past it, that connection's deliveries go Mode C. It is
  anti-monopoly, not the depletion guard.
- **Mode-A `recv_hold` cap** (above) throttles one slow forward from pinning the
  ring.
- **Per-class-aware class selection & re-arm.** `arm_multishot_recv` must pick
  the smallest class ≥ target **with free buffers**, falling back to a deeper
  smaller non-empty class rather than arming against a drained ring. The re-arm
  gate must check the connection's *own* target-class free count, not the current
  global `replenished` bool (which otherwise re-arms a class-2 connection against
  a still-empty class-2 ring every iteration → ENOBUFS churn).
- **`recv_hint` is not a pure win.** Sizing up for big values concentrates
  connections on the shallowest ring (class 2 = 64); couple it to occupancy and
  budget class-2 depth for the target concurrent-large-stream count.

There is **no spill valve** (unimplementable — see Rejected). Ring safety comes
from the aggregate reserve (force-copy under pressure), one-at-a-time pinning, and
the Mode-A hold cap — never from reclaiming consumer-held memory.

## Buffer lifetime and replenish soundness

Every held bid is driver-owned (Mode A, released on write CQE), pin-tracked and
released on scoped drop (Mode B, via `segment_pinned` + `try_with_state` +
close-drain + single-release discriminant), or copied and replenished at delivery
(Mode C). Invariants:

- **Copy before replenish**, no await between (INC template).
- **Replenish to origin class** (`PendingRecvBuf.class`), never live `recv_class`.
- **Exactly one replenish per bid** — enforced by the single-release discriminant
  across the guard drop, `into_owned`/`collect`, Mode-A write CQE, and
  `close_connection`. No double-replenish, no leak.
- **`outstanding`/free count updated at every hand-out and every replenish.**
- Generation guards connection *slots*, not bid lifetime — never rely on it to
  police a held buffer.

## Streaming value APIs (redis, memcache)

Single-value framing is length-delimited: the header is tiny and lands in one
buffer, the value length is known once parsed, so the value body streams with
**no cross-segment parser changes** — the client parses the header contiguously,
then bounds a `ValueStream` (a `SegmentReader`) to `len`. **Streaming is offered
only on the single-connection `Client`**; `Pool`/`ShardedClient`/`ClusterClient`
`get`/`gets` stay **materialized** (`Option<Bytes>`), which also confines the
poison hazard to caller-owned connections and sidesteps MOVED/ASK re-read.

**No forced materialization.** A GET consumer that discards or validates (a load
generator like cachecannon, a proxy, a checksum tool) pays **no** copy:

```rust
pub struct ValueStream<'a> { /* borrows &mut Client; bounded to len */ }
impl ValueStream<'_> {
    pub fn len(&self) -> usize;
    pub async fn discard(self) -> io::Result<()>;                  // consume+release, no copy
    pub async fn next_segment(&mut self) -> io::Result<Option<RecvSegment<'_>>>; // Mode B
    pub async fn collect(self) -> io::Result<Bytes>;               // Mode C — always 1 copy
    pub async fn forward_to(self, sink: &SinkFd) -> io::Result<usize>; // Mode A
}
```

Constraints (from review):

- **`ValueStream<'a>` borrows `&mut Client`** — a second concurrent stream on one
  connection is a compile error (prevents interleaved-read desync); it also can't
  outlive the client.
- **fire/recv stays materialized by default.** `recv() -> CompletedOp` keeps
  returning a materialized value so the "fire N, collect N" batch idiom still
  compiles. Streaming is a distinct, named, opt-in method (`recv_streaming()`),
  which is explicitly drain-before-next.
- **cachecannon pays nothing:** `discard()` (pure throughput) or `next_segment`
  validate-and-release (Mode B). `collect()` (Mode C) is the only copy and only
  if the app keeps the value.
- **Single-value framing only; multi-value stays eager.** `mget`, `hgetall`,
  `smembers`, memcache multi-key `gets(keys)` carry N values per frame; streaming
  N held streams would exhaust the ring. They keep returning `Vec<Option<Bytes>>`
  (gather). (Accepted trade: very large multi-values reintroduce the copy — a
  ring-safety decision, not a redesign.)
- **No name collision.** memcache `gets(keys)` remains the multi-key eager method;
  the single-key CAS stream is a **new name** (`get_cas`). A per-method
  stream-vs-gather table is part of the spec.
- **`collect()` is always 1 copy** (Mode C) — no O(1) claim; a multi-buffer value
  re-gathers but the copy count is still 1. `get_bytes` wraps `collect` for
  callers that just want the bytes.
- **Bounded to `len`, error on short FIN.** `eof_truncated()` flags only *TLS*
  truncation and returns `false` for a plaintext mid-value FIN, so `ValueStream`
  enforces `bytes_remaining == 0` (+ trailing delimiter) independently on both;
  an early end is an **error**, not `None` or short bytes.
- **Poison = immediate `close()`.** `ConnCtx` is `Copy`/stateless and pools never
  read a soft flag, so an undrained-`ValueStream` drop calls `conn.close()`
  (bumping the slot generation) directly — making the stored handle stale so the
  next op fails `NotConnected` and the pool's existing reconnect fires. A soft
  "next op errors" flag is insufficient (undrained bytes stay inbound → desync).
  Confining streaming to owned `Client`s keeps this out of the pool.
- **Writes (`set`/`cas` with `len` + `SegmentSource`):** the client counts bytes
  pulled and errors if the source is short or over-produces; a source error after
  the header is on the wire leaves a half-frame → `close()` (same desync-recovery
  discipline as the read side). Value segments use the per-connection send queue
  (ordering holds vs pipelined reads); large segments can use `SendGuard`.

## Out of scope / unchanged

- `resp-proto` / `memcache-proto` cross-segment value slicing — unneeded
  (length-delimited handoff; parser sees the header only).
- TLS zero-copy recv — impossible (rustls owns its buffer).
- `ConnStream` `poll_fill_buf` — stays gathered.
- Multi-value cache replies, and `Pool`/`Sharded`/`Cluster` `get` — stay eager.
- NVMe / O_DIRECT zero-copy forward sink — Mode C fallback (alignment).
- UDP / QUIC / h3 / ping — already datagram/segment-shaped.

## Reference migration & validation

- **Reference consumer:** migrate `ringline-http`'s `h2.recv` feed to Mode B1;
  confirm ringline's accumulator copy is eliminated.
- **Copy accounting:** extend recv copy counters; assert gather counts drop to
  zero on Mode A/B paths.
- **Throughput:** `ring_fill_bench` gains `MODE=forward` (A) and `MODE=segments`
  (B); re-run the 200 GbE 64 MB sweep. Hypothesis: Mode A large-object throughput
  toward ~2× per core; halves worker count to saturate 200 GbE.
- **Backpressure:** a fan-in test (f.e. 256 conns, class-2 large values) must show
  no starvation/deadlock — the low-water reserve forces copy and everyone
  progresses; a slow-`forward_to` test must not stall other connections.
- **Cache:** `discard()`/validate pay zero copy (cachecannon profile); small-value
  `get` unregressed; undrained-drop closes the connection; truncation errors;
  streaming absent on pooled/cluster clients.

## Phasing

1. **Occupancy accounting + Mode C.** Per-class `outstanding`/free counter,
   Mode-C copy-at-delivery (origin-class, single-release), aggregate low-water
   reserve, per-class-aware class selection & re-arm gate. No new user API yet.
2. **Mode B.** `SegmentReader` lending iterator (`!Send`, `&mut`-exclusive),
   `with_segments` (own result type + heterogeneous ordered `SegChain` +
   under-drain gather), `segment_pinned` pin tracking + `try_with_state` drop +
   close-drain, per-connection cap, contiguity-as-gather. Reference-migrate
   `ringline-http`.
3. **Mode A forward-to-fd.** `SinkFd` (non-raw), recv/write interleave with
   offset + single-write-in-flight + short-write resubmit, `recv_hold` cap +
   re-arm throttle, close-drain. Sockets + buffered files; NVMe alignment-gated to
   Mode C. Validate crucible recv→file zero-copy on 200 GbE.
4. **TLS + mio.** TLS owned copy-per-chunk with the plaintext bound + kill; mio
   fresh-owned-copy-per-delivery.
5. **Streaming value APIs.** `ValueStream<'a>` (borrows `&mut Client`;
   `discard`/`next_segment`/`collect`/`forward_to`), single-value `Client`-only,
   `recv_streaming()` opt-in, `get_cas` (no `gets` collision), bounded-`len` +
   short-FIN error, poison=`close()`, `SegmentSource` length contract. Breaking
   client change → major release. Pooled/sharded/cluster `get` stay materialized.
6. **`ConnStream` review** — `poll_read` drains segments; `poll_fill_buf` stays
   gathered; no `BufRead` behavior change.

## Risks / open questions

- **Reserve / cap values** — low-water reserve size, per-connection cap fraction,
  `recv_hold` cap; interaction with `arm_multishot_recv` class fallback. Tune on
  the fan-in and slow-sink tests.
- **`SegmentReader`/`RecvSegment` ergonomics** — the `!Send`, `&mut`-exclusive
  lending iterator is unusual async Rust; validate usability (esp. nested inside
  `ValueStream`).
- **`forward_to` opcode work** — offset-tracked `writev` path distinct from
  `SendMsg`; short-write resubmit at offset; `SinkFd` registration.
- **Segment count for very large objects** — 256 MB / 256 KiB = 1024; per-segment
  overhead vs the copy saved. Mode A (serialized `MAX_IOVECS` writes) is the path,
  not Mode-B pull-per-segment.
- **Poison composition** — confined to owned `Client`s, but confirm `close()`
  from `Drop` requires `CURRENT_DRIVER` set (true on the owning worker) and
  composes with `?`-early-return (a genuine desync, correct to close).
- **Occupancy counter hot-path cost** — one `u32` inc/dec per hand-out/replenish;
  keep it branch-light.
