# Two shared receive rings per worker, consumed incrementally where supported

Note (2026-10-25): the receive views (#677), `with_bytes_segments` (#678),
and `recv_zc_threshold` and `copy_small_view` (#679) were removed with the
segment readers.

Note (2026-10-25): `forward_to` (Mode A), the segment hold
(`segment_hold`, `HeldRecvBuf`) and `recv_segment_reserve` were removed.

Note (2026-10-25): TLS connections receive directly into their TLS engine's
ciphertext buffer, so no TCP connection receives into the TCP ring.

Note (2026-10-25): the TCP provided-buffer ring was removed, with
`recv_buffer`, `recv_incremental`, `recv_buffer_bgid`, the incremental-ring
preflight and its conformance tests, `OpTag::RecvMulti`,
`OpTag::SendRecvBuf`, the fallback receive, the lend cap, the receive
throttle, `ConnectionState::recv_arm`, and the `recv_parked`,
`recv_fallback`, `forward_throttled` and `recv_preflight_failed` counters.
Nothing this document designs remains in the code.

Status: steps 0, 2 and 3 are implemented (#632, #633), and step 4 behind
`recv_incremental` (#634–#636; 4b-2's recv-forward and direct-echo paths
were removed in 0.7.0-alpha.5). Steps 1, 5, 6 and 7 are not. The receive
views (#677–#679) landed; on io_uring no TCP connection receives one now.
Since 0.7.0-alpha.5 a plaintext connection on io_uring receives directly
into its accumulator, so the TCP provided-buffer ring serves only TLS
connections (UDP has its own ring). recv-forward, direct echo, `recv_hold`
and the recv sink this design refers to were removed. The measurements
behind it, and the alternatives that were measured and not chosen, are in
`docs/journal/2026-09-incremental-buffer-consumption.md`, sections "2026-10:
measurements" and "2026-10: kernels, two rings, tiered caches".

Related: `docs/segmented-recv-design.md` (the bid lifecycle of the lending
paths), `docs/journal/2026-07-enobufs-fallback-recv.md` (#274, the fallback
recv).

## Goal

A TLS receive on io_uring lands in a buffer from one provided-buffer ring
shared by the worker's connections, 256 buffers of 16 KiB
(`config.rs` `RecvBufferConfig::default`). Buffer size sets how much one
completion can deliver; at a fixed memory budget, larger buffers mean fewer
of them. Messages larger than a buffer pay a completion per buffer. (Before
0.7.0-alpha.5, plaintext connections whose task held their bytes kept
buffers every other connection needed; a TLS connection returns its buffer
when rustls reads it.)

This design gives each worker two shared TCP rings, registered as two buffer
groups. The defaults follow the ring kind selected (see "Selecting the ring
kind"), not the kernel version:

| Ring kind | Selected on | Small group (every connection starts here) | Large group (promoted connections) | Large group default | Ring memory per worker |
|---|---|---|---|---|---|
| `IOU_PBUF_RING_INC` | Linux 6.12 and later | 64 buffers of 1 MiB | 64 buffers of 1 MiB | off | 64 MiB, 128 MiB with the large group |
| plain | Linux 6.1–6.11, or `recv_incremental(false)` (from step 7) | 4096 buffers of 64 KiB | 256 buffers of 1 MiB | on | 512 MiB |

With `IOU_PBUF_RING_INC` one buffer is consumed incrementally by successive
completions, from any connection, and returns to the ring only when it is
used up, so a large buffer also serves small arrivals. Plain rings are
backed with `MADV_NOHUGEPAGE` so a completion makes resident only the 4 KiB
pages it writes.

A connection moves to the large group when it streams or holds a lend; see
"The large group". Promoted streaming connections draw from the large
group's buffers instead of the small group's.

With an INC ring the large group is proposed off by default. On 6.12, each
difference between one and two groups was smaller than the rep-to-rep range
of one of the two configurations (three reps). The sign changed between the
run with the first promotion rule and the run with the `SOCK_NONEMPTY` rule
(journal). Landing step 6's measurements decide whether it is turned on. On
6.1, in every cell with 16 streamers sharing the worker in the first
two-group runs (`01a11d44-3a9e`, `01a11d45-3f7d`), two groups cut request
p50 and p99 by 2.8× to 25×. In the tiered and heavy-tailed cells without
streamers, p50 was the same with one or two groups. In the 1 MiB × 64
request/ack cell (`01a11d44-3a9e`), two groups lowered p50 from 46–48 to
36–38 ms and raised p99 from 92–96 to 117–126 ms; the reps did not overlap.
Tiered p999 per rep was 2.75, 2.62 and 3.15 ms with one group and 2.36,
2.03 and 2.49 ms with two (`01a11d44-3a9e`). Heavy-tailed tiered p99 was
3.54, 3.80 and 3.80 ms against 4.06, 4.19 and 3.93 ms, and its p999 5.2
against 6.6 ms (`01a11d45-3f7d`).

Variation between runs is large on 6.1 too. In the later run
(`01a11d87-5bd5`) two groups without the quiet period gave mixed p99 reps
of 168, 369 and 419 ms against 336, 336 and 352 ms with one group, and cut
holding p50 and p99 4.2–4.7×. With the 1 s quiet period, two-group mixed
p99 was 36–122 ms. Two groups on by default with a plain ring is the
author's proposal; landing step 6 confirms or rejects it.

The copy into the accumulator, the lend-in-place paths and the `ENOBUFS`
fallback stay. The accumulator copy is bounded: see "Bounded accumulator".
Under INC a buffer holds the bytes of several completions at increasing
offsets, and returns to the ring only when the kernel has finished with it
and nothing holds any of its bytes.

## Costs

- The receive copy into the accumulator stays, bounded to what completes a
  pending message when the parser announced its length. `with_bytes` gets
  the bound through views over held buffers ("`with_bytes`").
- The `ENOBUFS` park, the fallback recv and the starvation arbitration stay,
  and the buffer state below is added, once per group.
- Above a group's lend cap, arrivals are copied instead of lent.
- `with_bytes` keeps its merge copy when bytes arrive while a task holds
  slices of the remainder.
- Ring memory per worker rises from today's 4 MiB to 64 MiB with an INC
  ring (128 MiB with the large group), 512 MiB with a plain ring. Each group's
  touched pages stay resident. Every measurement used one worker. Peak
  process RSS in the benchmark, MiB, median of three reps per cell (range
  across the cells in the row):

  | Cells | 6.12 one group | 6.12 two groups | 6.1 4096 × 64 KiB | 6.1 two groups |
  |---|---|---|---|---|
  | mixed (1000 request/response + 16 streamers) | 71 | 117–135 | 282 | 580–583 |
  | streaming (1000 connections) | 264 | 328–329 | 361 | 709 |
  | heavy-tailed request sizes | 774–778 | 823–842 | 970–990 | 1061–1275 |

  In the heavy-tailed cells the accumulators dominate: the benchmark's
  bounded accumulator holds up to one message, 1 MiB here, per connection,
  at 1000 connections.
- A promoted connection's small messages each take a whole large-group
  buffer on a plain ring. On 6.1 the 256-buffer large group returned
  `ENOBUFS` 7.8k times per run with promoted holders and streamers
  together (10.9k with heavy-tailed sizes, `01a11d45-3f7d`; 18k–83k,
  median 69k, in the heavy-tailed cell of `01a11d87-5bd5`), 410–955 with
  the 16 streamers alone, and none with the holders alone. With the 1 s
  quiet period: 1.0k–2.2k with streamers alone, 1.6k–2.6k with holding
  streamers, 6.9k–7.1k with holders and streamers. Its size is unsettled.
- On 6.1 (Amazon Linux 2023, loopback) the 4096 × 64 KiB ring had a tail no
  other geometry had at 10,000 connections: p99 906 ms and p999 2.7 s at
  256 B against 130 and 134 ms for the 1024-buffer geometries, and p999
  5.1 s at 64 KiB. It is unexplained. Across two hosts on Debian 12's 6.1
  its p999 at 64 KiB × 10,000 was 1074 ms against 805–872 ms for the
  1024-buffer geometries.
- At equal offered load with one group, latency matched the 256 × 16 KiB
  ring's or was lower, except p999 at 4 KiB messages near capacity
  (1000 connections): 2.4 ms against 1.8 ms on hv01, 3.3 ms against 2.8 ms
  across hosts.
- The ring emulator (#621), if it lands, must reproduce incremental shared
  buffers and two groups.

## Selecting the ring kind

At startup the worker runs the preflight below and, if it passes, registers
the small group with `IOU_PBUF_RING_INC`. A failed preflight, or `EINVAL` from
the registration, selects plain rings for both groups; Linux 6.1 (Debian 12
and Amazon Linux 2023) returns `EINVAL`, and 6.12 and 7.1 accept the flag. Any
other error from either attempt fails the worker's startup with
`Error::BufferRegistration`, as a registration failure does today (`ENOMEM`
from `RLIMIT_MEMLOCK` on a kernel that charges rings included). If the large
group's registration fails after the small group's succeeded, startup fails
the same way and names the large group.

`ConfigBuilder::recv_incremental(bool)` gates the attempt. From step 7 the
defaults are: with an INC ring, 64 × 1 MiB, large group off; with a plain
ring, 4096 × 64 KiB plus 256 × 1 MiB, large group on. From step 7,
`recv_incremental(false)` alone selects the plain row on any kernel, which
lets CI cover the plain path on a kernel that supports INC. Before step 7
`recv_incremental(false)` is the default and selects today's 256 × 16 KiB
ring with no large group. `recv_large_group(true)` is honoured with
`recv_incremental(false)`, so before step 7 CI reaches the two-group plain
path with an explicit `recv_buffer(4096, 64 KiB)` plus
`recv_large_group(true)`.

The incremental-buffer code had fixes in 6.12 stable releases, through at
least 6.12.81, so no patch level marks a kernel with all of them, and a
distribution kernel's patch level does not show its backports. The fixes
after 6.12.63, the release the conformance tests passed on, concern
non-pollable files, bundles, zero-length transfers and multishot `RECVMSG`
with little space left in a buffer. Instead of a version check, each
worker checks the behaviour the driver relies on, on the running kernel,
before it registers the small group with `IOU_PBUF_RING_INC`. It runs on
the worker's own ring, set up with the production flags, before anything
else is armed, and uses an `AF_UNIX` stream socketpair, which needs no
network configuration:

1. Register a one-entry INC ring with a small buffer at the reserved bgid
   65535, the one the `incremental_buffers` probe uses.
2. Arm a multishot `RECV` on one end. Write, reap, write, reap: the two
   completions must land at offsets 0 and the first's length, both with
   `F_BUF_MORE`, and the ring entry must advance in place.
3. Write more than the space left, by fewer bytes than the buffer holds.
   The completion must deliver exactly the space left with `F_BUF_MORE`
   clear, and the excess must end the arm with `-ENOBUFS` without
   `F_MORE`.
4. Post the buffer again and re-arm. The excess must complete at offset 0
   with `F_BUF_MORE`; then a half-close must end the arm with `res` 0, no
   `F_BUFFER` and no `F_MORE`, leaving the entry at the used length.
5. Tear down before the event loop starts: cancel the arm if it is still
   live and reap its last completion, unregister the group, and close the
   sockets, so no preflight completion reaches the event loop.

Steps 1 to 5 run twice: once with a multishot `RECV`, and once with a
one-shot buffer-select `RECV` armed again after each completion, where each
completion has `F_MORE` clear. TCP receives on the ring are one-shot, and
the unit tests that arm a multishot TCP receive use a plain ring, so no
connection arms the receive the multishot pass checks. It still runs, first,
so a kernel that fails only the multishot pass gets a plain ring.

Each step waits at most 1 s for its completion; a step that times out does
not match. A registration refused with `EINVAL` (no INC), a step that does
not match, or a failure to create the socketpair selects plain rings, and
the worker records which step failed in a metric. Any other registration
error fails startup as above, and so does a receive the preflight cannot
cancel within 1 s, since its last completion would reach the event loop;
the preflight ring is then leaked rather than freed. The preflight's
one-page ring is unregistered before the TCP ring is registered, so the
memlock preflight does not count it. The preflight does not cover
ordering under CQ overflow or SQPOLL; the conformance tests checked those
on 6.12.63 and 7.1. It takes about 0.1 ms per worker (85–115 µs over 11
runs on Linux 6.12, arm64), and 2.3 ms on a cold first run.

Ubuntu's 6.8 kernels from 6.8.0-139 reject every provided-ring registration
whose reserved words are zero, the form other kernels require, and accept
one with `resv[0]` set (#626). `UringEngine::register_buf_ring` retries
that way only after `EINVAL` on a 6.8 kernel (#627). On these kernels, ring
selection sees `EINVAL` from the INC attempt in both forms and from the
plain attempt's standard form before the plain retry succeeds. That
sequence is untested. Measurements of this design on 6.8 are pending a
rerun with #627.

## Kernel behaviour relied on

| Behaviour | Result |
|---|---|
| Multishot `RECV` on an INC ring | Successive completions append into one buffer at increasing offsets. Each carries `F_BUFFER` and the bid, and `F_BUF_MORE` while the buffer has room left. |
| The completion that uses up a buffer | Clears `F_BUF_MORE`. The kernel does not write into that buffer again until it is posted again. |
| Data offset | Not in the CQE. Completions for one buffer are reaped in the order the kernel filled it, across every connection sharing it. |
| The ring entry | Rewritten by the kernel as it consumes (`addr` advances, `len` shrinks). |
| More data queued | A multishot receive completion carries `IORING_CQE_F_SOCK_NONEMPTY` when the socket still has data after it. On Debian 12's 6.1.0-53 every full completion of a streaming connection carried it; no completion of a 64 KiB request/response message did (102,678–104,001 per run), and 99.9% of 1 MiB requests' full completions did. |
| No buffer left | `-ENOBUFS` without `F_MORE`, ending the arm. |
| CQ overflow | A multishot completion that finds the CQ full goes to the overflow list and ends its arm (no `F_MORE`), whether or not data is still queued; the driver re-arms it. The byte order holds across the overflow and the re-arm. From 6.13, on a `DEFER_TASKRUN` ring, the kernel runs at most 20 deferred task_work items per pass (`IO_LOCAL_TW_DEFAULT_MAX`), and an `io_uring_enter` makes at most two passes, so a burst of single-completion receives no longer fills the CQ; receives that each post several completions still do. |
| EOF on a partly used INC buffer | A completion with `res` 0, no `F_BUFFER` and no `F_MORE`. The buffer stays posted, and another connection's next data lands at the following offset. |
| `RLIMIT_MEMLOCK` (kernels that charge rings; see `ringline/src/memlock.rs`) | Charged for each ring's entry array, not the buffers: 16 bytes per entry, at least a page per ring. |

The offset order was checked byte for byte on Linux 6.12 and 7.1 with a
64-entry CQ and 32-entry SQ, under SQPOLL, with held lends and at 10,000
connections (journal). The kernel does not run a multishot receive on
io-wq: `io_wq_submit_work` arms poll for it (6.12 and 7.1 source), so
`IOSQE_ASYNC` does not change where its data is received.

The conformance tests in `ringline/src/backend/uring/engine/conformance.rs`
cover each row except `RLIMIT_MEMLOCK`, which `ringline/tests/memlock_rings.rs`
covers. They passed on 6.1.0-53 (Debian 12), 6.8.0-142 (Ubuntu 24.04),
6.12.63 (Debian 13) and 7.1.13 (Debian 13 backports)
(`experiments/recv-conformance-run.toml`). 6.1 and 6.8 have no INC rings,
so only the plain-ring rows ran there. On 6.12 and 7.1 the overflow test's
96 connections posted 508 completions into a 64-entry CQ and 225 arms
ended. CI's Linux test jobs (`ubuntu-latest`, 6.17) run them on pull
requests to `main`.

## Buffer state

Each buffer, identified by its group and bid, has in the driver:

- `written`: bytes the kernel has written since the buffer was last posted;
- `exhausted`: the kernel is done with it;
- `holds`: the number of live lends into it.

The rules:

1. Every completion that carries `F_BUFFER` updates its buffer first, before
   the connection's identity is checked: it advances `written` by `res` and,
   if `F_BUF_MORE` is clear, sets `exhausted`. The group is read from the
   completion's tag, not from the connection, since a completion can arrive
   after its connection moved groups. The stale-CQE early return does this,
   returns the buffer if rule 3 allows it, and touches no connection state.
2. The completion's data is `[base + written_before, base + written)`.
3. A buffer returns to its group's ring when it is `exhausted` and `holds` is
   zero, and only then. It is posted whole (`addr = base`,
   `len = buffer_size`), and `written` resets to zero.
4. Every completion takes one hold, and every path releases it once by
   pushing the bid to `pending_replenish`: a copy path (the accumulator
   copy, TLS, recv sinks, `ForceCopy`, the stale-CQE early returns) in the
   completion handler, a lend path when it is done with the bytes. `flush_replenish_and_rearm` releases the pushed bids
   (`Driver::release_pending`, which frees owned copies and passes ring
   bids to `ProvidedBufRing::release_batch`).
5. On a plain ring every completion exhausts its buffer, at offset 0. One
   code path serves both ring kinds.

The per-path single pushes (`docs/segmented-recv-design.md`) remain; each
releases one hold, and the buffer returns at one site, `release_batch`. A
release without a hold panics, naming the bid. A duplicate release that
arrives after the buffer was posted and completed again takes that
completion's hold and is not detected. A runtime check guards rule 1: when a
completion clears `F_BUF_MORE`, `written` must equal `buffer_size`, and
while it is set, be less; a mismatch is a bug, and the assertion panics
the worker, in release builds too.

A buffer counts as out of the ring when it is exhausted and not yet
returned; a partly filled buffer is still in the ring. A group's `free()` is
then its `ring_size` minus its buffers out, as of the last reaped
completion. It can overstate the kernel's view. That costs an extra
`ENOBUFS`: the connection parks, and since re-arming is driven by
replenishment, it re-arms when a buffer returns.

### Changes in the driver

These read a provided buffer at its base, release by bid, or count
buffers; each now also names the group:

- A multishot receive's 32-bit payload is the connection's full generation
  (`ring.rs` `submit_multishot_recv`), so there is no spare bit for the
  group. A receive armed on the large group uses a second tag,
  `OpTag::RecvMultiLarge`, handled like `RecvMulti` with the large group's
  buffers. Generation checks are unchanged. The connection records which tag
  its live receive uses.
- Every site that builds a `RecvMulti` user_data to cancel the live receive
  uses the live receive's tag: `DriverCtx::cancel` (`handler.rs`, which
  matches on `RecvArm` and gains a variant for the large group), the
  close-time cancel (`driver.rs`), and in `event_loop.rs` the Mode A
  hold-cap throttle (`handle_recv_multi`) and `begin_park`'s cancel
  (`Ring::submit_park_recv_cancel`). A cancel with the wrong tag matches
  nothing.
- `Ring` holds one bgid (`ring.rs`), which `submit_multishot_recv` uses for
  every arm. The arm takes the target group per call.
- `OpTag::SendRecvBuf`'s payload carries the bid in its low 16 bits and
  `SEND_RECV_BUF_REMAINDER` at bit 16 (`completion.rs`); bit 17 carries the
  group. The payload is built in `driver.rs`, `io.rs` and `event_loop.rs`.
- The completion handler (`event_loop.rs` `handle_recv_multi`) reads the
  data at the offset `complete` returns (steps 2 and 3).
- `HeldRecvBuf::Pinned` (`driver.rs`), `SegBacking::Pinned` and
  `SegSettle::Pinned` (`runtime/io.rs`) carry `off`, and their readers use
  `data_ptr(bid, off)`: `driver.rs` forward-write iovecs, the Mode A split,
  `advance_forward` and `settle_forward_end`; `io.rs` segment readers and
  the `with_segments` remainder (step 3). They gain `group` in step 5.
- `PendingRecvBuf`'s pointer is the data's address (step 3).
  `PendingRecvBuf` (backing `pending_recv_bufs` and `recv_hold`) gains
  `group` in step 5; a migrating connection can hold entries from both
  groups.
- The send slab's recv-forward entries record a group per bid (`bids`
  becomes `(group, bid)` pairs), read by `recv_forward_bids` at the
  `SendRecvBufsCoalesced` completion.
- `copy_out_bid` (park) takes the data pointer (step 3).
- `handle_send_recv_buf` resubmits a partial send from
  `data_ptr(bid, off + original_len - remaining)`, where the per-connection
  `send_recv_buf_offs`, next to `send_recv_buf_original_lens`, holds the
  original data's offset (step 3). Its user_data gains the group bit in
  step 5.
- `provided_bufs` becomes one `ProvidedBufRing` per group, and
  `pending_replenish` becomes per group (or `(group, bid)`);
  `flush_replenish_and_rearm` replenishes each.
- Every `pending_replenish.push` of a TCP bid releases one hold through
  rule 3's return check (step 2). The lend paths include the `segment_pinned` single-release check,
  the recv-forward slab's one-bid-per-iovec replenish,
  `release_queued_sends`, the Mode A forward-write completion and
  `fail_forward_write`, `start_forward_write`'s error paths, the close and
  park drains, and the `pending_recv_bufs` flushes (`io.rs` `with_data`,
  `with_bytes`, segmented entry, `with_segments`, direct-echo arm;
  `stream.rs`; the starved and accumulator flushes in `event_loop.rs`).
- `complete` and `release_batch` count buffers out of the ring as defined
  above, and `free()` reads the count (step 2); in step 5, per group.
- `MAX_FORWARD_IOV` (16), `FORWARD_HELD_MAX_BUFFERS` (32) and the send
  slab's `MAX_IOVECS` (32) bound ranges per call; one gathered write can
  hold that many shared 1 MiB buffers.

The UDP ring shares the `ProvidedBufRing` type and stays plain; under rule 5
it needs no special case.

## Bounded accumulator

When a connection's parser last returned `ParseResult::NeedAtLeast(n)`, the
driver records a target accumulator length: the length of the bytes that
parse was shown plus `n`. A completion copies
`min(target.saturating_sub(len), completion length)` bytes into the
accumulator and holds the rest of the completion in place, at its offset.
The held rest is a `pending_recv_bufs` lend; above its group's lend cap
(from step 4) it is copied instead. One buffer is held per connection: a
completion that arrives while a rest is held moves the held rest into the
accumulator and is then copied whole after it.

`NeedAtLeast(n)` is a lower bound, so a parse can need bytes that are
still held. When a parse returns anything other than `Consumed(k)` with
`k > 0` while a buffer is held, the driver moves held bytes into the
accumulator and runs the closure again before the future parks or resolves
at EOF. With `NeedAtLeast(n)` it moves up to the new target, keeping the
rest held at its new offset, or all of them if that would move none
(`NeedAtLeast(0)`); otherwise it moves all of them. On the second
consecutive re-run it moves all of them, so a parser returning small lower
bounds costs at most two extra parses. The future parks, or resolves at
EOF, only when nothing is held. A parse of a held buffer through the fast
path (accumulator empty) that does not complete flushes the held buffer
into the accumulator and parses again, as today.

The target is cleared by any parse result other than `NeedAtLeast`, and
with the accumulator: on reset, on close, and whenever bytes leave it
other than through a parse (`ConnStream` reads, the segmented entry's
`take_frozen`, `settle_forward_end` refilling it).

With no target, a completion is handled as today: held in place if the
accumulator is empty and nothing is held, otherwise copied. While a target
is set, the accumulator holds at most the target plus every byte received,
from the rest of the completion that reaches it onward, before the next
parse; without one it holds every byte the task has not consumed, as
today.

This needs three driver changes, since today a buffer is held in place only
while the accumulator is empty and the held buffer is the older data:

- The driver records the target from `NeedAtLeast(n)` and clears it as
  above, and moves held bytes into the accumulator before the future parks
  or resolves at EOF. Today both futures only call
  `accumulators.reserve(n)`, whose `reserve_target` is a capacity hint
  cleared when the accumulator drains.
- `handle_recv_multi` holds the rest of a completion while a target is
  set and the accumulator is non-empty (today, when the accumulator has
  bytes or a buffer is already held, it copies the held buffer and then
  the completion into the accumulator, `event_loop.rs`). Every path that
  appends to the accumulator or installs a recv sink flushes a held buffer
  first, so a held buffer is always newer than the accumulator's bytes;
  today the recv-sink overflow append and `set_recv_sink` do not.
- `WithDataFuture` parses the accumulator before the held buffer, instead
  of prepending the held buffer to the accumulator (`runtime/io.rs`,
  `accumulators.prepend`). The held rest is parsed by the next `with_data`
  call through the fast path, once the accumulator is empty. After the
  fast path returns `Consumed(k)`, the rest is copied into the
  accumulator, as today, until the views step (landing, after step 4)
  keeps it held.

`park_blocker` reports `DataPending` while `pending_recv_bufs[conn]` is
`Some` (#670), and `take_pending_for_park` does not drain that slot. From step 1
a rest can stay held after a parse of the accumulator returns
`Consumed(k)` (and, from the views step, after the fast path's); the gate
refuses such a connection until the handler reads the rest.

A hold at an offset needs the data-address changes in "Changes in the
driver" (`PendingRecvBuf`'s pointer and `handle_send_recv_buf`'s short-send
resubmit, which today computes from the buffer's base), so they land with
it.

### `with_bytes`

Today `with_bytes` copies a held buffer into the accumulator when it polls,
so the bound would save no copy and no accumulator memory for
`with_bytes` callers. ringline-redis, the only `NeedAtLeast` producer in
the workspace, parses with `with_bytes`.

Decision (owner, 2026-10-08): `with_bytes` hands out `Bytes` views over
held provided buffers. When the accumulator is empty and a buffer is held,
`WithBytesFuture` hands the parser a view over the held rest. After
`Consumed(k)` the rest stays held at offset + k, as a hold, and is not
copied, for `with_data` as for `with_bytes`; `Consumed(k)` with k equal to
the length releases the hold. Each parse over a held buffer takes one
hold, owned by the `Bytes` passed to the parser (`Bytes::from_owner`); the
hold is released when the last `Bytes` sliced or cloned from it drops.
Values the parser slices from it are views. The held rest's
`pending_recv_bufs` lend is a separate hold. Views count under the
per-group lend cap. A parse over the accumulator yields slices of the
accumulator, as today. Whether a value is a view therefore depends on
whether the accumulator was empty when its parse began. Bytes moved into
the accumulator by the re-run rule above are copied.

Buffer memory moves out of `ProvidedBufRing` into a reference-counted
allocation that every view also holds. Only the entry array is mmap'd; the
buffers are a `Vec` today (`provided.rs`). The worker's drop releases its
reference after the ring is dropped (`ring` is `Driver`'s first field, and
fields drop in declaration order), and the last view to drop frees the
memory. A view dropped on its worker queues its release as an `Orphan`
(`defer_release`), which `release_orphans` applies at the start of each
poll pass and before the worker waits for I/O, ahead of
`flush_replenish_and_rearm`. A drop inside a `with_state` closure, such as
the parser's, or in `on_tick`, therefore never takes the driver and is
released before the worker blocks. The orphan queue is per thread, and a
thread can run more than one worker in turn, so a release names its
allocation by a process-unique id (or a `Weak`), not by address, since a
later worker's allocation can reuse a freed one's address;
`release_orphans` ignores a release whose allocation is not among this
worker's group allocations. A release queued after the worker's last
iteration is never applied; the allocation is freed when the last view
drops. One dropped on another thread releases through the worker's
cross-thread inbox, which carries task indices today and gains a message
kind for it. A release sent after the worker exits finds no inbox and is
dropped.

A view the caller keeps pins its whole buffer: a 1 MiB buffer on an INC
ring, shared with other connections' data, for a value of any size. With
64 buffers per group, about 32 kept views on distinct buffers reach the
lend cap; from then on arrivals are copied, and the group has fewer
buffers to refill from until the views are dropped. A client that hands
values to an application cache can do this.

Decision (owner, 2026-10-08): a receive threshold, `recv_zc_threshold`,
mirrors `send_zc_threshold`. The mechanism is the author's design: the
runtime hands the parser one `Bytes` and never sees individual values, so
the threshold is applied where values are known:

- `ConfigBuilder::recv_zc_threshold(bytes)` sets the runtime default.
- A ringline helper takes a `Bytes` returned from a `with_bytes` parse and
  returns it unchanged if it is not a view or is at least the threshold,
  and an owned copy otherwise. It tells a view from an accumulator slice by
  checking whether the data pointer lies in one of the calling worker's
  group allocations, so values parsed from the accumulator stay zero-copy,
  as they are today. Called off a worker, it treats every `Bytes` as a
  view. A view parsed on one worker and passed to the helper on another is
  not recognised and is returned uncopied.
- The client crates (ringline-redis, ringline-memcache) apply the helper
  to every `Bytes` in a response, with a client-level `recv_zc_threshold`
  override. ringline-redis walks the `Value` tree in `read_value_from`,
  which gains the threshold as a parameter so `Pipeline` applies it too. A
  client without an override uses the runtime's configured
  `recv_zc_threshold`; the send side's default (`DEFAULT_ZC_THRESHOLD`) is
  a crate constant and does not read the runtime's value.

The default is measured as `send_zc_threshold` was; until then it is 4096,
the send side's default. A metric counts buffers held by views.

In the benchmark's streaming cells it cut process RSS from 2.3 GiB to 262
MiB (INC 64 × 1 MiB, hv01); with a 1 GiB plain ring RSS only halved, from
2.0 to 1.07 GiB. Bytes copied fell sevenfold, at 10–58% more throughput. The
benchmark parses in the completion handler; ringline parses in the
connection's task, so the gain for ringline is inferred, not measured. The
benchmark knows each message's exact length from its header. Ringline's
bound engages only after a parse has returned `NeedAtLeast`, and
`NeedAtLeast` is a lower bound.

## The large group

### Promotion

A connection's next arm targets the large group when either holds:

- four consecutive completions were each at least `promote_bytes` (default
  64 KiB) and each carried `IORING_CQE_F_SOCK_NONEMPTY`;
- a lend from this connection is still held when its task next parks.
  Every in-place delivery is a lend held past the completion handler, so
  the test is at the park, not after the handler. Two lends count under
  the lend cap but not here or for the demotion exemption (author's
  proposal): a `with_bytes` view, which the caller owns, not the
  connection's task, so a client that keeps values would otherwise stay
  promoted; and a rest the bounded accumulator holds (the part of a
  completion beyond the target, or the rest after a fast-path
  `Consumed(k)`), which would otherwise promote every request/response
  connection that awaits anything between two pipelined requests.

The rule uses a byte threshold rather than "filled its buffer": under INC a
completion clears `F_BUF_MORE` whenever it reaches the end of a shared
buffer, at any size, so "filled" does not identify a stream there.

The `SOCK_NONEMPTY` condition separates a stream from request/response
messages no larger than the threshold. In the two-host 6.1 run, 64 KiB
request/response at 1000 connections produced 102,678–104,001 completions
of 64 KiB per run, none flagged, and promoted no connection. On 6.12 that
cell also promoted no connection, but the benchmark did not count
completions of at least 64 KiB there, so how often the threshold was
reached is unknown. Requests larger than `promote_bytes` (256 KiB or 1 MiB
requests) can satisfy it and promote a request/response connection: with
heavy-tailed request sizes on 6.1, about 290 of 1000 connections were in
the large group at the end of a run, at the same p50 and p99; p999 in the
tiered heavy-tailed cell rose from 5.2 to 6.6 ms in all three reps, with
454 connections in the large group.

Promotion on a held lend was measured only as a static rule: in the
benchmark a fixed set of connections held every range and were promoted on
their first hold. The runtime rule above is unmeasured.

There is no cap on promoted connections. A cap of 64 kept slow handlers and
streamers in the small group, and every cell that needed more than 64
promotions was worse with it than without: on 6.1, streaming throughput
1137 against 1328 MB/s, and request p99 with slow handlers and streamers
570 against 117 ms.

### Migration

A connection whose target differs from its live receive's group cancels
that receive (`ASYNC_CANCEL` by its user_data, with the live receive's
tag). Its completions, up to the final one without `F_MORE`, are handled
under the old group's buffer state (rule 1). The final completion re-arms
the connection on its target group. A receive that ended on its own
(`ENOBUFS`, or `F_MORE` clear) re-arms on the target without a cancel.
Generation checks are unchanged.

### Demotion

A promoted connection returns to the small group after 64 consecutive
completions that do not count toward promotion (see "Promotion"), at the
first such completion once `recv_large_demote_quiet` has passed since the
last one that did. A connection that has never had a completion counting
toward promotion (one promoted on a held lend) is demoted without waiting
for the quiet period. An idle promoted connection receives no completions
and is never demoted. A connection holding a lend that counts toward
promotion is not demoted while it holds. The quiet period applies to both
ring kinds, default 1 s; with an INC ring, landing step 6 decides it
together with the large group.

Moves should be rare. Per-rep medians without the quiet period: decision to
re-arm 1.3–12 ms on 6.12 and 17–586 ms on 6.1. Streamer first delivery 8–21
ms on 6.12 and 130 ms–7.4 s on 6.1. With the 1 s quiet period: re-arm
0.4–25 ms on 6.12 and 15–336 ms on 6.1, and streamer first delivery 7–26 ms
on 6.12 and 96–150 ms on 6.1. For request/response connections, first
delivery also waits for the next request, which in these cells came every
50 ms. Without the quiet period connections moved back and forth: on 6.1, 1
MiB request/ack connections were promoted and demoted about 600 times per
run (eight seconds of measurement plus two of warmup).

With a plain ring, where the large group is proposed on by default, the
quiet period is the proposed rule. On 6.1 the quiet period lowered the
median demotions in the mixed (40 to 5) and tiered (99 to 11) cells, but
the per-rep counts overlapped (mixed 62, 40, 0 against 2, 38, 5; tiered
115, 99, 13 against 23, 4, 11). Mixed p99 and p999 fell 8.4× and 5.6× and
tiered p999 2.6× at the median, and the reps did not overlap. How much of
the difference the rule causes is not established. In the
streamers-holding cell the rule cannot act, because the streamers are the
holders and had 0 demotions either way; that cell moved by 1.4× at p99 and
−21% in streamer throughput. In the heavy-tailed cell the demotions (415
and 381) and the tails overlapped across reps.

With an INC ring the large group is proposed off by default. On 6.12 the
rule changed median demotions only in the mixed cell (6 to 0) and the
heavy-tailed cell (4 to 1, reps overlapping). In the mixed cell p50 and p99
rose in every rep (4.5–6.8 to 9.4–10.5 ms; 7.1–11.0 to 15.2–16.8 ms), and
the p999 reps overlapped. How much of the difference the rule causes is not
established. The tiered cell had at most one demotion per rep without the
quiet period (0, 0, 1) and none with it; its p50 per rep was 5.2, 12.6 and
4.7 ms against 8.4, 14.2 and 12.6 ms.

## Lends

A lend (`pending_recv_bufs`, including a rest the bounded accumulator
holds, `forward_recv_buf`, recv-forward, direct echo, segments,
`forward_to` Mode A, and `with_bytes` views) holds a range of a buffer
until its task polls, its send completes, or, for a view, the caller drops
it. Under INC the buffer is shared, so a 200-byte lend keeps a whole 1 MiB
buffer out of the ring. A connection whose lend, other than a view or a
rest the bounded accumulator holds, is held when its task parks is
promoted, so its later lends pin large-group buffers.

- With `recv_incremental` on, on either ring kind, a lend is taken only
  while at most half that group's buffers have a hold, this completion's
  included. Step 4b-1 counts every hold, so completions copied in the same
  pass, whose releases are queued for the end-of-pass flush, count too; a
  lend refused that way costs a copy. Plaintext lends in `pending_recv_bufs` are otherwise
  uncapped, and connections whose tasks do not poll could hold every
  buffer, leaving a parked connection with nothing to re-arm into. The
  two-ring runs set no lend cap (`--lend-cap` 1.0), so the half-the-group
  cap is unmeasured.
- Above the cap, each path copies instead:
  - `pending_recv_bufs`: into the accumulator;
  - segments and Mode A: into `HeldRecvBuf::Owned`, as the `ForceCopy`
    decision does;
  - recv-forward and direct echo, which deliver only from `recv_hold`: into an
    owned heap copy (`Driver::owned_recv`), not a `SendCopyPool` slot, since
    an incremental completion can exceed a 16 KiB slot. The entry's bid is
    `ring_entries()` plus the copy's index, above every ring bid, so every
    existing release path pushes it unchanged and the flush frees the copy
    instead of releasing a ring buffer; at worker exit, `Driver`'s drop frees
    any left. At most `ring_entries()` copies exist per worker; past that the
    ring buffer is lent, so a peer that sends without reading drains the ring
    and meets `ENOBUFS` backpressure. Step 5 must move the owned bids above
    every group's `ring_entries()`, or mark them with their own group, since a
    large-group bid can exceed the small group's ring size.
- Per connection, `forward_hold_cap` still counts held ranges; one forwarder
  can pin up to that many shared buffers, which the per-group cap bounds.
- With `recv_incremental` on, `recv_segment_reserve` is ignored and the
  per-group cap
  governs; its default (64 free buffers) would otherwise force a copy on
  every segmented and Mode A delivery from a 64-buffer ring. It is removed
  in step 7, which removes a public `ConfigBuilder` method.
- Lends are sent with plain `send`, `sendmsg` and `writev`, never zero-copy,
  so a hold is released at the send's completion. A lend sent zero-copy
  would have to hold until the notification.

## Starvation and the fallback recv

A group can be used up: 10,000 connections × 64 KiB in flight is 625 MiB.
The `ENOBUFS` park and the fallback one-shot recv (#274) stay, per group.

Measured, per run:

- On 6.1 and 6.12, plain rings return `ENOBUFS` at 10,000 connections,
  falling with depth (Debian 12 6.1, 256 B messages: 12.9M for
  256 × 16 KiB, 4.3M for 1024 × 64 KiB, 0.83M for 4096 × 64 KiB).
- INC 64 × 1 MiB returned none at 256 B × 10,000 on 6.12, but 2.3M at
  64 KiB × 10,000 (hv01).
- Streaming at 64 connections used up the 64 MiB INC ring in every run on
  hv01 (about 30–42k).
- On 6.12 with two groups, a median of 88 of 1000 streaming connections
  ended in the large group, and the small group still returned 122k.
- On 7.1 no ring tested, plain or INC, returned any at 10,000 or 50,000
  connections.

Without `recv_incremental` the fallback chunk is `max(4 × buffer_size,
1 MiB)`, and its arbitration prefers the fallback over a re-arm on the
premise that the chunk exceeds the ring's capacity (`event_loop.rs`
`flush_replenish_and_rearm`). That premise does not hold for a 64 MiB ring.
With it (step 4b-1) the chunk is 1 MiB, and a parked connection re-arms
when the group's `free() × buffer_size`, less one chunk for each
connection already re-armed that way in the pass, exceeds it. The benchmark used the 4 MiB chunk, so
step 6 measures this.

When a group is empty the multishot ends, the bytes stay in the socket's
receive queue, and TCP closes the window until the worker re-arms.

## Sizing

- Per worker: 64 MiB with an INC ring (128 MiB with the large group), 512
  MiB with a plain ring. With `recv_incremental`, owned copies for
  recv-forward and direct echo add at most one more ring's worth (one copy
  per ring entry, each at most one buffer). Only touched pages are resident: the plain groups
  use `MADV_NOHUGEPAGE`, and with transparent huge pages a completion would
  otherwise make its whole 2 MiB region resident.
- A group covers the bytes that arrive while a worker is not reaping:
  ingress rate into that worker × the longest stall to absorb before TCP
  backpressure starts. At 100 Gbit/s (12.5 GB/s) into one worker, 64 MiB is
  about 5 ms; a 10 ms stall needs about 128 MiB.
- Before 6.12 the small group's 4096 buffers are for depth: of the plain
  geometries measured on 6.1, it had the fewest `ENOBUFS` and the most
  throughput at 10,000 connections. The large group's 256 buffers are the
  only large-group size measured.
- When `prefault_buffers` is set (off by default), it touches each group's
  memory at startup.
- `RLIMIT_MEMLOCK`, on a kernel that charges rings, is charged only for entry
  arrays. The launch preflight (`worker.rs` `memlock_required`, through
  `memlock.rs`) counts both groups' entries: 4096 + 256 for plain rings; 64,
  or 64 + 64 with the large group, for INC.
- `recv_accumulator_max` must be at least the larger of 1 MiB and every
  configured buffer size (`recv_buffer`, `recv_large_buffer`), since the
  geometry is chosen at runtime; `build()` rejects a smaller value. Today's
  check (`config.rs`) covers only `recv_buffer`. That is a breaking change,
  made in step 7.
- `recv_buffer(ring_size, buffer_size)` still sets the small group's
  geometry, which is then used as given on either kind of ring.
  `RecvBufferConfig` gains a flag recording that `recv_buffer` was called;
  `recv_buffer_bgid` does not set it.
- `ConfigBuilder::recv_large_group(bool)` turns the large group on or off
  (default per ring kind, as in the first table, from step 7);
  `recv_large_buffer(ring_size, buffer_size)` sets its geometry; and
  `recv_large_buffer_bgid(u16)` its buffer group id, default 2;
  `recv_large_demote_quiet(Duration)` the demotion quiet period, default
  1 s. `build()` rejects a large-group bgid equal to the TCP bgid
  (default 0), or the UDP bgid (default 1) when UDP is in use.

## Unchanged

- The UDP ring (`udp_recv_buffer`, its own bgid) stays plain.
- TLS (both engines) copies out of the ring and releases its completion's
  hold in the handler.
- mio. If the ring emulator (#621) lands, it implements this state machine.

## Metrics

Kept: `buffer_ring_empty`, `recv_parked`, `recv_fallback`,
`forward_throttled`. New, per group where it applies: buffers out of the
ring, buffers held by lends, views included, each counted once (the count
the lend cap compares), lends refused by the lend cap, `ENOBUFS`,
promotions, demotions, connections in the large group, the time from a
move's decision to the connection's first delivery on its new group,
buffers held by `with_bytes` views, values copied by the
`recv_zc_threshold` helper, and the ring kind in use.

## Not measured

- Anything in ringline itself: every number is from the `recv-strategies`
  benchmark, including the bounded accumulator's gain.
- Two groups on 7.1.
- Kernels 6.2–6.11; 6.8 is pending #627.
- More than one worker.
- The runtime hold-promotion rule, the holder exemption from demotion, and
  demotion without a quiet period of a connection promoted on a held lend
  (only a static per-connection rule ran).
- The half-the-group lend cap.
- The 1 MiB fallback chunk with the free-space re-arm.
- The demotion rule and the time a migration takes in ringline (measured
  only in the benchmark).
- Quiet periods other than 1 s, and the quiet period outside the four
  cells with streamers (1 MiB request/ack, 64 KiB, stream-mix, cells
  without streamers).
- The demotion rule for an INC ring: the 6.12 runs measured the 1 s quiet
  period; which rule INC uses is open.
- The size of the plain large group: 256 × 1 MiB, the only size run, runs
  out when holders are promoted alongside streamers and, less often, with
  streamers alone.

## Landing

0. Probe and conformance tests: each row of the behaviour table, the
   byte-verified offset order (a CQ overflow, SQPOLL), and EOF on a partly
   used buffer; run on CI and as SystemsLab experiments on 6.1, 6.8, 6.12
   and 7.1. Ring selection uses a behaviour preflight instead of a 6.12.y
   minimum.
1. Bounded accumulator: the target length from `NeedAtLeast` and the
   sites that clear it (reset, close, `ConnStream` reads, the segmented
   entry's `take_frozen`, `settle_forward_end`), the hold of a
   completion's rest while a target is set and the accumulator is
   non-empty, the flush of a held buffer before any append,
   `WithDataFuture` parsing the accumulator before the held buffer, the
   move of held bytes into the accumulator, with a re-parse, before the
   future parks or resolves at EOF. It needs the
   data-address changes to `PendingRecvBuf` and `handle_send_recv_buf`
   from step 3; land those here. `with_bytes` views over held buffers (see
   "`with_bytes`"), with `recv_zc_threshold`, its helper, the client
   crates' use of it and the view metric, are a step of their own after
   step 4, since a view is a hold (Buffer state rule 4) counted under the
   per-group lend cap. That step also keeps the rest held at offset + k
   after `Consumed(k)` (for `with_data` too), and gives `WithBytesFuture`
   the fast path and the accumulator-first parse order.
2. Buffer state (`written`, `exhausted`, `holds`) with the ring registered
   plain. Every completion exhausts its buffer at offset 0, so behaviour is
   unchanged; each per-path push releases one hold. The existing
   lifecycle tests (double replenish, leaks, close drain, the Mode A hold
   cap) pass unchanged. Steps 2 and 3 can be one change if that is simpler.
3. Offsets: the `off` fields, data at `base + written`, `copy_out_bid`
   and `settle_forward_end`. Still a plain ring, where these offsets are 0,
   so these paths are exercised only from step 4.
4. INC and the plain geometry, behind `recv_incremental` (default
   `false`), in two changes. 4a: ring-kind selection with the behaviour
   preflight (about 0.1 ms per worker on Linux 6.12, arm64),
   `MADV_NOHUGEPAGE`, the geometry per ring kind, the memlock preflight
   and the ring-kind metrics. 4b-1: the lend cap with the copy paths that
   exist (`pending_recv_bufs` into the accumulator, segments and Mode A
   into `HeldRecvBuf::Owned`), `recv_segment_reserve` ignored, the 1 MiB
   fallback chunk with the free-space re-arm, and the lends-refused count;
   all only with `recv_incremental`. 4b-2: the owned `recv_hold` entry for
   recv-forward and direct echo.
5. The large group, behind `recv_large_group` (default `false`): its bgid
   and validation, the arm taking the group per call,
   `OpTag::RecvMultiLarge` and the `SendRecvBuf` group bit, `group` in
   `PendingRecvBuf` and the send slab, the cancel sites, promotion,
   migration and demotion with `recv_large_demote_quiet`, the two-group
   memlock preflight, and the per-group gauges and `ENOBUFS` count.
   Migration is timed in ringline's metrics.
6. Measure ringline on hv01 and across hv01/hv02, on Linux 6.1, 6.8, 6.12
   and 7.1: the geometry per ring kind with and without the large group
   against the 256 × 16 KiB ring, with the bench suite (echo at 256 B to
   1 MiB, mixed and heavy-tailed sizes, the #415 forward proxy, streaming,
   slow handlers alongside request/response, 64 to 10,000 connections).
   Record throughput, RSS, and p50/p99/p999 at fixed offered load (an
   open-loop client measuring from each message's scheduled time, with
   streamers held to a fixed rate), five reps or more per cell with an A/A
   pair on each setup; a difference counts when it exceeds the A/A spread.
   Gate: no cell slower, or worse at p99, than the 256 × 16 KiB ring beyond
   that spread, and no sustained `buffer_ring_empty`. A cell that fails is
   resolved before step 7, by geometry for that kernel, by leaving the
   large group off there, or by keeping the 256 × 16 KiB ring there. This
   step decides the large group's default and its demotion rule with an
   INC ring, and confirms or rejects the proposed plain-ring default (two
   groups on) on 6.1 and 6.8, and with `recv_incremental(false)` on 6.12
   and 7.1.
7. New defaults (the geometry per ring kind, `recv_incremental` on, the
   large group's default per ring kind, the `recv_accumulator_max` floor,
   the removal of `recv_segment_reserve`) in a coordinated release. Before
   `recv_incremental` is on by default, the rule-1 assertion in
   `ProvidedBufRing::complete` becomes a counted recovery, so a kernel
   whose TCP receive differs from what the preflight checks does not panic
   a worker.

Steps 1 to 3 change neither the ring's registration nor its geometry, and
can land before INC is switched on. Step 1 holds a buffer in
`pending_recv_bufs`, out of the ring, in more states than today, still at
most one per connection, with no lend cap until step 4.
