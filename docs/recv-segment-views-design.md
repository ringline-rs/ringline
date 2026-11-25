# Segment views: `Bytes` over held receive buffers for segment parsers

Note (2026-10-25): the segment readers (`segments`, `recv_owned_segment`,
`with_segments`, `end_segments`, `SegmentReader`, `RecvOwnedSegment`,
`SegChain`, `SegConsumed`) and landing steps 1 to 3 (the receive views,
`with_bytes_segments`, `recv_zc_threshold`, `copy_small_view`) were
removed.

Note (2026-10-25): `forward_to` and the segment hold (`segment_hold`) were
removed.

Note (2026-10-25): the TCP provided-buffer ring and `recv_incremental` were
removed.

Status: landing steps 1 (the view machinery), 2 (the reader) and 3
(`recv_zc_threshold`) are implemented; steps 4 to 6 are a proposal.

Related: `docs/recv-incremental-ring-design.md` ("`with_bytes`", the owner
decisions of 2026-10-08 on views and `recv_zc_threshold`),
`docs/segmented-recv-design.md` (the segmented domain and its readers),
`docs/recv-buffering-approaches.md`.

## Goal

resp-proto (`Value::parse_segments`, ringline-rs/resp-proto#8) and
memcache-proto (`ResponseBytes::parse_segments`,
ringline-rs/memcache-proto#13) parse a message from bytes split across
several `Bytes` pieces. A value that lies inside one piece is returned as a
slice of that piece; a value that spans pieces is copied. Both are merged
and not yet released.

Ringline cannot hand such a parser its received bytes as `Bytes` without
copying them first. This design adds a reader that presents a connection's
buffered bytes as `&[Bytes]`, where each held provided buffer is a `Bytes`
view of the buffer's memory, so values a segment parser takes from one
buffer are not copied.

## What exists

On io_uring a connection receives in one of two domains
(`Driver::recv_domain`).

- Default domain. At most one completion is held in place per connection
  (`pending_recv_bufs`); a completion that arrives while the accumulator has
  bytes or a lend is held, or whose lend the lend cap refuses, is copied
  into the accumulator. `with_bytes` copies the held lend into the
  accumulator when it polls (`WithBytesFuture`, `runtime/io.rs`), then hands
  the parser the accumulator as one frozen `Bytes`. Every byte a
  `with_bytes` parser sees has been copied at least once; bytes appended
  while a parse remainder is held (`put_back` after `NeedMore`) are copied
  again when `unfreeze` merges them into the remainder.
- Segmented domain, entered by `segments`, `recv_owned_segment`,
  `with_segments`, `forward_to` and `forward_to_conn`.
  - Completions queue in `segment_hold` as `HeldRecvBuf::Pinned { bid, off,
    len }`, or as `HeldRecvBuf::Owned(Bytes)` when the lend is refused: by
    the lend cap with `recv_incremental`, or at or below
    `recv_segment_reserve` free buffers without it (`handle_recv_multi`,
    `backend/uring/event_loop.rs`).
  - `throttle_if_held` stops re-arming the receive (and cancels an armed
    multishot receive) when `at_hold_cap` is true, and
    `rearm_throttled_recvs` re-arms it once the hold drains below the cap.
    The TLS branch of `handle_recv_multi` calls it too when the connection
    is in the segmented domain.
  - `at_hold_cap` has two terms. The segment term is true when the hold plus
    the buffers a `forward_to` write pins reaches `forward_hold_cap` entries
    with a lend cap, or `quarter_ring_cap` without one. The send term is
    true when `send_held_recv`, the lent buffers held by the connection's
    `forward_recv_buf` sends, reaches `quarter_ring_cap`.
    `quarter_ring_cap` is `min(forward_hold_cap, max(ring entries / 4, 1))`.
  - `close_connection` leaves the hold, so a reader woken by a FIN can still
    parse it; `handle_close` (teardown) releases what is still held.
  - A segmented connection is not eligible for the `ENOBUFS` fallback
    receive (`fallback_eligible`).
  - `end_segments` (`settle_forward_end`) copies what is still held into the
    accumulator and returns the connection to the default domain.
- `with_segments` presents the held bytes as a `SegChain` of `&[u8]` slices,
  borrowed for the callback only. After the callback it copies every
  unconsumed byte into the accumulator, so a parser that needs more than is
  buffered (`SegConsumed(0)`) copies every unconsumed held byte it was
  shown.
- The buffers are a `RingMemory` mapping that `ProvidedBufRing` shares
  through an `Arc` (`provided.rs`, `view.rs`). `Driver::recv_view` makes a
  `Bytes` view of a held range (landing step 1), and `with_bytes_segments`
  hands views to a parser (landing step 2).
- `BufState::holds` counts uses of a buffer's bytes. A buffer returns to the
  ring when it is exhausted and has no buffer hold (rule 3 of "Buffer state"
  in `docs/recv-incremental-ring-design.md`). `ProvidedBufRing::held` counts
  buffers with a buffer hold, the number the lend cap compares.
- `runtime::defer_release` queues an `Orphan` from code that cannot reach
  the driver, and `release_orphans` applies the queue at the start of every
  task-poll pass and before the worker waits for I/O
  (`backend/uring/event_loop.rs`).

`docs/segmented-recv-design.md` ("Rejected: user-held zero-copy") rejected a
`Bytes::from_owner` over a provided buffer as unsound, and the 2026-10-08
decision in `docs/recv-incremental-ring-design.md` ("`with_bytes`") reversed
that. This design answers that section's three objections ("Views", "Ring
pressure"):

- A view never takes the driver. Dropped on its worker's thread it queues
  an `Orphan`; dropped elsewhere its release goes through the creating
  worker's inbox; after the worker exits the release is dropped, and the
  `Arc` keeps the memory alive until the last view drops.
- There is no spill valve, and the runtime never returns a buffer a view
  holds. Kept views count against the lend cap (`held()`) or, without one,
  against `recv_segment_reserve` (`free()`). Once a bound is reached, later
  segmented completions are copied rather than lent, so segmented holds and
  views leave at least half the ring unheld with a lend cap, or
  `recv_segment_reserve` buffers free without one (one buffer at a reserve
  of 0; see "Ring pressure"). A view's range ends within
  `BufState::written`, and the kernel writes only past those bytes, on
  incremental rings too.
- A view holds its buffer by a buffer hold of its own, not through the
  connection's slot. `release_batch` posts a buffer only when its last hold
  is released, so close's release of each held entry (`handle_close`) and a
  view's release are separate decrements, and neither posts a buffer the
  other still holds. A buffer is posted again only after every hold on it
  is released, so a view's release always lands before the bid's next
  posting. It cannot take the hold of a completion after that posting, the
  duplicate-release case `release_batch` does not detect.

## API

```rust
impl RecvHalf {
    pub fn with_bytes_segments<F>(&mut self, f: F) -> WithBytesSegmentsFuture<F>
    where
        F: FnMut(&[Bytes]) -> ParseResult;
}
```

`Connection` has the same method and forwards to `RecvHalf`'s, which
forwards to a `pub(crate)` method on `ConnCtx`, as `with_bytes` does. The
future resolves to `io::Result<usize>`:

- `Ok(k)` for `k` bytes consumed;
- `Ok(0)` at EOF, for a stale handle, or after closing the connection
  because buffered bytes exceed `recv_accumulator_max`, as `with_segments`
  does;
- `Err(EBUSY)` when a forward runs, a `SegmentReader` is live, or another
  reader used the connection while the future was parked (below).

It uses `ParseResult` because its callers are the parsers that already use
`with_bytes`: a parser over `&[Bytes]` returns `Consumed(k)`, `NeedMore` or
`NeedAtLeast(n)` as it does over one `Bytes`. `with_bytes` tolerates an `n`
that is too large, since it only reserves with it. This reader does not call
the parser again until `n` more bytes arrive, the hold cap is reached, or
the receive side finishes, so an `n` that is too large stalls it. On mio,
which has no hold cap, it stalls until EOF, or until the accumulator reaches
`recv_accumulator_max` and the connection is closed. The
`ParseResult::NeedAtLeast` rustdoc says so.

Each call's first poll enters the segmented domain through
`enter_segmented_domain` (`runtime/io.rs`), with `SegmentedEntry::ViaHalf`
and `exclusive` false (true would set `segment_reader_live`, and every later
call would return `EBUSY`). It maps the refusals: a stale handle (`EPIPE`
there) resolves to `Ok(0)`, and a running forward or a live `SegmentReader`
to `Err(EBUSY)`.

On io_uring the parser runs under `ReaderCallback::enter`, as the callbacks
of `with_data`, `with_bytes`, `with_segments` and `try_with_data` do, so
`offer_park` declines a park offer made from inside it (#671). Held entries
stay in `segment_hold` during the callback, so `holds_unread` is true while
any are held. After a hold-cap copy the parser can be called with only the
accumulator, which `take_frozen` has taken out, and then `holds_unread` is
false while a request is half read.

Entering moves any accumulator bytes to the front of the hold as one `Owned`
entry, and converts a `pending_recv_bufs` lend into a `Pinned` entry at the
back, which copies nothing: the lend's buffer hold becomes the entry's.
`PendingRecvBuf` holds `bid`, `len` and the data pointer; the offset is the
pointer less `ProvidedBufRing::data_ptr(bid, 0)`. The conversion applies to
every caller of `enter_segmented_domain`, so `segments` and
`recv_owned_segment` read the lend as a `Pinned` entry too. Before step 2
they read it as an `Owned` copy.

The future does not borrow the half, so while it is parked the caller can
run another reader on the connection: start a forward or a `SegmentReader`,
call `with_segments`, `recv_owned_segment`, `end_segments` or another
`with_bytes_segments`. Any of them can consume bytes the future was shown,
and a forward that ends, a dropped `SegmentReader` and `end_segments` return
the connection to the default domain (`settle_forward_end`). A later poll
that continued would act on stale state: a recorded `NeedAtLeast(n)` counts
bytes that are gone, and in the default domain the next completion is lent
into `pending_recv_bufs`, which this reader does not read. The future
therefore records two per-connection values at the end of each poll that
parks:

- `segment_epoch`, a counter `settle_forward_end` increments, so it changes
  when a forward ends, a `SegmentReader` drops or `end_segments` runs;
- `Driver::recv_consumed`, the bytes of the stream readers have removed:
  the arrival log's `delivered` less `recv_buffered`. A reader that consumes
  bytes raises it, and moving bytes between the accumulator, the lend and the
  holds does not change it. It counts consumption by every reader without an
  increment at each reader's consume site.

Every later poll first checks the handle (stale: `Ok(0)`), `forward_progress`
and `segment_reader_live` (`Err(EBUSY)`), and then the two values: if either
changed, the poll resolves to `Err(EBUSY)` without touching the hold, and
the caller calls again. Without the first two checks a poll would parse the
hold a forward owns, and at the cap copy it into the accumulator, which a
forward never reads.

The executor keeps one receive waiter per connection (`recv_waiters`,
`owner_task`), so a reader parked in one task is not woken when a reader in
another task on the same connection finishes; that holds for every reader in
ringline today. The checks above apply when the future is polled again,
which happens when both readers run in one task.

On io_uring the slice then holds one `Bytes` per `segment_hold` entry, in
order: a view for a `Pinned` entry, a clone of the `Bytes` for an `Owned`
one. Whenever the accumulator has bytes it is presented first, as one frozen
`Bytes` (`take_frozen`, as `with_bytes` does). Its bytes are older than
anything held, because they come from this future's hold-cap copy. A TLS
connection in the segmented domain pushes each decrypted plaintext chunk to
the hold as an `Owned` entry (`feed_tls_recv` with
`PlaintextSink::Segments`), so its pieces are heap `Bytes`, not views; a
value inside one chunk is still not copied again.

On mio the slice has at most one element, the accumulator. Mio has no
`SegmentReader`, and has a forward (`forward_to_conn`, `forward_conn`). The
mio path follows the io_uring reader:

- at EOF with nothing buffered it resolves to `Ok(0)` without calling the
  parser;
- it applies the `NeedAtLeast` skip;
- a stale handle resolves to `Ok(0)`;
- while a forward runs it resolves to `Err(EBUSY)`;
- a later poll resolves to `Err(EBUSY)` when `Driver::recv_consumed` changed
  since the previous poll: another reader or a forward consumed accumulator
  bytes. The mio plaintext read path records a read before it appends it, so
  bytes it drops past `recv_accumulator_max` are counted in a per-connection
  `recv_dropped`, which `recv_consumed` subtracts. Mio has no domain to
  leave, so it has no `segment_epoch`.

A client crate calls one method on both backends and gets the same errors,
except on an io_uring connection that receives directly, where the call
returns `Unsupported` (`docs/recv-direct-design.md`).

The connection stays in the segmented domain after the future resolves;
`end_segments` returns it to the default domain. On mio `end_segments`
returns `Ok(())`, for a stale handle too, so a caller leaves the domain with
one call on both backends. Until `end_segments` runs, on io_uring,
`with_data`, `with_bytes`, `recv_ready` and `ConnStream` never see bytes that
arrive, because those bytes go to `segment_hold`; a caller that switches
readers calls `end_segments` first. No client crate reads with segments
(decision 12 in `docs/recv-direct-design.md`).

## After the callback

- The future drops the `Bytes` it presented before it puts anything back, as
  `with_bytes` moves its clone into the callback; a clone still alive when
  the accumulator next merges forces `unfreeze` to copy the whole
  accumulator.
- `Consumed(k)`, `k > 0`: `k` is clamped to the bytes presented, as in
  `with_segments`, and the first `k` bytes are dropped. The accumulator's
  unconsumed rest is put back (`put_back`, as `with_bytes`). Each
  `segment_hold` entry wholly inside the `k` bytes is popped and its buffer
  hold released; an entry partly inside has its `off` and `len` advanced and
  stays at the front. Nothing is copied. The future resolves to `k`.
- `NeedMore`, `NeedAtLeast(n)` or `Consumed(0)`: everything stays held and
  the future parks, or resolves to `Ok(0)` if the receive side has finished.
  `NeedAtLeast(n)` records `n` in the future; the parser is not called again
  until the accumulator and the hold together have `n` more bytes than it
  was shown, or the receive side finishes, or the hold cap is reached (next
  item). The resp-proto and memcache-proto docs warn that retrying a segment
  parse on every arrival costs the square of the piece count; the recorded
  `n` removes the retries for a parser that reports one. Each parse creates
  one view per `Pinned` entry, so a reader that consumes one message per
  call from a hold of H entries creates at least H views per message, and H
  more for each re-parse.
- At the hold cap the poll ignores the `NeedAtLeast` skip and calls the
  parser over the pieces. If the skip applied at the cap, a parser that
  returned `NeedAtLeast` would not be called while the receive is throttled,
  and the hold would never drain.
- If that parse is incomplete and the receive side has not finished, every
  held entry is copied into the accumulator, in order, their buffer holds
  are released, and the future parks; its next poll presents the accumulator
  first. At end of stream the future resolves to `Ok(0)` and teardown
  releases the hold. A message that arrives in more completions than the
  hold cap completes only through this copy.
- Before the copy, `AccumulatorTable::reclaim` reclaims the frozen remainder
  (`unfreeze` with nothing appended, recovering the allocation with
  `try_into_mut`). That costs nothing once the presented clone and any slice
  the parser kept of it have dropped; if a slice is still alive, the method
  copies the remainder once into a buffer of the reserve target's size. The
  copy then calls `reserve` with the held bytes plus the recorded `n`, so
  the accumulator grows once, and each held byte is copied once by this
  path.
- An `Owned` entry (a refused lend, a TLS chunk, a fallback receive
  completion in flight at entry, or the accumulator moved in on entry) was
  copied once already, so its bytes are copied twice.
- The accumulator bound (`recv_accumulator_max`) applies to the copy; past
  the bound the connection is closed and the future resolves to `Ok(0)`, as
  in `with_segments`.
- On a TLS connection the same copy runs whenever the hold reaches the cap.
- Bytes the copy leaves in the accumulator after the future resolves are
  moved into the hold by the next segmented reader's entry
  (`enter_segmented_domain`), which does not count them. Only a
  `RecvOwnedSegment` future made before the copy and polled after it adopts
  them through `adopt_stranded_accumulator`, which increments
  `SEGMENT_STRANDED_ADOPTED`.
- The future checks only the segment term of `at_hold_cap`,
  `Driver::segment_at_hold_cap`. The forward term
  would run the hold-cap copy while a lend sent by `forward_recv_buf` is in
  flight, with `segment_hold` under the cap.

Pieces made from `Pinned` entries, and slices of them, are views, described
next; the parser can keep them past the callback. The `Bytes` handed to the
parser for the accumulator is the accumulator's own frozen buffer, as in
`with_bytes`, and slices of it are not views.

## Arrival times

`with_bytes_segments` is a reporting reader of the arrival log
(`docs/recv-arrival-times-design.md`, "The consumed range"), and settles as
`with_segments` does: each poll whose handle matches takes `arrival_mark`,
and a poll that returns `Ready` calls `arrival_settle`, with `report` true
only for `Ok(k)` with `k > 0`. `Err(EBUSY)`, end of stream and a close at
`recv_accumulator_max` leave `Connection::recv_arrival` at `None`; a stale
handle does not touch the log.

`recv_buffered` counts the accumulator, `recv_direct_held`,
`pending_recv_bufs` and `segment_hold`. Entering the domain, converting a
lend to a `Pinned` entry and the hold-cap copy move bytes among the
accumulator, `pending_recv_bufs` and `segment_hold` without changing the
sum, so the range a call reports is the `k` bytes its `Consumed(k)`
removed. A view the parser keeps holds consumed bytes, which
are not in `recv_buffered` and do not delay the arrival log's trim.

## Views

Step 1 moves a ring's buffer memory into `RingMemory`, an anonymous mapping
shared through an `Arc`, with a process-unique memory id. A view is
`Bytes::from_owner(RecvView { .. })`. `RecvView` holds an `Arc` of the
ring's `RingMemory`, the range it covers, the buffer's bid, and the id of
the worker that created it; the memory id is read from the `Arc`.

- Creating a view takes one buffer hold (`BufState::holds += 1`), so the
  buffer is not posted again after it is exhausted, and counts in
  `held()`, under the lend cap.
  It asserts that the buffer already has a hold and that the range ends
  within the bytes the kernel has completed in the buffer
  (`BufState::written`); the kernel writes only past those bytes. The
  `segment_hold` entry's own buffer hold is separate: popping the entry
  releases it, and the buffer returns to the ring only when every view of it
  has also been dropped.
- A view records the id of the worker whose driver made it
  (`Driver::worker_id`, set by the event loop), not the thread's current
  worker, so its release reaches that worker when a thread has run more
  than one.
- Dropping the last clone of a view (Bytes's owner refcount) releases its
  buffer hold. While the creating worker is current on the dropping thread,
  the drop queues `Orphan::RecvView { alloc, bid }` with `defer_release`,
  where `alloc` is the memory id. `release_orphans` queues the bid for the
  flush, which releases the buffer hold (`release_batch`) and posts the
  buffer if rule 3 allows it. The drop never takes the driver, so a view
  dropped inside a parser callback, a `with_state` closure or `on_tick` is
  safe.
- Otherwise (another thread, or a later worker on the same thread), the drop
  pushes `(alloc, bid)` onto a release list in the creating worker's inbox
  (`runtime/waker.rs`), sets that list's own nonempty flag, and writes the
  worker's wake fd if the flag was clear. `release_orphans` drains the list.
  A worker that has exited has no inbox; the release is dropped.
- `release_orphans` ignores a release whose memory id is not the current
  worker's `RingMemory`'s. A thread can run more than one worker in turn,
  and a later worker's `RingMemory` can reuse a freed one's address, so the
  memory id is a process-unique counter and not an address.
- The buffer memory moves from `ProvidedBufRing`'s `Vec<u8>` into
  `RingMemory`. Like the `calloc` behind `vec![0; n]`, a mapping leaves
  untouched pages unbacked; a page-aligned `alloc_zeroed` would zero, and so
  make resident, the whole ring at startup. `Driver` drops its `ring` first
  (fields drop in declaration order), then `provided_bufs` drops its
  reference; the memory is freed when the last view drops. The memory is
  freed no earlier than the `Vec` is today, after the ring is dropped, so
  the change adds no case where the kernel can write to freed buffer memory.
- Under `IOU_PBUF_RING_INC` the kernel keeps writing a buffer past `written`
  while views of its earlier bytes are alive. The ranges are disjoint, and
  the allocation is reached only through raw pointers, so no `&mut [u8]` to
  the buffer exists while a view does. `prefault` and `advise_no_huge_pages`
  run before the ring is armed.
- A view's buffer hold does not count toward a connection's hold cap,
  because `at_hold_cap` counts `segment_hold` entries. With a lend cap, kept
  views count in `held()` against it; without one, they count in `free()`
  against `recv_segment_reserve`.
- A view does not block a park. `park_blocker` and `offer_park` refuse
  while `holds_unread` is true: while `recv_buffered` counts bytes, or a
  buffer is in `segment_pinned`. A view holds bytes already consumed and is
  not tied to the connection's slot. `handle_park_install` closes the
  connection on the creating worker, and `handle_close` drops the handler
  future there, with any view it holds. A view in `ParkState` that drops on
  another worker releases through the creating worker's inbox; one dropped
  on the creating worker (a deposit cleared by `offer_park`,
  `withdraw_park_offer`, `close_connection` or slot reuse, or a `ParkedFd`
  that `drain_park_ready` drops because its target worker has gone) queues
  an `Orphan`.

The default-domain `with_bytes` views decided in
`docs/recv-incremental-ring-design.md` ("`with_bytes`") can use `RecvView`
when they land.

## Kept values

A view the caller retains keeps its whole buffer from being posted again,
for a value of any size: 16 KiB on the default ring, 1 MiB on an incremental
ring, and 64 KiB on the plain ring used when `recv_incremental` is on and
the kernel has no incremental rings or fails the preflight. These are the
default geometries; an explicit `recv_buffer` overrides them. The
`recv_zc_threshold` decision (owner, 2026-10-08) applies, except that on
mio nothing is a view, and code on a worker thread outside the worker's
tasks and its `on_tick` and `on_notify` callbacks is treated as off a
worker:

- `ConfigBuilder::recv_zc_threshold(bytes)`, default 4096, which
  `ringline::recv_zc_threshold()` returns in the worker's tasks and
  callbacks (4096 elsewhere). The runtime does not apply it itself.
- `ringline::copy_small_view(value, threshold)` returns `value` unchanged if
  it is not a view or is at least `threshold` bytes, and an owned copy
  otherwise. It identifies a view by checking whether the data pointer lies
  in the calling worker's `RingMemory`. Elsewhere, on any thread, it treats
  every `Bytes` as a view; on mio nothing is a view.
- ringline-redis and ringline-memcache apply it to every `Bytes` in a parsed
  response, with a client-level override (step 6).

A value that spans pieces was already copied by the parser, so the helper
returns it unchanged. A slice of an `Owned` piece (a refused lend's copy, up
to 1 MiB, a TLS chunk, a fallback receive completion, or the accumulator
moved in on entry, up to `recv_accumulator_max`) is not a view either, and
the helper returns it unchanged, so a small kept value can retain a large
heap copy. This design does not bound that.

## Lend refusals

A completion whose lend is refused is copied into an `Owned` entry today,
and the connection keeps receiving. With the lend cap at half an incremental
ring's 64 buffers, a connection that keeps refusing grows `Owned` entries up
to its hold cap, 64 entries of up to 1 MiB each, so up to 64 MiB of `Owned`
entries per connection besides the accumulator, with no bound across
connections. `docs/recv-buffering-approaches.md` records the same growth for
accumulator copies: 1.5 GiB peak RSS in ringline's forward echo at 64 KiB ×
16,384, two workers.

The reader keeps that behaviour. The completion's bytes are already received
when the lend is refused, so they are copied in any case; the choice is
whether the connection then keeps receiving. A throttle that stopped the
receive after a refused lend until the reader next polled was considered and
left out of this design:

- `wake_recv` wakes the reader on every completion (`handle_recv_multi`), so
  for a reader that polls after each one the per-connection maximum is
  unchanged: a hold cap's worth of completions plus `recv_accumulator_max`.
  The throttle changes only a connection whose reader is not polling, which
  would hold one refused completion instead of a hold cap's worth.
- It needs a per-connection flag checked at every re-arm site (the end of
  `handle_recv_multi`, `drain_recv_rearm_retries`,
  `rearm_multishot_if_idle`, the starved re-arm in
  `flush_replenish_and_rearm`, and `maybe_rearm_throttled_forward`), a
  cancel when a multishot receive is armed, and a clear-and-re-arm at slot
  reuse, in `settle_forward_end`, and whenever the connection switches to
  another segmented reader. A path that clears it without re-arming leaves
  the connection with no receive.
- Its re-arm cannot wait for the ring's held count (`ProvidedBufRing::held`)
  to fall, since views that callers keep count in it and nothing in the
  runtime releases them.

`docs/journal/2026-10-receive-starvation.md` leaves open whether a refused
lend should copy or wait for a buffer. The question applies to the default
domain as well, and this design does not settle it.

## Ring pressure

In the default domain a connection holds at most one lend for its reader. In
the segmented domain it holds one per completion until its parser consumes
the bytes, up to the hold cap. A client with many connections and small
pipelined responses therefore holds more buffers at once than it does today.
Without a lend cap, deliveries at or below `recv_segment_reserve` free
buffers are copied. Views count in `free()`, so with a nonzero reserve they
leave at least that many buffers free. With a reserve of 0, which validation
allows, a segmented delivery is still copied when no buffer is free
(`delivery_decision(0, 0)` is `ForceCopy`), so segmented holds and views pin
at most all but one buffer. Most receives then get `ENOBUFS` and re-arm one
at a time as that buffer returns. A segmented connection is not eligible for
the fallback receive (`fallback_eligible`), so after `ENOBUFS` it waits for
a buffer to return. Plain rings return `ENOBUFS` at 10,000 connections on
6.1 and 6.12 (`docs/recv-incremental-ring-design.md`, "Starvation and the
fallback recv"), where default-domain connections use the fallback one-shot
receive (#274). Whether a segment reader holds fewer copied bytes overall
than `with_bytes` depends on the response size and the connection count, and
is measured in landing step 5 before the client crates switch. Step 5
records fallback receives and `ENOBUFS` parks for both readers.

## Metrics

New counters in `RECV_RING`:

- Views created, and view buffer holds released. Created minus released is
  the views alive plus the releases not applied: those still queued, and
  those dropped or ignored. It is an upper bound on the buffers held by
  views.
- Releases sent through the inbox, from another thread or by a later worker
  on the same thread.
- Releases dropped after the worker exited.
- Values copied by `copy_small_view` (`THRESHOLD_COPIED`).
- Entries copied at the hold cap (`HOLD_CAP_COPIED`).
- Bytes copied in the receive path (`BYTES_COPIED`), on both backends.

The bytes-copied counter is incremented where bytes are copied into receive
storage:

- `append` and the `unfreeze` merge, including the existing bytes copied
  when either reallocates;
- both copies in `prepend`, and `AccumulatorTable::reclaim`'s copy;
- a copy into an `Owned` entry (a refused lend, a fallback receive
  completion, a lend copied by `arm_forward_source`, a TLS plaintext chunk),
  except the accumulator moved in on entry;
- TLS plaintext the unbuffered engine stashes when the send path decrypts
  it;
- `copy_small_view`.

The hold-cap copy is counted through `append` and `reclaim`. TLS ciphertext
staging is not counted; it is the same for both readers.

The 2026-10-08 decision asked for a count of buffers held by views. These
counters count views, and several views of one buffer count several times. A
per-buffer count needs a view count in `BufState`, and replaces the counters
if step 5 needs it.

## Tests

Each test below is written to fail on the regression it names. The mutations
that check the first five: no buffer hold at view creation and a release
never queued (first and second); the inbox never drained and the wake fd
never written (third); a view that does not keep the memory alive (fourth);
no memory id check (fifth). The ring memory's own test fails if the memory
is zeroed eagerly, which would make the whole ring resident at startup.

- A view kept past the callback keeps its buffer from being posted again;
  dropping it posts the buffer at the next flush.
- A buffer with two views (an incremental buffer shared by two completions,
  or two slices of one view) returns only after both drop.
- A view dropped on another thread releases its buffer hold and wakes a
  worker blocked in its wait.
- A view dropped after its worker exits frees nothing early and leaks
  nothing (the test holds a `Weak` of the `RingMemory`, which upgrades until
  the last view drops and fails after). Miri cannot set up an io_uring ring;
  a test of `RingMemory` and `RecvView` alone can run under it.
- A release queued by one worker is ignored by a later worker on the same
  thread.
- `NeedMore` keeps every entry held; a following arrival is presented as a
  further piece; no byte is copied (accumulator stays empty).
- `NeedAtLeast(n)` does not call the parser again until `n` more bytes are
  held.
- At the hold cap, a parser that reported `NeedAtLeast` is still called;
  complete messages in the hold are consumed without a copy; an incomplete
  parse copies the hold into the accumulator and parks, and the receive
  re-arms.
- A message whose completions are partly lent and partly refused (`Pinned`
  and `Owned` entries) parses in order and completes.
- `end_segments` with entries held, then `with_bytes`, sees the held bytes
  first.
- Partial consumption leaves the rest held at `off + k`.
- Close with entries held, and with views alive, releases every entry's
  buffer hold exactly once and leaves the views valid.
- On mio the slice has one piece and the bytes consumed match `with_bytes`,
  except at EOF with nothing buffered, where the parser is not called.
- On a TLS connection the pieces are the decrypted chunks, in order, and the
  hold-cap copy runs at the cap.
- Entering converts a pending lend into a `Pinned` entry at its offset with
  no copy.
- A stale handle resolves to `Ok(0)`; a live `SegmentReader` or a running
  forward gives `Err(EBUSY)`, on the first poll and on a later one, on both
  backends where they exist.
- In one task, a parked reader followed by a forward that runs to
  completion, a `SegmentReader` created and dropped, an `end_segments` call,
  a `with_segments` call and a `recv_owned_segment` call, one per test: the
  reader's next poll resolves to `Err(EBUSY)`, and a new call reads the next
  reply, including one that arrives in one completion. The same on mio with
  a forward.
- A reader that recorded `NeedAtLeast(n)`, then another reader consumes the
  bytes it was shown: the next poll resolves to `Err(EBUSY)` instead of
  waiting for `n` more bytes.
- `Consumed(k)` with `k` past the bytes presented consumes only the bytes
  presented.
- `end_segments` on mio returns `Ok(())`.
- On io_uring, `recv_arrival` after a `Consumed(k)` call over several
  pieces, and after one that follows a hold-cap copy, reports the arrival
  of the first and last consumed byte. On mio it reports what `with_bytes`
  reports for the same bytes. On both backends it is `None` after a call
  that resolved to `Err(EBUSY)`.
- On io_uring, a parser called with only the accumulator (after a
  hold-cap copy, with nothing arrived since) that calls `offer_for_park`
  has its offer declined; the test fails without `ReaderCallback::enter`.
- A connection with a view alive and nothing held can be parked.
- Client crates: a value inside one piece is a view; a value across pieces
  is owned; a view below the threshold is copied by the helper.

## Landing

1. View machinery: `RingMemory`, `RecvView`, `Orphan::RecvView`, the inbox
   release, the memory id check, and the view counters. No public API; tests
   create views through a crate-private constructor. `Bytes::from_owner`
   needs `bytes` 1.9; ringline takes `bytes` from the workspace (1.11.1),
   and the CHANGELOG names that floor.
2. The reader:
   - `with_bytes_segments` on both backends, with the `NeedAtLeast` skip and
     the `segment_epoch` and `recv_consumed` checks;
   - the `Pinned` conversion in `enter_segmented_domain`, which also changes
     `segments` and `recv_owned_segment`;
   - the hold-cap copy, its counter, and the `AccumulatorTable` reclaim
     method;
   - the segment term of `at_hold_cap` split into its own `Driver` method;
   - the bytes-copied counter;
   - `end_segments` on mio;
   - arrival reporting, with `with_bytes_segments` added to the list of
     reporting readers in `Connection::recv_arrival` and in
     `docs/recv-arrival-times-design.md`;
   - rustdoc: `ParseResult::NeedAtLeast`, the `RecvHalf` note that mio has
     no segmented domain, `with_bytes_segments` in `RecvHalf`'s list of
     methods whose futures carry no borrow, the list of nine recv entry
     points in the rustdoc that begins "Take this connection's exclusive
     recv half" (`runtime/io.rs`), `with_bytes_segments` in
     `ConnCtx::offer_for_park`'s list of reader callbacks and in its list
     of callbacks during which the runtime does not hold the request's
     bytes, the `READER_CALLBACK_CONN` comment, and the
     `SEGMENT_STRANDED_ADOPTED` comments in `runtime/io.rs` and
     `metrics.rs`;
   - the parser run under `ReaderCallback::enter`.
3. `recv_zc_threshold`, its helper and metric.
4. Release resp-proto and memcache-proto with `parse_segments`, and move
   ringline's workspace requirements and `Cargo.lock` on main to those
   releases. memcache-proto 0.0.6 has `parse_segments`, and the lock pins it.
   The lock pins resp-proto 0.0.2, which does not, and resp-proto's
   unreleased main also rewrites the parser `with_bytes` uses.
5. Measure two builds that differ only in the client read path: main after
   step 4, and a branch from it where ringline-redis and ringline-memcache
   read with `with_bytes_segments`, `parse_segments` and the helper. The
   branch is the change step 6 merges.
   - Hosts and kernels: hv01, and hv01 to hv02; Linux 6.1, 6.12 and 7.1.
   - Rings: default, and incremental on 6.12 and 7.1 (6.1 has no incremental
     rings).
   - Loads: a RESP GET load and a memcache text-protocol GET load, at value
     sizes 64 B, 4 KiB, 64 KiB and 1 MiB, 64 to 10,000 connections,
     pipelined and not.
   - Recorded: throughput; p50, p99 and p999 at fixed offered load; RSS;
     bytes received; bytes copied (the bytes-copied counter, plus, in the
     benchmark client, the bytes of each parsed value that is neither a view
     nor a slice of a presented piece, which the parser copied); `ENOBUFS`;
     `ENOBUFS` parks; fallback receives; lends refused; entries copied at
     the hold cap; views created per response.
   - Five reps per cell, with an A/A pair.
6. Switch ringline-redis (`read_value_from`) and ringline-memcache
   (`read_reply`, shared by every response read and by `BinaryClient`
   through `self.binary`; step 6 keeps the binary branch on `with_bytes`)
   to `with_bytes_segments`, with the helper, if no cell of step 5 is worse
   beyond its A/A spread. memcache-proto has no binary-protocol
   `parse_segments`, so `BinaryClient`
   (`ClientBuilder::build_binary`) keeps reading with `with_bytes` and never
   enters the segmented domain. ringline-memcache's `read_reply` returns
   `Consumed(0)` when a response is incomplete and gains a length hint.
   ringline-redis's `bulk_remainder_hint` reads only a `$` reply in one
   contiguous slice, and is changed to read a header split across pieces.
   Without a hint each arrival re-parses and re-creates a view for every
   held entry, up to the hold cap. The receive copy counts in
   `docs/syscalls-and-copies.md` and in CLAUDE.md ("Copy Semantics") change
   in the same PR.

## Decisions

The owner accepted these on 2026-10-15.

- The reader runs in the segmented domain, so it reuses the hold queue, the
  hold cap, the hold-cap throttle and the teardown drain. It also gives up
  the fallback receive (see "Ring pressure"). The alternative is a queue of
  lends in the default domain, which would change every site that reads
  `pending_recv_bufs`: `with_data`, `with_data_result`, `with_bytes`,
  `with_segments`, `enter_segmented_domain`, `arm_forward_source`,
  `forward_recv_buf`, `ConnStream`, `handle_recv_multi`,
  the starved drain in `flush_replenish_and_rearm`,
  `install_accepted_with_pending`, `handle_connect`, `handle_close`, and
  `Driver::recv_buffered` (through it `holds_unread` and the arrival log).
  Both remove the copy into the accumulator.
- The name is `with_bytes_segments`. It is to `with_segments` what
  `with_bytes` is to `with_data`, and the proto crates name the parser
  `parse_segments`. `std::io::Read::read_vectored`, `Write::write_vectored`
  and tokio's `AsyncWrite::poll_write_vectored` transfer bytes between an
  I/O object and caller-supplied buffers in one call (one `readv` or
  `writev` on a socket). This reader hands the parser buffers the runtime
  already holds, so a `vectored` name would suggest a `readv`.
- A refused lend copies the completion and the connection keeps receiving,
  as in the other segmented readers; no new throttle (see "Lend refusals").
- The client crates switch only on step 5's measurement.
- The view counters count views; the per-buffer count the 2026-10-08
  decision asked for waits on step 5 (see "Metrics").
- A parked reader resolves to `Err(EBUSY)` when another reader used the
  connection since its last poll (`segment_epoch`), instead of re-entering
  the segmented domain. Re-entering would take the connection back from a
  reader the caller had switched to, and would leave a recorded
  `NeedAtLeast(n)` counting bytes another reader consumed.

## Not measured

- Nothing in this design has been measured. The `recv-strategies` benchmark
  (`docs/journal/2026-09-incremental-buffer-consumption.md`, "2026-10:
  kernels, two rings, tiered caches") cut RSS from 2.3 GiB to 262 MiB with a
  bounded accumulator that parses each completion's remainder in place, in
  the completion handler; ringline parses in the connection's task.
- How many buffers a segmented-domain client holds at once against the
  default domain, at any connection count.
- The cost of the cross-thread release path.
