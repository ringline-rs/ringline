# Transactional copied sends: pool reservation and SQ-pressure parking (series PR 4)

Note: identifiers in this document are those of the PR it describes;
`docs/send-completion-slots-design.md` "What goes away" lists the renames
since. Code: `ringline/src/runtime/send_completion.rs`.

Fourth PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 4"). Design origin:
@thinkingfish in #318; re-derived on current `main`.

## Problem

`DriverCtx::send` on io_uring (`ringline/src/handler.rs`) splits data larger
than one send-pool slot into `data.chunks(slot_size)` and, per chunk, calls
`SendCopyPool::copy_in` and then `submit_or_queue`. When the pool runs out on
chunk *k*, chunks 1..k-1 are already queued (or on the wire) and the caller
gets `Err("send copy pool exhausted")`. The method's own doc says so and tells
callers to treat the error as fatal for the connection, because a retry would
duplicate the prefix. `ConnCtx::send` / `send_nowait` document only "Err if
the pool is exhausted or the SQ is full", so a handler that retries after an
error — the natural reaction to a pool-pressure error — silently corrupts the
stream for any send wider than one slot. A send wider than the *whole* pool
can never succeed and today fails only after committing the first
`slot_count` chunks (the 4 MiB-on-64-slots incident during PR 1).

The other multi-slot producers are already transactional:

- TLS, both engines (`tls/backend_uring.rs`, `tls/buffered.rs`): stage slots,
  `release_all` on failure, drain into the send vector only on success.
- `send_parts` / `send_chain` copy parts: one `copy_in_gather` slot, or an
  atomic chain push.
- mio `DriverCtx::send`: one `Vec<u8>` per logical send.

That leaves two holes, and this PR closes both.

**Hole 1 — pool admission.** The plaintext path above: pool exhaustion on
chunk *k* commits chunks 1..k-1.

**Hole 2 — submission-queue pressure on an already-admitted send.** A copied
send is committed once its first SQE is accepted; its remaining chunks wait in
the per-connection `send_queues[ci].queue` and are pushed one CQE at a time by
`submit_next_queued` (`backend/uring/driver.rs`). When that push fails because
the SQ is still full after `submit()`, both branches (coalesced run and single
entry) release the entry, release every queued send behind it, set
`in_flight = false`, put the write half back to `Open` and return. Nobody is
woken and nothing is closed: the prefix is on the wire, the tail and any
pipelined sends behind it are gone, the `SendFuture` waiting on the
end-of-send chunk never resolves, and a `send_nowait` caller never learns.
The same condition on the *first* entry (`submit_or_queue` with an idle
queue) returns `Err` to `DriverCtx::send`; for plaintext that is harmless
after Hole 1 is fixed, but for TLS the ciphertext was already produced, so
rustls' record sequence has advanced and every later record fails
`bad_record_mac` at the peer. Three callers discard that `Err` with
`let _ =` (handshake responses and alerts in `handle_recv`, the TLS flush,
and `send_close_notify_queued`), so a handshake reply or close_notify can
be dropped silently under SQ pressure.

The codebase already has the right model for this condition next door:
`handle_send`'s partial-write resubmit and the `Close` SQE both treat a full
SQ as backpressure — the op is parked on `pending_copy_retries` /
`pending_close_retries` and re-pushed on the next loop iteration; copy
retries give up after two attempts by failing the waiter and closing the
connection "so it isn't left open with a hole in its byte stream" (#830
removed the cap). mio never
fails a send on submission at all (queue, then write when writable). Queued
sends are the odd one out.

No per-send heap allocation is added anywhere (series departure 3).

## Design

### Pool: count-based reservation

`SendCopyPool` gains a `reserved: usize` counter and a token type:

```rust
#[must_use = "an unfilled reservation must go back through release_reservation"]
pub struct SlotReservation { remaining: usize }

pub enum ReserveError {
    /// Fewer than `needed` slots are free right now (retryable).
    Exhausted,
    /// `needed` exceeds the pool's total slot count (never retryable).
    TooLarge { needed: usize, capacity: usize },
}

impl SendCopyPool {
    /// Promise `n` slots to the caller without popping them. Fails without
    /// side effects (other than the SEND_EXHAUSTED metric on `Exhausted`).
    pub fn reserve_slots(&mut self, n: usize) -> Result<SlotReservation, ReserveError>;

    /// Pop one promised slot and copy `data` into it. `data.len()` must be
    /// <= slot_size and the reservation must have slots remaining (both
    /// `debug_assert`ed; the caller iterates `chunks(slot_size)` over a
    /// buffer whose chunk count it reserved).
    pub fn copy_in_reserved(&mut self, r: &mut SlotReservation, data: &[u8]) -> (u16, *const u8, u32);

    /// Return the unfilled remainder of a reservation to the pool.
    pub fn release_reservation(&mut self, r: SlotReservation);

    /// Slots available to a new allocation: free_list.len() - reserved.
    pub fn free_count(&self) -> usize;   // was #[cfg(test)]
    /// Total slots.
    pub fn slot_count(&self) -> usize;
}
```

- `reserve_slots(n)`: `n > count` → `TooLarge`; `n > free_count()` →
  `Exhausted` (+ metric); else `reserved += n`, `Ok(SlotReservation { remaining: n })`.
  `n == 0` succeeds with an empty reservation (empty sends stay a no-op).
- `copy_in_reserved`: pops `free_list` (guaranteed non-empty by the
  accounting), fills exactly as `copy_in` does, `reserved -= 1`,
  `r.remaining -= 1`.
- `release_reservation`: `reserved -= r.remaining`.
- `copy_in`, `copy_in_gather`, `alloc_raw` take a slot only when
  `free_count() > 0`, so an outstanding reservation is honoured even if a
  future caller interleaves an allocation. Today nothing does: the reservation
  lives inside one synchronous `DriverCtx::send` call, and `push_sqe`'s
  internal `ring.submit()` cannot run completions (no `GETEVENTS`).
- `SlotReservation` has a `Drop` with `debug_assert_eq!(remaining, 0)`. It
  cannot release without the pool, so misuse is caught in debug/test builds
  rather than silently shrinking the pool.
- `free_count` and `slot_count` become `pub(crate)`-visible (the `buffer`
  module is `pub(crate)`) with no `cfg(test)`. Both have production callers
  in this PR (`reserve_slots` uses both), so no dead-code lint on either
  backend; PR 5's admission FIFO is their next consumer.

### io_uring `DriverCtx::send`

The plaintext branch becomes:

```rust
let slot_size = self.send_copy_pool.slot_size() as usize;
let needed = data.len().div_ceil(slot_size);
let mut reservation = match self.send_copy_pool.reserve_slots(needed) {
    Ok(r) => r,
    Err(ReserveError::Exhausted) => return Err(io::Error::other("send copy pool exhausted")),
    Err(ReserveError::TooLarge { needed, capacity }) => return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("send of {} bytes needs {needed} send-pool slots but the pool has {capacity} \
                 (raise Config::send_pool)", data.len()),
    )),
};
let mut chunks = data.chunks(slot_size).peekable();
while let Some(chunk) = chunks.next() {
    let (slot, ptr, len) = self.send_copy_pool.copy_in_reserved(&mut reservation, chunk);
    self.send_copy_pool.set_end_of_send(slot, chunks.peek().is_none());
    // ... build the SQE exactly as today ...
    self.submit_or_queue(conn.index, built); // infallible: parks under SQ pressure
}
self.send_copy_pool.release_reservation(reservation); // remaining == 0
Ok(())
```

(An earlier draft kept a release-on-error arm after `submit_or_queue`; once
parking made `submit_or_queue` infallible that arm became unreachable and was
removed.)

(Superseded for sends of two or more slots: their chunks are queued
together and submitted as one run, `DriverCtx::submit_queued_run`. The
conclusion below still holds: queueing cannot fail, and a push that finds
the SQ full parks the run, or its head, instead of failing. The paragraph's
"releasing that slot" predates parking.)

Why this is transactional: `submit_or_queue` pushes to the ring only when
the connection has no send in flight, i.e. only for chunk 1; once chunk 1 is
accepted, `in_flight` is set and every later chunk is queued, which cannot
fail. So the only failure after reservation is a full SQ on chunk 1, which
`submit_or_queue` already handles by releasing that slot before returning —
nothing has been transmitted or queued, and the remaining reservation is
returned. The error kind stays `Other` (series departure 1).

The error message strings are unchanged for the `Exhausted` case so existing
tests and the documented `send_nowait` contract keep matching.

### Send queue: SQ pressure parks the entry, never drops it

A `BuiltSend` that cannot be pushed stays at the head of its connection's
queue with `in_flight = true`, and the connection is registered for a retry
on the next loop iteration. Concretely:

- `submit_or_queue` (first entry, idle queue): on `push_sqe` failure, push
  the entry to the (empty) queue, set `in_flight = true`, register the
  connection, return `Ok(())`. It no longer returns an error for SQ
  pressure; its only remaining error is none (the pool checks happen in the
  callers). `queue_built_sends`' "release the rest on error" arm becomes
  unreachable and is removed; its three `let _ =` callers are changed to
  plain calls.
- `submit_next_queued`: entries are popped only after a successful push.
  The coalesced path releases just the slab entry on failure and falls into
  the parking path; the single path parks without popping. Both register
  the connection. The function's contract becomes "returns true if an SQE
  was pushed; if it returns false with a non-empty queue the connection is
  parked, `in_flight` stays true". `write = Open` is no longer reset here.
- New driver field `pending_send_retries: Vec<(u32, u32, u8)>` (conn index,
  generation, attempts) plus a `send_retry_scratch` swap buffer, mirroring
  `pending_copy_retries`. A new `drain_send_retries` runs where
  `drain_copy_retries` runs. Per entry: skip if the slot is gone or the
  generation changed or `close_submitted` (the queue is released by the
  close path); otherwise call `submit_next_queued`; on success done, on
  failure re-register with `attempts + 1`; at `attempts >= 2` give up
  exactly as `drain_copy_retries` does — `drain_conn_send_queue`,
  `wake_send(Err(io::Error::other("max retries during send submit")))`,
  `wake_recv`, `close_connection`. The cap and message shape are shared
  with the existing copy-retry path so the two failure modes read the same
  in logs. (#830 removed the cap and the attempt count from both: an entry
  is retried every iteration until the ring takes it.)
- A parked connection satisfies `in_flight` for the close-deferral
  machinery (`try_finalize_close` waits for `!in_flight && queue.is_empty()`),
  so a close requested while parked waits for the parked send to go out or
  for the retry cap to convert it into a terminal error. The existing
  close-notify deadline still bounds that wait. (#830 removed the cap. The
  close deadline is armed only by `DriverCtx::close` on a TLS connection
  (the fatal-encrypt close) and for a connection whose handshake or connect
  has not completed. An application close of an established connection,
  plaintext or TLS, behind a parked send now has no deadline: it waits
  until the ring takes the send.)

After this, `DriverCtx::send` on io_uring can fail only before it has
committed anything: stale token, or pool admission (Hole 1, now reserved
up front). Its `# Errors` sections drop "or the submission queue is full".
TLS pool exhaustion *during* encryption (`encrypt_to_sends` releases the
staged ciphertext but rustls has advanced) is closed on io_uring:
`encrypt_tls_send` admits against the ciphertext bound before encrypting. A
failure after rustls has sealed a record still fails the operation and
closes the connection.

**Series departure 1, refined.** Departure 1 says a full SQ is terminal so
that nothing parks and re-runs a logical send after rustls mutation. Parking
a *built* SQE and re-pushing the same bytes re-runs nothing; it is the model
the ring already uses for partial resubmits and Close. What stays terminal
is persistent starvation past the retry cap, and it is terminal for the
connection with the waiter failed, never a silent drop. The series doc's
departure 1 paragraph is updated to say this. (#830 removed the cap, so
nothing here is terminal any more.)

### Ring: `#[cfg(test)] force_push_failures(n)`

`Ring` gains `#[cfg(test)] forced_push_failures: usize`;
`push_sqe128` returns `io::Error::other("forced SQ push failure")` and
decrements while the counter is non-zero, before touching the real queue.
`push_sqe` routes through `push_sqe128`, so `submit_or_queue`,
`submit_next_queued` and every `submit_*` helper are covered;
`push_sqe_chain`'s multi-entry path is not (it uses `push_multiple`; the
chain builder is already transactional through its `Drop` release). The kind
is `Other`, not `WouldBlock` as in #318 (departure 1). The hook now has real
consumers: the parking tests below.

### Docs

- `DriverCtx::send` doc: replace the "chunks queued before it are already
  committed ... treat a mid-buffer error as fatal" paragraph with the new
  contract: on `Err` nothing was queued or transmitted; the same buffer may
  be resent later; SQ pressure is absorbed by the queue.
- `ConnCtx::send` and `send_nowait` "# Errors": pool exhaustion only, plus
  `InvalidInput` for a send wider than the whole pool; state the
  nothing-committed guarantee. Persistent SQ starvation surfaces as the
  `SendFuture` resolving `Err` and the connection closing, like a write
  error.
- `submit_or_queue` / `submit_next_queued` docs rewritten for the parking
  contract; `CLAUDE.md` Domain Invariant 7 gains "and a queued send that
  cannot be pushed is parked, not dropped".
- `docs/send-completion-design.md`: one paragraph under the copied-send
  section stating the reservation invariant (this is the required reading
  for the send path).
- CHANGELOG `Unreleased` / Fixed: one entry. The series doc said "no
  changelog line" for PR 4 on the assumption that only PR 9 would surface
  the change; the retry hazard above is observable today through the public
  `send`/`send_nowait` API, so it gets its own line, and the series doc's
  PR 4 paragraph is updated to say so.
- Journal `docs/journal/2026-09-backpressured-sends-series.md`: PR 4 entry.

## Tests

Pool unit tests (`buffer/send_copy.rs`, both backends):

- `reserve_then_fill_consumes_exactly_the_reserved_slots`: pool(4, 8);
  reserve 3; `free_count` == 1; fill three chunks; `free_count` == 1,
  `reserved` back to 0 (observable as `free_count` == `free_list.len()`
  after `release_reservation`).
- `reserve_fails_without_side_effects_when_short`: pool(2, 8); take one
  via `copy_in`; `reserve_slots(2)` → `Exhausted`; `free_count` == 1;
  `copy_in` still succeeds.
- `reserve_rejects_more_than_the_pool_holds`: pool(2, 8);
  `reserve_slots(3)` → `TooLarge { needed: 3, capacity: 2 }`; `free_count` == 2.
- `reservation_blocks_plain_allocation_until_released`: pool(2, 8);
  reserve 2; `copy_in` → `None`; `alloc_raw` → `None`; release; `copy_in`
  → `Some`.
- `partially_filled_reservation_releases_the_rest`: pool(3, 8); reserve 3;
  fill 1; release; `free_count` == 2.
- `zero_slot_reservation_is_a_no_op`.

io_uring event-loop tests (`backend/uring/event_loop.rs`, `cfg(has_io_uring)`,
run on Linux CI and the delta VM job), config `send_pool(4, 64)`:

- `send_wider_than_free_slots_commits_nothing`: `copy_in` three fillers;
  `make_ctx().send(token, &[0; 100])` (needs 2) → `Err` (kind `Other`);
  `free_count` == 1; send queue empty; `in_flight` false.
- `send_wider_than_the_pool_is_invalid_input`: `send(token, &[0; 300])` →
  `Err` kind `InvalidInput`; `free_count` == 4; nothing queued.
- (A forced first-push failure no longer makes `send` return `Err`; it
  parks. That case is `first_push_failure_parks_and_completes_next_iteration`
  below.)
- `multi_chunk_send_still_queues_all_chunks_in_order`: pool of 6 with one
  slot held; with an in-flight send, `send(token, &[0; 200])` queues 4
  entries whose `pool_slot`s carry `end_of_send` false,false,false,true and
  lengths 64,64,64,8, and `free_count` == 1 afterwards (the reservation was
  consumed, not left outstanding). Guards the streaming rewrite; passes on
  `main` by design.

Parking tests (same file, `send_pool(8, 64)`):

- `first_push_failure_parks_and_completes_next_iteration`:
  `force_push_failures(1)`; `send(token, b"hello")` → `Ok`; queue len 1,
  `in_flight` true, `pending_send_retries == [(conn, gen, 0)]`; run
  `drain_send_retries`; queue empty, retry list empty; drive the CQE
  (`submit_and_wait` + `drain_completions` as the existing loopback tests
  do); the peer socket reads exactly `hello` once.
- `queued_tail_push_failure_parks_without_dropping_the_queue`: with a send
  in flight, queue two chunks of one logical send plus one independent send;
  `force_push_failures(1)`; `submit_next_queued` → false; queue still has
  3 entries in order, `in_flight` true, pool free count unchanged;
  `drain_send_retries` pushes the head; the remaining two are intact.
- `coalesced_push_failure_releases_only_the_slab_entry`: three coalescable
  entries queued; `force_push_failures(1)`; `submit_next_queued` → false;
  slab free count restored, queue still 3, pool unchanged.
- `send_retry_cap_fails_the_waiter_and_closes`: `force_push_failures(3)`;
  send with a registered waiter; drain retries three times; the third gives
  up: `io_results[conn] == Err`, queue empty, pool free count restored,
  `close_requested()` true.
- `parked_send_defers_a_requested_close`: park a send, `close_connection`;
  `try_finalize_close` does not submit Close while parked; after the retry
  pushes it and its CQE lands, the close finalizes.
- `queue_built_sends_parks_under_sq_pressure`: two built sends through
  `queue_built_sends` with a forced first-push failure are both queued in
  order, parked, and registered once. This is the path the TLS handshake
  flight, alerts and close_notify take; there is no TLS harness in the
  event-loop test module, so a TLS-level test of the same behaviour is not
  included here (recorded as a follow-up in the journal).
- `parked` idempotency: `drain_send_retries` acts only while
  `ConnSendState::parked` is set, so a retry entry that outlives its park
  cannot push a second SQE alongside one already in flight.

Integration (`ringline/tests/echo.rs`, both backends, small pool): a handler
that sends a response wider than the free pool, gets `Err`, waits one tick,
retries, and the client receives exactly one copy of the response. On mio
this passes today (Vec-backed) and pins the contract; on io_uring it fails
before this PR (duplicate prefix) — verified red-then-green on the VM.

## Verification

- `cargo fmt`, clippy `-D warnings` default + `force-mio` (+ `tls-unbuffered`
  compile check), `cargo test --all` both backends on the Mac.
- io_uring: one-guest VM job on delta (`uring-*-job.json` template: clone
  under `$HOME`, clippy + tests, `clippy_exit=`/`test_exit=` markers) before
  the PR opens; adversarial subagent review of the diff against Domain
  Invariants 1–5 and this document; CI green before merge.

## Out of scope

- Bounded-send identity (`slot_bounded_send_id` in #318) — PR 6/7.
- TLS pre-mutation bound — PR 8.
- A `WouldBlock` push error that re-runs a logical send from the task —
  rejected by series departure 1. Driver-level parking of a built SQE is
  in scope (above) and is a different thing.
- TLS pool exhaustion mid-encryption (rustls advanced, pool refused) — PR 8.
- `push_sqe_chain` failure injection; the chain builder is already
  transactional via `Drop`.
- `handle_send`'s other SQ-full sites (POLLOUT re-arm, ZC notification
  paths) keep their existing retry lists; not touched.
