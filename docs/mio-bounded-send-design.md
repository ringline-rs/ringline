# mio completion identity and bounded-send path (series PR 6)

Note: identifiers in this document are those of the PR it describes;
`docs/send-completion-slots-design.md` "What goes away" lists the renames
since. Code: `ringline/src/runtime/send_completion.rs`.

Sixth PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 6"). Design origin:
@thinkingfish in #318; re-derived on current `main` on top of PR 4
(`reserve_slots`) and PR 5 (`SendCapacityQueue`). No public API yet; PR 9
adds the future. mio first because it is testable on the development
machine and simpler than the io_uring CQE paths (PR 7).

## What a bounded send is on mio

mio sends are `Vec`-backed: `DriverCtx::send` copies into a `Vec<u8>` and
queues it on `pending_sends[idx]`; `flush_sends` writes with `writev` when
the socket is writable. There is no per-connection SQE queue and no pool
slot per send. In fact **`SendCopyPool` is never used at all on mio**: the
driver allocates one per worker and hands it to `DriverCtx`, but every
caller (`SendBuilder`, `SendChainBuilder`, the UDP send paths) is
`#[cfg(has_io_uring)]` and nothing under `backend/mio/` touches it.

For `send_backpressured` the pool is therefore the *admission budget* and
nothing else: a bounded send reserves `ceil(len / slot_size)` slots with
PR 4's `reserve_slots` and holds that reservation as an unfilled permit
until its last byte reaches the socket, then releases it. The data still
goes through a `Vec` (one copy, like every mio send); no byte is ever
written into pool memory on this backend.

The permit is the `SlotReservation` itself, kept unfilled. Its `Drop`
debug-assert guarantees a permit is never silently dropped: every path that
discards a `PendingSend` must release it explicitly.

**Decision (owner, 2026-09-12): gate mio admission on the pool, accepting
that the counter maps to no real mio resource.** The point of
`send_backpressured` is a single documented rule — "waits until one whole
message can be admitted" — and the same knob (`Config::send_pool`) tuning
it on both backends. Two alternatives were considered and rejected:

- *Cap bounded bytes queued in `pending_sends`* (sized from
  `send_pool_count * slot_size`). This tracks what mio actually consumes,
  heap plus socket backlog, but introduces a second admission mechanism and
  two rounding rules — io_uring admits in whole slots, this would admit in
  bytes — so the same call could be admitted on one backend and parked on
  the other at the same occupancy.
- *No admission cap on mio at all*, resolving only when the bytes reach the
  socket. Simplest and honest about the absent pool, but it makes the API's
  backpressure guarantee backend-dependent and lets a fast producer grow
  `pending_sends` without bound — precisely the hazard the API exists to
  prevent.

The cost of the chosen option is that on mio `send_pool` becomes a knob
whose *memory* is unused while its *count* throttles bounded sends. PR 9's
documentation must say so plainly, and the mio-side allocation being dead
weight is worth a separate follow-up (it is pre-existing, not introduced
here).

## Changes

### `PendingSend` becomes a struct (`backend/mio/driver.rs`)

```rust
pub(crate) struct PendingSend {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
    /// `Some(len)` for `send().await` entries: `wake_send(Ok(len))` when the
    /// last byte reaches the socket (unchanged behaviour).
    pub(crate) notify_len: Option<u32>,
    /// A `send_backpressured` entry: exact completion routed by id, and the
    /// pool permit released with it.
    pub(crate) bounded: Option<(BoundedSendId, SlotReservation)>,
}
impl PendingSend { fn plain(data) -> Self; fn awaited(data) -> Self; fn bounded(data, id, permit) -> Self; }
```
All tuple sites (`handler.rs` mio `send`, TLS ciphertext push, the
awaitable-send push in `runtime/io.rs`, `flush_sends`) move to the struct;
the compiler finds them.

### Driver: `bounded_send_completions`, `clear_pending_sends`

- New field `bounded_send_completions: VecDeque<(BoundedSendId, io::Result<u32>)>`,
  exposed on the mio `DriverCtx` like `send_completions`.
- `flush_sends`: when an entry's last byte is written, a bounded entry
  pushes `(id, Ok(data.len()))` and releases its permit; the
  `iovecs.is_empty()` bail-out goes through `clear_pending_sends` instead of
  `clear()` so it cannot drop permits or ids.
- `clear_pending_sends(idx, err: impl Fn() -> io::Error)`: drains the
  queue, releases every permit, and pushes `(id, Err(err()))` for every
  bounded entry — the one place a queued bounded send can be discarded.
  Callers: `finish_close` (`ConnectionAborted`), the accept-time slot reuse
  in `mio/event_loop.rs` (defensive, `ConnectionAborted`), and
  `fail_connection_on_send_error` (the real write error, cloned per id:
  `clone_io_error` keeps the raw OS errno). Plain `pending_sends[idx].clear()`
  is removed everywhere.
- `DriverCtx::send_bounded(conn, data, id) -> io::Result<()>` (mio):
  generation and `close_submitted`-equivalent checks as `send`;
  `reserve_slots(needed)` → `Exhausted` = `Other("send copy pool
  exhausted")`, `TooLarge` = `InvalidInput` (same messages as io_uring);
  TLS connections encrypt as `send` does and attach the id and permit to
  the ciphertext entry (the permit is sized by plaintext length; PR 8
  revisits TLS sizing); push, `mark_send_dirty`. Nothing is written
  synchronously; admission is the reservation.

### Event loop (`backend/mio/event_loop.rs`)

- `drain_send_completions` first drains `bounded_send_completions` into
  `executor.complete_bounded_send(id, result)`, counting those towards its
  `delivered` flag so a future woken by one is re-polled in the same call,
  then runs the existing `send_completions` pass.
- A flag `capacity_released: bool` on the driver is set wherever a permit is
  returned, and `wake_capacity_if_released` calls
  `executor.wake_send_capacity(driver.send_copy_pool.free_count())` once per
  iteration. **It runs as the last step of the run loop, not inside
  `drain_send_completions`** (an earlier draft of this design said the
  latter). Permits come back at many points — a writable flush, either
  `flush_all_pending_sends`, an accept-time slot reuse, a write error, a
  task's own send, and `finish_close` inside `drain_pending_closes` — and
  only the end of the loop covers all of them. In particular
  `drain_pending_closes` runs *after* the final `drain_send_completions`, so
  waking from inside the drain would leave a teardown's released permits
  unsignalled until the next iteration's drain, which only runs after a
  `poll` that may block on the timer deadline: a parked head could stall.
  Waking last also means `free_count()` is the iteration's final figure.
  Nothing is lost by waking late, since `poll_ready_tasks` has already run
  and a task woken from that point on is polled next iteration either way.
- `fail_connection_on_send_error` uses `clear_pending_sends` with the real
  error, then `wake_send`/`wake_recv`/`close_connection` as today.
- Departure 4 ("a real completion overwrites the synthetic abort") is
  **required**. An earlier version of this section claimed the loop order
  `flush_all_pending_sends` → `drain_send_completions` →
  `drain_pending_closes` made it moot. That analysis checked only
  `drain_pending_closes`, which is one of `Executor::remove_connection`'s
  three callers. The other two are in `poll_ready_tasks` — a connection task
  that returns `Poll::Ready`, and one that panics — and `poll_ready_tasks`
  is step 6, *before* step 6a's flush. So a bounded send owned by a task
  that outlives connection X (a standalone task, or another connection's
  task) is aborted when X's own task returns, and the flush that follows in
  the same iteration still writes every byte to the socket: without the
  overwrite rule the caller of a fully delivered message is told
  `ConnectionAborted`. `SendCapacityQueue` therefore records teardown's
  abort as `Completion::Aborted`, which `complete` overwrites with the
  driver's result and `take_result` resolves if no driver result ever
  arrives. "First result wins" holds only between two driver results.
  `bounded_completion_is_delivered_before_teardown` covers the
  `drain_pending_closes` route,
  `bounded_send_owned_by_another_task_survives_its_connection_task_returning`
  the `poll_ready_tasks` one.

### Executor

No changes; PR 5's wrappers are the consumers' API. The dead-code
allowance stays until PR 9 (io_uring still has no callers).

### Two decisions made during implementation

**`Driver::drop` is a sixth disposal path and releases permits.** Worker
shutdown drops the driver with whatever is still queued. A `PendingSend`
holding a permit would hit `SlotReservation`'s `Drop` debug-assert, so the
existing `impl Drop for Driver` gains a pass that drains `pending_sends` and
returns each permit. No completions are pushed: the executor is going away
with the driver, and there is nobody left to read a result.

**`send_bounded` does not refuse once a close is merely *pending*.** The
`close_submitted` check is implemented so the two backends' entry points
cannot drift, but it is inert on mio — only the io_uring close path sets that
flag. mio's `close_pending` means "teardown requested, deferred until queued
sends drain", and plain mio `send` happily queues behind it, so a bounded send
queuing behind it too is the consistent behaviour and the send still reaches
the socket before `drain_pending_closes` finalizes. Making mio refuse on
`close_pending` would be a change to the close path's contract, not to this
feature, and belongs with the close-lifecycle work if it is ever wanted.

## Tests

Tests are `#[cfg(test)]` unit tests in `backend/mio/driver.rs` that build a
`Driver` around a real `TcpStream` pair, plus a small event-loop module in
`backend/mio/event_loop.rs` for the cases that also need an `Executor`
(it reuses the driver module's `attach_conn` / `token`), plus integration
tests in `ringline/tests/echo.rs` gated `#[cfg(not(has_io_uring))]` where a
handler is needed. `send_bounded` has no public caller yet, so the tests
call it through `make_ctx()`.

A queued bounded entry's permit is disposed of at seven places:
`Driver::clear_pending_sends` (from `finish_close`, from the accept-time
slot reuse in `drain_channels`, and from `fail_connection_on_send_error`),
`DriverCtx::clear_pending_sends` (the connect-time slot reuse),
`flush_sends`' completion, `flush_sends`' empty-iovec bail-out, and
`Driver::drop`. Every one has a test that fails if it is reverted to a bare
`pending_sends[idx].clear()` — checked by reverting each in turn. That
matters because `SlotReservation`'s drop assert only fires on a path some
test actually walks, so an unexercised site is unprotected, not protected.

Driver-level:
- `send_bounded_reserves_a_permit_and_queues_without_writing`: pool(4,
  64), 200-byte send → `free_count == 0`, one queued entry with `bounded`
  set, nothing on the socket yet.
- `flush_completes_bounded_entry_and_releases_permit`: flush → peer reads
  200 bytes, `bounded_send_completions == [(id, Ok(200))]`, `free_count ==
  4`.
- `partial_write_keeps_permit_and_id`: tiny `SO_SNDBUF`, peer not reading;
  flush returns `(false, n)`; permit still held; a later flush after the
  peer drains completes it exactly once.
- `send_bounded_refuses_without_side_effects`: three slots held by
  another bounded send; `send_bounded` needing 2 → `Err(Other)`, queue and
  `free_count` unchanged; 5-slot send → `InvalidInput`.
- `clear_pending_sends_fans_out_and_releases`: two bounded + one plain
  queued; clear with `ConnectionAborted` → two `Err` completions in queue
  order, `free_count` restored, queue empty.
- `finish_close_fails_a_send_left_queued_by_a_gone_socket`: the socket is
  already gone, so teardown's opening flush writes nothing and the clear is
  what disposes of the entry.
- `connect_time_slot_reuse_fails_a_stale_bounded_send`: a bounded send is
  queued, the slot is released with the queue still populated, and
  `DriverCtx::start_connect` reuses it (LIFO free list) → the stranded id gets
  `ConnectionAborted` ("reused by a new connect") and its permit back.
- `empty_iovec_bailout_fails_the_bounded_entry_it_discards`: a zero-length
  bounded entry built by hand (only kind that reaches the bail-out;
  `send_bounded` settles those itself) → flush returns `(true, 0)`, the id
  is failed and the permit returned.

Event-loop level (these need an `Executor` too):- `bounded_completion_is_delivered_before_teardown` (event-loop order,
  departure 4, `drain_pending_closes` route): queue a bounded send, request
  close, run one loop iteration's `flush_all_pending_sends` +
  `drain_send_completions` + `drain_pending_closes` by hand; the executor
  sees `Done(Ok(len))` and the slot is released, not `ConnectionAborted`.
- `bounded_send_owned_by_another_task_survives_its_connection_task_returning`
  (departure 4, `poll_ready_tasks` route): a standalone task owns the
  bounded send; the connection's own task returns `Poll::Ready`, so
  `poll_ready_tasks` tears the connection down *before* the flush. The
  owner must still see `Ok(len)`, which only the provisional-abort rule
  delivers.
- `accept_time_slot_reuse_fails_a_stale_bounded_send`: same shape as the
  connect-time test, through `drain_channels`' accept path with a real
  accepted fd on the channel.
- `write_error_fails_queued_bounded_sends_with_the_real_error`: peer closed
  with RST; `flush_all_pending_sends` hits the write error and routes it
  through the real `fail_connection_on_send_error`, which fails every queued
  bounded id with the same `raw_os_error` and returns the permits. It drives
  the helper rather than re-implementing its body, so reverting the helper's
  clear fails it.
- `capacity_head_is_woken_once_per_iteration_when_permits_return`: two
  bounded sends complete in one flush; `wake_send_capacity` is called once.
  Counted through `Executor::send_capacity_wakes` (a `cfg(test)` counter),
  because `ready_queue.len()` cannot tell one wake from two — `wake_task`
  pushes only on a Parked → Ready transition. The test also shows the
  counter moving on a genuine second release.

Integration (`tests/echo.rs`, mio-gated): none needed beyond the driver
tests until PR 9 has a future to drive end to end.

## Verification

fmt, clippy `-D warnings` default + `force-mio`, `cargo test -p ringline`
on the Mac (this PR is mio code; the Mac is the authority). One VM job on
delta for the io_uring build's clippy (the shared `PendingSend` and
handler.rs edits must not break it). No changelog line.
