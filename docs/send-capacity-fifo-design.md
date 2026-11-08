# Executor send-capacity FIFO (series PR 5)

Superseded by `docs/send-completion-slots-design.md`: `SendCapacityQueue`
became the waiting half of `SendCompletions`
(`ringline/src/runtime/send_completion.rs`), and `runtime/send_capacity.rs`
does not exist. The admission rule below survives there (`turn` admits the
head only when `free_slots >= required_slots`).

Fifth PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 5"). Design origin:
@thinkingfish in #318; re-derived on current `main`. No callers land here;
PRs 6, 7 and 9 consume it.

## Purpose

`ConnCtx::send_backpressured` (PR 9) needs a per-worker admission queue:
a bounded send waits until it is the oldest waiter *and* the copied-send
pool can admit its whole message, then reserves, copies once (PR 4's
`reserve_slots`), submits, and later collects the exact result of that one
operation. The queue is worker-local state and lives in the `Executor`,
next to the other per-connection waiter bookkeeping.

## Departures from #318's version

- **Executor-owned, no `Rc<RefCell<_>>`.** #318 shared the queue between
  the executor and a `SendCapacityRegistration` guard so the guard's `Drop`
  could unregister without driver access. All other futures in this crate
  clean up through `try_with_state` and accept that a drop outside the
  executor skips cleanup; the queue's `remove_connection` is the backstop
  for the one case that matters (teardown drops the connection task outside
  a poll). Same pattern, no shared ownership.
- **No per-operation `HashMap`.** Waiting entries are a `VecDeque`;
  submitted entries are a `Vec` scanned linearly (in-flight bounded sends
  per worker are bounded by pool slots). Allocation only on growth.
- **Capacity is part of `turn`.** Each waiter records `required_slots`;
  `turn(id, free_slots)` is true only when the id is the head *and*
  `free_slots >= required_slots`. The driver's slot-release hook (PR 6/7)
  calls `wake_send_capacity(free_slots)`, which wakes the head only when it
  can now fit. #318's head was woken on every release and retried a failing
  reservation.
- **Wakes are immediate, by task id.** The queue stores the owning task id
  (refreshed on every poll, as `SendFuture` refreshes `owner_task`) and the
  executor calls `wake_task` directly; no deferred `pending_wakes` list.
  Between a completion and the next poll no poll runs, so resolving the
  owner at push time is equivalent to resolving it at drain time.

## API (`ringline/src/runtime/send_capacity.rs`, new module)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct BoundedSendId(u64);          // monotonic per worker, never reused

pub(crate) struct SendCapacityQueue {
    waiting: VecDeque<Waiter>,                  // FIFO; head is the only one that may admit
    submitted: Vec<Submitted>,                  // committed, awaiting a completion
    next_id: u64,
}
struct Waiter    { id, conn_index: u32, generation: u32, required_slots: usize, task_id: u32 }
struct Submitted { id, conn_index: u32, task_id: u32, state: Completion }
enum Completion  { InFlight, Done(io::Result<u32>), Aborted(io::Error), Abandoned }

impl SendCapacityQueue {
    fn enqueue(&mut self, conn_index, generation, required_slots, task_id) -> BoundedSendId;
    fn set_owner(&mut self, id, task_id);                       // waiting or submitted
    fn turn(&self, id, free_slots) -> bool;
    fn mark_submitted(&mut self, id) -> Option<u32 /*next head's task*/>;
    fn complete(&mut self, id, result) -> Option<u32 /*owner to wake*/>;
    fn take_result(&mut self, id) -> Option<io::Result<u32>>;   // removes the entry
    fn cancel(&mut self, id) -> Option<u32 /*next head's task*/>;
    fn head_ready(&self, free_slots) -> Option<u32 /*head's task*/>;
    fn remove_connection(&mut self, conn_index) -> impl Iterator<Item = u32 /*tasks to wake*/>;
    fn remove_task(&mut self, conn_index) -> impl Iterator<Item = u32 /*next head's task*/>;
    fn fail_waiting(&mut self, conn_index, generation, kind: io::ErrorKind, msg) -> ...;
}
```

Semantics:

- `enqueue` appends; ids come from `next_id` (a `u64` cannot wrap in
  practice; `checked_add` + `expect` as in #318).
- `mark_submitted` moves the entry from `waiting` to `submitted`
  (`InFlight`). If it was the head, returns the new head's task id so the
  caller can wake it (it will re-check `turn`).
- `complete(id, result)`: `InFlight` → `Done(result)`, returns the owner;
  `Aborted` → also `Done(result)`, returns the owner (the driver's outcome
  is authoritative — see the abort rule below); `Done` → ignored, so between
  two *driver* results for one id the first wins; `Abandoned` → entry
  removed, result discarded (the future is gone); unknown id → ignored (a
  stale completion after `remove_connection`).
- `take_result(id)`: `Done` or `Aborted` → removes and returns; anything
  else `None`. `Aborted` must resolve too, or a send whose connection really
  was torn down before the driver reported would park forever.
- `cancel(id)` (future dropped): waiting → removed, and if it was the head
  the next head's task is returned for waking; `InFlight` → `Abandoned`
  (the driver still owns the operation; its completion is dropped on
  arrival); `Done` or `Aborted` → removed.
- `head_ready(free_slots)` → the head's task if `free_slots >=
  head.required_slots`. `wake_send_capacity` is this plus `wake_task`.
- `remove_connection(conn)`: for every waiting and in-flight entry of the
  connection, if the owner is a task that outlives the connection (a
  standalone task, or another connection's task) the entry becomes
  `Aborted(ConnectionAborted)` (moved to `submitted` if it was waiting) and
  the owner is returned for waking. `Aborted` and not `Done` because this
  abort is **provisional** (series departure 4): a driver result arriving
  after the abort overwrites it, so a delivered message is never reported
  as aborted. `Executor::remove_connection` runs when the backend releases
  the slot (io_uring `handle_close`, mio `drain_pending_closes`), after the
  queued sends drained. If the owner is the connection's
  own task (`task_id == conn_index`) nobody is left to read a result:
  `task_slab.remove` has already dropped that future. Those entries are
  cancelled instead:
  waiting removed, `InFlight` → `Abandoned` (the completion removes it),
  `Done` removed — so a closed connection never leaves a `Done` entry
  behind. Abandoned entries are removed. If the head was removed, the new
  head's task is also returned. Called from `Executor::remove_connection`
  after `task_slab.remove`.
- `remove_task(conn)`: the connection task `conn` returned or panicked
  while its connection is still closing. Only the entries that task owns
  are touched, on whichever connection: waiting removed, `InFlight` →
  `Abandoned` (the completion removes it, unless a poll of a future the
  task had handed to another task revives it; see `set_owner`), `Done` or
  `Aborted` removed. Entries other tasks own on the connection are left
  for the driver, which delivers or fails each queued send before the
  slot is released and `remove_connection` runs. If the head was removed,
  the new head's task is returned. Called from
  `Executor::remove_connection_task`, the task-exit arms of both backends'
  `poll_ready_tasks`.
- `fail_waiting(conn, generation, kind, msg)`: waiting entries for that
  connection generation become `Done(Err(kind))` — final, not the
  provisional `Aborted`, since they were never submitted and no driver
  result is coming — and their owners are returned for waking, plus the new head's task if the head was among them;
  in-flight ones are left alone. PR 9's `shutdown_write` uses it with
  `BrokenPipe`. `remove_connection` and `fail_waiting` return a `Vec<u32>`
  (teardown/shutdown paths; the allocation is acceptable there).

`Executor` gains `send_capacity: SendCapacityQueue` and thin wrappers that
call `wake_task` on whatever the queue returns:
`enqueue_send_capacity`, `set_bounded_send_owner`, `send_capacity_turn`,
`mark_bounded_send_submitted`, `complete_bounded_send`,
`take_bounded_send_result`, `cancel_bounded_send`, `wake_send_capacity`,
`fail_waiting_bounded_sends`; `Executor::remove_connection_task` calls
`remove_task` and wakes what it returns; `Executor::remove_connection` calls the
queue's `remove_connection`.

Dead code: nothing outside tests calls the wrappers until PRs 6–9, and the
`runtime` module is not under the mio `allow(dead_code)` blanket, so the new
module carries `#![cfg_attr(not(test), allow(dead_code))]` with a comment
naming the PRs that remove it (PR 9 deletes the attribute).

## Tests (`send_capacity.rs`, both backends)

Queue-level, no driver (plus
`remove_connection_drops_entries_owned_by_the_dead_connection_task` for the
own-task rule above, and `send_capacity_wrappers_wake_through_wake_task` so
every wrapper has a test caller under `cfg(test)`, where the dead-code
allowance is off):

- `fifo_admits_only_the_head_and_only_with_capacity`: two waiters (3 and 1
  slots); `turn(second, 8)` false; `turn(first, 2)` false; `turn(first, 3)`
  true.
- `mark_submitted_promotes_and_reports_the_next_head`.
- `cancel_at_head_promotes_next_but_cancel_behind_head_wakes_nobody`.
- `abandoned_operation_discards_its_late_completion`: enqueue, submit,
  cancel → `Abandoned`; `complete` returns no owner and removes the entry;
  `take_result` is `None`.
- `take_result_returns_exactly_once`.
- `a_real_result_overwrites_a_teardown_abort_but_not_another_result`: the
  provisional-abort rule, and that two driver results are still first-wins.
- `a_teardown_abort_nothing_overwrites_still_resolves`: the other half —
  an `Aborted` no driver result reaches is handed to the future.
- `cancelling_an_aborted_entry_drops_it_and_its_late_result`.
- `remove_connection_fails_waiting_and_in_flight_and_wakes_unrelated_head`:
  conn A head waiting, conn A in flight, conn B waiting behind; remove A →
  both A entries `Done(Err(ConnectionAborted))` with owners returned, B is
  head and returned; A's abandoned entry (if any) removed.
- `fail_waiting_leaves_in_flight_alone_and_uses_the_given_kind`.
- `head_ready_respects_required_slots`.
- `set_owner_redirects_the_wake`.

Executor-level (existing `mod tests` in `runtime/mod.rs`):

- `remove_connection_wakes_bounded_send_owner_on_a_standalone_task`: a
  standalone task id owns an in-flight entry; `remove_connection` marks
  the task ready (`wake_task` returned true).
- `complete_bounded_send_wakes_the_refreshed_owner`.

## Verification

fmt, clippy `-D warnings` on default and `force-mio`, `cargo test -p
ringline` on the Mac; the module is backend-independent, so one VM job on
delta for clippy on the io_uring build (the dead-code attribute is what it
checks) before the PR opens. No changelog line (no observable change).
