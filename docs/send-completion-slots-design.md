# Send completion slots

Every awaited send owns an entry in a per-worker completion table. The
driver settles that entry when the send it names completes, and the
send's future resolves from it. This replaces the per-connection send
waiter (`Executor::send_waiters`, the `IoResult::Send` slot in
`io_results`, and `wake_send`).

Issue: #617.

## Why the per-connection waiter does not work

A connection has one send waiter. Any send completion on the connection
wakes it, whichever send completed. On io_uring an awaited `send()` queued
behind a `send_nowait()` resolves with the `send_nowait`'s byte count, and
the awaited send's own completion then finds no waiter. The same happens
behind an unawaited chain, a direct echo, a `forward_recv_buf`, or a
bounded send. Two awaited sends in flight at once on one connection share
the waiter, so only one of them is woken.

Bounded sends (`send_backpressured`) do not have this problem. Each one
has a `SendId` stored on the resource its completion releases, and the
completion settles exactly that operation. This design extends that
mechanism to every awaited send.

## The table

`runtime::send_completion::SendCompletions`, owned by the `Executor`.

- A `SendId` is a slot index and a generation, 32 bits each. A slot's
  generation advances each time the slot is freed, so a stale id never
  matches a reused slot.
- Each live slot holds the target connection index, the owning task id,
  and a state:

| State | Meaning |
|---|---|
| `Waiting` | A bounded send waiting for admission (in the capacity FIFO). |
| `InFlight` | Submitted; the driver owns the operation. |
| `Done(result)` | The driver reported. Waits for the future to take it. |
| `Aborted(err)` | Teardown recorded this before the driver reported. A driver result overwrites it. |
| `Abandoned` | The future was dropped while the operation was in flight. The driver's completion frees the slot; nothing else leaves this state. |

Lookups are by index, so `register`, `complete`, `take_result`,
`set_owner` and the cancel of an admitted operation are O(1);
`mark_submitted` and the cancel of a waiting one search the FIFO. Each
entry is also listed under its target connection and, when a connection
task owns it, under that task, so `remove_connection` visits only the
entries it can affect.

The state rules: a driver result wins over a teardown abort, the first
driver result wins over a second, and teardown drops the entries owned by
the connection's own task (its future is gone and nothing can take them).
A submission that fails withdraws its entry (`withdraw`), since no
completion will free it.

The bounded-send FIFO (`SendCompletions::waiting`) keeps only admission
order: the ids of waiting operations. Their required slots, owner and
state live in the table.

## What carries the id

The id is stored on the resource whose completion ends the logical send,
together with the length the send reports on success.

| Send | Carrier |
|---|---|
| `send`, `send_backpressured`, copy-only batch (io_uring) | Final pool slot (`SendCopyPool`), lifted onto the coalesced slab entry when the run is coalesced |
| TLS send (io_uring) | The final ciphertext chunk's pool slot (`OpTag::Send`), lifted onto the coalesced slab entry when the run is coalesced |
| Zero-copy batch (io_uring) | The `SendMsgZc` slab entry, or the pool slot the batch folded into below `send_zc_threshold` |
| `forward_to_conn` chunk (io_uring) | Not in the table; `DirectForward` settles its own future |
| `send_chain` (io_uring) | The chain's `ChainState`; on a TLS connection, the final ciphertext chunk's pool slot, lifted onto the coalesced slab entry when the run is coalesced |
| Any awaited send (mio) | The last `PendingSend` the call queued |

Sends nothing awaits (`send_nowait`, `send_chain_nowait`,
`forward_recv_buf`, TLS handshake and alert records) carry no id, and
their completions settle nothing.

## The reported length

A send settles with the length its caller passed: the plaintext length
under TLS, and the sum of the parts for a batch. A chain settles with the
bytes its operations' CQEs reported; on a TLS connection, with its plaintext
length, as a TLS send does.

## Failure

- The in-flight operation fails: its id settles with the errno
  (`WriteZero` for a zero-byte completion of a copy or zero-copy send).
- A chain fails: its id settles with the first error, or `WriteZero` if it
  sent fewer bytes than it holds, and the connection closes.
- A failure or close drains the connection's queue: every id on
  a drained entry settles `ConnectionAborted`.
- A completion, or a dropped retry, that arrives after `close_submitted`:
  its id settles `ECANCELED`.
- A completion for a connection slot that has since been reused settles
  nothing (teardown already recorded the abort); it frees an `Abandoned`
  entry (`forget`).
- Connection teardown: `Executor::remove_connection` records a provisional
  `Aborted(ConnectionAborted)` for every waiting or in-flight entry on that
  connection and keeps a resolved one for the future that holds it.
- Worker shutdown: the table is dropped with the executor.

An entry leaves the table through its future, never through its owner's
task. The future's `Drop` cancels it, and a connection task is dropped with
the driver state installed, in its task-exit arm and at its connection's
release (`with_driver_state`), so the futures that die with it cancel their
entries first. An entry a dead task still owns is held by a future the task
handed to another task that has not polled it yet: `remove_task` (at the
task's exit) and `remove_connection` (at the release) re-own it to
`NO_OWNER`, a wake target no task answers to, and leave its state alone;
that task's first poll records itself as the owner (`set_owner`) and takes
the result if one has landed.

Every disposal path that releases a carrier must take its id first. The
copy pool's `release` debug-asserts that the slot no longer carries one.
The slab entry's `release` clears the id without a check, and
`ChainState` has none.

## The futures

`SendFuture` holds either a `SendId` or a result known at submission (a
`send_chain` whose closure submitted nothing resolves `Ok(0)` without a
send). Polling takes the result or records the polling task as the owner.
Dropping it cancels the id: the entry becomes `Abandoned`, and the send
itself continues. A future handed to another task resolves there with the
send's own result, however late that task first polls it: after the
creating task returned, after the send completed, and after the connection
was released.

Two awaited sends on one connection each resolve with their own result.

## What goes away

- `Executor::send_waiters`, `IoResult::Send`, `Executor::wake_send`.
- `ConnSendState::acked_bytes` (the carried length replaces the
  accumulated wire count).
- mio's `PendingSend::notify_len`, `send_completions` and
  `DriverCtx::mark_last_send_awaited`.
- The `bounded_` prefix: `BoundedSendId` becomes `SendId`, and
  `take_bounded_send` / `set_bounded_send` / `bounded_send_completions`
  become `take_send_id` / `set_send_id` / `settled_sends`.

## Landing

1. The table. `SendCompletions` replaces `SendCapacityQueue`; waiting and
   admitted operations both hold a slot, and `BoundedSendId` becomes
   `SendId`. No behaviour change.
2. Awaited sends. Every awaited API takes a `SendId`, every carrier
   carries one, and the per-connection send waiter is removed, on both
   backends. Fixes #617.
