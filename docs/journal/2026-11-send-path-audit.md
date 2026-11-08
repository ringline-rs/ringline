# 2026-11: Audit of the send path

- **Status:** open — 14 findings recorded; F1 to F4 fixed, the rest in progress in the owner's order (F5, F7, F13, then the docs findings F9, F12, F14)
- **Span:** 2026-11-07 → · tree 6ea67e6c (`main`) · PRs: F1 #773, F2 #775, F3 #777, F4 this PR

## Goal

Audit the stream send path, from a public `send*` call to the released pool
slot or slab entry, on both backends, against a written list of invariants.
No diff was under review; the question was whether the code as it stands
holds what its docs, comments and tests say it holds. Four questions:
correctness against the invariants; concurrency and ordering (SQE order,
stale completions, slot reuse, loop step order); error paths, partial
failure, close and worker exit; whether the docs state current behaviour.

Method (`cs:audit`): scope and invariants written first and agreed with the
owner; a map of entry points and state; five fresh read-only reviewer
agents, one per concern, in parallel; every finding re-checked by the
auditor by reading the quoted path, and run on macOS where the mio backend
allows it. The io_uring path cannot be compiled on the development host, so
every io_uring finding is a trace, not a run; each finding's status line
says which.

The close path was audited four commits earlier on the same day
([2026-11-connection-close-audit.md](2026-11-connection-close-audit.md)).
Findings that record already holds (its F7, F11, F12, F13, F14, L4, L6) are
cited there, not repeated here.

## Scope

### Boundary

Stream sends on TCP and Unix connections, both backends, from the public call
to the released resource. In scope:

Public entry points (`ringline/src/runtime/io.rs`):
- `SendHalf` / `Connection`: `send`, `send_nowait`, `send_parts`
  (`AsyncSendBuilder::build`, `submit_batch`, `submit_batch_await`),
  `send_backpressured`, `send_chain`, `send_chain_nowait`,
  `forward_recv_buf`, `shutdown_write`, `close` (only where it waits on
  sends).
- `RecvHalf::forward_to_conn` on io_uring (`DirectForward`, sends on the
  sink) and on mio (`forward_push` into the sink's queue).
- `ConnStream::poll_write` / `poll_close` (`runtime/stream.rs`).
- Futures: `SendFuture`, `BackpressuredSendFuture`, `ForwardFuture`.

Internal (shared): `handler.rs` (`ConnSendState`, `DriverCtx::send_inner`,
`send_bounded`, `encrypt_tls_send`, `attach_send_id`, `queue_built_sends`,
`submit_or_queue`, `submit_queued_run`, `close`, `shutdown_write`,
`SendBuilder`, `SendChainBuilder`, `ChainPartsBuilder`, `bounded_send_slots`);
`buffer/send_copy.rs`; `buffer/send_slab.rs`; `runtime/send_completion.rs`
and `Executor::remove_connection`; `chain.rs`; `completion.rs` (send tags,
`send_payload`); `guard.rs`.

Internal (io_uring): `backend/uring/driver.rs` (`close_connection`,
`try_finalize_close`, `submit_committed_close`, `force_finalize_close`,
`submit_next_queued[_inner]`, `submit_or_queue_send`,
`close_connection_graceful`, `queue_tls_close_notify`,
`drain_conn_send_queue`, `release_queued_sends`, `fail_send_ids`,
`reset_send_state`, `run_shutdown` and its `release_*_at_shutdown`,
`submit_coalesced_run`); `backend/uring/event_loop.rs` (`run` loop order,
`handle_send`, `handle_tls_send`, `handle_send_msg_coalesced`,
`handle_send_msg_zc`, `wait_for_room`, `arm_send_poll`,
`resubmit_waiting_send`, `fail_waiting_send`, `handle_send_pollout`,
`handle_send_backstop`, `fire_chain_complete`, `handle_close`,
`handle_shutdown`, `settle_send`, `drain_settled_sends`,
`wake_capacity_if_released`, the six retry drains,
`check_close_notify_deadlines`, the task-exit and panic arms of
`poll_ready_tasks`); `backend/uring/ring.rs` (`push_sqe`, `push_sqe_chain`,
`submit_send_*`, `submit_drain_send_fixed`, `submit_tls_send`,
`submit_close` + `CloseLead`, `submit_shutdown`, `submit_send_pollout`,
`submit_cancel_send_pollout`); `backend/uring/sqe.rs` send constructors;
`backend/uring/engine/uring.rs` `push`, `push_pair`, `push_chain`.

Internal (mio): `backend/mio/driver.rs` (`PendingSend`,
`clear_pending_sends[_into]`, `close_connection`, `finish_close`,
`flush_sends`, `forward_push`, `mark_send_dirty`, `Drop for Driver`);
`backend/mio/event_loop.rs` (`run` loop order, `handle_writable`,
`fail_connection_on_send_error`, `flush_all_pending_sends`,
`drain_send_completions`, `drain_pending_closes`, accept-time
`clear_pending_sends`, task-exit and panic arms of `poll_ready_tasks`).

TLS send side: `tls/backend_uring.rs` (`ciphertext_to_sends`,
`encrypt_to_sends`, `flush_tls_output`), `tls/backend_mio.rs`
(`encrypt_for_send_mio`, `flush_tls_output_mio_*`), `tls/mod.rs`
(`CiphertextCapacity`, `TlsTable::ciphertext_capacity`,
`send_close_notify_queued`, `build_pool_send`), `tls/unbuffered/mod.rs`
(`encrypt_chunk`, `encrypt_to_vec`, `queue_close_notify`), `tls/buffered.rs`
(`PoolWriter`, `encrypt_to_sends_buffered`, `take_tls_output_sends`,
`encrypt_for_send_mio_buffered`).

Docs under test: CLAUDE.md "Domain Invariants" 1, 2, 4, 5, 7, 8, 9 and the
"Send path" copy table; `docs/send-completion-design.md`,
`send-completion-slots-design.md`, `copied-send-reservation-design.md`,
`send-capacity-fifo-design.md`, `uring-bounded-send-design.md`,
`mio-bounded-send-design.md`, `tls-premutation-bound-design.md`,
`half-closed-send-wait-design.md`, `write-half-design.md`,
`backpressured-sends-series-design.md`; `docs/syscalls-and-copies.md` send
rows; the public doc comments on the entry points above.

### Out of scope

UDP sends (`send_to`, GSO, `udp_send_to`, `handle_send_msg_udp`); the recv
path except where it feeds a forward; park and adopt except where a park
meets an in-flight send; the acceptor; disk I/O; QUIC and the protocol
client crates (they call these APIs; their own buffering is theirs).

### Question

All four concerns: correctness against the invariants below; concurrency
and ordering (SQE ordering, stale CQEs, slot reuse, loop step order);
error paths, partial failure, close and worker exit; docs against code.

### State the subsystem owns

Per worker: `SendCopyPool` (slots, `reserved` count, `slot_send_id`),
`InFlightSendSlab` (entries, `held` per connection), `SendChainTable`,
`SendCompletions` (slots by `SendId`, `waiting` FIFO, `by_conn`, `by_task`),
`Driver::settled_sends`, `capacity_released`, the retry lists
(`pending_send_retries`, `pending_copy_retries`, `pending_zc_retries`,
`pending_coalesced_retries`, `pending_send_pollout_retries`,
`pending_close_retries`), `send_backstop_list`, `pending_finalize_closes`,
`close_notify_armed`. Per connection: `ConnSendState` (`in_flight`,
`queue`, `parked`, `close_pending`, `close_submitted`, `shutdown_inflight`,
`waiting_send`, `send_poll`, `pollout_seen`, `resubmitted_on_pollout`,
`on_send_backstop`, `close_notify_deadline`), `ConnectionState::write`,
`ConnectionState::lifecycle`. mio: `pending_sends[idx]`, `sends_dirty`,
`writable`, `pending_closes`. Nothing persists across a restart.

## Invariants

Each is a checkable statement. Source: D = a design doc or CLAUDE.md,
C = a code comment, T = an existing test, I = inferred by me from the code
and not written down anywhere I found.

### Resource lifetime

- S1 (D: CLAUDE.md DI-1). Memory an SQE references stays valid until its
  CQE, and for `SendMsgZc` until its notification CQE. A pool slot is
  released only by the handler of its CQE, or by a teardown path that knows
  no SQE was submitted for it; a slab entry only once
  `pending_notifs == 0 && awaiting_notifications`; guards drop only at slab
  release or `leak_in_flight`.
- S2 (I). Every pool slot and slab entry a send path takes is released
  exactly once on every exit: success CQE, error CQE, stale CQE,
  pre-submission error, teardown (`drain_conn_send_queue`,
  `force_finalize_close`, `reset_send_state`, `run_shutdown`), retry-list
  give-up, builder `Drop`. No double release reaches the pool.
- S3 (C: `SendCopyPool::release`). A pool slot never carries a `SendId` when
  released; every disposal path takes the id first and settles or forgets
  it.
- S4 (D: copied-send-reservation). `free_count = free_list.len() - reserved`;
  `copy_in`, `copy_in_gather`, `alloc_raw` never take a reserved slot; a
  reservation is filled or returned in full; on io_uring no reservation
  outlives the synchronous call that took it; on mio a permit is released
  exactly once (flush completion, `clear_pending_sends`, `Driver::drop`).
- S5 (D: half-closed-send-wait, #607). At worker exit no memory the kernel
  may still read is freed: an unreleased slab entry's guards and the pool
  backing are leaked after the bound.

### Ordering

- O1 (D: DI-2; C: `submit_or_queue`). A connection has at most one stream
  send operation in the kernel at a time, except the linked SQEs of one
  active chain. A non-empty queue implies `in_flight`. A send made while a
  chain is active is queued behind it; a chain is refused while sends are
  queued, in flight, parked or waiting.
- O2 (D). Bytes reach the wire in call order per connection: the queue is
  FIFO, a coalesced run keeps queue order, a short send's remainder goes
  out before the next queued entry, TLS records never interleave or gap.
- O3 (D: departure 1). A parked send (SQ full) stays at its queue head with
  `in_flight = true` and is re-pushed with the same bytes; nothing re-runs
  encryption or re-copies.
- O4 (D: write-half). The FIN of `shutdown_write` goes out only after every
  send queued or in flight at the time of the call has completed.
- O5 (D: send-completion, #518). The `Close` SQE is submitted only when
  `!in_flight`, the queue is empty, no chain is active and no `Shutdown`
  SQE is outstanding; after `close_submitted` no new send SQE, resubmit or
  poll is pushed for that slot.

### Completion identity

- C1 (D: send-completion-slots). Every awaited send resolves exactly once,
  with its own result: `Ok(logical length)` or `Err`, never another send's
  result, never a truncated count, and never silence. This covers a send
  queued behind one that fails, one drained at teardown, one parked past
  the retry cap, one on a connection the peer closed, and one whose
  connection slot was reused. At worker exit a lost result is accepted.
- C2 (D: DI-3). A CQE whose generation does not match touches only the
  resources it names and settles nothing; a reused slot starts with no send
  state from its previous occupant (`reset_send_state`, mio accept-time
  clear).
- C3 (D: departure 4). A driver result overrides a provisional teardown
  `Aborted`; between two driver results the first wins; an `Abandoned`
  entry is freed by its completion; every registered `SendId` is eventually
  removed from `SendCompletions` (no table growth from closed connections).
- C4 (D: send-capacity-fifo). The admission FIFO admits only its head, and
  only when `free_count >= required_slots`; `required_slots` is computed by
  `bounded_send_slots` on both sides; the head never has an owner that
  cannot be woken; a capacity wake runs at least once in any loop iteration
  in which a slot or permit was released.

### Transactionality

- T1 (D: copied-send-reservation, departure 1). On `Err` from `send`,
  `send_nowait`, `send_backpressured`'s submit, `submit_batch` or
  `submit_batch_await`, nothing was queued or transmitted and the same
  buffer may be resent. On a TLS connection admission is decided against
  the ciphertext bound before rustls mutates; a failure after rustls has
  sealed a record fails the operation and closes the connection, on both
  backends.
- T2 (D). A send wider than the whole pool is refused with `InvalidInput`
  before anything is taken; a pool shortfall is `Other` and retryable.
- T3 (D: tls-premutation-bound). The ciphertext bound is never beaten
  (`debug_assert` tripwires); a bounded TLS send on an unbuffered connection
  whose slot cannot hold one worst-case record is refused up front.

### Waiting for room

- W1 (D: half-closed-send-wait). Every stream send except a chain part
  carries `MSG_DONTWAIT`; a short result or `-EAGAIN` waits in ringline on a
  `SendPollOut`, never on an io-wq thread; one poll per connection; a poll
  that completes without `POLLOUT` moves to multishot; the backstop timer
  resubmits every waiting send about once a second; the wait ends at close
  (poll cancelled, waiting send failed by the poll CQE or `handle_close`).
- W2 (D). A waiting send has nothing in the kernel: at exit it is released
  directly, and a forced close fails it without waiting.
- W3 (D: #642, #734). `-ENOMEM` on a `SendMsgZc` sends the rest of the entry
  as plain sends, at most one `-ENOMEM` per send; inside a chain it fails
  the chain and closes.

### Failure and teardown

- F1 (D, C). A terminal send error fails the connection one way: on
  io_uring a plaintext error drains the queue (queued ids settle
  `ConnectionAborted`) and a TLS chunk or TLS run error also closes; a
  failed chain closes; on mio a write error fails every queued id with the
  real error and closes.
- F2 (D: DI-7). Each retry list gives up after two failed attempts by
  failing the send and closing the connection, never by dropping it; an
  entry for a closed, reused or `close_submitted` connection releases its
  resources and pushes nothing.
- F3 (D: #607, #753). At worker exit: waiting sends are released first,
  every connection is closed with the `CancelAll` lead, slab entries are
  awaited for at most 10 s, a connection still holding entries after 1 s
  is closed with `SO_LINGER {on, 0}` where the kernel allows it.
- F4 (D: mio-close-lifecycle). mio finalizes a close only once
  `pending_sends` is empty, the stream is gone, or a write error cleared
  the queue; `Driver::drop` returns every permit.

### Docs against code

- X1. CLAUDE.md Domain Invariants 1, 2, 4, 5, 7, 8, 9 and the send copy
  table describe the code on `main`.
- X2. The design docs listed under Scope describe current behaviour, or
  mark what they describe as superseded.
- X3. The public doc comments on `SendHalf`'s send methods, `SendFuture`,
  `BackpressuredSendFuture`, `AsyncSendBuilder`, `SendChainBuilder` and
  `ChainPartsBuilder` state current behaviour and error kinds.
- X4. The open follow-ups the journal lists against the send path are
  either closed by later code or still open: `ConnCtx::send(&[])` hanging;
  chains bypassing the queue; the mio TLS bounded send reporting two
  different lengths.

## Map

### Entry to queue (io_uring)

`SendHalf::send` -> `ConnCtx::send` -> `Executor::register_send` (a `SendId`
owned by `CURRENT_TASK_ID`) -> `DriverCtx::send_awaited` ->
`send_inner`: generation check, `close_submitted` refusal; TLS branch
`encrypt_tls_send` (bound check, `encrypt_to_sends` allocates slots with
`alloc_raw`, final chunk tagged `OpTag::Send`, others `TlsSend`; failure
closes via `DriverCtx::close`) then `attach_send_id` on the last `BuiltSend`
and `queue_built_sends`; plaintext branch `reserve_slots(ceil(len/slot))`,
`copy_in_reserved` per chunk, id on the last slot, one chunk ->
`submit_or_queue`, several -> queue then `submit_queued_run`. `send_nowait`
is the same with no id. `submit_batch[_await]` -> `SendBuilder`: TLS gathers
into a `Vec` and goes through `encrypt_tls_send`; copy-only ->
`copy_in_gather` one slot; guards below `send_zc_threshold` -> gather fold;
otherwise `build_with_guards` -> slab `allocate` + `SendMsgZc`; `commit` ->
`attach_send_id` + `submit_or_queue`. `send_chain` -> `SendChainBuilder`:
plaintext parts become `chain_send` / `chain_send_msg_zc` SQEs
(`MSG_WAITALL`), `finish` refuses stale, `close_submitted`, and `WouldBlock`
while anything is queued/in flight/parked, then `push_sqe_chain` (atomic in
the engine) and `chain_table.start`; TLS parts are gathered and encrypted
as one send. `send_backpressured` -> future: first poll checks generation,
write half, close_notify, `bounded_send_slots`, enqueues; `poll_waiting`
calls `send_bounded` when `turn`; `send_bounded` mirrors `send_inner` with
a capacity check before encrypting. `forward_recv_buf` of the whole
accumulator -> `send_parts().guard(AccumulatorGuard)`; `forward_to_conn`
-> `DirectForward` registers an id on the sink and submits a guard send per
chunk. `ConnStream::poll_write` -> `send_nowait` capped at one slot.

Queue mechanics: `submit_or_queue` pushes if `!in_flight && !chain_active`,
else queues and sets `in_flight`; a push failure parks (`parked`,
`pending_send_retries`). `submit_queued_run` / `submit_next_queued_inner`
first try `submit_coalesced_run` (a run of >= 2 consecutive pool-slot
entries, up to 32, into one `SendMsgCoalesced` slab entry; ids lifted off
the slots onto the entry with byte offsets; `restore` puts them back on a
push failure or a full slab), else push the head alone. An empty queue
clears `in_flight`, submits a pending `Shutdown`, and calls
`try_finalize_close`.

### Completion (io_uring)

`drain_completions` -> `dispatch_cqe`. `handle_send` (`OpTag::Send`):
in-use guard, 16-bit generation guard (`forget_send` + release), chain path
(claims every Send CQE while a chain is active), `result > 0`: partial ->
`wait_for_room` unless `close_submitted`; full -> take id, release,
`submit_next_queued`, `note_send_finalized`, settle `Ok(logical_len)`;
`-EAGAIN` -> `wait_for_room`; other error -> release, drain queue, settle
`Err`. `handle_tls_send` is the same minus settle on success and plus
`close_connection` on error. `handle_send_msg_coalesced`: same shape on a
slab entry; a partial write settles the sends `take_sent_sends` covers;
`close_on_error` closes for TLS runs. `handle_send_msg_zc`: notification
accounting via `IORING_CQE_F_MORE`, chain path, `-EAGAIN` wait, `-ENOMEM`
-> `set_plain_send` + `submit_slab_drain`, partial -> wait, else settle and
`mark_awaiting_notifications`; `submit_next_queued` on `result >= 0`,
drain on error. `fire_chain_complete`: `chain.failure()` -> drain + close,
else `submit_next_queued`; settles the chain's id; `note_send_finalized`.

Waiting: `wait_for_room` stores the send's user_data in `waiting_send`,
registers on `send_backstop_list`, resubmits at once if `pollout_seen`,
else arms a one-shot or multishot `SendPollOut`. `handle_send_pollout`:
stale by generation; error or `close_submitted` -> `fail_waiting_send`
through the send's own handler with the errno; `POLLOUT` (or `POLLERR |
POLLHUP` on multishot) -> `resubmit_waiting_send`; no `POLLOUT` and poll
ended -> arm the other kind. `handle_send_backstop` resubmits every waiting
send once a second. `resubmit_waiting_send` falls back to the per-kind
retry list when the SQ is full.

Close: `close_connection` (peer FIN, read error, send error, task exit via
`close_connection_graceful`, which queues close_notify when `write ==
Open`) sets `Closing` and `close_pending`; starts the drain if the queue is
non-empty and nothing is in flight; otherwise defers to
`pending_finalize_closes`. `try_finalize_close` checks O5, sets
`close_submitted`, `submit_committed_close` (cancel the `SendPollOut`,
then `Close` with the kernel's `CloseLead`); a failed push goes to
`pending_close_retries`. `force_finalize_close` (TLS close_notify deadline,
armed only by `DriverCtx::close`, which only the encrypt-failure paths
call) releases the queue and cancels the chain first. `handle_close` fails
a still-waiting send, `release_tls_state`, `Executor::remove_connection`
(drops the task; `SendCompletions::remove_connection`), releases the slot.
`reset_send_state` runs at slot reactivation and releases anything still
queued. `run_shutdown` as F3.

Loop order (per iteration): wait -> `drain_completions` -> retry drains ->
`check_close_notify_deadlines` -> `poll_ready_tasks` -> flush ->
`drain_completions` -> fast-path poll -> `on_tick` -> park -> drain
`pending_finalize_closes` -> `drain_settled_sends` ->
`wake_capacity_if_released`.

### mio

`send_inner`: generation check only (no `close_submitted` on mio); TLS ->
`encrypt_for_send_mio` into a `Vec` (an `Err` does not close the
connection); `PendingSend::{plain, awaited}` pushed on `pending_sends[idx]`,
`mark_send_dirty`. `send_bounded`: `bounded_send_slots`, `reserve_slots` as
the permit, TLS encrypt then `shrink_reservation`, `PendingSend::bounded`.
`flush_sends`: `writev` of up to 1024 iovecs, pops completed entries
(release permit, push `(id, Ok(len))` on `settled_sends`), `WouldBlock`
re-dirties, `Err` returned to `fail_connection_on_send_error`
(`clear_pending_sends` with the real error, `wake_recv`,
`close_connection`); after a full drain a `ShutdownPending` write half
issues `shutdown(Write)`. Loop: poll -> readable/writable handlers ->
channels -> `poll_ready_tasks` -> `flush_all_pending_sends` ->
`drain_send_completions` (re-polls woken tasks) -> forward resumes ->
`drain_pending_closes` (finalize when `pending_sends` empty or stream gone:
`Executor::remove_connection` then `finish_close`, which flushes once,
writes close_notify best-effort, deregisters, `clear_pending_sends`
`ConnectionAborted`) -> `on_tick` -> flush, completions, closes again ->
`wake_capacity_if_released`.

### Shared

`SendCompletions`: slots by index + generation; `register` (InFlight),
`enqueue` (Waiting), `set_owner`, `withdraw`, `forget`, `turn`,
`mark_submitted`, `complete` (InFlight/Aborted -> Done, Abandoned ->
removed, Done/Waiting ignored), `take_result` (Done/Aborted -> removed),
`cancel`, `head_ready`, `remove_connection` (dead target or dead
connection-task owner: Waiting/InFlight -> Aborted unless owner gone, then
removed/Abandoned), `fail_waiting`. `Executor::remove_connection` callers:
io_uring `handle_close` and the two `poll_ready_tasks` arms; mio
`drain_pending_closes` and the two `poll_ready_tasks` arms.

### Tests that reach this

io_uring unit tests in `backend/uring/event_loop.rs` (`cfg(has_io_uring)`,
Linux only; about 220 send-related names, including `nop_inject_*` kernel
round trips, parking, coalescing, bounded sends, waiting for room, chains,
stale CQEs, teardown settles, proptest sequences for pool and slab leaks);
mio unit tests in `backend/mio/driver.rs` and `event_loop.rs` (bounded
permits, clear fan-out, slot reuse, write errors, capacity wake once);
`buffer/send_copy.rs`, `buffer/send_slab.rs`, `runtime/send_completion.rs`,
`chain.rs`, `completion.rs` unit tests; integration tests
`awaited_send.rs`, `submit_batch_await.rs`, `chain_short_send.rs`,
`guard_send_threshold.rs`, `half_closed_peer_send.rs`,
`half_closed_send_wait.rs` (counts io-wq threads), `shutdown_zero_copy.rs`,
`zc_send_enomem.rs`, `zc_chain_enomem.rs`, `echo.rs` (backpressured,
half-close, post-FIN response, slot release), `tls_echo.rs`,
`stream_echo.rs`, `close_on_drop.rs`, `segment_backpressure.rs`.

Not reached by any test I found: the `handle_send_msg_zc` path for
`result == 0` with `close_submitted` false (continues the queue); a
`drain_send_retries` entry duplicated for one connection across two parks;
`DriverCtx::close`'s deadline on the mio backend (there is none);
`ConnStream::poll_write` on a TLS connection.

## Verdict per invariant

Reviewer verdicts, each re-checked by the auditor against the quoted code.
io_uring verdicts are from reading; mio verdicts from reading plus the runs
named under Findings.

| Invariant | io_uring | mio |
|---|---|---|
| S1 memory outlives the SQE | holds | n/a (no SQE) |
| S2 release exactly once | holds with caveat (F9: a slot on `pending_copy_retries` at exit is freed with the pool, not released) | holds |
| S3 no id at release | holds | n/a |
| S4 reservation accounting | holds | holds |
| S5 nothing freed the kernel can read at exit | holds with caveat (`leak_backing` is conditioned on the slab; a plain send's slot is freed if its Close CQE is missing at the bound, a case not constructed) | n/a |
| O1 one send in the kernel | holds | n/a (one `writev` at a time) |
| O2 wire order | holds | holds |
| O3 parking re-pushes the same bytes | holds | n/a |
| O4 FIN after queued sends | **violated** (F3: an active chain is not waited for); F10 plausible | holds |
| O5 Close gated; nothing after `close_submitted` | holds | n/a |
| C1 one result per awaited send | **violated** (F1 silence, F2 wrong result); F7 settles `WriteZero` for a zero-length batch | **violated** (F1, F2) |
| C2 stale CQE touches only its resources | holds (16-bit generation caveat; previous audit L6) | holds |
| C3 driver result outranks the provisional abort; no table leak | **violated** (F2: the override cannot apply to a live, woken owner; F1: an `Abandoned` entry with a live future) | **violated** (same) |
| C4 admission FIFO | holds (caveat L6 below) | holds |
| T1 nothing committed on `Err`; TLS failure after sealing closes | holds | **violated** (F4) |
| T2 `InvalidInput` up front | holds (caveat L1) | holds (caveat L1) |
| T3 ciphertext bound never beaten | holds | holds |
| W1 waiting in ringline, one poll, backstop | holds with caveat (F12: the multishot re-arm takes two steps) | n/a |
| W2 nothing of a waiting send in the kernel | holds | n/a |
| W3 ENOMEM to plain sends | holds | n/a |
| F1 one failure mode per error | holds with caveat (the mode differs by send kind and backend; previous audit F13; L2, L7) | holds with caveat (F4) |
| F2 retry give-ups fail and close | holds | n/a |
| F3 worker exit | holds with caveat (F8 plausible; F9) | holds |
| F4 mio finalize after drain; permits returned | n/a | holds |
| close_notify reaches the peer | **violated** (F5 under pool exhaustion; F6 on key exhaustion); F11 plausible for fatal alerts | **violated** (F6); F11 plausible |
| X1 CLAUDE.md | holds with caveat (F14: Connection Lifecycle sentence contradicts DI-8); every count, default and flag checked matches | same |
| X2 design docs | **violated** (F9, F12, F14: departure 2 in four docs, six docs naming identifiers #617 removed with no superseded note, send-capacity-fifo describes a module that no longer exists) | same |
| X3 public doc comments | **violated** (F3, F10, F11, F14: `send`/`send_nowait` error contract, `send_parts` slot limit, `send_slab_slots`, `max_chain_length`, `WriteHalf::Shutdown`, `forward_recv_buf`, `AsyncSendBuilder`) | same |
| X4 journal follow-ups | four of five closed by code, one open and harmless; both journal entries list the closed ones as open (F14) | same |

## Findings

Status: **confirmed** = reproduced by a run on a clean worktree at 6ea67e6c,
or every step of the path traced and quoted with no trigger assumption;
**plausible** = the path is real, the trigger was not shown. Each reviewer
report is under the session scratchpad as `review-{a,b,c,d,e}.md`; the
reviewer letter and its finding number are given so the full argument can
be found. Each finding ends with a **Disposition** line once it closes:
fixed (the PR), refuted (the evidence), design limitation, or not fixed
(where it is tracked and what reopens it). A finding without one is open.

### F1 — A `SendFuture` created in one task and first polled by another, after the creator's connection task returned, never resolves (C1, C3). Confirmed: mio test fails on a clean worktree; io_uring by reading. (B1)

`runtime/send_completion.rs:657` records the owner at the `send()` call
(`CURRENT_TASK_ID`), not at the first poll. When connection task N returns,
the task-exit arm (`mio/event_loop.rs:1635-1636`, `uring/event_loop.rs:944-945`)
runs `Executor::remove_connection(N)`, and `SendCompletions::remove_connection`
(`send_completion.rs:527-537`) treats an `InFlight` entry whose recorded owner
is N as owner-gone and marks it `Abandoned`. The spawned task S then polls the
future: `set_owner(id, S)` (`:287-300`) changes the owner but leaves the state
`Abandoned`; `take_result` is `None`; the slot's generation is unchanged
because the close is deferred behind the queued send; S parks. The driver
delivers the bytes and `complete(id, Ok(n))` (`:356-358`) finds `Abandoned`,
removes the entry and wakes nobody. S hangs forever on a send that was
delivered.

Shape: `let fut = tx.send(b"..")?; spawn(async move { fut.await })` from
`on_accept`, then return. Also reachable from `on_tick`, where
`CURRENT_TASK_ID` is whatever task was polled last.

Reproduced: `review_b_set_owner_from_a_live_future_revives_an_abandoned_entry`
(unit, `SendCompletions`) and
`review_b_send_future_handed_to_a_spawned_task_hangs_when_its_creator_returns`
(mio event loop) both fail on a clean worktree at 6ea67e6c; the peer reads
`hello`, `send_completions.live() == 0`, the spawned task's result is `None`.

Fix: a poll proves the future is alive, so `set_owner` should revive an
`Abandoned` entry to `InFlight`. `cancel` also produces `Abandoned`, but a
cancelled future is never polled again. With the fix the reviewer's scratch
copy passes the lib tests (432) and the mio integration suite (744 passed).

**Disposition: fixed** (this PR). `set_owner` returns an `Abandoned` entry to
`InFlight`. Regression tests:
`a_poll_from_a_live_task_revives_an_entry_its_dead_creator_abandoned` (unit)
and `a_send_future_handed_to_a_spawned_task_resolves_after_its_creator_returns`
(mio event loop); both fail on the unfixed tree (`complete` returns `None`;
the spawned task's result stays `None`) and pass with the fix. One window
stays open: if the driver's completion lands between the creator's return
and the new owner's first poll, `complete` frees the `Abandoned` entry and the
later poll finds an unknown id. The creator's return also closed the
connection, so that poll resolves `ConnectionAborted` for delivered bytes
once the slot is released (`SendFuture::poll`'s generation arm), or parks
forever if it runs after the completion but before the release. On mio the
spawned task is polled in the same `poll_ready_tasks` pass as the creator's
return and the flush runs after it; on io_uring the spawned task is polled in
the same pass too, ahead of the flush that submits the send. So the direct
`spawn(async move { fut.await })` shape is outside the window on both backends; a spawned task that awaits something
else before polling the handed-off future is not. Recorded as L10.

### F2 — An awaited send owned by a live task on a connection whose own task returns resolves `ConnectionAborted` for bytes that reach the wire (C1, C3). Confirmed: mio test fails on a clean worktree; io_uring by reading. (B2)

The task-exit arms call `close_connection[_graceful]` and then
`Executor::remove_connection` at once. `remove_connection`
(`send_completion.rs:530-534`) records a provisional `Aborted` for every
entry on the connection with a live owner and wakes that owner. The owner is
polled in the same pass, `take_result` returns the `Aborted`, the future
resolves `Err(ConnectionAborted)` and the entry is removed. The queued send
drains afterwards (mio finalizes only on an empty `pending_sends`; io_uring
`close_connection` drains the queue before the Close) and
`complete(id, Ok(n))` finds nothing. The departure-4 override (a driver
result outranks the provisional abort) cannot apply, because the abort's
own wake makes the owner poll first. The existing
`bounded_send_owned_by_another_task_survives_its_connection_task_returning`
passes only because its owner is `std::future::pending` and never polls.

Shape: a writer task holding the `SendHalf` outlives the reader task on the
same connection (reader returns on EOF while the response is queued).

Reproduced:
`review_b_awaited_send_owned_by_a_live_task_reports_aborted_for_delivered_bytes`
fails on a clean worktree: `left: Err(ConnectionAborted) right: Ok(5)`, and
the peer read `hello`.

Fix: separate task death from slot death. The task-exit arms should drop
the dead task and the entries it owned (the owner-gone rule) and leave the
entries other tasks own on the connection to the driver, which delivers or
fails every queued send before the slot is released; `handle_close` (io_uring)
and `drain_pending_closes` (mio) keep the full `remove_connection` as the
backstop. The reviewer applied this on mio in a scratch copy
(`SendCompletions::remove_task_owner`, `Executor::remove_connection_task`);
the io_uring arms at `uring/event_loop.rs:945` and `:968` need the same.

**Disposition: fixed** (this PR). `SendCompletions::remove_task` drops only
the entries the dead connection task owns; `Executor::remove_connection_task`
calls it from the four task-exit arms (mio and io_uring, return and panic).
`remove_connection` runs only at the slot's release (`handle_close`,
`drain_pending_closes`). Regression tests:
`a_send_another_task_awaits_resolves_delivered_when_the_connection_task_returns`
(mio event loop; fails on the unfixed tree with `Err(ConnectionAborted)`
against `Ok(5)`) and two `remove_task` unit tests:
`remove_task_leaves_entries_other_tasks_own_on_the_connection` fails when
`remove_task` is made to behave as `remove_connection`;
`remove_task_drops_the_task_s_entries_on_other_connections` passes under
either and pins that the narrower rule still follows the task across
connections. The io_uring arms
were changed by the same edit and compile only in CI. The provisional-abort
rule (departure 4) stays: in the current loops no driver result reaches
`complete` after the release (mio finalizes only with `pending_sends` empty;
io_uring commits the Close only with the queue empty and nothing in flight;
a CQE that outlives the slot goes to `forget`), so the rule has no effect
today and keeps `remove_connection` correct from any call site.

### F3 — `shutdown_write` pushes the FIN while a send chain is active (O4, X3). Confirmed by trace; io_uring only. (A1, C1)

`handler.rs:1182`: `if in_flight || !queue.is_empty()` defers the FIN;
a chain sets neither (`SendChainBuilder::finish`, `handler.rs:4283-4302`,
records the chain in `chain_table` only). Every other site that must wait
for a chain checks `chain_table.is_active` (`handler.rs:974`, `:1002`,
`driver.rs:1643`, `:1860`); `shutdown_write` does not. A `send_chain_nowait`
of parts larger than the socket's free send-buffer space followed by
`shutdown_write()` in the same poll pushes an unlinked `Shutdown(SHUT_WR)`
beside the linked `MSG_WAITALL` parts; the FIN queues behind the bytes
already in the buffer, the later parts fail `EPIPE`, `fire_chain_complete`
closes. The peer receives a prefix and a clean FIN. The doc on
`SendHalf::shutdown_write` (`runtime/io.rs:3157-3159`, "the FIN is ordered
behind them") is false for chains. TLS chains go through the queue and are
deferred correctly.

Fix: add `|| self.chain_table.is_active(conn.index)` to the condition. The
deferred FIN already fires from `fire_chain_complete` → `submit_next_queued`
→ the empty-queue arm (`driver.rs:1813-1830`). Test: a chain of two parts
larger than a small `SO_SNDBUF`, `shutdown_write` in the same poll, the peer
reads to EOF and gets the full length.

**Disposition: fixed** (this PR). `shutdown_write` defers on
`chain_table.is_active` as well. Regression test
`shutdown_write_defers_while_chain_active` (io_uring lib test: with a chain
started, `shutdown_write` must leave the write half `ShutdownPending` with no
Shutdown SQE, and `fire_chain_complete` must submit it). Red and green were
run on Linux in a SystemsLab VM (`experiments/shutdown-write-chain-verify.toml`,
result recorded in the PR); macOS cannot compile the test. The socket-level
test the finding proposed (a chain larger than `SO_SNDBUF`, peer reads to
EOF) was not written: the lib test pins the state machine the fix changes,
and the FIN's ordering behind a deferred send is the existing
`submit_next_queued_inner` path.

### F4 — mio leaves a TLS connection open after an encrypt failure; TLS 1.2 traffic-key exhaustion is a reachable trigger and the second of two encrypt calls can spend a sequence number (T1, F1). Confirmed by trace; rustls behaviour verified in the fork. (D1, C4)

`handler.rs:2659-2661` (mio `send_inner`) and `:2772-2780` (mio
`send_bounded`) propagate `encrypt_for_send_mio`'s `Err` without closing;
the io_uring twins call `self.close(conn)` (`handler.rs:487`, `:762`).

Trigger: the `ringline-tls-config` builders enable TLS 1.2 AES-GCM by
default (`ringline-tls-config/src/lib.rs:441-443`). In ringline-tls 0.1.2
(the version `Cargo.lock` resolves) those suites carry
`confidentiality_limit: 1 << 24` (`crypto/ring/tls12.rs:53-95`);
`prepare_message_encrypter` sets `write_seq_max = min(SEQ_SOFT_LIMIT, max)`
(`record_layer.rs:147`); `pre_encrypt_action` returns `RefreshOrClose` at
the limit (`record_layer.rs:217-223`); on a non-1.3 connection
`write_plaintext` calls `send_close_notify()` and returns
`EncryptExhausted` (`common_state.rs:295-307`), which `encrypt_with` maps
to `Err(Other("TLS traffic keys exhausted; connection must close"))`
(`tls/unbuffered/mod.rs:856-860`). The config's own doc puts that at about
168 s at 100,000 records/s.

Two sub-cases. Limit hit on the first `encrypt_chunk` of a message: the
check runs for every fragment before any is sealed, no sequence number is
spent, the caller gets a retryable-looking `Other`, every retry fails the
same way, and the connection stays `Open`, receiving. Limit hit on the
second call: `encrypt_to_vec` (`tls/unbuffered/mod.rs:928-975`) makes two
`encrypt_chunk` calls whenever the trailing partial record is shorter than
`F - 64` (with `QUEUED_RECORD_ROOM = 64`: for `rest = k*F + r`,
`dst_len = rest + (k+1)*oh + 64`, `whole = dst_len / (F + oh) = k` when
`r < F - 64`, so the first call seals `k` records and the second encrypts
`r` bytes). If the second call hits the limit, the first call's records
are sealed and discarded with their sequence numbers spent; the next send
on the connection is `bad_record_mac` at the peer. The alert rustls queued
is also lost (F6).

Fix: in both mio TLS branches call `self.close(conn)` (mio
`DriverCtx::close`, `handler.rs:2874`) before returning `Err`. Say on
`SendHalf::send` that a TLS encrypt error closes the connection and the
buffer cannot be resent. Not reproduced (needs 2^24 records on one TLS 1.2
connection).

**Disposition: fixed** (this PR). Both mio TLS branches call
`DriverCtx::close` before returning the error, as io_uring's
`encrypt_tls_send` does for every error from `encrypt_to_sends`.
Regression test `a_tls_encrypt_error_closes_the_connection` (mio driver,
unbuffered engine): the trigger is a session that has not handshaked, which
`encrypt_with` refuses with `WouldBlock`; key exhaustion is not reproducible
in a test. On the unfixed tree the connection stayed `Open` after the error.
The sequence-number claim rests on the fork reading above and is not tested.

### F5 — close_notify is dropped silently when the pool is exhausted at close, and the connection records it as sent (close_notify). Confirmed by trace; io_uring only. (D3)

`tls/mod.rs:791-804` (unbuffered arm of `send_close_notify_queued`):
`queue_close_notify` sets `close_notify_sent = true` when it wrote bytes
(`tls/unbuffered/mod.rs:1003-1005`), then
`let _ = backend_uring::ciphertext_to_sends(..)` discards the `false` that
`copy_in` failure returns (`tls/backend_uring.rs:91-96`), appending
nothing. The buffered arm (`tls/mod.rs:809-818`) sets rustls'
`has_sent_close_notify` through `send_close_notify()` and discards
`take_tls_output_sends`' `false`. Both callers (`queue_tls_close_notify`,
`driver.rs:1907-1927`; `DriverCtx::close`, `handler.rs:1125-1148`) treat an
empty `sends` as "nothing to queue". The connection closes with a bare FIN
while `close_notify_sent` says the alert went out; the peer reads the
stream as truncated. The trigger is the pool fully allocated at the moment
of close, the ordinary backpressure state the pool exists to produce; the
alert needs one slot.

Fix: keep the ciphertext when `ciphertext_to_sends` fails (an
`Option<Vec<u8>>` on `ConnSendState`) and retry placing it from
`try_finalize_close` before the Close SQE and from the capacity-release
path; drop it at the close_notify deadline as queued sends are dropped. At
minimum, count the drop in a metric and do not set `close_notify_sent`.

### F6 — On TLS 1.2 key exhaustion the close_notify rustls queued is dropped by the `EncodeTlsData` arm; the peer gets a bare FIN (close_notify). Confirmed by trace; both backends. (D2)

`tls/unbuffered/mod.rs:1069-1071`: `Ok(ConnectionState::EncodeTlsData(_)) =>
Err("a queued TLS record was dropped by the close_notify path")`. After F4's
`EncryptExhausted`, rustls has queued the alert in `sendable_tls`;
`process_tls_records` pops it ahead of deframing (fork
`conn/unbuffered.rs:77-87`) and returns `EncodeTlsData`, which this arm
drops. On io_uring the path is `encrypt_tls_send` → `DriverCtx::close` →
`send_close_notify_queued` → `queue_close_notify`; on mio it is
`finish_close` → `flush_tls_output_mio_direct`. The comment at
`:1056-1068` and `close_notify_reports_a_dropped_queued_record`
(`tls/unbuffered/tests.rs:1029`) record the drop as deliberate (an `Err`
instead of `Ok(0)`); the peer's outcome is unchanged by that choice.

This is a question for the owner rather than a fix to apply: the comment's
objection to encoding the record (re-entering the state machine strands the
alert) concerns re-entry after `queue_close_notify` has queued it; draining
an `EncodeTlsData` before the first `queue_close_notify` call is what
`drive_inner` already does (`:463-487`). `send_close_notify`'s
`sent_fatal_alert` guard (fork `common_state.rs:675-677`) would make the
second queue a no-op when the drained record was the alert.

### F7 — A zero-length `send_parts` copy send on io_uring is pushed as a zero-length SQE, whose result 0 the handler treats as a failed send; every send queued behind it is discarded and the connection stays open (O2, S2 adjacent). Confirmed by trace; io_uring only. (auditor)

`SendBuilder::submit` (`handler.rs:3770-3781`) returns early only for
`part_count == 0`; `copy(&[])` adds a part of length 0 (`:3699-3718`).
`build_copy_only` → `copy_in_gather(.., total_len = 0)` takes a slot
(`send_copy.rs:150-172` has no zero check) and `stream_send(.., len = 0)` is
pushed. `send(fd, p, 0, MSG_DONTWAIT)` on a stream socket returns 0.
`handle_send` (`uring/event_loop.rs:2715-2784`): `result > 0` is false,
`errno == 0` is not `EAGAIN`, so the terminal-error arm runs:
`drain_conn_send_queue` releases every entry queued behind this one and
settles their ids `ConnectionAborted`; no close follows (the previous
audit's F13), so later sends reach the peer after a gap. Awaited: the
future settles `Err(WriteZero)`. The same call on mio sends nothing
(`AsyncSendBuilder::build`/`submit_batch` skip an empty buffer), and on a
TLS connection `encrypt_to_sends(&[])` yields no record. `send_inner` with
empty data queues no SQE and settles `Ok(0)`. No in-tree caller passes a
zero-length part (`ringline-redis`, `ringline-memcache` always include a
prefix); it is reachable through the public API.

Fix: in `SendBuilder::submit`, when `total_len == 0`, settle the id with
`Ok(0)` and return without building (as the `part_count == 0` arm does), or
refuse with `InvalidInput` as `submit_batch_await` does for an empty batch.

### F8 — `run_shutdown` step 2 ignores a refused plain `Close`, holding exit for the full 10 s bound (F3). Plausible. (C3)

`driver.rs:2702`: `let _ = self.ring.submit_close(i, CloseLead::CancelAll)`.
The adjacent `held_by > 0` branch retries a refused `submit_cancel_all`
through `cancels_to_retry`, and step 3 retries a refused `submit_close` for
`holding_sends`; the plain branch retries nothing. A connection whose Close
push fails (a `make_sq_room` → `submit()` error) never closes,
`active_count()` never reaches 0, and the step-3 loop runs to
`SHUTDOWN_BOUND`. The ring's drop then closes the fd, so nothing leaks past
the worker. Fix: on `Err`, push `i` onto `holding_sends` (step 3 then
submits a `CancelAll` close once `held_by == 0`), or add a
`closes_to_retry` list.

### F9 — `pending_copy_retries` is not released at worker exit; the design doc says every retry list is (X2, S2). Confirmed by reading; no resource consequence. (C5, A caveat)

`docs/send-completion-design.md:120-121`: "Entries parked on a retry list,
with no operation in flight, are released first." `driver.rs:2651-2656`
releases `pending_coalesced_retries` and `pending_zc_retries` only. A copy
send parked by `resubmit_waiting_send` (`uring/event_loop.rs:2861-2865`)
keeps its pool slot `in_use` until the pool drops with the driver; nothing
waits on it and nothing the kernel can read is freed. Fix: release it in
step 1 through `release_slot_at_shutdown`, or correct the sentence.

### F10 — A refused `Shutdown` SQE is forgotten and the public doc promises a FIN (O4, X3). Plausible; a recorded decision. (C2)

`driver.rs:1819-1829` and `handler.rs:1191-1195` set `write` back to `Open`
when `submit_shutdown` fails. `docs/write-half-design.md` records this ("a
repeat `shutdown_write` re-requests; there is no Shutdown retry list"), but
`SendHalf::shutdown_write` returns `()` and its doc says "Sends a TCP FIN
to the peer". Every send whose push fails is parked and retried (DI-7); a
Shutdown whose push fails is dropped. The trigger (a failed `io_uring_enter`
without `GETEVENTS`) was not shown. A question for the owner: a small retry
list, or a doc sentence saying the FIN may be dropped under
submission-queue pressure.

### F11 — The unbuffered engine never sends the fatal alert a receive error generates; the `feed_tls_received` doc says it does (close_notify adjacent, X3). Plausible; both backends. (D4)

`tls/backend_uring.rs:244-247`: "an alert generated on the way to a fatal
error still has to reach the peer". `drive_inner` returns on the first
`Err` from `process` (`tls/unbuffered/mod.rs:424-426`, `527-529`) without
calling `process` again. rustls' `send_fatal_alert` appends the alert to
`sendable_tls` (fork `common_state.rs:655-665`), and
`process_tls_records_common` hands a `sendable_tls` record back only on the
next call (`conn/unbuffered.rs:77-87`), so `scratch` holds no alert and
`close_connection` sends a FIN. The buffered engine drains `wants_write()`
on its error path (`tls/buffered.rs:203-210`, `561-564`), so the doc
describes that engine only. Fix: on `Err` from `process`, call `process`
once more and encode an `EncodeTlsData` into `out` before returning. Not
run against the fork; the pop at `conn/unbuffered.rs:77` precedes the
deframe that re-reports the error, so a second call is expected to return
the alert.

### F12 — Comments and design text that do not match the code (X2, X3). Confirmed by quote.

- `runtime/send_completion.rs:496-499`: "its futures' `Drop` does not run
  (teardown is not inside a driver-state guard on either backend)". False
  for the panic arm of `poll_ready_tasks` on both backends
  (`uring/event_loop.rs:966-968`, `mio/event_loop.rs:1651-1653`): the future
  is dropped under `set_driver_state_guarded`, so `SendFuture::drop` and
  `BackpressuredSendFuture::drop` run `cancel_send`. Harmless (the entry
  becomes `Abandoned` and its completion frees it); the io_uring panic
  arm's "close first" comment exists because `Drop` does run there.
- `docs/half-closed-send-wait-design.md` step 5, "A multishot poll that
  ends with the send still waiting is armed again": `handle_send_pollout`
  (`uring/event_loop.rs:2953-2955`) arms a one-shot (`!multi`), which on a
  half-closed socket completes at once with `POLLRDHUP` and then re-arms
  the multishot. Two extra CQEs, no hang.
### F13 — An oversize copy-only `send_parts` batch, and an oversize `SendChainBuilder::copy`, are refused as retryable pool exhaustion instead of `InvalidInput` (T2, X3). Confirmed by reading. (E2)

`build_copy_only` (`handler.rs:3862-3870`) maps `copy_in_gather`'s `None`
to `Other("send copy pool exhausted")`, but `copy_in_gather`
(`send_copy.rs:155-157`) returns `None` for `total_len > slot_size` as well
as for an empty pool. `SendChainBuilder::copy` (`handler.rs:4179-4184`) and
the copy-only arm of `ChainPartsBuilder::add` (`:4567-4596`) do the same
through `copy_in`. With guards present the same input is `InvalidInput`
(`handler.rs:3894-3899`). A caller following the `send` contract retries a
batch that can never fit. Fix: check `total_len > slot_size` before the
gather in `build_copy_only`, `SendChainBuilder::copy` and the copy-only arm
of `add`, returning `InvalidInput`; document the one-slot limit on
`send_parts` and `send_chain` (F14).

### F14 — Documents and doc comments that do not state what the code does (X1, X2, X3, X4). Confirmed by quote and grep; every quote re-read by the auditor at HEAD. (E1-E18)

Would lead a caller or operator astray:

- `runtime/io.rs:3023-3033` (`SendHalf::send`) and `:3045-3049`
  (`send_nowait`): "# Errors" names pool admission only. `send_inner`
  returns `NotConnected` for a stale handle, a committed Close and, on TLS
  over io_uring, a queued close_notify (`handler.rs:526-546`, `:436`); on
  mio a plaintext send never fails for pool reasons and a TLS send returns
  rustls' error without closing (F4). A caller treating every `Err` as
  retryable pool pressure retries a dead handle for ever.
- `runtime/io.rs:3058-3065` and `:1611-1616` (`send_parts`,
  `submit_batch`): no mention that the copy parts of one batch share one
  pool slot (`InvalidInput` with guards, F13 without), of `Other("send slab
  exhausted")`, of the `NotConnected` cases, or that a TLS batch is not one
  SQE; "the protocol clients cap at 4 guards / 9 iovecs" is stale
  (`ringline-redis/src/lib.rs`: 8 guards, 17 iovecs).
- `config.rs:188-191` (`send_slab_slots`): "scatter-gather sends ... that
  include at least one guard". `submit_coalesced_run` takes an entry for
  every run of two or more queued copy sends, including a multi-slot `send`
  and TLS ciphertext; a full slab degrades those to one slot per CQE and
  fails guard sends. An operator sizing for guards alone under-provisions.
- `config.rs:280-284` (`max_chain_length`): describes automatic chaining
  and a fallback "via on_send_complete". The knob is read only by
  `SendChainBuilder::copy` and `ChainPartsBuilder::add`
  (`handler.rs:4166`, `:4461`); 0 refuses every chain; nothing chains a
  plain send; `on_send_complete` does not exist.
- `docs/backpressured-sends-series-design.md:50-54` (departure 2),
  `docs/tls-premutation-bound-design.md:143-146`,
  `docs/send-completion-design.md:154-158`,
  `docs/copied-send-reservation-design.md:211-214`: the ciphertext bound
  "gates only bounded sends" and the mid-encryption exhaustion is "the one
  remaining exception ... PR 8 closes". On io_uring `encrypt_tls_send`
  (`handler.rs:433-497`) applies the bound to every plain TLS send and
  closes on a failure after it; on mio plain TLS sends are unbounded.
- `connection.rs:69-71` (`WriteHalf::Shutdown`): "does not refuse later
  sends". `BackpressuredSendFuture` refuses `BrokenPipe`
  (`runtime/io.rs:3810-3818`) and `shutdown_write` fails waiting bounded
  sends (`:1439-1447`); `docs/write-half-design.md:66` was superseded by
  PR 9 without a note. (Also recorded by the previous audit, F14.)
- `CLAUDE.md:193` Connection Lifecycle: "with a `shutdown` hard-linked
  ahead of it" contradicts Domain Invariant 8 in the same file (`Shutdown`
  before 6.13, `CancelAll` from 6.13, nothing for a handed-off socket).
  (Also previous audit F14.)
- `CHANGELOG.md:1209-1211` (#603) says a waiting send holds an io-wq
  thread; `:587-593` (#605) says it does not. Both are under Unreleased.

Stale references and claims:

- `handler.rs:55-59` `close_send_count`: written once, never read
  (previous audit F14). `on_send_complete` named at `handler.rs:15`,
  `config.rs:282`, `chain.rs:6`, `uring/ring.rs:445`; no such function.
- `docs/send-capacity-fifo-design.md` describes `runtime/send_capacity.rs`
  and `SendCapacityQueue`, neither of which exists (now the waiting half
  of `SendCompletions`); `docs/mio-bounded-send-design.md`,
  `docs/uring-bounded-send-design.md`,
  `docs/copied-send-reservation-design.md` and
  `docs/send-backpressured-design.md` name `notify_len`,
  `bounded_send_completions`, `BoundedSendId`, `slot_bounded_send`,
  `wake_send`, `io_results`, `settle_bounded`, `mark_bounded_send_submitted`
  and others #617 removed (grep: 0 non-test hits each), with no note
  pointing at `docs/send-completion-slots-design.md` "What goes away".
  `docs/uring-bounded-send-design.md:3` says "`forward_to` was removed";
  `ConnCtx::forward_to` exists (`runtime/io.rs:1232`, `:1278`) as the body
  of `forward_to_conn`; `:113` "the six retry drains' give-up arms": four
  drains give up today, and `drain_send_retries` settles nothing itself.
  `docs/tls-premutation-bound-design.md:34` "rustls 0.23.41
  (`Cargo.lock`)": the lock has ringline-tls 0.1.2 and rustls 0.23.46.
- `docs/send-completion-design.md:10-12`: "the provided buffer a
  `forward_recv_buf` send lends"; the TCP provided ring is gone and
  `forward_recv_buf` sends a guard over the detached accumulator.
- `docs/send-completion-slots-design.md:70`: a zero-copy batch below
  `send_zc_threshold` folds into a pool slot that carries the id
  (`attach_send_id`, `handler.rs:926-940`); `forward_to_conn` chunks are
  not in the table.
- `handler.rs:660-664` (io_uring `send_bounded`): "The plaintext-sized
  budget is what both backends use; bounding the ciphertext is series PR
  8" (the TLS branch below uses the ciphertext bound). `handler.rs:2702`
  "Called by series PR 9's future". `tls/mod.rs:378`, `:641-647`: PR 8/9
  obligations written as the present. `tls/mod.rs:486`: io_uring writes
  ciphertext "via `PoolWriter`" (the `tls-buffered` path; the default
  engine uses `encrypt_chunk`). `tls/backend_uring.rs:363-366`: "the same
  rule `DriverCtx::send` documents for its own mid-buffer failures"; that
  doc now says nothing is committed on `Err`. `send_copy.rs:5-7`: a
  reservation "lives inside one synchronous `DriverCtx::send`"; on mio a
  bounded permit is held until flush or discard.
- `handler.rs:2619-2622` (mio `DriverCtx::send`): TLS data "written
  directly to the TcpStream (bypassing the pending send queue)"; it is
  queued as a `PendingSend`. `handler.rs:2905` (mio `shutdown_write`):
  "Flushes any buffered pending sends before"; it records
  `ShutdownPending` and `flush_sends` issues the FIN later.
- `uring/event_loop.rs:4743-4744`: "by calling `try_finalize_close`"; the
  body calls `force_finalize_close` (previous audit F14).
- `runtime/io.rs:3126-3128` (`forward_recv_buf`): the TLS sentence reads
  as both backends; on mio the path is `ctx.send` with no detach.
- `runtime/io.rs:1572` (`AsyncSendBuilder`): "fire-and-forget (no
  future)"; `submit_batch_await` returns a `SendFuture`.
- `runtime/send_completion.rs:496-499` (F12 above) and
  `docs/half-closed-send-wait-design.md:80-81` step 5 (F12 above).
- `docs/write-half-design.md:59`: "the two give-up branches of
  `submit_next_queued`" moved to `drain_send_retries` with PR 4 and no
  longer reset `write`. `docs/send-writer-design.md:180` names
  `take_send`, removed.
- `handler.rs:1100-1106` (`DriverCtx::close`): history after the
  behaviour statement.

X4, the journal's open follow-ups: (a) `handle_send_recv_buf`'s drop is
closed by removal; (b) `send(&[])` settles `Ok(0)` (`handler.rs:604-609`);
(c) the TLS parking test exists
(`bounded_tls_send_parks_and_then_fails_rather_than_re_encrypting`); (e)
chains refuse while sends are in flight and plain sends queue behind a
chain; the mio TLS bounded length is `data.len()` on both branches
(`handler.rs:2797-2816`). (d) `drain_send_retries` wakes the recv side on
give-up and `drain_copy_retries` does not (`uring/event_loop.rs:4637`);
open, harmless. `docs/journal/2026-09-backpressured-sends.md:158-160` and
`2026-09-backpressured-sends-series.md:149-172` still list the closed ones
as open; the series entry's status is "open" for a series the later entry
records as shipped.

Replacement text for each item is in the review E report under the
scratchpad; every replacement sentence was written against the code at
6ea67e6c and has not been applied.

## Design limitations (questions for the owner, not fixes)

- **L1** The admission bound's slack record makes a TLS message of exactly
  `slot_count` records `InvalidInput` for ever (pool 8 x 16448, unbuffered,
  F = 16384, a 131072-byte send: `records = 9 > 8`), though eight records
  fit eight slots unless a key_update is queued. By design
  (`docs/tls-premutation-bound-design.md`); the `SendHalf::send` doc
  describes `InvalidInput` as "wider than the entire pool", one record short
  of the TLS truth.
- **L2** On io_uring a terminal plaintext send error drains the queue and
  does not close the connection (previous audit F13, unchanged at 6ea67e6c);
  a TLS chunk or TLS run error closes; mio closes on any write error. The
  same peer RST therefore gives a different connection lifecycle per send
  kind and per backend (table in review C). F7 is one consequence.
- **L3** `handle_send_msg_zc` with `-EAGAIN` or `-ENOMEM` after
  `close_submitted` (`uring/event_loop.rs:3404`, `:3418`) settles the awaited
  send `WouldBlock` or `OutOfMemory`; the other three handlers settle the
  same situation `ECANCELED`. Unreachable today: `close_submitted` with a
  send in flight needs `force_finalize_close`, which only the TLS deadline
  calls, and a TLS connection never holds a ZC entry.
- **L4** `Send`/`TlsSend` CQEs carry a 16-bit truncated generation (previous
  audit L6). A false match needs 65536 reuses of one index while one Send
  CQE is outstanding on a dead occupant.
- **L5** `force_finalize_close` with `shutdown_inflight` set re-runs every
  tick from `check_close_notify_deadlines` until the Shutdown CQE lands
  (previous audit F11). Harmless churn.
- **L6** A bounded send whose owner task is woken but does not poll its
  future holds the admission FIFO head and stalls every bounded send on the
  worker. Inherent to a FIFO with task-owned entries; not documented.
- **L7** mio `finish_close`'s own flush discards a `writev` error
  (`mio/driver.rs:633`); the still-queued awaited sends then fail
  `ConnectionAborted` from `clear_pending_sends`, where the same error one
  iteration earlier from `handle_writable` reports the real errno. Permits
  and ids are released either way.
- **L8** io_uring `DriverCtx::close` (`handler.rs:1125-1148`) queues
  close_notify without the `write != Open` check `queue_tls_close_notify`
  applies. An encrypt failure after `shutdown_write` queues an alert onto a
  shut-down write side, which fails `EPIPE`; no visible effect.
- **L9** On mio `SendCopyPool` memory is allocated and never written; the
  pool's count is the bounded-send admission budget only
  (`docs/mio-bounded-send-design.md`). Still true at 6ea67e6c.

### L10 — An abandoned entry whose completion lands before its new owner's first poll is freed; that owner resolves `ConnectionAborted` once the slot is released, or parks forever if polled before then

The completion table records an awaited send's owner at the `send()` call.
When the creating connection task returns, `remove_connection` cannot tell a
future that died with the task from one handed to a task that has not
polled it yet, so it abandons both; F1's fix revives the entry on the next
poll. If the completion arrives first, `complete` frees the abandoned entry
(it must: an entry whose future really died would otherwise leak one slot per
such send) and the later poll finds an unknown id. The creator's return
closed the connection, so `SendFuture::poll` resolves `ConnectionAborted`
for bytes the peer received once `ConnectionTable::release` has advanced the
generation; a poll that runs after the completion but before the release
(on mio, the `poll_ready_tasks` inside `drain_send_completions` or
`finalize_closes`, both ahead of `drain_pending_closes`) finds the
generation unchanged and parks forever. Closing the window needs the table to learn that the future is dead from the future
itself rather than from its owner's death: the task-exit arms drop the task's
future inside the driver-state guard (`drop_caught` after
`Executor::remove_connection` on both backends), so `SendFuture::drop` does
reach `cancel`, and dropping the future before `remove_connection` and
narrowing the owner-died rule would let a live future keep its entry. That
is a change to the teardown order the module docs and
`docs/send-completion-slots-design.md` describe, and is left as a question
for the owner. Reopened by: a hang, or a `ConnectionAborted` for delivered
bytes, in a task that awaits a `SendFuture` it did not create, after
awaiting something else first.

## What the audit did not cover

- Nothing on the io_uring path was executed. F3, F5, F6 (io_uring half),
  F7, F8, F9, F10 and the io_uring halves of F1, F2, F4, F11 are traces.
  The io_uring unit tests (about 220 send-related) were not run. Reproducing
  F3 and F7 needs a Linux anvil VM.
- F4's trigger (2^24 records on one TLS 1.2 connection) and F11's second
  `process` call were not run against the fork; both rest on reading the
  fork's source at 0.1.2.
- Kernel behaviour the code relies on was not verified: that `send` with
  `MSG_DONTWAIT` completes inline; that `IORING_CQE_F_MORE` is set on every
  `SendMsgZc` main CQE that will have a notification; that io_uring copies
  the `msghdr`/iovecs at submit; the half-closed `POLLOUT` sequence beyond
  what `docs/half-closed-send-wait-design.md` measured; the 6.7 and 6.13
  boundaries.
- UDP sends; park and adopt beyond the TLS park's send refusal; the recv
  path except where a forward feeds a send; QUIC and the client crates'
  own buffering.
- Reviewer E (docs) did not read `sqe.rs`, the engine, `tls/unbuffered`,
  `tls/buffered.rs` or the integration tests; its claims about those are
  from grep.
- Reviewer A did not read `DirectForward`, the mio backend or the TLS
  engines; reviewer B did not read `ring.rs`, `sqe.rs`, the engine or the
  TLS encrypt code; reviewer C did not read `send_copy.rs`/`send_slab.rs`
  bodies or `chain.rs`; reviewer D did not read `send_slab.rs`,
  `send_completion.rs`, `chain.rs` or the fork's `encrypt_into`
  implementations. Each area was read by at least one other reviewer except
  the fork's `encrypt_into` bodies and `tls_echo.rs` test bodies.
- `tls-buffered` on io_uring was read (review D) but every run here was on
  mio; its `PoolWriter` exhaustion mid-record is unreachable after admission
  by the reviewer's argument and was not tested.
- Unix-socket TLS on mio: `finish_close`'s TLS path takes a `TcpStream`; what
  happens for a TLS connection accepted on a Unix listener was not checked.
- The performance of any fix was not measured; none was applied to the tree.

## Reproductions

A clean worktree at 6ea67e6c with reviewer B's three tests inserted into
`runtime/send_completion.rs` and `backend/mio/event_loop.rs` is under the
session scratchpad at `audit-wt/`; `cargo test -p ringline --lib review_b`
there fails all three as quoted in F1 and F2. The reviewer's fixed copy and
its integration run log are under `scratchpad/review-b/`. Each test is a
usable draft of the regression test its finding needs.
