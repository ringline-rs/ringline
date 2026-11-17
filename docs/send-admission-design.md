# Send admission a server can bound

Status: sections 1 to 3 are built; section 3 was specified from Experiment
A's results (`docs/journal/2026-11-abort-close.md`). Section 4 records
Experiment B's result and names Experiments C and D. C chooses an admission
order; D tests sending large replies in pieces that take pool slots only once
their socket has room, which the owner chose for plaintext on 2026-11-15, with
C's orders as the fallback. C's runs are
recorded in `docs/journal/2026-11-send-admission-c.md` and D's in
`docs/journal/2026-11-send-admission-d.md`, where gated pieces pass D's
decision rule. Section 4 ends with the proposed fast-path specification.
"What exists" describes the code before section 1, at 07dd0f56; section 3's
specification cites the code at 03628fee. `send_nowait` was removed in
0.7.0-alpha.141 (#965); the sections that name it describe the code before
that.

A server that answers many connections on one worker replies with
`send_nowait`. When the send copy pool is exhausted the reply fails, and the
server closes the connection. The server is meant to wait for capacity, with a
bound, and close only when the bound elapses. A review of a cache server's
attempt to do that on the current API found four problems in the code. None
was observed in a run.

1. A timeout around `send_backpressured` also times the connection's own
   backlog draining, because the future resolves when the send settles. A
   connection whose queued replies take longer than the bound to drain is
   closed although its peer is reading.
2. `send`, `send_nowait` and `submit_batch` do not read the send-capacity
   FIFO, so small replies can take the slots a queued large reply waits for,
   until that reply's bound elapses. The server's workaround was to copy
   instead of sending zero-copy while any of its replies waited. It still let
   `send_nowait` replies take slots ahead of the waiting one.
3. A refused `submit_batch` drops its guard parts, and its error does not say
   whether the pool or the zero-copy send slab was short. The caller can
   neither retry the batch nor fall back to a copy of the same bytes.
4. Closing a connection whose peer has stopped reading does not release what
   its sends hold: the close waits for the queue to drain, with no deadline.
   Closing the connections whose replies timed out therefore recovers nothing.

Reviewing this design found a fifth, reproduced on mio at e34d0015:

5. A send future polled on a worker other than the one that created it sends
   on that worker's connection with the same index and generation. A
   `send_backpressured` future created on worker 0 and awaited on worker 1
   delivered its bytes to worker 1's client and resolved `Ok(14)`; the owning
   client received nothing. Every worker hands out index 0 at generation 0
   first, so the ids collide by default.

Section 1 fixes problem 5. Section 2 (`send_admitted`) solves problem 1.
Section 3 (`abort`) is for problem 4, and section 4 (the fast path) for
problems 2 and 3.

## What exists

Read at 07dd0f56; line numbers are at that commit, except in section 3's
specification, which cites 03628fee. `io.rs` is `ringline/src/runtime/io.rs`,
`sc.rs` is `ringline/src/runtime/send_completion.rs`, `waker.rs` is
`ringline/src/runtime/waker.rs`, `handler.rs` is `ringline/src/handler.rs`,
and `completion.rs` is `ringline/src/completion.rs`. `udriver.rs`, `uloop.rs`
and `ring.rs` are `ringline/src/backend/uring/driver.rs`, `event_loop.rs` and
`ring.rs`. `mdriver.rs` and mio `event_loop.rs` are
`ringline/src/backend/mio/driver.rs` and `event_loop.rs`.

- `BackpressuredSendFuture` (io.rs:3938) moves through the states of
  `BackpressuredState` (io.rs:3865-3874): `Fresh`, `Waiting(SendId)` in the
  FIFO, `Submitted(SendId)` after `send_bounded`, and `Done`. The `Submitted`
  arm (io.rs:4069-4083) resolves only from `take_send_result`: on io_uring the
  send's completion, on mio the last byte reaching the socket
  (handler.rs:2802-2806). A caller cannot tell admitted from settled.
- The FIFO is `SendCompletions::waiting` (sc.rs:162). Only the head is
  admitted (sc.rs:370-372), when the free slots cover its whole
  `required_slots` (`head_ready`, sc.rs:485-495). `head_task`, `turn` and
  `head_ready` read `waiting.front()` (sc.rs:266-272, 370-372, 485-495).
  Removing an entry is a linear `position` and `VecDeque::remove`
  (sc.rs:383-388, 458-470).
- `send` registers an entry in `send_completions` and returns a `SendFuture`
  that resolves when the send settles (io.rs:1404-1413). `send_nowait` returns
  nothing to wait on. Neither reads the FIFO, and neither does `submit_batch`.
  `send` was kept unchanged when the FIFO was added
  (`send-backpressured-design.md:37`).
- `BackpressuredSendFuture`, `SendFuture` and `ForwardFuture` are `Send`,
  because no field of theirs is `!Send`; no design chose it. Their polls and
  drops act on whichever worker's driver and executor are current
  (io.rs:3995-4105, 4143-4151, 4218-4219, 4248-4255), and a `SendId` names no
  worker (sc.rs:93-96). `ForwardFuture` carries a connection index the same
  way (io.rs:3539-3546). `RecvReadyFuture` was made `!Send` for this reason
  (io.rs:3815-3826, `public-context-types-design.md:116-121`). A drop outside
  a task poll leaves the entry in the table for the life of the worker
  (sc.rs:452-457).
- `SendFuture` is built by `send`, `send_chain` (io.rs:1480-1482),
  `submit_batch_await` on both backends (io.rs:1765, 1889) and the forward
  path (io.rs:3755). One built already holding its result returns it without
  touching runtime state (io.rs:4209-4211). `mpsc::SendFuture`
  (`runtime/channel.rs:357`) has the same name.
- `BackpressuredSendFuture` has not been released (CHANGELOG, Unreleased).
  `SendFuture` has, since the first release.
- `submit_batch` drops its guard parts on `Err` (io.rs:1686-1690). It fails
  with `Other("send copy pool exhausted")` or `Other("send slab exhausted")`
  (handler.rs:4117-4120, 4188).
- `close()` drains queued sends with no time bound (io.rs:3265-3268), plain
  or TLS (udriver.rs:2260-2263). `CLOSE_NOTIFY_TIMEOUT` (5 s, handler.rs:175)
  is armed for a connection whose handshake or connect has not completed, and
  by `DriverCtx::close` on an io_uring TLS connection (handler.rs:1161-1170).
- A zero-copy slab entry is released when its notifications land, after the
  peer has acknowledged the data (`send-completion-design.md:126-135`). A
  fixed file's `Close` does not release the socket while requests that hold
  it are in flight: from Linux 6.13 the connection's own, before that earlier
  requests on any connection (CLAUDE.md, invariant 8). Worker exit cancels
  every request on a connection and only then closes it, with
  `CloseLead::Abort` (a `SO_LINGER {on, 0}` setsockopt, Linux 6.7,
  ring.rs:70-74 and 584-593) for one still holding slab entries
  (udriver.rs:3207-3315).
- On mio, `send`, `send_nowait` and `submit_batch` copy into a `Vec` and never
  touch the pool (handler.rs:2737-2789, io.rs:1826-1848). The pool on mio is
  the admission budget for bounded sends only (handler.rs:2794-2800), and
  there is no slab.

## 1. Send futures stay on their worker

The send futures become `!Send` and are renamed:

| before | after |
| --- | --- |
| `SendFuture` | `SendCompletion` |
| `BackpressuredSendFuture` | `BackpressuredSend` |

- `SendCompletion`, `BackpressuredSend`, `ForwardFuture`, `AsyncSendBuilder`
  and section 2's `Admission` hold `PhantomData<*const ()>`, as
  `RecvReadyFuture` does. Moving one to another thread is then a compile
  error, so its poll, its sends and its drop always run on the worker whose
  tables its ids index. `AsyncSendBuilder`, from `send_parts`, holds a
  `ConnId`: one made on worker 0 and used on worker 1 sent on worker 1's
  connection, through `build`, `submit_batch` or `submit_batch_await`
  (reproduced on mio after the futures were made `!Send`).
- The rename has two reasons. A `!Send` type named `SendFuture` reads as a
  statement about the `Send` trait. The name is also taken by
  `mpsc::SendFuture`. `SendCompletion` names what the future resolves on. No
  aliases are kept for the old names: 0.7.0 batches breaking changes
  (CLAUDE.md, API Design Principles).
- Every builder of a `SendFuture` returns `SendCompletion`. These are `send`,
  `send_chain`, `submit_batch_await` on both backends, and the forward path.
- With `!Send`, the one drop left outside the executor is a drop in the
  synchronous body of `on_accept`, which still leaves its entry
  (sc.rs:452-457). `send` and the other sends that return a future panic
  there, in `with_state` (io.rs:204-206). `send_backpressured` builds its
  future without runtime state (io.rs:1417-1424), but a `Fresh` future has no
  entry to leave. Reaching the case needs a waiting future made in a task and
  shared with the handler, for example through an `Rc` or thread-local
  storage. It is not handled.
- Code, tests, `ringline/README.md`, `docs/architecture.md` and the CHANGELOG's
  Unreleased entries take the new names. The released CHANGELOG entries, the
  other design docs and the journal keep the names they had. Outside `docs/`,
  tracked files name `SendFuture` 48 times and `BackpressuredSendFuture` 24
  times, counted with
  `git ls-files | grep -v -e '^docs/' -e 'runtime/channel\.rs$' -e 'tests/combinators\.rs$' | xargs grep -ow SendFuture | wc -l`.
  The count leaves out `mpsc::SendFuture` in `runtime/channel.rs` and a
  test-local alias in `tests/combinators.rs`, which keep their names.

Tests:

- `compile_fail` doctests that assert `!Send` for `SendCompletion`,
  `BackpressuredSend`, `ForwardFuture` and `AsyncSendBuilder`, as
  `RecvReadyFuture` has, and for `Admission`, which section 2 adds. The
  reproductions kept the future or the builder in a `static Mutex`, which no
  longer compiles.
- Each doctest fails with the `PhantomData` field removed, except io_uring's
  `ForwardFuture`, which is also `!Send` through the `SendCompletion` it holds
  in flight, and, since section 2, `BackpressuredSend`, which is `!Send`
  through the `Admission` or `SendCompletion` it holds.

## 2. `send_admitted`: a future that resolves on admission

```rust
impl SendHalf {
    /// Wait in the send-capacity FIFO, as `send_backpressured` does, and
    /// resolve once the send is admitted and queued, with a `SendCompletion`
    /// that resolves when it settles.
    pub fn send_admitted<'a>(&mut self, data: &'a [u8]) -> Admission<'a>;
}

/// Resolves to `io::Result<SendCompletion>`. `!Send` (section 1).
pub struct Admission<'a> { /* Fresh, Waiting(SendId), Done */ }
```

`Connection` gets the same method, as it mirrors `SendHalf`'s other sends
(io.rs:2880-2898).

`Admission` is `BackpressuredSend` with the `Submitted` state removed. On its
turn it calls `send_bounded` and `mark_send_submitted`, then resolves with a
`SendCompletion` built from the same `SendId`. Today's `SendFuture` is public
(io.rs:4168), and its constructor (io.rs:4184) takes a bounded id,
which has the same `InFlight` to `Done` lifecycle. A caller can then bound the
wait for capacity and the wait for the peer separately:

```rust
let sent = match timeout(admit_limit, tx.send_admitted(out)).await {
    Ok(Ok(sent)) => sent,
    Ok(Err(e)) => return Err(e), // refused, or the connection closed
    Err(_elapsed) => {
        // no capacity within the limit
        tx.close();
        return Ok(());
    }
};
if timeout(settle_limit, sent).await.is_err() {
    tx.close(); // the peer did not take the reply in time
}
```

- Every wait should carry a bound. An unbounded waiter at the head of the FIFO
  holds back every bounded send on the worker for as long as it waits.
- Cancellation: dropping the future while `Waiting` removes its entry and
  wakes the next head, as today. Once it has resolved, the send is queued;
  dropping the `SendCompletion` abandons the result, as dropping a
  `BackpressuredSend` in `Submitted` does (io.rs:4134-4152), and the
  bytes still go out.
- Byte order: after admission the bytes are in the connection's queue
  (handler.rs:970-1016 on io_uring, 2922-2947 on mio). A send made on the same
  connection while the future waits goes out ahead of it, as with
  `send_backpressured`.
- `send_backpressured` becomes `send_admitted` followed by awaiting the
  `SendCompletion`, with no change in behaviour.
- On mio, admission is the permit `send_bounded` takes, and settling is the
  last byte reaching the socket, as today.

A server that waits on every refused reply with a timeout makes the FIFO
longer and its cancellations more frequent, so removal stops scanning it.
`cancel` removes the entry from the table and `by_conn` and leaves its id in
`waiting`. Connection release marks a waiting entry `Aborted` and keeps it for
its future to collect (sc.rs:547-553), as today, and stops pruning `waiting`
with a full `retain` (`prune_waiting`, sc.rs:619-631). `fail_waiting` finds
its entries through `by_conn` instead of a `retain` over `waiting`. Before
each read of the head, `head_task`, `turn` and `head_ready` pop the ids at the
front that `prune_waiting` would drop: a slot whose generation differs, or an
entry that is no longer `Waiting`. `turn` takes `&mut self` for this. A
release that aborts the head still wakes the new head, as `prune_waiting` does
today (sc.rs:632-635). An admitted id is always the head, so `mark_submitted`
pops the front. Each id is pushed once and leaves once, popped at the front or
dropped by a `retain`. Once the stale ids in `waiting` number more than the
live ones plus 64, a `retain` drops them, so a head that waits while the
waiters behind it time out does not leave the list growing.

Tests, on both backends:

- `send_admitted` resolves while the send has not settled: a peer that has
  stopped reading, a backlog ahead of the send, and a free pool.
- The existing `send_backpressured` tests pass unchanged.
- With a test-only count of ids visited, cancelling the 64 waiters behind a
  head from the back of the FIFO leaves their ids in place and visits 64 ids,
  one read of the head per cancel. Admitting the head then visits 65: the
  head, and the 64 stale ids, popped once each. A search per cancel would
  visit more than 2,000.
- A connection released while its send is at the head of the FIFO, with no
  pool slots of its own, so no capacity wake follows: the next head is
  admitted without the aborted send's future being polled.
- Each test fails with its check mutated: the admission resolve point, the
  front pop, and the predicate the front pop uses.

Nothing in sections 1 and 2 depends on the kernel version. They run on CI's
kernel (GitHub runners, Linux 6.17, `.github/workflows/ci.yml:143`).

## 3. `abort`: release what a stalled connection's sends hold

Problem 4 needs a way to close a connection now, dropping its queued sends and
releasing their pool slots and slab entries. The contract the caller needs:

- queued, waiting and in-flight sends on the connection all fail with
  `ConnectionAborted`, whatever the kernel reported for them (`ECANCELED`,
  `EPIPE`, `ECONNRESET`), and a send that wins capacity after the abort gets
  `ConnectionAborted` too;
- a parked reader gets `ConnectionAborted`;
- no close_notify is sent, and on mio the queue is not flushed first
  (`finish_close` flushes and writes the alert, mdriver.rs:738-785);
- it applies to a connection that is already closing, which is problem 4's
  case, and does nothing once the connection's `Close` has been committed;
- callers use it in place of `close()` for a peer that has stopped reading.

```rust
impl SendHalf {
    /// Close the connection now, as the contract above describes.
    pub fn abort(&mut self);
}
```

`Connection` gets the same method.

### Mechanism, from Experiment A

Experiment A ran on Linux 6.8, 6.12 and 7.2, and its method, predictions and
results are in `docs/journal/2026-11-abort-close.md`, with the probe in
`experiments/abort-close-probe.c`. In short:

- `IORING_OP_CONNECT` with an `AF_UNSPEC` address, then the `Close`, reset the
  connection and released its zero-copy send within 0.2 ms on all three
  kernels, with 0, 1 and 256 other connections whose hangup polls were
  pending. The disconnect does not wait for the fixed file's release.
- Cancelling the connection's requests, setting `SO_LINGER {1, 0}` and closing
  released it at once with no other connections, and, with other
  connections' requests pending, at once only on 7.2. On 6.8 and 6.12 it was
  then released only once every request that other connections had pending
  before it had ended: not within
  5 s while they stayed pending, and as soon as the probe ended them by closing
  the idle peers (0.08 to 0.17 ms after closing one, 2.3 to 4.3 ms after
  starting to close 256).
- Closing, with or without `SO_LINGER`, while the connection's own hangup poll
  is pending released nothing on any kernel.

So `abort` uses the disconnect on every kernel. On io_uring, for a TCP
connection, plain or TLS:

1. The connection is marked closing (`Lifecycle::Closing`) before anything
   is pushed, and a parked reader is failed with `ConnectionAborted`, as
   `abort_connection` does (uloop.rs:3341). `abort` does this also when
   a close is already requested, where `abort_connection` returns early. The
   disconnect completes the connection's hangup poll and any armed receive,
   and their handlers drop completions for a connection that is not open
   (`handle_hangup_poll`, uloop.rs:1559; `handle_recv_direct`,
   uloop.rs:1236).
2. Its queued sends and its waiting bounded sends fail with
   `ConnectionAborted` and release their pool slots, an active send chain's
   accounting is cancelled, and a close_notify the pool retained is dropped,
   as `force_finalize_close` does (udriver.rs:2070-2110). A `SendPollOut` is
   cancelled first, as `submit_committed_close` does (udriver.rs:2024-2033).
   When step 3 commits the whole chain, pushed or refused and queued for
   retry, `close_submitted` is set and `close_pending` cleared, as
   `try_finalize_close` does before its push (udriver.rs:2003-2009), so
   nothing else submits a second `Close`.
3. An `IORING_OP_CONNECT` with an `AF_UNSPEC` address, the connection's
   normal close lead (`close_lead_for`, ring.rs:83) and the `Close` are pushed
   as one hard-linked chain of three through `Engine::push_chain`
   (engine/mod.rs:58), so the `Close` runs whether or not the disconnect
   succeeds. The connect has a completion tag of its own, whose handler
   ignores the result as the close leads' handlers do, so that it does not
   reach `handle_connect` (`submit_connect`, ring.rs:617). `push_chain`
   refuses a chain longer than the SQ, so config validation raises the SQ
   minimum to 4. If a `shutdown_write` `Shutdown` is still in the kernel
   (`shutdown_inflight`, udriver.rs:2189), the `Close` must wait for it,
   because the `Close` frees the slot it names (udriver.rs:1987-1993, #518).
   Then only the connect is pushed at once, since it frees nothing,
   `close_pending` is set (an open connection has none yet), and the
   `Shutdown`'s completion
   (`handle_shutdown`, uloop.rs:2800-2815) reaches `try_finalize_close`, which
   commits the lead and `Close` through `submit_committed_close`. The queue and
   any retained close_notify are already gone, so nothing is sent ahead of
   them. A refused chain, or a refused lone connect, is retried as itself: the
   connection's send state records that the close is an abort
   (`ConnSendState::disconnect`), so `submit_committed_close`, which
   `drain_close_retries` (uloop.rs:4935-4941) calls, pushes the chain again
   rather than the lead-and-`Close` pair, which would leave the zero-copy
   entries held. A refused lone connect has its own retry list
   (`pending_disconnect_retries`). In the `Shutdown` case the lone
   connect holds `try_finalize_close` until its completion lands, pushed at
   once or after a retry, as `shutdown_inflight` does. Its handler ignores
   the result, clears the hold and calls `defer_finalize_close`, as
   `handle_shutdown` does (uloop.rs:2813-2814), so the `Close` commits after
   the disconnect has run.
4. On TCP the disconnect returns 0 for an established, closing or
   peer-reset socket. It sends an RST unless the socket is already closed,
   and purges the socket's write queue,
   so the zero-copy notifications land and the slab entries and their paired
   pool slots are released. Only errors before the protocol is reached, such
   as `EBADF`, fail it. This is from the Linux 6.8 source (`tcp_disconnect`
   always returns 0), not a run. A send still in the kernel is expected to
   complete with an error, which `abort` reports as `ConnectionAborted`.
   Experiment A had none in flight at the disconnect, so this is not
   verified, and the tests below check it.
5. The `Close`'s completion releases the slot at once (`handle_close`,
   uloop.rs:4026). The kernel releases the socket later (before 6.13,
   after older requests on other connections end), but nothing the
   connection's sends hold waits for it.

On a Unix-domain connection, `abort` drops the queue and closes with the
normal lead, without a disconnect. Guarded sends there release at completion
(CLAUDE.md, the copies table), so nothing outlives the `Close`. The peer sees
end of file, or `ECONNRESET` if this end had received data it did not read.
Experiment A did not test a disconnect on a Unix-domain socket.

On mio, `abort` drops the queue on the open connection, as
`fail_connection_on_send_error` does (mio event_loop.rs:1341), returns the
queued sends' permits, sets `SO_LINGER {1, 0}` on the socket and closes it,
skipping `finish_close`'s flush and close_notify (mdriver.rs:738-785). The
socket is a normal descriptor there, so the setsockopt and close reset it on
every kernel; Experiment A did not cover mio.

Worker exit is unchanged. It cancels every connection's requests. A connection
holding no slab entry is closed at once with the `CancelAll` lead, and one
still holding entries after `ABORT_AFTER` (1 s) is closed with the `Abort`
lead (udriver.rs:117, 3221-3237, 3311-3326). Experiment A's batch arm is that
last step without the wait: the cancel, `SO_LINGER` and `Close` of all 257
connections submitted together, after which the target was released by the
first reap, 7.1 to 8.2 ms after the batch began on 6.8 and 6.12 and 3.2 to
3.7 ms on 7.2, and every idle client read `ECONNRESET` when checked just
after.

### Tests

- On one worker (`workers(1)`), so that both connections share a ring: a
  connection whose peer has stopped reading holds a zero-copy send, and
  another, idle connection has its hangup poll pending. `abort` returns the
  slab entry, its paired pool slot and the queued sends' slots within 100 ms,
  and the peer reads `ECONNRESET`. CI's 6.17 cannot tell the disconnect from
  the cancel-and-linger close here, so the test also runs on the rack's 6.8
  and 6.12 images through an `experiments/*-verify.toml` spec, red with the
  disconnect replaced by the cancel-and-linger close and green without.
- Queued, waiting and in-flight sends fail with `ConnectionAborted`, and a
  parked reader gets `ConnectionAborted`.
- `abort` after `close()` on a connection whose peer has stopped reading
  releases the same resources; `abort` after the `Close` is committed does
  nothing.
- A TLS connection sends no close_notify. A Unix-domain connection closes and
  its queued sends' pool slots are released.
- On mio, the peer reads `ECONNRESET`, no close_notify is written, and the
  permits return to the pool.
- Each test fails with its mechanism removed.

## 4. The fast path

Problems 2 and 3 are about replies sent without waiting. If every plain reply
goes through `send_admitted`, no plain reply overtakes another. TLS handshake
and close_notify records, guarded batches, forwards and chains still take pool
slots outside the FIFO. Strict order has two costs. Each reply pays a
completion-table entry and a FIFO enqueue even when the pool is free. And while
the free slots are fewer than the head needs, every reply waits behind the
head, with slots unused.

### Experiment B

Run after sections 2 and 3 are built.

- Instrument: `ringline-bench`'s two-machine echo setup, with the server's one
  worker pinned and saturated. Each arm takes the bytes with `with_bytes` and
  sends outside the closure, so the arms differ only in the send call.
- Arms:
  - `send_nowait`;
  - `send_admitted` with the `SendCompletion` dropped;
  - `send_admitted` with a `timeout` on settlement, as in section 2's example.
- Statistics: worker-thread CPU per operation (primary), and p99 at a fixed
  offered load below saturation.
- An A-against-A pair first for the noise floor, then four interleaved runs
  per arm.
- A contended case:
  - peers that do not read hold most of the pool;
  - one reply needing more slots than are free waits;
  - small replies arrive at a fixed rate;
  - in every arm, the server aborts connections whose replies do not settle
    within `settle_limit`;
  - the ratio of `admit_limit` to `settle_limit` is swept over 0.5, 1 and 2.

  Arms for the small replies: `send_admitted`, and `send`, which returns a
  `SendCompletion` the server can time but takes no place in the FIFO. The
  `send` arm isolates the cost of FIFO order. `send_nowait` is not used here,
  because it returns nothing to time and its server could not find the
  stalled peers.

  Measured: the small replies not delivered within `admit_limit`, whether
  refused, timed out or closed, and small-reply p99.
- Prediction:
  - Uncontended, the CPU per operation of each `send_admitted` arm is within
    the floor of `send_nowait`.
  - Contended, with `admit_limit` at or above `settle_limit`, `send_admitted`
    delivers no fewer small replies within the limit than `send`. Below it,
    fewer, because small replies wait behind the head until the stalled peers
    are aborted.
- Decision:
  - If both hold, the specification for this section covers only guarded
    batches. A server sends every plain reply with `send_admitted` and sets
    `admit_limit` at or above `settle_limit`.
  - Either of these rejects that: a CPU difference outside the floor, or
    fewer small replies delivered than with `send` at a ratio of 1 or more.
    The specification then adds tries under the constraints below.

Result (`docs/journal/2026-11-send-admission-b.md`): both conditions held.
Uncontended, at one saturated worker, `send_admitted` was higher than
`send_nowait` in 12 of 16 paired rounds, by a median of 1.7% of worker CPU per
operation. That is inside the floor, which cannot tell a cost of 1 to 2% from
none. Contended, at ratios of 1 and 2, `send_admitted` delivered every small
reply within `admit_limit`; `send` missed 4 in one of eight runs, to pool
refusals. The rule does not count latency: small replies sent with
`send_admitted` waited behind the head, p99 about 770 ms, where `send`'s p99
was 11.5 ms. The 11.5 ms was the load generator writing requests up to a timer
tick late; with requests written on time, Experiment C's C0 measured `send`'s
delay to admission at 0.4 ms at p99. The owner decided (2026-11-15) that a
server cannot accept that wait. Experiment C compares admission orders that let
a reply past a waiting head without starving the head. Experiment D tests the
design the owner chose for plaintext instead, which bounds what one send holds.

### Admission orders

Terms, for one worker: P is the pool's slots, F the free slots, H the slots
the FIFO's head needs, and S = P - H the slots other sends can hold while the
head still fits. A passing send is one admitted while an older waiter's
message did not fit. B is the slots passing sends hold. Line numbers in this
subsection and in Experiment C, except its list of constraints for each
outcome, are at 18a20526.

Every order except O1 admits a reply only once no earlier reply on its
connection waits, so each connection's replies keep their order.

- O0, strict FIFO, today's order: only the head is admitted, when F >= H.
- O1, small replies outside the FIFO: they are sent with `send`, and large
  replies wait in the FIFO. This is Experiment B's `send` arm. It is a
  control and cannot be chosen: `send` does not read the FIFO
  (io.rs:1409-1423), so a small reply can pass a large reply waiting on its
  own connection.
- O2, first fit: while the head does not fit, each waiter behind it that fits
  in F is admitted, oldest first.
- O3, bounded overtaking: as O2, but a send passes only while F + B < H.
  F + B is P less the slots held by sends that did not pass, so O3 lets sends
  pass while those other sends hold more than S, whatever the passing sends
  hold. A send outside the FIFO lowers F + B without passing. So once
  F + B >= H has held during a head's wait, nothing passes until that head
  is admitted or leaves. B counts a passing send's slots until they return,
  across changes of head. Under O3 the head waits about as long as under O0,
  plus at most the time the passing sends take to return their slots. A send to a
  peer that reads slowly holds its slots until the peer reads, or until the
  server aborts the connection after `settle_limit`.
- O4, bounded overtaking from idle connections: as O3, and a reply passes
  only if its connection has no send queued or in flight
  (`ConnSendState`'s `queue` and `in_flight`, handler.rs:16-18) and its last
  send did not wait for room in the socket (`wait_for_room`,
  uloop.rs:3089). The first condition alone always holds in a server that
  awaits each reply's settlement before reading the next request, as
  `admission-server` and the pattern under Non-goals do. The completion that
  settles a reply has already called `submit_next_queued`, which clears
  `in_flight` when the queue is empty (uloop.rs:3024-3034).
- O5, two pools. This is the author's reading of the owner's suggestion of
  parallel send rings, which the owner has not confirmed. A reply that fits
  one slot of a pool of small slots takes one. Every other reply takes slots
  of a second pool of large slots. The two pools together have the bytes of
  O0's single pool.
  - Each pool has its own FIFO, in strict order. A waiter whose connection
    has an earlier waiter in either pool joins neither FIFO until that waiter
    is admitted, so it never becomes a pool's head.
  - A small reply never waits behind a large head, and never takes its
    slots.
  - Neither pool takes the other's free slots, and a medium reply waits
    behind a large head in the large pool.
  - No TLS reply fits one slot, because its bound is the plaintext's records
    plus one (tls/mod.rs:665). Every TLS reply takes the large pool.
  - Which pool handshake and close_notify records take is left to the
    specification.
  - The send payload has 16 bits for the slot (completion.rs:296-298), so the
    two pools share one index space or take a bit from it.
  - A 7 MiB reply takes 448 slots of 16 KiB, or 7 of 1 MiB.
- O6, overtaking for a bounded time: as O2 for the first half of the head's
  `admit_limit`, then as O0 until the head changes. `send_admitted` does not
  take a deadline today.
- O7, a fixed budget: a send passes only while B plus its own slots is at
  most min(R, S), where R is a configured number of slots. The head is
  admitted no later than when the sends that did not pass hold S - R or
  fewer. That bound does not depend on how long the passing sends hold their
  slots.
- O7w: as O7, and a send passes only onto a connection that O4 would pass
  onto: no send queued or in flight, and its last settled send did not wait
  for room in the socket.

Earliest deadline first is not an order here. Every reply waits under the
same `admit_limit`, so deadlines sort the waiters in arrival order, as the
FIFO does.

What each order adds to the runtime:

| order | beyond O0 |
| --- | --- |
| O2 | a search behind the head (`turn` reads only the front, sc.rs:444-446); each connection's earliest waiter (`by_conn` keeps no order, sc.rs:198-204); a wake for a waiter that is not the head (`wake_send_capacity` wakes only the head, sc.rs:915-923) |
| O3 | O2's, and a mark on each slot a passing send takes, cleared in `SendCopyPool::release` (send_copy.rs:325), since an abort returns slots without `release_pool_slot`; a latch per head |
| O4 | O3's, and one bit per connection set in `wait_for_room` |
| O5 | a second pool, its configuration, and a pool bit in the send payload |
| O6 | O2's, and a deadline argument to `send_admitted` |
| O7 | O3's marks, without the latch, and R in the configuration |
| O7w | O7's, and O4's bit per connection |

`mark_submitted` already admits an id that is not the head
(sc.rs:457-470).

### Experiment C

Run after Experiment B. It chooses the order the fast-path specification
uses, in three stages.

- C0, on the rack, with today's code. `admission-server` and
  `admission-load` gain the instruments and the starvation case below, and
  run W1 and W2 under O0 and O1. C0 shows whether W2 reaches contention, and
  gives the floor between O0 runs for the head's delay. Its W2 runs are also
  C1's second validation.
- C1, a model. A discrete-event model of one worker's pool and its
  connections' socket buffers, a `ringline-bench` binary, sweeps every order
  over many more cells than the rack can run. It is validated against
  Experiment B's contended runs, which test little of it, since B's figures
  follow from the schedule (journal, Prediction). It is also validated
  against C0's W2 runs, which exercise draining. The model is used to reject
  orders and to choose the cells C2 runs, not to choose the order.
- C2, on the rack: the orders C1 does not reject, with O0 and O1, built on a
  work branch behind a hidden configuration option, not in ringline. O2, O3 and
  O7 are small changes to the FIFO, so C2 builds them whatever C1 finds.

Instruments, in `admission-server` and `admission-load`:

- A request carries its scheduled send time (`CLOCK_MONOTONIC`, which client
  and server share on loopback). The server records each reply's delay from
  that time to its admission. Measured from the first poll of
  `send_admitted`, a reply on a connection that answers one request at a
  time would not include the time its request waited unread behind the
  connection's previous reply. The client still records end-to-end latency,
  as in Experiment B.
- Every 10 ms the server samples the slots held by unsettled small replies.
  L is their mean over a head's wait, from its request to its admission or
  removal.
- Per head: its admission delay, or a timeout, which is counted apart from
  the delays.
- C2 only: each send admitted past a head, with its slots and the time it
  held them (C2's harness, not in ringline).
- `--pipeline N`: up to N unsettled replies per connection. Each is timed
  from when it was queued or, if later, from when the reply before it
  settled, and the connection is aborted when the oldest has been unsettled
  for `settle_limit`. This is the shape of the cache server this design is
  for. With N = 1 the server is Experiment B's.

Workloads, each cell one experiment in its own guest, as in Experiment B's
contended runs, four repetitions:

- W1: Experiment B's contended case: three stalled peers asking for 3 MiB
  each, a 7 MiB head 200 ms later, and 256 B small replies to fast readers at
  2,000/s on 16 connections. The pool is 512 x 16 KiB, `tcp_wmem` is capped at
  1 MiB, `settle_limit` is 1 s, the ratio of `admit_limit` to it is 1 or 2,
  and N is 1 or 16. One further cell adds sends outside the FIFO
  (`send_nowait`, 1,000/s on four connections).
- W2, the starvation case, with no stalled peers. Each episode, connections
  that read at a fixed rate ask for 2 MiB replies and hold most of the pool
  for a drain time below `settle_limit`. The head needs 448 or 256 slots and
  waits for them. N is 16, `tcp_wmem` is capped at 256 KiB, and the ratio is
  1 or 2. Slow readers on small-reply connections pipeline 4 KiB requests and
  read slowly enough to hold L slots: L / S of 0, 0.5 and 1.5. L / S of 0 is
  the negative control, where every order must admit every head. The read
  rates and the number of slow readers are set by C0's pilots under O1, so
  that L reaches each target; the pilots are recorded in the journal.
- Two extra repetitions of O0 in each cell give the floor between O0 runs.

Statistics:

- small replies to fast readers: the p99 of the delay from scheduled time to
  admission, and the count beyond `admit_limit`;
- the head: the median and maximum admission delay (a cell has about 40
  heads, so its p99 is the maximum), and its timeouts;
- L, and in C2 the hold times of passing sends.

Prediction (the author's, written before C0 runs):

- O2 times heads out in W2 at L / S of 1.5, as O1 does.
- O3 times heads out in W2 at L / S of 1.5 at a ratio of 1, and not at a
  ratio of 2. Passing sends to slow readers hold their slots for up to
  `settle_limit`, and only a ratio of 2 covers O0's wait plus that.
- O4's maximum head delay is within 10 ms of O0's in every contended cell,
  and its small-reply p99 in W1 is at most 10 ms.
- O5 admits heads as O0 does, and small replies as O1 does while the small
  pool has free slots.
- O7's maximum head delay exceeds O0's by at most the time the large holders
  take to return R slots. In W2 its small replies wait behind the head once
  slow readers hold R.

The owner's prediction, which names no cell, is that O3 starves a large head.
C tests it in every contended cell. It is refuted if, in every one, O3 has no
more head timeouts than O0, and its maximum head delay exceeds O0's by at most
the longest hold of a send that passed it.

Decision:

- A W2 cell is contended if O1 timed out at least one head in it. If no W2
  cell with L / S of 1.5 is contended, the experiment stops, and its result
  goes to the owner before anything is decided.
- An order passes when, in every W1 cell and every contended W2 cell:
  - it has no more head timeouts than O0;
  - its maximum head delay exceeds O0's by at most the larger of 10% and the
    spread between O0 runs;
  - its count of small replies beyond `admit_limit` is no more than O0's;
  - in W1, its small-reply p99 is at most 10 ms.

  It must also admit every head at L / S of 0, and its uncontended CPU per
  operation must be within the floor of O0's, in Experiment B's echo
  comparison.
- The specification uses the passing order that adds least, by the table
  above, for TLS connections, and for plaintext if Experiment D's gated
  pieces do not pass. O1 cannot be chosen. If no order passes, the result
  goes to the owner.

Result (`docs/journal/2026-11-send-admission-c.md`): the rule passed O4, O5
and O7w. Its tie-break did not rank them, since the table had no O7w row when
it was applied. The owner chose O7w for TLS, and Experiment D's design for
plaintext.

If Experiment C chooses an order other than O0, a waiting form covers the
fast path: `send_admitted` resolves on its first poll whenever the order
admits it, and tries are not needed. The constraints on tries apply if it
does not.

Constraints already found for each outcome (line numbers in this list are at
07dd0f56):

- Guarded batches, in either outcome. A waiting form waits only for the
  batch's own pool cost (at most one slot on a plain connection, the
  ciphertext bound on TLS) and takes the slab entry when it is submitted. With
  no free entry it refuses and returns the parts. The checks run before any
  guard is consumed. `submit_tls` gathers and drops the guards before its
  ciphertext check (handler.rs:3976-3999), and `send_slab.allocate` drops
  them when no entry is free (handler.rs:4101-4120). Copying a refused guarded
  1 MiB reply instead costs 64 slots where the batch needed one.
- Tries, if they are needed:
  - A try returns a `SendCompletion`, as `send` does, so the caller can time
    settlement and find the connections whose peers have stopped reading.
  - A try refuses while its own connection has a waiter, so replies on one
    connection keep their order (`by_conn` indexes entries per connection,
    sc.rs:163-165).
  - A try refuses when the free slots less the FIFO head's need do not cover
    it. While stalled peers hold the pool, that refusal lasts until the head
    is admitted or times out, and the head's need can be the whole pool
    (`bounded_send_slots` refuses only `needed > capacity`, handler.rs:284).
    The specification sets the result that would drop this rule. In
    Experiment B's contended case the head needed 448 of 512 slots and the
    stalled peers held most of the pool, so the free slots stayed below the
    head's need, and a try under this rule would have been refused until the
    head was admitted or timed out.
  - A refused batch's error is `#[non_exhaustive]`, carries an `io::Error`
    case, returns the parts on every refusal, and converts to an `io::Error`
    whose pool and slab refusals are `WouldBlock`. Nothing wakes a caller after
    `WouldBlock`; the way to wait is `send_admitted`.

### Experiment D

The owner decided on 2026-11-15 that for plaintext the fast path bounds what
one send holds, instead of choosing an admission order. Large replies are
sent in pieces, and a piece takes pool slots only once its socket has room
for it. Values are sent zero-copy where they can be, and guarded batches wait
in the FIFO for their own pool cost (Constraints, above). Experiment D tests
the pieces and the gate on socket room. Experiment C's orders are the
fallback, and cover TLS.

What holds slots today:

- A copied send of n bytes takes ceil(n / slot_size) slots. It is queued as
  one entry per slot and sent in runs of up to 32 slots (`send_slab.rs`). A
  partial send advances the run and waits for room, and the run's slots return
  together once all of it is sent (the `try_advance` branch of the io_uring
  send completion). A send whose peer stops reading holds the runs its socket
  has not taken: h slots, a multiple of a run.
- A whole reply is admitted only when all its slots are free (`head_ready` in
  `send_completion.rs`), and under O7w a waiter that needs more than R slots
  never passes. So stalled whole replies stop being admitted once fewer than
  their slots are free, and the replies waiting behind them hold nothing. In
  W1, three 3 MiB stalled replies are admitted and hold 384 to 480 slots, and
  the fourth waits at the head. Small replies wait behind it under O0 and pass
  it under O7w, whatever the number of stalled peers.

Pieces, as D's harness (not in ringline) sends them, with `--stream-piece p`
and `--stream-gate` for the gate:

- A reply of more than p bytes is sent as ceil(n / p) pieces, one unsettled at
  a time. The pieces count as one reply against `--pipeline N`.
- With the gate, every piece first waits until its socket reports `POLLOUT`,
  then waits in `send_admitted` for its slots, under `admit_limit`. Gating only
  the pieces that follow a send that waited for room would let each stalled
  peer's first piece into a full socket.
- The gate is `SendHalf::writable`, a hidden method built for D and not yet in
  ringline. On io_uring it uses the connection's `SendPollOut`, the poll the
  wait for room uses, so the cancel that `close` and `abort` already issue
  covers it, and a pending poll cannot hold the socket past its `Close`. With
  no poll armed, the gate arms it one-shot; today a `POLLOUT` that arrives with
  no send waiting is dropped, and `handle_send_pollout` instead wakes a waiting
  gate. The gate resolves on `POLLOUT`, fails on `POLLERR` or `POLLHUP`, and is
  failed by `abort` as a parked reader is. After the peer half-closes, a
  one-shot poll completes at once with `POLLRDHUP`, so the connection's poll
  becomes multishot, as for the wait for room. A multishot poll reports only
  edges, so on such a connection the gate first arms a one-shot probe with its
  own tag. The probe completes at once, with `POLLOUT` only if the socket is
  writable now, so it never stays pending. When the socket is not writable,
  `tcp_poll` sets `SOCK_NOSPACE`, and the multishot poll reports the next
  `POLLOUT`. The gate resolves on the probe's `POLLOUT`, or else on the
  multishot poll's next one. On mio the gate polls with a zero timeout, then
  waits for the connection's next writable event. Its tests cover a socket
  already writable, a full socket that drains, a half-closed peer with a full
  socket, filled by a short send and filled by whole sends, an abort and a peer
  reset while waiting, and a connection whose multishot poll is already armed.
- TCP reports `POLLOUT` when `wmem_queued` is at most two thirds of
  `sk_sndbuf` (`sk_stream_is_writeable`), and `tcp_sendmsg` queues while
  `wmem_queued` is below `sk_sndbuf`, checking only before it starts a new
  segment. Both count truesize: payload plus per-segment overhead. A piece is
  sure to go in whole when its truesize fits in a third of `sk_sndbuf`. A
  larger piece goes in whole when the gate opens with less queued, which is
  always the case for a stalled peer's first pieces and never for a reader
  that keeps its buffer near two thirds full. On loopback `sk_sndbuf` grows to
  the `tcp_wmem` maximum at the handshake, so a third is about 341 KiB at
  1 MiB and about 85 KiB at W2's 256 KiB. Small segments add overhead: a peer
  with a 4 KiB receive window gets about 2 KiB segments, about 61% payload
  (derived from the kernel source, not measured). A piece that does not go in
  whole holds its slots until the socket takes the rest, as an ungated piece
  does. To a reader that drains, that is until it has read enough for the
  socket to take the rest; to a stalled peer, until `settle_limit`.
- The wait for room is bounded by `settle_limit`, and a socket that stays
  unwritable that long is aborted. The gate opens again once the reader has
  taken about one piece, so a reader is aborted when it takes less than about
  one piece in `settle_limit`: 128 KiB/s with 128 KiB pieces and a 1 s limit.
  Without the gate a piece follows a full buffer, and the floor is about a
  third of the buffer: 340 KiB/s at 1 MiB. With whole replies it is about
  (n - X) / `settle_limit`, where X is what the socket accepts: about 2 MiB/s
  for a 3 MiB reply. A reader between the gated floor and that is served with
  gated pieces. It holds up to two thirds of its send buffer and a piece of
  kernel memory, and no pool slots, for n / rate seconds: 24 s for 3 MiB at
  128 KiB/s.
- A reply's total time is bounded by ceil(n / p) x (`admit_limit` + 2 x
  `settle_limit`): for each piece, the wait for room, for slots, and for a
  partly sent piece to settle.
- After its first piece, a reply that fails aborts its connection. The peer
  has a prefix, and a FIN after it would read as a complete reply in a
  protocol delimited by close, so section 2's `close()` on an admission
  timeout does not apply. Once a reply's first piece is out, a server cannot
  send an error reply in its place.
- Without the gate, a piece takes slots as soon as the one before it
  settles. A stalled peer's piece is admitted while its socket looked
  writable, is partly sent, and holds its run, h_p slots (8 for a 128 KiB
  piece), until `settle_limit`. Under O0, small replies then wait once k
  stalled peers hold so much that the head's piece does not fit:
  k x h_p + ceil(p / slot_size) > P, k > 63 at 128 KiB. Under O7w they pass the
  waiting piece while any slots are free. This arm shows what the gate does.

Arms, in C2's harness, N = 16, a ratio of 1, R = 32, all on D's binaries:

- O0, whole replies: the control shared with Experiment C, rerun because
  C2's runs predate D's instruments.
- O7w, whole replies.
- O0, pieces of 128 KiB without the gate.
- O0, gated pieces of 64 KiB, and of 128 KiB.
- The order Experiment C chooses, with gated pieces of 128 KiB, run after C's
  decision. The order is set per worker, so if TLS on the same worker uses
  C's order, plaintext pieces run under it.

Before the matrix, a calibration run on io_uring confirms h for a stalled
3 MiB whole reply and h_p for an ungated stalled piece, from the runtime's
free-slot count, with one to three stalled peers. It also records
`ss -tmi` (`sk_sndbuf`, `wmem_queued`) for a stalled socket and for a drainer
with a 4 KiB receive window, where the truesize ratio matters, and the image's
`rmem_max` and `wmem_max`. W4's values of k follow from it.

Workloads, four repetitions, with two extra repetitions of O0 whole:

- U, uncontended: a closed loop of at least 1,000 7 MiB replies per run to one
  reader that reads as fast as it can, with `SO_RCVBUF` set to 512 KiB, which
  the kernel doubles to 1 MiB (`rmem_max` raised so that it takes effect, and
  the value `getsockopt` reports printed), so that loopback's autotuning does
  not hide gaps between pieces, and nothing else running. Per run: the median
  and p99 time per reply in microseconds, and the worker thread's CPU per
  reply from its schedstat, as in Experiment B. Each arm is compared with
  whole replies and with the spread between O0 whole's own runs, and the cost
  of one piece is the difference divided by the number of pieces.
- W1, and W2 with six slow readers (L / S of 1.5), as in Experiment C. Pieces
  alone keep each connection to one piece here, so these cells check that
  pieces cost nothing under contention; they do not test the gate.
- W4, stalled peers: W1 with k stalled peers, at k = 4, either side of the
  ungated arm's limit, and 128, with `tcp_wmem` at 1 MiB. One more cell at
  k = 128 with `tcp_wmem` at 256 KiB, a third of which is smaller than a
  128 KiB piece.
- W5, slow readers of large replies: W1 with four readers taking 512 KiB/s
  that each ask for 3 MiB, in place of the stalled peers, with 8 s episodes
  and an 80 s duration, so that a 3 MiB reply (6 s) completes within an
  episode.

Statistics, beyond Experiment C's, from instruments built for D and not in
ringline:

- per 7 MiB reply, and in W5 per slow reader's 3 MiB reply: whether it
  completed, and the time from its request to its last byte at the client, in
  microseconds. A reply did not complete if the client did not receive all of
  it, any of its pieces timed out waiting for slots or for room, or its
  connection was aborted. Completion times are taken over completed replies;
  the rest are counted.
- the pool's free slots every 10 ms (`SendAdmissionCounters::main_free`),
  every sample kept, and the smallest from each 7 MiB reply's request to its
  last byte;
- per piece, whether it waited for room, from a new hidden flag on its
  `SendCompletion` that every call of the wait for room sets, including a send
  refused with `EAGAIN` before any byte went in, read as `passed_head()` is;
- aborts by cause: admission timeout, room-wait timeout, settlement timeout,
  peer reset;
- `/proc/net/sockstat` and `TcpExtTCPMemoryPressures` per run, so that memory
  pressure, which shrinks `sk_sndbuf` and the gate's third with it, would show.

Prediction (the author's, before C1 or the rack runs it):

- U: I do not know the cost of a piece well enough to predict it closely. On
  loopback a reader drains 128 KiB in tens of microseconds, about the time a
  piece takes to settle, wake its task, poll and be admitted, so I expect
  gated pieces of 128 KiB to take up to 50% longer than a whole reply, and
  pieces of 64 KiB longer still.
- W1 and W2: every gated arm keeps fast small replies' p99 below 1 ms and
  completes every 7 MiB reply.
- W4 at 1 MiB: every gated arm keeps fast small replies' p99 below 1 ms,
  completes every 7 MiB reply at every k, and keeps at least 3/4 of the pool
  free during each. The ungated arm's fast small p99 exceeds 100 ms once
  k x h_p + 8 > 512. O0 whole makes small replies wait behind the fourth
  stalled reply at every k, and O7w whole keeps them below 1 ms at every k.
  C1 predicts whether the whole arms complete the 7 MiB reply at k >= 4.
- W4 at 256 KiB: both gated arms keep 3/4 of the pool free. A stalled peer's
  socket takes its first pieces whole, more than two thirds of 256 KiB, and its
  gate then stays closed, so its pieces hold no slots. For 128 KiB pieces this
  is derived, with a margin of less than one segment: the second piece's last
  segment starts at about 236 KiB of 256 KiB.
- Partial sends: in W4 no stalled peer's gated piece waits for room. In W2,
  where drainers keep their buffers near two thirds of 256 KiB full, every
  128 KiB piece to a drainer after the first waits for room, and most 64 KiB
  pieces do too, each until the drainer reads the rest.
- W5: every gated arm completes the slow readers' replies and the 7 MiB reply
  with no aborts, and keeps fast small replies' p99 below 1 ms. Both whole
  arms abort the slow readers.
- Refuted if, in any cell, a gated arm's fast small p99 exceeds 10 ms, it
  fails to complete a 7 MiB reply or a W5 slow reader's reply, less than 3/4
  of the pool is free during a 7 MiB reply in W4, or a stalled peer's gated
  piece waits for room in W4.

C1's model gains pieces, the gate as a wait for a third of the socket buffer
to be free, and stalled requests written one after another as
`admission-load` writes them, in place of all at once. It checks the
arithmetic above and the cells before the rack runs.

Decision:

- Gated pieces are used for plaintext by the fast-path specification if a
  gated arm, in W1, W2, W4 at 1 MiB and W5, completes every 7 MiB reply and
  every W5 slow reader's reply, keeps fast small replies' p99 at or below
  10 ms, and has no more fast small replies beyond `admit_limit` than O0
  whole. The specification then uses the larger passing p, under O0, or under
  Experiment C's order if TLS on the same worker uses it. How it sizes p
  against a socket's send buffer follows from the partial sends measured in
  each cell.
- U's cost is reported with the decision, as worker CPU per byte against
  whole replies. A gated arm that costs more than twice as much per byte goes
  to the owner before it is chosen.
- Small replies are not gated, so a connection that pipelines small requests
  and stops reading still holds its unsettled small replies' slots (Non-goals).
- Otherwise the result goes to the owner, and Experiment C's outcome stands
  for plaintext too.

Not tested here:

- zero-copy pieces, which hold their memory until the peer acknowledges them,
  so the gate bounds the socket's share and not the arena's. Each also takes a
  send-slab entry, of which a worker has 512 by default; how many a stalled
  peer would hold is not checked;
- TLS, where a piece's ciphertext is copied into slots as a whole reply's is;
- a network between server and client, where `sk_sndbuf` starts near 85 KiB
  and grows with the congestion window, so pieces of 64 or 128 KiB can be
  partly sent early in a connection;
- mio: `writable` is built and tested on it, and not run on the rack;
- `TCP_NOTSENT_LOWAT`, which would cap a stalled socket's unsent payload at a
  chosen value and make the fit exact in bytes while the buffer has room;
- guarded batches waiting in the FIFO.

### The fast-path specification

Proposed on 2026-11-16, from Experiments C and D. It is built in three pull
requests, one per part below, each with its own tests. The owner decided the
choices it rests on: gated pieces for plaintext, O7w for TLS, and guarded
batches that wait in the FIFO for their own pool cost (Experiment D's opening
paragraph), and on 2026-11-16 the API decisions listed under Decisions.

#### Part 1: the gate, `writable`

`SendHalf::writable` and `Connection::writable` become public. The code is the
gate Experiment D ran, which is not in ringline, plus the fixes made after D's
matrix (a busy loop on a resubmit, a gate that armed against a send still in
the kernel, a reset that no longer woke the gate, and a completion that closes
the connection dropping the connection's own task with its gate unresolved). It
was written on a work branch based on main before #965, together with
Experiment C's orders, so this part is a port onto main, not a change of
visibility. The port carries the gate and the hidden `waited_for_room` that the
gate's tests read, and none of the orders. The fixes after D's last review are
unreviewed (journal D). Its tests are the gate's event-loop unit tests and
`tests/writable_gate.rs`, run on the rack's 6.8, 6.12 and 7.3 images as section
3's were. The part is done when they pass there, each fix's test fails with
that fix reverted, and the existing suite passes unchanged; `send_buffer_size`
returns, on both backends, the send buffer `ss -tmi` reports as `tb`; and a
`compile_fail` doctest shows that a second `writable` on one half does not
compile.

- It resolves `Ok` once the socket reports `POLLOUT`, after every send the
  connection has queued has been handed to the kernel (io_uring) or written
  (mio). It sends nothing and takes no pool slot.
- It fails on `POLLERR` or `POLLHUP`, on `abort` (`ConnectionAborted`), on a
  close requested or committed, and on a write half that is shut down
  (`BrokenPipe`), with the error kinds of its doc comment on the gate's
  branch.
- It has no bound of its own. A caller bounds it with `ringline::timeout` and
  treats a timeout as the room-wait timeout of Experiment D: it aborts the
  connection once any piece of the reply has been sent.
- The future borrows its half mutably, so a second `writable` on the same
  half while one waits does not compile. On the branch it borrows nothing,
  and dropping the registered one of two futures left the other unwoken.
- `SendHalf::send_buffer_size` and `Connection::send_buffer_size` return the
  socket's `SO_SNDBUF` (the kernel's `sk_sndbuf`). It is a future on both
  backends, since on io_uring it is a round trip through the ring: it installs
  a real descriptor for the fixed file (`IORING_OP_FIXED_FD_INSTALL`), reads
  the option and closes the descriptor; on mio it reads the `TcpStream`'s. A
  server sizes its pieces as min(`send_buffer_size` / 3, 128 KiB), Experiment
  D's recommendation, read per reply since the buffer grows with the
  connection.
- A gate does not wait for a send that waits in the FIFO on its connection.
  Such a send, admitted after the gate opens, can take the room a piece was
  gated for; bytes stay in order, but the piece may not go in whole.

A server sends a plaintext reply of n bytes larger than p as ceil(n / p)
pieces. Before each piece it awaits `writable`, then `send_admitted` for the
piece under `admit_limit`, then the piece's `SendCompletion` before the next
piece. This is the sequence Experiment D's harness ran. The caller forms the
pieces (Decisions). A reply that fails after its first piece is sent
aborts its connection (Experiment D, "After its first piece"). With pieces
formed by the caller, ringline documents this rule and cannot enforce it: a
caller that calls `close()` after a prefix sends a FIN, which a protocol
delimited by close reads as a complete reply.

#### Part 2: O7w, the default order

The send pool gets one admission order besides strict FIFO: O7w, with a budget
R of slots. It is the default, at R = 32. `ConfigBuilder` takes a
`#[non_exhaustive]` order enum, strict or O7w with R. R must be at least 1,
or the configuration is refused; an R above the pool's slots admits as R = P
does, since a waiter passes only within min(R, S). A waiter passes a
head that does not fit only while the slots held by passing sends plus its own
are at most min(R, S), and only onto a connection with no send queued or in
flight whose last settled send did not wait for room. Experiment C ran it at
R = 32 of 512 slots, and Experiment D's O7w arm with gated 128 KiB plaintext
pieces passed.

- The order is per worker, since the pool is. With O7w on, plaintext pieces
  on that worker run under it too, as in D's O7w arm.
- The code is the `BudgetIdle` order from Experiment C's work branch, which is
  not in ringline, without the other orders. That includes the marks on slots
  held by passing sends and their release paths, the search behind the head and
  its wake, oldest-first admission, each connection's earliest waiter, the
  expiry of a woken waiter's claim, the exclusion of a forced close_notify from
  B, and the room-wait state per connection (`room_waited` and `send_waited`,
  and on mio `waited_entries`), kept only while the order is on. The two
  backends count different sends as having waited when replies are pipelined.
- On the branches `SendCompletion::passed_head`, `waited_for_room` and the
  admission counters are `#[doc(hidden)] pub`, and stay so (Decisions).
- Neither Experiment C nor D sent TLS replies. Under O7w a TLS reply is a
  whole reply: in D, O7w with whole replies completed no 7 MiB reply in W4 or
  W5, and its fast small p99 was 25.4 ms in W4 at 256 KiB. A TLS reply needs
  at least two slots, so R admits fewer TLS passers than plaintext ones.
- The part is done when C2's seven cells and the W1 cell with sends outside
  the FIFO, rerun on the ported code, give, under O7w, each cell's largest
  head delay within the larger of 10% of C2's O7w figure and the spread
  between O0's runs in that cell (journal C), and fast small p99 within
  0.3 ms of C2's O7w median (for the cell with sends outside the FIFO, within
  C2's range over the passing orders, 810.2 to 811.2 ms and 0.5 to 0.6 ms);
  under strict order, the same against C2's O0 figures; and the echo check
  puts the default build within the floor of main.
- Because O7w is the default and C and D sent no TLS replies,
  `admission-server` and `admission-load` gain TLS, with a pool slot of at
  least one whole record (16,413 bytes; `validate_tls_slot_size` refuses C's
  16 KiB), and the W1 and W2 cells run once with TLS under both orders. By two
  of C's conditions, O7w must time out no more heads than strict order and
  keep W1's fast small p99 at or below 10 ms. Otherwise the default goes back
  to the owner before the pull request merges.
- Part 2's runs, against these criteria, are in
  `docs/journal/2026-11-send-admission-o7w.md`.

#### Part 3: guarded batches that wait

A new method beside `AsyncSendBuilder::submit_batch`, which is unchanged,
waits in the FIFO for the batch's own pool cost, as `send_admitted` waits for
a copied send's. Its refusal is a new `#[non_exhaustive]` error that returns
every part; it converts to an `io::Error`, dropping the parts, for a caller
that does not want them back.

- The pool cost is that of the copy parts: at most one slot on a plaintext
  connection, and the ciphertext bound on TLS. A batch below
  `send_zc_threshold` takes one slot or goes zero-copy (handler.rs:3624-3632).
  On a plaintext connection, a batch whose copy parts are empty joins no FIFO
  and is submitted at once; one with copy parts waits for one slot. On TLS
  every part is copied, and the batch waits for the ciphertext bound of its
  total length.
- The send-slab entry is not part of the FIFO's admission (Alternatives). It
  is taken when the batch is admitted, and a full slab then refuses the
  batch.
- On mio, where `submit_batch` copies the whole batch and takes no slots,
  the method waits as `send_admitted` does for the batch's total length.
- A refusal returns every part to the caller, guards included, and every
  check runs before any guard is consumed. On main every refusal of
  `submit_batch` drops its parts: the empty batch, the builder's limits, a
  stale or closing connection, TLS (which gathers the guards before its
  capacity check), a guard outside its registered region, copy parts over
  one slot, pool exhaustion and the slab (io.rs:1772-1820,
  handler.rs:3570-3855).
- Nothing wakes a caller after a slab refusal; releasing an entry wakes
  nothing. A caller copies the same bytes or aborts.
- The part is done when a test of each refusal path gets every part back,
  a batch that waits is admitted when its slots return, and each of those
  tests fails with its check moved after the guards are consumed.

#### What the parts do not cover

These are untested, and each is a limit of the specification as written:

- zero-copy pieces, which hold their memory until the peer acknowledges them,
  and a send-slab entry each: a stalled peer's socket takes gated pieces until
  it is about two thirds full, about six 128 KiB pieces at 1 MiB, so about 85
  stalled peers would hold the default 512 entries (derived, not measured),
  and other connections' guarded batches would then be refused;
- TLS replies in pieces;
- a network between server and client, where `sk_sndbuf` starts near 85 KiB
  and grows with the congestion window, so a piece can be partly sent early
  in a connection;
- mio under load: `writable` is tested on mio but did not run on the rack;
- small replies to a peer that pipelines and stops reading, which still hold
  their slots until `settle_limit` (Non-goals).

#### Decisions

Made by the owner on 2026-11-16:

- O7w is on by default at R = 32, set through a `#[non_exhaustive]` order
  enum (Part 2).
- Pieces are sized from a new `send_buffer_size` accessor (Part 1).
- `writable` borrows its half mutably (Part 1).
- A waiting batch's refusal returns its parts (Part 3).

Not asked, and followed as recommended until the owner says otherwise:

- The caller forms the pieces. Its code has its framing and chooses which
  values go zero-copy. A ringline method that sends one buffer as gated
  pieces can be added later without breaking callers.
- `SendCompletion::waited_for_room`, `passed_head` and the admission
  counters stay `#[doc(hidden)] pub`: the gate's integration tests and the
  experiments' harness read them.

## Alternatives considered

- Keeping the send futures `Send` and checking the owner, as the disk-I/O
  futures do (ringline/src/fs.rs:601-644): record `current_worker()` at
  creation, stay pending on another worker, and route a foreign drop's cancel
  to the owner. The disk-I/O futures leave their entry instead, and a waiting
  entry left at the head of the FIFO would hold back every bounded send on the
  owner. That needs a second list in each worker's `Inbox` (waker.rs:47-56)
  with its own wake and a drain in `collect_wakeups`. It also needs owner
  checks in both `SendFuture` constructors, since one built holding its result
  works on any thread today. No caller in the workspace, and none in the
  server this design is for, moves these futures between threads.
- Strict refusal of tries while anything waits. A waiter that cannot be
  admitted soon holds back every fast-path send even with most of the pool
  free.
- An occupancy accessor in place of tries. Each caller would apply the rule
  itself.
- Slab entries in FIFO admission. The slab is taken outside the FIFO by
  coalesced runs, which run in completion handlers before woken tasks are
  polled (uloop.rs:539, 621, 730), and by forwards. Releasing a guard-only
  entry wakes nothing (`wake_send_capacity` counts pool slots, sc.rs:792-800),
  and a peer that does not read holds its entries. A batch at the head waiting
  for an entry would hold back every send on the worker. Today only that batch
  fails.
- A progress-based stall deadline in ringline. A chain part is sent with
  `MSG_WAITALL` and completes only when all of it is in the socket
  (completion.rs:10-17). A send waiting for room is retried once a second
  (`SEND_BACKSTOP_INTERVAL`, udriver.rs:421-423), and `POLLOUT` needs half of
  `wmem_queued` free. A slow reader can show no progress for longer than a
  short deadline. A per-iteration scan over connections has cost about 25% of
  worker CPU before (uloop.rs:5037-5044).
- A deadline on every `close()`. `half-closed-send-wait-design.md:195-200`
  rejected it because a FIN called `close_connection`. Since
  `half-close-design.md`, a FIN closes nothing, except a TLS FIN before the
  handshake completes (`half-close-design.md:41-50`). A deadline on every
  close would still cut the tail off a slow reader that a caller closed after
  its last reply.
- Admitting a large plain send a slot at a time (`send_inner` already copies
  per slot, handler.rs:597-665). The admission point would then include the
  connection's own drain, which is problem 1. Experiment D's gated pieces keep
  the two waits apart: a piece waits for room in its socket, under
  `settle_limit`, before it waits for slots, under `admit_limit`.

## Non-goals

- One connection's share of the pool. A client that pipelines and reads slowly
  can hold many admitted replies. A caller bounds this by awaiting a reply's
  `SendCompletion` before admitting the next on the same connection.
- Slab use by coalesced runs and forwards.
- Changes to `send`, `submit_batch` and `close()`.

## Order of work

1. Section 1: the send futures become `!Send` and are renamed. It fixes
   problem 5 and can land without the other sections.
2. Section 2, `send_admitted`, with `send_backpressured` rewritten on it and
   removal from the FIFO without a scan. This ends the false closes of
   problem 1.
3. Section 3, `abort`, as specified from Experiment A. Its tests run on the
   rack's 6.8, 6.12 and 7.2 images through `experiments/abort-verify.toml`.
4. Experiment B, then Experiments C and D, then the fast-path specification
   (section 4), built in three pull requests: the gate, O7w, and guarded
   batches that wait.

## What a caller can no longer do

Section 1 removes three things, each a compile error:

- Moving `SendCompletion`, `BackpressuredSend` or `ForwardFuture` to another
  thread, or keeping one in a `Send` container. Moving a waiting one sent its
  bytes on the wrong connection. Moving one built already holding its result
  (from a `send_chain` that submitted nothing, on io_uring, io.rs:1480)
  worked.
- Naming `SendFuture` or `BackpressuredSendFuture`. The types are renamed and
  no aliases are kept.
- Requiring `Send` of a user future that holds one of them across an `.await`.
  A task that also holds a `SendHalf` was `!Send` already.

Section 2 adds API and changes no existing behaviour.

Section 3 raises the smallest `sq_entries` from 2 to 4, the smallest power of
two that holds `abort`'s chain of three: a config with 2 now fails validation.
On io_uring a bounded send on a connection whose `Close` is committed now
fails with `NotConnected` before it joins the FIFO, as it already did on a TLS
connection whose close_notify was queued. Before, it joined the FIFO and was
refused when it won capacity, and with the write half also shut down it failed
with `BrokenPipe`.

The fast-path specification changes one default and adds API:

- With O7w the default, a send can be admitted ahead of an older waiter on
  another connection. A caller that relied on strict FIFO order across
  connections sets the order to strict. Sends on one connection keep their
  order either way.
- A configuration with an O7w budget of 0 fails validation.
- `writable`, `send_buffer_size` and the waiting batch method
  (`AsyncSendBuilder::submit_batch_admitted`) are new; no existing signature
  changes.
