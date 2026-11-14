# Send admission a server can bound

Status: sections 1 and 2 are built. Section 3 is specified for building, from
Experiment A's results (`docs/journal/2026-11-abort-close.md`). Section 4
names the experiment that decides it and the constraints already found.
"What exists" describes the code before section 1, at 07dd0f56; section 3's
specification cites the code at 03628fee.

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
   retry entry records that the close is an abort, so `drain_close_retries`
   (uloop.rs:4935-4941) does not fall back to the lead-and-`Close` pair, which
   would leave the zero-copy entries held. In the `Shutdown` case the lone
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

Constraints already found for each outcome:

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
    The specification sets the result that would drop this rule.
  - A refused batch's error is `#[non_exhaustive]`, carries an `io::Error`
    case, returns the parts on every refusal, and converts to an `io::Error`
    whose pool and slab refusals are `WouldBlock`. Nothing wakes a caller after
    `WouldBlock`; the way to wait is `send_admitted`.

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
  connection's own drain, which is problem 1.

## Non-goals

- One connection's share of the pool. A client that pipelines and reads slowly
  can hold many admitted replies. A caller bounds this by awaiting a reply's
  `SendCompletion` before admitting the next on the same connection.
- Slab use by coalesced runs and forwards.
- Changes to `send`, `send_nowait`, `submit_batch` and `close()`.

## Order of work

1. Section 1: the send futures become `!Send` and are renamed. It fixes
   problem 5 and can land without the other sections.
2. Section 2, `send_admitted`, with `send_backpressured` rewritten on it and
   removal from the FIFO without a scan. This ends the false closes of
   problem 1.
3. Section 3, `abort`, as specified from Experiment A.
4. Experiment B, then the fast-path specification and its PR.

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
