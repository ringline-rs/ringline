# Send admission a server can bound

Status: proposed. Nothing here is built. Sections 1 and 2 are specified for
building. Sections 3 and 4 name the experiments that decide them and the
constraints already found; each gets its own specification once its
experiment has run.

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

Read at e34d0015. `io.rs` is `ringline/src/runtime/io.rs`, `sc.rs` is
`ringline/src/runtime/send_completion.rs`, `waker.rs` and `mod.rs` are in
`ringline/src/runtime/`, `handler.rs` is `ringline/src/handler.rs`, and
`udriver.rs`, `uloop.rs` and `ring.rs` are
`ringline/src/backend/uring/driver.rs`, `event_loop.rs` and `ring.rs`.

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
  or TLS (udriver.rs:2258-2261). `CLOSE_NOTIFY_TIMEOUT` (5 s, handler.rs:175)
  is armed for a connection whose handshake or connect has not completed, and
  by `DriverCtx::close` on an io_uring TLS connection (handler.rs:1161-1170).
- A zero-copy slab entry is released when its notifications land, after the
  peer has acknowledged the data (`send-completion-design.md:126-135`). A
  fixed file's `Close` does not release the socket while requests that hold
  it are in flight: from Linux 6.13 the connection's own, before that earlier
  requests on any connection (CLAUDE.md, invariant 8). Worker exit cancels
  every request on a connection and only then closes it, with
  `CloseLead::Abort` (a `SO_LINGER {on, 0}` setsockopt, Linux 6.7,
  ring.rs:69-73 and 570-579) for one still holding slab entries
  (udriver.rs:3205-3307).
- On mio, `send`, `send_nowait` and `submit_batch` copy into a `Vec` and never
  touch the pool (handler.rs:2737-2789, io.rs:1826-1848). The pool on mio is
  the admission budget for bounded sends only (handler.rs:2794-2800), and
  there is no slab.

## 1. Send futures stay on their worker

The send futures become `!Send` and are renamed:

| today | becomes |
| --- | --- |
| `SendFuture` | `SendCompletion` |
| `BackpressuredSendFuture` | `BackpressuredSend` |

- `SendCompletion`, `BackpressuredSend`, `ForwardFuture` and section 2's
  `Admission` hold `PhantomData<*const ()>`, as `RecvReadyFuture` does. Moving
  one to another thread is then a compile error, so its poll and its drop
  always run on the worker whose tables its ids index.
- The rename has two reasons. A `!Send` type named `SendFuture` reads as a
  statement about the `Send` trait. The name is also taken by
  `mpsc::SendFuture`. `SendCompletion` names what the future resolves on. No
  aliases are kept for the old names: 0.7.0 batches breaking changes
  (CLAUDE.md, Release Process).
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
  times. The count is `git ls-files | grep -v '^docs/' | xargs grep -ow`.
  It leaves out `mpsc::SendFuture` in `runtime/channel.rs` and a test-local
  alias in `tests/combinators.rs`, which keep their names.

Tests:

- `compile_fail` doctests that assert `!Send` for each of the four, as
  `RecvReadyFuture` has. The reproduction kept the future in a
  `static Mutex`, which no longer compiles.
- Each doctest fails with the `PhantomData` field removed.

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
with a full `retain` (`prune_waiting`, sc.rs:619-631). Before each read of the
head, `head_task`, `turn` and `head_ready` pop the ids at the front that
`prune_waiting` would drop: a slot whose generation differs, or an entry that
is no longer `Waiting`. `turn` takes `&mut self` for this. A release that
aborts the head still wakes the new head, as `prune_waiting` does today
(sc.rs:632-635). An admitted id is always the head, so `mark_submitted` pops
the front. Each id is pushed once and popped once.

Tests, on both backends:

- `send_admitted` resolves while the send has not settled: a peer that has
  stopped reading, a backlog ahead of the send, and a free pool.
- The existing `send_backpressured` tests pass unchanged.
- With a test-only count of ids visited, cancelling 64 waiters from the back
  of the FIFO and then admitting the next head visits at most 65 ids. The
  linear scan visits 2,080 for the cancels alone.
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
  (`finish_close` flushes and writes the alert, mdriver.rs:736-776);
- it applies to a connection that is already closing, which is problem 4's
  case, and does nothing once the connection's `Close` has been committed;
- callers use it in place of `close()` for a peer that has stopped reading.

The mechanism is not decided. Committing a `Close` behind `CloseLead::Abort`
does not release them: that lead only sets `SO_LINGER`, and the connection's
hangup poll, an armed receive or a chain part keeps the socket open after the
`Close`. Below 6.13, requests on other connections do too. Worker exit cancels
every request first, which an `abort` on one connection cannot rely on below
6.13.

### Experiment A

Setup, on io_uring:

- `workers(1)`, so both connections below share one ring (the acceptor
  round-robins connections across workers).
- A plain TCP connection whose peer has stopped reading, with copy sends
  queued, one send waiting for room, and a 4 MiB guarded zero-copy send. That
  is larger than the loopback socket buffers, as in
  `ringline/tests/shutdown_zero_copy.rs:19-21`. Over loopback, zero-copy data
  that is transmitted is copied and its notification lands at once, so only
  data behind the closed window keeps its entry. Each run checks that the
  entry is still held after 1 s before applying a candidate.
- Two arms: with and without a second, idle connection whose hangup poll is
  armed.
- Kernels: Linux 6.8 (Ubuntu 24.04), 6.12 (Debian 13) and 7.2 (Debian 14),
  from the rack's guest images. Add 6.1 (Debian 12) if candidate 2 is chosen,
  since the supported range starts there.
- Five runs per kernel, arm and candidate.

Candidates:

1. `ASYNC_CANCEL` of every request on the fixed file, then the `SO_LINGER`
   setsockopt, then the `Close`, joined by hard links as `submit_close` joins
   its lead to the `Close` (ring.rs:551-552, 581). The setsockopt fails below
   6.7, and a hard link still runs the next step after a failed one.
2. `IORING_OP_CONNECT` with an `AF_UNSPEC` address, then the `Close`. In the
   Linux 6.12 source, `__inet_stream_connect` calls the protocol's
   `disconnect` for `AF_UNSPEC`, and `tcp_disconnect` sends a reset and purges
   the write queue. io_uring's connect copies any address (6.8). The
   completion is tagged on its own, because one under `OpTag::Connect` would
   reach `handle_connect` (ring.rs:603-620).
3. Control A: `close()` with a send waiting for room. ringline's drain never
   commits the `Close` (udriver.rs:1974, 1986).
4. Control B, with its own setup:
   - copy sends close the peer's window;
   - then a guarded send that fits in the space left in the send buffer, so
     its main completion reports its full length;
   - nothing waits for room, and `close()` commits the `Close` with its normal
     lead.

   This measures how long the kernel holds the entry, up to 60 s. Its result
   does not feed the decision.

Measured: whether the peer sees an RST and when, and when the slab entry and
the pool slots are released. "At once" means within 100 ms of the candidate's
submission.

Prediction:

- Control A releases nothing. For control B, I don't know whether the kernel
  frees an orphaned socket's data behind a zero window within 60 s.
- Candidate 1 releases at once on 7.2 in both arms. On 6.8 and 6.12 it
  releases at once only without the idle connection.
- Candidate 2 releases at once on every kernel, in both arms.

Decision: if candidate 2 releases at once everywhere, including 6.1, `abort`
uses it on every kernel. Otherwise candidate 1 from 6.13, and the
specification states what `abort` does below.

Not covered: on a Unix-domain socket, I expect `connect` with `AF_UNSPEC` to
fail (not checked). Guarded sends there release at completion (CLAUDE.md,
the copies table), and the specification states what `abort` does on them.

On mio, `SO_LINGER {on, 0}` can be set on the socket, which `tcp_streams`
holds until `finish_close` drops it (mdriver.rs:754, 784-787). The queue on an
open connection can already be dropped, as `fail_connection_on_send_error`
does (mio event_loop.rs:1304-1314). `abort` also needs a flag that skips
`finish_close`'s flush and alert.

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
  futures do (ringline/src/fs.rs:597-640): record `current_worker()` at
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
  polled (uloop.rs:538, 619, 727), and by forwards. Releasing a guard-only
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
  worker CPU before (uloop.rs:5023-5030).
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

1. Section 1: the send futures become `!Send` and are renamed. A bug fix that
   stands alone.
2. Section 2, `send_admitted`, with `send_backpressured` rewritten on it and
   removal from the FIFO without a scan. This ends the false closes of
   problem 1.
3. Experiment A, then the `abort` specification and its PR. The experiment
   does not depend on steps 1 and 2 and can run alongside them.
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
