# mio close lifecycle: unify with io_uring

Note (2026-10-25): `ConnectionState::recv_arm` was removed.

**Status:** approved design, 2026-09-10. Fixes ringline-rs/ringline#368.
**Prerequisite for** the backpressured-sends series
(`docs/backpressured-sends-series-design.md`), whose PR 3 (mio
`shutdown_write` deferral) and PR 6 (mio completion identity) build on the
mio close path.

## The bug

On mio, a connection whose peer closes first (FIN) or whose read fails
(RST) is never torn down. The four sites in `backend/mio/event_loop.rs`
(TLS EOF, TLS read error, plaintext EOF, plaintext read error) set
`recv_mode = RecvMode::Closed` directly and never push to
`pending_closes`. When the task later returns, `poll_ready_tasks` calls
`Driver::close_connection`, which early-returns because `recv_mode` is
already `Closed`, so `finish_close` never runs: the `TcpStream` stays
registered, the accumulator is never reset, and `connections.release` is
never called. `ConnCtx::close()` (the `DriverCtx` close in `handler.rs`)
takes the same early return. Every peer-first-closed connection permanently
consumes one slot and one fd. Reproduced at `046f204`: with
`max_connections(2)`, only 2 of 6 sequential peer-closed connections
succeed.

The root cause is that mio gave `RecvMode::Closed` two meanings, "the
receive side is finished" and "teardown is pending", while io_uring gives
it one.

## Decision: adopt the io_uring model on mio

Considered and rejected:

- A separate mio-only `close_pending: Vec<bool>` flag, guarding
  `close_connection` on it instead of on `recv_mode`. Fixes the leak with
  the smallest diff but leaves the backends with different lifecycles (mio
  tasks linger after EOF indefinitely; io_uring tasks are torn down once
  sends drain), and PR 3 of the series would then have to invent its own
  drain-then-act machinery on mio.
- Adopting the mio model on io_uring (FIN only marks `Closed`; teardown
  waits for the task to return). Changes the production backend's
  lifecycle, needs Linux verification for every step, and leaks any
  outbound connection whose owning task never calls `close()`.

Chosen: unify on io_uring's model.

## State model (both backends)

> Naming superseded by `docs/connection-state-model-design.md` (2026-09-11):
> `RecvMode::Closed` became `Lifecycle::Closing`, with the TCP read half in a
> separate `read: ReadHalf` field and recv arming in `recv_arm`. The
> invariants below are unchanged; read `Closed` as `Closing` throughout.

- `RecvMode::Closed`: the receive side is finished — by peer FIN, by a
  read error, or because a close was requested. **Invariant: only
  `close_connection` and the `DriverCtx` close set it.** This is already
  true on io_uring; mio gains it. It is what every recv future reads to
  return `0`.
- `ConnSendState::close_pending`: teardown has been requested and is
  finalized once queued and in-flight sends have drained. The field exists
  on both backends today (`handler.rs`); the mio
  `#[cfg_attr(not(has_io_uring), allow(dead_code))]` comes off.
- The `close_connection` idempotency guard on `recv_mode == Closed` stays
  and is now correct on both backends, because nothing else sets `Closed`.

The doc comments on `RecvMode::Closed` (`connection.rs`) and
`ConnSendState::close_pending` (`handler.rs`) become the single statement
of these rules; backend code comments point at them.

## mio changes

1. **The four sites call `close_connection`.** After their existing wake
   (`wake_recv`) or `fail_recv`, in that order, matching io_uring. The
   `eof_truncated` bookkeeping on the TLS EOF site and the stream put-back
   on the TLS sites are unchanged. The sites no longer assign `recv_mode`.
2. **`Driver::close_connection`** keeps its `Closed` guard, sets
   `recv_mode = Closed`, sets `send_queues[idx].close_pending = true`,
   and pushes to
   `pending_closes`. The `DriverCtx` close in `handler.rs` (mio branch)
   does the same via the same code, not a copy.
3. **Finalize is deferred.** `drain_pending_closes` finalizes an entry only
   when `pending_sends[idx]` is empty, or the stream is already gone, or
   the last flush reported a write error. Entries still draining are
   retained and re-checked on every loop iteration (the loop already
   drains twice per iteration; the writable event that lets the sends
   drain wakes the loop). Finalize is `Executor::remove_connection`
   followed by `Driver::finish_close`, together, so the existing
   slot-reuse safety ordering ("executor cleanup first") is unchanged and
   the connection task stays alive, wakeable by its send completions,
   until its sends have drained. Deferral is unbounded, as on io_uring;
   a write error ends it.

   **Correction from CI, resolved (#371):** at the time of #370, io_uring's
   deferral covered only sends already queued when the FIN arrived; with an
   empty queue `close_connection` ran `try_finalize_close` synchronously
   and committed the Close before the task was polled, so a post-EOF
   response was never delivered. #371 moved that finalize to the event
   loop's end-of-iteration drain of `pending_finalize_closes` (where
   `DriverCtx::close` already was), so both backends now give the task the
   same poll window.
4. **Task-exit and panic arms unchanged.** They call `close_connection`
   then `remove_connection` immediately; finalize's later
   `remove_connection` on an already-cleared slot is a no-op.
5. **`finish_close`** is unchanged apart from clearing `close_pending`. TLS
   close_notify stays generated and written best-effort there: because
   finalize is now deferred until `pending_sends` is empty, it runs on a
   drained socket and the write succeeds in practice, and keeping it there
   avoids duplicating TLS logic between `Driver::close_connection` and the
   `DriverCtx` close (which cannot reach the TLS table). Decided during
   planning.

## io_uring

No behavioural change. Its build is touched only by the shared doc
comments and the removed cfg attribute on `close_pending`, verified by
Linux CI.

## Behaviour change on mio, stated plainly

A mio connection task that today does several awaited steps after reading
EOF (or after a read error) is now torn down once its queued sends drain,
as it already is on io_uring. The full test suite on both backends is the
check that nothing depends on the old linger-after-EOF behaviour. A test
that does is a finding to bring back to this design, not something to
patch around.

## Worker exit

A worker that exits, at runtime shutdown or after its own failure under
`TaskPanicPolicy::Contain`, does not run `drain_pending_closes` for the
connections still open. It counts each established one out of
`CONNECTIONS_ACTIVE` and into `conn::CLOSED` (`count_out_open_connections`),
then drops the event loop, which closes every socket: queued sends are not
written and no close_notify is sent. io_uring closes each connection through
the ring at exit (`run_shutdown`) and counts it the same way.

## Tests

In `ringline/tests/echo.rs`, all run on both backends:

- `peer_fin_releases_the_slot`, `peer_reset_releases_the_slot`,
  `close_after_eof_releases_the_slot`: `max_connections(2)`, one worker,
  six sequential client connections that each echo one message and then
  close first (orderly FIN; `SO_LINGER 0` RST; and, for the third, a
  handler that calls `conn.close()` after `with_data` returns `0`). All
  six must echo. At `046f204` the mio backend passes only the first two.
- `response_after_peer_fin_is_delivered`: the handler reads to EOF, then
  sends a 4 MiB response and returns; the client connects, sends a short
  request, `shutdown(Write)`, then reads to EOF and asserts the full
  length. Proves the deferral on both backends (it received 0 bytes on
  io_uring until #371 — CI run 34530460078).
- `deferred_close_does_not_spin_on_half_closed_peer`: counts loop
  iterations while the response drains to a peer that does not read;
  guards against the READABLE re-report spin. Runs on both backends.

The mio driver has no unit-test harness (no `#[cfg(test)]` module in
`backend/mio/`), so the `close_connection`/`finish_close` flag behaviour is
covered by the integration tests above plus a `debug_assert!` in
`drain_pending_closes` that every entry carries `close_pending`.

## Docs

- `CHANGELOG.md` Unreleased: **Fixed** (mio slot/fd leak on peer-first
  close or read error, #368) and **Changed** (mio connection lifecycle now
  matches io_uring: teardown after peer close once sends drain).
- `CLAUDE.md`, Connection Lifecycle: one sentence stating the invariant
  that only `close_connection` sets `RecvMode::Closed` on either backend
  and that teardown finalizes after sends drain.
- `docs/journal/2026-09-backpressured-sends-series.md`: record this as the
  prerequisite it was (found by PR 1's adversarial review).

## Verification

fmt; clippy `-D warnings` on default and `force-mio`; `cargo test --all`
on default and `force-mio`; `cargo doc -D warnings`. mio on the
development machine; io_uring by Linux CI on the PR. PR via a worktree on
the fork, opened against `ringline-rs/ringline`.
