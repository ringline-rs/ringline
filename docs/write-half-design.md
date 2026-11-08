# Write half: deferred `shutdown_write` on mio, `WriteHalf` on both backends

**Status:** approved design, 2026-09-11. Series PR 3 of
`docs/backpressured-sends-series-design.md`, and the `WriteHalf` follow-up
from `docs/connection-state-model-design.md`.

## The bug

mio's `DriverCtx::shutdown_write` (`ringline/src/handler.rs`, mio impl)
drains `pending_sends[idx]` with `stream.write_all(..)` on a nonblocking
socket. The first `WouldBlock` fails `write_all`; the error is discarded,
the rest of the queued bytes and their awaited-send completions are dropped
(`drain(..)` already consumed them), and `shutdown(Write)` sends the FIN.
Any response larger than the socket buffer that is followed by a half-close
is truncated on mio.

io_uring already defers: if the send queue is non-empty or a send is in
flight it sets `ConnSendState::shutdown_pending`, and the serialized drain
path submits the Shutdown SQE once the queue empties
(`backend/uring/driver.rs`, `submit_next_queued`'s `None` arm). Six sites
read or clear the flag.

## Decision

Give the write half its own state and make mio defer like io_uring.

```rust
/// The TCP write half as this end drives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteHalf {
    /// Sends are accepted.
    Open,
    /// `shutdown_write` was requested while sends were queued or in flight;
    /// the FIN goes out once the queue drains.
    ShutdownPending,
    /// Our FIN has been issued (io_uring: Shutdown SQE submitted; mio:
    /// `shutdown(Write)` called). Nothing here refuses later sends — that
    /// is a policy decision left open, and today they fail at the socket.
    Shutdown,
}
```

`ConnectionState` gains `pub write: WriteHalf` (default `Open`; reset to
`Open` by `activate`, `activate_outbound`, `deactivate`).
`ConnSendState::shutdown_pending` is removed on both backends; every site
that read or cleared it reads or sets `write` instead. Rejected: keeping
the bool and fixing mio only — it leaves the write half as the one TCP half
without a named state after #373 gave the read half one.

## Transitions

| Event | io_uring | mio |
|---|---|---|
| `shutdown_write`, queue empty and nothing in flight | `submit_shutdown`; `write = Shutdown` | `stream.shutdown(Write)`; `write = Shutdown` |
| `shutdown_write`, sends outstanding | `write = ShutdownPending` | `write = ShutdownPending`; `mark_send_dirty(idx)` so the flush pass registers writable interest |
| `shutdown_write` when `write != Open` | no-op (idempotent) | no-op |
| `shutdown_write` after the Close is committed (`close_submitted`) | no-op, as today | after `close_requested()`: no-op; the deferred finalize's `close(fd)` emits the FIN once the drain completes. Observable difference only for `close()` followed by `shutdown_write()` with the peer still sending: unread bytes at `close(fd)` produce an RST without a preceding FIN, where the old code FIN'd first. io_uring already behaves this way. |
| queue drains with `ShutdownPending` | `None` arm of `submit_next_queued`: `submit_shutdown`; `write = Shutdown` whether or not the ring accepted it, and a refused SQE goes on `pending_shutdown_retries`, which `drain_shutdown_retries` pushes again on the close-retry backoff (the "back to `Open`, no retry list" rule this row first recorded was replaced by the retry list: `SendHalf::shutdown_write` promises a FIN and every other refused SQE on the send path is retried) | `flush_sends` tail, once `pending_sends` is empty: `shutdown(Write)`; `write = Shutdown` |
| terminal send failure / forced finalize (the io_uring sites that cleared the flag: `force_finalize_close` and the two give-up branches of `submit_next_queued`; `reset_send_state`'s clear is deleted because both its callers run right after `activate`/`activate_outbound`) | `write = Open` — a faithful 1:1 replacement of `shutdown_pending = false` (the pending request is forgotten because the connection is closing; `deactivate` resets anyway) | `fail_connection_on_send_error` clears `pending_sends`; the deferred finalize then runs `finish_close` → `connections.release` → `deactivate`, which resets `write` |
| slot released | `write = Open` (`deactivate`) | same |

## What does not change

- `ConnCtx::shutdown_write`'s public contract ("Sends a TCP FIN to the
  peer. The read side remains open.") and signature.
- Send acceptance after `shutdown_write`. Recording `Shutdown` enables a
  later decision; this PR makes no policy change.
- io_uring behaviour. Its six flag sites are renamed, verified in an anvil
  VM before the PR opens.
- The deferred-close machinery from #370/#371/#373.

## Tests

`ringline/tests/echo.rs`, both backends:

- `half_close_waits_for_queued_sends_to_drain`: handler reads a request,
  queues a 4 MiB response with `send_nowait` (using `large_send_config()`,
  the 8 MiB pool from #370's tests), calls `shutdown_write()`, then reads
  until EOF; the client reads to EOF, must receive exactly 4 MiB, then
  closes. Fails on mio today (truncated). The handler records progress in
  an atomic so the test also asserts the handler reached the read-after-
  half-close step and saw the peer's EOF.
- `async_shutdown_write_triggers_eof` (existing) covers the empty-queue
  path and stays.

`ringline/src/connection.rs`: unit tests for the `write` transitions
through `activate`/`deactivate`.

## Verification

mio locally (fmt, clippy on default and `force-mio`, `cargo test --all` on
both). io_uring: `cargo clippy --all-targets -- -D warnings` and `cargo test
-p ringline` in an anvil VM on the validation host (`validation` tag,
`z4.c`, `debian-13-6.12`, build under `$HOME`) before the PR, then Linux CI.

## Docs

CHANGELOG Fixed (mio truncation) and Changed (write half is now explicit
state on both backends); `CLAUDE.md` Connection Lifecycle sentence gains
`write`; `docs/connection-state-model-design.md` follow-up marked done;
series journal PR 3 entry.
