# Connection state model: name the read half, the arming, and the lifetime

Note (2026-10-25): `ConnectionState::recv_arm` (`RecvArm`) and
`recv_multishot_armed` were removed with the TCP provided-buffer ring
(#716), so the `recv_multishot_armed` follow-up below is moot.
`ReadHalf::Cancelled` and `DriverCtx::cancel` were removed in #739;
`ConnSendState::shutdown_pending` became `WriteHalf::ShutdownPending`
(#374, `docs/write-half-design.md`). Connection state is `read`,
`lifecycle` and `write`.

**Status:** approved design, 2026-09-11. Behaviour-preserving refactor.
**Motivation:** #368 (mio leaked slots) and #371 (io_uring dropped post-FIN
responses) were both consequences of `RecvMode::Closed` meaning three
things at once. **Precedes** series PRs 6 and 7
(`docs/backpressured-sends-series-design.md`), which add more lifecycle
state.

## The problem

`ConnectionState::recv_mode: RecvMode { Multi, MsgMulti, Closed,
Connecting }` is named for a mechanism (which recv operation is armed) but
its `Closed` variant is read as lifecycle. Of its 72 uses, 48 are `Closed`,
and they ask three different questions:

1. *Is the read side finished, so a recv future returns EOF?* — the eleven
   recv futures in `runtime/io.rs`, the segmented reader in
   `runtime/stream.rs`, `is_alive`, mio's readable/interest checks.
2. *Was a close already requested?* — the idempotency guards in both
   backends' `close_connection` and both `DriverCtx::close`s.
3. *Which operation is armed, so what do I cancel or re-arm?* — the cancel
   path's `match cs.recv_mode`, the arming sites, `Connecting` for outbound
   connects.

Only (3) is what the enum is for. `eof_truncated: bool` is a sub-state of
(1) kept in a separate field. The write-side teardown progress lives on
`ConnSendState` as `close_pending` / `close_submitted` / `shutdown_pending`.
The word "Closed" also suggests the socket is gone when it is not: a
"Closed" connection may still be draining queued sends for as long as the
peer takes to read them.

## The model

Three fields on `ConnectionState` (`ringline/src/connection.rs`) replace
`recv_mode` and `eof_truncated`:

```rust
/// Which receive operation the driver currently has armed. Mechanism, not
/// lifecycle: `Idle` says nothing about whether more data will arrive.
pub enum RecvArm {
    /// Nothing armed (slot inactive, connect in flight, recv cancelled, or
    /// the multishot self-terminated).
    Idle,
    /// Multishot recv with the provided buffer ring (io_uring) / readable
    /// interest registered (mio).
    Multi,
    /// Multishot recvmsg with cmsg timestamps (io_uring, `timestamps`).
    #[cfg(feature = "timestamps")]
    MsgMulti,
}

/// The TCP read half as this end observed it.
pub enum ReadHalf {
    /// The peer may still send.
    Open,
    /// The peer's FIN arrived. `truncated` is the TLS case where the FIN
    /// came without a preceding close_notify (formerly `eof_truncated`).
    Eof { truncated: bool },
    /// A socket read failed; the exact error, if any task wants it, is in
    /// `Executor::recv_errors` (generation-tagged).
    Error,
    /// The application cancelled the pending receive (`DriverCtx::cancel`).
    Cancelled,
}

/// Where the connection is in its life.
pub enum Lifecycle {
    /// Slot not allocated (replaces the meaning `RecvMode::Closed` had on a
    /// fresh or deactivated slot). `active` stays as the slot flag this PR.
    Inactive,
    /// Outbound connect in flight; no recv armed yet.
    Connecting,
    /// Established or accepted; the task may send and receive.
    Open,
    /// Teardown requested (`close_connection` / `DriverCtx::close`) and
    /// finalizing once queued sends drain. The sub-states live on
    /// `ConnSendState`: `close_pending` (waiting for the drain) and
    /// `close_submitted` (io_uring: Close SQE committed; no new SQEs).
    Closing,
}
```

Two helpers on `ConnectionState` give the two lifecycle questions a name:

```rust
/// A recv future must resolve to EOF instead of parking: the peer closed,
/// the read failed, the receive was cancelled, or a close was requested.
pub fn recv_finished(&self) -> bool {
    !matches!(self.read, ReadHalf::Open) || matches!(self.lifecycle, Lifecycle::Closing)
}

/// A close has already been requested; a second request is a no-op.
pub fn close_requested(&self) -> bool {
    matches!(self.lifecycle, Lifecycle::Closing)
}
```

`eof_truncated()` on `ConnCtx` keeps its public signature and reads
`ReadHalf::Eof { truncated: true }`.

## Transitions (today's policy, expressed in the new terms)

| Event | Before | After |
|---|---|---|
| slot allocated (`activate`) | `recv_mode = Multi` | `lifecycle = Open`, `read = Open`, `recv_arm = Multi` |
| outbound connect (`activate_outbound`) | `recv_mode = Connecting` | `lifecycle = Connecting`, `recv_arm = Idle` |
| connect completes | `recv_mode = Multi` | `lifecycle = Open`, `recv_arm = Multi` |
| multishot (re)armed / self-terminated | `Multi` / `MsgMulti` set | `recv_arm` set / `Idle` |
| peer FIN | `close_connection` → `Closed` | `read = Eof { truncated }` then `close_connection` → `lifecycle = Closing` (since `docs/half-close-design.md`: `read = Eof` only, no close) |
| read error | `fail_recv` + `close_connection` | `read = Error`, `fail_recv`, `close_connection` |
| `DriverCtx::cancel` | `Closed` after cancelling | `read = Cancelled`, `recv_arm = Idle` (lifecycle unchanged) |
| `close_connection` / ctx close | guard on `Closed`, set `Closed` | guard on `close_requested()`, set `lifecycle = Closing` |
| `deactivate` | `Closed` | `lifecycle = Inactive`, `read = Open`, `recv_arm = Idle` |

Every reader maps to one of: `recv_finished()`, `close_requested()`,
`matches!(lifecycle, Connecting)`, or a `recv_arm` match. The policy "peer
FIN implies Closing" was unchanged by this refactor, which made it two
visible steps; `docs/half-close-design.md` later dropped the second step,
so `Eof` with `Open` is now a steady state.

## What does not change

- `ConnSendState` (`close_pending`, `close_submitted`, `shutdown_pending`,
  `close_notify_deadline`) and every send-path invariant in
  `docs/send-completion-design.md`. Their docs gain one sentence each
  tying them to `Lifecycle::Closing`.
- `active`, `established`, `outbound`, `generation`, `peer_addr`,
  `connect_timeout_armed`, `recv_multishot_armed`.
  `recv_multishot_armed` overlaps `recv_arm == Multi` on io_uring; leaving
  it is deliberate (its semantics include "the kernel still pins the
  socket", which the arming field does not promise). Follow-up.
- All observable behaviour. Every existing test passes unchanged except
  for assertions that name `RecvMode` directly, which are rewritten to the
  new field they meant.
- Public API. `connection` is a `pub(crate)` module and only `PeerAddr` is
  re-exported from `lib.rs`; `RecvMode` and `ConnectionState` are
  crate-private, so removing `RecvMode` is not a breaking change.

## Sites, by file (from the survey at 9e5c3b4)

- `connection.rs`: the enum, fields, `new`/`activate`/`activate_outbound`/
  `deactivate`, the helpers, existing unit tests.
- `runtime/io.rs` (11 futures + `is_alive` + `eof_truncated`) and
  `runtime/stream.rs` (1): `recv_finished()`.
- `handler.rs`: uring ctx close guard/set (2), uring `cancel` match on
  `recv_arm` / `Connecting` and `read = Cancelled`, mio ctx close
  guard/set (2).
- `backend/uring/driver.rs`: `close_connection` guard/set; the `Multi`
  check at ~L920.
- `backend/uring/event_loop.rs`: arming sites (`Multi`/`MsgMulti`, ~7),
  connect-completion (`Connecting` → `Open`), the FIN/error sites set
  `read` before `close_connection`, the TLS-EOF truncation site, and ~25
  test assertions.
- `backend/mio/driver.rs`: `close_connection` guard/set; the two
  interest checks (`recv_finished()`).
- `backend/mio/event_loop.rs`: connect-completion, the `Connecting`
  checks, the readable early-return, the four read-side sites set `read`.
- `CLAUDE.md` Connection Lifecycle paragraph and the `RecvMode` mention in
  Key Abstractions; `docs/mio-close-lifecycle-design.md` state-model
  section gets a pointer here.

## Tests

- Unit tests in `connection.rs` for the helpers and every transition in
  the table above.
- No new integration tests: the existing suite, including the #368 and
  #371 tests on both backends, is the behaviour net. A behaviour
  difference found by that suite is a defect in this refactor, not a
  reason to change the suite.

## Verification

- mio: fmt, clippy `-D warnings` (default and `force-mio`), `cargo test
  --all` on both, locally.
- io_uring: about 25 production and 25 test sites cannot be compiled on the
  development host. Before the PR opens, run `cargo clippy --all-targets
  -- -D warnings` and `cargo test -p ringline` on Linux in an anvil VM job
  through systemslab (custom-skills `vm-job`), iterating there until
  green. Linux CI on the PR is the final authority.

## Follow-ups (not this PR)

- **Done (`docs/half-close-design.md`, 2026-11):** a peer FIN finishes the
  read half and requests no teardown; the task keeps writing until it
  closes.
- **Done (series PR 3, `docs/write-half-design.md`):** `WriteHalf { Open, ShutdownPending, Shutdown }` when series PR 3 touches
  `shutdown_write`; `shutdown_pending` moves there.
- Fold `active` into `Lifecycle::Inactive` and reconcile
  `recv_multishot_armed` with `recv_arm` once PR 7 has reworked the
  multishot handlers.
