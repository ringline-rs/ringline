# Public `send_backpressured` (series PR 9)

Note: identifiers in this document are those of the PR it describes;
`docs/send-completion-slots-design.md` "What goes away" lists the renames
since. Code: `ringline/src/runtime/send_completion.rs`.

Ninth and final PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 9"). Origin: @thinkingfish
in #318. Sits on every prior PR in the series; #385 in particular.

This is the first PR in the series with a user-visible send API. Everything
under it already exists and is tested: the executor's FIFO
(`runtime/send_capacity.rs`, #377), both backends' `DriverCtx::send_bounded`
(#381, #384), completion identity (#382, #384), and the TLS ciphertext bound
(#385). PR 9 adds the future that drives them and nothing else.

## The API

```rust
impl ConnCtx {
    pub fn send_backpressured<'a>(&self, data: &'a [u8]) -> BackpressuredSendFuture<'a>;
}
```

Resolving to `io::Result<u32>` — the **plaintext** length the caller passed,
not the wire bytes, matching what `send_bounded` settles the id with.

Contrast with `send`, which is the reason both exist:

| | `send` | `send_backpressured` |
|---|---|---|
| pool exhausted | `Err` immediately | waits for capacity |
| admission | at call time | at its turn in a per-worker FIFO |
| submission | eager, in `send()` | deferred to the first poll where its turn comes |
| unpolled | already submitted | nothing happened |

`send` stays exactly as it is (departure 2). A caller who wants the current
fail-fast behaviour keeps it by not changing anything.

## Why the required-slot count must not be computed here

`SendCapacityQueue::enqueue` takes `required_slots`, and `turn` will not
release the future until the pool's free count covers it. If the future's
number is smaller than what `send_bounded` then tries to reserve, the FIFO
admits a message the backend immediately refuses — and on the TLS path that
refusal arrives *after* rustls has mutated, which by departure 1 closes the
connection. A bound that is too large merely delays.

#385 put the arithmetic in `CiphertextCapacity::slots`, and its design
already flagged this coupling as PR 9's obligation. Honouring it by
convention is not enough: the two call sites would drift on the next change
to either.

**Decision: one function, two callers.** `DriverCtx::bounded_send_slots(conn,
data) -> io::Result<usize>` becomes the single definition of "how many pool
slots will this bounded send need", and both the future (to `enqueue`) and
`send_bounded` (to reserve, or to capacity-check on io_uring) call it. The
refusals move there too, so `InvalidInput` for an oversize message and for a
slot size that cannot bound a TLS record are worded once and cannot diverge
between the pre-check and the submission.

This is a refactor of existing code, not new logic: both `send_bounded`
implementations already compute exactly this, inline.

## The future

Lazy by construction (departure 6's spirit): building it touches no runtime
state, so an unpolled drop is inert and `send_backpressured(x)` without
`.await` is a no-op rather than a leak. The `'a` borrow on `data` is what
lets submission be deferred without copying — the bytes are only read at the
moment `send_bounded` runs.

State:

```
Fresh ──first poll──> Waiting(id) ──turn──> Submitted(id) ──result──> Done
  │                      │                       │
  └── refused ───────────┴───────────────────────┴──> Done (Err)
```

**First poll** validates and enqueues, in this order, because each step's
failure must leave nothing behind:

1. generation mismatch → `ConnectionAborted`;
2. write half not `Open` → `BrokenPipe`;
3. `bounded_send_slots` → `InvalidInput` on refusal;
4. `enqueue(conn, gen, slots, CURRENT_TASK_ID)`;
5. fall through to the waiting check immediately — the pool is very often
   free, and making the common case cost an extra wake-up round-trip would
   be a poor default for the API people reach for under load.

**Every later poll** calls `set_owner` before anything else. A future can be
polled from a different task than the one that enqueued it (moved into a
`join!`, sent to a spawned task), and the queue wakes owners by task id; a
stale owner is a lost wake-up, which for a FIFO head is a stalled queue, not
just a stalled send.

**Waiting → Submitted** happens when `turn(id, free_count)` is true: call
`send_bounded` exactly once, then `mark_bounded_send_submitted(id)` which
promotes and wakes the new head. If `send_bounded` returns `Err` the
operation is over — cancel the id and resolve with that error.

**Submitted → Done** is `take_bounded_send_result(id)`. Nothing else is
called in this state; in particular the future must not re-submit, which is
what makes `canceled_submitted_..._cannot_complete_the_next_send` hold.

### Half-close refuses, and `WriteHalf`'s open policy question

`WriteHalf::Shutdown`'s doc says refusing later sends "is a policy decision
left open; today they fail at the socket". PR 9 makes that decision **for
bounded sends only**: `ShutdownPending` or `Shutdown` → `BrokenPipe` before
enqueue. Waiting for capacity in order to write to a half-closed socket is
never useful, and the FIFO is a shared resource — a doomed entry at the head
delays every other connection's sends on that worker.

Plain `send` keeps failing at the socket, unchanged. `shutdown_write` also
fails any already-waiting entries for that connection
(`fail_waiting_bounded_sends`, `BrokenPipe`), so a shutdown cannot strand a
parked future.

### Drop

- `Fresh` — nothing to undo.
- `Waiting` — `cancel_bounded_send(id)`, which removes it and wakes the new
  head. Dropping the head must not stall the queue behind it.
- `Submitted` — `cancel_bounded_send(id)` marks it `Abandoned`; the backend
  completion still arrives and removes the entry. The bytes may or may not
  have reached the wire, which is inherent to cancelling a submitted write
  and is documented on the future.
- `Done` — nothing.

`Drop` runs outside a poll, so it must tolerate a missing `CURRENT_DRIVER`
(the same guard `SendFuture::drop` uses) rather than assuming thread-local
state is installed.

## Departure 1, end to end

The series' first departure — a failure after rustls has mutated fails the
operation *and* closes the connection — has been asserted so far only at the
driver level. PR 9 is the first point where it can be observed the way a user
would: a bounded TLS send whose push fails after encryption must resolve
`Err`, close the connection, and leave the peer with no record gap (no
`bad_record_mac`). That end-to-end test is the one the series has been
building toward and is required here.

## Tests

From #318's list, both backends unless noted:
`backpressured_send_waits_for_pool_capacity_without_duplication`,
`..._construction_is_lazy_and_unpolled_drop_is_inert`,
`..._registers_the_first_polling_task_after_move`,
`..._refreshes_owner_after_first_poll_move`,
`..._rejects_oversize_before_writing`,
`shutdown_drops_parked_backpressured_send_without_hanging`,
`canceled_submitted_backpressured_send_cannot_complete_the_next_send`,
`mio_half_close_completes_submitted_send_and_cancels_capacity_waiter` (mio),
plus the departure-1 end-to-end regression above, and a test that the
future's `required_slots` equals what `send_bounded` reserves for the same
message on a TLS connection — the coupling this PR exists to make structural.

## Docs and changelog

`architecture.md` section, `request-flow.svg` panel, `tools/doc-diagrams`
needle checks. Changelog: `Added` for both public futures, plus `Fixed` for
"copied sends can no longer transmit a prefix and then fail".

## Verification

Four configurations (default/io_uring, default/mio, `tls-unbuffered`/io_uring,
`tls-unbuffered`/mio) plus `timestamps`, on an anvil guest, with per-test
`ran=N` counts. The two-guest X710 A/B applies here for the first time in
the series: this PR gives the send path its first bounded caller, so the
`send` path's numbers must be unchanged and the bounded path's cost measured
rather than assumed.
