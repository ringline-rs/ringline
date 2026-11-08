# io_uring bounded-send completion identity (series PR 7b)

Note: identifiers in this document are those of the PR it describes;
`docs/send-completion-slots-design.md` "What goes away" lists the renames
since. Code: `ringline/src/runtime/send_completion.rs`.

Note (2026-10-25): the recv-buffer forward (`handle_send_recv_buf`, and
`forward_to` as it then was) was removed; `ConnCtx::forward_to` today is the
body of `RecvHalf::forward_to_conn`.

Note (2026-10-25): `OpTag::RecvMulti` was removed with the TCP
provided-buffer ring.

Seventh PR of the series that lands #318
(`docs/backpressured-sends-series-design.md`, "PR 7"), re-derived on current
`main` rather than ported. Design origin: @thinkingfish in #318. Sits on
#376 (`reserve_slots`, SQ-pressure parking), #377 (`SendCapacityQueue`),
#381 (the mio equivalent, and the `Aborted`/`Done` distinction), and #382
(`RecvMulti` generation identity, split out of this work).

No public API: PR 9 adds the future. PR 8 adds the TLS pre-mutation bound.

## Goal

A bounded send must resolve with the exact result of *its own* operation —
not a neighbour's, not a truncated count, and not silence. On mio that meant
routing a per-id completion out of `flush_sends`. On io_uring the operation
is a set of SQEs whose completions arrive separately, can repeat for one
logical send (partial write, POLLOUT re-arm, ZC notification), and can
outlive the connection.

## Scope decisions, made before implementing

**Carrier: the end-of-send pool slot, plus a lift into the coalesced slab
entry.** `SendCopyPool` gains
`slot_bounded_send: Vec<Option<(BoundedSendId, u32)>>` — the id and the
**logical (plaintext) length**. It is set only on the slot marked
`end_of_send`, exactly parallel to `slot_end_of_send`, which
`DriverCtx::send`'s chunk loop already maintains and which every success
path already reads before releasing. `submit_next_queued_inner` coalesces a
run that stops at the first end-of-send slot, so a coalesced op covers at
most one logical send's tail and **one id per slab entry suffices**;
`allocate_coalesced` already propagates `end_of_send` from the last slot and
lifts the id at the same line. Departure 5. (Superseded by #628: a run now
spans sends, the end-of-send flag is gone, and the slab entry carries each
send's id with where its bytes end; see `InFlightSendSlab::take_sent_sends`.)

**Why the logical length travels with the id.** Owner decision, 2026-09-12:
a bounded TLS send reports the **plaintext** length the caller passed. The
alternatives were wrong in ways worth recording: `handle_send` reports
`acked_bytes` accumulated from the wire, `handle_tls_send` never accumulates
at all, and `encrypt_to_sends` tags only the *final* ciphertext chunk
`OpTag::Send` — so the number that falls out naturally is the last TLS
record's length, which is meaningless to a caller. Carrying the length makes
both backends and both TLS engines agree by construction, and makes the
plaintext path report the same number it would have computed anyway.

**Safety net: `SendCopyPool::release` refuses to drop a live id.** mio's
audit was mechanical because a leaked permit tripped `SlotReservation`'s
destructor assert. io_uring has no such guard — the reservation is consumed
into real slots inside `DriverCtx::send`. The equivalent chokepoint is
`release`, which every disposal path already funnels through and which
already carries a `debug_assert`. It gains:

```rust
debug_assert!(
    self.slot_bounded_send[idx as usize].is_none(),
    "slot {idx} released while still carrying bounded send {:?}; \
     every disposal path must take the id and complete or fail it first",
    self.slot_bounded_send[idx as usize],
);
```

A handler that releases the id-carrying slot without settling the operation
now fails loudly in every debug build and every test, which restores the
"revert a site and see a test fail" discipline that PR 6 relied on. The
release still clears the entry, so a release-build miss degrades to a lost
completion rather than a corrupted pool.

## Out of scope, deliberately

- **`handle_send_recv_buf` gets no identity or `close_submitted` guard.** A
  bounded send can never reach it (`forward_to` is the only producer), and
  the absence is a documented, reasoned invariant tied to
  `force_finalize_close` being TLS-only. Adding guards "for symmetry" is
  risk with no bounded-send value.
- **No id on `InFlightSendSlab::allocate` or `allocate_recv_forward`.**
  (`allocate_recv_forward` was removed in 0.7.0-alpha.5 with recv-forward.)
  `send_backpressured` is copy-only, so the ZC and recv-forward allocators
  would carry a field nothing ever sets. Only `allocate_coalesced` needs it.
- **TLS admission sizing stays as it is.** The permit is sized by plaintext;
  the ciphertext bound is PR 8.

## Changes

### Settling an operation

One helper on the event loop, so no site open-codes the rule:

```rust
fn settle_bounded(&mut self, id: BoundedSendId, result: io::Result<u32>)
```
It calls `executor.complete_bounded_send(id, result)`. Every settle goes
through it.

**Success** (`handle_send`, `handle_send_msg_coalesced`): where the handler
already reads `is_end_of_send` before releasing, it also takes the id and
settles `Ok(logical_len)` — the carried length, not `acked_bytes`.
(Superseded by #628: the flag is gone; the slab entry settles each send in
its run, and a partial write settles the sends it covers.)

**Failure with a completion** (every send-family error branch, the
`close_submitted` gates, and `handle_tls_send`'s two silent
`close_submitted` returns and its `drain_conn_send_queue` path): take the id
and settle `Err`. Those three TLS returns are today's "a TLS send error
hangs `send().await`" hole; this PR does not fix that for `SendFuture`, but
it must not reproduce it for bounded sends.

**Failure with no completion** (the retry drains' give-up arms; today four
drains give up, and `drain_send_retries` settles through
`drain_conn_send_queue`): settle
beside the existing `wake_send(Err(..))`.

**Teardown** (`release_queued_sends`, reached from `drain_conn_send_queue`,
`force_finalize_close` and `run_shutdown`): each destroyed `BuiltSend`'s
pool slot may carry an id. Rather than threading a failure queue through a
free function with four `&mut` parameters — the survey's highest-risk,
lowest-visibility change — `release_queued_sends` *returns* them and each
of its callers puts them on
`Driver::bounded_send_completions: VecDeque<(BoundedSendId, io::Result<u32>)>`,
which the event loop drains beside the completions. (`#[must_use]` is what
stops a caller dropping them.) The payload is an `io::Result`, not an
`io::Error` as first written here: the queue's defining property is the
*missing completion*, not the failure, and `send_bounded`'s two no-SQE cases
below settle `Ok` through it — as mio's equivalent queue does. `run_shutdown` drains into a
queue nobody reads, which is correct and is commented as such: the executor
is going away with the driver, exactly as mio's `Driver::drop` does not push
completions.

`bounded_send_completions` also carries the synchronous settles from
`DriverCtx::send_bounded`, which has no executor access — the same reason
mio has a completion queue at all.

### `DriverCtx::send_bounded` (io_uring)

Mirrors `DriverCtx::send`: generation check, `close_submitted` refusal,
TLS via `encrypt_to_sends`, `reserve_slots` with the same two error
mappings, then the existing chunk loop with the id and logical length
attached to the last slot.

**Where it departs from mio**: mio takes the reservation *first* and holds
it unfilled as the entry's permit, because mio's ciphertext never comes out
of the pool. On io_uring it cannot: `encrypt_to_sends` allocates the
ciphertext's slots from this same pool, and an outstanding reservation hides
them from `alloc_raw` (`SendCopyPool::reserve_slots`). So the TLS branch
returns before the reservation, exactly as `send` does, and a bounded TLS
send's admission is the capacity FIFO's plaintext-sized `turn` alone — which
is the same plaintext-sized budget the "TLS admission sizing stays as it is"
decision above already records as PR 8's gap.

A message that produces no SQE has no completion coming, so `send_bounded`
settles it itself, through `bounded_send_completions`, with the value mio
reports: a zero-length plaintext send (`[].chunks(n)` yields nothing) and a
TLS send whose plaintext produced no record both settle `Ok(data.len())`.
Everything else is written by a CQE.

**Departure 1 applies unchanged**: a TLS failure after `encrypt_to_sends`
has advanced rustls fails *that operation* and closes the connection. Post
#376 an SQ-full no longer reaches here — it parks.

### Capacity wake

`Driver::capacity_released` set wherever a slot returns, and one
`wake_capacity_if_released` as the last step of the run loop — the same
placement, and for the same reason, as #381: `pending_finalize_closes` is
drained after the final `drain_completions`, so a wake from inside the
completion drain would leave teardown's released slots unsignalled until
after a `submit_and_wait` that can block.

### Departure 4

Already satisfied: #381 gave `SendCapacityQueue` a provisional `Aborted`
that a driver result overwrites. It is **required** here for the same reason
it was there — `Executor::remove_connection` has three callers on io_uring
too, two of them in `poll_ready_tasks`, which runs before the flush and the
second `drain_completions`. No further change; a test pins it.

## Tests

Event-loop tests (`cfg(has_io_uring)`, Linux only), on the existing
scaffolding (`make_test_loop_with_config`, `built_copy_send`,
`attach_socketpair`, `test_dispatch_cqe`, `Ring::force_push_failures`):

- one id, one settle, `Ok(logical_len)` — single-slot and multi-slot, the
  latter asserting intermediate chunk completions settle nothing;
- a partial write then completion settles once, with the whole length;
- a coalesced run settles the id lifted into the slab entry;
- an error branch settles `Err` and releases;
- each of the six drains' give-up arms settles `Err`;
- teardown through `drain_conn_send_queue` and through
  `force_finalize_close` settles `Err(ConnectionAborted)` for a queued
  bounded send;
- a stale-generation completion settles nothing and disturbs no new
  occupant;
- departure 4: a bounded send owned by a standalone task, on a connection
  whose own task returns `Ready`, still settles `Ok`;
- TLS: a bounded TLS send settles `Ok(plaintext_len)`, not the last record's
  length.

**Every test must be shown to fail against the behaviour it pins**, and the
`release` assert must be shown to fire when a settle is removed — that is
the evidence that the disposal audit is mechanical rather than asserted.

## Verification

macOS covers fmt, the mio build, docs. Everything substantive is
`has_io_uring` and is verified on a Debian 13 anvil guest via systemslab:
clippy `-D warnings` on default, `timestamps` and `tls-unbuffered`, and
`cargo test -p ringline` on default and `timestamps`. Then the two-guest
X710 A/B (`experiments/send-path-ab*.toml`) with **six io_uring runs per
arm** before this is relied on. No changelog line; nothing is externally
observable until PR 9.
