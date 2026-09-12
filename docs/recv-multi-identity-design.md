# RecvMulti completion identity: carrying the connection generation

## 1. The bug

`OpTag::RecvMulti` (and its `timestamps` twin `OpTag::RecvMsgMultiTs`) is the
only per-connection completion family that carries **no identity** beyond the
connection index. `Ring::submit_multishot_recv` encoded

```rust
let user_data = UserData::encode(OpTag::RecvMulti, conn_index, 0);
```

— a literal zero in the 32 payload bits. `handle_recv_multi` then validated only
liveness (`connections.get(conn_index).is_none()`), never the generation. Slots
recycle, so "the slot is occupied" is not the same question as "the slot is
occupied by the connection this recv was armed for" (Domain Invariant 3: *stale
CQEs are normal*).

Every other per-connection family already answers the second question: the send
family packs a truncated generation via `UserData::send_payload`, `SendPollOut`
via `send_pollout_payload`, `ForwardWrite` carries the generation at submit,
slab-backed sends record it in the slab entry. `RecvMulti` was the gap.

### The escape that makes it reachable

`Driver::try_finalize_close` cancels a still-armed multishot before submitting
the `Close`:

```rust
let _ = self.ring.submit_async_cancel(recv_ud.raw(), conn_index);
```

The result is discarded. On a full submission queue the push fails, and nothing
retries it: `pending_close_retries` / `drain_close_retries` re-drive only the
`Close` SQE. The multishot therefore outlives the fixed-file close. The kernel
tears it down asynchronously and posts a terminal completion — typically
`-ECONNRESET`, sometimes `-ECANCELED` — which can land arbitrarily later, after
the `Close` CQE released the slot and `accept` handed the index to a **new**
connection.

At that point `handle_recv_multi` finds the slot live and takes the error branch:

```rust
} else if !has_more {
    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
        cs.read = ReadHalf::Error;
    }
    let generation = self.driver.connections.generation(conn_index);   // the NEW one
    self.executor.fail_recv(conn_index, generation, io::Error::from_raw_os_error(errno));
    self.driver.close_connection(conn_index);
}
```

The *new* occupant's read half is poisoned, its recv future is failed with the
dead connection's errno, and it is closed — on a connection that never saw an
error. The data branch is corrupting in the other direction: a late `result > 0`
completion would append the dead connection's bytes into the new occupant's
accumulator and wake its task.

It is marginally worse than that: the `!has_more` prologue clears
`recv_multishot_armed` unconditionally at the top of the handler, so a stale
terminal completion also disarms the *live* occupant's flag.

## 2. Why the generation is the only discriminator

The tempting cheap fix is to gate the error branch on `recv_multishot_armed` —
"this connection has no recv armed, so this cannot be its completion". It does
not work, and the failure is exactly the interesting case:

1. `try_finalize_close` finds `recv_armed == true`, pushes the cancel — the push
   **fails** (SQ full).
2. `driver.rs` clears `recv_multishot_armed = false` regardless of whether the
   push landed.
3. The `Close` CQE arrives; `ConnectionTable::release` → `deactivate()` also
   clears the flag and bumps the generation.
4. `accept` reuses the index. `EventLoop::arm_recv` submits a fresh multishot and
   sets `recv_multishot_armed = true`.
5. The *stale* completion finally arrives and finds the flag **set**.

So the flag is per-*slot*, not per-connection-instance, and it is `true` again by
the time the stale CQE lands. Nothing else in `ConnectionState` distinguishes
occupants either — `lifecycle`, `recv_arm`, `read` are all reset by
`activate()`. `generation` is the single field whose whole purpose is to
distinguish occupants of the same index, and it is incremented exactly once per
release (`ConnectionState::deactivate`).

The payload has 32 free bits and the generation is a `u32`, so this is an
**exact** match — no truncation, and none of the mask-choice fragility that
`handle_send` (`0xFFFF`) and `handle_send_pollout` (`0x7FFF`) carry. A wrapped
`u32` generation needs 4 billion reuses of one index while a single CQE is in
flight.

## 3. Edit list

**Encoders (submit side)**

- `Ring::submit_multishot_recv(&mut self, conn_index: u32, generation: u32)` —
  payload becomes `generation`.
- `Ring::submit_multishot_recvmsg(&mut self, conn_index: u32, generation: u32,
  msghdr: *const libc::msghdr)` (`feature = "timestamps"`) — same.

**Arm sites** (each reads `connections.generation(conn_index)` immediately
before submitting; the slot cannot change generation between the read and the
push, since only a `Close` CQE releases a slot):

- `driver.rs` — forward-unthrottle re-arm in `settle_forward_end`.
- `event_loop.rs` — `flush_replenish_and_rearm` (park/ENOBUFS re-arm),
  `handle_recv_multi` tail re-arm, `maybe_rearm_throttled_forward`, `arm_recv`.
- `event_loop.rs` (`timestamps`) — `handle_recv_msg_multi_ts` ENOBUFS re-arm and
  tail re-arm, `arm_recv`.

**Cancel sites** — a cancel matches by `user_data`, so these must reproduce the
*same* payload or the cancel silently stops matching (which would itself
reintroduce the uncancelled-multishot escape):

- `driver.rs` `try_finalize_close`.
- `event_loop.rs` `handle_recv_multi` Mode A forward-throttle cancel.
- `handler.rs` `Driver::cancel` — `target_ud`. This one is shared with
  `OpTag::Connect`, whose submit payload is `0`; only the two recv tags take the
  generation. The validated `conn.generation` is used (the function has already
  rejected a stale `ConnToken`).

**Decoders (completion side)** — a single identity gate at the very top of
`handle_recv_multi` and `handle_recv_msg_multi_ts`, *before* the
`recv_multishot_armed` prologue, folded into the existing liveness check:

```rust
if self.driver.connections.get(conn_index).is_none()
    || self.driver.connections.generation(conn_index) != ud.payload()
{
    if result > 0 && let Some(bid) = cqueue::buffer_select(flags) {
        self.driver.provided_bufs.on_handout();
        self.driver.pending_replenish.push(bid);
    }
    return;
}
```

`ConnectionTable::generation` is valid for an inactive slot, so the released-
but-not-yet-reused case is covered by either half. The `result > 0` arm is the
pre-existing replenish block: the kernel consumed a provided buffer for this
completion whoever it belonged to, and it must go back to the ring exactly once
— once, because the early return means no other branch can also push the bid.

**Not changed: `recv_multishot_armed`.** `try_finalize_close` clears it whether
or not the cancel push landed. Making that conditional is *truthful* (a failed
cancel does leave a multishot armed in the kernel) but buys nothing and is not
clearly better:

- nothing retries the cancel — `drain_close_retries` re-drives only `submit_close`
  — so a `true` flag produces no second attempt;
- every remaining reader is gated on `Lifecycle::Open`
  (`settle_forward_end`'s re-arm, `maybe_rearm_throttled_forward`), and the
  connection is `Closing` from here on, with `close_submitted` refusing new SQEs
  for the slot;
- `deactivate()` clears the flag when the `Close` CQE releases the slot, so the
  lie cannot outlive the connection.

With the generation now carried, the late completions from an uncancelled
multishot are rejected on identity, which is the actual repair for this escape.
Left alone deliberately.

## 4. Test plan

`ringline/src/backend/uring/event_loop.rs` test module (`cfg(has_io_uring)` —
Linux only). Existing `RecvMulti` tests are updated to encode
`connections.generation(conn_index)` instead of the hard-coded `0`, which for a
first-use slot (generation 0) is the same value; the one exception is
`handle_recv_multi_stale_connection_replenishes_buffer`, whose whole point is an
unallocated index. The proptest `mixed_operations_no_leak_no_panic` genuinely
reuses slots and needs the real generation.

New tests, all driving synthetic CQEs through `test_dispatch_cqe`:

1. **`handle_recv_multi_stale_generation_error_does_not_touch_new_occupant`** —
   close and release slot `i` (generation 0 → 1), re-accept it, arm a recv
   waiter on the new occupant, then dispatch an `-ECONNRESET` terminal
   completion bearing generation **0**. Assert the connection is still open and
   not close-requested, `read` is still `ReadHalf::Open`, and
   `executor.recv_errors[i]` is still `None`. Without the fix the handler takes
   the error branch and all three assertions fail.
2. **`handle_recv_multi_stale_generation_replenishes_buffer_once`** — same slot
   setup, dispatch a `result > 0` completion with `F_BUFFER | bid` at the stale
   generation. Assert the bid appears in `pending_replenish` exactly once, the
   new occupant's accumulator is empty, and its `pending_recv_bufs` slot is
   untouched. Without the fix the bytes land in the new occupant's accumulator
   (or its zero-copy pin slot) and the bid is *not* replenished here.
3. **`handle_recv_multi_stale_generation_leaves_armed_flag_set`** — the new
   occupant has `recv_multishot_armed = true`; a stale terminal (`!has_more`)
   completion must not clear it. Without the fix the unconditional prologue
   clears it and the connection can never be re-armed by the throttle path.
4. **`submit_multishot_recv_encodes_generation`** — a round-trip assertion that
   the user_data the arm path builds decodes back to
   `(RecvMulti, conn_index, generation)`, pinning the encoder/cancel contract.
