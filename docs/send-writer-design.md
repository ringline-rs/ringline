# Encoding sends directly into the send pool

Status: proposal. Prototype and measurement pending (see "Measurement").

## Problem

An application that builds its response bytes pays one copy more on
ringline than on a readiness runtime. It encodes into its own buffer, and
`send` / `send_nowait` copy that buffer into `SendCopyPool` slots. A tokio
server writes from its own buffer, and the only copy is the kernel's.

The profile that showed this ran a RESP server benchmark
(`ringline-bench/src/bin/resp-server.rs` on the `exp/oneshot-ab` branch of
the brayniac/ringline fork, commit 9b72617, not merged). Server and load
generator ran in VMs on two hypervisors, connected through Intel X710 NICs,
with Debian 13 guests (Linux 6.12): 8 server workers, 2048 connections,
pipeline depth 16, 80/20 GET/SET. The ringline
arm used a 1024-buffer receive ring, so it had no receive-ring starvation.
It was compared with the same server on tokio, one current-thread runtime
per core. SystemsLab experiments `01a12a6d-1a82-71a5-329e-d642483b6a9a`
(4 KiB values) and `01a12a6d-1af9-7140-3d1a-8074bb4a0b7b` (64 KiB values):

| Values | Runtime | ops/s | system CPU per op | user `memmove` per op | kernel `rep_movs_alternative` per op |
|---|---|---|---|---|---|
| 4 KiB | ringline | 896k | 24.1 µs | 3.18 µs | 2.03 µs |
| 4 KiB | tokio | 1083k | 17.7 µs | 1.87 µs | 1.23 µs |
| 64 KiB | ringline | 61.7k | 340 µs | 60.3 µs | 34.8 µs |
| 64 KiB | tokio | 72.0k | 259 µs | 34.7 µs | 26.4 µs |

Of the functions in the profile, user `memmove` differs most: 1.31 µs per
op at 4 KiB and 25.6 µs at 64 KiB. Two copies on ringline's side have no
tokio counterpart: the response buffer into the send pool, and the provided
receive buffer into the accumulator. With 80% GETs, response bytes per
operation are about four times request bytes, so most of the extra
`memmove` is the send copy. That split is inferred from the byte counts;
the profile has no call graph that separates the two copies.

An arm of the same server that sent GET values of 4 KiB and up zero-copy
(`send_parts` with guards; experiments
`01a12922-edca-71fc-d27a-3071b58fdf46` and
`01a12922-ef13-713f-9990-ac7d71c006cf`)
matched tokio's throughput at 4 KiB (1082k against 1080k ops/s) and beat it
at 64 KiB (84k against 73k). It used 9.95 cores of softirq at 4 KiB and
18.43 at 64 KiB. In the profile above, at 4 KiB, the copy arm used 7.44
cores of softirq and tokio 6.06; the zero-copy arm's figures come from a
different run. Guards also require the value to live in memory the
application can hand to the kernel until the zero-copy notification
arrives, which a cache whose values move or expire does not offer cheaply.

This document proposes a send API that removes the application-to-pool copy
without zero-copy: the application encodes into pool slots directly, and the
slots are submitted as they are today. The receive copy is a separate
problem and is not addressed here.

## API

The writer is scoped to one call. The application encodes inside a closure,
and the call commits the bytes when the closure returns.

```rust
impl SendHalf {
    /// Run `f` with a writer over send-pool slots, then queue what it wrote
    /// on this connection. Fire-and-forget, like `send_nowait`.
    pub fn send_with<R>(&mut self, f: impl FnOnce(&mut SendWriter<'_>) -> R) -> io::Result<R>;

    /// As `send_with`, and also return a future that resolves like `send`'s.
    pub fn send_with_awaited<R>(
        &mut self,
        f: impl FnOnce(&mut SendWriter<'_>) -> R,
    ) -> io::Result<(R, SendFuture)>;

    /// Wait for send-pool capacity for `len` bytes, through the same
    /// admission queue as `send_backpressured`, then run `f` and queue its
    /// bytes. Resolves to the closure's result and the bytes sent.
    pub fn send_with_backpressured<F, R>(&mut self, len: usize, f: F) -> SendWithFuture<F>
    where
        F: FnOnce(&mut SendWriter<'_>) -> R; // Output = io::Result<(R, u32)>
}

pub struct SendWriter<'a> { /* slot chain, state; borrows the call */ }

impl SendWriter<'_> {
    /// Reserve pool capacity for `additional` more bytes written through
    /// `io::Write` or `BufMut`.
    pub fn reserve(&mut self, additional: usize) -> io::Result<()>;

    /// Reserve `n` more whole slots, for `contiguous` calls.
    pub fn reserve_slots(&mut self, n: usize) -> io::Result<()>;

    /// The pool's slot size: the largest `max` `contiguous` accepts.
    pub fn slot_size(&self) -> usize;

    /// Hand `f` a contiguous region of `max` bytes in the current slot,
    /// starting a new slot if the current one has less room. `f` returns
    /// how many bytes it wrote. `max` must not exceed the slot size.
    pub fn contiguous<F>(&mut self, max: usize, f: F) -> io::Result<usize>
    where
        F: FnOnce(&mut [u8]) -> usize;

    /// Bytes the writer has accepted, including bytes discarded after a
    /// failure.
    pub fn len(&self) -> usize;

    /// Release everything written and clear a failure. Writing can start
    /// again; if nothing more is written, the call sends nothing and
    /// returns `Ok` with the closure's result.
    pub fn discard(&mut self);
}

impl std::io::Write for SendWriter<'_> { /* ... */ }
unsafe impl bytes::BufMut for SendWriter<'_> { /* ... */ }
```

`Connection` gets the same three methods, delegating to its `SendHalf` as
its other send methods do. `ConnCtx`'s send methods are `pub(crate)`, and
its `send_with` would be too. The methods take `&mut self`, as every public
send method on `SendHalf` does.

A RESP response loop changes from

```rust
let mut out = Vec::new();
encode_responses(&requests, &mut out);
tx.send_nowait(&out)?;
```

to

```rust
tx.send_with(|w| encode_responses(&requests, w))?; // io::Write or BufMut
```

`resp-proto` encoders write into `&mut [u8]` and report their length
through `encoded_len()`. They use `contiguous`:

```rust
let n = value.encoded_len();
w.contiguous(n, |buf| value.encode(buf))?;
```

`memcache-proto` encoders also write into `&mut [u8]` and have no
`encoded_len()`. `ringline-memcache` already computes an upper bound for
its scratch buffer; it passes that bound as `max` and uses the returned
count. The bound includes a SET's value, so a SET larger than a slot takes
the header, value and trailer path below; `append_set_guard_prefix` already
encodes the text header on its own.

`contiguous` cannot carry an encoding larger than one slot, and
`resp-proto`'s `encode` has no streaming form. A response with a value
larger than a slot is written by the caller as the frame header, then
`put_slice` (or `write_all`) of the value, which continues into the next
slot, then the trailer.

### Why scoped

A writer that outlives the call (`let w = tx.writer(); ... w.commit()`)
can be held across `.await`. Three problems follow, and the scoped form has
none of them:

- A connection's task is dropped at teardown with no driver installed
  (`handle_close` → `Executor::remove_connection`), so a held writer's
  `Drop` cannot release its slots. `handle_close` already reclaims
  `RecvSegment` bids explicitly for the same reason. A held writer would
  need a thread-local list of orphaned slot chains, drained by the event
  loop.
- The send-capacity FIFO admits its head only when `free_count()` covers
  the head's slots (`SendCompletions::turn`). Every slot outside a
  reservation is freed today by kernel progress. A held writer's slots are
  freed only by the task holding it. A task that holds a writer and then
  awaits `send_backpressured` for more than the remaining free slots waits
  for itself. A task that holds a writer and awaits a message from another
  task, while that task is the FIFO head waiting for capacity, waits
  forever, and every sender behind that head stalls.
- A writer carrying only a connection token can be committed after its
  `SendHalf` is dropped and the write side is taken by another owner
  (`take_send`), for example one running a forward.

Inside the closure the application cannot `.await`, so none of these can
happen to `send_with` or `send_with_awaited`. `send_with_backpressured`
returns a future that carries only the connection token, as
`send_backpressured`'s does, so it shares that method's exposure to a
change of write-side owner while it waits. Its slots are taken only after
admission, inside one poll, so the teardown and FIFO problems do not apply
to it. The costs:

- The coalescing client below keeps its own buffer.
- An encoder that must `.await` partway through a response (a value read
  from disk, for example) splits it across several `send_with` calls.
  Order holds, but if a later call fails, the earlier part is already
  queued, as with several `send` calls today.
- A response produced by another task arrives at the connection's task as
  bytes that already exist, so it goes through `send`.
- The writer has no seek. An encoder that writes a body and then fills in
  a length prefix ahead of it (HTTP/2 or gRPC frame headers) needs the
  length first, as `contiguous` with `encoded_len()` does.

## Semantics

### Admission and pool exhaustion

The writer takes slots from the pool as it fills them. Its slots count
against the pool from the moment they are taken.

- Any write that needs a slot when none is free marks the writer failed.
  `io::Write::write` and `contiguous` return `Err(Other, "send copy pool
  exhausted")`. `BufMut` cannot report an error. After a failure, its
  `chunk_mut` returns a 64-byte buffer inside the writer, and bytes written
  there are discarded.
- `remaining_mut()` returns `isize::MAX as usize - len()`, as `Vec<u8>`'s
  does. The `BufMut` contract does not allow it to track pool space: it may
  change only through `advance_mut` or a method documented to move the
  position, and the default `put_slice` panics when it is smaller than the
  slice. `discard` resets `len()` to 0 and is documented as moving the
  position, as `Vec::clear` does.
- When the closure returns, a failed writer releases every slot and the
  call returns `Err`, whatever the closure returned, unless the closure
  called `discard` after the failure. Nothing was queued or
  transmitted, which is the guarantee `send` gives
  (`docs/copied-send-reservation-design.md`). The application can run its
  encoder again. A failed writer is never committed, so a frame cut short
  by a failed write cannot reach the wire.
- A writer whose slots would exceed the pool's slot count fails with
  `InvalidInput`, matching `send`'s refusal of a buffer wider than the
  pool.
- `contiguous` with `max` larger than the slot size returns `InvalidInput`
  and does not mark the writer failed.
- `reserve(additional)` calls `SendCopyPool::reserve_slots` for the slots
  `additional` bytes need after the current slot's free space. After it
  returns `Ok`, `io::Write` and `BufMut` writes up to the reserved total
  take reserved slots and cannot fail. `contiguous` can leave the tail of a
  slot unused, so a writer that mixes `contiguous` with a byte-count
  reservation can need more slots than it reserved; those come from the
  free pool and can fail. An application that wants a guarantee for
  `contiguous` writes calls `reserve_slots` with one slot per `contiguous`
  call that can start a new slot. Unused reserved slots go back through
  `release_reservation` when the call ends.
- `SendWriter`'s `Drop` releases its slot chain and any outstanding
  reservation. That covers a panic inside the closure: the default
  `TaskPanicPolicy::Contain` catches it and keeps the worker running, and
  the unwind runs inside the task's poll, where `CURRENT_DRIVER` is set.
  Without this each panic would shrink the worker's pool for good. The
  implementation tests it: panic inside `send_with` under `Contain`, then
  check `free_count`.
- `SendCopyPool` gains `alloc_raw_reserved(&mut SlotReservation)`, the
  `alloc_raw` counterpart of `copy_in_reserved`: it pops a promised slot
  for incremental filling.

### Id lifecycle per form

- `send_with` attaches no id.
- `send_with_awaited` runs `f` with no id. In the commit's `with_state` it
  registers its id (`register_send`) and attaches it to the last slot
  (`set_send_id`). If the commit returns `Err` (a failed writer, the
  stale-connection check, or on TLS the encryption's admission), it
  withdraws the id (`withdraw_send`), as `ConnCtx::send` does for any `Err`
  from `send_awaited`. A panic in `f` leaves no id behind.
- `send_with_backpressured(len, f)` on a plaintext connection joins the
  send-capacity FIFO (`docs/send-capacity-fifo-design.md`) with
  `ceil(len / slot_size)` slots. On its turn it reserves them, leaves
  `with_state`, runs `f` with the reservation, commits with the id on the
  last slot, and marks the id submitted. On failure it cancels the id
  while the id is still waiting, which wakes the next head. While `f` runs
  the future stays in its waiting state, so a panic in `f` drops it there
  and its `Drop` cancels the id and wakes the next head, as
  `BackpressuredSendFuture`'s does.
  `BackpressuredSendFuture` does all of its work inside one `with_state`;
  this future has to leave it to run `f`.
- Writing past `len`, or `contiguous` leaving slot tails unused, can need
  more slots than `ceil(len / slot_size)` even when `len()` is at most
  `len`. Those come from the free pool and can fail.
- A closure that writes nothing settles its id at once with `Ok(0)`, as
  `send_inner` does for an empty send.
- On TLS and on mio the backpressured form differs; see those sections.

### Order

The bytes are queued on the connection when the closure returns, as one
unit in the per-connection send queue, so one call's bytes reach the wire
contiguously, as `send`'s do. Wire order is the order in which calls queue
their bytes. For `send_with` and `send_with_awaited` that is call order.
For `send_with_backpressured` it is admission time, so a send issued while
it waits goes first, as with `send_backpressured`.

### Stale connections

The call checks the connection's generation, and on io_uring
`close_submitted`, before the closure runs and again before queueing, as
`DriverCtx::send_inner` does. On either, it releases the slots and returns
`NotConnected`.

## Implementation on io_uring

### Slot chain

The writer records its slots without a heap allocation per send
(this keeps departure 3 of `docs/backpressured-sends-series-design.md`:
no per-send heap allocation on the copy path). `SendCopyPool` gains a
`next: Vec<u16>` with one entry per slot. The writer keeps the first
slot, the slot being filled, its base pointer, capacity and fill level, and
the slot count. Sealing a slot
sets its filled length (`set_filled`) and links it to the next one. The
internal TLS `PoolWriter` (`tls/buffered.rs`) keeps the same state in a
`Vec`. It can move to the chain afterwards; that is not required here.

### Pool access

The closure runs outside any `with_state` borrow taken by `send_with`.
Writes inside the current slot are pointer arithmetic on the slot's memory,
which stays at a fixed address for the life of the worker
(`SendCopyPool::backing` is allocated once). Taking or releasing a slot
goes through `with_state`, once per slot.

A `send_with` inside a `with_data` closure reaches the driver from inside
that closure's `with_state`, as `send_nowait` already does in the
documented split-echo pattern (`Connection::split`). That pattern's
soundness under Rust's aliasing rules predates this change and is unchanged
by it.

### Commit

When the closure returns, the call seals the tail slot and walks the chain.
For `send_with_awaited` and the backpressured form, the last slot carries
the send's id and total length (`set_send_id`), so the send settles once.
Inside one `with_state`, each slot becomes one `Sqe::stream_send` entry, as
in `DriverCtx::send_inner` after its copy step. A chain of one slot goes
through `submit_or_queue`. A longer chain is queued whole and submitted by
`submit_queued_run` (#697), so with nothing in flight up to 32 slots go to
the kernel as one `sendmsg`; a longer chain continues through the queue's
coalescing in `submit_next_queued`. A slot the writer took and left empty
is released at the commit and not sent.

## TLS

A writer on a TLS connection writes plaintext into a buffer owned by the
call, taken from a per-worker free list so steady-state use does not
allocate. When the closure returns, the buffer goes to
`encrypt_tls_send` (io_uring) or `encrypt_for_send_mio` (mio), so
admission and copy count are what `send` has today on each backend:
admission against the ciphertext bound on io_uring, and none on mio.

The writer holds no pool reservation on TLS. `encrypt_to_sends` allocates
ciphertext slots with `alloc_raw`, which cannot take reserved slots, and
`encrypt_tls_send` checks `free_count()`, which subtracts reservations. A
reservation held by the writer would therefore count against its own
encryption. On TLS:

- `reserve` and `reserve_slots` succeed without reserving, and guarantee
  nothing. Pool exhaustion and `InvalidInput` are reported after the
  closure returns, when the plaintext is encrypted.
- `send_with_backpressured` runs `f` into the plaintext buffer on its first
  poll, before it joins the FIFO. It then joins with the ciphertext bound
  of the bytes written (`bounded_send_slots`), and on its turn hands the
  buffer to `send_bounded`, which checks capacity and encrypts with nothing
  allocating in between. `len` is ignored on TLS. Running `f` after
  admission instead would let the closure take slots between the check and
  the encryption.
- A buffer returned to the free list keeps at most 64 KiB of capacity, so
  one large response does not hold memory for the life of the worker. The
  commit, which already holds the driver, puts the buffer back on the list
  itself. The buffer's `Drop` covers abnormal drops: it returns the buffer
  through `try_with_state` when a driver is installed, and otherwise frees
  it, since a task dropped by unguarded teardown (connection close, worker
  exit) runs `Drop` with no driver installed.

The API is the same on TLS and plaintext connections; TLS gains nothing
from it.

## mio

The mio backend queues a `Vec<u8>` per send (`data.to_vec()` in
`DriverCtx::send_inner`). On a plaintext connection, a writer on mio
writes into that `Vec` directly, which removes the `to_vec` copy, and the
call queues it as
`PendingSend::plain` or `PendingSend::awaited`. As with `send` on mio, the
pool limits only the backpressured form. Its admission reservation becomes
the permit of a `PendingSend::bounded` entry, as in `send_bounded`
(`docs/mio-bounded-send-design.md`). When `f` writes fewer bytes than
`len`, the permit is narrowed with `shrink_reservation` before the entry
is queued, and the capacity release is flagged (`capacity_released`) so
the FIFO head is woken, as the TLS branch of mio's `send_bounded` does.
When `f` writes more, the permit is grown in place with a new
`SendCopyPool::grow_reservation(&mut SlotReservation, more) -> Result<(),
ReserveError>` (mio-only, like `shrink_reservation`), which reserves the
shortfall and adds it to the permit. It returns `TooLarge` when the
permit's slots plus the shortfall exceed the pool, which maps to
`InvalidInput`. On either error the call releases the permit
(`release_permit`), cancels the id while it is still waiting, which wakes
the next head, and the future resolves to `Err` with nothing queued (the
closure's `R` is dropped).

## Protocol clients

`ringline-redis` and `ringline-memcache` encode a request into a reused
scratch buffer and copy it into the pool with `send_nowait`. With
`max_batch_size` 1 (the default), `fire_*` can encode with `send_with`,
which removes that copy.

With coalescing (`max_batch_size` > 1), the client keeps one buffer across
several `fire_*` calls and sends it when the batch fills. A scoped writer
cannot span those calls, so the coalescing path keeps its buffer. A
holdable writer would also not cover it as it stands: the redis client
mixes guard parts into a batch (`fire_set_with_guard`, sent through
`send_parts().submit_batch`), which a writer does not carry, and pool
exhaustion would move from `flush()` to `fire_*`, which changes the
client's recovery path (`pending.truncate`).

## Relation to the other send methods

`send`, `send_nowait`, `send_backpressured`, `send_parts`, `send_chain`,
`forward_recv_buf` and `forward_to_conn` are unchanged. The writer is for
bytes the application produces. Bytes that already exist in memory the
application owns go through `send` (one copy) or a guard (no copy, at or
above `send_zc_threshold`).

The writer becomes the documented first choice for responses an application
encodes, in the crate docs and in `docs/syscalls-and-copies.md`. Its row in
the CLAUDE.md copy table is "user encode → `SendCopyPool` slot: 0 copies
beyond the encode".

## Measurement

The prototype goes on an experiment branch with the io_uring path only. It
adds a `--writer` arm to the RESP server benchmark that encodes responses
with `send_with` through `io::Write`: header with `write!`, value with
`write_all`, as the server's copy arm builds its buffer today. Runs: the
rig setup of the profile above, 4 KiB and 64 KiB values, the writer arm
against the copy arm and tokio, three reps each, with a server profile per
arm.

Predictions, recorded before the runs:

- User `memmove` per op falls by most of the difference to tokio: by at
  least 0.9 µs at 4 KiB and at least 18 µs at 64 KiB.
- Throughput rises at both sizes and stays below the zero-copy arm at
  64 KiB. At 4 KiB, softirq CPU stays near the copy arm's 7.44 cores and
  below the zero-copy arm's 9.95. At 64 KiB the comparison needs the copy
  arm's softirq from the same run.
- If `memmove` falls and throughput does not, the send copy was not what
  limited throughput, and the next candidate is the receive copy.
- If `memmove` does not fall, the inference above that most of the extra
  `memmove` is the send copy is wrong.

## Decisions for the owner

1. Scoped or holdable. This proposal is scoped (`send_with`). A holdable
   writer (`writer()` with `commit`) is what the coalescing clients would
   need, and it brings the teardown, FIFO and ownership problems in "Why
   scoped". It could be added later behind those three fixes: an orphan
   list drained by the event loop, a documented rule against awaiting
   admission or other tasks while holding one, and a re-check of the
   write-side owner at commit.
2. Name: `send_with` / `SendWriter`.
3. Whether a `BufMut` write that finds the pool empty is recorded until the
   call ends, as above, or panics. `Vec<u8>`'s `BufMut` cannot fail, so
   encoders written for `BufMut` do not check for errors. A panic would
   close the connection when it happens in a connection task under the
   default `TaskPanicPolicy::Contain`; in a standalone task it drops the
   task and the connection stays open. Under `TaskPanicPolicy::Shutdown` it
   shuts the runtime down.

## Not in scope

- The receive copy into the accumulator.
- Zero-copy parts inside a writer (a guard between two filled slots). It
  would merge the writer with `send_parts`, and the measurement above
  decides whether it is wanted.
- Moving the TLS `PoolWriter` to the slot chain.
- A gauge for slots held by writers: a scoped writer holds slots only
  during one synchronous call.
