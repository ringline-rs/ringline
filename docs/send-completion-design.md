# Send-completion overhead: CQE-skip analysis, short sends, zero-copy RX scoping

## 1. Why IOSQE_CQE_SKIP_SUCCESS does not apply to ringline sends

Diag counters (cachecannon client, GET-heavy p32) show ~15% of event-loop
iterations wake for send CQEs that wake no task ("dead iterations"). The
obvious-looking fix — `IOSQE_CQE_SKIP_SUCCESS` on fire-and-forget sends —
is unsound here, for two independent reasons:

1. **Slot lifecycle runs on the CQE.** Every send references ringline-owned
   memory (SendCopyPool slot, InFlightSendSlab entry, the provided buffer
   a `forward_recv_buf` send lends). The completion CQE is the *only*
   signal that the kernel is done with that memory; skipping it leaks the
   slot. There is no send path with no resource to release.
2. **Partial sends are silent with skip.** CQE_SKIP_SUCCESS suppresses all
   `res >= 0` completions, including short writes. A short send with no CQE
   means the remainder is never resubmitted — data loss on backpressure.

So the CQE must stay. The realistic levers are (a) making dead iterations
cheaper (done: #239 no-block-with-ready-queue, #245 pre-block replenish),
and (b) reducing the *number* of send CQEs under backpressure — see next.

## 2. Short sends

A stream send carries `MSG_DONTWAIT` (`STREAM_SEND_FLAGS`). It takes what the
socket has room for and returns, and never waits on an io-wq worker thread. A
short result or `-EAGAIN` waits for room as §4 describes, and the final CQE
settles the send with its full length.

The sends of a `send_chain` carry `MSG_WAITALL` (`CHAIN_SEND_FLAGS`): the kernel
retries a short send until the buffer is sent or an error occurs. Its parts are
linked, so a short part would be followed by the next one across a gap (#734).

## 3. io_uring zero-copy RX (kernel 6.15+) — scoping

On io_uring a plaintext connection receives directly into its accumulator:
the kernel copies from its socket buffers into the accumulator, and no copy
follows in user space, except when the accumulator grows to fit a longer
message and moves the part already received. A TLS connection's ciphertext
is received into its TLS engine's buffer and goes to rustls; the copies on
that path are counted in `docs/syscalls-and-copies.md`.
io_uring zcrx (`IORING_OP_RECV_ZC`, netdev queue + refill ring, merged
~6.15) removes the kernel's copy: it DMA-places packet payload into
user-registered memory; completions carry
(offset, len) into that area, and userspace returns regions via the refill
ring.

What adopting it would mean for ringline:

- **Hardware/config gated**: needs NIC header-data split + flow steering
  to a dedicated RX queue per worker; falls back to copy mode otherwise.
  This is a deployment feature, not a default.
- **Accumulator model changes**: data arrives as non-contiguous regions of
  the registered area with kernel-controlled lifetime (region is pinned
  until returned via refill). Either (a) copy into the accumulator, which
  adds a user-space copy in place of the kernel's, or (b) make the accumulator
  a rope over zcrx regions with `Bytes`-like refcounts driving refill
  returns. (b) is real surgery: `with_data(&[u8])` needs a contiguous
  view, so a rope must linearize on demand (copy only when a message
  spans regions) or the parser API must accept iovecs.
- **Interaction with #246**: the frozen-remainder design already
  refcounts; a zcrx region handle could slot into a new enum arm of the
  accumulator. The `try_into_mut` recovery path would not
  apply (region memory is never uniquely owned by the accumulator).
- **Sizing**: refill-ring starvation replaces ENOBUFS as the stall mode;
  the #245 event-driven re-arm pattern transfers.

Verdict: large, worthwhile only after a workload shows the kernel's receive
copy at the top of a profile on >=6.15 kernels with capable NICs. Not this
phase. Prereq checklist for revisiting: kernel >= 6.15 on the rig, NIC with
HDS (mlx5/bnxt/ice), a profile showing the kernel's receive copy >= ~5% of
worker CPU.

## 4. Waiting for room

A send that comes back short or with `-EAGAIN` waits in the event loop, behind a
`POLLOUT` poll. Its pool slot or slab entry stays allocated, nothing of it is in
the kernel, and `in_flight` stays true, so byte order holds.
`docs/half-closed-send-wait-design.md` has the design, the kernels it was
measured on, and the options not chosen.

io_uring adds `POLLRDHUP` to every poll's event mask. Once a peer has half-closed
(sent its FIN), a `PollAdd(POLLOUT)` on the socket completes at once with
`POLLRDHUP` even while the send buffer is full, so a send retried behind a
one-shot poll spins the worker's event loop (#603). That result moves the send to
a multishot poll, which is edge-triggered: it reports `POLLRDHUP` once and then
`POLLOUT` when room appears.

`MSG_WAITALL` waits in the kernel instead, on an io-wq worker from the
unbound pool, which `ConfigBuilder::iowq_max_workers` does not cap: one
thread for each connection whose send waits on a half-closed socket (#605).
A `send_chain` uses it, because its parts are linked. Zero-copy sends inside a
`send_chain` can fail instead: an `-EAGAIN` there fails the chain and closes the
connection, so a chain part larger than the send buffer's free space cannot reach
a half-closed peer, even one that is reading. `send_parts` waits for room.

### `-ENOMEM` from a zero-copy send

From Linux 6.15, a `SendMsgZc` from memory that is not a registered buffer
charges `len / page_size + 2` pages to the user's `RLIMIT_MEMLOCK` while it
is in flight. From 6.14 the same limit also holds every io_uring ring
(`ringline/src/memlock.rs`). When the pages do not fit, the operation fails
with `-ENOMEM` and sends nothing. The handler sends that entry with a plain
`send` of its first non-empty unsent iovec, under the `SendMsgZcDrain` tag, and
marks the entry so that the rest of it, including a resubmission that waited on
a full SQ or for room, also goes out as plain `send`s rather than as further
`SendMsgZc`s. A plain `send` pins no memory and posts no notification. Each send therefore takes at
most one `-ENOMEM`, counted by the `ringline/pool` counter `send_zc_enomem`.
A process with `CAP_IPC_LOCK` in the initial user namespace is not charged
and does not reach this path. Inside a `send_chain`, `-ENOMEM` fails the
chain and closes the connection (#642, #734).

### At worker shutdown

`run_shutdown` releases each send waiting for room first, since nothing of it
is in the kernel. It closes every connection with the `CancelAll` lead, on every
kernel, so a send in the kernel is cancelled, and a coalesced send's slab entry
is released on its completion. A connection holding
slab entries gets the cancel alone, and its `Close` waits for them, as below. Entries parked on
a retry list, with no operation in flight, are released first. It then waits,
for at most 10 s (`SHUTDOWN_BOUND`), until every connection's `Close` has completed and
every send-slab entry is released. A zero-copy entry is
released only once its notifications land, and the kernel posts them when the
peer has acknowledged the data and the kernel has freed it. A peer that does
not read keeps that data queued, so a connection whose entries are not released
within 1 s is closed with `SO_LINGER {on, 0}`, which sends an RST and discards the
queued data, so the notifications land at once (#607). That includes a peer that
is reading too slowly to take its data in that second. Setting the option on a
fixed file needs io_uring's setsockopt command (Linux 6.7). Below 6.7, or for an
entry whose connection had closed before exit began, nothing can abort it: the
entry holds the worker for the 10 s bound, and its guards and the send pool's
memory are then leaked, since the kernel can still read them.

## 5. Admission and parking

Copied sends are admitted transactionally. On io_uring `DriverCtx::send`
reserves every send-pool slot the buffer needs (`SendCopyPool::reserve_slots`
— a count, not popped slots) before copying the first byte, so a pool `Err`
from `ConnCtx::send` / `send_nowait` means nothing was queued or transmitted
and the same buffer may be resent; a buffer wider than the whole pool is
refused up front with `InvalidInput`. The hole this closes (a retry after a
mid-buffer refusal duplicated the already-queued prefix) and the design are
in [copied-send-reservation-design.md](copied-send-reservation-design.md).

A built SQE that cannot be pushed because the SQ is still full after
`submit()` is parked, never dropped: it stays at the head of its connection's
send queue with `in_flight = true`, the connection is registered on
`pending_send_retries`, and the event loop's `drain_send_retries` re-pushes
the same bytes on the next iteration. After two failed attempts the send
waiter is failed and the connection closed, exactly as `drain_copy_retries`
does for a partial-write resubmit, so a starved connection is never left open
with a hole in its byte stream.

Consequence: on io_uring `DriverCtx::send` fails only before it has committed
anything (stale token, or pool admission). The one remaining exception is TLS
pool exhaustion mid-encryption — rustls has advanced its record sequence but
the pool refused the ciphertext — which series PR 8's pre-mutation bound
closes.
