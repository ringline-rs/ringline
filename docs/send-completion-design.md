# Send-completion overhead: CQE-skip analysis, MSG_WAITALL, zero-copy RX scoping

## 1. Why IOSQE_CQE_SKIP_SUCCESS does not apply to ringline sends

Diag counters (cachecannon client, GET-heavy p32) show ~15% of event-loop
iterations wake for send CQEs that wake no task ("dead iterations"). The
obvious-looking fix — `IOSQE_CQE_SKIP_SUCCESS` on fire-and-forget sends —
is unsound here, for two independent reasons:

1. **Slot lifecycle runs on the CQE.** Every send references ringline-owned
   memory (SendCopyPool slot, InFlightSendSlab entry, provided-buffer bids
   for recv-forward). The completion CQE is the *only* signal that the
   kernel is done with that memory; skipping it leaks the slot. There is no
   send path with no resource to release.
2. **Partial sends are silent with skip.** CQE_SKIP_SUCCESS suppresses all
   `res >= 0` completions, including short writes. A short send with no CQE
   means the remainder is never resubmitted — data loss on backpressure.

So the CQE must stay. The realistic levers are (a) making dead iterations
cheaper (done: #239 no-block-with-ready-queue, #245 pre-block replenish),
and (b) reducing the *number* of send CQEs under backpressure — see next.

## 2. MSG_WAITALL on stream sends (prototype candidate)

io_uring honors MSG_WAITALL for `IORING_OP_SEND`/`SENDMSG` on stream
sockets: on a short send the kernel re-arms internally and retries until
the full buffer is sent or an error occurs. Today, each short send costs:
CQE → userspace resubmit of the remainder (new SQE) → another CQE. With
MSG_WAITALL those intermediate round trips collapse into one final CQE.

- Win regime: backpressured connections (slow readers, deep pipelines,
  large values). No effect when sends complete fully (the common case at
  low load — this is a tail optimization).
- Correctness: the final CQE still fires with the total length (or error),
  so slot release and queue progression are unchanged. The userspace
  partial-resubmit machinery stays as a fallback for kernels where a path
  doesn't honor WAITALL.
- Risk: a WAITALL send on a stuck peer holds its pool slot until the
  socket errors or is closed — but the userspace resubmit loop has the
  same property (the slot is held across resubmits), so no new hazard.
- Non-goal: SendMsgZc + WAITALL interaction is murkier (notif semantics);
  prototype plain Send/SendMsg first.

## 3. io_uring zero-copy RX (kernel 6.15+) — scoping

The last mandatory copy on the ringline recv path is
ProvidedBufRing → RecvAccumulator (`extend_from_slice`). io_uring zcrx
(`IORING_OP_RECV_ZC`, netdev queue + refill ring, merged ~6.15) DMA-places
packet payload into user-registered memory; completions carry
(offset, len) into that area, and userspace returns regions via the refill
ring.

What adopting it would mean for ringline:

- **Hardware/config gated**: needs NIC header-data split + flow steering
  to a dedicated RX queue per worker; falls back to copy mode otherwise.
  This is a deployment feature, not a default.
- **Accumulator model changes**: data arrives as non-contiguous regions of
  the registered area with kernel-controlled lifetime (region is pinned
  until returned via refill). Either (a) copy into the accumulator —
  pointless, that's the copy we're removing — or (b) make the accumulator
  a rope over zcrx regions with `Bytes`-like refcounts driving refill
  returns. (b) is real surgery: `with_data(&[u8])` needs a contiguous
  view, so a rope must linearize on demand (copy only when a message
  spans regions) or the parser API must accept iovecs.
- **Interaction with #246**: the frozen-remainder design already
  refcounts; a zcrx region handle could slot into `PendingUdpBuf`-style
  enum arms of the accumulator. The `try_into_mut` recovery path would not
  apply (region memory is never uniquely owned by the accumulator).
- **Sizing**: refill-ring starvation replaces ENOBUFS as the stall mode;
  the #245 event-driven re-arm pattern transfers.

Verdict: large, worthwhile only after a workload shows the recv memcpy at
the top of a profile on >=6.15 kernels with capable NICs. Not this phase.
Prereq checklist for revisiting: kernel >= 6.15 on the rig, NIC with HDS
(mlx5/bnxt/ice), a profile showing accumulator append >= ~5% of worker CPU.

## 4. Waiting for room after `EAGAIN`

io_uring adds `POLLRDHUP` to every poll's event mask. Once a TCP peer has
half-closed (sent its FIN), a `PollAdd(POLLOUT)` on the socket completes at
once with `POLLRDHUP` even while the send buffer is full. Measured on a socket
with a full send buffer, before and after the peer's `shutdown(SHUT_WR)`, on
Linux 6.12 (arm64 and x86_64) and 7.1 (x86_64):

| op | no FIN | after FIN |
|---|---|---|
| `Send` + `MSG_WAITALL` | waits | waits |
| `SendMsg` + `MSG_WAITALL` | waits | `-EAGAIN` |
| `SendMsgZc` | waits | `-EAGAIN` |
| `Writev` | waits | `-EAGAIN` |
| `PollAdd(POLLOUT)` | waits | completes with `POLLRDHUP` |

So a vectored send (`sendmsg`, `SendMsgZc`, `writev`) that returns `-EAGAIN`
is not retried behind a `POLLOUT` poll: that loop never waits and spins the
worker's event loop (#603). The handler instead submits a plain `send` of the
entry's first non-empty unsent iovec, under a `*Drain` tag
(`SendMsgCoalescedDrain`, `SendRecvBufsCoalescedDrain`, `SendMsgZcDrain`,
`ForwardWriteDrain`). Its result is a partial write of the same entry, so the
drain tag's completion goes through the entry's own handler, which advances
the iovecs and resubmits the rest with the entry's own operation. The entry
stays the one operation in flight on the connection, so byte order holds. A
zero-copy entry's drain is a copying `send` and posts no notification.
Zero-copy sends inside a `send_chain` are linked SQEs and are not drained: an
`-EAGAIN` there fails the chain.

A `send` waits in this state by running on an io-wq worker thread from the
**unbound** pool, which `ConfigBuilder::iowq_max_workers` does not cap: one
thread for each connection whose send is waiting for room on a half-closed
socket. Without a FIN the kernel waits with an internal poll and no thread.
(Measured on Linux 6.12 arm64: 16 waiting sends held 16 `iou-wrk` threads
after the peers' FINs, and none without them.)
Waiting through an epoll fd instead would need an ordinary fd per connection;
#605 tracks that.

Plain `Send` paths (single-buffer copy sends, TLS) keep their `POLLOUT`
fallback (`SendPollOut`): a `send` with `MSG_WAITALL` does not return
`-EAGAIN` in this state, so the fallback is not reached.

### `-ENOMEM` from a zero-copy send

From Linux 6.15, a `SendMsgZc` from memory that is not a registered buffer
charges `len / page_size + 2` pages to the user's `RLIMIT_MEMLOCK` while it
is in flight. From 6.14 the same limit also holds every io_uring ring
(`ringline/src/memlock.rs`). When the pages do not fit, the operation fails
with `-ENOMEM` and sends nothing. The handler sends that entry through the
same drain as `-EAGAIN`, and marks the entry so that the rest of it,
including a resubmission that waited on a full SQ, also goes out as plain
`send`s rather than as further `SendMsgZc`s. Each send therefore takes at
most one `-ENOMEM`, counted by the `ringline/pool` counter `send_zc_enomem`.
A process with `CAP_IPC_LOCK` in the initial user namespace is not charged
and does not reach this path. Inside a `send_chain`, `-ENOMEM` fails the
chain (#642).

### At worker shutdown

`run_shutdown` closes every connection with the `CancelAll` lead, on every
kernel, so a send waiting for room on a connection is cancelled, and a
coalesced or recv-forward send's slab entry is released on its completion. A
forward write's operation is on its sink's file, which that lead does not
reach, so it is cancelled by its user_data. Entries parked on a retry list,
with no operation in flight, are released first. It then waits, for at most
100 × 100 ms, until every connection's `Close` has completed, every send-slab
entry is released, and every forward write has completed. A zero-copy entry is
released only once its notifications land, and the kernel posts them when the
peer has acknowledged the data and the kernel has freed it. A peer that does
not read keeps that data queued after the close, so such an entry holds the
worker for the whole bound, after which the guards are dropped with the
driver. #607 proposes replacing that wait with an abortive close
(`SO_LINGER {on, 0}`), which discards the queued data so the notifications land
at once; it needs io_uring's setsockopt command (Linux 6.7), so it waits on the
6.8 minimum proposed in #605.

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
