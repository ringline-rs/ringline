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
