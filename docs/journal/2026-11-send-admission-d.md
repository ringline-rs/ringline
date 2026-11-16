# Experiment D: large replies in pieces gated on socket room

- **Status:** open. The design is at 618149b4; the model (C1-D) and the
  calibration have run; the matrix (234 runs) is running on 3db626d8.
- **Span:** Nov 2026 · follows Experiment C (`2026-11-send-admission-c.md`)
  · SystemsLab context `send-admission-expC`

## Goal

Experiment C compared admission orders that let small replies past a large
reply waiting at the head of the send-capacity FIFO. The owner decided on
2026-11-15 that for plaintext the fast path should instead bound what one
send holds: large replies are sent in pieces, and a piece takes pool slots
only once its socket reports `POLLOUT`. Experiment D tests that design
against whole replies under O0 and O7w, and against pieces without the gate
(`docs/send-admission-design.md`, section 4, "Experiment D").

## How the design got here

- The first draft had pieces and no gate. Its review found that whole replies
  limit themselves (a whole reply is admitted only when all its slots are
  free, so stalled 3 MiB replies stop after three in W1, and O7w then keeps
  small replies fast however many peers stall), while pieces let every
  stalled peer hold one. The draft's own decision rule would have rejected
  streaming. The review's model runs, reproduced in the session: O7w whole at
  k = 16, fast small p99 0 ms; O0 with emulated 256 KiB pieces, 0 ms at
  k = 31 and 960 ms at k = 32.
- A worker-wide budget on slow connections' pieces was considered next and
  dropped before it was written down: a stalled peer's stuck piece is
  admitted while its connection still looks fast, so no budget sees it.
- The gate on `POLLOUT` replaced it. Two more review rounds corrected the
  gate's poll (it must be the connection's own `SendPollOut`, with a one-shot
  probe on a connection whose poll is multishot), the rule for when a piece
  goes into the socket whole (truesize, and `tcp_sendmsg` filling the last
  segment without a check), the gated abort floor (about one piece per
  `settle_limit`, not a third of the buffer), W5's episode length, and the
  decision's criteria, which are now absolute.

## Prediction

As committed in 618149b4, before any run: the design's "Prediction" list.

## Results

### C1-D: the model

`admission-model` at fbf4b3f9, sweep `experiments/send-admission-d-model.py`
at 4c759ac0, seeds 1 to 5, N = 16, `admit_limit` = `settle_limit` = 1 s,
R = 32. With every new flag off, the model's output over C1's 160 cells at
seeds 1 and 2 is identical to cb95cc7e's apart from the added keys.

Parameters the model assumes, derived, not measured:

- Stalled requests are 40 µs apart, the median gap between stalled requests
  in C2's 120 W1 runs (p10 33, p90 52 µs), and the head one gap plus 200 ms
  after the last. The rack's server joined stalled replies to the FIFO about
  530 µs apart, because the worker builds each 3 MiB reply; the model has no
  CPU time.
- 896 B of truesize overhead per segment, from Linux 6.12's small-head cache
  (`SKB_TRUESIZE(320)`), assuming `MAX_TCP_HEADER` is 320 and `sk_buff`
  aligns to 256. That gives 69.6% payload at 2 KiB segments. The design's
  61% corresponds to a 1,280 B head, as before 6.3. An overhead of 1,280 B
  changes no outcome below.
- Segments are the MSS, at most half the peer's largest window: 65,483 B to
  fast readers, 32 KiB to stalled peers (which set `SO_RCVBUF` after
  connecting, so advertised 64 KiB at the handshake), 2 KiB to drainers and
  slow readers. `sk_sndbuf` is the `tcp_wmem` maximum for every connection,
  and acknowledgement is instant.
- U is not modelled: the model has no CPU cost per piece.

Fast small replies' p99 (median over seeds, ms), 7 MiB replies completed of
50, and the fewest free slots during a 7 MiB reply:

| cell | O0 whole | O7w whole | O0 ungated 128 KiB | O0 gated 64 KiB | O0 gated 128 KiB | O7w gated 128 KiB |
| --- | --- | --- | --- | --- | --- | --- |
| W1 | 759.3, 50, 48 | 0.0, 50, 64 | 0.0, 50, 479 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| W2, 6 slow | 686.9, 50, 0 | 0.0, 50, 0 | 0.0, 50, 377 | 0.0, 50, 394 | 0.0, 50, 377 | 0.0, 50, 377 |
| W4, 1 MiB, k = 4 | 1151.4, 0, 48 | 0.0, 0, 64 | 0.0, 50, 471 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 32 | 1152.5, 0, 63 | 0.0, 0, 64 | 0.0, 50, 247 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 56 | 1153.4, 0, 63 | 0.0, 0, 64 | 0.0, 50, 55 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 63 | 1153.7, 0, 63 | 0.0, 0, 64 | 0.0, 50, 0 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 64 | 1153.8, 0, 63 | 0.0, 0, 64 | 957.1, 50, 0 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 72 | 1154.1, 0, 63 | 0.0, 0, 64 | 957.1, 50, 0 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| k = 128 | 1156.3, 0, 63 | 0.0, 0, 64 | 1828.6, 50, 0 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |
| W4, 256 KiB, k = 128 | 1156.3, 0, 119 | 0.0, 0, 127 | 1876.6, 50, 0 | 0.0, 50, 508 | 0.0, 50, 503 | 0.0, 50, 503 |
| W5 | 919.2, 50, 32 | 0.0, 50, 31 | 0.0, 50, 471 | 0.0, 50, 508 | 0.0, 50, 504 | 0.0, 50, 504 |

The full sweep (k = 4, 8, 16, 32, 48, 56, 63, 64, 72, 96, 128) is in the
sweep's output; the rows left out follow the same pattern. The ungated arm
at k = 128 also timed out 580 fast small replies.

Against the predictions, in the model:

- W1 and W2: every gated arm keeps fast small replies at 0 ms (the model has
  no CPU floor) and completes every 7 MiB reply. Agrees.
- W4 at 1 MiB: the gated arms keep at least 503 of 512 slots free and
  complete every 7 MiB reply at every k. The ungated arm steps between k = 63
  (0 ms) and 64 (957 ms), where k x 8 + 8 > 512. O0 whole is at 1,151 to
  1,156 ms at every k and O7w whole at 0. Agrees. Neither whole arm completes
  a 7 MiB reply at any k >= 4: every one times out waiting for admission.
- W4 at 256 KiB: agrees with 32 KiB segments to the stalled peers, where no
  stalled peer's gated piece waits for room. Varying that segment size, 64 KiB
  gated pieces pass at 2, 4, 8, 16, 32 KiB and 65,483 B, and 128 KiB gated
  pieces pass at 2 KiB and at 16 KiB or more but fail at 4 and 8 KiB: the
  second piece is partly sent, each stalled peer holds 8 slots, the pool runs
  out, fast p99 reaches 1,885 ms and no 7 MiB reply completes. At 32 KiB
  segments the second piece's last segment starts at 226 KiB of 256 KiB
  (the design says about 236 KiB). The calibration run's `ss -tmi` decides
  which case the rack is in.
- Partial sends: in W4 no stalled peer's gated piece waited for room at
  either `tcp_wmem`. In W2, 2,250 of 2,400 128 KiB pieces to drainers waited
  (every piece after the first), and 4,500 of 4,800 64 KiB pieces (all but
  the first two of each reply's 32). Agrees.
- W5: the gated arms complete every slow reader's 3 MiB reply (200 of 200)
  and every 7 MiB reply, with no aborts. Both whole arms abort every slow
  reader. Agrees. Not predicted: ungated 128 KiB pieces also complete all
  200, so W5 separates pieces from whole replies, not the gate from ungated
  pieces.
- Against the rack: with these parameters the model's O0 whole in W2 is
  within 1.3% of C2 (686.9 against 679.0 ms fast p99; 730.6 against 721.3 ms
  slowest head), closer than C1's 648 and 689 ms.

The rack's W4 k values either side of the ungated limit: 56 and 72, with 4
and 128. The model's step is between 63 and 64 at 8 slots per stalled peer;
if calibration measures h_p slots per stalled peer, the limit is
floor(504 / h_p).

### Calibration

Binaries: ba3cec47 of `exp/send-admission-d-run` (artifact `01a1e2b3-f183`),
the gate before its second round of fixes; the calibration's arms do not use
the gate. hv03, `debian-13-6.12`, one run per cell, all `success`
(`01a1e2b4-9fb8` to `01a1e2b4-a2c1`). The fewest free slots of 512, and the
stalled peers' sockets from `ss -tmi` every 100 ms:

| stalled peers | whole 3 MiB replies | ungated 128 KiB pieces |
| --- | --- | --- |
| 1 | 384 free: 128 held | 504 free: 8 held |
| 2 | 256 free: 256 held | 496 free: 16 held |
| 3 | 128 free: 384 held | 488 free: 24 held |

- h = 128 slots (2 MiB) per stalled whole reply: the socket took 1 MiB of
  the 3 MiB. h_p = 8 slots per stalled ungated piece, the whole run, as the
  model had it. The ungated limit is floor(504 / 8) = 63, so W4 runs k = 4,
  56, 72 and 128 as planned.
- A stalled peer's socket: `sk_sndbuf` (tb) 1,048,576 and `wmem_queued`
  1,078,336, one segment past the buffer, as `tcp_sendmsg`'s unchecked last
  segment allows. Its MSS is 32,768, the case in which the model predicts
  that 128 KiB gated pieces pass W4 at 256 KiB (they fail at 4 and 8 KiB).
- The drainer (CAL-DRAIN, 3 MiB at 512 KiB/s, 4 KiB receive window): MSS
  2,048 and `snd_wnd` 4,096, as derived. Whole replies aborted its three
  replies at `settle_limit`; ungated pieces completed all three, 30 of 72
  pieces waiting for room.
- The image's own `rmem_max` and `wmem_max` are 212,992. No run recorded
  TCP memory pressure.

### The matrix's binaries, and a pilot

The matrix runs on 3db626d8 of `exp/send-admission-d-run` (artifact
`01a1e2ca-f88b`): the gate after its first two review rounds, the harness
after both of its rounds, and the order arm set to O7w. On delta's io_uring
suite at 3db626d8 every gate test passed but one,
`a_socket_filled_by_whole_sends_is_not_writable`, and 16 of 18 mutations
went red; the two that stayed green had tests that could not reach them, and
the failing test was later shown to be the socket's buffer growing, not the
gate (below).

Two later review rounds found gate bugs that 3db626d8 still has, each of
which needs a second send waiting on, or still in the kernel of, the gated
connection: a gate re-armed on `Recheck` could busy-loop the worker on a
socket that reports `POLLOUT` while `send` returns `EAGAIN`, and a gate
blocked on a waiting send could arm against that send while it was still in
the kernel. The harness gates a piece only after the previous piece has
settled, so neither can happen in D. The fixed gate, at cf35d0fb, broke the
gate's wake on a peer reset (`a_peer_reset_while_waiting` hung), which D's
drainers produce at the end of each episode, so the matrix stays on
3db626d8 and the fixes continue on the gate branch.

At cf35d0fb the whole-sends test read the kernel's figures through
`NETLINK_SOCK_DIAG`: the gate started on a socket with `wmem_queued`
1,761,664 and `sk_sndbuf` 2,626,560, not writable, and by the time it
resolved `sk_sndbuf` had grown to 4,194,304 and the socket was writable. The
gate was right; loopback's autotuning moved the threshold.

A pilot on 3db626d8 checked the gate in D's own setting before the matrix:
W4 with 128 stalled peers and gated 128 KiB pieces, one run each at
`tcp_wmem` 1 MiB and 256 KiB, hv03 (`01a1e2d2-83e1`, `01a1e2d2-8442`):

| `tcp_wmem` | fast small p99 | 7 MiB replies | their median | fewest free | stalled pieces that waited for room |
| --- | --- | --- | --- | --- | --- |
| 1 MiB | 2.4 ms | 10 of 10 | 4.2 ms | 501 of 512 | 0 of 7,680 |
| 256 KiB | 1.1 ms | 10 of 10 | 4.2 ms | 503 of 512 | 0 of 2,560 |

All 1,280 stalled connections were aborted at the room-wait limit, holding
no slots. 21 of the 560 head pieces at 256 KiB waited for room, to a reader
that drains. No TCP memory pressure.

## Outcome

Not yet.
