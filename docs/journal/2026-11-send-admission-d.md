# Experiment D: large replies in pieces gated on socket room

- **Status:** closed. All three gated arms pass the decision rule, which
  picks 128 KiB pieces. A profile of U puts 90% of the 42% extra worker CPU
  per byte in loopback's receive path, mostly waking the reader.
- **Span:** Nov 2026 · follows Experiment C (`2026-11-send-admission-c.md`)
  · SystemsLab context `send-admission-expC`
- **Commits:** commits cited here that are not on main are on
  brayniac/ringline: the `exp/send-admission-*` branches, and
  `docs/send-admission-expC`, which holds this entry's commits as they were
  before they were squashed into main. The files under `experiments/` that
  are cited here and are not on main are on `exp/send-admission-d-run`.

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

### The matrix

234 runs on 3db626d8 (artifact `01a1e2ca-f88b`), with the spec
`experiments/send-admission-d.toml` and the matrix file as at 3db626d8:
nine cells, six arms, four repetitions and two more of O0 whole. Run ids
`01a1e2ed-d4df` to `01a1e2ee-4a24`, all `success`. The report is
`experiments/send-admission-d-report.py` at a603ad17. Hosts: U, W1 and W4 at
256 KiB on hv01 (Zen 2); W2 and W5 on hv02; the other W4 cells on hv03
(Zen 4). No run recorded TCP memory pressure.

Fast small replies' p99, median over runs and the largest run in brackets
(ms), and 7 MiB replies completed:

| cell | O0 whole | O7w whole | O0 ungated 128 KiB | O0 gated 64 KiB | O0 gated 128 KiB | O7w gated 128 KiB |
| --- | --- | --- | --- | --- | --- | --- |
| W1 | 765.3 (765.7), 60/60 | 0.4 (0.5), 40/40 | 0.3 (0.4), 40/40 | 0.3 (0.5), 40/40 | 0.2 (0.4), 40/40 | 0.3 (0.4), 40/40 |
| W2, 6 slow | 680.6 (681.2), 60/60 | 0.5 (0.5), 40/40 | 0.4 (0.5), 40/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 |
| W4, 1 MiB, k = 4 | 1153.2 (1153.7), 0/60 | 0.4 (0.4), 0/40 | 0.4 (0.6), 40/40 | 0.4 (0.4), 40/40 | 0.4 (0.5), 40/40 | 0.4 (0.4), 40/40 |
| k = 56 | 1161.9 (1164.2), 0/60 | 0.5 (0.5), 0/40 | 0.6 (0.9), 40/40 | 0.5 (0.9), 40/40 | 0.6 (0.6), 40/40 | 0.6 (0.8), 40/40 |
| k = 72 | 1162.9 (1164.1), 0/60 | 0.5 (0.5), 0/40 | 961.7 (962.0), 40/40 | 1.1 (3.0), 40/40 | 0.7 (1.1), 40/40 | 0.8 (1.0), 40/40 |
| k = 128 | 1165.6 (1171.4), 0/60 | 5.4 (6.7), 0/40 | 957.5 (965.3), 40/40 | 1.2 (1.2), 40/40 | 2.6 (2.8), 40/40 | 2.4 (2.5), 40/40 |
| W4, 256 KiB, k = 128, hv01 | 1168.6 (1169.9), 0/60 | 25.4 (26.5), 0/40 | 994.1 (1611.9), 40/40 | 8.8 (9.1), 40/40 | 12.7 (12.8), 40/40 | 12.1 (12.3), 40/40 |
| W5 | 1112.3 (1114.4), 0/60 | 0.5 (0.5), 0/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 | 0.5 (0.6), 40/40 | 0.5 (0.5), 40/40 |

- Gated arms: every 7 MiB reply completed in every cell, with medians of 3.9
  to 7.2 ms. The fewest free slots during a 7 MiB reply was 501 of 512, in
  W4, and none of the 282,920 pieces sent to stalled peers (W1 and
  W4) waited for room. Every stalled connection was aborted at the room-wait
  limit. W5's slow readers: 160 of 160 replies completed in each gated arm,
  with no aborts. No fast small reply went past `admit_limit`.
- Ungated 128 KiB pieces: fine at k = 56 (fewest free 55), and at k = 72 and
  128 every slot was taken and fast small p99 was 957 to 994 ms, with 18 to
  1,136 fast small replies per run past `admit_limit`. The step falls between
  the calibrated limit's sides, 56 and 72 (floor(504 / 8) = 63).
- O0 whole: fast small p99 1,112 to 1,169 ms in W4 and W5, with 3,905 to 4,375
  fast small replies per run (mean of each cell's runs) past `admit_limit`; no
  7 MiB reply completed in W4 or W5, and every W5 slow reader was aborted at
  `settle_limit`.
- O7w whole: fast small replies 0.4 to 0.5 ms in W4 up to k = 72, 2.0 to
  6.7 ms at k = 128, and 16.9 to 26.5 ms at k = 128 with 256 KiB on hv01. No
  7 MiB reply completed in W4 or W5 (every one timed out waiting for
  admission, as C1 predicted), and every W5 slow reader was aborted.

Partial sends (pieces that waited for room, of those sent):

- W2, to drainers: 1,800 of 1,920 128 KiB pieces (every piece after the
  first of each 2 MiB reply) and 3,600 of 3,840 64 KiB pieces (all but the
  first two), in each 128 KiB arm, gated or not.
- The 7 MiB reply to a fast reader, with `tcp_wmem` at 256 KiB: 128 KiB
  pieces waited in 467 and 472 of 2,240 in W2 and 699 and 702 of 2,240 in W4
  on hv01; 64 KiB pieces in none of 4,480 in either cell. With `tcp_wmem` at
  1 MiB, no gated arm's 7 MiB pieces waited, in any cell.
- W5, to slow readers at 1 MiB: no gated piece waited (0 of 3,840 and 0 of
  7,680); 1,600 of 3,840 ungated pieces did.

U, one reader, `SO_RCVBUF` reported as 1,048,576 in every run, every reply
completed:

| arm | p50 per reply (µs) | p99 (µs) | worker CPU per reply (µs) | CPU per byte against O0 whole |
| --- | --- | --- | --- | --- |
| O0 whole (6 runs) | 2,813 | 3,258 | 2,802 | 1.00 |
| O7w whole | 2,806 | 3,174 | 2,793 | 1.00 |
| O0 ungated 128 KiB | 4,013 | 4,241 | 3,976 | 1.42 |
| O0 gated 64 KiB | 4,523 | 4,843 | 4,401 | 1.57 |
| O0 gated 128 KiB | 4,085 | 4,362 | 3,979 | 1.42 |
| O7w gated 128 KiB | 4,138 | 4,400 | 4,089 | 1.46 |

O0 whole's own runs spread 135 µs in p50 and 0.017 ns/B in CPU per byte.
Each piece adds 21 to 23 µs of worker CPU at 128 KiB (56 a reply) and 14 µs
at 64 KiB (112 a reply).

The worker thread was 97.7 to 98.8% busy over the load's run in every arm
(schedstat CPU against wall time), with one connection. The worker blocks in
the kernel when it has nothing to do (no SQPOLL, no busy polling), so U
already saturated it, and the extra time per reply is CPU time on the
worker's CPU, not idle time between pieces. I do not know how that CPU
divides between ringline's work per piece (admission, completion, the gate's
poll and wake), the kernel's send path run once per piece, and loopback's
receive processing, which runs on the sending CPU and would not run on the
server with a real NIC. A profile of the worker's CPU would separate them.

### W4 at 256 KiB, rerun on hv03

The prediction's 10 ms limit was exceeded in one cell, W4 at k = 128 with
`tcp_wmem` at 256 KiB, by both 128 KiB gated arms (12.1 to 12.8 ms). I had
placed that cell on hv01, and the other W4 cells on hv03. The gated arms of
that cell were rerun on hv03 on the same binaries, four runs each (ids
`01a1e37f-964d` to `01a1e37f-9a8c`):

| arm | fast small p99, median (largest run) | 7 MiB replies, median | fewest free | 7 MiB pieces that waited |
| --- | --- | --- | --- | --- |
| O0 gated 64 KiB | 1.0 (1.0) ms | 40/40, 5.3 ms | 504 | 0 of 4,480 |
| O0 gated 128 KiB | 1.3 (1.4) ms | 40/40, 4.3 ms | 501 | 90 of 2,240 |
| O7w gated 128 KiB | 1.2 (1.5) ms | 40/40, 4.5 ms | 500 | 90 of 2,240 |

No stalled peer's piece waited for room (0 of 40,960), and no run recorded
TCP memory pressure. On hv03 the 7 MiB reply's 128 KiB pieces were partly
sent in 4% of cases against 31% on hv01. I do not know which property of
hv01 causes either difference. The refutation stands as measured on hv01;
the rerun shows the cell passes on the host class the other W4 cells ran on.

### U profile: where the extra CPU goes

The matrix's U left the 42% extra worker CPU per byte unattributed (above).
With the owner's agreement this replaced a saturated-worker sweep, since U
already kept the worker 98-99% busy with one connection.

Setup: `experiments/send-admission-d-profile.toml` and its build spec at
2f145cc4 of `exp/send-admission-d-run`, binaries from 3db626d8 rebuilt with
forced frame pointers (artifact `01a1e3da-50c2`). U as in the matrix on
hv01, with `perf record -e cpu-clock -F 4000 -C 0 -g --call-graph fp` on the
worker's CPU for the load's run; two runs each of O0 whole, O0 ungated
128 KiB and O0 gated 128 KiB (`01a1e3df-70e8` to `01a1e3df-7319`). A first
batch of six (`01a1e3db-249a` to `01a1e3db-26f6`) recorded nothing: the
image has no `perf`, and `apt-get install` needs an `apt-get update` first.
Samples are bucketed per reply by `send-admission-d-profile-buckets.py`; a
sample goes to the first bucket whose frames are in its stack: loopback
receive (`net_rx_action`, `tcp_v4_rcv` and the like), kernel send
(`tcp_sendmsg` and the like), poll, other io_uring, then user space.
Profiled replies took longer than unprofiled ones (O0 whole's p50 3,212
against 2,813 µs), so only the shares are used.

Prediction, written before these runs:

- P1: ringline's user-space code accounts for less than a quarter of the
  extra, under 5 µs per piece; refuted at 5 µs per piece or more.
- P2: the gate costs under 1 µs per piece: gated exceeds ungated by under
  56 µs per reply, and the gate's poll path is under 1 µs per piece.
- P3 (a guess, not a test): most of the extra is in the kernel, more likely
  in loopback's receive processing than in the send path.

CPU 0's busy time per reply (µs, mean of two runs; idle excluded):

| bucket | O0 whole | ungated 128 KiB | gated 128 KiB | gated minus whole |
| --- | --- | --- | --- | --- |
| loopback receive: waking the reader (`sock_def_readable`) | 284 | 1,015 | 1,228 | +944 |
| loopback receive: the rest | 274 | 424 | 538 | +264 |
| kernel send | 1,764 | 2,132 | 2,123 | +359 |
| copy into send slots (libc, under `send_bounded`) | 777 | 563 | 464 | -313 |
| ringline user space | 45 | 90 | 96 | +51 |
| io_uring, other | 61 | 78 | 83 | +22 |
| poll (gate and room) | 1 | 1 | 11 | +10 |
| other kernel | 9 | 41 | 15 | +6 |
| total busy | 3,215 | 4,342 | 4,557 | +1,342 |

The reader-wakeup row is the samples whose leaf is
`_raw_spin_unlock_irqrestore` called from `sock_def_readable`: cpu-clock
samples taken with interrupts off are recorded where they are re-enabled, so
the leaf stands for the wakeup of the client's reading thread on another
CPU, an IPI. The widest run-to-run spreads are gated's loopback receive
(1,632 and 1,900) and its slot copy (416 and 511); the buckets script prints
each run's range.

- Most of the extra (+1,208 µs per reply, 90%) is loopback's receive path
  on the sending CPU, and three quarters of that is waking the reader:
  in pieces the reader drains the socket and sleeps between sends, so it is
  woken more often. Over a NIC this work runs on the client's machine.
- Kernel send grows 359 µs per reply, about 225 of it in `clear_page_rep`
  under `prep_new_page` from `sk_page_frag_refill`, the kernel zeroing new
  pages for the socket as it allocates them: 687 against 912 µs.
- The copy into send slots costs 313 µs less per reply in 128 KiB pieces. I
  infer that a 128 KiB piece's slots are still in cache when they are
  reused, where a 7 MiB reply's are not; I did not measure cache misses.
- Ringline's own code, io_uring's and the gate's poll together add 83 µs per
  reply, 1.5 µs per piece.

Against the prediction:

- P1 holds: ringline's user space adds 0.9 µs per piece (1.5 µs with
  io_uring and the poll).
- P2: the gate's poll path costs 0.2 µs per piece, which holds; gated busy
  time exceeds ungated by 215 µs per reply, which refutes the condition as
  written. The excess is in the reader-wakeup and receive rows, which vary
  most between runs. The unprofiled matrix (four runs each) gave 3,979
  against 3,976 µs of worker CPU per reply, no difference.
- P3 holds: 90% of the extra is loopback receive.

Derived, not measured: without the loopback receive rows, gated 128 KiB's
busy time per reply is 2,791 µs against whole's 2,657, 5% more. A NIC send
path has costs loopback does not (driver, interrupts, segmentation), which
this does not include.

### Against the prediction

- U: 128 KiB gated pieces took 45% longer than whole replies, inside "up to
  50%", and 64 KiB pieces 61%, longer still. Agrees.
- W1 and W2: below 1 ms (at most 0.5) and every 7 MiB reply completed.
  Agrees.
- W4 at 1 MiB: every 7 MiB reply completed and at least 500 slots stayed
  free. Fast small p99 was above the predicted 1 ms at k = 72 (64 KiB,
  median 1.1 ms and 3.0 ms in one run; 128 KiB, 1.1 ms in one run) and at
  k = 128 (1.2 to 2.8 ms), inside the
  10 ms refutation threshold. The ungated arm exceeded 100 ms at k = 72 and
  128, past k x h_p + 8 > 512. O0 whole made small replies wait over a
  second at every k. O7w whole was below 1 ms up to k = 72 but not at
  k = 128 (2.0 to 6.7 ms); C1, which has no CPU time, gave 0.
- W4 at 256 KiB: both gated arms kept at least 503 slots free and no stalled
  peer's piece waited, as derived for 32 KiB segments. Fast small p99 for
  128 KiB pieces exceeded 10 ms on hv01, which refutes the prediction there
  (above).
- Partial sends: none in W4 to stalled peers; in W2 every 128 KiB piece to a
  drainer after the first and all but two 64 KiB pieces of each reply.
  Agrees. Not predicted: at 256 KiB the 7 MiB reply's 128 KiB pieces to a
  fast reader were also partly sent (4 to 31% by host), and its 64 KiB pieces
  were not.
- W5: every gated arm completed every slow reader's reply and every 7 MiB
  reply with no aborts, below 1 ms. Both whole arms aborted every slow
  reader. Agrees.

## Outcome

By the decision rule, applied as written:

- O0 gated 64 KiB, O0 gated 128 KiB and O7w gated 128 KiB each pass in W1,
  W2, W4 at 1 MiB and W5: every 7 MiB reply and every W5 slow reader's reply
  completed, fast small p99 at most 3.0 ms, and no fast small reply past
  `admit_limit` (O0 whole had 3,905 to 4,329 per run, mean of each cell's
  runs, in the rule's W4 and W5 cells, and 4,375 in W4 at 256 KiB, which is
  not one of the rule's cells).
- The rule picks the larger passing p, 128 KiB, under O0, or under O7w where
  TLS on the same worker uses it.
- U's CPU per byte is 1.42 times whole replies for 128 KiB pieces (1.46
  under O7w), under the rule's 2x threshold, so the rule does not send it to
  the owner. The profile puts 90% of the extra in loopback's receive path
  on the worker's CPU, mostly waking the reader; without it, pieces cost 5%
  more CPU per reply (derived). Ringline's own code adds 1.5 µs per piece.
- The prediction is refuted in one cell, W4 at 256 KiB on hv01, by both
  128 KiB gated arms (12.1 and 12.7 ms median against 10 ms). On hv03 the same
  arms gave 1.2 and 1.3 ms.

My recommendation, apart from the rule:

- Gated pieces for plaintext, as the rule says.
- Size p from the socket's send buffer, not as a constant: at most a third of
  `sk_sndbuf`, which is the free space the gate waits for, and at most
  128 KiB. The partial sends support it: with `tcp_wmem` at 256 KiB (a third
  is 85 KiB) 128 KiB pieces to a fast reader were partly sent and 64 KiB
  pieces never were; at 1 MiB neither was. This is the rule's "how it sizes p
  against a socket's send buffer" clause, inferred from these cells.
- U's cost does not argue against 128 KiB or against 64 KiB pieces: the
  per-piece cost on the server is about 1.5 µs of ringline and io_uring plus
  the kernel's per-send work.

D ran on 3db626d8, whose gate still had two bugs that need a second send
waiting on the gated connection (above); D's harness gates a piece only
after the previous one settled, so neither occurs in D. cf35d0fb fixed them
and broke the gate's wake on a peer reset; a603ad17 fixed that. The commits
on the gate branch after its last review (67297b33, c381e17b, 8bde5e21,
b7c28f9c, 7f0b245a) are unreviewed and go with the specification's PR.
