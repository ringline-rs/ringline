# Experiment C: an admission order that lets replies past a waiting head

- **Status:** open. C0, C1 and C2's matrix have run; C2's W1 cell with sends
  outside the FIFO and the echo check are queued on the final binaries.
- **Span:** Nov 2026 · follows #945 (Experiment B) · SystemsLab context
  `send-admission-expC`

## Goal

Experiment B (`2026-11-send-admission-b.md`) showed that with every reply
sent through `send_admitted`, small replies wait behind a large reply at the
head of the send-capacity FIFO until the head is admitted: p99 about 770 ms
in its contended case, against 11.5 ms with `send`. The owner decided on
2026-11-15 that a server cannot accept that wait. Experiment C chooses the
admission order the fast-path specification uses (`docs/send-admission-design.md`,
section 4, "Admission orders" and "Experiment C"): one that keeps small
replies near the uncontended delay while a head waits, without timing out
heads that today's order admits.

## Method

As designed in section 4, at cd4f9bc5:

- C0, on the rack with today's code: `admission-server` and `admission-load`
  gain request timestamps, server-side scheduled-to-admission delays, an L
  sampler, a pipelined server mode, slow readers, draining connections and
  sends outside the FIFO. W1 and W2 run under O0 and O1.
- C1, a discrete-event model (`ringline-bench/src/bin/admission-model.rs`),
  validated against Experiment B and C0's W2, sweeps every order.
- C2, on the rack: the orders C1 does not reject, with O0 and O1, behind a
  hidden configuration option on the work branch
  `exp/send-admission-c-orders`.

The specifications the tools were built from are summarised here as they are
built; deviations from the design are listed with their reason.

## Prediction

As committed in cd4f9bc5, before any run. The author's:

- O2 times heads out in W2 at L / S of 1.5, as O1 does.
- O3 times heads out in W2 at L / S of 1.5 at a ratio of 1, and not at a
  ratio of 2. Passing sends to slow readers hold their slots for up to
  `settle_limit`, and only a ratio of 2 covers O0's wait plus that.
- O4's maximum head delay is within 10 ms of O0's in every contended cell,
  and its small-reply p99 in W1 is at most 10 ms.
- O5 admits heads as O0 does, and small replies as O1 does while the small
  pool has free slots.
- O7's maximum head delay exceeds O0's by at most the time the large holders
  take to return R slots. In W2 its small replies wait behind the head once
  slow readers hold R.

The owner's, which names no cell: O3 starves a large head. It is refuted if,
in every contended cell, O3 has no more head timeouts than O0, and its
maximum head delay exceeds O0's by at most the longest hold of a send that
passed it.

Added on 2026-11-15, after C2's matrix started and before the echo check
ran: the owner asked for the echo check to also measure `send` (its
`SendCompletion` dropped, bench-server `--echo-mode bytes-send`) against
`send_nowait` (`bytes-nowait`). They differ only in the completion-table
entry that `send_nowait` skips. Judged as Experiment B judged its arms, over
four boots of four rounds each, closed loop, worker CPU per operation, each
arm paired by round with `nowait`:

- The author's: `send` is within the floor of `nowait` (the median change
  between consecutive `nowait` rounds in one boot; 2.0% in B), with a paired
  median change no larger than `strict`'s (`send_admitted`, +1.7% in B).
  Refuted if `send`'s paired median change exceeds that floor. If it is
  refuted, the clients that call `send_nowait` have a measured reason to keep
  a path without a completion.
- The control: `strict` against `nowait` repeats B's `bytes-admitted` against
  `bytes-nowait`. A paired median change outside B's range (-5.1% to +4.1%)
  means this session is not comparable with B's.

## Results

### C0 pilots

Binaries: `experiments/send-admission-c-build.toml` at 81cc413c of
`exp/send-admission-c-tools` (artifact `01a1e022-5ac7`). One run per cell,
`experiments/send-admission-c0.toml`, one guest on hv03, Linux 6.12. W2 here:
three drainers per episode asking for 2 MiB each and reading at 2 MiB/s with
`SO_RCVBUF` 4096, `tcp_wmem` capped at 256 KiB, `--pipeline 16`, a 7 MiB head
(S = 64 slots), slow readers asking for 4 KiB replies at 100/s each and
reading 128 KiB/s with `SO_RCVBUF` 4096, ratio 1. "Fast p99" is the server's
delay from scheduled time to admission for small replies to fast readers.

| run (`01a1e022-`) | cell | fast p99 | heads admitted | head median / max | L / S |
| --- | --- | --- | --- | --- | --- |
| `a056` | W1, O0, N = 1 | 770.5 ms | 10 of 10 | 802.2 / 806.2 ms | 0 |
| `a089` | W2, O0, no slow readers | 706.5 ms | 10 of 10 | 740.8 / 741.6 ms | 0 |
| `a0b6` | W2, O0, 6 slow readers | 688.1 ms | 10 of 10 | 719.8 / 725.1 ms | 0.86 |
| `a0e1` | W2, O0, 8 slow readers | 689.4 ms | 10 of 10 | 721.9 / 726.7 ms | 1.15 |
| `a10b` | W2, O1, no slow readers | 11.5 ms | 10 of 10 | 740.3 / 741.6 ms | 0 |
| `a135` | W2, O1, 6 slow readers | 11.6 ms | 0 of 10 (timed out) | - | 1.50 |
| `a15f` | W2, O1, 8 slow readers | 11.6 ms | 0 of 10 (timed out) | - | 2.00 |

- W1 under O0 reproduces Experiment B with the new instruments.
- W2 is contended: under O1, six slow readers hold L / S = 1.50 and every head
  times out, while O0 admits every head. Under O0 the same readers hold less
  (0.86), because their later replies wait behind the head.
- No slow reader was aborted (no reconnects).
- The 11.5 ms under O1 with nothing waiting is the floor Experiment B saw at
  the client. In `a10b` the delay was 5.75 ms at p50 and 11.5 ms at p99 while
  the `send` call took at most 53 us, so the requests reached the server
  late. The fast connections waited for their next send in a blocking read
  under `SO_RCVTIMEO`, which the kernel rounds up to a timer tick. e550b661
  waits with `ppoll` instead and records how late each request is written.

With e550b661 (artifact `01a1e02c-28c0`):

| run (`01a1e02c-`) | cell | fast p99 | send lateness p99 | heads admitted | head median / max |
| --- | --- | --- | --- | --- | --- |
| `8191` | W1, O1, N = 1 | 0.4 ms | 0.37 ms | 10 of 10 | 802.1 / 805.7 ms |
| `815a` | W2, O1, no slow readers | 0.6 ms | 0.50 ms | 10 of 10 | 740.3 / 741.2 ms |
| `81c0` | W2, O0, 6 slow readers, repetition 2 | 679.2 ms | - | 10 of 10 | 717.1 / 720.9 ms |

- The floor is gone: the server's p99 under O1 is the load's lateness in
  writing the request, about 0.4 to 0.6 ms. The design's 10 ms threshold for
  small replies is above it.
- Under O1 the pool refused 2 (W1) and 9 (W2) fast small replies in the
  window, each aborting its connection, once requests arrived on time.
- The second O0 repetition of W2 with six slow readers admitted its heads
  within 4 ms of the first (717.1 / 720.9 against 719.8 / 725.1 ms), with
  the same L / S.

### C2 pilots

Binaries: a6b625d8 of `exp/send-admission-c-run` (the tools merged with
97375dea of `exp/send-admission-c-orders`; artifact `01a1e035-6b34`), before
the fixes from that branch's review. ringline's whole suite, fmt, clippy and
doc pass on io_uring at a6b625d8 (`experiments/send-admission-c-test.toml`,
`01a1e041-c739`, Linux 6.12). One run per order, W2 with six slow readers at
a ratio of 1, hv03, R = 32 for the budget orders:

| run (`01a1e035-`) | order | fast p99 | heads admitted | head median / max | L / S |
| --- | --- | --- | --- | --- | --- |
| `abd1` | O0 | 679.3 ms | 10 of 10 | 717.2 / 721.0 ms | 0.86 |
| `aba1` | O1 | 0.4 ms | 0 of 10 (timed out) | - | 1.50 |
| `abfb` | O2 | 0.4 ms | 0 of 10 (timed out) | - | 1.50 |
| `ac23` | O3 | 178.2 ms | 10 of 10 | 933.9 / 949.4 ms | 1.50 |
| `ac4b` | O4 | 0.4 ms | 10 of 10 | 716.7 / 718.8 ms | 0.86 |
| `ac7a` | O7 | 275.8 ms | 10 of 10 | 717.0 / 719.3 ms | 1.07 |
| `aca2` | O7w | 0.5 ms | 10 of 10 | 716.7 / 718.7 ms | 0.86 |

- O4 and O7w kept small replies to fast readers at O1's delay and admitted
  every head when O0 did. About 14,300 fast replies passed a head in each,
  holding their slots for at most 0.07 ms at p99, and B reached 3 slots. No
  reply to a slow reader passed, so L / S is O0's.
- O3 admitted every head, 217 ms later than O0 at the median, within 51 ms
  of `admit_limit`. 822 replies to slow readers passed and held their slots
  for 935 ms at p99, near `settle_limit`; B reached 113 slots and the latch
  closed 170 times.
- Under O7, 262 replies to slow readers passed, held their slots for 570 ms
  at p99 and kept B at R = 32, so small replies to fast readers then waited
  behind the head.
- O2 timed out every head, as O1 did.

### C1 validation

`admission-model` (cb95cc7e), at its default buffer parameters (the kernel
buffer 260 KiB in W2: the 256 KiB `tcp_wmem` cap plus the reader's
`SO_RCVBUF`), seed 0.

Against Experiment B's contended runs:

- O0: small-reply end-to-end p99 459.5, 759.5 and 759.5 ms at ratios 0.5, 1
  and 2, against B's 470, 771 and 770 ms; the head admitted after 800 ms and
  delivered after 806.8 ms, against 808 ms; no head at 0.5, as in B.
- O1: the head delivered after 806.8 ms, against 805 and 806 ms.
- Missed: at ratio 0.5, O0's small replies not delivered within the limit,
  0 against B's 124 to 200 per run. The model has no delay between the
  client and the server, so no request is in flight when the head joins.
- None of these figures moves with the kernel buffer, the writable mark or
  the stalled peers' buffer: B tests the schedule, not the draining.

Against C0's W2 pilots, with L counted as the server counts it (the slots of
admitted, unsettled small replies):

- Within 10%: the heads' admission (O0: -4 to -7%), L / S (O0: 0.93 and
  1.24 against 0.86 and 1.15; O1: 1.50 and 2.00, as measured), O1's head
  timeouts (10 of 10 at six and eight slow readers, as measured), and O0's
  fast-reply p99 with no slow readers and with six (-8% and -6%).
- Missed: with eight slow readers, O0's fast-reply p99 (840.9 against
  689.4 ms) and O1's refused fast replies (2540 against 558). With eight
  slow readers and three drainers the pool is full at each episode's start
  in the model, every episode starts in the same state, and a freed slot
  goes back to the reader that freed it at once.
- Under O0, the slots the model's slow readers hold, counting settled
  replies whose slots wait in an unfinished 32-slot run, are 1.6 times L as
  the server counts it (1.1 times under O1); the server cannot see those.

The model is used to rank and reject orders, not for counts that depend on
the pool's exact state at an episode's start.

### C1 sweep

`admission-model` at cb95cc7e over the cells C2 runs, every order, seeds 1 to
5 (the seeds move only the open-loop phases): W2 with 0, 2 and 6 slow readers
and W1 with N = 1 and 16, at `admit_ms` 999, 1001 and 2000 (999 and 1001
straddle the tie at a ratio of 1), and W1 with sends outside the FIFO at 1001.
O5 has a main region of 448 x 16 KiB and a small one of 256 x 4 KiB, the
bytes of O0's pool; O7 and O7w have R = 32. Heads admitted of 50, the
largest admission delay, and the median p99 of fast small replies'
scheduled-to-admission delay:

| cell | O0 | O1 | O2 | O3 | O4 | O4w | O5 | O6 | O7 | O7w |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| W2, 6 slow, 999 | 50, 689, 648 | 0 | 0 | 0 | 50, 689, 86 | 50, 689, 86 | 50, 689, 0 | 0 | 50, 689, 218 | 50, 689, 0 |
| W2, 6 slow, 2000 | 50, 689, 648 | 0 | 0 | 50, 1434, 702 | 50, 689, 86 | 50, 689, 86 | 50, 689, 0 | 50, 1434, 390 | 50, 689, 218 | 50, 689, 0 |
| W2, 2 slow, 999 | 50, 689, 648 | 50, 689, 0 | 50, 689, 0 | 50, 689, 0 | 50, 689, 0 | 50, 689, 0 | 50, 689, 0 | 50, 689, 150 | 50, 689, 215 | 50, 689, 0 |

- With no slow readers (W2) and in every W1 cell, every order admits all 50
  heads at O0's delay (689 and 800 ms), and every order but O0 and O6 keeps
  fast small replies at 0. O0's are 648 and 759 ms; O6's 150 and 260 ms at
  999 and 1001, and 0 at 2000.
- C1 rejects O2 (every head timed out with six slow readers, as O1), O3
  (every head timed out at a ratio of 1, and at 2 the heads admitted after
  twice O0's delay) and O6 (the same, and W1's small replies at 260 ms).
- O4, O4w, O5, O7 and O7w admit every head when O0 does. O5 and O7w keep
  fast small replies at 0 in every cell; O4 and O4w reach 86 ms with six
  slow readers, O7 215 ms with two or six.
- C2 still runs O3, which the owner's prediction is about.

### C2 matrix

Binaries: a8249ba1 of `exp/send-admission-c-run` (artifact `01a1e08d-3591`),
the orders after their first two reviews. Its io_uring suite passed
(`01a1e08c-b436`). Seven cells, each on one host: the W1 cells on hv01, W2
with no slow readers on hv02, the other W2 cells on hv03. Seven orders, four
repetitions with the order rotated each round, and two more of O0: 210 runs,
all `success`, ids in the scratch list `c2-ids-keep.txt` of the session that
ran them. The W1 cell with sends outside the FIFO is not here: its 30 runs
were cancelled before they ran, because the third and fourth reviews found
that sends outside the FIFO could leave O3's and O4's latch open at a head
change. It reran on the final binaries (below).

Summarised by `experiments/send-admission-c2-report.py`. The largest head
admission delay over every run, and the median over runs of the per-run p99
of fast small replies' scheduled-to-admission delay, in ms:

| cell | O0 | O1 | O3 | O4 | O5 | O7 | O7w |
| --- | --- | --- | --- | --- | --- | --- | --- |
| W1, N = 1 | 808.6, 766.2 | 808.9, 0.2 | 808.5, 0.3 | 808.8, 0.3 | 809.0, 0.4 | 808.6, 0.2 | 808.3, 0.4 |
| W1, N = 16 | 808.6, 765.2 | 808.6, 0.3 | 808.5, 0.3 | 808.6, 0.3 | 808.9, 0.3 | 808.5, 0.3 | 808.0, 0.4 |
| W1, N = 16, ratio 2 | 808.5, 765.4 | 809.5, 0.2 | 808.6, 0.3 | 808.5, 0.4 | 809.2, 0.2 | 808.8, 0.5 | 808.8, 0.3 |
| W2, no slow readers | 741.5, 701.8 | 741.6, 0.5 | 741.4, 0.5 | 741.6, 0.5 | 743.2, 0.5 | 741.5, 0.5 | 741.7, 0.5 |
| W2, 2 slow | 743.5, 678.2 | 744.3, 0.4 | 743.3, 0.4 | 743.1, 0.4 | 742.9, 0.4 | 743.8, 198.6 | 743.4, 0.4 |
| W2, 6 slow | 721.3, 679.0 | all timed out, 0.4 | 949.2, 180.6 | 742.8, 0.4 | 743.1, 0.4 | 743.2, 274.1 | 742.8, 0.4 |
| W2, 6 slow, ratio 2 | 721.2, 679.3 | all timed out, 0.4 | 949.2, 179.6 | 718.9, 0.4 | 743.1, 0.4 | 721.1, 274.0 | 718.9, 0.4 |

Every head (40 per order and cell, 60 for O0) was admitted, except under O1
with six slow readers, where all 40 timed out. The per-run fast p99s are
within 0.3 ms of their median for every order but O0 (within 2.6 ms), O3
(178.0 to 181.0 ms) and O7 (195.6 to 198.8 and 273.6 to 276.4 ms). Fast small
replies beyond `admit_limit` or not admitted: none except O1's refusals (12 to
31 per cell in W1 and W2 with no slow readers, 5 with two slow readers). The
spread of O0's per-run maximum head delay is under 2.2 ms in every cell except
W2 with two slow readers (24.3 ms).

The orders' counters with six slow readers at a ratio of 1, summed over each
order's four runs (at a ratio of 2 they are within 4 slots and 0.1%):

| order | passes by slow readers | longest hold of one | passes by fast readers | most slots passing sends held | latch closings |
| --- | --- | --- | --- | --- | --- |
| O3 | 3,288 | 939.7 ms | 57,293 | 114 | 635 |
| O4 | 0 | - | 57,301 | 7 | 0 |
| O7 | 1,084 | 570.1 ms | 32,398 | 32 (R) | - |
| O7w | 0 | - | 57,292 | 6 | - |

- O3's 228 ms over O0 is the slow readers' passing sends: they held their
  slots for up to 940 ms, and passing sends held up to 114 slots.
- O4 let no reply to a slow reader pass, and its latch never closed: its idle
  condition alone kept them out. O7w likewise.
- O7's slow readers' passing sends filled R = 32, after which fast small
  replies waited behind the head (274 ms p99). The W2 small-reply criterion
  counts replies beyond `admit_limit`, of which O7 has none, so O7 passes
  the rule. The criterion was written before the runs and is applied as
  written; O7's p99 is reported beside it.

The W1 cell with sends outside the FIFO (`send_nowait`, 1,000/s on four
connections) ran on hv02 on the final binaries: f561f58a (artifact
`01a1e11f-c3a0`), whose library is that of 86346b85, the run branch with the
orders' last fix. The io_uring suite passed at 86346b85 (`01a1e126-bbea`, on
delta) after a test fixed in eb956201 (below). 30 runs, all `success`. Every
order admitted every head, and the largest head delay was 810.2 to 811.2 ms
against O0's 810.4 ms (O0's run maxima spread 1.2 ms). Fast small replies'
p99 was 766.3 ms under O0 and 0.5 to 0.6 ms under every other order, with
none beyond `admit_limit`. The sends outside the FIFO changed no order's
result.

The suite at e0203d46 (`01a1e0c7-790d`) had failed one test,
`a_cancelled_head_s_successor_latches_on_free_plus_passing_at_the_change`,
with 12 free slots where it expected 9, alone and in the suite, every time
(`01a1e121-6eb8`). An instrumented run (`01a1e124-423e`) showed the released
task was never polled: the test pushed a parked task's index onto the ready
queue, and `take_ready` returns a standalone task only once its slot records
a wake. eb956201 wakes it with `wake_task`. With
`restart_send_window_if_head_changed` made to return at once, the fixed test
fails at its last assertion (`01a1e126-bc1a`).

With that cell, the decision rule's result for C, before the echo check:
O3 fails, on its head delay with six slow readers; O4, O5, O7 and O7w pass.

Against the predictions:

- O3 times heads out at a ratio of 1 and not at 2: refuted. O3 timed out no
  head at either ratio; its slowest head was 949 ms at both.
- O4 within 10 ms of O0's maximum in every contended cell: refuted in one
  cell, where it exceeded O0's by 21.5 ms (742.8 against 721.3 ms, six slow
  readers, a ratio of 1), held in the other (718.9 against 721.2). O0's own
  maximum in W2 with two slow readers was 743.5 ms, so a 743 ms head occurs
  under O0 too. O4's W1 p99 is 0.3 to 0.4 ms, as predicted.
- O5 admits heads as O0 does and small replies as O1 does: held.
- O7's head within O0's plus the time to return R slots, and small replies
  waiting behind the head once slow readers hold R: held.
- The owner's, that O3 starves a large head: refuted by its stated condition.
  O3 timed out no more heads than O0 (none), and its maximum exceeded O0's by
  228 ms, less than the 940 ms longest hold of a send that passed it. O3
  fails the decision rule on that 228 ms.

Against C1: the model's O0 is within 5% of the rack (648 against 679 ms in
W2, 759 against 765 ms in W1), and its O5 and O7w match. It overstated O3,
timing out every head with six slow readers at a ratio of 1 where the rack
timed out none, and O4's fast p99 with six slow readers (86 ms in the model,
0.4 ms on the rack). The rack's O4 passed no slow reader's reply; whether the
model's idle condition lets them pass has not been checked.

## Outcome

None yet.
