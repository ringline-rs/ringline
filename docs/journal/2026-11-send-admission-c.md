# Experiment C: an admission order that lets replies past a waiting head

- **Status:** open. C0, C1 and C2 have not run.
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

## Outcome

None yet.
