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

None yet.

## Outcome

None yet.
