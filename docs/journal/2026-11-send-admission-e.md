# Experiment E: TLS replies in gated pieces under strict order

- **Status:** open. Prediction written; no run yet.
- **Span:** Nov 2026 · follows Experiment D (`2026-11-send-admission-d.md`)
  and the fast-path specification's Parts 1 to 3 · SystemsLab context
  `send-admission-expC`
- **Code:** `ringline-bench`'s `admission-server` and `admission-load` with
  Experiment D's pieces, gate, closed loop and records added to main's
  versions, which serve TLS. Spec `experiments/send-admission-e.toml`, cells
  and arms `experiments/send-admission-e-matrix.json`, report
  `experiments/send-admission-e-report.py` (D's report with TLS as a cell
  key).

## Goal

Experiment D showed that, over plaintext, large replies sent in pieces of at
most 128 KiB, each gated on socket room (`SendHalf::writable`), keep small
replies fast under strict FIFO order (O0) in every rule cell. The owner
chose O7w for TLS (`docs/send-admission-design.md`, section 4), and D did
not run TLS. A server that sends its TLS replies in gated
pieces may not need O7w. E runs D's rule cells over TLS, with whole replies
under O0 and O7w and gated pieces under O0. The question is whether gated
pieces under O0 pass D's decision rule over TLS. If they do, a server whose
large replies are all copied and sent in gated pieces can use strict order.

Differences from plaintext that could change the result:

- Admission counts a TLS reply as one slot per 16 KiB record plus one. A
  128 KiB piece is 9 slots (8 over plaintext), and a whole 3 MiB reply 193.
  Three stalled whole replies (579 slots) exceed the 512-slot pool, so W1's
  whole TLS heads cannot be admitted under either order: the Part 2 runs
  (`2026-11-send-admission-o7w.md`, TLS) timed out every W1 head at 1,000 ms.
- The worker encrypts every byte, so it spends more CPU per reply, and U's
  per-piece overhead is a smaller share of it.
- The runtime writes one record per slot. A piece is several sends to the
  socket, so whether a piece goes into the socket whole after `POLLOUT`
  may differ from plaintext.

## Design

Cells: D's rule cells (W1; W2 with six slow readers; W4 at `tcp_wmem` 1 MiB
with 72 and 128 stalled peers; W5), W4 at 256 KiB with 128 stalled peers,
and U. D's W4 cells with 4 and 56 stalled peers are left out because every
D arm except O0 whole passed them. Every W4 cell runs on hv03, where D's W4
cells at 1 MiB ran; D ran W4 at 256 KiB on hv01, where 128 KiB pieces
exceeded 10 ms, and on hv03 in a rerun, where they did not.

Arms, with TLS in a 16,448-byte slot:

- TLS O0 whole: positive control. It must fail as plaintext O0 whole did in
  D, with fast small p99 above 100 ms in W1, W4 and W5. If it does not, the
  cells are not contended over TLS and the other arms are not read.
- TLS O7w whole: the runtime's default order with whole replies.
- TLS O0 gated 128 KiB: the arm under test.
- TLS O0 gated 64 KiB: the smaller piece, as in D.
- Plaintext O0 whole and O0 gated 128 KiB: D's arms on this build, which has
  the gate's fixes made after D, to compare TLS with plaintext on the same
  binaries and hosts.

Four runs per arm and cell, two of each O0 whole arm: 18 runs per cell, 126
in all. The report puts TLS in the cell key, so each gated arm is compared
with the O0 whole arm of its own transport.

## Prediction

Written before any run.

- TLS O0 gated 128 KiB passes D's decision rule in W1, W2, W4 at 1 MiB and
  W5: every 7 MiB reply and every W5 slow reader's reply completes, fast
  small p99 is at most 10 ms in every run, and no more fast small replies
  pass `admit_limit` than under TLS O0 whole. Reason: the gate admits a
  stalled peer's piece only while its socket has room, so the peer holds at
  most one piece, 9 slots, and only until the socket takes it. In D no
  stalled peer's piece waited for room, so each left the pool once sent.
- In W4 at 1 MiB with 128 stalled peers, TLS gated fast small p99 is higher
  than plaintext gated on the same host, because the worker also encrypts,
  and at most 10 ms.
- No stalled peer's gated TLS piece waits for room in W4. Refuted if any
  does: that would mean a TLS piece does not go into the socket whole after
  `POLLOUT`.
- TLS O0 whole fails: fast small p99 above 100 ms in W1, W4 and W5, and no
  7 MiB reply completes in W1, W4 or W5.
- TLS O7w whole keeps fast small p99 below 10 ms in W1 and in W4 up to 72
  stalled peers, and completes no 7 MiB reply in W1, W4 or W5.
- U: TLS whole replies cost more worker CPU per byte than plaintext whole.
  TLS gated 128 KiB pieces cost at most 1.42 times TLS whole per byte, D's
  plaintext ratio, since the per-piece cost is unchanged and the per-byte
  cost grows.
- The plaintext arms reproduce D's figures for the same cells within D's
  spread: O0 gated 128 KiB fast small p99 at most 3.0 ms in the rule cells.

What would refute the conclusion that a TLS server can use strict order with
gated pieces: TLS O0 gated 128 KiB with fast small p99 above 10 ms in any run
of a rule cell, a 7 MiB or W5 slow-reader reply not completed, or more fast
small replies past `admit_limit` than TLS O0 whole.

What each outcome would lead to:

- TLS gated 128 KiB passes: a server that sends every large copied TLS reply
  in gated pieces can run strict order for TLS. A server that also sends
  plaintext replies by zero-copy still needs a bound on those before strict
  order covers them.
- It fails only in W4 at 128 stalled peers or at 256 KiB: compare with
  plaintext gated on the same host; if plaintext passes, the difference is
  TLS (CPU, or pieces not going in whole); the free-slot and waited-for-room
  figures separate the two.
- It fails in W1 or W5: look at the pieces that waited for room and the
  room-wait aborts; that would point at the gate under TLS, not the order.
