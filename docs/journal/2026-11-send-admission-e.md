# Experiment E: TLS replies in gated pieces under strict order

- **Status:** closed. TLS O0 gated 64 and 128 KiB pieces pass D's decision
  rule in every rule cell; 128 KiB fails W4 at `tcp_wmem` 256 KiB (929 ms),
  where 85 KiB (a third of the send buffer) and every smaller piece pass.
  With 512 slots, pieces of 16 to 128 KiB pass every rule cell over both
  transports; CPU per byte rises as they shrink (Addenda 2 and 3). In W2 the pool's slot count
  decides the result, not its slot size: 128 slots fail at 16 KiB and 64 KiB
  alike, and 512 pass (Addendum 4).
- **Span:** Nov 2026 · follows Experiment D (`2026-11-send-admission-d.md`)
  and the fast-path specification's Parts 1 to 3 · SystemsLab context
  `send-admission-expE`
- **Code:** `ringline-bench`'s `admission-server` and `admission-load` with
  Experiment D's pieces, gate, closed loop and records added to main's
  versions, which serve TLS. Spec `experiments/send-admission-e.toml`, cells
  and arms `experiments/send-admission-e-matrix.json`, report
  `experiments/send-admission-e-report.py` (D's report with TLS and the
  send pool as cell keys, and the decision and U cost run per transport and
  pool).

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
  may differ from plaintext. (Corrected after the runs: on io_uring the
  piece's slots go to the socket as one `sendmsg`, as a plaintext piece's
  do; see Outcome.)

## Design

Cells: D's rule cells (W1; W2 with six slow readers; W4 at `tcp_wmem` 1 MiB
with 72 and 128 stalled peers; W5), W4 at 256 KiB with 128 stalled peers, and
U. D's W4 cells with 4 and 56 stalled peers are left out because every D arm
that sent pieces, gated or not, passed them. (Corrected after the runs: this
said every arm but O0 whole; O7w whole completed no 7 MiB reply there.) Every
W4 cell runs on hv03, where D's W4 cells at 1 MiB ran; D ran W4 at 256 KiB on
hv01, where 128 KiB pieces exceeded 10 ms, and on hv03 in a rerun, where they
did not.

Arms, with TLS in a 16,448-byte slot:

- TLS O0 whole: positive control. It must fail as plaintext O0 whole did in
  D, with fast small p99 above 100 ms in W1, W4 and W5. If it does not, the
  cells are not contended over TLS and the other arms are not read.
- TLS O7w whole: the runtime's default order with whole replies.
- TLS O0 gated 128 KiB: the arm under test.
- TLS O0 gated 64 KiB: the smaller piece, as in D.
- Plaintext O0 whole and O0 gated 128 KiB: D's arms on this build, which has
  the gate as merged in #969, to compare TLS with plaintext on the same
  binaries and hosts.

Four runs per arm and cell, two of each O0 whole arm: 20 runs per cell, 140
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

## Addendum: an arm at a third of the send buffer

Written after 107 of the 140 matrix runs, before this arm ran. In W4 with
`tcp_wmem` at 256 KiB, TLS gated 128 KiB pieces failed (fast small p99 about
929 ms, 1,890 of 7,680 stalled peers' pieces waited for room), while TLS
gated 64 KiB and plaintext gated 128 KiB pieces passed. The stalled peers'
sockets had `sk_sndbuf` 262,144. A server that sizes pieces as a third of
the send buffer, at most 128 KiB, as Experiment D recommended, sends 85 KiB
pieces on these sockets, a size the matrix did not run.

Arm: TLS O0 gated 87,381-byte pieces (262,144 / 3), four runs in each cell
with `tcp_wmem` at 256 KiB (W4 with 128 stalled peers, W2 with six slow
readers) and in W4 at 1 MiB with 128 stalled peers.

Prediction: it passes in all three cells, with fast small p99 at most 10 ms,
every 7 MiB reply completed and no stalled peer's piece waiting for room:
when the gate opens at least a third of the buffer is free, and an 85 KiB
piece over TLS is six records. Refuted if a stalled peer's piece waits for
room in W4 at 256 KiB, which would mean a third of the buffer is too large a
piece over TLS.

## Results

Binaries: artifact `01a1ee2b-390b`, from build experiment `01a1ee2a-b75b`,
which records the source it built. Matrix runs `01a1ee34-6fc2` to
`01a1ee34-aa3d`: 138 of 140 `success`. The other two (W4 at 72 stalled peers,
rep 2, TLS O0 gated 128 KiB and plaintext O0 whole) never started: hv03 had
5.7 GiB available for an 8 GiB guest. Both were resubmitted once
(`01a1ee6c-61c7`, `01a1ee6c-622c`, `success`). Addendum runs `01a1ee6d-8643`
to `01a1ee6d-8a54`, 12 of 12 `success`. Summarised by
`experiments/send-admission-e-report.py` over the 152 runs. No run recorded
TCP memory pressure.

Fast small replies' p99, median over runs and the largest run in brackets
(ms), and 7 MiB replies completed. TLS:

| cell | O0 whole | O7w whole | O0 gated 64 KiB | O0 gated 85 KiB | O0 gated 128 KiB |
| --- | --- | --- | --- | --- | --- |
| W1 | 1152.2 (1154.4), 1/20 | 0.3 (0.4), 1/40 | 0.2 (0.5), 40/40 | - | 0.2 (0.4), 40/40 |
| W2, 6 slow | 698.5 (698.6), 20/20 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 |
| W4, 1 MiB, k = 72 | 1199.0 (1200.0), 0/20 | 0.5 (0.5), 0/40 | 0.5 (0.6), 40/40 | - | 0.5 (0.6), 40/40 |
| k = 128 | 1231.6 (1231.7), 0/20 | 0.5 (0.5), 0/40 | 0.5 (0.6), 40/40 | 0.5 (0.5), 40/40 | 0.4 (0.5), 40/40 |
| W4, 256 KiB, k = 128 | 1233.3 (1233.5), 0/20 | 0.5 (0.5), 0/40 | 0.5 (0.5), 40/40 | 0.5 (0.5), 40/40 | 928.4 (929.1), 40/40 |
| W5 | 1113.5 (1114.4), 0/20 | 0.5 (0.6), 0/40 | 0.5 (0.6), 40/40 | - | 0.5 (0.5), 40/40 |

Plaintext, on the same binaries and hosts:

| cell | O0 whole | O0 gated 128 KiB |
| --- | --- | --- |
| W1 | 765.0 (765.2), 20/20 | 0.2 (0.3), 40/40 |
| W2, 6 slow | 680.1 (680.2), 20/20 | 0.5 (0.5), 40/40 |
| W4, 1 MiB, k = 72 | 1163.0 (1163.3), 0/20 | 0.8 (1.1), 40/40 |
| k = 128 | 1171.4 (1173.7), 0/20 | 2.4 (2.8), 40/40 |
| W4, 256 KiB, k = 128 | 1167.0 (1169.9), 0/20 | 1.2 (1.4), 40/40 |
| W5 | 1112.9 (1113.6), 0/20 | 0.5 (0.5), 40/40 |

- Every gated arm completed every 7 MiB reply in every cell, with medians of
  4.1 to 9.2 ms except TLS 128 KiB in W4 at 256 KiB (755 ms, below), and
  every W5 slow reader's reply (160 of 160 per arm). No
  gated arm had a fast small reply past `admit_limit`; TLS O0 whole had
  3,715 to 5,610 per run in W1, W4 and W5.
- TLS W4 at 256 KiB with 128 KiB pieces: 2,520 of 10,240 stalled peers'
  pieces waited for room, the fewest free slots during a 7 MiB reply was 7
  of 512, and the 7 MiB replies took 755 ms (median). A stalled peer's
  second piece, when partly sent, holds its 9 slots until the kernel takes
  its last byte (admission counts one slot more than the piece's eight
  records). The next piece's gate then timed out, as it does for every
  stalled reply in every gated W4 arm (5,120 room-wait aborts there). Here
  5,080 ended that way and 40 in a settlement abort, a piece the socket
  never finished taking. A piece counts as waiting for room when a send of
  it came back short (`SendCompletion::waited_for_room`). The stalled peers'
  server-side sockets had `sk_sndbuf` 262,144 and about 235 KB queued
  (`wmem_queued`, from `ss`), in the TLS and plaintext arms alike, and each
  stalled peer was sent two pieces in both. Over plaintext no second piece
  waited for room. In every other TLS gated cell, and in the 85 KiB and
  64 KiB arms of this one, no stalled peer's piece waited (0 of 15,360 at
  85 KiB, 0 of 20,480 at 64 KiB).
- TLS O7w whole kept fast small p99 at 0.3 to 0.5 ms (medians) and completed 1
  of 40 7 MiB replies in W1 and none in W4 or W5, where every slow reader in
  W5 was aborted. TLS O0 whole completed 1 of 20 in W1.
- Pieces that waited for room, to readers that drain: TLS W2 drainers 1,800
  of 1,920 (128 KiB), 2,640 of 3,000 (85 KiB), 3,600 of 3,840 (64 KiB); the
  7 MiB reply's pieces 4 of 2,240 at 128 KiB and none at 64 or 85 KiB. Over
  plaintext in W2, 539 of 2,240 of the 7 MiB reply's 128 KiB pieces waited,
  and 82 of 2,240 in W4 at 256 KiB.

U, one reader, `SO_RCVBUF` reported as 1,048,576, every reply completed:

| arm | p50 per reply (µs) | p99 (µs) | worker CPU per byte (ns) | against O0 whole of its transport |
| --- | --- | --- | --- | --- |
| plaintext O0 whole (2 runs) | 2,867 | 3,522 | 0.385 | 1.00 |
| plaintext O0 gated 128 KiB | 4,091 | 4,454 | 0.551 | 1.43 |
| TLS O0 whole (2 runs) | 7,042 | 7,478 | 0.602 | 1.00 |
| TLS O7w whole | 7,061 | 7,480 | 0.601 | 1.00 |
| TLS O0 gated 64 KiB | 5,848 | 6,334 | 0.791 | 1.31 |
| TLS O0 gated 128 KiB | 5,652 | 6,032 | 0.758 | 1.26 |

Over TLS, gated pieces made a reply faster (5.7 ms against 7.0 ms median)
while costing more CPU. Each 128 KiB piece adds 20.5 µs of worker CPU over
TLS and 21.8 µs over plaintext. I do not know why the TLS reply is faster in
pieces; one candidate is that the client decrypts a piece while the server
encrypts the next, which whole replies do not allow.

### Against the prediction

- TLS O0 gated 128 KiB passes D's rule in W1, W2, W4 at 1 MiB and W5.
  Agrees.
- TLS gated fast small p99 higher than plaintext gated in W4 at 1 MiB with
  128 stalled peers: refuted. TLS was 0.4 ms (median) against plaintext's
  2.4 ms. I do not know why.
- No stalled peer's gated TLS piece waits for room in W4: refuted in W4 at 256
  KiB with 128 KiB pieces (2,520 of 10,240). Fast small p99 there was 928 ms
  (median), and the report's 3/4-free check, inherited from D, fails (7 of 512
  free); neither is a condition this prediction set for that cell. Holds in
  every other W4 cell and arm.
- TLS O0 whole fails in W1, W4 and W5 (1,114 to 1,233 ms) and completes no
  7 MiB reply there: holds but for one W1 reply of 20. The positive control
  failed, so the cells were contended over TLS.
- TLS O7w whole below 10 ms in W1 and W4 at 72 (0.3 to 0.5 ms), and no
  7 MiB reply completed in W1, W4 or W5: holds but for one W1 reply of 40.
- U: TLS whole costs more CPU per byte than plaintext whole (0.602 against
  0.385 ns), and TLS gated 128 KiB costs 1.26 times TLS whole, under 1.42.
  Agrees.
- Plaintext arms within D's figures: O0 gated 128 KiB at most 2.8 ms in the
  rule cells (D: 2.8 ms; the prediction's 3.0 ms is D's largest over all its
  gated arms) and 1.2 ms in W4 at 256 KiB on hv03 (D's rerun:
  1.3 ms). Agrees.
- Addendum, 85 KiB pieces: pass in all three cells with no stalled peer's
  piece waiting for room. Agrees.

## Outcome

- Over TLS, gated pieces under O0 pass D's decision rule at 64 and 128 KiB.
  Strict order with gated TLS pieces kept small replies at or below 0.6 ms
  in every rule cell and completed every large reply, which O7w with whole
  replies did not do in W1, W4 or W5.
- A fixed 128 KiB piece is too large over TLS for a 256 KiB send buffer: the
  piece is partly sent and holds its 9 slots until the kernel takes its last
  byte, and 128 stalled peers' pieces exceed the pool. I do not know why a TLS
  piece is partly sent where a plaintext piece of the same size is not. It is
  not one send per record: on io_uring `submit_coalesced_run` sends a run of
  up to 32 queued copy sends, plaintext or ciphertext, as one `sendmsg`, so a
  128 KiB piece is one `sendmsg` of eight slots either way (131,072 bytes of
  plaintext, or eight records of 16,413 bytes). A trace of the bytes each
  `sendmsg` returned, with `wmem_queued` and `sk_sndbuf` before it, for one
  stalled peer in each transport would separate the candidates.
- A piece of a third of the send buffer, at most 128 KiB, passed in every cell
  it ran, at 85 KiB on 256 KiB buffers and at 128 KiB on 1 MiB buffers. That
  is the sizing the design specifies, min(`send_buffer_size` / 3, 128 KiB)
  (`docs/send-admission-design.md`, Part 1). The 85 KiB arm ran only with a
  send buffer that had reached 262,144 bytes; a reply sized from a smaller
  buffer read earlier in the connection gets a smaller piece.
- Not covered: zero-copy replies, which hold send-slab entries rather than
  pool slots; network rather than loopback sockets; kernels other than 6.12;
  and buffers between 256 KiB and 1 MiB, where a third of the buffer is
  between 85 and 128 KiB.

## Addendum 2: smaller pieces, 64 and 32 KiB

Written after the 152 runs above, before these arms ran, to choose a piece
size. Arms: plaintext O0 gated 64 KiB and 32 KiB, and TLS O0 gated 32 KiB,
four runs in each of the seven cells, 84 runs. A 32 KiB piece is two TLS
records (three slots as admission counts them); a piece that is a multiple
of 16 KiB ends on a record boundary, which 85 KiB pieces did not.

Prediction:

- All three arms pass D's rule in every rule cell, and in W4 at 256 KiB, with
  no stalled peer's piece waiting for room: each is at most a third of the
  smallest send buffer in the cells (256 KiB).
- Fast small p99 is no lower than with 128 KiB pieces in any cell by more
  than run-to-run spread. Plaintext W4 at 1 MiB with 128 stalled peers, where
  128 KiB gave 2.4 ms, is the cell where it could fall.
- U costs more per byte as pieces shrink, from the per-piece cost E and D
  measured (about 12 to 22 µs of worker CPU per piece): plaintext 64 KiB 1.5
  to 1.7 times plaintext whole (D: 1.57), plaintext 32 KiB 1.7 to 2.1, and
  TLS 32 KiB 1.4 to 1.7 times TLS whole. A plaintext 32 KiB ratio above 2
  sends that size to the owner under D's rule.
- The 7 MiB reply's median rises as pieces shrink, in every cell.

Refuted if a 32 KiB arm fails a rule cell, or if any stalled peer's 32 or
64 KiB piece waits for room.

## Addendum 3: 16 KiB pieces, and 64 KiB slots

Written before these arms ran, while Addendum 2's runs were still running.

16 KiB pieces: plaintext and TLS O0 gated 16 KiB, four runs in each of the
seven cells, 56 runs. A 16 KiB piece is one TLS record, which admission
counts as two slots.

Slot size at equal pool memory, 8 MiB: the arms above use 512 slots of
16 KiB (16,448 bytes over TLS); these use 128 slots of 64 KiB, the slot size
of the cache server this design is for. Arms: plaintext O0 whole (two runs
per cell, the control for these cells), plaintext O0 gated 128 KiB, and TLS
O0 gated 128 KiB and 32 KiB, in each of the seven cells, 98 runs. TLS whole
replies cannot run here: a 7 MiB TLS reply needs 449 slots, more than the
pool has. The unbuffered TLS engine writes one record per slot, so a 64 KiB
slot carries 16 KiB of TLS ciphertext, and TLS O0 whole has no 64 KiB-slot
control; TLS arms here are read against the plaintext control and against
the same piece size with 16 KiB slots. The report puts slot size and pool
count in the cell key with TLS.

Prediction:

- 16 KiB pieces pass D's rule in every rule cell and in W4 at 256 KiB, over
  both transports, with no stalled peer's piece waiting for room.
- U: CPU per byte against whole replies of the same transport, 2.3 to 4.0
  for plaintext 16 KiB (above 2, so that size would go to the owner under
  D's rule) and 1.8 to 2.8 for TLS 16 KiB; the 7 MiB reply's median in
  every cell is higher than with 32 KiB pieces.
- Fast small p99 with 16 KiB pieces is no lower than with 128 KiB pieces in
  any cell by more than run-to-run spread.
- 64 KiB slots, plaintext: O0 whole fails as with 16 KiB slots (fast small
  p99 above 100 ms in W1, W4 and W5). Gated 128 KiB passes every rule cell.
  U: plaintext whole costs 5 to 15% less CPU per byte than with 16 KiB
  slots, since a run of 32 slots is one `sendmsg` of 2 MiB instead of
  512 KiB; gated 128 KiB pieces cost the same as with 16 KiB slots within
  spread, since each piece is one `sendmsg` either way.
- 64 KiB slots, TLS: gated 32 KiB passes every cell including W4 at 256 KiB.
  Gated 128 KiB passes the rule cells and fails W4 at 256 KiB, as with
  16 KiB slots, with fewer free slots relative to the pool, since 9 slots
  are 7% of 128. TLS U figures equal the 16 KiB-slot ones within spread.

Refuted if a 16 KiB arm fails a rule cell, if 64 KiB slots change a gated
arm's pass or fail in any cell against 16 KiB slots, or if plaintext whole
U does not get cheaper with 64 KiB slots.

## Results of Addenda 2 and 3

Addendum 2 runs `01a1ee93-4fcb` to `01a1ee93-74b2`, 84 of 84 `success`;
Addendum 3 runs `01a1ee99-5bb0` to `01a1ee99-ad0f`, 154 of 154 `success`.
Same binaries as above. Summarised by `experiments/send-admission-e-report.py`
over all 390 runs. No run recorded TCP memory pressure.

Fast small replies' p99 with 512 slots of 16 KiB, median over runs and the
largest run in brackets (ms). Every arm in these tables completed every 7 MiB
reply and every W5 slow reader's reply, and had no fast small reply past
`admit_limit`, except TLS 128 KiB in W4 at 256 KiB (above). Plaintext:

| cell | 16 KiB | 32 KiB | 64 KiB | 128 KiB |
| --- | --- | --- | --- | --- |
| W1 | 0.3 (0.4) | 0.3 (0.3) | 0.3 (0.3) | 0.2 (0.3) |
| W2, 6 slow | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) |
| W4, 1 MiB, k = 72 | 0.8 (4.0) | 0.7 (0.8) | 2.2 (3.0) | 0.8 (1.1) |
| k = 128 | 0.8 (0.9) | 0.9 (1.0) | 1.2 (1.2) | 2.4 (2.8) |
| W4, 256 KiB, k = 128 | 0.8 (0.9) | 0.8 (0.9) | 1.0 (1.1) | 1.2 (1.4) |
| W5 | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) |

TLS:

| cell | 16 KiB | 32 KiB | 64 KiB | 128 KiB |
| --- | --- | --- | --- | --- |
| W1 | 0.3 (0.5) | 0.2 (0.3) | 0.2 (0.5) | 0.2 (0.4) |
| W2, 6 slow | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) |
| W4, 1 MiB, k = 72 | 0.5 (0.5) | 0.5 (0.6) | 0.5 (0.6) | 0.5 (0.6) |
| k = 128 | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.6) | 0.4 (0.5) |
| W4, 256 KiB, k = 128 | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.5) | 928.4 (929.1) |
| W5 | 0.5 (0.5) | 0.5 (0.5) | 0.5 (0.6) | 0.5 (0.5) |

- No stalled peer's piece waited for room at 16, 32 or 64 KiB, over either
  transport, in any W4 cell (0 of 220,160 at 16 KiB in W4 at 1 MiB with 128
  stalled peers).
- In W2, pieces to the three drainers waited for room at 64 KiB over
  plaintext (3,600 of 3,840), as over TLS and at 128 KiB, and at no piece
  size of 32 KiB or less over either transport.
- The 7 MiB reply's median rose as pieces shrank in every cell: over
  plaintext from 4.1 to 6.0 ms at 128 KiB to 8.3 to 12.7 ms at 16 KiB, over
  TLS from 5.3 to 8.4 ms to 9.3 to 15.5 ms.

U, worker CPU per byte against whole replies of the same transport and pool:

| arm | plaintext, ns (ratio) | TLS, ns (ratio) |
| --- | --- | --- |
| whole | 0.385 (1.00) | 0.602 (1.00) |
| gated 128 KiB | 0.551 (1.43) | 0.758 (1.26) |
| gated 64 KiB | 0.613 (1.59) | 0.791 (1.31) |
| gated 32 KiB | 0.701 (1.82) | 0.896 (1.49) |
| gated 16 KiB | 1.067 (2.77) | 1.340 (2.23) |

Each piece adds 9.6 to 21.8 µs of worker CPU, the most at 128 KiB. Over
plaintext a reply in pieces took longer (p50 4.1 ms at 128 KiB, 7.9 ms at
16 KiB, against 2.9 ms whole); over TLS it was faster down to 32 KiB (6.6 ms
against 7.0 ms) and slower at 16 KiB (9.9 ms).

128 slots of 64 KiB (8 MiB, as 512 of 16 KiB), fast small p99 median
(largest) in ms, and the fewest free slots during a 7 MiB reply:

| cell | plaintext whole | plaintext gated 128 KiB | TLS gated 32 KiB | TLS gated 128 KiB |
| --- | --- | --- | --- | --- |
| W1 | 1152.0 (1152.2), 0/20 7 MiB | 0.2 (0.3) | 0.3 (0.4) | 0.3 (0.4) |
| W2, 6 slow | 1156.5 (1158.2), 2/20 7 MiB | 446.1 (447.6), 0 free | 449.3 (449.6), 1 free | 443.9 (444.5), 1 free |
| W4, 1 MiB, k = 72 | 1164.2 (1164.8) | 0.7 (0.8) | 0.5 (0.5) | 0.5 (0.6) |
| k = 128 | 1172.0 (1173.1) | 2.5 (2.8) | 0.5 (0.5) | 0.5 (0.5) |
| W4, 256 KiB, k = 128 | 1167.6 (1170.9) | 1.2 (1.3) | 0.5 (0.6) | 945.3 (945.7), 6 free |
| W5 | 1115.8 (1115.9) | 0.5 (0.5) | 0.5 (0.6) | 0.5 (0.6) |

- Every gated arm with 64 KiB slots failed W2: fast small p99 about 445 ms,
  the 7 MiB replies completed at about 500 ms (median), and no more than one
  slot free at the fewest. The same arms with 16 KiB slots had 371 to 404 of
  512 free there. Addendum 4 tests why.
- TLS 128 KiB with 64 KiB slots failed W4 at 256 KiB as with 16 KiB slots
  (945 ms; 1,605 of 10,240 stalled peers' pieces waited for room).
- U with 64 KiB slots: plaintext whole 0.369 ns per byte (0.385 with 16 KiB
  slots, 4% less), plaintext gated 128 KiB 0.541 (0.551, 2% less), TLS gated
  128 KiB 0.751 (0.758), TLS gated 32 KiB 0.858 (0.896, 4% less). The
  report's decision for the TLS 64 KiB-slot arms prints "no O0 whole runs to
  compare", because TLS whole cannot run with that pool; their fast small
  replies past `admit_limit` were 0.

### Addenda 2 and 3 against their predictions

- Addendum 2, all three arms pass every rule cell and W4 at 256 KiB with no
  stalled peer's piece waiting: agrees.
- Fast small p99 no lower than with 128 KiB pieces by more than spread:
  refuted over plaintext in W4 with 128 stalled peers, where 16, 32 and
  64 KiB pieces gave 0.8, 0.9 and 1.2 ms against 2.4 ms (2.3 to 2.8), and in
  W4 at 256 KiB (0.8 ms at 16 and 32 KiB against 1.2, 1.1 to 1.4). Holds in
  every other cell and over TLS. Every figure was at most 4.0 ms.
- U ratios: plaintext 64 KiB 1.59 (predicted 1.5 to 1.7), plaintext 32 KiB
  1.82 (1.7 to 2.1), TLS 32 KiB 1.49 (1.4 to 1.7), plaintext 16 KiB 2.77
  (2.3 to 4.0), TLS 16 KiB 2.23 (1.8 to 2.8): agree. Plaintext 16 KiB costs
  more than twice whole replies, which sends that size to the owner under
  D's rule; the TLS 16 KiB ratio is also above 2.
- The 7 MiB reply's median rises as pieces shrink, in every cell: agrees.
- Addendum 3, 16 KiB pieces pass every rule cell and W4 at 256 KiB with no
  stalled peer's piece waiting: agrees.
- 64 KiB slots, plaintext O0 whole fails in W1, W4 and W5: agrees.
- 64 KiB slots, plaintext gated 128 KiB passes every rule cell: refuted, it
  fails W2.
- 64 KiB slots, plaintext whole U 5 to 15% cheaper: it was 4% cheaper, below
  the range; the refutation condition (not cheaper) does not hold. Gated
  128 KiB pieces cost the same within spread: refuted narrowly, 2% less with
  the runs' ranges not overlapping (0.538 to 0.543 against 0.546 to 0.563).
- 64 KiB slots, TLS gated 32 KiB passes every cell: refuted, it fails W2.
  TLS gated 128 KiB fails W4 at 256 KiB: agrees; it also fails W2. The
  predicted fewer free slots relative to the pool there did not hold: 6 of
  128 against 7 of 512. TLS U equal within spread: holds at 128 KiB, refuted
  at 32 KiB (0.858 against 0.896, ranges not overlapping).
- The refutation condition "64 KiB slots change a gated arm's pass or fail
  in any cell" holds: every gated arm changed from pass to fail in W2.

## Addendum 4: slot count or slot bytes in W2

Written after Addendum 2's and 3's runs, before these ran. With 128 slots of
64 KiB, every gated arm failed W2 (fast small p99 about 445 ms, no free slot at
the fewest), where the same arms with 512 slots of 16 KiB passed. The pools
hold the same 8 MiB. The candidate mechanism is the slot count: in W2 six slow
readers each request a 4 KiB reply 100 times a second and read 128 KiB a
second, 32 replies' worth, so once a slow reader's socket buffer is full its
replies queue in the runtime, each holding one slot whatever the slot's size,
up to the pipeline depth of 16: 96 slots. With 16 KiB slots the gated arms
had 108 to 141 slots taken at the fewest free (371 to 404 of 512 free), which
fits; 96 of 128 leaves too few for the 7 MiB reply's pieces and the fast
small replies. W5's slow readers have no small replies and passed with
64 KiB slots.

Arms, all in W2 with six slow readers, four runs each unless stated:

- 512 slots of 64 KiB (32 MiB): plaintext O0 gated 128 KiB and TLS O0 gated
  32 KiB.
- 128 slots of 16 KiB (2 MiB; 16,448 bytes over TLS): the same two arms.
- 128 slots of 64 KiB with the pipeline depth at 4 (W2-s6-p4): plaintext O0
  gated 128 KiB.
- 128 slots of 64 KiB, plaintext O0 gated 128 KiB, two runs: the failing arm
  of Addendum 3 again, the positive control for this batch.

Prediction:

- The control fails again, fast small p99 above 100 ms.
- 512 slots of 64 KiB: both arms pass (fast small p99 at most 10 ms, every
  7 MiB reply completed), with at least 371 slots free at the fewest, as
  with 512 slots of 16 KiB.
- 128 slots of 16 KiB: both arms fail as 128 slots of 64 KiB did, with fast
  small p99 above 100 ms and no slot free at the fewest.
- Pipeline depth 4: passes, since the slow readers can hold at most 24
  slots. A pipeline depth of 4 also limits the fast connections, so a fast
  small p99 above 10 ms here does not by itself refute the mechanism; the
  fewest free slots does (refuted if it is 0).

Refuted, and the pool's byte size rather than its slot count decides W2, if
128 slots of 16 KiB pass, or 512 slots of 64 KiB fail. If pipeline depth 4
still leaves no slot free, the slow readers' queued replies are not what holds
the slots.

### Addendum 4 results

Runs `01a1ef1d-e6a5` to `01a1ef1d-f11a`, 22 of 22 `success`, same binaries.
W2 with six slow readers, fast small p99 median [range] in ms, the 7 MiB
reply's median, and the fewest free slots during a 7 MiB reply:

| pool | arm | fast small p99 | 7 MiB median | fewest free |
| --- | --- | --- | --- | --- |
| 128 x 64 KiB (control, 2 runs) | plaintext gated 128 KiB | 446.4 [446.1-446.6] | 515 ms | 0 of 128 |
| 512 x 64 KiB | plaintext gated 128 KiB | 0.5 [0.5-0.6] | 6.1 ms | 391 of 512 |
| 512 x 64 KiB | TLS gated 32 KiB | 0.5 [0.5-0.5] | 10.1 ms | 406 of 512 |
| 128 x 16 KiB | plaintext gated 128 KiB | 443.7 [441.7-446.4] | 714 ms | 0 of 128 |
| 128 x 16 KiB | TLS gated 32 KiB | 450.3 [449.8-451.2] | 500 ms | 1 of 128 |
| 128 x 64 KiB, pipeline 4 | plaintext gated 128 KiB | 0.5 [0.5-0.5] | 6.0 ms | 79 of 128 |

Every arm completed every 7 MiB reply and every drainer's reply, and had no
fast small reply past `admit_limit`.

Against the prediction:

- The control fails again (446 ms): agrees.
- 512 slots of 64 KiB pass, with at least 371 slots free: agrees (391 and
  406, against 371 to 404 with 512 slots of 16 KiB).
- 128 slots of 16 KiB fail as 128 slots of 64 KiB did, with no slot free:
  agrees (0 and 1 free).
- Pipeline depth 4 passes, with slots free: agrees (79 of 128 free at the
  fewest, so 49 taken where the slow readers could hold at most 24).
- Neither refutation condition held. In W2 the slot count decides the result
  and the slot size does not: at 128 slots both sizes fail, at 512 both pass.
  The candidate mechanism, small replies queued to slow readers each holding
  one slot up to the pipeline depth, fits the pipeline-depth arm; no run
  counted the slots each connection held, so it rests on those two
  interventions and the arithmetic above.

## Outcome of the addenda

- Every piece size from 16 to 128 KiB passed every rule cell with 512
  slots, over both transports. Below 128 KiB the only cell that separated
  the sizes was TLS in W4 at 256 KiB, where 128 KiB failed and 85 KiB and
  smaller passed; a piece of a third of the send buffer, at most 128 KiB,
  passed everywhere it ran.
- Smaller pieces cost more CPU per byte (plaintext 1.43 to 2.77 times whole
  replies from 128 down to 16 KiB, TLS 1.26 to 2.23) and made the 7 MiB
  reply slower, and gave fast small replies a lower p99 only in two
  plaintext W4 cells, where every size was at most 4 ms.
- At equal pool memory, 64 KiB slots made plaintext whole replies 4%
  cheaper per byte, pieces up to 4% cheaper, and divided the slot count by
  four. A reply smaller than a slot still takes a whole slot, and over TLS
  each slot carries one record of at most 16 KiB, so a 64 KiB slot holds at
  most 16 KiB of TLS ciphertext. In W2 the slot count decided the result.
- Not measured: piece sizes between 85 and 128 KiB other than 85 KiB, 80 KiB
  (five whole TLS records), pools other than 128 and 512 slots, and how many
  slots each connection held.
