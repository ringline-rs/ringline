# O7w as the default order: the fast-path specification's Part 2 runs

- **Status:** closed. On the ported code O7w met Part 2's criteria in C2's
  seven cells, and in the cell with sends outside the FIFO once it ran on
  C2's host. It admitted every head strict order admitted over TLS and cost
  no CPU per operation beyond main's floor. Strict order missed the 0.3 ms
  fast p99 bar against C2's O0 in five cells, by 1.0 to 2.1 ms; the two of
  them rerun on C2's hosts met it.
- **Span:** Nov 2026 · follows #967 (the specification) and #969 (Part 1)
  · SystemsLab context `send-admission-expC`
- **Code:** `SendAdmissionOrder` and the harness changes are in the pull
  request that adds this entry. Runs are identified by their SystemsLab
  experiment and build artifact ids; each artifact's build experiment records
  the source it built. Runs are named `P2 ...` in the context.

## Goal

Part 2 of the fast-path specification (`docs/send-admission-design.md`,
section 4) makes O7w, with R = 32, the default admission order. Its done
criterion compares a rerun of C2's cells on the ported code with C2's own
figures (journal C), runs the W1 and W2 cells over TLS under both orders,
and repeats the echo check against main.

## Predictions, written before each set of runs

- Plaintext: every cell meets the criterion under both orders, since the port
  carries O7w's logic unchanged. Refuted if any cell misses a bar.
- TLS calibration: with a 1,024-slot pool, strict order admits its heads;
  with 512 slots and a 2,000 ms admission limit it may not. Refuted ("the
  cell tests the pool, not the order") if strict admits every head in the
  chosen cell and O7w times out any.
- Host-matched rerun: the plaintext misses below disappear on C2's hosts.
- Echo: the default build's closed-loop CPU per operation is within main's
  floor.

## Plaintext matrix

Binaries: artifact `01a1e634-0125`. C2's seven cells and the W1 cell with
sends outside the FIFO, four rounds with the order alternated and two more
strict runs in each cell: 80 runs, all `success`. Summarised by
`experiments/send-admission-c2-report.py`.

Every run ran on hv03: `send-admission-c0.toml` tagged its job `host:hv03`
whatever the submission asked. C2 ran the W1 cells on hv01, the W1 cell with
sends outside the FIFO and W2 with no slow readers on hv02. This pull request
makes the host a parameter.

Largest head delay and the median of the per-run fast small p99, in ms.
Ratio 2 is an `admit_limit` of 2,000 ms against a `settle_limit` of
1,000 ms, as in journal C; the other cells use 1,000 ms for both.

| cell | O0 | O7w | C2 O0 | C2 O7w |
| --- | --- | --- | --- | --- |
| W1, N = 1 | 809.0, 765.0 | 809.2, 0.4 | 808.6, 766.2 | 808.3, 0.4 |
| W1, N = 16 | 809.4, 764.2 | 808.3, 0.4 | 808.6, 765.2 | 808.0, 0.4 |
| W1, N = 16, ratio 2 | 808.9, 764.3 | 808.5, 0.4 | 808.5, 765.4 | 808.8, 0.3 |
| W1, sends outside the FIFO | 808.5, 764.2 | 808.4, 0.4 | 810.4, 766.3 | 810.2-811.2, 0.5-0.6 |
| W2, no slow readers | 742.6, 701.6 | 741.4, 0.5 | 741.5, 701.8 | 741.7, 0.5 |
| W2, 2 slow | 743.6, 679.6 | 743.3, 0.4 | 743.5, 678.2 | 743.4, 0.4 |
| W2, 6 slow | 721.2, 679.2 | 719.0, 0.4 | 721.3, 679.0 | 742.8, 0.4 |
| W2, 6 slow, ratio 2 | 743.0, 679.2 | 718.8, 0.4 | 721.2, 679.3 | 718.9, 0.4 |

Every head was admitted, and no fast small reply went beyond `admit_limit`.

- O7w met both bars in C2's seven cells. In the cell with sends outside the
  FIFO it missed the range bar, at 808.4 ms and 0.4 ms; strict order in the
  same runs was 1.9 ms below C2's O0.
- Strict order met the head bar everywhere. Its fast p99 was 1.0 to 2.1 ms
  off C2's O0 in the four W1 cells and 1.4 ms off in W2 with two slow
  readers, against a 0.3 ms bar. C2's own O0 per-run fast p99s were within
  2.6 ms of their median, so the bar is tighter than O0's run-to-run spread.
  C2 ran W2 with two slow readers on hv03 too, so the host does not explain
  that miss.

### Host-matched rerun

Binaries: artifact `01a1e757-4055`, the branch with main at alpha.147 merged.
W1 at N = 16 on hv01 and the cell with sends outside the FIFO on hv02, two
runs per order (`01a1e758-355e` to `-37e9`), all `success`:

| cell | O0 | O7w |
| --- | --- | --- |
| W1, N = 16, hv01 | 807.8, 765.0 | 808.3, 0.4 |
| W1, sends outside the FIFO, hv02 | 810.4, 766.5 | 810.2, 0.6 |

On C2's hosts both rerun cells meet every bar under both orders, so the
misses in those two cells followed the host. Strict order's misses in W1 at
N = 1 and at ratio 2 were not rerun on hv01, nor was W2 with no slow readers
rerun on hv02.

## TLS

Binaries: artifact `01a1e634-0125`. TLS with a 16,448-byte slot. A smoke run
of W1 at N = 16 with 512 slots and a 1,000 ms limit timed out all 10 heads
under both orders (strict fast p99 1,155 ms, O7w 0.5 ms), so that cell could
not tell the orders apart.

Calibration, strict order only:

| setting | heads admitted | head median | fast p99 |
| --- | --- | --- | --- |
| 1,024 slots, 1,000 ms (`01a1e687-f996`) | 10 of 10 | 1.7 ms | 0.4 ms |
| 512 slots, 2,000 ms (`01a1e687-faa4`) | 10 of 10 | 1,800 ms | 1,954 ms |

With 1,024 slots the heads waited at most 4.1 ms, too short to tell the
orders apart. The prediction that the 512-slot cell might time out was wrong.
That cell was chosen, and W1 at N = 16 and W2 with six slow readers ran there
at ratio 2, four rounds per order. C2's seven cells and the W1 cell with sends
outside the FIFO also ran once per order over TLS as the specification
states. The TLS runs total 32 (`01a1e6e7-a1cd` to `-af12`, all `success`).

| cell | O0 heads timed out | O0 head max | O0 fast p99 | O7w heads timed out | O7w head max | O7w fast p99 |
| --- | --- | --- | --- | --- | --- | --- |
| W1, N = 1 | 10 of 10 | - | 1,157.2 | 10 of 10 | - | 0.5 |
| W1, N = 16 | 10 of 10 | - | 1,155.1 | 10 of 10 | - | 0.4 |
| W1, sends outside the FIFO | 10 of 10 | - | 1,154.4 | 10 of 10 | - | 0.4 |
| W1, N = 16, ratio 2 | 0 of 50 | 1,800.9 | 1,954.2 | 0 of 50 | 1,800.0 | 0.4 |
| W2, no slow readers | 0 of 10 | 732.9 | 693.1 | 0 of 10 | 732.0 | 0.4 |
| W2, 2 slow | 0 of 10 | 735.1 | 694.6 | 0 of 10 | 733.5 | 0.4 |
| W2, 6 slow | 0 of 10 | 737.6 | 695.9 | 0 of 10 | 733.4 | 0.4 |
| W2, 6 slow, ratio 2 | 0 of 50 | 738.0 | 696.0 | 0 of 50 | 733.5 | 0.4 |

O7w timed out no more heads than strict order in any cell and kept W1's fast
small p99 at or below 0.5 ms, the two conditions the specification sets. In
the chosen cell the median head delay was 1,799.4 ms under O7w and 1,799.8 ms
under strict order. The prediction held.

## Echo check

Four boots (`01a1e758-3843`, `-38a7`, `-3904`, `-395d`), all `success`, on
artifact `01a1e757-4055`, which holds main's `bench-server` (strict order)
and the branch's (O7w by default). The spec was generated from Experiment C's
echo generator with two arms, both `--echo-mode bytes-admitted`, the order
rotated each round. Summarised by C's echo report, with main's binary as the
base arm:

| statistic | rounds higher | median change | range | main's floor |
| --- | --- | --- | --- | --- |
| closed loop, CPU per op | 6 of 16 | -1.4% | -4.8% to +3.4% | 2.5% (max 4.4%) |
| closed loop, ops per second | 10 of 16 | +1.4% | -3.2% to +5.1% | 2.6% (max 4.6%) |
| open loop, CPU per op | 9 of 16 | +0.9% | -4.8% to +6.2% | 2.9% (max 6.7%) |
| open loop, p99 | 10 of 16 | +4.0% | -33.9% to +168.2% | 1.6% (max 86.4%) |

- The default build's CPU per operation is within main's floor, which is the
  echo condition.
- Open-loop p99 was 0.39 to 0.50 ms in most cells. Above 0.55 ms were two
  of main's 16 rounds (0.76, 0.80 ms) and two of its four warm-ups (0.75,
  1.30 ms), and four of the branch's 16 rounds (0.63, 0.70, 1.33, 1.34 ms).
  Sixteen pairs do not separate a difference from these spikes. The
  specification sets no open-loop condition.

## Not covered

- The per-short-send walk that sets `waited_for_room` was not measured
  separately. Whether the echo load at 256 B produced any short sends was not
  checked.
- W2 was not contended in any cell, plaintext or TLS, so these runs do not
  exercise the decision rule's contended W2 condition, as in C2.
