# Send pool stage 0: a per-connection bound, measured with no runtime change

- **Status:** closed. `M` = 64 met the decision rules; NO-GO for an always-on
  cap and for round-robin.
- **Span:** Nov 2026 · follows #981 (`docs/send-pool-partition-design.md`)

## Goal

Stage 0 of `docs/send-pool-partition-design.md` (Experiment, stage 0) asks
whether a bound on the send-pool slots one connection holds meets the
design's criterion before tickets, the TLS ordering, the API change or mio
are built, and whether round-robin can act in these workloads.

## Round-robin: decided by reading the code

The cache server this design is for runs one task per connection, and every
reply on a connection is sent by that task and awaited before the next one
(read in its source: the connection task sends each reply through a function
that awaits `send_admitted`, or `submit_batch_admitted` for a guarded reply,
before it reads the next request). `admission-server` does the same: its
serve loop reads a request only between replies (`serve`,
`ringline-bench/src/bin/admission-server.rs`). So at most one bounded send
waits per connection, by construction, and round-robin would reorder
nothing. The design's NO-GO for round-robin holds, from this reading and
not from a counter, and stage 0 has no round-robin arm. Reopen if either
program starts sending on one connection from more than one task, or joins
or selects over several sends on one connection.

## The stand-in for the cap

`admission-server --conn-slot-cap M` (new in this entry's pull request): before
it admits a reply, a connection waits while its admitted and unsettled replies
hold at least `M` slots, for the oldest to settle, bounded by
`--settle-limit-ms`. A reply is admitted whatever its size while the connection
holds fewer than `M`, as the design's `held >= M` rule does. The connection
reads no request while it waits, as a handler awaiting a bounded send at the cap
also reads nothing. Slots are counted as admission counts them (`ceil(len /
--slot-size)`). A counter, `cap_waits`, counts the waits, and `cap_wait_us`
their total, so a run shows whether the bound acted.

It differs from the design's cap in two ways that matter here: it counts a
reply's slots until the reply settles, where the runtime would count each
slot until its own send completes, and it applies only to this server's
replies. Neither changes which replies wait in these cells, where every
reply is a copy send. (Corrected after the runs: that last sentence is not
measured. A 64 KiB reply's four slots stay counted until the whole reply
settles, where the runtime would free each as its own write completes, so
a connection can fall below `M` sooner under the runtime's count.)

## Setup

`admission-server` on one worker, pinned, `--pool-slots 8192
--slot-size 16448` (the cache server's pool), `--small-send admitted`,
`--admit-limit-ms 60000 --settle-limit-ms 60000` so no connection is aborted
for slow reading within a run, `--pipeline 4096` so the per-reply limit does
not bind. `admission-load` on the same VM, loopback. Order: `budget` (the
runtime default, 32 slots) and `strict`.

Arms: unchanged (no `--conn-slot-cap`), `M` = 16, `M` = 64.

Cells:

- `slow-N`, N = 1, 4, 16: N slow connections each offer 64 KiB requests at
  100 per second (6.5 MB/s) and read at most 1 MB/s with `SO_RCVBUF` 4096.
  The probe: 16 fast connections, 2,000 requests per second in total, 1 KiB,
  open loop, `--within-ms 10`.
- `mixed`: `slow-4` plus 4 closed-loop connections each keeping 4 requests
  for 120 KiB outstanding.
- `batch-K`, K = 2,000, 6,000, 10,000: one connection with `SO_RCVBUF` and
  `SO_SNDBUF` 4096 writes K requests for 1 KiB, then reads K replies, and
  repeats until the run ends. Measured: rounds completed, and rounds that
  did not finish within 10 s.
- `idle`: 4 closed-loop connections each keeping 64 requests for 1 KiB
  outstanding, nothing else. Measured: replies per second.
- `bulk`: one closed-loop connection keeping 4 requests for 1 MiB
  outstanding, nothing else. Measured: bytes per second.

Runs: 30 s after a 4 s warmup. Three runs per arm, order and cell, the arms
interleaved. `idle` and `bulk` first get four unchanged runs each for their
A/A spread.

## Predictions, written before the runs

- Unchanged, `slow-N` and `mixed`: more than 1% of probe requests miss
  10 ms in every run, as in the cache server's measurement. This is the
  positive control for those cells: if the unchanged arm meets the bar, the
  cell does not hold the pool and says nothing about the bound.
- `M` = 16 and `M` = 64, `slow-N` and `mixed`: at most 1% miss 10 ms in
  every run, since N × M (at most 1,024 slots) leaves most of the pool free.
  Refuted if any run misses.
- Slow readers' bytes read: within 10% of unchanged under both `M`, since
  their reads, not the pool, limit them.
- `idle`: within the A/A spread under both `M`. Replies settle as soon as
  the kernel takes them on loopback, so a connection rarely holds 16 slots.
- `bulk`: under `M` = 16 each 1 MiB reply (64 slots) waits for the one
  before it to settle, so throughput falls; I expect more than 10% at
  `M` = 16 and within 10% at `M` = 64. Not confident in either number.
- `batch-K`: unchanged completes every round at every K. Under `M` = 16 the
  server stops reading once the connection's unsettled replies reach the cap
  and the kernel's send buffer is full; at K = 10,000 the requests still
  unread then exceed what the server's receive buffer and the client's send
  buffer hold, so the client's writes block and the round never finishes.
  At K = 2,000 every round finishes. K = 10,000 under `M` = 16 is the
  positive control for the NO-GO: if it finishes, the cell cannot show the
  deadlock and the NO-GO is untested.

## Decision rules

- An `M` meets stage 0 if, under both orders: every `slow-N` and `mixed`
  run has at most 1% of probe requests miss 10 ms; slow readers' bytes read
  are within 10% of unchanged; `idle` and `bulk` lose at most 10% or the A/A
  spread, whichever is larger; and every `batch-K` round finishes.
- If an `M` meets every rule except `batch-K`: NO-GO for an always-on cap.
  Stage 1 then builds the cap to apply only above an occupancy.
- If no `M` meets the `slow-N` and `mixed` rules: the cap does not meet the
  criterion at these reader counts, and the design goes back for review
  before anything is built.
- A cell whose counter shows the bound never acted (`cap_waits` = 0 under
  `M`) did not test it, whatever its result.

## What happened

### Calibration

SystemsLab experiment `01a1f52f-4f3e-71f3-f926-705f774e2310` on hv03 (Linux
6.12, image TCP defaults: `tcp_rmem` 4096 131072 6291456, `tcp_wmem` 4096 16384
4194304), binaries artifact `01a1f52e-6226-73b5-355e-e0548e618e7d` built at
0dc0a18e. One run per line, `budget` order.

| Run | Probe not within 10 ms | Other | `cap_waits` |
|---|---|---|---|
| `slow4`, unchanged | 55,482 of 60,000 (48,131 lost) | p99 26 s | 0 |
| `slow4`, `M` = 16 | 0 of 60,000 | p99 0.50 ms; slow readers 120.0 MB read in the window, as unchanged | 1,207 |
| `batch10000`, unchanged | | 442 rounds, none stalled | 0 |
| `batch10000`, `M` = 16 | | 454 rounds, none stalled | 643,434 |
| `batch2000`, `M` = 16 | | 7,039 rounds, none stalled | 1,981,484 |
| `bulk`, unchanged | | 4.73 GB/s | 0 |
| `bulk`, `M` = 16 | | 4.77 GB/s | 154,400 |
| `idle`, `M` = 16 | | 616,337 replies/s | 2,340,664 |

The `slow4` positive control holds, and the bound acted in every run that
had it.

The `batch10000` positive control failed: under `M` = 16 every round
finished, as fast as unchanged, though the bound made the connection wait
643,434 times. The batch client's writes did not block. (Corrected after
reading the receive path: an earlier version of this paragraph inferred that
ringline keeps receiving into the connection's accumulator while the handler
does not read. On a plaintext io_uring connection a receive is armed only
when a reader parks (`park_recv`, `runtime/io.rs`), so the accumulator does
not grow while the handler waits.) The likelier cause is the cell's size:
10,000 requests of 24 bytes are 240 KB, and the server's kernel receive
buffer (`tcp_rmem` up to 6 MB, autotuned while the server reads quickly) and
the client's send buffer hold the requests left unread when the bound stops
the server, so the client's writes complete. Not measured. The `batch-K`
cells as planned therefore cannot trip the always-on NO-GO; they still run in
the matrix, as recorded above. Testing the NO-GO needs the server's socket
buffers held small, so that the unread requests fill them.

`bulk` under `M` = 16 was as fast as unchanged in this one run each, against
the prediction of more than 10% loss; the matrix has three runs per arm.

### Batch retest: predictions, written before its runs

The retest (`send-pool-stage0-plan.py batchretest`) runs `batch-K` at
K = 500, 2,000 and 10,000, unchanged and `M` = 16, `budget` order, two runs
each, with `net.ipv4.tcp_rmem` set to 4096 8192 16384 and `tcp_wmem` to
4096 8192 65536 for its runs only. The client sets its own buffers (4096,
which Linux doubles), so the sysctls cap the server's sockets: about 16 KB
to receive and 64 KB to send.

Under `M` = 16 the server stops reading once 16 replies are unsettled and its
socket's send buffer is full, about 60 replies of 1 KiB later: after about
80 requests. The requests still unread then fit in the server's receive
buffer and the client's send buffer (about 24 KB, 1,000 requests) only if K
is below about 1,100.

- K = 500: every round finishes under both arms.
- K = 2,000: unchanged finishes every round (the pool holds all 2,000
  replies); `M` = 16 stalls in the write phase of its first round. This is
  the positive control for the always-on NO-GO. Refuted if `M` = 16
  finishes its rounds.
- K = 10,000: both arms stall, since about 9,900 unsent replies exceed the
  8,192-slot pool even unchanged. This shows the pool bounds a batch writer
  without any cap.

### Addendum: where M binds, and the pool's S / M; predictions written before its runs

Rep 1 of the matrix showed `M` = 16 costing `idle` about a third of its
replies per second and `M` = 64 costing nothing measured. The addendum
(`send-pool-stage0-plan.py addendum`, two runs, `budget` order, binaries
with a new server counter, `max_conn_slots`: the most slots one
connection's unsettled replies held) asks where between those the healthy
connections stop being held, whether anything improves above 64, and how
many slow readers the 8,192-slot pool holds at `M` = 64.

Cells, at `M` = 0 (unchanged), 32, 64, 128 and 256: `idle` (4 connections,
64 outstanding 1 KiB replies each), `deep1k` (4 connections, 256 outstanding
1 KiB replies), `deep16k` (4 connections, 64 outstanding 16 KiB replies, one
slot each). At `M` = 64 only: `slow96`, `slow128` and `slow160`, the
`slow-N` cell with 96, 128 and 160 slow readers.

Predictions:

- `max_conn_slots` unchanged is at most the depth in slots: 64 for `idle`
  and `deep16k`, 256 for `deep1k`. A cell loses replies per second under an
  `M` below that peak and not under an `M` at or above it.
- `idle`: `M` = 32 loses more than 10%; 64, 128 and 256 are within the A/A
  spread of unchanged.
- `deep1k`: `M` = 32, 64 and 128 lose more than 10%; 256 is within the
  spread. If so, `M` = 64 costs a healthy connection that pipelines 256
  small replies.
- `deep16k`: as `idle`.
- Slow readers at `M` = 64: each holds up to 67 slots (a 64 KiB reply is 4
  slots, admitted while the connection holds fewer than 64), so the pool
  fills at about 122 readers. `slow96`: at most 1% of probe requests miss
  10 ms. `slow128` and `slow160`: more than 1% miss. Refuted in the useful
  direction if `slow128` passes (readers hold less than the bound); refuted
  in the other if `slow96` fails.

### Matrix

SystemsLab experiments `01a1f535-c329-719a-14b8-ae76097e6f75`,
`01a1f535-c4d1-7102-aabb-c729b4d15559` and
`01a1f535-c56b-7166-cdd9-80e8b1eeff1d` (reps 1 to 3) on hv03, binaries
`01a1f52e-6226-73b5-355e-e0548e618e7d`, plans from 8c9e12f6. 170 runs, all with
load results. Summarised by `experiments/send-pool-stage0-report.py`. In the 12
`mixed` runs under a bound the server's summary file is missing; the full output
is complete, and the report reads the counters from it. Inferred: the server ran
out of memory copying its output, which holds one record per 120 KiB reply.

| Cell | Unchanged | `M` = 16 | `M` = 64 |
|---|---|---|---|
| `slow1`, probe not within 10 ms | 32.00% | 0% | 0% |
| `slow4` | 92.47% | 0% | 0% |
| `slow16` | 100% | 0% | 0% |
| `mixed` | 90.24-92.52% | 0% | 0% |
| `mixed`, 120 KiB clients | 308-317 MB/s, p99 402 ms | 3.83-3.90 GB/s | 4.11-4.20 GB/s |
| `idle`, replies/s (A/A 911k-946k) | 829k-925k | 593k-626k | 899k-935k |
| `bulk` (A/A 4.68-4.71 GB/s) | 4.67-4.71 GB/s | 4.67-4.80 GB/s | 4.74-4.82 GB/s |

Ranges are over three reps and both orders. Every one of the 48 runs of
`slow-N` and `mixed` under a bound had 0 of 60,000 probe requests miss
10 ms, with p99 at most 0.8 ms; the slow readers read the same bytes in the
window under every arm (30, 120, 480 and 120 MB). The bound acted in every
run that had it (`cap_waits` above zero) except `idle` at `M` = 64, where no
connection reached it. `strict` and `budget` gave the same results in every
cell. None of the 54 `batch-K` runs stalled, as calibration showed.

Against the predictions: the unchanged arm failed `slow-N` and `mixed` in every
run, so those cells tested the bound. `M` = 16 and 64 met the probe bar in every
run, as predicted. `idle` under `M` = 16 lost about a third (593k-626k
replies/s), against the prediction of no loss: four connections with 64
outstanding replies each reach 16 unsettled slots between their reads. `bulk`
lost nothing under either bound, against the prediction of more than 10% at
`M` = 16.

### Batch retest

SystemsLab experiments `01a1f552-9ae6-718e-781c-dbb605d80b66` and
`01a1f552-9b8d-7159-330e-358d6b31897e`, plans from 94d3e326.

| K | Unchanged | `M` = 16 |
|---|---|---|
| 500 | 23,261-23,317 rounds, none stalled | 25,879-25,899 rounds, none stalled |
| 2,000 | 5,968-6,024 rounds, none stalled | stalled in the first round's writes, at 768 requests written |
| 10,000 | stalled in the first round's writes, at 5,205 written | stalled at 768 written |

The predictions held for K = 500 and 2,000: with the server's socket buffers
small, a batch writer deadlocks under the bound at a batch that finishes
unchanged. The positive control for the always-on NO-GO holds. At K = 10,000
the unchanged arm stalled as predicted, but the predicted cause (replies
beyond the pool) does not fit: it stalled after 5,205 requests were written,
which fits the server's `--pipeline 4096` limit plus about 1,100 requests in
the buffers. Inferred, not checked, and it does not fit `M` = 16's stalls at
768 requests written, which imply about 680 requests buffered.

### Addendum

SystemsLab experiments `01a1f56f-0989-71ca-38ca-af3cbd8e5381` and
`01a1f56f-09fc-71e1-775a-8b52aa2a748c`, binaries
`01a1f56e-e190-7337-442c-17695dcb1e7d` built at 3c0acaf1, plans from 3c0acaf1.
Two runs per line.

| Cell | Unchanged | `M` = 32 | `M` = 64 | `M` = 128 | `M` = 256 |
|---|---|---|---|---|---|
| `idle`, replies/s | 906k-907k | 756k-869k | 902k-912k | 898k-904k | 903k-904k |
| `deep1k`, replies/s | 1.076M-1.080M | 0.997M-1.072M | 1.082M-1.092M | 1.105M-1.109M | 1.076M-1.087M |
| `deep16k`, replies/s | 263k-265k | 240k-241k | 259k-262k | 263k-266k | 262k-265k |

`max_conn_slots` unchanged was 64 in `idle` and 256 in `deep1k`, as
predicted, and equal to `M` wherever `M` was below that. The `deep16k`
server crashed before writing any output in every run, so that cell has no
server counters; inferred to be the same memory exhaustion, with 263,000
records a second.

Against the predictions: `M` = 32 lost 4% and 17% in `idle` and 1% and 7% in
`deep1k`, so 32 is at the edge of the 10% rule. `M` = 64 and 128 lost nothing
in `deep1k`, against the prediction of more than 10%: a connection with 256
outstanding replies held 256 slots unbounded but ran as fast held to 64.

| Readers at `M` = 64 | Probe not within 10 ms | Pool free slots (median; share of samples under 64) | Slots the server counted held (mean over the window) |
|---|---|---|---|
| 96 | 11.81%, 13.02% | 536-576; 14-26% | 6,117-6,119 (30 s) |
| 128 | 100% | 0; 94% | 5,882-6,002 (2.6-3.0 s) |
| 160 | 100% | 0; 94% | 5,960-6,359 (2.0 s) |

The free-slot columns cover the whole run (about 3,550 samples); the held
means cover the server's measurement window, which spans the scheduled times
of requests that reached an admission result and so is 2-3 s long at 128 and
160 readers.

`slow96` failed, against the prediction that it would pass; 128 and 160 failed
as predicted. The pool ran out while the server counted about 6,000 slots held
by unsettled replies at every reader count, so about 1,500 to 2,300 slots
(8,192 less the free slots, as the whole-run median, and the held slots, as the
window mean) were in use that the server's count does not
cover. What holds them is not established. The runtime's own held count, which
stage 1 builds, is the measurement that would show it.

## Outcome

- `M` = 64 meets stage 0's decision rules under both orders: every `slow-N`
  and `mixed` run met the probe bar, slow readers read what they read
  unchanged, and `idle` and `bulk` lost nothing. `M` = 16 fails the `idle`
  rule. `M` = 32 is at the rule's edge. `deep1k` at `M` = 128 was 2-3%
  faster than unchanged in both runs; with no A/A runs for that cell,
  whether that is noise is not known. Nothing else improved above 64.
- NO-GO for an always-on cap: with small server socket buffers a batch
  writer deadlocks under the bound at 2,000 requests, where it finishes
  unchanged. Stage 1 builds the cap to apply only above an occupancy, as
  the send slab's caps do. With the image's default buffers no batch run
  stalled up to 10,000 requests. Reopen if servers come to keep reading
  requests while a send waits at the cap.
- NO-GO for round-robin, by reading the code (above).
- At `M` = 64 the 8,192-slot pool held the probe bar with 16 slow readers
  and missed it at 96 (counts in between were not run), against 128
  (`S / M`) if each reader held only its 64 slots: `max_conn_slots` was 64
  in all six addendum slow-reader runs (the matrix binaries predate the
  counter), since 64 is a multiple of a reply's 4 slots. The prediction's 122
  assumed 67 per reader. The shortfall is the slots the server's count does
  not cover. Reopen the pool-size question once stage 1's held count shows
  what holds them.
- The harness records one entry per reply above `--small-max`, which runs
  the server out of memory in cells with many such replies. This entry's
  pull request keeps records for the first 100,000 and counts the rest
  (`LARGE_RECORDS_MAX`, `large_replies_unrecorded`). No stage 0 run used it;
  the crash cause is inferred from the empty server output and the record
  rate, with no kernel log.
- The commits this entry cites (plans and binaries) are on the
  `exp/send-pool-stage0` branch of brayniac/ringline, which is kept.
