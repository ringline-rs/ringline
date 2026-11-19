# Send pool stage 0: a per-connection bound, measured with no runtime change

- **Status:** open. Predictions and decision rules are written; no runs yet.
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

`admission-server --conn-slot-cap M` (new in this entry's pull request):
before it admits a reply, a connection waits while its admitted and
unsettled replies hold at least `M` slots, for the oldest to settle, bounded
by `--settle-limit-ms`. A reply is admitted whatever its size while the
connection holds fewer than `M`, as the design's `held >= M` rule does. The
connection reads no request while it waits, as a handler that awaits a
bounded send at the cap would not. Slots are counted as admission counts
them (`ceil(len / --slot-size)`). A counter, `cap_waits`, counts the waits,
and `cap_wait_us` their total, so a run shows whether the bound acted.

It differs from the design's cap in two ways that matter here: it counts a
reply's slots until the reply settles, where the runtime would count each
slot until its own send completes, and it applies only to this server's
replies. Neither changes which replies wait in these cells, where every
reply is a copy send.

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

SystemsLab experiment `01a1f52f-4f3e-71f3-f926-705f774e2310` on hv03
(Linux 6.12, image TCP defaults: `tcp_rmem` 4096 131072 6291456,
`tcp_wmem` 4096 16384 4194304), binaries artifact `01a1f52e-6226` built at
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
