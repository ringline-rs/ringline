# 2026-11: The acceptor's queue-full poll does not bound the connect rate

- **Status:** NO-GO — a wake from a worker that drained its accept queue, in place of the 1 ms poll `send_when_room` runs while every queue is full, is not built. One io_uring worker under a connect storm took about 32,000 conns/s (measured). At capacity 64 the queue filled about 5,300 times per 12 s run and the rate and the mean latency were not worse than at the default, 1024; at 16 the rate was 10 to 14% lower; at 4 it was 4,400 to 5,150/s and at 1 about 910/s. The default is 1024.
- **Span:** 2026-11-15 · tree 4509097c (`main`, 0.7.0-alpha.135) · follows #817 · SystemsLab experiments `01a1e10a-62e7-7120-3130-b055cec01169` (8 client threads) and `01a1e19c-bfd0-7194-4e4c-59ccf9630106` (256)

## Goal

#817 moved the accept and park channels to `std::sync::mpsc`, which has no
wait on several senders, so the acceptor's wait for queue room became a poll:
`send_when_room` (`ringline/src/acceptor.rs`) retries every live worker's
channel with `try_send` and sleeps `ROOM_POLL_INTERVAL` (1 ms) between rounds.
The PR left open whether a wake from a worker that drained its queue should
replace the poll. This entry answers that with a measurement.

Decision rule, written before the run: build the wake only if the poll bounds
the accepted rate at a capacity a deployment would use. The default is 1024.

## What the code says

A worker drains its whole accept channel on every eventfd wake
(`handle_eventfd_read` on io_uring, `drain_channels` on mio), so a full
channel means the worker is `accept_queue_capacity` connections behind at that
instant. While the acceptor sleeps, no connection is lost: later connections
wait in the kernel listen backlog (65535 by default), and a SYN that overflows
it is retried by the peer (#658). With
the acceptor sleep-bound and refilling exactly `capacity` connections per
sleep, the accepted rate is about min(R_worker, capacity × 1000/s), where
R_worker is the one-worker rate with the queue never full. It is more when
the worker drains while the acceptor refills, so the queue takes longer than
`capacity` deliveries to fill again (the second run below measures that at
capacity 16), and a little less when a sleep plus the retry takes longer than
1 ms (capacity 1).

Predictions, from that model: at 1024 the `accept_queue_full` counter stays 0
and the rate is R_worker; at 64 the rate is within the round-to-round spread
of R_worker; at 4 about 4,000/s; at 1 about 1,000 to 2,000/s. A rate at 4 or
1 near R_worker would refute the model and say the poll costs nothing at any
capacity. The pre-run estimate of R_worker, about 4,000/s per worker from the
two-machine run below, was wrong by 8×: one worker alone takes about
32,000/s.

## What happened

A first attempt on macOS (mio, loopback) was discarded: the client exhausted
the 16,384 loopback ephemeral ports (49152 to 65535, 30 s TIME_WAIT) and
reported 33,253 to 38,668 connect errors per run, so its rates measured the
client's port table.

The measurement ran in a SystemsLab guest from a spec that embedded the
diagnostic patch as base64 at rev 4509097c and tried `sudo prlimit` for the
fd and memlock limits; `experiments/accept-queue-poll-sweep.toml` is that
spec with the patch read from the clone, `rev = "main"`, and `ulimit -Sn` in
place of the `prlimit`. The guest: Debian 13, Linux 6.12.116, 16 vCPU
(`slots = 1` on hv03, whose one slot is the whole host), io_uring backend
confirmed by `bench-server --print-backend`, `ip_local_port_range` 1024 to
65000 and `tcp_tw_reuse=1`. The build took 14.17 s (the image's sccache; not
shown in the log). The `prlimit` did not take effect on the payload's shell
(`nofile=1024 memlock=8192` were printed after it: the brace group runs in a
pipeline subshell forked before the `prlimit` ran). ringline's launch raised
its own fd soft limit (`ensure_nofile_limit`), the client holds at most 8
sockets, and every run had 0 errors, so the run stands.

One `bench-server --runtime ringline --echo-mode copy --workers 1` against
`connect-bench --threads 8 --duration 10 --warmup 2`: 8 synchronous threads,
each with one connection at a time (connect, write a 64-byte request, read
the echo, close), no TLS. The client therefore has at most 8 connections in
flight, so a capacity above 8 cannot fill with it: the 64 and 1024 cells
measure R_worker and say nothing about whether those queues fill under an
open-loop storm. The accept queue capacity came from
`experiments/accept-queue-poll.patch`, a diagnostic that reads
`BENCH_ACCEPT_QUEUE` in bench-server; it is not merged into bench-server. Four
rounds, capacities interleaved, 16 runs, 0 connect or I/O errors in every run.
The server's counters were read from its metrics dump after each run.

| Capacity | Runs | conns/s (min to max) | Mean connection latency | `accept_queue_full` |
|---|---|---|---|---|
| 1024 (default) | 4 | 31,972 to 32,367 | 240 to 243 µs | 0, 0, 0, 0 |
| 64 | 4 | 31,789 to 32,145 | 242 to 244 µs | 0, 0, 0, 0 |
| 4 | 4 | 4,474 to 5,150 | 1,531 to 1,762 µs | 9,900 to 10,235 |
| 1 | 4 | 905 to 915 | 8,688 to 8,780 µs | 10,496 to 10,624 |

The predictions at 4 and 1 held; the ones at 1024 and 64 were guaranteed by
the client's concurrency and test nothing. R_worker is about 32,000/s for one
io_uring worker in this guest, measured, with the four rounds at 1024 spread
over 1.2%. At capacity 4 the rate was 12 to 29% above the model's 4,000/s;
the surplus is the connections the acceptor delivers when a drain lands
between its retries (inferred). At capacity 1 it was about 9% below the
model's 1,000/s: about 10,600 waits in 12 s is about 1.1 ms per wait
(derived), a `sleep(1 ms)` plus the retry. `accept_queue_full` counts one per
entry to `send_when_room` plus one per 100 ms waited, so about 10,000 in a
12 s run at capacity 4 or 1 is about 830 waits per second.

The 2026-11-06 connect-rate run (`docs/listeners-and-accept-design.md`:
32,945 to 33,194 conns/s into 8 workers at about 0.65 core each) was not
CPU-bound on the server, and that doc does not say what bounded it; one
worker alone takes about the same rate here. With arrivals at R_worker, a
1024-deep queue fills only if the worker takes nothing for about 32 ms
(1024 / 32,000, derived); with arrivals above R_worker it fills in
1024 / (arrival rate − R_worker) seconds with no stall.

## Second run: 256 client threads

Written before it ran: with 256 connections in flight a queue of 64 can
fill and one of 1024 cannot, so `accept_queue_full` is above 0 at 64 and 0
at 1024, and the rate at 64 stays at R_worker. The run used the first run's
spec with the base64-embedded patch at 4509097c plus the `threads` param and
the `gate_patch` gate the committed spec has (the committed spec reproduces
it with `-p threads=256 -p caps="1024 64 16 4"` once this entry is on `main`,
since the patch file it reads is not at 4509097c). Same guest class: hv03,
Linux 6.12.116, io_uring, `nofile=65536` this time. Four rounds, capacities
interleaved, 16 runs, 0 connect or I/O errors.

| Capacity | Runs | conns/s (min to max) | Mean connection latency | `accept_queue_full` |
|---|---|---|---|---|
| 1024 (default) | 4 | 31,905 to 31,992 | 7,992 to 8,014 µs | 0, 0, 0, 0 |
| 64 | 4 | 32,205 to 32,258 | 7,927 to 7,941 µs | 5,307 to 5,402 |
| 16 | 4 | 27,507 to 28,601 | 8,944 to 9,298 µs | 10,029 to 10,093 |
| 4 | 4 | 4,412 to 4,543 | 56,319 to 57,996 µs | 10,647 to 10,677 |

Both predictions held. At capacity 64 the acceptor waited about 5,300 to
5,400 times per 12 s run, about 440 to 450 per second, and the rate and the
mean latency were not worse than at 1024: the rate was 0.7 to 1.1% higher
and the latency 0.6 to 1.1% lower, a difference larger than the spread within
either capacity (0.3% and 0.2%) and in the direction of the poll costing
nothing; why 64 is slightly faster was not investigated. The mean latency of
about 8 ms at every capacity above 4 is the 256 connections in flight divided
by the rate (Little's law, derived); it is not the poll. At capacity 16 the
rate was 10 to 14% below R_worker and the
latency 12 to 16% above it, so the poll costs something there; the model's
floor for 16 is 16,000/s and the measured 27,507 to 28,601 is 72 to 79% above
it, which is the refill the model leaves out. At capacity 4 the rate matched
the first run (4,412 to 4,543 against 4,474 to 5,150).

## Outcome

NO-GO on the wake. At capacity 64 the queue filled about 440 to 450 times a
second and the rate and the mean latency were not worse than at 1024
(measured, second run). The poll costs rate from capacity 16 down: 10 to 14%
at 16, 86% at 4, 97% at 1 (measured). The model's floor, min(R_worker,
capacity × 1000/s), puts the boundary at about R_worker / 1000, about 32
(derived); the measured boundary is between 16 and 64. At the default, 1024, a
queue that fills under an open-loop storm costs each connection at most about
1 ms of poll on top of about 32 ms of queueing behind the 1024 ahead of it
(derived). The code, `ROOM_POLL_INTERVAL` and its doc comment are unchanged.

What the wake would cost was not measured, since no case was found where it
changes the rate or the latency: it adds a signal from every worker's drain
to the acceptor, on the accept path of every connection, for a state the
`accept_queue_full` metric already reports as overload.

## Ruled out

- That the poll adds to connection latency at capacity 64 or above: with 8
  client threads mean latency at 1024 and 64 was the same, 240 to 244 µs
  (the queue never filled); with 256 threads, where the 64-deep queue filled
  about 440 to 450 times a second, it was 7,927 to 7,941 µs at 64 against
  7,992 to 8,014 µs at 1024. Neither client can fill a 1024-deep queue.
- That macOS loopback can host this measurement: it cannot, at this rate,
  without a shorter TIME_WAIT (`net.inet.tcp.msl`), which was not changed on
  the development machine.

## Reopen if

- A deployment needs `accept_queue_capacity` below 64 (the cost was measured
  at 16 and not at 64; the boundary between them was not located), or a
  worker rate well above about 32,000 connections/s, where a 64-deep queue
  refills in less time and the poll could start to cost there.
- `accept_queue_full` is seen rising at the default capacity under a real
  workload. That says arrivals exceeded the worker's rate for long enough to
  queue 1024 connections; by the model the poll then adds at most about 1 ms
  per connection to about 32 ms of queueing, and a measurement of that case
  would be the first with a queue of that depth.
