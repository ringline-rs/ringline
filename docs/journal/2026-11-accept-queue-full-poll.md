# 2026-11: The acceptor's queue-full poll does not bound the connect rate

- **Status:** NO-GO — a wake from a worker that drained its accept queue, in place of the 1 ms poll `send_when_room` runs while every queue is full, is not built. At the default `accept_queue_capacity` (1024) and at 64 the acceptor never waited under a connect storm at one worker's maximum rate; the poll binds only below a capacity of about 32.
- **Span:** 2026-11-15 · tree 4509097c (`main`, 0.7.0-alpha.135) · follows #817 · SystemsLab experiment `01a1e10a-62e7-7120-3130-b055cec01169`

## Goal

#817 moved the accept and park channels to `std::sync::mpsc`, which has no
wait on several senders, so the acceptor's wait for queue room became a poll:
`send_when_room` (`ringline/src/acceptor.rs`) retries every live worker's
channel with `try_send` and sleeps `ROOM_POLL_INTERVAL` (1 ms) between rounds.
The PR left open whether a wake from a worker that drained its queue should
replace the poll. This entry answers that with a measurement.

Decision rule, written before the run: build the wake only if the poll bounds
the accepted rate, or adds to connection latency, at a capacity a deployment
would use. The default is 1024.

## What the code says

A worker drains its whole accept channel on every eventfd wake
(`handle_eventfd_read` on io_uring, the same loop on mio), so a full channel
means the worker is `accept_queue_capacity` connections behind at that
instant. While the acceptor sleeps, later connections wait in the kernel
listen backlog (65535 by default), so the sleep costs acceptor time, not
connections (#658). With the acceptor sleep-bound it delivers at most
`capacity` connections per sleep, so the accepted rate is about
min(R_worker, capacity × 1000/s), where R_worker is the one-worker rate with
the queue never full.

Predictions, from `min(R_worker, capacity × 1000/s)`: at 1024 the
`accept_queue_full` counter stays 0 and the rate is R_worker; at 64 the rate
is within the round-to-round spread of R_worker; at 4 about 4,000/s; at 1
about 1,000 to 2,000/s. A rate at 4 or 1 near R_worker would refute the model
and say the poll costs nothing at any capacity.

## What happened

A first attempt on macOS (mio, loopback) was discarded: the client exhausted
the 16,384 loopback ephemeral ports after about 16,000 connections (30 s
TIME_WAIT) and reported 33,000 to 38,000 connect errors per run, so its rates
measured the client's port table.

The measurement ran in a SystemsLab guest (`experiments/accept-queue-poll-sweep.toml`):
Debian 13, Linux 6.12.116, 16 vCPU (one CCX slot of an x86 hypervisor),
io_uring backend confirmed by `bench-server --print-backend`,
`ip_local_port_range` 1024 to 65000 and `tcp_tw_reuse=1`. The build went
through the shared compiler cache (14 s). The payload's `prlimit` did not
take effect on its shell (`nofile=1024 memlock=8192` were printed after it);
ringline raised its own fd limit at launch as it does, and the result has 0
errors, so the run stands.

One `bench-server --runtime ringline --echo-mode copy --workers 1` against
`connect-bench --threads 8 --duration 10 --warmup 2` (one 64-byte request per
connection, no TLS). The accept queue capacity came from
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

All four predictions held. R_worker is about 32,000/s for one io_uring worker
in this guest, measured, with the four rounds at 1024 spread over 1.2%. At
capacity 4 the rate was 12 to 29% above the model's 4,000/s, which is the
connections the acceptor delivers when a drain lands between its retries; at
capacity 1 it was 9% below the model's 1,000/s, a `sleep(1 ms)` plus the
retry taking a little over a millisecond. `accept_queue_full` counts one per
entry to `send_when_room` plus one per 100 ms waited, so about 10,000 in a
12 s run at capacity 4 or 1 is about 830 waits per second.

The 2026-11-06 connect-rate run (`docs/listeners-and-accept-design.md`,
about 33,000/s into 8 workers at 0.65 core each) was bounded by its client;
one worker alone takes about the same rate here, so a 1024-deep queue fills
only when its worker takes nothing for about 32 ms while connections arrive at
that rate.

## Outcome

NO-GO on the wake. The poll binds when the capacity is below about
R_worker / 1000, about 32 here. Capacity 64 is unaffected; the default 1024
never entered the wait under a storm at the worker's maximum rate. The code,
`ROOM_POLL_INTERVAL` and its doc comment are unchanged.

What the wake would cost was not measured, since nothing it would buy was
found: it adds a signal from every worker's drain to the acceptor, on the
accept path of every connection, for a state the `accept_queue_full` metric
already reports as overload.

## Ruled out

- That the poll adds to connection latency at the default: mean latency at
  1024 and 64 was the same, 240 to 244 µs, and `accept_queue_full` stayed 0.
- That macOS loopback can host this measurement: it cannot, at this rate,
  without a shorter TIME_WAIT (`net.inet.tcp.msl`), which was not changed on
  the development machine.

## Reopen if

- A deployment needs `accept_queue_capacity` at or below about 32, or a
  worker rate above about 64,000 connections/s, where capacity 64 would start
  to bind.
- `accept_queue_full` is seen rising at the default capacity under a real
  workload, which says a worker stalls for tens of milliseconds while
  connections arrive, and is then a finding about the worker before it is one
  about the poll.
