# Direct receive: one-shot receives into the connection's accumulator

Note (2026-10-25): `segments`, `recv_owned_segment`, `with_segments`,
`with_bytes_segments` and `forward_to` were removed; no read holds provided
buffers.

Note (2026-10-25): TLS connections receive directly too, into their TLS
engine's ciphertext buffer (`tls_recv_buffer`), and no TCP connection uses
the provided-buffer ring.

Note (2026-10-25): the TCP provided-buffer ring was removed, with
`recv_multishot`.

Status: merged (#684). Since decisions 11 and 15, every plaintext
connection on io_uring, outbound or accepted, receives this way, with no
option. Measured through build C8 and at 250 and 1,000 connections per
worker (Evidence, "Scale"), and for accepted connections in a RESP server
(Evidence, "Accepted connections"); owner decisions made (see Decisions).
Open: the causes listed under Not known.

Related: `docs/recv-buffering-approaches.md` ("One-shot receive into
connection-owned memory", "Per-connection rings"),
`docs/recv-segment-views-design.md`, `docs/recv-kernel-errata.md`.

## Goal

A plaintext connection on io_uring, accepted or from `connect` or
`connect_unix`, receives without a provided buffer. Each
receive is a one-shot `RECV` whose destination is the free space of the
connection's `RecvAccumulator`. The kernel writes the bytes where `with_data`
and `with_bytes` read them, so the copy from a provided buffer into the
accumulator does not happen, and neither does the move of buffered bytes when
the accumulator grows. Parsers and the protocol crates do not change.

The first user was a client making outbound plaintext connections;
decision 15 extends it to accepted connections.

## Evidence

All runs below are cachecannon with 16 client workers and 1,000 connections
(62 or 63 per worker) against Valkey (RESP) and memcached, on two VMs, at a
fixed request rate per cell, in `experiments/segviews-screen.toml` on branch
`feat/segment-clients`. Client CPU is the cachecannon process's user plus
system time for the run. Each build runs in every cell of a SystemsLab
experiment, and the three experiments rotate the build order. The ringline
commits named below (06c6c43, ff61e77, c67d328) are the measured builds,
from before this branch was rebased onto main; they are on branch
`exp/segviews-c8-ringline` of `brayniac/ringline`.

### What the ring path copies

`with_bytes` on the shared multishot ring copies 1.0 to 3.1 bytes into
accumulators per byte received (`ringline/recv_ring` `BYTES_COPIED` divided
by `ringline/bytes` `RECEIVED`). The ratio exceeds 1 because growing the
accumulator moves the bytes already in it, and `BYTES_COPIED` counts both.

### Segment views did not remove enough

Build B read with `with_bytes_segments` and the segment parsers of
unreleased `resp-proto` and `memcache-proto` revisions. On the incremental
ring (`bi`) its client CPU relative to A was 0.949 to 0.973 at 8 to 64 KiB.
At 64 KiB and up the parser still copied 0.92 to 0.95 bytes per received
byte, because receives from many connections interleave in each ring buffer,
and the incremental ring added about 1 GiB of peak RSS
(`01a151fb-71b7-71c1-d9de-4cf187e4ba3f`, `01a151fb-7249-714c-93c9-b7db10eae5c3`,
`01a151fb-72b0-7179-3e37-47c2b8e111fe`).

### Direct receive (build C)

Build C is cachecannon `exp/segviews-c2` on ringline `exp/segviews-c2`
(`feat/recv-direct` on the commit build A used), binaries
`01a154c2-7be1-7364-667e-192b469e7a14`. In the screen, `c` connects with
`recv_direct(true)`, `c0` is the same binary on the multishot ring, and `c1`
is the same binary with one-shot ring receives (`recv_multishot(false)`).
Experiments `01a154c2-aff0-713a-2088-c31a3277e2ed`,
`01a154c2-b062-71ec-499e-2eb343075ee1` and
`01a154c2-b0c7-718f-7432-8370282733f8`.

Client CPU relative to A, mean of three runs, and bytes copied per byte
received:

| Cell | `c0` | `c1` | `c` | `c` copies | A copies |
|---|---|---|---|---|---|
| memcache 64 B, depth 16 | 0.999 | 1.006 | 1.039 | 0.000 | 1.01 |
| RESP 64 B, depth 16 | 0.998 | 1.017 | 1.009 | 0.000 | 1.00 |
| memcache 4 KiB, depth 1 | 1.000 | 1.015 | 1.007 | 0.000 | 1.35 |
| memcache 4 KiB, depth 16 | 0.998 | 1.027 | 0.972 | 0.015 | 2.37 |
| memcache 8 KiB, depth 16 | 1.002 | 1.037 | 0.967 | 0.050 | 2.54 |
| memcache 64 KiB, depth 1 | 1.000 | 1.042 | 0.964 | 0.000 | 2.06 |
| memcache 64 KiB, depth 16 | 1.003 | 1.031 | 0.960 | 0.073 | 3.09 |
| RESP 64 KiB, depth 16 | 0.997 | 1.022 | 0.948 | 0.070 | 2.92 |
| memcache 1 MiB, depth 1 | 1.002 | 1.058 | 0.928 | 0.000 | 2.86 |
| RESP 1 MiB, depth 1 | 0.995 | 1.048 | 0.950 | 0.000 | 1.98 |

- `c0` is within 1.4% of A in every run, so the prototype did not change the
  ring path.
- At 8 KiB and up, `c` lowers user time by 26 to 67% and raises system time
  by 2 to 5%. `c1` pays a similar system-time increase for one-shot arming
  without the copy saving, and costs 2 to 6% more than A.
- At memcache 64 B, `c` costs 3.9% more than A, against 0.6% for `c1`, so the
  extra cost is in the direct path's own work, not in arming a one-shot
  receive. Profile `01a15549-6402-71d7-74c4-134a9ee740c0` found it:
  `madvise` was 8.4% of `c`'s worker samples (`zap_page_range_single`,
  `flush_tlb_mm_range`, `smp_call_function_many_cond`) and absent in `c0` and
  `c1`. Each receive allocated a new 64 KiB buffer and freed the previous one,
  and glibc trimmed the thread's heap on the free (see "Reusing a consumed
  buffer"). Counted on loopback with an `LD_PRELOAD` allocator shim: 92,594
  allocations of 32 KiB or more in 66,315 direct receives, against 641 on the
  ring. Commit 06c6c43 fixed it: in build C3, `c` at memcache 64 B was 1.004
  of `c0`'s CPU, mean of three runs (`01a1556b-604f-710c-e4bc-1f4aaa2ee165`,
  `01a1556b-60d2-716b-893f-80d6a1500614`,
  `01a1556b-6146-7100-d5c4-9bfde714bafe`).
- p50 and p99 are unchanged within run-to-run spread, except memcache 64 B
  p50, which rose from about 400 µs to about 430 µs.
- Peak RSS: 510 MiB lower than A at memcache 1 MiB, 945 MiB higher at RESP
  1 MiB, within 60 MiB elsewhere.
- No completion arrived for a closed connection (`STALE` 0), and the bytes
  the direct receives counted equal the bytes received.

### The pool (builds C5 to C8)

Build C5 is ringline ff61e77: the per-worker pool, a 32 KiB own buffer, no
`MSG_WAITALL`. Its screen adds two cells: 1 MiB values at 100 requests per
second, which leaves most connections idle after a large value, and mixed
values, where all 400 keys hold 1 MiB and then the first 300 are rewritten at
4 KiB, so a quarter of GETs return 1 MiB. Experiments
`01a157db-d318-7132-bb08-a01d91b2363e`,
`01a157db-d38e-71ed-a8ff-f6a91eaee037` and
`01a157db-d3fd-71b3-f1cc-c584357eb3b1`; mean of three runs:

| Cell | `c` CPU / A | `c` / `c0` | `c` copies | A copies | Peak RSS A | Peak RSS `c` |
|---|---|---|---|---|---|---|
| memcache 64 B, depth 16 | 0.992 | 1.008 | 0.000 | 1.01 | 2,412 MiB | 2,368 MiB |
| RESP 64 B, depth 16 | 0.995 | 0.992 | 0.000 | 1.00 | 2,410 MiB | 2,368 MiB |
| memcache 4 KiB, depth 1 | 1.007 | 1.006 | 0.000 | 1.35 | 2,410 MiB | 2,367 MiB |
| memcache 4 KiB, depth 16 | 0.978 | 0.978 | 0.047 | 2.37 | 2,452 MiB | 2,444 MiB |
| memcache 8 KiB, depth 16 | 0.972 | 0.970 | 0.108 | 2.55 | 2,481 MiB | 2,451 MiB |
| memcache 64 KiB, depth 1 | 0.982 | 0.984 | 0.454 | 2.07 | 2,494 MiB | 2,542 MiB |
| memcache 64 KiB, depth 16 | 0.954 | 0.953 | 0.191 | 3.09 | 2,822 MiB | 2,703 MiB |
| RESP 64 KiB, depth 16 | 0.944 | 0.950 | 0.183 | 2.91 | 2,789 MiB | 2,890 MiB |
| memcache 1 MiB, depth 1 | 0.936 | 0.935 | 0.028 | 2.86 | 3,921 MiB | 3,566 MiB |
| RESP 1 MiB, depth 1 | 0.965 | 0.962 | 0.018 | 1.98 | 3,423 MiB | 3,381 MiB |
| memcache 1 MiB, idle | 0.939 | 0.963 | 0.031 | 3.47 | 3,911 MiB | 3,389 MiB |
| mixed, depth 1 | 0.932 | 0.935 | 0.029 | 3.18 | 3,935 MiB | 2,947 MiB |
| mixed, depth 16 | 0.959 | 0.956 | 0.190 | 3.51 | 3,225 MiB | 5,891 MiB |

Every build's client holds about 2.4 GiB, 1.1 GiB of it in huge pages, at
64 B values, so the differences in the RSS columns are what the receive path
holds. The client hosts run THP in mode `always` with `defrag` `madvise`.

- 4 KiB depth 16 costs about 1% more than in C3 (0.968). A 64 KiB batch no
  longer fits the 32 KiB own buffer, so its first part is copied into a
  borrowed buffer. 64 KiB depth 1 costs about 2.5% more than in C3 (0.956)
  for the same reason, at 0.45 bytes copied per byte.
- RESP 1 MiB costs 0.965 against C3's 0.943 (see Known lengths).
- Mixed values at depth 16 held 2.7 GB more than A, and no borrowed buffer
  was reused. Diagnostic counters (build C6, `01a159c1-ad72-7117-17a8-5a3f5bb6909c`)
  showed borrowed buffers averaging 2.4 MiB when given back: a buffer that
  ran out of room with part of a message of no known length buffered grew by
  the whole receive size with `BytesMut::reserve`, which doubles the
  allocation. A few buffers of about 5 MiB filled each worker's 16 MiB of
  free buffers, no borrow could use them, and every buffer given back after
  that was freed. Commit c67d328 sizes a grown buffer to the receive size and
  evicts the largest free buffers (see Buffers).

Build C7 is c67d328 with the diagnostic counters (experiments
`01a159d3-e857-71bf-0a65-6c6903c6bb6e`,
`01a159d3-e8ce-718e-c651-340efa5fda70`,
`01a159d3-e946-7148-afb8-545333526581`). At mixed depth 16, CPU is 0.936 of
A, peak RSS 4,392 MiB, and every borrow after the warmup reused a free
buffer. The buffers given back average 2.0 MiB: a connection's first 1 MiB
value grows by doubling, because no message has set its receive size yet, and
a borrow accepts a free buffer up to twice the size it needs, so those
buffers stay in use. Moving partial messages raised copies there from 0.19 to
0.74 bytes per byte. The other C7 cells match C5 within 1%.

Build C8 is c67d328 without the counters (binaries
`01a159f3-e054-73af-bc3f-8b6ea08f60b1`).

- Throughput with no rate limit (`01a159f3-edbf-7115-c5dd-6d420d46108d`,
  `01a159f3-ee2e-71c3-e05d-043c27ea7fee`; a third run lost its client VM):
  every memcache cell from 4 KiB depth 16 up reaches 37.4 Gb/s with A and with
  `c`, so the link limits them. memcache throughput of `c` is 0.994 to 1.009
  of A's in every cell. The RESP cells are limited by Valkey and move by 2 to
  7% between runs in both directions. At the same throughput `c` uses up to
  9% less client CPU (memcache 1 MiB: 710 against 642 CPU-seconds).
- Latency at the C5 rates, three runs (`01a159f3-ee9e-719d-b861-353068a62e55`,
  `01a159f3-ef0a-71ed-fef5-60c8b2cad632`,
  `01a159f3-ef74-71da-d9a7-9f3283f547b1`): mean p50 of `c` is at or below
  A's in 11 of 13 cells, and 4% lower at memcache 8 KiB depth 16 and RESP
  64 KiB depth 16; it is 1.5% higher at mixed depth 16 and 1.3% higher at
  RESP 1 MiB. p99 of `c` is above A's in all three runs in four cells:

  | Cell | p99 A (µs) | p99 `c` (µs) |
  |---|---|---|
  | memcache 4 KiB, depth 16 | 929 / 929 / 925 | 946 / 983 / 942 |
  | mixed, depth 16 | 21,495 / 22,020 / 20,840 | 21,757 / 22,544 / 22,675 |
  | memcache 1 MiB, idle | 2,162 / 2,473 / 2,359 | 2,293 / 2,506 / 2,441 |
  | RESP 64 B, depth 16 | 692 / 942 / 1,212 | 909 / 1,056 / 1,400 |

  The first three are 1 to 9% higher; RESP 64 B is 12 to 31% higher, in a
  cell where A's own p99 varies by 75% between runs. In the other nine
  cells `c`'s p99 is above A's in at most two runs.
- Throughput with the hosts swapped (`experiments/segviews-screen-flip.toml`
  on `feat/segment-clients`: client on the Zen 1 host with 12 threads,
  servers on the Zen 2 host), one run (`01a15aad-c9c5-7104-23a5-5be594d89ccd`).
  A's client uses 597 to 604 CPU-seconds, all 12 cores for the 50 s of
  warmup and measurement, in six cells; at memcache 64 KiB depth 16,
  memcache 1 MiB and RESP 64 KiB depth 16 it uses 542 to 548 at about
  26 Gb/s, and at RESP 64 B 131. `c`'s throughput relative to A is 1.098 at
  memcache 4 KiB depth 16, 1.100 at 8 KiB depth 16, 1.058 at 64 KiB depth 1,
  1.026 at 64 KiB depth 16, 1.029 at 1 MiB, 1.045 at RESP 64 KiB depth 16,
  1.121 at RESP 1 MiB, 1.032 at memcache 64 B depth 16 and 0.998 at 4 KiB
  depth 1. At RESP 64 B, which Valkey limits, it is 0.943, within the 2 to 7%
  the Valkey-limited cells moved between runs above.
  At 8 KiB depth 16 and in every cell of 64 KiB and up except 64 KiB depth
  1, `c` stops at 26.4 to 27.0 Gb/s with 474 to 555 CPU-seconds, so its
  ratios there are bounded by that rate. The network sets it: the data path
  is a bond of four 10 Gb/s links (802.3ad, `layer3+4` hashing), and 1,000
  connections do not spread the traffic evenly enough across the four. At
  4 KiB depth 16, where both builds use all 12 cores, `c`'s throughput is
  1.098 of A's, more than its CPU saving at a fixed rate there (2%, C5 and
  C8); I do not know why. Two more runs were cancelled before they started,
  so this rests on one run.

### Scale (C8 binaries, 4,000 and 16,000 connections)

`experiments/recv-direct-scale.toml` ran the C8 binaries with cachecannon's 16 threads, so 250 and 1,000
connections per worker, against the same Valkey and memcached, with no rate
limit. Three builds: `a` (multishot ring, 256 × 16 KiB per worker), `ar`
(the same with 1,024 × 16 KiB, at least one buffer per connection) and `c`.
Runs: 4,000 connections `01a15fe3-a1f6-71ef-7e8a-98c63220f424`; 16,000
connections `01a15fe3-a2ce-713a-458f-3f22fbe7aa4a` and
`01a15fe3-a333-7140-e7c5-8701e5846dcd`. A second 4,000-connection run
(`01a15fe3-a266-7134-c38f-188c9111e5b6`) lost its client VM partway
through and is not used. The second 16,000-connection run lost its client
VM after the memcache 4 KiB cells; its figures below are from the run log.
I do not know why the VMs dropped.

Client CPU per GET relative to `a`, memcache:

| Cell | 4,000: `ar` | 4,000: `c` | 16,000: `ar` | 16,000: `c` |
|---|---|---|---|---|
| 64 B, depth 1 | 1.002 | 1.031 | 1.010 / 0.997 | 1.041 / 1.021 |
| 64 B, depth 16 | 1.010 | 1.027 | 0.991 / 0.990 | 1.006 / 1.008 |
| 4 KiB, depth 1 | 0.993 | 0.999 | 0.975 / 0.979 | 1.003 / 1.012 |
| 4 KiB, depth 16 | 1.000 | 0.973 | 1.017 / 1.023 | 0.890 / 0.887 |
| 64 KiB, depth 1 | 0.996 | 0.959 | 1.059 | 0.879 |
| 64 KiB, depth 16 | 1.073 | 0.925 | – | – |

- At 4 KiB depth 16 and 16,000 connections `c` reached 37.1 Gb/s, the link
  limit, in both runs, and `a` 36.1; `c`'s throughput was 1.028 of `a`'s and
  its p99 518 and 505 ms against `a`'s 1,258 and 1,242. At 64 KiB depth 1
  its p99 was 604 ms against 1,166.
- At 64 B depth 1 `c` used 2.1 to 4.1% more CPU per GET than `a` in all
  three runs, with the same throughput. In the second 16,000-connection run
  `c` spent less user time and more system time than `a` there, which fits
  one submission per message to re-arm (the multishot ring re-arms without
  one); that is an inference, and ringline's default ring, one-shot since
  #647, was not run.
- `ar` was 0.975 to 1.073 of `a`'s client CPU per GET, with no consistent
  direction.
- Peak RSS at 4,000 connections: `c` the same as `a` or lower in every
  memcache cell, 1.8 GiB lower at 64 KiB depth 16. At 16,000, `c` was 0.1
  GiB higher at 64 B depth 1 (`c` 2.60 GiB, `a` 2.49) and 0.2 GiB higher at
  4 KiB depth 16 (`c` 3.63 and 3.69, `a` 3.44 and 3.45).
- Not usable: every RESP cell, and memcache 64 KiB depth 16 at 16,000
  connections. With no rate limit Valkey fell behind, and requests timed
  out at 5 s and connections failed, in all three builds; memcached at 64 KiB
  depth 16 timed out too. RESP at scale is not measured.

The standalone benchmark's `oneshot` strategy
(`docs/recv-buffering-approaches.md`) fell behind the shared ring at 1,000
connections per worker. That strategy grew its regions from 4 KiB and parsed
in the completion handler; this design does neither, and at 1,000
connections per worker it did not fall behind.

Per-connection provided rings are not proposed. The benchmark measured them
and recorded wrong bytes in the variant that rewrites a posted entry, one
`RLIMIT_MEMLOCK` page per ring on 7.1, and regions that grew to their cap and
stayed (`recv-buffering-approaches.md`).

### Accepted connections (RESP server, 1,000 and 8,000 connections)

These runs used a prototype of this change (brayniac/ringline d960afe; specs
at 060260f) that had neither the hangup poll nor the single-`sendmsg`
multi-slot send (#697). The poll's cost is not measured. #697 changes only
the GET 4 KiB depth-16 cells at 16 KiB send slots, where a flush spans up to
5 slots. Both ringline arms send through the same path, so #697 is expected
to affect them alike; this is not measured.

A RESP server (`ringline-bench` `resp-server` at d960afe, bins
`01a164ab-e6aa-73c2-fd0b-2feb02733191`) ran with 8 workers on one VM and
cachecannon with 16 threads on another, no rate limit, at 1,000 and 8,000
connections. Arms: `ring` (one-shot receives from the provided-buffer ring),
`direct` (accepted connections receive directly) and `tokio` (one
current-thread runtime per core, reading into a 64 KiB `BytesMut`). Runs
`01a164e0-24aa-71bc-ce35-4a84ec0c51bc`,
`01a164e0-2817-71bf-da2b-238030fa20ce` (ring),
`01a164e0-26a5-7121-403d-f1bebde5c2c4`,
`01a164e0-27a2-71b3-ef7b-45731668ff1e` (direct) and
`01a164e0-2718-7185-c1fe-34adadde25f1` (tokio, one run), and with 128 KiB
send-pool slots `01a16631-073f-719c-03aa-d21614dfc776`,
`01a16631-087e-7112-eff4-8c1091346236` (ring),
`01a16631-07b0-7180-c61e-a43f144647ee` and
`01a16631-0813-718f-adf3-9ed51d31ac45` (direct). The table lists the 16 KiB
runs. Two runs of one arm differed by up to 9% on a GET cell (the depth-1
cells), and by 0 to 5% in the cells below.

| Cell | ring ops/s | direct ops/s | tokio ops/s |
|---|---:|---:|---:|
| GET 4 KiB, depth 16, 1,000 conns | 1.88M / 1.79M | 1.83M / 1.83M | 2.28M |
| GET 64 B, depth 16, 8,000 conns | 2.07M / 2.02M | 1.99M / 2.07M | 2.35M |
| SET 4 KiB, depth 16, 8,000 conns | 891k / 866k | 984k / 1,006k | 1,087k |
| SET 64 KiB, depth 1, 1,000 conns | 68.0k / 66.3k | 71.3k / 73.1k | 75.6k |

- GET throughput and server CPU per request: equal within the run-to-run
  spread.
- SET: direct is ahead on the means of the two runs, by 7.5% at 64 KiB with
  1,000 connections, 6% at 64 KiB with 8,000 and 13% at 4 KiB depth 16 with
  8,000, where its p99 was 155 ms against 313 ms. The ring arm's
  provided ring went empty 1M to 16M times per cell at 8,000 connections.
- RSS: direct is 0.3 to 0.6 GiB higher at 8,000 connections.
- p99 at GET depth 16 with 8,000 connections is higher on direct (Not
  known). A depth-1 p99 difference in the first two direct runs did not
  recur in two later runs of the same build.
- The server's per-connection flush counts per 5 s interval show no
  starved connection in any arm: the least-served connection had 84 to 98%
  of the median in the ring and direct arms.

## Mechanism

### When a receive is armed

A direct connection has at most one receive in flight, and it is armed only
when a read parks: `with_data`, `with_bytes` or `recv_ready` returns
`Pending` after the parser has seen every buffered byte and returned
`NeedMore` or `NeedAtLeast` (`park_recv` in `runtime/io.rs`). No receive
into the accumulator is armed at connect or at a completion; the hangup poll
and peek below take no bytes. While the task works on what it has,
no receive is in flight, unless a read that parked was dropped before its
receive completed; data that arrives in that time waits in the socket's
receive queue.

A FIN or reset is seen without a read. When the connection opens, the
runtime arms a one-shot `POLL_ADD` for `POLLRDHUP` on its fixed file
(`OpTag::HangupPoll`, `arm_hangup_poll`). `POLLERR` and `POLLHUP` are always
reported, so it completes on a FIN, a reset or a socket error, and data
alone does not complete it. With a receive in flight, that receive returns
the queued bytes or the end, and the connection goes on
`Driver::hangup_rechecks`, so an end behind those bytes closes the
connection once they are read, whether or not a read parks again. With none,
the runtime submits a non-blocking one-byte `recv` with `MSG_PEEK`
(`OpTag::HangupPeek`), which consumes no bytes.

- A positive result means bytes are queued ahead of the end. They stay in
  the socket, and the connection goes on `Driver::hangup_rechecks`: after a
  receive has delivered bytes, and once nothing is buffered and nothing is
  armed, `recheck_hangups` peeks again, so the end closes the connection
  even if no read parks after the bytes are consumed.
- A result of 0 or an error means the stream has ended with nothing queued.
  If no receive is in flight and nothing is buffered in the accumulator, the
  connection closes as under a parked read. Otherwise it stays open and goes
  on `hangup_rechecks`, so the end closes it once the buffered bytes are
  read, whether or not a read parks. A peek that returns an error has
  cleared the socket's pending error, so the error is kept in
  `ConnectionState::hangup_error`, and the receive or recheck peek that
  later finds the end reports it.

No receive is armed on the hangup path, so the accumulator does not take
more than a parked read would. A poll or peek that cannot be pushed is
counted (`ring::RECV_ARM_FAILURES`). A poll goes on
`Driver::hangup_poll_retries`, and `retry_hangup_polls`, which runs before
each wait for completions, submits it again while no park is pending. A
peek goes on `hangup_rechecks`, and `recheck_hangups` submits it once
nothing is buffered, armed or parking. Until the poll is armed, a FIN or
reset is seen by the next receive to complete, which a read arms when it
parks. TCP does not tell a half-close from a close, so a FIN closes a
connection whose task only sends.

Cost: one `POLL_ADD` SQE per connection, its completion at a hangup or at
the close's lead (`shutdown` before 6.13 completes it with `POLLHUP`, the
cancel from 6.13 with `-ECANCELED`), and one peek SQE and completion per
hangup with no receive in flight, plus one per recheck. While armed, the
poll is on the socket's wait queue, so every wakeup of the socket also runs
its wake callback, which rejects the event unless it is a hangup. That cost
is not measured.

Before 6.13 the kernel frees removed fixed files in order. A request held
for a connection's life, such as this poll or the ring path's receive,
keeps every socket closed after it on the same ring from being freed until
the request completes. The `shutdown` lead still sends the FIN (Domain
Invariant 8 in CLAUDE.md).

Arming after the parse means no receive is outstanding while `with_bytes`
holds the accumulator frozen, so the remainder the parser left can be taken
back without a copy (below).

### The buffer in flight

`AccumulatorTable::detach_for_recv` first takes back the frozen remainder
(`reclaim`). If the parser kept no slice of it, `Bytes::try_into_mut`
succeeds and the remainder becomes the mutable buffer in place; otherwise the
remainder is copied once into a new buffer, counted in `BYTES_COPIED`. It then
grows the buffer if needed (below) and moves the whole `BytesMut`, unconsumed
bytes included, out of the accumulator. The driver stores it with the
connection index and generation in a per-worker slab entry
(`Driver::direct_recvs`) and submits `RECV` on the fixed file with the
buffer's spare capacity as the destination, under `OpTag::RecvDirect` with
the slab index as payload.

While the buffer is in the slab the accumulator is empty, and nothing else
writes to a direct connection's accumulator, so nothing can move or free the
memory the kernel is writing. The slab entry keeps the allocation alive until
the completion arrives (domain invariant 1).

On completion (`handle_recv_direct`), the driver frees the slab entry and
checks the connection: the generation must match and the lifecycle must be
`Open`. Otherwise the completion is stale and `RECV_DIRECT` `STALE` is
incremented. The buffer goes to `recycle_direct`: a buffer of at least
64 KiB for which `DirectPool::put` finds room stays in the pool, and any
other is freed.

For a live connection, the arrival is recorded first, while
`recv_direct_held` still counts the bytes the buffer held, as the multishot
path records it before appending. `attach_received` then sets the buffer's
length to include the received bytes and puts it back as the accumulator's
buffer, without a copy. Then:

- `n > 0`: count the bytes and wake the reader.
- `0`: the peer closed; mark EOF, wake the reader, close.
- `-ECANCELED`: wake the reader, which re-arms when it parks again.
- Any other error: mark the read half failed, fail the read with the error,
  close.

### Reusing a consumed buffer

`with_bytes` freezes the accumulator's contents for the parser
(`take_frozen`) and leaves the accumulator without a handle to the
allocation. When the parser consumes everything, the frozen view and the
parser's values are the only references to it. On the ring path the next
append allocates a small buffer. On a direct connection the next arm
reserved a buffer of at least the receive size, so a workload whose
receives end at message boundaries allocated and freed 64 KiB per receive.

A direct connection's `with_bytes` therefore keeps the view it consumed whole
(`keep_spent`). `detach_for_recv` takes its allocation back with
`Bytes::try_into_mut`, which succeeds when no slice of it is alive, clears it,
and receives into it. If the caller still holds a value from it, a new buffer
is allocated as before. `tests/recv_direct_alloc.rs` counts allocations of
32 KiB or more over 2,000 request-response batches: 0 with the change, 1,999
without it.

### Buffers

Each direct connection owns one buffer of `recv_direct_region` bytes
(default 32 KiB). With nothing buffered, a receive goes into it, so an idle
connection holds that much, or the initial accumulator capacity
(`recv_accumulator_capacity`) if that is larger and at most twice the
region. A message that does not fit borrows
a larger buffer from the worker's pool (`DirectPool` in `accumulator.rs`):
the part of the message received so far, at most `recv_direct_region` bytes,
is copied into the borrowed buffer, and the rest of the message is received
behind it. When the parser has consumed everything and no value read from
the borrowed buffer is alive (the `keep_spent` check above), the next receive
goes into the connection's own buffer again and the borrowed one goes back to
the pool.

A buffer grows when it holds part of a message and less than the parser's
`NeedAtLeast` value, or less than half of `recv_direct_region`, is spare. It
grows to hold the rest of the message when the `NeedAtLeast` value is at
least `recv_direct_region`, and otherwise to the larger of the receive size
and the buffered bytes plus `recv_direct_region`. The receive size is
`recv_direct_region`, or for a connection whose largest `Consumed` value so
far is `m`, the larger of `recv_direct_region` and
`min(4m, m + 4 * recv_direct_region)`. The own buffer grows by borrowing. A
borrowed buffer moves the buffered bytes to the front of its allocation when
that makes room (`BytesMut::try_reclaim`), and otherwise takes a buffer of
the new size from the pool, copies the buffered bytes into it, and gives the
old one back. A message longer than any before it on the connection grows
with `BytesMut::reserve` instead, which doubles the allocation, so a 100 MiB
value is not copied once per region; glibc grows large allocations with
`mremap` without copying their bytes.

The pool keeps free buffers by capacity. A borrow takes
the smallest free buffer that holds the message and is at most twice the size
it would allocate; otherwise it allocates one of at least 64 KiB, rounded up
to one of eight steps per power of two up to 2 MiB, and to a multiple of
2 MiB (a transparent huge page) above that. Messages of nearly the same size
therefore share buffers, and a 100 MiB value wastes at most 2 MiB. Free
buffers are kept up to `recv_direct_pool_max` bytes per worker (default
16 MiB). A buffer given back when there is no room frees the largest free
buffers that are larger than it until it fits; if they are not enough, it is
freed itself. A buffer larger than `recv_direct_pool_max` is never kept, so a
workload with 100 MiB values reuses their buffers only with
`recv_direct_pool_max` above 100 MiB.

A buffer recovered from a consumed view starts where that view started, so
its `capacity()` leaves out the bytes before it. `put` moves its start back
to the start of the allocation (`try_reclaim`) before keeping it; without
that, a buffer that had held several messages measured under 64 KiB and was
freed, and every batch of 16 × 4 KiB allocated a new one (C5's 1.94 million
allocations per run before ff61e77, 0 after).

A receive that ends inside a message leaves that part to be moved to the
front of the buffer at the next growth. Sizing receives to several messages
makes that move once per several messages. On loopback with 70,000-byte
messages at pipeline depth 16, sizing a receive to the most the connection
had buffered before copied 0.82 bytes per byte received, because each receive
ended at the same point inside a message; sizing by the largest message
copied 0.011.

Before the pool, a connection kept the largest buffer it had grown to until
it closed. That is the 945 MiB RSS increase measured at RESP 1 MiB with 1,000
connections in build C, and it would have been about 20 GiB at 16,000.

`tests/recv_direct_alloc.rs` reads request-response batches of 16 × 60 B,
1 × 64 KiB, 4 × 64 KiB, 1 × 1 MiB, 16 × 4 KiB and 16 × 8 KiB messages: after
four warmup batches, none allocates 32 KiB or more. With the pool keeping
nothing, 1 × 64 KiB makes 196 such allocations in 200 batches, and so do
16 × 4 KiB without the `try_reclaim` in `put`.

In THP mode `always`, the kernel backs each aligned 2 MiB range inside a large
borrowed buffer with a huge page at first touch, so a contiguous buffer gets
huge pages without being split into 2 MiB chunks. A buffer of about 1.1 MiB
contains no aligned 2 MiB range, so at 1 MiB values `c` holds no more huge
pages than A. Mode `madvise` would need `MADV_HUGEPAGE` on borrowed buffers,
which under `defrag=madvise` compacts memory at fault time.

A chain of 2 MiB chunks would need no size classes, but a message spanning
chunks is not contiguous, so `with_bytes` could not hand it to the parser
as one `Bytes` without a copy. It fits a reader that streams huge values
(the removed `get_stream`), and is not part of this design.

### Known lengths

When the parser returns `NeedAtLeast(additional)` with `additional` of at
least `recv_direct_region`, the buffer is grown to hold the rest of the
message before the receive is armed. Growing copies the part of the message
already received, once. The receive asks for all the spare capacity, like
any other, and every completion wakes the reader, whose parser sees the
bytes so far and returns a smaller `NeedAtLeast` or `Consumed`. The receives
that follow land behind the bytes already received, in place, because the
buffer already holds the whole message.

So a parser that overestimates `additional` costs memory and nothing else,
as the `NeedAtLeast` contract documents (`an_overestimated_need_does_not_stall_a_direct_read`).
A reset in the middle of a message completes the next receive with
`ECONNRESET`, which `with_data_result` returns as an error
(`a_reset_in_the_middle_of_a_message_is_an_error`).

An earlier version of the prototype asked for exactly `additional` bytes with
`MSG_WAITALL`, so that a large value arrived in one completion. Both tests
above fail against it: the overestimating reader stalled, and a reset after
part of the rest had arrived was reported as a clean EOF, because the kernel
returns the partial byte count without the error.

In the build C screen only RESP 1 MiB had a known length (about 45,000 such
receives per run, then with `MSG_WAITALL`). memcache 1 MiB copied 0 bytes per
byte without a length, because receives sized by the largest message hold
whole values. Without `MSG_WAITALL`, RESP 1 MiB takes about 27 completions
per value, each of which wakes the reader, and costs 0.965 of A's CPU (C5)
against 0.943 with it (C3).

### Accumulator cap

`detach_for_recv` clamps every receive to `recv_accumulator_max` minus the
bytes buffered. When the accumulator is full and the parser still needs
more, the connection is closed, as it is on the ring path (`config.rs`
documents "The connection is closed if the cap is exceeded").

### Close

`try_finalize_close` submits no cancel for a receive. The direct receive is
ended by the close's lead: `shutdown` before 6.13,
`ASYNC_CANCEL` of every request on the fixed file from 6.13. A handed-off
socket (park, below) is the only case that closes without a lead, and a
park ends the receive and the hangup poll before the hand-off. The buffer stays in its slab entry
until the receive's completion. If that completion arrives after the slot
holds another connection, the generation check treats it as stale.

### Park

A park (`offer_for_park`, merged accept mode) moves an accepted connection's
socket to another worker. On a direct connection `begin_park` cancels the
direct receive of a parked read, if one is in flight (its user_data carries
the `direct_recvs` index, kept in `ConnectionState::recv_direct_slot`), and
the hangup poll. The install waits until neither is armed
(`drive_park_drains`), and `arm_direct_recv_or_close` refuses to arm while a
park is pending (`Driver::park_pending`), so a reader that polls again in
that time stays parked with no receive. Bytes received before the cancel
withdraw the offer, as on the ring path. The adopting worker arms the
hangup poll when it installs the connection, and its reader arms a receive
when it parks. An abandoned park arms the hangup poll again and wakes the
reader (`rearm_direct_after_park`).

### Worker exit

`run_shutdown` waits, among its other conditions, until every
`direct_recvs` entry is empty, and handles `RecvDirect` completions in its
drain loop. The wait is bounded at 100 × 100 ms like the rest of the loop.
The `Ring` field drops before the slab, and the kernel tears the ring down
asynchronously after its fd closes, so an entry still in flight when the
bound runs out is freed while the kernel may hold it. Every connection has
been closed with a lead by then, so the receive has been cancelled; I have not
checked whether the cancel can still be pending after 10 s.

## Which reads a direct connection supports

- `with_data`, `with_bytes`, `with_data_result`, `recv_ready` and
  `ConnStream` reads: supported. Each arms the receive when it parks
  (`park_recv`).
- `try_with_data` does not park or arm a receive. While a receive is in
  flight, for example after a parked read was dropped, the buffered bytes
  are in that receive's buffer and `try_with_data` returns `None`.
- `segments`, `recv_owned_segment`, `with_segments`, `with_bytes_segments`
  and `forward_to` return `io::ErrorKind::Unsupported`. They read held
  provided buffers, and a direct connection has none.
- `forward_to_conn` sends from the accumulator (`DirectForward` in
  `runtime/io.rs`): it takes what the accumulator holds, up to what is left
  of the length, and sends it on the sink through the sink's send queue
  under a guard, zero-copy at or above `send_zc_threshold`. One send is in
  flight at a time; while it is, the source receives into an empty
  accumulator, so at most one more chunk is buffered. A second forward from
  the same connection is refused with `EBUSY` (`direct_forwarding` on
  `ConnectionState`). A send the runtime cannot submit resolves the forward
  with that error and puts the chunk back in front of the accumulator.
- `forward_recv_buf` is a send from the accumulator and is not refused. The
  `forward_echo_*` tests in `ringline/tests/echo.rs` run it on accepted
  direct connections. A connection that holds `forward_hold_cap` send slab
  entries after one, with the slab over half used, arms no receive when a read
  parks, and arms it when that changes (#733).
- TLS: a TLS connection receives through the provided-buffer ring. The
  kernel's bytes are ciphertext, and rustls copies the plaintext into the
  accumulator in any case.
- mio: unchanged. The mio backend reads into one 8 KiB buffer
  per worker and appends to the accumulator (`handle_readable`); reading
  plaintext connections into the accumulator's spare capacity is a separate
  change.
- `cancel`: finishes the read half and cancels the receive in flight.

## API

- None to choose it: accepted, `connect` and `connect_unix` connections
  receive this way on io_uring unless they use TLS (decisions 11 and 15).
  `TcpConnect::recv_direct`
  and the client crates' `recv_direct` config options were removed.
- `ConfigBuilder::recv_direct_region(bytes)`, the size of a connection's
  own buffer, default 32 KiB, at least 1.
- `ConfigBuilder::recv_direct_pool_max(bytes)`, the most free borrowed
  buffers a worker keeps, default 16 MiB.
- `ConnCtx::is_recv_direct()` (and on `Connection` and `RecvHalf`): whether
  the connection receives this way.
- The client methods that read with segments were removed (decision 12):
  ringline-redis `get_stream`, `recv_get_discard` and `recv_get_segments`,
  and ringline-memcache `get_stream` and `get_cas`. ringline-redis
  `recv_meta` drains a GET reply through `with_bytes` on every connection.

## Metrics

`ringline/recv_direct`: `ARMED` (receives submitted), `KNOWN_LENGTH` (of
those, receives into a buffer grown for a `NeedAtLeast` of at least
`recv_direct_region`), `BYTES` (bytes the kernel wrote into accumulators),
`STALE` (completions for a closed or reused slot), `POOL_REUSED` and
`POOL_ALLOCATED` (borrowed buffers that came from the pool, and ones
allocated because none fit), `HANGUP` (connections closed because a hangup
peek found the stream ended with no receive in flight and nothing
buffered). Copies on a direct connection still count in
`ringline/recv_ring` `BYTES_COPIED`.

## Tests

- `tests/recv_direct.rs`:
  - Patterned messages from 1 B to 1 MiB + 3, written in uneven pieces with
    pauses, read and checked byte by byte with `with_bytes` (keeping every
    fourth value alive across the next read) and with `with_data`.
  - A connection closed with a receive armed, followed by a connection on the
    same slot that must read only its own bytes.
  - A reader whose `NeedAtLeast` is 10 MiB for 200,000-byte frames reads
    every frame without an EOF.
  - A reset after 2,000 bytes of a 100,000-byte frame is returned as
    `ConnectionReset`.
  - A plaintext `connect` is direct; every refusal listed above, and a
    `with_data` read on the same connection afterwards.
  - `recv_ready` resolves at once when a read gave up with part of a message
    held in the buffer of an armed receive (fails when `recv_buffered` does
    not count `recv_direct_held`).
  - `ConnStream` `read_exact` and `fill_buf` on a direct connection (fail
    when they park without `park_recv`).
  - A `connect_unix` connection is direct and reads what its peer wrote.
  - `forward_to_conn` from a direct connection: a second forward is refused
    with `EBUSY` while the first is alive; a forward of 60,000 of 100,000
    bytes stops there and leaves the next byte readable; a forward of more
    than the peer sends resolves with what arrived before the FIN; the sink
    receives the bytes in order (fails when the forward ignores its
    length). `echo.rs`'s `forward_to_conn_proxies_both_directions` forwards
    a proxy's outbound leg the same way.
  - Hangup: a connection that is not read sees its peer's FIN
    (`a_connection_that_is_not_read_sees_the_peer_close`); a forward
    delivers every byte when the source's peer closed behind them; bytes
    buffered ahead of a FIN or a reset stay readable, and the reset is
    reported as a reset; the end behind queued or buffered bytes closes a
    connection that reads them once and does not park again; the recheck
    runs before a worker with no tick blocks; a reset behind buffered bytes
    read once is reported as a reset.

  Dropping one received byte fails the first three tests. The overestimate
  test and the mid-message reset test
  (`a_reset_in_the_middle_of_a_message_is_an_error`) fail against the
  `MSG_WAITALL` version; the refusal test as changed for decision 11 has not
  been run against it.
- `event_loop.rs` unit test `a_hangup_with_a_receive_in_flight_is_rechecked`:
  a hangup poll that completes with a receive in flight puts the connection
  on `hangup_rechecks`.
- `tests/recv_direct_alloc.rs` (its own binary, for the counting global
  allocator): request-response batches of small, 64 KiB, 1 MiB and
  16 × 4 KiB and 16 × 8 KiB messages make fewer than one allocation of
  32 KiB or more per 20 batches after the warmup (see Buffers).
- `accumulator.rs` unit tests: borrowed sizes round to the steps and to
  2 MiB; the pool reuses a fitting buffer, refuses one more than twice the
  size, keeps no more than its cap, gives a smaller buffer room by freeing the
  largest free one, and frees a larger one; a connection returns its borrowed
  buffer once nothing is buffered and borrows the same one for the next
  large message; a borrowed buffer holding a 1 MiB message, three 4 KiB
  messages and the start of the next 1 MiB message grows to the receive size
  in place (fails against `reserve`, which grows it to 1.49 MiB); a 1 MiB
  message of known length whose start arrived while a value from the same
  buffer was held leaves the connection's own buffer no larger than the
  region while the message is borrowed, and at exactly the region when
  idle, with the
  large one in the pool (fails when `reclaim` sizes its copy by the reserve
  target, and when an idle buffer smaller than the region grows with
  `reserve`, to 65,336 bytes); an own buffer larger than twice the region
  goes to the pool when idle (fails without that check). All four tests
  that check the pool's free bytes fail when the pool keeps nothing.
- `tests/recv_direct_copies.rs` (its own binary, for the process-wide
  counters): 70,000-byte messages in 64 KiB and 1 MiB writes copy at most a
  quarter of a byte per byte received; 500 B messages at most 1/20; 1 MiB
  messages at most 1/5, with at least one known-length receive.
- `event_loop.rs` unit tests: a synthetic `RecvDirect` completion with data
  for a connection whose generation moved on is not attached to the slot's
  new occupant, and its slab entry is freed (fails with the generation
  check removed); a direct connection whose accumulator is at the cap is
  closed instead of armed. No test checks the `STALE` counter.
- The ringline-redis and ringline-memcache `streaming` tests, on both
  backends, read small and 100,000-byte values through a pool and a sharded
  client. The redis test drains GET replies with `recv_meta`, including a
  100,000-byte value, a desynced reply that poisons the connection, and a
  value cut short by the peer's FIN; the memcache test reads values with
  their CAS tokens through `gets` and a value cut short by a FIN.

Not tested: worker exit with a receive armed; the order of `record_arrival`
and `attach_received` in `handle_recv_direct` (no test fails if the arrival
is recorded after the bytes are attached); arrival times on a direct
connection.

## Landing

Done: the 64 B fix (C3), the pool (C5), its growth and eviction fix (C7),
throughput and latency of the commit (C8), the PR (#684), the three client
configs made opaque, the scale run, direct receive for every outbound
plaintext connection (decision 11), and for every accepted one, with the
hangup poll and park (decisions 15 to 17).

1. The cause of `c`'s higher p99 at memcache 4 KiB depth 16, mixed depth 16,
   1 MiB idle and RESP 64 B (Evidence): a profile of the 4 KiB depth-16
   cell. One candidate is the submit round trip of arming a receive only
   after the reader parks, which the multishot ring does not pay; I have not
   checked it.
2. Accepted connections: measure whether the same decision holds for a
   server.
3. mio: read plaintext connections into the accumulator (separate PR).

## Decisions

Made by the owner on 2026-10-19:

1. No `MSG_WAITALL`: a known length grows the buffer, and every completion
   wakes the reader.
2. Reads that need the provided-buffer ring, and TLS with `recv_direct`,
   return `Unsupported`.
3. Client crates: `PoolConfig::recv_direct` in the next release;
   `ShardedConfig` and `ClusterConfig` in the next breaking release.
4. No length hint for ringline-memcache: memcache 1 MiB copied 0 bytes per
   byte without one.
5. Opt-in per connection, off by default, until C3 and the scale run show no
   cell where it costs more than the ring.
6. Segment views: the client switch on `feat/segment-clients` and the proto
   releases it needs are not pursued.

Made by the owner on 2026-10-20:

7. Accept the cost of no `MSG_WAITALL` at RESP 1 MiB (0.965 of A's CPU
   against 0.943).
8. Keep the borrow fit at twice the size: at mixed depth 16 a tighter fit
   would save about 0.8 GB of the 4.4 GB, which is not worth more early
   allocations.
9. Open the PR on the C8 results so far, assuming the remaining runs agree.
   They did not on p99; see 10.
10. Merge with `c`'s higher p99 in four cells recorded here, and look for its
    cause afterwards.

Made by the owner on 2026-10-21:

11. Every outbound plaintext connection on io_uring receives directly, with
    no option, on the scale run's results. This replaces 5, and 3 for
    `PoolConfig`, `ShardedConfig` and `ClusterConfig`. A TLS connection
    receives through the ring instead of failing, which replaces the TLS
    half of 2.
12. Remove the client methods that read with segments instead of making
    them read from the accumulator.
13. `forward_to_conn` from a direct connection sends from the accumulator,
    so a proxy's outbound leg keeps working.
14. No control run with the one-shot ring for the 64 B cost, and no second
    4,000-connection run.

Made by the owner on 2026-10-22 and 2026-10-23:

15. Every accepted plaintext connection on io_uring receives directly, with
    no option, based on the accepted-connection runs.
16. Remove `enable_recv_forward`, `forward_held`, `run_direct_echo` and
    `set_recv_sink` on both backends: after 15 no io_uring connection
    receives through the path they read, except a TLS one, where they did
    nothing.
17. Park carries a direct connection, instead of refusing it.

Open: whether the scanner PRs in `resp-proto` and `memcache-proto` are
closed or merged without a release.

## Not known

- The cost of the TCP provided-buffer ring that every worker still
  registers (256 × 16 KiB by default) for a server with no TLS listener,
  which now never receives through it.

- The cost of the hangup poll's wait-queue entry on busy connections (every
  socket wakeup runs its callback), and how much memory the delayed release
  of closed sockets holds before 6.13 on a ring with long-lived idle
  connections (Mechanism, the hangup poll).
- Why GET p99 at depth 16 with 8,000 accepted connections is higher on
  direct than on the ring (86 to 94 ms against 68 to 75 ms at 64 B, four
  runs each, two with 16 KiB and two with 128 KiB send slots), with a lower
  p50. The 5 s flush counts cannot show stalls shorter than the interval.

- Why `c`'s p99 is higher than A's in four cells (Evidence, C8 latency).
- Why `c`'s throughput gain at 4 KiB depth 16 with the client limited
  (about 10%, one run) is larger than its fixed-rate CPU saving, and whether
  more runs agree.
- Why `c` costs 2 to 4% more CPU per GET at 64 B depth 1 (Evidence,
  "Scale").
- A `ForwardToFuture` dropped by `handle_close` (which tears down another
  connection's task without `CURRENT_DRIVER` set) cannot clear
  `direct_forwarding`, so later forwards from its source are refused with
  `EBUSY` until the source's slot resets. The ring forward leaves its
  `forward_progress` set the same way.
- How a direct forward compares with the ring forward in throughput and CPU;
  neither has been measured against the other.
- Whether a cancelled direct receive can still be in flight when the worker
  exit bound runs out.
