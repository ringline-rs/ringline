# Benchmarks

Point-in-time performance numbers for the ringline **server**, alongside a
tokio reference. Checked in so future changes have a baseline to beat (or to
flag a regression against).

These numbers are from a **clean two-machine run** — two separate EC2 instances,
not the co-located/single-host configuration whose unreliable tail-latency
numbers were withdrawn previously. The workload is a realistic cache server, not
echo.

---

## Segcache cache-server comparison (two-machine, AWS Graviton4)

This compares the **ringline server** against a **tokio server**, both serving the
same read-heavy cache workload: a real Segcache (segment-structured TTL cache)
answering rotating-key `GET`s. On a hit the
value is borrowed zero-copy from segment memory (`ValueRef`) and written to the
socket — ringline serves it through its send path, tokio copies it on `write`.
Client and server run on **separate physical instances**.

### Summary

With each runtime tuned to a **load-appropriate worker count** (see *Worker count*
below), the ringline server is the stronger cache server:

- **Small/medium values (256 B, 1 KiB):** ringline delivers **~30% more
  throughput**, **~25% lower p50** and **15–18% lower p99** latency, at **~22%
  better CPU efficiency** (ops per server-core-second) than tokio.
- **Large values (4 KiB):** throughput and median latency **tie** — the workload
  is bandwidth-bound at that size — but ringline still serves it on **~14% less
  CPU** with an **8% lower p99 tail**.
- **At raw saturation** (open-loop, max offered rate) the two runtimes are a
  **dead tie**: both saturate the instance's network/packet-per-second ceiling,
  and the server runtime stops mattering. ringline's advantage is in *latency and
  CPU efficiency at a given load*, not in a higher saturation ceiling on this rig.

### Test rig

| Item | Value |
|:-----|:------|
| Server | AWS EC2 `c8g.4xlarge` — 16 vCPU, Graviton4 (Neoverse-V2), aarch64 |
| Client | AWS EC2 `c8g.8xlarge` — 32 vCPU, Graviton4, aarch64 |
| Placement | Same AZ (`us-west-2b`), cluster placement group |
| Network | VPC-private ENA between the two instances (data plane); the SystemsLab control plane is out-of-band over Tailscale |
| OS / kernel | Debian 13 (trixie), Linux 6.12 |
| Rust | stable |
| Cache | Segcache, 16384 keys pre-populated, value size per row; GET-only |
| Server workers | per-core pinned; worker count noted per table |

### Methodology

- **Closed-loop** (throughput/latency/CPU tables): 128 connections (8 client
  processes × 16 connections), each connection issuing the next request on
  response. Reported throughput is the aggregate; latency percentiles are
  coordinated-omission-free service latency.
- **Server CPU** is measured on the server instance only (it runs alone): the
  `bench-server` process `utime+stime` from `/proc/<pid>/stat` over a 30 s steady
  window (warmup excluded). An **idle baseline** (server up, zero connections) is
  subtracted, so `cores busy` reflects load-attributable CPU. `ops/core` =
  achieved ops ÷ load-attributable cores busy. Idle baseline was ≤ 0.08 cores —
  the workers park when idle, so the loaded figure is real per-op work.
- **Open-loop** (saturation): 24 client processes at a high offered rate to find
  the throughput ceiling.
- Both runtimes are pinned one worker thread per core and **swept across worker
  counts**; the headline compares each at its best (matched) worker count.

### Closed-loop: ringline vs tokio at matched worker count

Both runtimes at 4 workers (the efficiency sweet spot for this 128-connection
load — see below), 128 connections:

| value | metric | ringline | tokio | ringline advantage |
|------:|:-------|--------:|------:|:-------------------|
| **256 B** | throughput (ops/s) | **803,916** | 613,552 | **+31%** |
| | p50 latency | **149 µs** | 207 µs | **−28%** |
| | p99 latency | **260 µs** | 305 µs | **−15%** |
| | ops / server-core-s | **214,000** | 176,000 | **+22%** |
| **1 KiB** | throughput (ops/s) | **772,533** | 593,163 | **+30%** |
| | p50 latency | **158 µs** | 209 µs | **−25%** |
| | p99 latency | **268 µs** | 328 µs | **−18%** |
| | ops / server-core-s | **207,000** | 168,000 | **+23%** |
| **4 KiB** | throughput (ops/s) | 451,155 | 451,145 | tie (bandwidth-bound) |
| | p50 latency | 279 µs | 277 µs | tie |
| | p99 latency | **422 µs** | 460 µs | **−8%** |
| | ops / server-core-s | **146,000** | 128,000 | **+14%** |

At 256 B and 1 KiB ringline wins every axis. At 4 KiB the per-request bytes
dominate and the two converge on throughput and median latency; ringline's
remaining edge is CPU efficiency and the tail.

### Worker count: efficiency vs. throughput

A thread-per-core runtime wants its worker count matched to the offered
concurrency — **not** set to the full core count. Sweeping the ringline server's
workers at fixed 128-connection load (256 B):

| workers | throughput (ops/s) | ops / server-core-s | p50 | p99 |
|--------:|-------------------:|--------------------:|----:|----:|
| 4 | 825,518 | **221,000** | 146 µs | 249 µs |
| 8 | 928,976 | 157,000 | 138 µs | 218 µs |
| 16 | 982,153 | 127,000 | 136 µs | 202 µs |

More workers buy **more throughput** (982k at 16w, +19% over 4w) and slightly
lower latency, but at a **steep CPU cost** — efficiency falls from 221k to 127k
ops/core because the same 128 connections are spread thinner across more event
loops. tokio shows the same shape (most efficient at 4 workers, ~176k ops/core).
For this load, 4 workers is the efficiency-optimal point for both; if you are
throughput-bound and CPU-rich, ringline scales further by adding workers.

At 4 KiB the throughput is flat across worker counts (~451k regardless) — the
workload is bandwidth-bound, so extra workers only erode efficiency.

### Peak throughput (open-loop saturation) — a network-bound tie

Driven open-loop at maximum offered rate (24 client processes, 16 server
workers), both runtimes converge on the instance's network/packet-per-second
ceiling:

| value | ringline | tokio |
|------:|---------:|------:|
| 256 B | ~7.03 M ops/s | ~7.04 M ops/s |
| 1 KiB | ~1.79 M ops/s | ~1.79 M ops/s |
| 4 KiB | ~441 k ops/s | ~448 k ops/s |

These are within run-to-run noise of each other, and the ringline server's event
loop reports ~50% idle iterations at this point — i.e. the **server is not the
bottleneck**, the NIC/PPS ceiling is. Peak throughput on this rig is a property of
the network, not the runtime. (The 16 KiB tokio cell errored in this harness and
is excluded pending investigation; ringline served ~109 k ops/s at 16 KiB.)

### Recommendation

| scenario | recommendation |
|:---------|:---------------|
| Cache values ≤ 1 KiB, latency- or CPU-sensitive | ringline: ~30% more throughput, ~25% lower p50, ~22% better CPU efficiency |
| Cache values ~4 KiB | throughput/median tie; ringline for lower tail + less CPU |
| Throughput-bound and CPU-rich | ringline scales with added workers (trading CPU efficiency for ops/s) |
| Driving the NIC to saturation | tied — bottleneck is the network, not the runtime |

---

## Caveats

- **Single rig, aarch64 Graviton4.** Absolute numbers are specific to this
  instance pair; ratios should travel better than absolutes, but a different CPU
  or NIC will shift them.
- **GET-only, read-heavy.** This measures cache reads with zero-copy value
  serving. SET/mixed workloads and other protocols are not covered here.
- **Worker count matters.** The comparison is best-vs-best at a load-appropriate
  worker count. Over-provisioning workers reduces CPU efficiency for *both*
  runtimes; size workers to your concurrency.
- **Large values are bandwidth-bound.** At ≥ 4 KiB and at open-loop saturation the
  bottleneck moves off the runtime onto network bandwidth / PPS, and the runtimes
  converge.
- **Two real machines.** Unlike the previously-withdrawn numbers, client and
  server are separate EC2 instances in a cluster placement group; there is no
  shared-host or shared-switch incast artifact.

## Reproducing

The distributed runs are SystemsLab experiments against an EC2 Graviton pair
(`aws.server` / `aws.client` tags). The `--protocol segcache` support on
`bench-server`/`bench-client`, the vendored Segcache, and the experiment specs
live on the **`bench/fair-throughput`** branch (not yet on `main`); these numbers
were produced from that branch.

The server is `bench-server --runtime <ringline|tokio> --protocol segcache
--cache-keys 16384 --workers <N> --msg-size <B>`. Closed-loop runs use a
closed-loop client (`bench-client ... --clients 16` without `--open`, 8 processes)
plus a server-side `/proc/<pid>/stat` CPU sampler with an idle baseline; the
open-loop saturation sweep is `experiments/tcp-aws-segcache.toml` on that branch.

## Updating this file

Re-run the experiments above on an equivalent two-machine rig, re-derive the
ratios from the raw `ops_per_sec` / latency / CPU figures, and update the tables.
Keep the methodology notes honest: state the worker counts, whether load was
sub-saturation, and how CPU was attributed.
