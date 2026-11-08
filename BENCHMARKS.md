# Benchmarks

Point-in-time performance numbers for the ringline **server**, alongside a
tokio reference. Checked in so future changes have a baseline to beat (or to
flag a regression against).

Two runs are recorded here, on different rigs and different workloads. Both are
two-machine (client and server on separate physical hosts); neither is
co-located.

| | workload | rig | date / commit |
|---|---|---|---|
| [TCP echo](#tcp-echo-comparison-two-machine-x710-40g) | TCP echo, 9 configurations x 4 sizes x 4 connection counts | bare metal, Xeon, X710 40G LAG | Sept 2026, `a685e16` (pre-0.7) |
| [Segcache](#segcache-cache-server-comparison-two-machine-aws-graviton4) | Segcache GET, read-heavy | AWS Graviton4 c8g | June 2026, `c77cfba` (0.1.3) |

### Read this first

**Against a well-configured tokio, ringline is roughly 0–10% faster — not the
27–71% this file used to lead with.** That larger number is real, but it is
measured against tokio's *default* runtime, and an earlier version of this file
quoted it while implying the stronger claim. Both figures are in the echo
section, labelled.

**Neither run measures a protocol server.** Echo is a byte pipe: no parsing, no
response building, no application work. Segcache is the closer proxy and has
not been re-run since June 2026. Any claim about ringline serving a real
protocol rests on the segcache section, which is the older and thinner of the
two.

---

## TCP echo comparison (two-machine, X710 40G)

**Run:** September 2026, commit `a685e16`. 432 arms, 9 server configurations x
4 connection counts x 4 message sizes x 3 repetitions.

### "ringline" and "tokio" are each more than one thing

The single most important thing this run established is that a two-bar chart
of "ringline vs tokio" hides the answer. Both runtimes have several ways to
serve this workload, they differ by more than the gap between the runtimes,
and an earlier version of this file compared ringline's best against tokio's
default without saying so.

| config | what it is | can a protocol use it? |
|---|---|---|
| `uring` | `run_direct_echo` — echo submitted from the completion handler, no task wakeup (removed; see Reproducing) | no, echo only |
| `uring-fwd` | `with_data` + `forward_recv_buf` — the ordinary read loop | **yes, this is the general path** |
| `rfwd` | `enable_recv_forward` + `forward_held` — byte pipe (removed; see Reproducing) | no, proxy only |
| `mio` | ringline's epoll fallback (the forward loop; `--echo-mode forward` to rerun) | yes |
| `tokio` | multi-thread work-stealing, canonical echo loop | yes, **tokio's default** |
| `tokio-pc` | one `current_thread` runtime per core + `SO_REUSEPORT` | yes |
| `tokio-splice` | multi-thread, `splice(2)` socket → pipe → socket | no, byte pipe |
| `tokio-pc-splice` | per-core + splice | no, byte pipe |
| `tokio-uring` | tokio futures on `tokio-uring` (inherently per-core) | yes |

`rfwd`, `tokio-splice` and `tokio-pc-splice` never let the handler see a byte —
no parsing, no TLS, no inspection. They belong in a proxy comparison, not a
server one.

### Test rig

| Item | Value |
|:-----|:------|
| Server | bare metal, 24 vCPU Xeon (hv02 guest) |
| Client | bare metal, 56 vCPU Xeon (hv01 guest) |
| Network | 4x Intel X710 in a 40G LAG, direct-attached, no switch hop |
| Server workers | 8 |
| Client threads | 16 |
| Load | closed loop, 20 s steady window after 5 s warmup |
| Reps | 3 per cell; tables report the median |

### Validity gates

Every arm was gated on **Little's law** — `connections = throughput x mean
latency` within 15% — plus a load floor and a funnel check on per-core CPU
concentration.

**426 of 432 passed.** The six rejections are one cell in three reps for each
of two configurations: `tokio` and `tokio-uring` at 2048 connections x 16 KiB,
16–25% out. The same cell was the only rejection in the previous campaign, so
that corner is systematically unmeasurable on this rig rather than noisy.

The gate is checked against the **mean**, not p50. A closed-loop arm whose tail
has taken over still has a healthy median, and that is exactly the arm the gate
exists to catch.

### Headline: it depends entirely on which tokio you mean

**Against the best of the five tokio configurations**, ringline leads in 13 of
16 cells, by roughly 0–10%:

| size | 1 conn | 64 | 512 | 2048 |
|---|---|---|---|---|
| 256 B | +4.5% | +1.5% | +4.7% | +3.5% |
| 1 KiB | +5.2% | +2.3% | +5.7% | +6.1% |
| 4 KiB | +5.7% | −0.1% | +5.1% | +5.7% |
| 16 KiB | +1.5% | **−10.3%** | **−4.9%** | +8.9% |

**Against tokio's default configuration** — the multi-thread work-stealing
runtime, which is what a tokio service runs unless someone deliberately builds
otherwise — the same data says:

| size | 1 conn | 64 | 512 | 2048 |
|---|---|---|---|---|
| 256 B | +4% | +70% | +46% | +27% |
| 4 KiB | +16% | +57% | +36% | +33% |
| 16 KiB | +42% | +71% | +51% | — |

Both tables are true and they answer different questions. The first is "is
ringline's architecture faster than tokio's"; the second is "will switching a
default tokio service to ringline make it faster". **Quoting the second while
implying the first is the mistake this file previously made.**

### Where the difference actually comes from

Most of it is the scheduler, not io_uring. Giving tokio thread-per-core
(`tokio-pc`) recovers the bulk of the gap on its own:

| effect on tokio | 256 B / 64 conns | 4 KiB / 64 | 16 KiB / 64 |
|---|---|---|---|
| per-core scheduler | **+67.6%** | **+55.4%** | +24.0% |
| splice data path | −8.5% | −0.9% | **+34.4%** |
| both | +63.8% | +57.4% | **+90.7%** |

The two effects are not separable — at 16 KiB/64 they are superadditive (+90.7%
against +66.6% predicted from the parts), at 512 subadditive. A 2x2 was needed
to see that; either change alone would have misattributed the gap.

`tokio-uring` is the strongest tokio arm in 7 of 16 cells and comes within 4.7%
of ringline at 256 B / 512 connections (591,854 against 619,863). Same
interface, same per-core shape — it is the closest like-for-like comparison in
the grid, and it says ringline's io_uring implementation is good rather than
categorically ahead.

### Mechanism — 512 connections, 256 B

| config | ops/s | ops/core-s | µs-CPU/op | syscalls/op |
|---|---:|---:|---:|---:|
| uring-fwd | 619,863 | **47,728** | **20.95** | **0.06** |
| uring | 606,096 | 47,032 | 21.26 | 0.06 |
| rfwd | 594,712 | 46,582 | 21.47 | 0.07 |
| tokio-uring | 591,854 | 45,030 | 22.21 | 0.11 |
| tokio-pc | 536,651 | 41,923 | 23.85 | 2.05 |
| tokio-pc-splice | 455,828 | 38,321 | 26.10 | 3.04 |
| mio (before #756) | 451,482 | 38,423 | 26.03 | 3.04 |
| tokio | 425,486 | 37,262 | 26.84 | 2.08 |
| tokio-splice | 361,576 | 32,915 | 30.38 | 3.16 |

Two things worth reading off this:

**Syscall count is not what separates the runtimes.** `tokio-pc` and `tokio`
issue 2.05 and 2.08 syscalls per operation and differ by 26% in throughput.
io_uring's 0.06 is a ~35x amortization against tokio's 2.08, and `uring` uses
21% less CPU per operation than `tokio` (21.26 against 26.84 µs), not the 50%+
that separates the default configurations.

The mio row was measured before #756. In this run mio read each socket until
`EAGAIN`, so every operation cost one read that returned nothing. Since #756 a
short read ends the drain on Linux TCP. An `LD_PRELOAD` syscall count on one
host, at 64 connections, went from about 3.03 to 2.06 syscalls per operation.
That count was not taken on this rig, and none of the mio row's columns have
been re-measured.

**splice costs syscalls to save copies**, which is only worth it when there are
copies worth saving: it is the slowest arm here at 256 B and the fastest at
16 KiB.

### 16 KiB: the one regime where ringline loses

At 16 KiB and moderate concurrency a zero-copy tokio beats every ringline
configuration — `tokio-pc-splice` 165,699 against ringline's best 148,659 at 64
connections. `splice(2)` moves bytes between descriptors without them entering
user space at all, and no user-space runtime beats a kernel-side tee at
forwarding bytes it never has to see.

The loss is bounded in three directions. Below 16 KiB splice *costs* tokio
8–15%. At 2048 connections it collapses — a pipe pair per connection is two
descriptors and a 64 KiB kernel buffer, and `tokio-splice` falls from 169,660
at 512 connections to 121,202 at 2048 while ringline holds near 161,000. And
splice cannot surface a byte to a handler, so the cells ringline loses are the
ones where tokio is doing strictly less work.

### Caveats specific to this run

- **Echo is a byte pipe.** It measures the I/O path with no parsing,
  allocation, or application work. `uring-fwd` is an upper bound on what a
  parsing server would see, not an estimate of it. The segcache tables below
  are the closer proxy for a real server.
- **The 2048-connection column is directional**, not quotable. Little's law
  errors reach 6–8% even where they pass, and it holds the only rejected cell.
- **Do not measure server CPU from `/proc/stat`.** A worker blocked in
  io_uring's `submit_and_wait` is accounted as **iowait**, not idle. A sampler
  counting iowait as busy reads an idle io_uring server at 806% CPU against
  tokio's 33%, and the error biases against io_uring specifically, since epoll
  runtimes have no equivalent quirk. These figures come from rezolus
  `cpu_usage`, which has only `user`/`system` states.
- **Depends on a client-side fairness fix.** Before #392 the tokio echo server
  read with `read_exact`, one syscall per message, while ringline read in bulk.
  Numbers from before that fix are not comparable to these.
- **`tokio-pc` is ~40 lines nobody gets for free.** It is `SO_REUSEPORT` plus a
  `current_thread` runtime per core, written for this comparison. That it
  closes most of the gap is a fact about architecture, not about what a tokio
  service does today.

### Reproducing

Build both servers on the rack's build host, then run one arm per configuration
through SystemsLab anvil-vm jobs on two hosts with the X710 PFs passed through
(`ports = 4`, bonded, fixed `172.31.0.1/.2`).

Server: `bench-server --runtime <ringline|tokio|tokio-uring> --workers 8`, plus
`--echo-mode forward` for ringline and
`--tokio-scheduler {multi-thread,per-core}` / `--tokio-echo {copy,splice}` for
tokio. The mio arm is a `--features force-mio` build; `tokio-uring` needs
`--features tokio-uring-arm`. The `uring` and `rfwd` arms cannot be rerun:
ringline has no `run_direct_echo` or `forward_held`. `--echo-mode` is
required with `--runtime ringline`: `copy` is a `with_data` + `send_nowait`
loop and `forward` is `with_data` + `forward_recv_buf`; `direct` and
`recv-forward` are refused. From 0.7.0-alpha.5 an accepted plaintext
connection receives into its accumulator and `forward_recv_buf` sends the
accumulator under a guard, so a rerun of `--echo-mode forward` measures that
path, not the one in the `uring-fwd` row.

Client: `bench-client --clients <n> --msg-size <bytes> --threads 16 --warmup 5
--duration 20`.

---

## Segcache cache-server comparison (two-machine, AWS Graviton4)

**Run:** June 2026, ringline 0.1.3 (commit `c77cfba`). Not re-run on the current
release.

This is the only workload here that parses a request and builds a response, so
it is the only one that says anything about ringline as a *protocol server*
rather than as a byte pipe — and it is fifteen months of development stale. It
also predates the harness fairness fix (#392) and compares against a single
tokio configuration, so the "which tokio?" caveat that reshaped the echo
section above has not been applied to it. Treat the ratios as indicative and
the absolutes as historical.

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
| | p50 latency | **158 µs** | 209 µs | **−24%** |
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

## Caveats (segcache run)

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

## Reproducing (segcache run)

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
ratios from the raw `ops_per_sec` / latency / CPU figures, and update the
tables. State the worker counts, whether load was sub-saturation, and how CPU
was attributed.

Four traps this file has actually fallen into, each of which produced a
plausible wrong number that survived review:

1. **Comparing your best against their default.** ringline has four ways to
   serve echo and tokio has five; they differ by more than the runtimes do.
   Name the configuration on both sides or the number means nothing.
2. **Measuring CPU from `/proc/stat`.** iowait is not idle, and a worker parked
   in `submit_and_wait` is accounted to it — which biases against io_uring
   specifically. Use rezolus `cpu_usage`.
3. **Picking a statistic by habit.** `Mean` over a whole recording diluted
   syscall rates below the floor the protocol demands (0.83 reads/op for an
   echo server, which is impossible). `Max` over a rate window fixed that — and
   then over-reported a bursty allocation metric by 100x. Ask whether the
   quantity is sustained or bursty before choosing.
4. **Reporting a null from a setup that could not have produced a positive.**
   Three separate runs here came back flat because the baseline did not
   reproduce the defect, because nothing exercised the code under test, or
   because the bottleneck was the harness. Before believing a null, check the
   configuration could have shown the effect.

The gate script and per-arm rezolus recordings are the evidence for the current
tables; a re-run that cannot reproduce the gate results should be treated as a
rig problem before it is treated as a result.
