# Benchmarks

Point-in-time performance numbers for ringline, alongside a tokio
reference. These are checked in so future changes have a baseline to
beat (or to flag a regression against).

## Test rig

| Item    | Value                                                          |
|:--------|:---------------------------------------------------------------|
| CPU     | AMD Ryzen Threadripper 3970X 32-Core (8 cores exposed to runner) |
| Memory  | 31 GiB                                                         |
| Kernel  | Linux 6.12.63 (Debian 13 trixie)                               |
| Rust    | 1.95.0                                                         |
| Backend | io\_uring                                                       |
| Worker threads | 1 (single-threaded ringline + single-thread tokio current\_thread) |
| Bench harness | `cargo run --release -p ringline-benchmarks`             |
| Sample window | 5 s, after 2 s warmup, per (clients × size × combo)      |
| Latencies   | per-iter `Instant::now()` → `t0.elapsed()` recorded into in-process histograms |
| Commit  | `f40de73` (after PR #184)                                      |

The runner spawns its own tokio-based server (TCP/UDP echo or RESP responder) and then drives it with either a tokio client or a ringline client. The "ringline → tokio" rows mean **ringline client** talking to a **tokio server** (which is also what the "ringline → ringline" rows are today — see *Caveats* below).

## Reproducing

```bash
# Full TCP / UDP matrix (~15 minutes on the rig above)
cargo run --release -p ringline-benchmarks -- \
    --clients 1,10,50,200 --sizes 64,512,4096,32768 \
    --only tcp,udp --json tcp-udp.json

# Redis (synthetic RESP server speaks GET/SET/PING/DEL)
cargo run --release -p ringline-benchmarks -- \
    --clients 1,10,50,200 --sizes 64,512,4096 \
    --only redis

# Smoke test
cargo run --release -p ringline-benchmarks -- --quick
```

Per-iter "ops/s" is total completed operations across all clients ÷ measured wall-clock (excluding warmup). `p50` / `p99` are per-op round-trip latencies aggregated across all clients.

## TCP echo

`ringline → ringline` column is the ringline client + ringline-runtime server. `tokio → tokio` is the tokio current\_thread baseline.

| Clients × Size | ringline → ringline | tokio → tokio | ringline vs tokio | p50 (ringline) | p99 (ringline) |
|:---|---:|---:|---:|---:|---:|
| 1c × 64 B   |  43 k |  37 k | **+17 %** | 23 µs |  37 µs |
| 1c × 512 B  |  40 k |  36 k | +10 % | 23 µs |  38 µs |
| 1c × 4 KiB  |  37 k |  32 k | +18 % | 26 µs |  46 µs |
| 1c × 32 KiB |  17 k |  21 k | −17 % | 53 µs | 158 µs |
| 10c × 64 B  | 200 k | 179 k | +12 % | 49 µs |  67 µs |
| 10c × 512 B | 197 k | 177 k | +12 % | 50 µs |  68 µs |
| 10c × 4 KiB | 166 k | 140 k | +19 % | 61 µs |  99 µs |
| 10c × 32 KiB |  35 k |  37 k | −4 % | 281 µs | 336 µs |
| 50c × 64 B  | 202 k | 180 k | +13 % | 246 µs | 321 µs |
| 50c × 512 B | 200 k | 179 k | +12 % | 248 µs | 310 µs |
| 50c × 4 KiB | 159 k | 140 k | +13 % | 278 µs | 566 µs |
| 50c × 32 KiB|  36 k |  36 k | ±0 % | 1.40 ms | 1.87 ms |
| 200c × 64 B | 205 k | 184 k | +11 % | 990 µs | 1.20 ms |
| 200c × 512 B | 205 k | 178 k | +15 % | 1.00 ms | 1.23 ms |
| 200c × 4 KiB | 154 k | 142 k | +8 % | 1.17 ms | 2.47 ms |
| 200c × 32 KiB|  31 k |  34 k | −10 % | 6.22 ms | 9.70 ms |

ringline leads tokio across most of the matrix; the 32 KiB cells where it trails are explained in *Caveats*.

## UDP echo

| Clients × Size | ringline → ringline | tokio → tokio | ringline vs tokio | p50 (ringline) | p99 (ringline) |
|:---|---:|---:|---:|---:|---:|
| 1c × 64 B   |  48 k |  38 k | **+27 %** | 18 µs |  33 µs |
| 1c × 512 B  |  51 k |  37 k | +37 % | 18 µs |  32 µs |
| 1c × 4 KiB  |  45 k |  31 k | +45 % | 21 µs |  35 µs |
| 1c × 32 KiB |  30 k |  27 k | +11 % | 30 µs |  50 µs |
| 10c × 64 B  | 266 k | 195 k | **+36 %** | 36 µs |  59 µs |
| 10c × 512 B | 263 k | 185 k | +42 % | 37 µs |  55 µs |
| 10c × 4 KiB | 201 k | 149 k | +35 % | 49 µs |  74 µs |
| 10c × 32 KiB |  61 k |  75 k | −19 % | 112 µs | 249 µs |
| 50c × 64 B  | 264 k | 205 k | **+29 %** | 187 µs | 255 µs |
| 50c × 512 B | 279 k | 200 k | +40 % | 179 µs | 223 µs |
| 50c × 4 KiB | 181 k | 147 k | +23 % | 138 µs | 212 µs |
| 50c × 32 KiB|  56 k |  74 k | −25 % | 120 µs | 267 µs |
| 200c × 64 B | 292 k | 209 k | **+40 %** | 598 µs | 758 µs |
| 200c × 512 B | 262 k | 200 k | +31 % | 513 µs | 727 µs |
| 200c × 4 KiB | 192 k | 144 k | +33 % | 135 µs | 335 µs |
| 200c × 32 KiB|  51 k |  72 k | −30 % | 127 µs | 324 µs |

UDP is where ringline pulls farthest ahead — at 10c × 64 B the gap is +36 %; at 1c × 4 KiB it's +45 %. The 32 KiB rows trail tokio for the same reason as the TCP 32 KiB ones (see *Caveats*).

## Redis (GET against a synthetic RESP server)

Workload: each client loops `GET k`. The server is a tokio TCP listener speaking a hand-rolled RESP subset (responds `$<msg\_size>\r\n<msg\_size B>\r\n` to any GET). Both clients hit the same server — the only thing varying is the client runtime.

| Clients × Size | ringline-redis | tokio (hand-rolled RESP) | ringline vs tokio |
|:---|---:|---:|---:|
| 1c × 64 B   |  40 k |  37 k | **+8 %** |
| 1c × 4 KiB  |  37 k |  35 k | +5 % |
| 10c × 64 B  | 184 k | 178 k | +4 % |
| 10c × 512 B | 191 k | 166 k | +15 % |
| 50c × 64 B  | 187 k | 179 k | +4 % |
| 50c × 512 B | 195 k | 174 k | +12 % |
| 200c × 64 B | 195 k | 182 k | +7 % |
| 200c × 4 KiB| 154 k | 166 k | −7 % |

The hand-rolled tokio client uses fixed-size reads (it knows the response length up front); `ringline-redis::Client::get` walks the full RESP parser on every response. Despite that extra work, ringline-redis still leads in most cells, and the largest deficits are small.

## Highlights & history

### `perf(runtime): skip close_notify deadline walk when nothing is armed` (PR #184)

Before this fix, every event-loop iteration ran a TLS-only `check_close_notify_deadlines` over **every** connection slot, even on plain-TCP workloads where no deadline was ever armed. A flamegraph of the redis 1c × 64 B config showed **25.1 %** of worker CPU in that scan.

| Bench               | Before | After | Δ |
|:--------------------|-------:|------:|------:|
| TCP echo 1c × 64 B  | 28 k   | 43 k  | +54 % |
| TCP echo 10c × 64 B | 131 k  | 200 k | +53 % |
| UDP echo 1c × 64 B  | 22 k   | 48 k  | **+120 %** |
| UDP echo 10c × 64 B | 143 k  | 266 k | +86 % |
| Redis 1c × 64 B     | 28 k   | 40 k  | +44 % |
| Redis 10c × 64 B    | 133 k  | 184 k | +38 % |

50c and 200c cells moved by ≤ 5 % — there the deadline scan was already amortized by real I/O work per iteration.

## Caveats

- **Single ringline worker.** Numbers are for `worker.threads = 1`. Multi-worker scaling is not exercised here.
- **Localhost only.** All servers and clients run on the same box. Real network latency would shift the relative shapes.
- **TCP/UDP "ringline → ringline" actually uses a tokio server today.** `protocols/tcp.rs` and `protocols/udp.rs` both call into a tokio-based echo server for both columns; see the `// Use tokio server for now — ringline server requires TLS setup` comment in `tcp.rs`. So the "vs tokio" rows really compare the **client** side; both have the same server CPU cost included. A native ringline echo server would likely widen ringline's lead on those rows.
- **Bench's ringline client at 32 KiB is the bottleneck for the −10 %..−30 % rows.** It uses `with_data` with a single buffered echo per round trip, and at 32 KiB the recv-buffer churn dominates. Improving that path is its own piece of work and unrelated to runtime perf.
- **Redis bench server is synthetic.** It does not implement a real Redis storage layer; the response size is fixed by `msg_size`. The numbers are an upper bound on what the wire+parser combo can do, not what a real Redis backend would deliver.
- **`ringline-memcache`, `ringline-momento`, HTTP/1/2/3, gRPC, QUIC bench stubs are still TODO.** `cargo run -p ringline-benchmarks --only memcache,http1,…` currently returns `0 ops/s` for those — they're not measured here.
- **Numbers reflect what's available to a single user-space process.** Under load from other tenants, especially on cloud VMs, ranks can flip.

## Updating this file

When you ship a performance-relevant change:

1. Rerun the matrix on the same rig (or note the rig).
2. Update the affected table cells in-place.
3. Add a row to *Highlights & history* with the PR number, the impacted cells, and the before/after numbers.
4. If a regression is unavoidable, document it here rather than silently pushing.
