# Benchmarks

Point-in-time performance numbers for ringline, alongside a tokio
reference. These are checked in so future changes have a baseline to
beat (or to flag a regression against).

---

## Distributed TCP server comparison

This section compares the **ringline server** against a **tokio server** — both
serving the same TCP echo workload from a dedicated VM, with the client on a
separate VM. This is distinct from the single-machine client benchmarks
below (which compare the ringline client vs tokio client against the same
server).

### Summary

For small and medium messages (≤ 4096 B), the ringline server delivers
**1.2–1.5× more throughput** and **2–3.5× lower p50 latency under load**
compared to a tokio server at equivalent connection counts. The advantage
grows with connection density (io_uring amortises per-syscall overhead more
effectively as CQE batches grow) and under high offered rates (the event loop
stays flatter as load approaches saturation). For large messages (≥ 16384 B)
the workload becomes bandwidth-limited and the two servers are equivalent —
the choice of runtime does not matter.

### Caveats

- **Intra-host network.** Client and server VMs sit on the same physical machine
  connected via dedicated 10 GbE ports. True cross-machine latency would
  increase the absolute numbers but should not change the relative ratios, since
  both servers see identical network conditions.
- **Echo workload.** The server does no application logic — receive, copy to send
  pool, transmit. Real applications that do meaningful per-request work will
  amortise runtime overhead further, which generally favours both runtimes
  equally (the delta is in connection-handling overhead, not compute).
- **4 server workers.** Results reflect the physical-core-count default. Fewer
  workers tighten the gap at low connection counts (less parallelism to cover
  idle connections); more workers would push the saturation ceiling higher for
  both runtimes.
- **Dedicated, non-oversubscribed cores.** The VMs run with pinned physical
  cores. On shared infrastructure with noisy neighbours or oversubscribed
  hypervisors, tail latency for both runtimes will increase; ringline's
  thread-per-core model has no work-stealing fallback if a core is stolen.

### Test rig

| Item | Value |
|:-----|:------|
| Physical host | AMD Threadripper 1950X (16 cores / 32 threads) |
| VMs | Two z1.n.small VMs on the same physical host, each with 4 dedicated physical cores and a dedicated 10 GbE network port |
| Network | VM-to-VM via dedicated 10 GbE ports on the same host |
| Kernel | Linux (SystemsLab managed) |
| Rust | 1.96.0 |
| Server workers | 4 (physical core count, default) |
| Methodology | Closed-loop: client fires next request immediately on response. Open-loop: fixed offered rate, latency measured from scheduled send time. |

### Closed-loop throughput

Throughput of each server at saturation, measured with a ringline client.
Ratio = ringline server ÷ tokio server at the same connection count and message
size.

| connections | 256 B | 1024 B | 4096 B | 16384 B | 65536 B |
|------------:|------:|-------:|-------:|--------:|--------:|
| 8 | 1.28× | 1.28× | 1.21× | 1.16× | 1.11× |
| 16 | 1.26× | 1.26× | 1.21× | 1.14× | 1.03× |
| 32 | 1.21× | 1.20× | 1.19× | 1.13× | 0.99× |
| 64 | 1.27× | 1.25× | 1.23× | 1.10× | 1.01× |
| 128 | 1.37× | 1.36× | 1.27× | 1.12× | 1.01× |
| 256 | 1.43× | 1.43× | 1.29× | 1.08× | 1.00× |
| 512 | **1.52×** | 1.45× | 1.21× | 1.08× | 1.00× |
| 1024 | 1.47× | 1.43× | 1.10× | 1.04× | 1.00× |
| 2048 | 1.47× | 1.43× | 1.09× | 1.04× | 1.01× |

Peak absolute throughput (ringline server, ringline client):
- **256 B / 512 connections: 225,633 ops/s**
- 1024 B / 512 connections: 213,660 ops/s
- 4096 B / 256 connections: 104,896 ops/s

**Where the advantage comes from:** io_uring's multishot recv and CQE batching
allow the server to process more completions per syscall as connection density
grows. The benefit is most pronounced at small messages (256–1024 B) where
per-connection overhead dominates, and at 128–512 connections where per-worker
CQE density is highest. The 65536 B column is bandwidth-limited — the choice
of server runtime stops mattering.

### Worker scaling & CPU efficiency

The tables above hold the ringline server at its 4-worker default. This section
sweeps the server's worker count (`--workers 1/2/4/8`) on the same 4-physical-core
`z1.n.small`, holding the workload fixed (ringline server + ringline client,
closed-loop). It answers two questions raw ops/s can't: **how does throughput
scale with cores**, and **how efficiently is each core spent** (ops/s per
server-core-second).

CPU is measured on the server VM only — the server runs alone on its host, so its
`/proc/<pid>/stat` `utime+stime` over the steady test window (warmup excluded) is a
clean per-process figure. `cores busy` is server CPU-seconds ÷ wall-seconds; `ops/s
per core` is throughput ÷ `cores busy`. Each worker is pinned to a core. Rerun
with `experiments/tcp-worker-scaling.toml`.

**256 B, 512 connections** — the high-density small-message cell:

| workers | ops/s | scaling | p50 | p99 | cores busy | ops/s per core |
|--------:|------:|--------:|----:|----:|-----------:|---------------:|
| 1 | 37,871 | 1.00× | 7.45 ms | 264 ms | 0.98 | 38,500 |
| 2 | 106,778 | 2.82× | 4.95 ms | 8.04 ms | 1.93 | 55,300 |
| 4 | **227,176** | **6.00×** | 2.17 ms | 4.74 ms | 3.35 | **67,900** |
| 8 | 241,127 | 6.37× | 2.01 ms | 4.61 ms | 4.73 | 51,000 |

**4096 B, 512 connections** — medium message, same connection density:

| workers | ops/s | scaling | p50 | p99 | cores busy | ops/s per core |
|--------:|------:|--------:|----:|----:|-----------:|---------------:|
| 1 | 31,030 | 1.00× | 9.17 ms | 105 ms | 0.88 | 35,100 |
| 2 | 66,568 | 2.15× | 7.72 ms | 13.6 ms | 1.57 | 42,300 |
| 4 | **104,009** | **3.35×** | 4.64 ms | 10.5 ms | 2.23 | **46,600** |
| 8 | 100,268 | 3.23× | 4.77 ms | 12.2 ms | 3.49 | 28,700 |

Throughput at lower connection density (64 connections; CPU not isolated here
because the server is far from saturated):

| msg | 1w | 2w | 4w | 8w |
|----:|---:|---:|---:|---:|
| 256 B  | 37,367 | 83,421 | 136,102 | 137,446 |
| 4096 B | 28,271 | 54,297 | 78,703  | 78,465  |

**What the numbers say:**

- **Near-linear to the physical core count, then flat.** Throughput rises steeply
  through 4 workers (the box has 4 physical cores) and barely moves — or regresses
  — at 8. The 8th-worker "gain" is hyperthread siblings contending for the same
  physical execution units; at 4096 B 8 workers is actually *slower* than 4.
- **Density makes scaling super-linear.** At 256 B / 512 conn, 4 workers deliver
  **6.0×** a single worker — more than the 4× a pure compute model predicts. The
  reason is the same mechanism the throughput tables credit: a single worker driving
  512 connections spends a large fraction of its core on per-connection bookkeeping
  and thin CQE batches, while 4 workers each handle ~128 connections at much higher
  per-poll CQE density. The per-core efficiency column shows it directly —
  **38,500 → 67,900 ops/s per core** from 1→4 workers. At 64 connections (16
  conn/worker at 4 workers) there isn't enough density to fill the pipeline, so
  scaling caps near 3.6×.
- **Efficiency peaks at the physical core count.** ops/s per core climbs 1→4
  workers, then collapses past 4 (51,000 at 8w for 256 B; 28,700 at 8w for 4096 B)
  as hyperthread oversubscription burns cores for no throughput. For this workload
  the physical-core-count default is also the efficiency sweet spot.
- **Workers crush tail latency.** A single worker fronting 512 connections head-of-
  lines badly — p99 of 264 ms (256 B) / 105 ms (4096 B). Adding workers spreads the
  connections and drops p99 by ~50× (to 4.6 ms / 12 ms at 4–8 workers). Worker count
  is a tail-latency lever, not just a throughput one.

### Open-loop latency vs. offered rate (256 B)

Latency measured from scheduled send time; points where actual throughput
dropped below 95% of offered rate are saturated and excluded.

**64 connections** — both servers sustain 150 K rps cleanly; ringline stays
flatter under load:

| offered rps | rl-server p50 | rl-server p99 | tok-server p50 | tok-server p99 |
|------------:|:-------------:|:-------------:|:--------------:|:--------------:|
| 1 K | 0.57 ms | 1.22 ms | 0.64 ms | 1.22 ms |
| 10 K | 0.40 ms | 0.86 ms | 0.51 ms | 0.96 ms |
| 50 K | 0.46 ms | 0.96 ms | 0.45 ms | 1.02 ms |
| 100 K | 0.61 ms | 1.56 ms | 0.74 ms | 3.06 ms |
| 150 K | **0.92 ms** | **6.7 ms** | **1.82 ms** | **9.8 ms** |

**512 connections** — gap widens significantly above 50 K rps:

| offered rps | rl-server p50 | rl-server p99 | tok-server p50 | tok-server p99 |
|------------:|:-------------:|:-------------:|:--------------:|:--------------:|
| 1 K | 0.95 ms | 4.65 ms | 1.17 ms | 5.32 ms |
| 25 K | 0.47 ms | 2.26 ms | 0.51 ms | 1.30 ms |
| 50 K | **0.54 ms** | **3.55 ms** | **1.92 ms** | **4.57 ms** |
| 100 K | 1.71 ms | 5.88 ms | 2.51 ms | 6.52 ms |
| 150 K | 3.54 ms | 8.75 ms | 5.62 ms | 19.5 ms |

At 512 connections × 50 K rps, the tokio server p50 jumps to ~1.9 ms while
ringline holds at 0.54 ms. At 150 K rps ringline's p50 is ~1.6× lower and
p99 is ~2.2× lower.

### Open-loop latency vs. offered rate (16384 B) — honest picture

At large message sizes the servers converge. Using valid (unsaturated) points
only (≤ 25 K rps for 64 connections, ≤ 25 K rps for 512 connections):

| offered rps | rl-server p50 | tok-server p50 |
|------------:|:-------------:|:--------------:|
| 64 conn, 1 K | 0.47 ms | 0.73 ms |
| 64 conn, 5 K | 0.65 ms | 0.61 ms |
| 64 conn, 10 K | 0.70 ms | 0.44 ms |
| 64 conn, 25 K | 0.60 ms | 0.68 ms |

No consistent winner at 16384 B. Both servers saturate around 40–60 K ops/s
for 64 connections and ~25–30 K ops/s for 512 connections. For large-message
workloads the bottleneck is bandwidth and message processing cost, not
server-side connection handling — the choice of runtime does not matter.

### Summary

| scenario | recommendation |
|:---------|:---------------|
| Small/medium messages (≤ 4096 B), any connection count | ringline server: 1.1–1.5× higher throughput |
| Small messages under high load (>50 K rps) with many connections | ringline server: 1.6–3.5× lower p50 latency |
| Large messages (≥ 16384 B) at any load | servers equivalent — use either |
| Bandwidth-saturated workloads (65536 B) | tied; bottleneck is elsewhere |

---

## Test rig

| Item    | Value                                                          |
|:--------|:---------------------------------------------------------------|
| CPU     | `z1.n.small` (4 physical / 8 logical cores), SystemsLab-managed |
| Kernel  | Linux (SystemsLab managed, Debian)                            |
| Rust    | 1.96.0                                                         |
| Backend | io\_uring                                                       |
| Worker threads | 1 (single-threaded ringline + single-thread tokio current\_thread) |
| Bench harness | `cargo run --release -p ringline-benchmarks`             |
| Sample window | 5 s, after 2 s warmup, per (clients × size × combo)      |
| Latencies   | per-iter `Instant::now()` → `t0.elapsed()` recorded into in-process histograms |
| Servers     | `ringline → *` rows use a native ringline server; `* → tokio` rows hit a tokio/hyper/reqwest reference (see each section) |
| Re-run note | All single-machine tables regenerated on this `z1.n.small` after the TCP server fix + a `PortManager` bindability-probe hardening. Absolute numbers differ from the earlier Threadripper 3970X figures; the ringline-vs-reference ratios are the durable comparison. |

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

`ringline → ringline` is the **full ringline stack** — ringline client + a native
ringline `RinglineBuilder` echo server (`forward_recv_buf`). `tokio → tokio` is the
**full tokio stack** — tokio client + tokio current\_thread server. So this is a
runtime-vs-runtime comparison of both ends, not just the client.

> **Server fix note.** The `ringline → ringline` server used to be a tokio echo
> (a stale `// requires TLS setup` shortcut), so this table previously measured
> only the *client*. It is now a real ringline server, so ringline leads the
> whole matrix including 32 KiB — see history below for the before/after.

| Clients × Size | ringline → ringline | tokio → tokio | ringline vs tokio | p50 (ringline) | p99 (ringline) |
|:---|---:|---:|---:|---:|---:|
| 1c × 64 B   |  12.0 k |  9.3 k | **+29 %** | 81 µs | 118 µs |
| 1c × 512 B  |  12.1 k |  9.0 k | +34 % | 82 µs | 121 µs |
| 1c × 4 KiB  |  11.6 k |  8.9 k | +30 % | 84 µs | 129 µs |
| 1c × 32 KiB |  10.2 k |  8.6 k | +19 % | 95 µs | 145 µs |
| 10c × 64 B  | 119 k |  88 k | +35 % | 84 µs | 152 µs |
| 10c × 512 B | 115 k |  83 k | +39 % | 87 µs | 161 µs |
| 10c × 4 KiB |  99 k |  77 k | +28 % | 99 µs | 187 µs |
| 10c × 32 KiB |  53 k |  20 k | **+163 %** | 194 µs | 323 µs |
| 50c × 64 B  | 123 k |  86 k | +44 % | 349 µs | 709 µs |
| 50c × 512 B | 128 k |  88 k | +45 % | 331 µs | 669 µs |
| 50c × 4 KiB | 108 k |  79 k | +37 % | 398 µs | 826 µs |
| 50c × 32 KiB|  46 k |  20 k | **+127 %** | 902 µs | 1.91 ms |
| 200c × 64 B | 135 k |  88 k | **+54 %** | 1.36 ms | 2.95 ms |
| 200c × 512 B | 130 k |  88 k | +47 % | 1.41 ms | 3.08 ms |
| 200c × 4 KiB | 102 k |  82 k | +25 % | 1.77 ms | 3.90 ms |
| 200c × 32 KiB|  36 k |  26 k | +35 % | 5.09 ms | 9.75 ms |

With a real ringline server on both ends, **ringline leads tokio across the entire
matrix**, including the 32 KiB cells. The previous version of this table showed
ringline *trailing* by 4–17 % at 32 KiB — that was an artifact of pointing the
ringline client at a **tokio** server (the `ringline → ringline` server was
silently a tokio echo); the large-message gap was the tokio server's per-stream
`io::copy`, not ringline. The full-stack gap is widest at small messages under
concurrency (io_uring batching) and at 32 KiB / moderate concurrency, where the
tokio echo server collapses to ~20 k ops/s while ringline holds 46–53 k.

## UDP echo

| Clients × Size | ringline → ringline | tokio → tokio | ringline vs tokio | p50 (ringline) | p99 (ringline) |
|:---|---:|---:|---:|---:|---:|
| 1c × 64 B   |  13 k |  10 k | **+37 %** | 73 µs | 112 µs |
| 1c × 512 B  |  13 k |  10 k | +33 % | 74 µs | 118 µs |
| 1c × 4 KiB  |  13 k |  10 k | +31 % | 77 µs | 123 µs |
| 1c × 32 KiB |  11 k |   9 k | +34 % | 85 µs | 135 µs |
| 10c × 64 B  | 170 k | 102 k | **+67 %** | 54 µs | 126 µs |
| 10c × 512 B | 168 k | 101 k | +67 % | 55 µs | 123 µs |
| 10c × 4 KiB | 137 k |  86 k | +59 % | 68 µs | 141 µs |
| 10c × 32 KiB |  57 k |  59 k | −3 % | 122 µs | 240 µs |
| 50c × 64 B  | 202 k | 110 k | **+85 %** | 248 µs | 360 µs |
| 50c × 512 B | 192 k | 108 k | +78 % | 256 µs | 376 µs |
| 50c × 4 KiB | 142 k |  92 k | +56 % | 175 µs | 281 µs |
| 50c × 32 KiB|  53 k |  58 k | −8 % | 123 µs | 244 µs |
| 200c × 64 B | 201 k | 113 k | **+78 %** | 877 µs | 1.20 ms |
| 200c × 512 B | 191 k | 112 k | +71 % | 765 µs | 1.11 ms |
| 200c × 4 KiB | 148 k |  92 k | +61 % | 174 µs | 394 µs |
| 200c × 32 KiB|  52 k |  56 k | −6 % | 127 µs | 251 µs |

UDP is where ringline pulls farthest ahead — the 64–512 B rows lead tokio by **+67 % to +85 %** at 10–50 connections. The 32 KiB rows still trail slightly (−3 % to −8 %); with the bench's zero-allocation recv path in place (PR #186), the residual gap is the unavoidable userspace memcpy into ringline's send copy pool (tokio's `send_to` syscall reads userland memory directly). Both columns are a real ringline UDP server vs a tokio UDP server.

## Redis (GET against a synthetic RESP server)

Workload: each client loops `GET k`. The server is a tokio TCP listener speaking a hand-rolled RESP subset (responds `$<msg\_size>\r\n<msg\_size B>\r\n` to any GET). Both clients hit the same server — the only thing varying is the client runtime.

| Clients × Size | ringline-redis | tokio (hand-rolled RESP) | ringline vs tokio |
|:---|---:|---:|---:|
| 1c × 64 B   |  10 k |   9 k | **+13 %** |
| 1c × 4 KiB  |  10 k |   9 k | +8 % |
| 10c × 64 B  |  96 k |  86 k | +11 % |
| 10c × 512 B | 100 k |  84 k | +18 % |
| 50c × 64 B  | 100 k |  88 k | +13 % |
| 50c × 512 B |  97 k |  86 k | +13 % |
| 200c × 64 B | 102 k |  87 k | +17 % |
| 200c × 4 KiB|  92 k |  86 k | +8 % |

The hand-rolled tokio client uses fixed-size reads (it knows the response length up front); `ringline-redis::Client::get` walks the full RESP parser on every response. Despite that extra work, ringline-redis still leads in most cells, and the largest deficits are small.

## Memcache (GET against a synthetic text-protocol server)

Workload: each client loops `get k`. The server is a tokio TCP listener speaking memcache's text protocol — responds `VALUE k 0 <msg\_size>\r\n<msg\_size B>\r\nEND\r\n` to any GET, `STORED\r\n` to SET (with a body-aware parser), `DELETED\r\n` to DELETE. Both clients hit the same server.

| Clients × Size | ringline-memcache | tokio (hand-rolled) | ringline vs tokio |
|:---|---:|---:|---:|
| 1c × 64 B   |  10 k |   9 k | **+12 %** |
| 1c × 512 B  |  10 k |   9 k | +12 % |
| 1c × 4 KiB  |  10 k |   9 k | +11 % |
| 10c × 64 B  |  98 k |  87 k | +13 % |
| 10c × 512 B | 101 k |  87 k | +16 % |
| 10c × 4 KiB |  91 k |  83 k | +9 % |
| 50c × 64 B  | 105 k |  88 k | **+19 %** |
| 50c × 512 B | 102 k |  89 k | +15 % |
| 50c × 4 KiB |  95 k |  87 k | +9 % |
| 200c × 64 B | 102 k |  92 k | +11 % |
| 200c × 512 B |  92 k |  91 k | +2 % |
| 200c × 4 KiB |  92 k |  85 k | +9 % |

Same broad shape as the Redis numbers: ringline-memcache leads the hand-rolled tokio client across the board (+9 % to +19 %), widest at small-payload high-concurrency. `ringline-memcache::Client::get` and the tokio client both parse the variable-length memcache response.

## HTTP/1.1 (GET against a synthetic server)

Workload: each client loops `GET /` over a keep-alive connection. The server is a tokio TCP listener that recognises `\r\n\r\n` request termination and emits a pre-computed `HTTP/1.1 200 OK\r\nContent-Length: <msg\_size>\r\n...` response with a `msg\_size`-byte body. Both clients hit the same server.

The reference client is **reqwest** — the de-facto tokio HTTP client — built with `.http1_only().tcp_nodelay(true)` and one pooled connection per host. Both clients do real HTTP work: build a request via a builder, send it over a keep-alive connection, parse a structured response with status / headers / body. This is the apples-to-apples comparison; the earlier version compared against a hand-rolled byte loop that skipped parsing entirely.

| Clients × Size | ringline-http | reqwest | ringline vs reqwest |
|:---|---:|---:|---:|
| 1c × 64 B   |  10 k | 7.1 k | **+40 %** |
| 1c × 512 B  |  10 k | 7.1 k | +42 % |
| 1c × 4 KiB  | 9.5 k | 7.1 k | +34 % |
| 10c × 64 B  |  97 k |  25 k | **+280 %** |
| 10c × 512 B |  92 k |  24 k | +283 % |
| 10c × 4 KiB |  85 k |  24 k | +258 % |
| 50c × 64 B  |  97 k |  28 k | **+254 %** |
| 50c × 512 B | 102 k |  27 k | +283 % |
| 50c × 4 KiB |  92 k |  26 k | +258 % |
| 200c × 64 B | 102 k |  30 k | +239 % |
| 200c × 512 B | 102 k |  31 k | +228 % |
| 200c × 4 KiB |  92 k |  29 k | +216 % |

`ringline-http::HttpClient::get("/").send()` runs **3–4× the throughput** of `reqwest::Client::get(url).send()` on the same wire format and the same server once there is any concurrency (single-connection is +34–42 %). Both paths allocate a builder, encode the request, send over keep-alive, and parse a typed response — the gap is purely in what the runtimes and protocol stacks do underneath.

## HTTP/2 (GET against a synthetic TLS server)

Workload: each client loops `GET /` over a single multiplexed HTTP/2 connection. HTTP/2 is TLS-only in `ringline-http`, so the bench server is hyper + tokio-rustls + a self-signed cert generated at startup; both clients trust it explicitly via `add_root_certificate`. The reference client is reqwest built with `.http2_prior_knowledge().tcp_nodelay(true)` and one pooled connection per host — both sides do a real TLS handshake, build a structured request, parse a structured response.

| Clients × Size | ringline-http | reqwest | ringline vs reqwest |
|:---|---:|---:|---:|
| 1c × 64 B   | 7.9 k | 5.7 k | **+40 %** |
| 1c × 512 B  | 7.9 k | 5.7 k | +37 % |
| 1c × 4 KiB  | 7.6 k | 5.7 k | +33 % |
| 1c × 32 KiB | 5.8 k | 4.6 k | +26 % |
| 10c × 64 B  |  46 k |  27 k | **+69 %** |
| 10c × 512 B |  45 k |  26 k | +71 % |
| 10c × 4 KiB |  41 k |  23 k | +84 % |
| 10c × 32 KiB |  19 k |  13 k | +48 % |
| 50c × 64 B  |  54 k |  30 k | **+79 %** |
| 50c × 512 B |  51 k |  30 k | +72 % |
| 50c × 4 KiB |  46 k |  27 k | +70 % |
| 50c × 32 KiB|  20 k |  15 k | +37 % |
| 200c × 64 B |  51 k |  33 k | +54 % |
| 200c × 512 B |  51 k |  33 k | +56 % |
| 200c × 4 KiB | 41 k |  26 k | +58 % |
| 200c × 32 KiB|  20 k |  16 k | +30 % |

`ringline-http` HTTP/2 over TLS runs **1.3–1.8× the throughput** of reqwest doing the equivalent work, widening at moderate concurrency (10–50 c) where HTTP/2 multiplexing benefits the runtime's batching most. With the real ringline server and the TLS-drain fix (PR #189) in place, ringline now **leads at every cell including 200 c × 32 KiB** (+30 %) — the −15 % deficit that cell used to show is gone.

## QUIC (stream echo against a ringline server)

Workload: a single QUIC connection multiplexes `num\_clients` concurrent bidirectional streams. Each stream writes `msg\_size` bytes + FIN, reads the echoed `msg\_size` bytes, and is replaced by a fresh stream as soon as it completes — so there are always `num\_clients` streams in flight at steady state. The server is a ringline `AsyncEventHandler` that drives `ringline_quic::QuicEndpoint` from `on_udp_bind`; same TLS 1.3 + ALPN handshake against a self-signed cert as the HTTP/2 bench. Both clients hit this same server.

The tokio reference client is **quinn** — the de-facto tokio QUIC stack — also built on `quinn-proto`.

| Clients × Size | ringline-quic | quinn | ringline vs quinn |
|:---|---:|---:|---:|
| 1c × 64 B   | 9.6 k | 8.8 k | +8 % |
| 1c × 512 B  | 9.3 k | 9.0 k | +3 % |
| 1c × 4 KiB  | 7.4 k | 7.8 k | −5 % |
| 10c × 64 B  |  86 k |  69 k | **+24 %** |
| 10c × 512 B |  74 k |  65 k | +13 % |
| 10c × 4 KiB |  28 k |  32 k | −12 % |
| 50c × 64 B  | 114 k |  82 k | **+40 %** |
| 50c × 512 B |  96 k |  74 k | +29 % |
| 50c × 4 KiB |  31 k |  35 k | −9 % |
| 200c × 64 B | 122 k |  92 k | **+33 %** |
| 200c × 512 B | 111 k |  89 k | +24 % |
| 200c × 4 KiB |  31 k |  34 k | −10 % |

ringline-quic leads at small payloads (≤ 512 B) and at high concurrency × 64 B (up to +40 %), via `UdpCtx::recv_batch()` (see *Highlights*) which drains up to N queued datagrams per task poll. The 4 KiB rows still trail quinn by 5–12 %: there the bench is bottlenecked on the server-side body memcpy into the QUIC stream rather than the recv path.

## HTTP/3 (POST echo against a ringline server)

Workload: a single QUIC connection multiplexes `num\_clients` concurrent bidirectional HTTP/3 request streams. Each iteration is a `POST /echo` with an `msg\_size`-byte body; the server echoes the body back in a DATA frame with FIN. As soon as one request completes the client opens a replacement so there are always `num\_clients` requests in flight. The server is a ringline `AsyncEventHandler` driving `ringline_h3::H3Connection` on top of `ringline_quic::QuicEndpoint`. The ringline client uses the same stack from another worker task and wraps `send_request` + `send_data` in `QuicEndpoint::batch()` for GSO coalescing.

The tokio reference client is **`h3` + `h3-quinn`** — the canonical tokio HTTP/3 stack — running on quinn for the transport. Both clients hit the same ringline server and negotiate ALPN `h3` over TLS 1.3 against the same self-signed cert.

| Clients × Size | ringline-h3 | tokio (h3 + h3-quinn) | ringline vs tokio |
|:---|---:|---:|---:|
| 1c × 64 B   | 8.4 k | 8.2 k | +3 % |
| 1c × 512 B  | 8.3 k | 8.0 k | +4 % |
| 1c × 4 KiB  | 7.2 k | 6.9 k | +4 % |
| 1c × 32 KiB | 3.5 k | 3.6 k | −1 % |
| 10c × 64 B  |  62 k |  50 k | **+22 %** |
| 10c × 512 B |  56 k |  50 k | +13 % |
| 10c × 4 KiB |  34 k |  33 k | +3 % |
| 10c × 32 KiB | 8.1 k | 8.4 k | −4 % |
| 50c × 64 B  | 160 k |  62 k | **+158 %** |
| 50c × 512 B | 132 k |  56 k | **+134 %** |
| 50c × 4 KiB |  51 k |  39 k | +29 % |
| 50c × 32 KiB | 8.0 k | 8.3 k | −4 % |
| 200c × 64 B | 236 k |  62 k | **+281 %** |
| 200c × 512 B | 171 k |  63 k | **+170 %** |
| 200c × 4 KiB | 52 k |  44 k | +17 % |
| 200c × 32 KiB | 7.8 k | 11 k | −29 % |

ringline-h3 leads tokio across the small-payload zone (≤ 512 B by up to ~3.8× at 200 c) and **leads through 4 KiB at every concurrency**. The 32 KiB cells are within −1 % to −29 % (1–10 c is a tie) after **UDP GRO on the receive path**, on top of the single-batch drive and four earlier stacked changes:

  1. **Server-side response batching** (PR #191): `QuicEndpoint::batch()` around the H3 event-drain + `send_data_bytes(Bytes::from(body))`, collapsing per-response `drain_transmits` and a per-echo body memcpy.
  2. **`UdpCtx::recv_batch()` / `recv_batch_timed()`** (PR #193 / #195): drain up to N queued UDP datagrams per task poll, with the driver-captured rx timestamp threaded through for accurate RTT samples.
  3. **Payload-size-aware client topup + server response caps** (PR #197): bound the streams opened / responses echoed per loop iteration so neither side floods quinn-proto's send buffer with `num_clients × msg_size` bytes before recv drains the ACKs that grow CWND.
  4. **Single-batch per-iteration drive**: one `QuicEndpoint::batch()` across each loop's recv → process → send phase, so `poll_transmit` runs once per iteration and coalesces the backlog into max-size GSO super-packets instead of per-datagram dribbles (details below).
  5. **UDP GRO on recv** (`Config::udp_gro`): the kernel coalesces inbound datagrams so ringline pays one recvmsg + decrypt-dispatch per *batch* instead of per packet — the recv-side mirror of GSO (details below).

### Why the 32 KiB cells trailed: CPU, not congestion control

A focused profiling pass overturned the standing hypothesis (RTT jitter pinning quinn-proto's CWND). Three findings, in order:

  - **Not RTT/CC.** Instrumenting both ends via `QuicEndpoint::connection_stats()` showed smoothed RTT was statistically identical between the ringline-client and tokio-client runs against the *same* server (~400–750 µs). What differed was loss: driven by the ringline client the server's send-CWND pinned at ~150 KB with steady loss; driven by tokio it grew to ~500 KB loss-free.
  - **Not the recv buffer.** The loss tracked kernel `RcvbufErrors`, but the rig's `rmem_max` equals `rmem_default` (208 KB) — the socket is already at the ceiling. Raising both to 8 MB removed the loss entirely yet made ringline *slower* (4.7 k, down from ~6 k): the drops were acting as load-shedding for a drive that couldn't keep up.
  - **It's CPU.** Both ringline worker threads run at ~100 % CPU during the 32 KiB cells (the machine is otherwise ~68 % idle), and `perf` put ~20 % of CPU in `io_sendmsg`. The bench drove quinn-proto's `poll_transmit` once per *received datagram* (inside `handle_datagram`), each call with only an ACK or two queued — emitting 3–4-segment GSO buffers and ~10× the `sendmsg` syscalls of quinn's recvmmsg+GSO transmit path for the same bytes. The pinned CWND was a *symptom* of the CPU-bound drive, not the cause.

This matches the payload-size shape: at ≤ 512 B each request is ~1 packet, per-packet overhead is negligible, and ringline's batched single-task design wins big; at 32 KiB each request is ~22 packets each way, so packet-rate-driven syscall overhead dominates and saturates the core.

The fix is bench-level: hold a single `QuicEndpoint::batch()` across each loop iteration's whole recv → process → send-generation phase (on *both* client and server; the recv callback reaches `handle_datagram` through the guard's `DerefMut`). Inside a batch, `poll_transmit` is deferred to one pass at batch-drop time, coalescing the iteration's entire backlog into max-size GSO super-packets instead of per-datagram dribbles. GSO segments-per-`sendmsg` rose 3.4 → 6.6 and the 32 KiB cells jumped:

| Cell | per-datagram drain | single-batch drain | Δ |
|:---|---:|---:|---:|
| 50 c × 32 KiB  | 5.9 k | **7.6 k** | +29 % |
| 200 c × 32 KiB | 4.4 k | **7.0 k** | +59 % |

p99 at 200 c × 32 KiB fell from ~340 ms to ~55 ms. Smaller payloads improved too (50 c × 4 KiB +44 %, 200 c × 512 B +30 %, ≤ 512 B +4–14 %) with no regressions — fewer syscalls help at every size. Because the server change also speeds up the shared ringline server, the *tokio*-client column rose as well (its 32 KiB numbers went up too), which is why the gap narrows rather than closes.

**Is the gap an io\_uring artifact?** No — a `--features force-mio` (epoll backend) differential showed the ringline-client ÷ tokio-client ratio is essentially identical on both backends, so it's not a CQE-drain / batched-wakeup artifact. After the single-batch fix the residual gap was the ringline stack's remaining per-packet *receive* overhead versus quinn's recvmmsg/GRO — which the next change tackles directly.

### Closing the rest: UDP GRO on recv

The single-batch fix coalesced the *send* side (GSO); the receive side still paid one io_uring CQE + provided-buffer + `handle_datagram` (decrypt-dispatch) per ~1400 B datagram — ~160k/s at 32 KiB, enough to keep the worker core saturated. quinn avoids this with `UDP_GRO`, which the runtime now supports via `Config::udp_gro`: the kernel coalesces consecutive same-flow datagrams into one `recvmsg` delivery and reports the segment size in a control message; the runtime splits the coalesced payload back into individual datagrams transparently, so `recv_batch` / `recv_batch_timed` callbacks still fire once per datagram and quinn-proto is fed exactly as before. On this host GRO coalesces 2–10 segments per delivery at 32 KiB.

GRO is a per-endpoint opt-in (`udp_gro`, default off) because a coalesced datagram is up to ~64 KiB and the recv buffer must be sized to hold it, and because the kernel's coalescing adds a little latency that *regresses* tiny high-concurrency payloads (64–512 B lost ~20 % when GRO was forced on globally) even as it lifts bulk flows. The bench therefore enables it only for `msg_size >= 4 KiB`, the same per-workload choice a real app would make. Impact on the large-payload cells, on top of the single-batch drive:

| Cell | single-batch | + GRO | tokio | gap: was → now |
|:---|---:|---:|---:|:---|
| 10 c × 32 KiB | 8 k | **10.6 k** | 10.5 k | −15 % → **+1 %** |
| 50 c × 32 KiB | 7.6 k | **10.1 k** | 11.0 k | −20 % → −9 % |
| 200 c × 32 KiB | 7.0 k | **9.9 k** | 13 k | −38 % → −25 % |
| 50 c × 4 KiB | 52 k | **65 k** | 57 k | −1 % → **+14 %** |
| 200 c × 4 KiB | 50 k | **67 k** | 61 k | −12 % → **+9 %** |

The 4 KiB cells flipped from trailing to leading; the 32 KiB gap roughly halved again (and 10 c is now a tie). Small-payload cells are unchanged (GRO off there). The remaining 32 KiB deficit narrows but doesn't vanish because the same GRO-enabled server also speeds up the tokio-client column (tokio's quinn already used GRO; now both receivers do). Implemented for both the io_uring and mio backends (`backend::udp_gro`); connected UDP sockets are GRO-blind (they use the plain `recv` path with no control message). What's left is the ringline client's residual single-thread send/scheduling overhead versus quinn's per-stream-task design — a structural difference, not a tunable.

## Highlights & history

### `feat(runtime): UDP GRO on the receive path (Config::udp_gro)`

The single-batch drive coalesced the send side (GSO); the receive side still paid one io_uring CQE + provided-buffer + `handle_datagram` per ~1400 B datagram (~160k/s at 32 KiB), keeping the worker core saturated. quinn avoids this with `UDP_GRO`. New runtime capability `Config::udp_gro` (default off): `setsockopt(SOL_UDP, UDP_GRO)` on bound UDP sockets, reserve a control region on the recvmsg path, parse the `UDP_GRO` cmsg for the segment size, and split the coalesced payload back into individual datagrams at drain time — so `recv_batch` / `recv_batch_timed` callbacks still fire once per datagram (no consumer changes; quinn-proto is fed exactly as before). `PendingUdpDatagram` carries a `segment_size`; the shared drain loop fans each entry out per-segment, with the kernel-buffer bid released once after the whole entry. Implemented on both backends (io_uring multishot recvmsg with a control region; mio via `recvmsg`); shared cmsg parsing lives in `backend::udp_gro`.

Opt-in because a coalesced datagram is up to ~64 KiB (the recv buffer must be sized to hold it, validated at startup) and because coalescing adds latency that regresses tiny high-concurrency payloads — 64–512 B dropped ~20 % when GRO was forced on globally. The H3 bench enables it only for `msg_size >= 4 KiB`.

| Cell | before (single-batch) | after (GRO) | Δ |
|:---|---:|---:|---:|
| 10 c × 32 KiB  | 8 k | **10.6 k** | +33 % |
| 50 c × 32 KiB  | 7.6 k | **10.1 k** | +33 % |
| 200 c × 32 KiB | 7.0 k | **9.9 k** | +41 % |
| 50 c × 4 KiB   | 52 k | **65 k** | +25 % |
| 200 c × 4 KiB  | 50 k | **67 k** | +34 % |

The 4 KiB cells flipped from trailing tokio to leading it (+9–14 %); the 32 KiB gap roughly halved (10 c now a tie, 50 c −9 %, 200 c −25 %). ≤ 512 B cells unchanged (GRO off). On this host GRO coalesces 2–10 segments per delivery at 32 KiB. Confirmed end-to-end on both backends; `cargo test --all` and clippy pass with and without `--features force-mio`.

### `perf(bench/http3): single-batch per-iteration drive — defer transmits to one GSO flush`

The 32 KiB H3 cells trailed tokio by 31–49 %. The standing theory was RTT jitter pinning quinn-proto's CWND; instrumentation refuted it. Driving both ends through `QuicEndpoint::connection_stats()`, smoothed RTT was identical to tokio (~400–750 µs) against the same server; the difference was loss, and the loss tracked kernel `RcvbufErrors`. But the rig's `rmem_max` already equals `rmem_default` (208 KB), and raising both to 8 MB *removed* the loss while making ringline **slower** (the drops were load-shedding). The real cause was CPU: both ringline worker threads ran at ~100 % (machine ~68 % idle), with ~20 % of CPU in `io_sendmsg`. The bench called `handle_datagram` once per received datagram, and each call ran quinn-proto's `poll_transmit` with only an ACK queued — emitting 3–4-segment GSO buffers and ~10× the `sendmsg` syscalls of quinn's batched transmit path.

Fix: wrap each loop iteration's recv → process → send-generation in one `QuicEndpoint::batch()` (both client and server). The recv callback reaches `handle_datagram` through the guard's `DerefMut`, so transmit generation is suppressed until the guard drops, then runs once and coalesces the iteration's whole backlog into max-size GSO. Segments-per-`sendmsg` rose 3.4 → 6.6.

| Cell | before | after | Δ |
|:---|---:|---:|---:|
| 50 c × 32 KiB  | 5.9 k | **7.6 k** | +29 % |
| 200 c × 32 KiB | 4.4 k | **7.0 k** | +59 % |
| 50 c × 4 KiB   |  36 k |  52 k | +44 % |
| 200 c × 512 B  | 159 k | 206 k | +30 % |
| ≤ 512 B cells  | — | — | +4–14 % |

p99 at 200 c × 32 KiB fell ~340 ms → ~55 ms. No regressions at any size. The gap to tokio at 32 KiB narrowed to −20 % (50 c) / −38 % (200 c); the remainder is the ringline client stack's per-iteration syscall overhead versus quinn's recvmmsg/GRO + sendmmsg/GSO — a runtime-level batching question, not a bench knob. Bumping `max_transmit_datagrams` past the default 10 gave no further gain (and ≥ 64 re-triggered the send-burst self-DoS).

### `perf(bench/http3): interleave send-generation with recv (client topup + server response caps)`

Both sides of the H3 bench had the same self-DoS bug at large payloads: generating a tick's worth of stream work all at once, dumping `num_clients × msg_size` bytes into quinn-proto's send buffer before the recv side drained the ACKs that grow the connection's CWND. quinn-proto's cubic CC mistook the buffer pressure for the network ceiling and pinned CWND at ~150 KB. The fix on both sides is the same shape tokio's per-stream-task design gets implicitly: spread send-generation across many loop iterations, interleaved with recv.

**Client topup cap** (PR #197): cap streams opened per loop iteration at `max(1, 32 KiB / msg_size)`. One stream per tick at 32 KiB, ~8 at 4 KiB, unbounded at ≤ 512 B.

**Server response cap** (this PR): the server echoing all completed requests' bodies in one event-drain is the mirror-image bug — it floods the *server's* send buffer and stalls processing of the ACKs growing the server's CWND. Same payload-aware cap on responses generated per loop iteration. This was the larger of the two effects.

| Bench cell | baseline | + client cap | + server cap | total Δ |
|:---|---:|---:|---:|---:|
| 50 c × 32 KiB  | 1.4 k | 4.2 k | **6.1 k** | **+335 %** |
| 200 c × 32 KiB | 1.0 k | 2.5 k | **4.3 k** | **+330 %** |
| 10 c × 4 KiB   |  31 k |  35 k |  35 k | +13 % |
| 200 c × 512 B  | 158 k | 167 k | 167 k | +6 % |
| smaller cells  | — | — | — | within run-to-run noise |

p99 latency at 50 c × 32 KiB also dropped from ~120 ms to ~17 ms with the server cap — the bursty send pattern had been producing long tail stalls.

Override the heuristics with `RINGLINE_BENCH_TOPUP_CAP=<n>` (client) and `RINGLINE_BENCH_RESP_CAP=<n>` (server) for experimentation.

The general lesson, applicable to any ringline app driving QUIC-style protocols: at payload sizes where each stream op carries significant data, generate a bounded amount of send work per event-loop iteration and let recv interleave — don't batch all of it into one tick.

### Investigation: SO_TIMESTAMPING for kernel-accurate rx times (didn't help)

Follow-up to `recv_batch_timed`. The CQE-drain timestamp threaded through in PR #195 still lags actual kernel arrival by the io_uring CQE generation + `submit_and_wait` wake path. The natural next step was to read the kernel's own software timestamp via `SO_TIMESTAMPING` + `SCM_TIMESTAMPING` cmsg and surface *that* as `recv_at`.

Built it end to end: setsockopt at UDP socket setup, `msg_controllen = 64` on the recv msghdr template, cmsg parsing in `handle_recv_msg_udp`, wall-clock-to-`Instant` conversion via `SystemTime::now()` delta. Confirmed end-to-end: control regions arrived with the expected size, timestamps parsed to plausible CLOCK_REALTIME nanoseconds-since-epoch.

Then A/B'd at the H3 32 KiB cell, five runs each side:

| Cell | CQE-drain TS (PR #195) | Kernel TS | Δ |
|:---|---:|---:|---:|
| 50 c × 32 KiB, mean | 1.12 k | 1.02 k | −9 % |
| 50 c × 32 KiB, range | 1075–1178 | 819–1280 | wider |
| 200 c × 32 KiB, mean | 1.36 k | 1.25 k | −8 % |
| 200 c × 32 KiB, range | 1229–1485 | 1126–1382 | wider |

Loss rate, CWND distribution, and RTT shape are statistically identical between the two modes — the kernel-accurate timestamp doesn't change quinn-proto's congestion-control state, it just adds per-packet overhead (cmsg parse + `SystemTime::now()` clock read + arithmetic). The earlier "+70 %" 200 c × 32 KiB result was within-run noise; later runs reverted to the same ~1.36 k mean as the CQE-drain baseline.

**Why kernel timestamps don't actually help:** quinn-proto's RTT machinery uses the receiver's `recv_at` to compute the *ack_delay* it reports back to the sender (so the sender can subtract local processing time from its RTT measurement). The CQE-drain timestamp correctly charges quinn-proto's ack_delay with our kernel→drain latency — that *is* processing time, and the sender's CC algorithm expects to see it included. Moving to a true kernel-arrival timestamp removes that legitimate charge from ack_delay, but the wire RTT itself doesn't change, so the sender's smoothed RTT just skews slightly tighter without any behavioral improvement.

The remaining ~85 % 32 KiB gap behind tokio is something else entirely. Not shipping the SO_TIMESTAMPING patch; recording the investigation here so we don't reach for it again.

### `perf(runtime): UdpCtx::recv_batch_timed() — feed actual arrival time to protocol drivers`

A follow-up to the 32 KiB investigation. The cubic CC in quinn-proto reads RTT measurements from the `now: Instant` we pass to `handle_datagram(now, ...)`. With the prior `recv_batch` callback, that `now` was `Instant::now()` at the moment our bench code ran the callback — which lags actual arrival by the executor wake + task poll path (measured at avg 65 µs, max 400 µs at 50 c × 32 KiB).

That gap was being charged to the network: quinn-proto's smoothed RTT inflated, cubic interpreted the variance as congestion, CWND oscillated around ~150 KB instead of growing. Switching to BBR moves the 50 c × 32 KiB cell from 1.1 k → 3.0 k ops/s but regresses 4 KiB cells 10–20 %, and Tokio also regresses at 32 K with BBR — so BBR is *not* a strict win on localhost. The structurally correct fix is feeding accurate timestamps to the CC instead.

New API: `UdpCtx::recv_batch_timed(max, |data, peer, recv_at| {...})`. The `recv_at` is captured in the io_uring CQE handler (or in the mio `recv_from` poll), before any user-space dispatch latency. Same zero-copy, single-consumer, configurable `max` as `recv_batch`.

Impact on the bench cells, vs `recv_batch` baseline (PR #193):

| Bench | Cell | Before | After | Δ |
|:---|:---|---:|---:|---:|
| HTTP/3, ringline → ringline | 50 c × 32 KiB | 1.1 k | 1.4 k | +27 % |
| HTTP/3, ringline → ringline | 200 c × 32 KiB | 1.0 k | 1.3 k | +30 % |
| HTTP/3, ringline → ringline | 50 c × 512 B  | 155 k | 163 k | +5 % |
| HTTP/3, ringline → ringline | 200 c × 64 B  | 297 k | 304 k | +2 % |
| Other cells | various | — | — | within run-to-run noise |

The remaining 32 KiB gap (still ~85 % behind tokio) comes from latency *before* `recv_at` is captured — kernel scheduling and io_uring CQE generation that's invisible in user space. Closing that needs `SO_TIMESTAMPING` + cmsg parsing on every `recvmsg`, which is significantly more work.

### Investigation: 32 KiB H3 cell — what we found, what to ship next

The 50 c × 32 KiB and 200 c × 32 KiB rows trail tokio by ~6×. A focused profile + instrumentation pass ruled out the obvious suspects and pointed at a structural issue:

  - **Not CPU-bound.** Worker threads idle at ~26 % each during the run; there is ample headroom to do more work.
  - **Kernel UDP socket buffer is tight on this rig** (`net.core.rmem_max` = 208 KB). Both columns produce kernel `RcvbufErrors`, but tokio produces ~10× *more* drops than ringline and still wins by 6× — drops aren't the gap.
  - **quinn-proto reports 1–2 % loss** during the ringline column even on localhost. RTT samples range 400 µs – 1.2 ms (large variance). Together these keep CWND oscillating around ~150 KB — with 50 streams × 32 KiB in flight per request batch, only ~150 KB of body data can ever be on the wire at once.
  - **Iter-gap histogram on the bench client loop** shows ~15 % of iterations sit idle for 1–5 ms between wakes — the natural burst-then-idle shape of a single QUIC connection under flow control. Adaptive sleep using `next_timer_deadline()` collapsed that bucket from ~1500 to ~60 occurrences per 2 s window but did not move throughput materially — the idle time was a *symptom* of the bursty arrival pattern, not the cause.

So the gap isn't "ringline wakes too slowly" — wakes are fast. It's that ringline-quic's CWND can't grow because something in the pipeline produces RTT measurements that quinn-proto's cubic interprets as congestion. Tokio's quinn endpoint, hitting the same ringline server, doesn't trigger that same feedback loop. The fix lives inside the QUIC layer (loss/RTT detection thresholds, or a less variance-sensitive controller like BBR), not in the runtime or the bench.

Two new public APIs landed during the investigation, both small enough to ship as building blocks even though they don't move the bench by themselves:

  - **`QuicEndpoint::connection_stats(conn) -> ConnectionStats`** — quinn-proto's full stats snapshot (RTT, CWND, frame counts, loss). Required for the diagnostic instrumentation above; useful for any caller that wants to react to congestion-control state or build observability into a long-running endpoint.
  - **`QuicEndpoint::next_timer_deadline() -> Option<Instant>`** — earliest pending QUIC timer across all live connections. The bench's adaptive-sleep loop uses this to wake on the right tick instead of polling every 1 ms; for users with non-bursty workloads, this is a real latency-floor win.

`ConnectionStats`, `PathStats`, `FrameStats`, and `UdpStats` are now re-exported from `ringline_quic::` for ergonomic access. The 32 KiB cells themselves did not improve in this pass — closing that gap is queued as future QUIC-layer work.

### `perf(runtime): UdpCtx::recv_batch() drain-style UDP recv`

io_uring's multishot recv pushes one CQE per UDP datagram; the prior `recv_from()` / `with_datagram()` futures dequeued one entry per poll, so at high pps the task woke N times to drain N datagrams. Per-packet executor wake + future-poll overhead capped throughput long before the kernel ran out of CQE capacity. Tokio's quinn endpoint avoids the equivalent via `recvmmsg` (multi-datagram per syscall); io_uring doesn't expose multi-datagram-per-CQE semantics, but the user-space queue accumulated datagrams between event-loop iterations regardless — what we needed was a future that drains that queue.

New API: `UdpCtx::recv_batch(max, |data, peer| {...})` resolves once at least one datagram is available and drains up to `max` queued datagrams in a single poll. Same zero-copy semantics as `with_datagram` (each invocation borrows the kernel buffer for its scope, bid released right after).

`max` is the lever between batching efficiency and ACK-pacing latency. Larger values amortise more wake overhead; smaller values keep the loop's `poll_send` call site running often enough that QUIC ACK / `MAX_STREAM_DATA` frames don't queue up behind the recv pile. The QUIC + H3 benches use `max = 8`.

| Bench | Cell | Before | After | Δ |
|:---|:---|---:|---:|---:|
| QUIC echo, ringline → ringline | 10 c × 64 B   |  98 k | **129 k** | **+32 %** |
| QUIC echo, ringline → ringline | 50 c × 64 B   | 111 k | **155 k** | **+40 %** |
| QUIC echo, ringline → ringline | 50 c × 512 B  |  95 k | 123 k | +29 % |
| HTTP/3, ringline → ringline    | 50 c × 512 B  | 104 k | **155 k** | **+49 %** |
| HTTP/3, ringline → ringline    | 200 c × 512 B | 136 k | 160 k | +18 % |
| HTTP/3, ringline → ringline    | 200 c × 4 KiB |  34 k |  39 k | +13 % |

The 32 KiB rows didn't move (and slightly regressed at extreme concurrency before tuning `max` down to 8). Those cells aren't gated by per-packet overhead — they're gated by ACK pacing through a single QUIC connection with deep send credit windows. That's a `ringline-quic` concern, not a runtime one.

### `perf(quic): batched stream operations for GSO coalescing` (PR #190)

`ringline-quic`'s `stream_send` / `stream_finish` / `open_bi` /
related entry points each called the internal `drain_transmits`
inline. That made quinn-proto's `poll_transmit` produce ~one UDP
datagram per stream operation, so a tight loop opening N streams
and writing a request on each would emit ~3N small `sendmsg`
syscalls instead of one GSO segment.

Profiling the bench at 50 c × 512 B showed **~21 % of CPU in the
kernel UDP sendmsg path**; instrumenting the bench's send loop
confirmed that 95 %+ of outgoing packets were non-GSO.

New API: `QuicEndpoint::batch()` returns a `BatchGuard` that
suppresses per-op drains for the duration of the scope. On drop
the guard performs one `flush()`, giving quinn-proto a single
opportunity to coalesce the batched work into a GSO segment that
runtime adapters with `UDP_SEGMENT` support can hand to the
kernel in one syscall.

| Bench (QUIC, ringline → ringline) | Before | After | Δ |
|:---|---:|---:|---:|
| 200c × 64 B  | 139 k | **162 k** | **+17 %** |
| 200c × 512 B | 139 k | 148 k | +6 % |
| 200c × 4 KiB |  34 k |  38 k | +13 % |

Below 200 c the batch isn't big enough to fill a GSO segment so
the underlying work is unchanged; cells at 1 c / 10 c / 50 c
moved within run-to-run noise.

### `fix(tls): drain ciphertext fully on recv` (PR #189)

`feed_tls_recv` called `Connection::read_tls` exactly once per CQE
and then drove the state machine. rustls's `read_tls` reads from
the supplied `io::Read` in 4 KiB chunks bounded by its own internal
input buffer; if the buffer can't be drained without first
producing plaintext (which it can't until we drain it via
`reader()`), the call stops mid-slice and we silently drop the
trailing bytes. For HTTP/2 over TLS this manifested as an
indefinite hang at message sizes ≥ 4 KiB — the response's
ciphertext arrived in one CQE but only the first 4 KiB ever made
it into rustls.

Fix: feed in a loop. After each `read_tls` call, run
`process_new_packets` and drain plaintext via `reader().read()`
so rustls has buffer room for the next chunk. Loop until the
cursor is fully consumed or `read_tls` returns 0.

| Bench (ringline → tokio) | Before | After |
|:---|---:|---:|
| HTTP/2 1c × 4 KiB | hung at 0 ops/s | 22 k |
| HTTP/2 10c × 4 KiB | hung at 0 ops/s | 68 k |
| HTTP/2 50c × 32 KiB | hung at 0 ops/s | 26 k |

Smaller sizes are unaffected: TCP/UDP echo, redis, memcache, and
HTTP/1.1 numbers all moved within run-to-run noise (the bug only
triggers when a single TLS record's ciphertext exceeds the rustls
internal read buffer, which in practice means HTTP/2 large-body
responses).

### `perf(bench): zero-allocation recv in UDP echo server` (PR #186)

The bench's ringline UDP server used `udp.recv_from().await`, which
allocates a fresh `Vec<u8>` for every datagram. At 32 KiB messages
this cost ~10-20 % throughput vs the tokio server (which echoes
out of a single stack buffer).

Switched the bench server to `udp.with_datagram(...)` — the
callback exposes the kernel-provided recv buffer directly, and the
common case calls `send_to` inside the closure so the only
userspace copy is the unavoidable one into ringline's send copy
pool. A reusable scratch `Vec` handles the rare retry-on-pool-
exhausted path.

| Bench (UDP, ringline → ringline) | Before | After | Δ |
|:---|---:|---:|---:|
| 10c × 32 KiB  | 61 k | 73 k | **+20 %** |
| 50c × 32 KiB  | 56 k | 72 k | +28 % |
| 200c × 32 KiB | 51 k | 62 k | +21 % |

Smaller sizes unchanged within noise. The residual gap to tokio at
32 KiB is now the send-pool memcpy; closing it further would need a
new `forward_recv_buf`-style zero-copy UDP send path on `UdpCtx`.

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

- **Single ringline worker.** These single-machine numbers are for `worker.threads = 1`. Multi-worker scaling is exercised separately in the distributed section's *Worker scaling & CPU efficiency*.
- **Localhost only.** All servers and clients run on the same box. Real network latency would shift the relative shapes.
- **Server semantics per table.** TCP and UDP `ringline → ringline` rows are a native ringline server vs a tokio server (both ends). QUIC and HTTP/3 run a native ringline server hit by ringline-quic/ringline-h3 vs quinn/h3-quinn clients. Redis, memcache, HTTP/1.1, and HTTP/2 are *client-vs-client* comparisons — ringline-redis/-memcache/-http vs a hand-rolled tokio client / reqwest — against a shared synthetic tokio/hyper server (there is no ringline server in those by design). The TCP server used to be a tokio echo by mistake; that is fixed (see history).
- **Single-machine harness is flaky for huge back-to-back sweeps.** Running all protocols in one process churns hundreds of server binds; `PortManager` now probes port bindability to avoid silently-dead cells, and the regeneration ran each protocol in its own process for isolation.
- **Redis bench server is synthetic.** It does not implement a real Redis storage layer; the response size is fixed by `msg_size`. The numbers are an upper bound on what the wire+parser combo can do, not what a real Redis backend would deliver.
- **`ringline-momento` and gRPC bench stubs are still TODO.** `cargo run -p ringline-benchmarks --only momento,grpc` currently returns `0 ops/s` for those — they're not measured here.
- **Numbers reflect what's available to a single user-space process.** Under load from other tenants, especially on cloud VMs, ranks can flip.

## Updating this file

When you ship a performance-relevant change:

1. Rerun the matrix on the same rig (or note the rig).
2. Update the affected table cells in-place.
3. Add a row to *Highlights & history* with the PR number, the impacted cells, and the before/after numbers.
4. If a regression is unavoidable, document it here rather than silently pushing.
