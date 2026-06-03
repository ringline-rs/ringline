# TCP Systemslab Experiments — Design Spec

**Date:** 2026-05-26  
**Status:** Approved

## Motivation

All prior ringline benchmarks (`BENCHMARKS.md`) ran loopback — client and server on the same host sharing the kernel network stack. This hides real-world effects: NIC interrupt coalescing, IRQ affinity, send/recv coalescing payoff, and actual cache pressure from two processes competing for CPU. The lab now has dedicated PF ports on a multi-port x710 10GbE NIC, one port per VM, enabling true wire-level measurements.

## Goals

1. **Throughput ceiling** — maximum requests/sec on 10GbE with real wire latency across the 4-runtime combo matrix.
2. **Latency distribution** — p50/p99/p999 under various load levels and message sizes.
3. **Saturation curve** — offered-rate sweep to find where latency blows up and how gracefully each runtime sheds load.

## Cluster Topology

| Role   | Tag          | Count | Hardware                        |
|:-------|:-------------|:-----:|:--------------------------------|
| Server | `z1.n.small` | 2     | 4c/8t, dedicated x710 NIC port  |
| Client | `z2.n.small` | 2     | 4c/8t, dedicated x710 NIC port  |

`$SERVER_ADDR` is injected automatically by systemslab into the client job's environment.

## File Structure

```
experiments/
  tcp-closed-loop.toml   # closed-loop throughput + latency matrix
  tcp-open-loop.toml     # open-loop saturation sweep (submitted after reviewing closed-loop)
```

## Experiment 1: Closed-Loop (`tcp-closed-loop.toml`)

### Matrix

```toml
[matrix]
server_runtime = ["ringline", "tokio"]
client_runtime = ["ringline", "tokio"]
clients        = ["1", "10", "50", "200"]
msg_size       = ["64", "512", "4096", "32768"]
```

**Total runs:** 64 (2 × 2 × 4 × 4), each independent, fully parallel up to cluster capacity.

### Fixed Parameters

```toml
[params]
ringline_repo    = "https://github.com/brayniac/ringline"
ringline_version = "main"
port             = "7878"
server_workers   = "8"
client_threads   = "8"
warmup_duration  = "3"   # seconds
test_duration    = "10"  # seconds
```

### Per-Run Job Structure

Two jobs per run (`server` on `z1.n.small`, `client` on `z2.n.small`), coordinated with two barriers:

```
server job (z1.n.small)               client job (z2.n.small)
─────────────────────────             ─────────────────────────
build ringline-bench                  build ringline-bench  (parallel)
system tuning
start bench-server (background)
wait-for-server (nc readiness loop)
  ── barrier: server-ready ─────────── barrier: server-ready
                                      verify connectivity (nc loop)
                                      run bench-client → results.json
                                      upload_artifact results.json
  ── barrier: benchmark-complete ───── barrier: benchmark-complete
print server socket stats
```

### Build Step (both jobs)

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone {ringline_repo} /tmp/ringline
cd /tmp/ringline && git checkout {ringline_version}
cargo build --release -p ringline-bench
sudo cp target/release/bench-server /usr/local/bin/bench-server
sudo cp target/release/bench-client /usr/local/bin/bench-client
```

Building only `ringline-bench` (not the full workspace) keeps build time short. Both jobs build in parallel, so client build does not add wall-clock time.

### System Tuning (server job)

```bash
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo fuser -k {port}/tcp 2>/dev/null || true
ulimit -n 500000
```

### Server Step

```bash
bench-server \
  --runtime {server_runtime} \
  --addr 0.0.0.0:{port} \
  --workers {server_workers}
```

Run with `background = true`.

### Client Step

```bash
bench-client \
  --runtime {client_runtime} \
  --addr $SERVER_ADDR:{port} \
  --clients {clients} \
  --msg-size {msg_size} \
  --warmup {warmup_duration} \
  --duration {test_duration} \
  --threads {client_threads}
```

Output: JSON to stdout, captured and written to `results.json`, then uploaded as an artifact.

### Artifact Naming

```toml
name = "ringline-tcp {server_runtime}s/{client_runtime}c {clients}conn {msg_size}B"
```

One `results.json` artifact per run, self-describing.

## Experiment 2: Open-Loop (`tcp-open-loop.toml`)

Submitted after reviewing closed-loop results to confirm throughput ceiling before choosing rate sweep bounds.

### Matrix

```toml
[matrix]
server_runtime = ["ringline", "tokio"]
client_runtime = ["ringline", "tokio"]
offered_rate   = ["50000", "100000", "200000", "500000", "1000000", "2000000"]
msg_size       = ["64", "4096"]
```

**Total runs:** 48 (2 × 2 × 6 × 2).

### Additional Fixed Parameters

```toml
clients      = "200"
max_inflight = "64"
```

### Client Step (open-loop variant)

```bash
bench-client \
  --runtime {client_runtime} \
  --addr $SERVER_ADDR:{port} \
  --clients {clients} \
  --msg-size {msg_size} \
  --warmup {warmup_duration} \
  --duration {test_duration} \
  --threads {client_threads} \
  --open \
  --rate {offered_rate} \
  --max-inflight {max_inflight}
```

## Comparison With Loopback Baseline

The JSON artifact fields (`ops_per_sec`, `p50_ns`, `p99_ns`, `p999_ns`) match what `BENCHMARKS.md` records. After both experiments complete, update `BENCHMARKS.md` with a new "Real network (x710 10GbE)" section alongside the existing loopback numbers.

## Out of Scope

- UDP, QUIC, HTTP/1.1, HTTP/2, HTTP/3, Redis, Memcache — future experiments following the same pattern.
- Multi-server fan-in topology.
- NUMA pinning / IRQ affinity tuning — possible follow-up if results show unexpected variance.
