# ringline

**Thread-per-core async I/O with an io_uring backend for Linux and a portable
Mio backend.**

ringline is a thread-per-core I/O framework. It provides an async/await API
(`AsyncEventHandler`) on a single-threaded executor with no work-stealing.

## What ringline is

- An io_uring backend that exploits advanced kernel features: TCP and Unix
  receives directly into a per-connection buffer (with `tls-buffered`, TLS
  receives into a pooled worker buffer), ring-provided buffers for UDP,
  SendMsgZc (zero-copy send), fixed file table
- A Mio backend for macOS and other Unix targets, for Linux kernels older
  than 6.1 (automatic build-time fallback), and for Linux builds using
  `force-mio`
- Thread-per-core with CPU pinning — no work-stealing, no task migration

## What ringline is NOT

- A Tokio replacement (different abstractions, not API-compatible)
- A general-purpose task scheduler (all tasks are `!Send`, pinned to cores)

## Quick Start

```rust
use ringline::{AsyncEventHandler, Config, Connection, ParseResult, RinglineBuilder};

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx.with_data(|data| {
                    tx.send_nowait(data).ok();
                    ParseResult::Consumed(data.len())
                }).await;
                if n == 0 { break; }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self { Echo }
}

fn main() -> Result<(), ringline::Error> {
    let config = Config::default();
    let (_runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:7878".parse().unwrap())
        .launch::<Echo>()?;
    for h in handles { h.join().unwrap()?; }
    Ok(())
}
```

## Architecture

For the code-derived runtime and request lifecycle diagrams, see
[Architecture](docs/architecture.md). For the technology tradeoffs behind the
Linux backend, see [Why consider io_uring?](docs/io-uring-primer.md); for the
counted syscalls and copies per request on each backend, backed by measurement,
see [Syscalls and copies, counted](docs/syscalls-and-copies.md).

The io_uring backend has this worker-local shape:

```
                      ┌─────────────────────────────┐
                      │        Acceptor Thread       │
                      │   blocking accept4() loop    │
                      └──────────┬──────────────────┘
                                 │ round-robin
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
   ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
   │  Worker 0   │       │  Worker 1   │       │  Worker N   │
   │ (CPU pinned)│       │ (CPU pinned)│       │ (CPU pinned)│
   │             │       │             │       │             │
   │  io_uring   │       │  io_uring   │       │  io_uring   │
   │  event loop │       │  event loop │       │  event loop │
   │             │       │             │       │             │
   │  Executor   │       │  Executor   │       │  Executor   │
   │  (futures)  │       │  (futures)  │       │  (futures)  │
   └─────────────┘       └─────────────┘       └─────────────┘
```

Each worker thread owns its backend driver, executor, connection table, and
handler instance. On the io_uring backend, each worker also owns:

- A dedicated **io_uring** instance (SQ + CQ)
- A **ring-provided buffer pool** for UDP receives (kernel selects buffers at completion time); a plaintext TCP or Unix connection receives into its own accumulator, and a TLS connection into its TLS engine's ciphertext buffer
- A **send copy pool** for small sends and a **send slab** for scatter-gather zero-copy sends
- A **fixed file table** for O(1) fd lookups (no per-syscall fd table traversal)

## io_uring Features Used

| Feature | Purpose |
|---------|---------|
| One-shot recv into the connection's buffer | TCP and Unix receives, plaintext and TLS, armed when a read parks — no copy from a shared buffer (with `tls-buffered`, TLS receives into a pooled buffer that `read_tls` copies from) |
| Ring-provided buffers | Kernel-managed recv buffer pool for UDP — kernel picks buffer at completion time |
| Multishot recv | UDP — one SQE, many completions |
| SendMsgZc | Zero-copy scatter-gather send — kernel DMAs directly from app buffers |
| Fixed file table | Direct descriptors — no per-syscall fd table lookup |
| IO_LINK chains | Atomic multi-step operations (connect + timeout) |
| COOP_TASKRUN (not with SQPOLL) | Reduced context switches |
| SINGLE_ISSUER | Lock-free kernel-side optimizations |

## Key Types

| Type | Description |
|------|-------------|
| `AsyncEventHandler` | Trait: `on_accept(Connection) -> Future` — one task per connection |
| `Connection` | An owned connection: `send()`, `send_nowait()`, `with_data()`; `split()` gives `SendHalf` and `RecvHalf` |
| `ParseResult` | Closure return type: `Consumed(n)` or `NeedMore` |
| `ConfigBuilder` | Discoverable builder: `ConfigBuilder::default().workers(4).build()` |
| `RinglineBuilder` | Launch builder: `RinglineBuilder::new(config).bind(addr).launch::<H>()` |
| `Config` | Runtime configuration (SQ size, buffer sizes, worker count, TLS, etc.) |
| `Runtime` | Returned by `launch()`; controls shutdown, listener addresses, deferred listeners and registered regions, and shuts the workers down when dropped |
| `GuardBox` | Type-erased container for `SendGuard` (64-byte inline storage, no heap) |

## Additional Features

- **Outbound connections** — `connect()` and `connect_unix()`, with `.tls()` and `.timeout()` on the returned builder
- **TLS** — built-in TLS through ringline-tls, a fork of rustls 0.23 (server and client)
- **UDP** — `on_udp_bind()` handler with `UdpSocket` for datagram protocols
- **Timers** — `sleep()`, `timeout()`, `sleep_until()`, `timeout_at()` with fallible variants
- **Standalone tasks** — `spawn()` for tasks not tied to a connection
- **NVMe passthrough** — direct NVMe command submission via io_uring
- **Direct I/O** — O_DIRECT file reads via io_uring
- **Zero-copy sends** — `SendGuard` trait with `GuardBox` inline storage
- **Scatter-gather** — `send_parts()` builder for mixed copy + zero-copy sends

## Platform Requirements

- The io_uring backend requires **Linux 6.1+** on **x86_64** or **ARM64**
  (`IORING_SETUP_DEFER_TASKRUN` and `IORING_OP_SENDMSG_ZC` are 6.1 features).
- Backend selection happens at build time in `ringline/build.rs`: a Linux
  host whose kernel reports a version older than 6.1 silently gets the Mio
  backend — no feature flag, no error. Verify which backend you built before
  benchmarking.
- macOS and other Mio-supported Unix targets always use the Mio backend.
  Linux builds can force it with `--features force-mio`.
- Requires a 64-bit target.

## MSRV

Rust 1.88+ (edition 2024; let-chains in the core crate require 1.88)

## Examples

```bash
# Echo server (async API)
cargo run --example echo_async_server

# Echo client (connects to echo server)
cargo run --example echo_client

# Benchmark
cargo run --release --example echo_bench

# Outbound connect example
cargo run --example connect_echo

# TLS echo server
cargo run --example echo_tls_server
```

## Benchmarks

Two-machine ringline-vs-tokio numbers, with methodology and caveats, are in
[BENCHMARKS.md](BENCHMARKS.md). It holds two runs: a TCP echo comparison
measured in September 2026 at commit `a685e16` (pre-0.7), and a segcache
cache-server comparison measured in June 2026 on ringline 0.1.3. Neither run
has been repeated on the current code; BENCHMARKS.md says which rows no longer
match it.
The benchmark tooling lives in `ringline-bench` (distributed load generator)
and `ringline-benchmarks` (single-machine matrix), with experiment specs under
`experiments/`.

## License

MIT OR Apache-2.0
