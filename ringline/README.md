# ringline

**Thread-per-core async I/O with an io_uring backend for Linux and a portable
Mio backend.**

ringline is a thread-per-core I/O framework. It provides an async/await API
(`AsyncEventHandler`) on a single-threaded executor with no work-stealing.

## What ringline is

- An io_uring backend that exploits advanced kernel features: multishot
  recv, ring-provided buffers, SendMsgZc (zero-copy send), fixed file table
- A Mio backend for macOS and other Unix targets, for Linux kernels older
  than 6.0 (automatic build-time fallback), and for Linux builds using
  `force-mio`
- Thread-per-core with CPU pinning — no work-stealing, no task migration

## What ringline is NOT

- A Tokio replacement (different abstractions, not API-compatible)
- A general-purpose task scheduler (all tasks are `!Send`, pinned to cores)

## Quick Start

```rust
use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn.with_data(|data| {
                    conn.send_nowait(data).ok();
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
    let (_shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:7878".parse().unwrap())
        .launch::<Echo>()?;
    for h in handles { h.join().unwrap()?; }
    Ok(())
}
```

## Architecture

For the code-derived runtime and request lifecycle diagrams, see
[Architecture](https://github.com/ringline-rs/ringline/blob/main/docs/architecture.md).
For the technology tradeoffs behind the Linux backend, see
[Why consider io_uring?](https://github.com/ringline-rs/ringline/blob/main/docs/io-uring-primer.md);
for the counted syscalls and copies per request on each backend, see
[Syscalls and copies, counted](https://github.com/ringline-rs/ringline/blob/main/docs/syscalls-and-copies.md).

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

Each worker thread owns its backend driver, executor, connection table
(with generation-based stale detection), and handler instance. On the
io_uring backend, each worker also owns:

- A dedicated **io_uring** instance (SQ + CQ)
- A **ring-provided buffer pool** for recv (kernel selects buffers at completion time)
- A **send copy pool** for small sends and a **send slab** for scatter-gather zero-copy sends
- A **fixed file table** for O(1) fd lookups (no per-syscall fd table traversal)

## io_uring Features Used

| Feature | Purpose |
|---------|---------|
| Multishot recv | Single SQE submission, multiple completions — no resubmission overhead |
| Ring-provided buffers | Kernel-managed recv buffer pool — kernel picks buffer at completion time |
| SendMsgZc | Zero-copy scatter-gather send — kernel DMAs directly from app buffers |
| Fixed file table | Direct descriptors — no per-syscall fd table lookup |
| IO_LINK chains | Atomic multi-step operations (connect + timeout) |
| COOP_TASKRUN | Reduced context switches |
| SINGLE_ISSUER | Lock-free kernel-side optimizations |

## Key Types

| Type | Description |
|------|-------------|
| `AsyncEventHandler` | Trait: `on_accept(ConnCtx) -> Future` — one task per connection |
| `ConnCtx` | Async connection context: `send()`, `send_nowait()`, `with_data()` |
| `WithDataFuture` | Future that resolves when recv data is available |
| `SendFuture` | Future that resolves when a send completes |
| `ConnectFuture` | Future that resolves when an outbound connection completes |
| `RinglineBuilder` | Builder: `RinglineBuilder::new(config).bind(addr).launch::<H>()` |
| `Config` | Runtime configuration (SQ size, buffer sizes, worker count, TLS, etc.) |
| `ShutdownHandle` | Triggers graceful shutdown of all workers |
| `GuardBox` | Type-erased container for `SendGuard` (64-byte inline storage, no heap) |
| `DriverCtx` | I/O context available in `on_tick()` and `on_notify()` callbacks |

## Platform Requirements

- The io_uring backend requires **Linux 6.0+** on **x86_64** or **ARM64**.
- Backend selection happens at build time in `build.rs`: a Linux host whose
  kernel reports a version older than 6.0 silently gets the Mio backend — no
  feature flag, no error. Verify which backend you built before benchmarking.
- macOS and other Mio-supported Unix targets always use the Mio backend.
  Linux builds can force it with `--features force-mio`.

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

## License

MIT OR Apache-2.0
