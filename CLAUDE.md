# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build
cargo build                          # includes TLS (rustls)
cargo build --examples               # all examples

# Lint
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# Test
cargo test --all                     # all workspace crates
cargo test --all --release           # release mode
cargo test -p ringline -- <name>     # single test by name
cargo test -p ringline-redis         # single crate

# Docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Examples
cargo run --example echo_async_server
cargo run --example connect_echo
cargo run --release --example echo_bench
cargo run --example echo_tls_server
```

## Workspace Structure

This is a Cargo workspace. The core runtime is in `ringline/`; protocol client crates build on top of it:

- **ringline** — core io_uring runtime, executor, connection management, TLS, timers, UDP, NVMe
- **ringline-redis** — RESP protocol client wrapping `ConnCtx`
- **ringline-memcache** — Memcache protocol client wrapping `ConnCtx`
- **ringline-ping** — Simple PING/PONG client
- **ringline-momento** — Multiplexed Momento cache client (protobuf over TLS)
- **ringline-h2** — Sans-IO HTTP/2 client framing (HPACK, streams)
- **ringline-h3** — HTTP/3 framing on top of `ringline-quic` (QPACK, control streams)
- **ringline-quic** — QUIC layer wrapping `quinn-proto` sans-IO state machine
- **ringline-http** — Async HTTP/1.1 and HTTP/2 client on top of `ringline-h2`
- **ringline-grpc** — gRPC client framing on top of `ringline-h2`

## Architecture

Ringline is a thread-per-core io_uring async I/O runtime. No work-stealing, no cross-thread task migration, all state is thread-local.

### Startup Flow

`RinglineBuilder::new(config).bind(addr).launch::<Handler>()` →
1. Validates config, ensures RLIMIT_NOFILE is sufficient
2. Spawns an **acceptor thread** (if `.bind()` was called) that runs `accept4()` and round-robins fds to workers via crossbeam channels
3. Spawns **N worker threads**, each pinned to a CPU core, each owning its own `Driver` + `Executor` + io_uring instance

### Event Loop (per worker)

`AsyncEventLoop::run()` is the core loop:
1. `submit_and_wait(1)` — block until a CQE arrives
2. `drain_completions()` — decode CQEs via `OpTag` + `UserData`, dispatch to appropriate handler (recv → accumulator append + wake task, send → dequeue next pending send, connect → store result + wake, timer → fire slot + wake)
3. `collect_wakeups()` — drain thread-local `READY_QUEUE` into executor's ready list
4. `poll_ready_tasks()` — poll all Ready futures (sets `CURRENT_DRIVER` thread-local before each poll)
5. `on_tick()` — call handler's sync tick callback

### Key Abstractions

**`AsyncEventHandler` trait** — Users implement this. `on_accept(ConnCtx)` returns a future that runs for the connection's lifetime. Uses RPITIT (`-> impl Future + 'static`), so implementations must use `async move {}` blocks (not `async fn`, which would borrow `&self`).

**`ConnCtx`** — Async connection handle. `with_data(|&[u8]| -> ParseResult)` for recv, `send()`/`send_nowait()` for send. Internally indexes into the driver's connection table via `(conn_index, generation)`.

**`Driver`** — Owns all io_uring state: the `Ring`, `ConnectionTable`, buffer pools (`ProvidedBufRing`, `SendCopyPool`, `InFlightSendSlab`), `AccumulatorTable`, `TimerSlotPool`.

**`Executor`** — Owns task state: `TaskSlab` (per-connection futures), `StandaloneTaskSlab` (spawned tasks), per-connection waiters/results vectors, ready queue.

### Thread-Local State Pattern

Async futures access the driver via `CURRENT_DRIVER` thread-local (raw pointer, set before poll, cleared after). `with_state(|driver, executor| ...)` is the accessor. `try_with_state()` returns `Option` for fallible access outside the executor.

### Connection Lifecycle

Inbound: acceptor → round-robin to worker → allocate `ConnectionTable` slot → submit multishot recv SQE → spawn `on_accept` task. Outbound: `connect(addr)` → allocate slot → submit connect SQE (optionally IO_LINK'd with timeout) → `ConnectFuture` resolves to new `ConnCtx`.

Generation-based stale detection: `ConnToken(index, generation)` prevents use-after-close when slots are reused.

### Waker Implementation

Zero-allocation wakers encode the `conn_index` (or `task_idx | STANDALONE_BIT`) as a pointer cast. Waking pushes the index onto thread-local `READY_QUEUE`. The event loop drains this into the executor's ready list.

### Buffer Systems

- **ProvidedBufRing** — kernel-managed recv pool (multishot recv selects buffers at completion time)
- **SendCopyPool** — pre-allocated slots for small copy sends
- **InFlightSendSlab** — tracks scatter-gather ZC sends until kernel notification
- **RecvAccumulator** — per-connection contiguous recv buffer with O(1) advance

### UserData Encoding (64-bit CQE identification)

```
Bits 63..56: OpTag (8 bits) — operation type (RecvMulti, Send, Connect, Timer, etc.)
Bits 55..32: ConnIndex (24 bits)
Bits 31..0:  Payload (32 bits) — buffer id, slab slot, timer slot, etc.
```

## Copy Semantics

Ringline aims to minimize data copies on the hot path. Understanding where copies happen is critical for performance work.

### Core Runtime Copy Counts

**Receive path** (kernel → user):

| Step | What happens | Copies |
|------|-------------|--------|
| Kernel → ProvidedBufRing | DMA into ring-provided buffer | 0 |
| ProvidedBufRing → RecvAccumulator | `BytesMut::extend_from_slice()` | 1 |
| Accumulator → `with_data()` callback | Borrowed `&[u8]` into accumulator | 0 |
| Accumulator → `with_bytes()` callback | `BytesMut::freeze()` → `Bytes` (O(1)), slicing via `Bytes::slice()` is O(1) refcount | 0 |

The key difference: `with_data(|&[u8]|)` provides a borrowed slice — the parser must copy any values it wants to keep. `with_bytes(|Bytes|)` provides a refcounted handle — the parser can return `Bytes::slice()` sub-references with zero copies.

**Send path** (user → kernel):

| Method | What happens | Copies |
|--------|-------------|--------|
| `send()` / `send_nowait()` | User data → `SendCopyPool` slot | 1 |
| `send_parts()` with `.copy()` only | All copy parts gathered into one `SendCopyPool` slot | 1 |
| `send_parts()` with `.guard()` only | Guard memory used in-place via `SendMsgZc` iovec | 0 |
| `send_parts()` mixed `.copy()` + `.guard()` | Copy parts → pool; guard parts zero-copy via iovec | 1 (copy parts only) |
| Any send with TLS | Gather → encrypt → pool (TLS prevents zero-copy send) | 3 |

**Zero-copy sends**: `SendGuard` keeps user memory alive until the kernel posts a ZC notification CQE confirming the DMA completed. Guards are stored in `InFlightSendSlab` entries and dropped only after all notifications arrive.

### Per-Client Copy Analysis

#### ringline-redis

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | Uses `with_bytes()` + `Value::parse_bytes()`. Bulk strings are `Bytes::slice()` into the accumulator — no allocation, O(1) refcount. Returned `Bytes` stays valid after accumulator advances. |
| **Send (commands)** | 1 | `encode_request()` serializes RESP into `Vec<u8>`, then `conn.send()` copies into pool. |
| **Send (SET value, standard)** | 1 | `send_parts().copy(&prefix).copy(value).copy(&suffix)` — all parts gathered into one pool slot. |
| **Send (SET value, guard)** | 1 (metadata only) | `set_with_guard()` / `set_ex_with_guard()`: prefix+suffix copied to pool, value stays in-place via `SendGuard`. Value is zero-copy. |
| **Pipeline** | 1 | All commands accumulated into one `Vec<u8>`, single `conn.send()` to pool. |

**Summary**: Recv is fully zero-copy (refcounted slices). Send always copies the command envelope (key names, RESP framing) into the pool. For large values, `set_with_guard()` avoids copying the value itself.

#### ringline-memcache

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | Uses `with_bytes()` + `ResponseBytes::parse()`. Keys and values are `Bytes::slice()` into the accumulator — no allocation, O(1) refcount. |
| **Send (commands)** | 1 | `encode_request()` → `Vec<u8>`, then `conn.send()` copies to pool. |
| **Send (SET value, guard)** | 1 (metadata only) | `set_with_guard()`: prefix+suffix to pool, value zero-copy via `SendGuard`. |

**Summary**: Recv is fully zero-copy (refcounted slices), matching redis. Send always copies the command envelope (key names, memcache framing) into the pool. For large values, `set_with_guard()` avoids copying the value itself.

#### ringline-momento

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | Uses `with_bytes()` + `CacheResponse::decode_bytes()`. Values are `Bytes::slice()` into the accumulator — no allocation, O(1) refcount. |
| **Send (requests)** | **1** | Single-pass `encode_into()` writes all protobuf nesting levels directly into one reusable buffer. Then `send_nowait()` copies into pool. |

**Summary**: Recv is fully zero-copy (refcounted slices), matching redis/memcache. Send uses single-pass encoding into a reusable buffer — 1 copy into the send pool. Note: all Momento connections use TLS, which adds encryption copies on the send path regardless (`SendGuard` cannot help since TLS must read plaintext and write ciphertext).

#### ringline-ping

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv** | **0** (parse only) | Uses `with_data()`. Parser just pattern-matches `PONG\r\n` — no value extraction needed. |
| **Send** | 1 | 6-byte `PING\r\n` encoded to stack, `conn.send()` copies to pool. |

**Summary**: Minimal — 1 copy send, zero-copy recv. Trivial protocol with no payload.

### Copy Semantics Design Principles

1. **Recv buffer ownership**: The kernel writes into `ProvidedBufRing` (zero-copy DMA), then data is appended to the per-connection `RecvAccumulator` (1 mandatory copy). After that, `with_bytes()` enables zero-copy parsing via `Bytes::slice()`. `with_data()` requires the parser to copy out any data it needs to keep.

2. **Send buffer ownership**: Ringline must own all memory referenced by SQEs (the io_uring submission must outlive the syscall). `SendCopyPool` provides pre-allocated slots for this. `SendGuard` is the escape hatch for zero-copy — it pins user memory and holds it alive until the kernel confirms completion.

3. **TLS negates zero-copy sends**: Encryption requires reading plaintext and writing ciphertext, so TLS connections always copy through the encryption layer regardless of `SendGuard` usage.

4. **Client choice of `with_data` vs `with_bytes`**: This is the single biggest design decision for recv-side copy count. `with_bytes` enables true zero-copy parsing but requires the protocol parser to work with `Bytes` (refcounted slices). `with_data` is simpler but forces a copy.

## Code Conventions

- `*_waiters: Vec<bool>` — tracks which tasks await I/O completion per connection index
- `*_results: Vec<Option<IoResult>>` — stores CQE results for awaiting tasks
- Async APIs return `io::Result<T>`. Internal errors use `crate::error::Error`.
- `try_*()` variants (e.g., `try_sleep`, `try_timeout`) return errors on pool exhaustion instead of panicking.
- Futures use `pin-project-lite` for pin projection.
- `ParseResult::Consumed(0)` on non-empty data is treated as "need more" (same as `NeedMore`).
- The `manual_async_fn` clippy lint is suppressed in tests/examples — `async fn on_accept` doesn't work because it borrows `&self` (not `'static`).

## Release Process

Use `/release <patch|minor|major>` to create a release PR. The workflow:
1. `cargo-release` bumps `ringline/Cargo.toml` version
2. `CHANGELOG.md` is updated (Keep a Changelog format)
3. PR commit message must start with `release: v` (triggers auto-tagging)
4. After merge, `tag-release.yml` creates the git tag → `release.yml` publishes to crates.io

Required secrets: `RELEASE_TOKEN` (PAT for tagging), `CARGO_REGISTRY_TOKEN` (crates.io).
