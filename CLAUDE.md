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
cargo test --all                     # all tests (76 unit + 42 integration + doctests)
cargo test --all --release           # release mode
cargo test -p ringline -- <name>     # single test by name

# Docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Examples
cargo run --example echo_async_server
cargo run --example connect_echo
cargo run --release --example echo_bench
cargo run --example echo_tls_server
```

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
