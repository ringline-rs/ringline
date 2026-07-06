# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Build
cargo build                          # includes TLS (rustls)
cargo build --examples               # all examples

# Lint — ALWAYS run all three before committing (CI runs clippy on both backends with -D warnings)
cargo fmt --all
cargo clippy --all-targets -- -D warnings                      # io_uring backend (Linux) / mio (macOS)
cargo clippy --all-targets --features force-mio -- -D warnings # mio backend explicitly

# Test
cargo test --all                     # all workspace crates
cargo test --all --release           # release mode
cargo test --all --features force-mio  # mio backend
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

`cargo build` succeeding is NOT sufficient verification — clippy `-D warnings` and fmt failures are CI failures. CI runs every cargo invocation with `--locked`; `Cargo.lock` is committed, so any dependency or version change must update the lockfile in the same commit or CI goes red. A daily `cargo audit --deny warnings` cron catches new advisories — security version pins live as comments in the workspace `Cargo.toml`.

## Platform & Backend Matrix

Ringline has two backends selected at **compile time** by the `has_io_uring` cfg, which `build.rs` emits only when: target is Linux AND the `force-mio` feature is off AND the host kernel is ≥ 6.0. There is no runtime backend selection (it would fight the `CURRENT_DRIVER` raw-pointer thread-local design).

- **io_uring** (`ringline/src/backend/uring/`) — the production path. Linux 6.0+ (SendMsgZc, multishot recv with provided buffers).
- **mio** (`ringline/src/backend/mio/`) — cross-platform fallback (macOS, containers without io_uring). Zero-copy sends degrade to copies (guards are consumed by copying), NVMe is unsupported, and fs/direct I/O run on a dedicated disk-I/O thread pool (`disk_io_pool.rs`) instead of the ring.

Development reality on macOS:
- You are always building/testing the **mio backend**; the io_uring path cannot even be type-checked here (cross-target builds fail in `ring`'s build script, which needs a cross gcc). The authoritative signal for io_uring code is Linux CI or a Linux host.
- `cargo test --all` on macOS occasionally aborts partway with `ringline-quic/tests/peer.rs` `"server should observe FIN"` (`large_payload_round_trip_via_endpoint_api`). This is a known timing flake under full parallel-suite load, not a regression: rerun the test in isolation (`cargo test -p ringline-quic --test peer large_payload_round_trip_via_endpoint_api`) — if it passes, move on and trust Linux CI.
- When piping cargo output (`| tail`, `| grep`), the pipe masks cargo's exit code — check `$pipestatus` (zsh) or avoid the pipe before claiming success.

Changes touching backend-shared code must compile and pass clippy on **both** backends. Behavior-sensitive tests that only make sense on one backend are gated with `#[cfg(has_io_uring)]` / `#[cfg(not(has_io_uring))]`.

## Workspace Structure

This is a Cargo workspace. The core runtime is in `ringline/`; protocol client crates build on top of it:

- **ringline** — core runtime: io_uring + mio backends, executor, connection management, TLS, timers, UDP (GRO/GSO), fs, NVMe passthrough, process spawning
- **ringline-redis** — RESP client (fire/recv pipelining, `Pipeline`, `ShardedClient` via ketama, `ClusterClient` with MOVED/ASK handling and topology refresh)
- **ringline-memcache** — Memcache client (fire/recv pipelining, `ShardedClient`)
- **ringline-ping** — Simple PING/PONG client
- **ringline-h2** — Sans-IO HTTP/2 client framing (HPACK, streams), zero runtime deps
- **ringline-h3** — Sans-IO HTTP/3 framing on `ringline-quic` (QPACK static-table only, control streams)
- **ringline-quic** — Sans-IO QUIC wrapping `quinn-proto`'s state machine
- **ringline-http** — Async HTTP/1.1 + HTTP/2 client bridging `ringline-h2` to `ConnCtx`
- **ringline-grpc** — Sans-IO gRPC framing on `ringline-h2` (no protobuf dep; caller serializes)
- **ringline-bench** / **ringline-benchmarks** — unpublished load-gen tools: `ringline-bench` is the echo/cache server comparison (ringline vs tokio); `ringline-benchmarks` is the multi-protocol harness (tcp/udp/redis/memcache/http1/2/3/quic) with a `force-mio` feature for backend A/B

Wire-protocol parsing/encoding lives in **external published proto crates** (`resp-proto`, `memcache-proto`, `ping-proto`, `ketama`), not in the client crates. The client crates own the runtime integration: `Client`/`ClientBuilder`, fire/recv + write coalescing, pooling, sharding/cluster routing, metrics. (The root `ketama/` directory is an orphaned source copy, not a workspace member — the published `ketama` crate is what's consumed.)

Other top-level artifacts: `BENCHMARKS.md` (checked-in two-machine ringline-vs-tokio baseline numbers — the bar future changes are measured against), `experiments/` (declarative SystemsLab experiment specs), `docs/send-completion-design.md` (required reading before touching the send path — see Domain Invariants).

## Architecture

Ringline is a thread-per-core async I/O runtime. No work-stealing, no cross-thread task migration, all state is thread-local.

### Startup Flow

`RinglineBuilder::new(config).bind(addr).launch::<Handler>()` →
1. Validates config, ensures RLIMIT_NOFILE is sufficient
2. Spawns an **acceptor thread** (if `.bind()` was called) that runs `accept4()` and round-robins fds to workers via crossbeam channels
3. Spawns **N worker threads**, each pinned to a CPU core (SMT-aware: one worker per physical core), each owning its own `Driver` + `Executor` + ring/poll instance

`Config` is **opaque** — all fields are `pub(crate)`; `ConfigBuilder` is the only construction path and validates on `build()`. Notable knobs: `workers`, `pin_to_core`/`core_offset`, recv buffer ring/accumulator sizing, `send_pool`/`send_zc_threshold` (default 4096)/`send_slab_slots`, timers, UDP (`udp_bind`, `udp_gro`, queue depths), subsystems (`nvme`, `direct_io`, `no_fs` — fs is on by default), `tls`/`tls_client`, `close_notify_timeout_ms`.

### Event Loop (per worker)

io_uring — `AsyncEventLoop::run()`:
1. `submit_and_wait(1)` — block until a CQE arrives
2. `drain_completions()` — decode CQEs via `OpTag` + `UserData`, dispatch (recv → accumulator append + wake task, send → dequeue next pending send, connect → store result + wake, timer → fire slot + wake)
3. `collect_wakeups()` — drain thread-local `READY_QUEUE` into executor's ready list
4. `poll_ready_tasks()` — poll all Ready futures (sets `CURRENT_DRIVER` thread-local before each poll)
5. `on_tick()` — call handler's sync tick callback

The mio loop is epoll-shaped (poll with timer-heap-derived timeout → readable/writable handlers → same `collect_wakeups()`/`poll_ready_tasks()` → fire expired timers → `on_tick()`) and uses dirty-lists + a timer min-heap rather than per-iteration scans. Steps 3–4 (the portable executor) are shared.

### Key Abstractions

**`AsyncEventHandler` trait** — Users implement this. `on_accept(ConnCtx)` returns a future that runs for the connection's lifetime. Uses RPITIT (`-> impl Future + 'static`), so implementations must use `async move {}` blocks (not `async fn`, which would borrow `&self`).

**`ConnCtx`** — Async connection handle. `with_data(|&[u8]| -> ParseResult)` / `with_bytes(|Bytes| -> ParseResult)` for recv; `send()`/`send_nowait()`/`send_parts()` for send; `eof_truncated()` distinguishes a peer FIN mid-message from a clean close. Internally indexes into the driver's connection table via `(conn_index, generation)`.

**`Driver`** — Owns all I/O state: the ring (or mio poll), `ConnectionTable`, buffer pools (`ProvidedBufRing`, `SendCopyPool`, `InFlightSendSlab`), `AccumulatorTable`, `TimerSlotPool`.

**`Executor`** — Owns task state: `TaskSlab` (per-connection futures), `StandaloneTaskSlab` (spawned tasks), per-connection waiters/results vectors, ready queue.

### Thread-Local State Pattern

Async futures access the driver via `CURRENT_DRIVER` thread-local (raw pointer, set before poll, cleared after). `with_state(|driver, executor| ...)` is the accessor. `try_with_state()` returns `Option` for fallible access outside the executor.

### Connection Lifecycle

Inbound: acceptor → round-robin to worker → allocate `ConnectionTable` slot → submit multishot recv SQE → spawn `on_accept` task. Outbound: `connect(addr)` → allocate slot → submit connect SQE (optionally IO_LINK'd with timeout) → `ConnectFuture` resolves to new `ConnCtx`.

Generation-based stale detection: `ConnToken(index, generation)` prevents use-after-close when slots are reused. Completion handlers must check the generation before acting on a CQE — slots recycle while CQEs for the old occupant may still be in flight.

### Waker Implementation

Zero-allocation wakers encode the `conn_index` (or `task_idx | STANDALONE_BIT`) as a pointer cast. Waking pushes the index onto thread-local `READY_QUEUE`. The event loop drains this into the executor's ready list.

### Buffer Systems

- **ProvidedBufRing** — kernel-managed recv pool (multishot recv selects buffers at completion time; io_uring only)
- **SendCopyPool** — pre-allocated slots for copy sends (and TLS ciphertext)
- **InFlightSendSlab** — tracks scatter-gather ZC sends until kernel notification
- **RecvAccumulator** — per-connection contiguous recv buffer with O(1) advance; `with_bytes` take/put-back is O(1) via refcounted remainders (zero-copy holds even for pipelined parsing)

### UserData Encoding (64-bit CQE identification)

```
Bits 63..56: OpTag (8 bits) — operation type (RecvMulti, Send, Connect, Timer, coalesced sends, etc.)
Bits 55..32: ConnIndex (24 bits)
Bits 31..0:  Payload (32 bits) — buffer id, slab slot, timer slot, etc.
```

`OpTag` has grown to ~28 variants — read `completion.rs` rather than assuming the set.

## Domain Invariants (io_uring correctness rules)

These are the recurring failure modes in this codebase — the 2026-07 audit (~35 fixes, PRs #236–#244) was mostly violations of them. Check any send/recv/lifecycle change against this list:

1. **SQE memory must outlive the operation.** Any memory referenced by an SQE must stay valid until its CQE arrives — and for ZC sends, until the *notification* CQE too. That's why sends copy into `SendCopyPool` slots, and why `SendGuard`s sit in `InFlightSendSlab` until all notifications land.
2. **io_uring does not order independent SQEs.** Anything that must hit the wire in order (TLS records, partial-send resubmits) goes through the per-connection send queue, never as parallel SQEs. Concurrent TLS sends that bypass the queue interleave records and produce `bad_record_mac` at the peer.
3. **Stale CQEs are normal.** Slots recycle; every completion must be validated against the connection generation (and disk-IO completions against sequence-tagged keys) before touching state.
4. **CQE-skip (`IOSQE_CQE_SKIP_SUCCESS`) is unsound for pool-backed sends** — slot lifecycle needs the CQE, and short sends would be silent. See `docs/send-completion-design.md` before any send-path change.
5. **Short sends happen.** Stream sends use `MSG_WAITALL` (5.19+) so the kernel retries in-place; any new send variant must handle partial completion explicitly.
6. **`ENOBUFS` on multishot recv means the provided ring is empty** — re-arm is event-driven (on replenish), not retried in a loop.
7. **Errors like `EINTR`/`EBUSY` on submit are backpressure, not failures.**

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
| TLS recv | rustls plaintext drained into accumulator via `BufRead` | 1 |

The key difference: `with_data(|&[u8]|)` provides a borrowed slice — the parser must copy any values it wants to keep. `with_bytes(|Bytes|)` provides a refcounted handle — the parser can return `Bytes::slice()` sub-references with zero copies.

**Send path** (user → kernel):

| Method | What happens | Copies |
|--------|-------------|--------|
| `send()` / `send_nowait()` | User data → `SendCopyPool` slot | 1 |
| `send_parts()` with `.copy()` only | All copy parts gathered into one `SendCopyPool` slot | 1 |
| `send_parts()` with `.guard()` only | Guard memory used in-place via `SendMsgZc` iovec | 0 |
| `send_parts()` mixed `.copy()` + `.guard()` | Copy parts → pool; guard parts zero-copy via iovec | 1 (copy parts only) |
| Any send with TLS | Gather plaintext, then rustls encrypts **directly into a pool slot** | 2 |

On the mio backend all of these degrade to copy sends (guards are consumed by copying).

**Zero-copy sends**: `SendGuard` keeps user memory alive until the kernel posts a ZC notification CQE confirming the DMA completed. Guards are stored in `InFlightSendSlab` entries and dropped only after all notifications arrive. ZC only pays off above a size threshold: the runtime's `send_zc_threshold` (default 4096, validated by sweep — crossover is 1–4 KiB) routes smaller "guarded" sends through the copy path.

### Per-Client Copy Analysis

#### ringline-redis

| Path | Copies | Mechanism |
|------|--------|-----------|
| **Recv (values)** | **0** | `with_bytes()` + `resp-proto`'s Bytes-based parser. Bulk strings are `Bytes::slice()` into the accumulator — no allocation, O(1) refcount. Returned `Bytes` stays valid after accumulator advances. |
| **Send (commands)** | 1 | RESP encoded into a **reused** scratch buffer (`encode_buf`/`write_buf` — no per-op allocation), then `send_nowait()` copies into pool. |
| **Send (SET value, standard)** | 1 | All parts gathered into one pool slot. |
| **Send (SET value, guard)** | 1 (metadata only) | `set_with_guard()` / `set_ex_with_guard()`: prefix+suffix copied to pool, value stays in-place via `SendGuard` — if the value is ≥ the client `zc_threshold`; smaller guarded values fold into the copy/coalescing buffer. |
| **Pipeline** | 1 | All commands accumulated into one buffer, single send to pool. |

**Summary**: Recv is fully zero-copy (refcounted slices). Send always copies the command envelope (key names, RESP framing) into the pool. For large values, `set_with_guard()` avoids copying the value itself.

#### ringline-memcache

Same shape as redis: recv is zero-copy via `with_bytes()` + `memcache-proto`'s `ResponseBytes` parser; sends encode into reused scratch and copy the envelope to the pool; `set_with_guard()` keeps large values zero-copy.

#### ringline-ping

Minimal — `with_data()` recv (pattern-match `PONG\r\n`, no value extraction), 1-copy 6-byte send. Trivial protocol with no payload.

### Copy Semantics Design Principles

1. **Recv buffer ownership**: The kernel writes into `ProvidedBufRing` (zero-copy DMA), then data is appended to the per-connection `RecvAccumulator` (1 mandatory copy). After that, `with_bytes()` enables zero-copy parsing via `Bytes::slice()`. `with_data()` requires the parser to copy out any data it needs to keep.

2. **Send buffer ownership**: Ringline must own all memory referenced by SQEs (the submission must outlive the syscall). `SendCopyPool` provides pre-allocated slots for this. `SendGuard` is the escape hatch for zero-copy — it pins user memory and holds it alive until the kernel confirms completion.

3. **TLS caps out at one extra copy**: encryption must read plaintext and write ciphertext, so `SendGuard` zero-copy is impossible under TLS — but ciphertext is encrypted directly into the send-pool slot (no intermediate scratch buffer), and it is serialized through the per-connection send queue for record ordering.

4. **Client choice of `with_data` vs `with_bytes`**: This is the single biggest design decision for recv-side copy count. `with_bytes` enables true zero-copy parsing but requires the protocol parser to work with `Bytes` (refcounted slices). `with_data` is simpler but forces a copy.

## Fire/Recv Pipelining API

The protocol client crates (`ringline-redis`, `ringline-memcache`) support a fire/recv pattern for pipelined request-response without blocking on each individual response.

### Pattern

```rust
// Fire multiple requests (non-blocking, synchronous sends)
client.fire_get(b"key1", 1)?;
client.fire_set(b"key2", b"val", 2)?;
client.fire_del(b"key3", 3)?;

// Recv responses in order (async, blocks until each arrives)
let op1 = client.recv().await?;  // CompletedOp::Get { result, user_data: 1 }
let op2 = client.recv().await?;  // CompletedOp::Set { result, user_data: 2 }
let op3 = client.recv().await?;  // CompletedOp::Del { result, user_data: 3 }
```

### Implementation

Each client has a `VecDeque<PendingOp>` tracking in-flight requests. `fire_*()` methods encode and send (or coalesce — see below), then push a `PendingOp` with the operation kind, timing state, and caller-provided `user_data: u64`. `recv()` pops the next pending op, reads the response, records metrics, and returns a typed `CompletedOp`.

### Write Coalescing

Two `ClientBuilder` knobs control batching of fired requests:
- **`max_batch_size`** (default 1): fired requests accumulate into a shared write buffer and flush as one send when the batch fills. At the default of 1, a fast direct-send path is taken. Coalescing is a large win for small ops (measured ~10x GET throughput at batch 16 vs batch 1 against memcached).
- **`zc_threshold`** (default 4096, matching the runtime's `send_zc_threshold`): `fire_set_with_guard` values *below* this fold into the coalescing copy buffer instead of forcing a separate zero-copy send.

### Available Methods

**ringline-redis**: `fire_get`, `fire_set`, `fire_set_with_guard`, `fire_set_ex`, `fire_set_ex_with_guard`, `fire_del`, `recv() -> CompletedOp`

**ringline-memcache**: `fire_get`, `fire_set`, `fire_set_with_guard`, `fire_delete`, `recv() -> CompletedOp`

### Design Notes

- `user_data: u64` lets callers correlate responses without tracking send order themselves.
- `recv()` returns `Err(Error::NoPending)` if called with no in-flight requests (no panic).
- Timing (`Instant::now()`) is skipped when no callbacks or metrics are configured — zero overhead in the uninstrumented path.
- Responses must be consumed in FIFO order (matching the protocol's response ordering guarantee).
- Distinct from `Pipeline` (redis batch API), which accumulates commands into a single buffer and sends them atomically.

## Code Conventions

- `*_waiters: Vec<bool>` — tracks which tasks await I/O completion per connection index
- `*_results: Vec<Option<IoResult>>` — stores CQE results for awaiting tasks
- Async APIs return `io::Result<T>`. Internal errors use `crate::error::Error`.
- `sleep`/`timeout` **panic** on timer-pool exhaustion (documented contract); `try_sleep`/`try_timeout`/`try_sleep_until`/`try_timeout_at` are the fallible variants.
- Futures use `pin-project-lite` for pin projection.
- `ParseResult::Consumed(0)` on non-empty data is treated as "need more" (same as `NeedMore`).
- The `manual_async_fn` clippy lint is suppressed in tests/examples — `async fn on_accept` doesn't work because it borrows `&self` (not `'static`).
- `unsafe fn` is used where the caller carries a real obligation (e.g. `nvme_read`/`nvme_write` require the buffer to be valid, aligned, and to outlive the future) — don't wrap such contracts in "safe" signatures that can't uphold them.

## API Design Principles

These reflect deliberate owner decisions — follow them for any public-surface change:

- **No `pub` fields on public config/value structs.** Everything is opaque: `pub(crate)` fields + builder or accessor methods (`Config`/`ConfigBuilder`, `TlsInfo`, `TlsConfig::new`). Do not split `Config` into sub-structs; it stays an opaque flat struct.
- **Public error enums are `#[non_exhaustive]`.**
- **Don't merge or prune send-path entry points casually.** The surviving set is deliberate: `with_data` vs `with_bytes`, `send` vs `send_nowait`, `.copy()` vs `.guard()`, `send_chain` (IO_LINK), `submit_batch` (dynamic part assembly) vs `build` (static) all carry distinct semantics.
- **Breaking changes are batched into coordinated major releases** (see Release Process), not dribbled out.

## Performance Work

- Performance claims require measurement. `BENCHMARKS.md` holds the checked-in baseline (two-machine AWS Graviton4, segcache workload, ringline vs tokio); `ringline-bench`/`ringline-benchmarks` are the load generators; `experiments/` holds SystemsLab specs. Microbenches: criterion `resp_bench` in `ringline-redis`.
- Think in copies and syscalls first (see Copy Semantics). Recent wins came from removing scratch buffers, reusing encode buffers, batching guards, and eliminating per-iteration O(n) scans — not from micro-tuning.
- Watch for environment artifacts before blaming the code: NIC bandwidth caps, IRQ/flow-steering placement, and SMT sibling enumeration have all masqueraded as ringline regressions.
- The io_uring backend is the performance target; mio needs to be correct and non-pathological, not optimal.

## Release Process

Use `/release <patch|minor|major>` (in-repo skill; `/pr` creates feature-branch PRs). Releases are **coordinated across all publishable crates**:

1. Bump all package versions, the workspace `ringline` dependency requirement, AND the inter-crate exact-version requirements (http→h2, grpc→h2, h3→quic) — a stale `version = "0.x.0"` req excludes the new major and breaks publishing mid-sequence.
2. Update the committed `Cargo.lock` (CI is `--locked`).
3. Move CHANGELOG `Unreleased` → the new version (Keep a Changelog format).
4. PR commit message must start with `release: v` (triggers auto-tagging). After merge, `tag-release.yml` creates the git tag → `release.yml` publishes unpublished crates to crates.io in dependency tiers.
5. Follow up with a post-release dev bump.

Required secrets: `RELEASE_TOKEN` (PAT for tagging), `CARGO_REGISTRY_TOKEN` (crates.io).
