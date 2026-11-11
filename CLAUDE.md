# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The design stances behind the rules below are written up separately in
[docs/principles/PRINCIPLES.md](docs/principles/PRINCIPLES.md). This file says
what to do; that one says why, and is the place to argue with a decision rather
than work around it.

## Build & Test Commands

```bash
# Build
cargo build                          # includes TLS (ringline-tls, a fork of rustls)
cargo build --examples               # all examples

# Lint — ALWAYS run all three before committing (CI runs clippy on both backends with -D warnings)
cargo fmt --all
cargo clippy --all-targets -- -D warnings                      # io_uring backend (Linux) / mio (macOS)
cargo clippy --all-targets --features force-mio -- -D warnings # mio backend explicitly

# Test (CI runs cargo-nextest: one process per test; config in .config/nextest.toml)
cargo nextest run --workspace                       # all workspace crates
cargo nextest run --workspace --release             # release mode
cargo nextest run --workspace --features force-mio  # mio backend
cargo nextest run -p ringline                       # without unstable-accept; see below
cargo test --workspace --doc                        # doctests (nextest does not run them)
cargo nextest run -p ringline <name>                # tests matching a name
cargo nextest run -p ringline-redis                 # single crate
cargo test --all                                    # also works; runs a binary's tests in one process

# Docs
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps                # io_uring docs on Linux
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features # --all-features turns on force-mio

# Examples
cargo run --example echo_async_server
cargo run --example connect_echo
cargo run --release --example echo_bench
cargo run --example echo_tls_server
```

Tests that open a socket bind port 0 and read the address back:
`Runtime::bound_addr` / `bound_addrs` for TCP listeners, `bound_udp_addr` /
`bound_udp_addrs` for UDP, `local_addr()` for a test's own `std` socket. Do not
choose a port and bind it later. Ringline binds with `SO_REUSEPORT`, so two test
processes given the same port both bind it and the kernel splits traffic between
their servers. A test that needs a port with nothing listening uses `refusing_port` in
`tests/common/mod.rs`, which holds the client end of an established loopback
connection. A bound socket that never listens refuses on Linux but not on macOS.

A test whose handler requests its own shutdown joins the workers with
`common::join_workers`, not a bare `h.join()`. The helper is in
`tests/common/mod.rs` in ringline, ringline-http, ringline-memcache,
ringline-ping and ringline-redis; copy it into another crate that needs it. It
shuts the runtime down and fails the test if the workers have not exited
within 30 s of the call, so a stuck handler fails the test instead of hanging
`cargo test` (#447).

`ringline-bench` enables the `unstable-accept` feature, and a build that includes it unifies features, so every `--workspace` build has it on. A selection that excludes `ringline-bench` builds it off, which is what a published dependent gets; `-p ringline` and `--workspace --exclude ringline-bench` both do. The feature gates six public items: `AcceptMode`, `ConfigBuilder::accept_mode`, `Runtime::set_worker_accepting`, `offer_for_park`, `on_adopt`, `ParkState`. The code behind them always compiles, and unit tests see it through `any(feature = "unstable-accept", test)`. Integration tests that use them need `cfg(feature = "unstable-accept")`. Run clippy with `--workspace --exclude ringline-bench` and the tests with `-p ringline` too. Doctests in `accept.rs` fail if a gated item becomes public.

`cargo build` succeeding is NOT sufficient verification — clippy `-D warnings` and fmt failures are CI failures. CI runs every cargo invocation with `--locked`; `Cargo.lock` is committed, so any dependency or version change must update the lockfile in the same commit or CI goes red. A daily `cargo audit --deny warnings` cron catches new advisories — security version pins live as comments in the workspace `Cargo.toml`. It does not see `ringline-tls` or `ringline-quic-proto`. Each fork's `ringline-advisories.yml` checks the upstream release merged on the fork's branch, not the version ringline requires or locks. After a fork release, the fork's `ringline-release.yml` opens a pull request here raising the requirement in the workspace `Cargo.toml` (`admin/ringline-raise`), when main requires an earlier version on the same minor version. A move to a new minor version, or a raise on a maintenance branch, is done by hand. The script rewrites the one sentence directly above the requirement, `# X.Y.Z is based on UPSTREAM A.B.C[ and is also past IDS].`, naming the RustSec advisories against the upstream crate that raises have fixed; the hand-written comment above that sentence lists the rest. `admin/ringline-raise` does not find an advisory against an upstream dependency such as `rustls-webpki`, one the fork's own changes fix (including a fix backported ahead of upstream), or a GitHub advisory (GHSA) against the upstream crate that is not in the RustSec database. Before merging, add those to the hand-written list. A RUSTSEC id against the upstream crate that the fork fixes ahead of upstream must go in that list too: the next raise removes it from the sentence while cargo-audit reports it against the new upstream release. In the sentence, the next raise carries forward only RUSTSEC-YYYY-NNNN ids and `GHSA-xxxx-xxxx-xxxx` ids with a lowercase suffix. If the sentence is in any other form, the next raise leaves that line in place and does not carry its ids.

## Platform & Backend Matrix

Ringline has two backends selected at **compile time** by the `has_io_uring` cfg, which `build.rs` emits only when: target is Linux AND the `force-mio` feature is off AND the host kernel is ≥ 6.1. There is no runtime backend selection (it would fight the `CURRENT_DRIVER` raw-pointer thread-local design).

Within the io_uring backend, `has_io_uring` selects the driver and `uring_engine` (emitted alongside it) runs that driver on the kernel's io_uring through `UringEngine` (`ringline/src/backend/uring/engine/`). The driver builds an `Sqe` per operation and only the engine encodes it, so only `engine/uring.rs` (and tests) use the `io_uring` crate. `RINGLINE_STUB_ENGINE=1 cargo clippy -p ringline` builds the driver on `StubEngine` instead, which fails at setup; CI's `Clippy (stub engine)` job uses it to check that the driver does not use the crate.

The kernel check is a **build-host, compile-time** gate and is necessary but not sufficient. At **run time** the kernel must also permit io_uring: `kernel.io_uring_disabled` (6.6+) must be 0, or 1 with the process in `kernel.io_uring_group` (or holding `CAP_SYS_ADMIN`), and no seccomp profile may deny `io_uring_setup`. Otherwise every launch fails with `Error::RingSetup`, whose message names the cause. RHEL 10 / Rocky 10 ship `io_uring_disabled = 2` (refused for everyone, root included), so on that family only a `force-mio` build runs — verified on Rocky 10.2, kernel 6.12.0-211.el10 (#355).

Ubuntu's 6.8 kernels from 6.8.0-139 on (24.04, and 22.04 HWE) invert the reserved-word check in `IORING_REGISTER_PBUF_RING`, and reportedly in `IORING_UNREGISTER_PBUF_RING`: the standard call, with `resv` zeroed, fails with `EINVAL`. `UringEngine::register_buf_ring` retries once with `resv[0] = 1`, only after an `EINVAL` on a 6.8 kernel, and uses that form for the worker's later registrations; unregistration tries it first and falls back to the standard form (#626). Code that registers a provided buffer ring through the `io-uring` crate directly fails on those kernels.

- **io_uring** (`ringline/src/backend/uring/`) — the production path. Linux 6.1+ (DEFER_TASKRUN and SendMsgZc are 6.1; multishot recv with provided buffers is 6.0).
- **mio** (`ringline/src/backend/mio/`) — cross-platform fallback (macOS, containers without io_uring). Zero-copy sends degrade to copies (guards are consumed by copying), NVMe is unsupported, and fs/direct I/O run on a dedicated disk-I/O thread pool (`disk_io_pool.rs`) instead of the ring.

Development reality on macOS:
- You are always building/testing the **mio backend**; the io_uring path cannot even be type-checked here (cross-target builds fail in `ring`'s build script, which needs a cross gcc). The authoritative signal for io_uring code is Linux CI or a Linux host.
- When piping cargo output (`| tail`, `| grep`), the pipe masks cargo's exit code — check `$pipestatus` (zsh) or avoid the pipe before claiming success. The same trap applies inside an experiment payload: a piped `cargo` there reports success too, so check `${PIPESTATUS[0]}` before a step concludes anything.

The `ringline-quic/tests/peer.rs` `"server should observe FIN"` flake
(`large_payload_round_trip_via_endpoint_api`) was **fixed in #471** — do not
rerun-and-move-on if you see it again, it means something new. It was described
here for months as a macOS timing flake, and that was wrong twice over: it failed
on Linux CI too, and the cause was not timing. `read_until_fin` flushed only the
reader, and `flush` is what *generates* packets while `poll_send` only yields
already-generated ones, so a sender holding the rest of the payload could never
transmit it. Two earlier fixes (#386, #389) tuned the loop's round budget instead,
because "both endpoints went quiet" reads as impatience. `poll_send_yields_nothing_until_flush`
now asserts the contract. The general lesson: a test helper that ferries packets
must flush **both** sides.

Changes touching backend-shared code must compile and pass clippy on **both** backends. Behavior-sensitive tests that only make sense on one backend are gated with `#[cfg(has_io_uring)]` / `#[cfg(not(has_io_uring))]`.

### Verifying io_uring code

macOS cannot type-check the io_uring path at all, so it has to be built on Linux
— and that means **a SystemsLab experiment, never a direct login to a rig host.**
`experiments/accept-mode-ab-build.toml` is the pattern to copy: an `anvil-vm`
step on a `validation`-tagged agent that clones the branch into an ephemeral VM
and builds there.

**Do not `ssh`/`rsync`/`scp` to hv01, hv02, delta, the pis, or any other host in
the rig, for builds or for anything else.** Those machines are SystemsLab agents;
hv01 and hv02 are also the two hypervisors every two-machine measurement runs on.
A cargo build on one of them is a CPU-heavy load landing on a measurement host,
which silently perturbs whatever experiment is in flight — someone else's as
easily as your own. Submit an experiment and let the scheduler place it.

Three things worth knowing wherever the uring tests run:

- **Run clippy on the io_uring path too, not just the tests.** Lints behind
  `has_io_uring` exist only there: a `///` doc comment above a `thread_local!`
  block is an `unused_doc_comments` error under `-D warnings` that no macOS job
  will ever show you. Tests passing on io_uring does not mean it is lint-clean —
  that combination broke CI on #470.
- **The uring test binary needs a generous `RLIMIT_NOFILE`.** At a 1024 soft
  limit it aborts with `io_uring_setup(2): Too many open files (EMFILE)`, which
  reads as a code failure and is not; raise the soft limit in the payload.
- **On Linux 6.14+ every ring is charged to `RLIMIT_MEMLOCK`**, and the
  charge of a dropped ring is released asynchronously. The lib test helpers
  `make_test_loop` and `ring.rs`'s `ring_with`, and the runtime launches in
  `close_tests.rs`, retry an ENOMEM from ring setup or provided-ring
  registration for up to 5 s (`is_memlock_enomem`, #589). Integration tests
  under `ringline/tests/` do not. If the user's total charge, across all
  their processes, still exceeds the limit after 5 s, `make_test_loop`
  aborts the binary with the setup message.

## Workspace Structure

This is a Cargo workspace. The core runtime is in `ringline/`; protocol client crates build on top of it:

- **ringline** — core runtime: io_uring + mio backends, executor, connection management, TLS, timers, UDP (GRO/GSO), fs, NVMe passthrough, process spawning
- **ringline-redis** — RESP client (fire/recv pipelining, `Pipeline`, `ShardedClient` via ketama, `ClusterClient` with MOVED/ASK handling and topology refresh)
- **ringline-memcache** — Memcache client (fire/recv pipelining, `ShardedClient`)
- **ringline-ping** — Simple PING/PONG client
- **ringline-h2** — Sans-IO HTTP/2 client framing (HPACK, streams), zero runtime deps
- **ringline-h3** — Sans-IO HTTP/3 framing on `ringline-quic` (QPACK static-table only, control streams)
- **ringline-tls-config** — `TlsConfig`/`TlsClientConfig` and their builders, the `TlsVersion`/`CipherSuite` enums, and the rustls escape hatch (`from_rustls`, `rustls_config`, the `rustls` re-export). ringline re-exports it as `ringline::tls_config`. Design: `docs/rustls-quinn-forks-design.md`
- **ringline-quic** — Sans-IO QUIC wrapping the state machine of `ringline-quic-proto` (ringline-rs/quinn, a fork of quinn-proto). Its API names no quinn-proto type outside `QuicConfig::from_proto` and the `proto` re-export: `QuicConfig::builder()` takes ringline-tls-config's `TlsConfig`/`TlsClientConfig`, and stream IDs, errors, events and stats are its own types (`types.rs`, `error.rs`, `event.rs`)
- **ringline-http** — Async HTTP/1.1 + HTTP/2 client bridging `ringline-h2` to `Connection`
- **ringline-grpc** — Sans-IO gRPC framing on `ringline-h2` (no protobuf dep; caller serializes)
- **ringline-bench** / **ringline-benchmarks** — unpublished load-gen tools: `ringline-bench` is the echo/cache server comparison (ringline vs tokio); `ringline-benchmarks` is the multi-protocol harness (tcp/udp/redis/memcache/http1/2/3/quic) with a `force-mio` feature for backend A/B

TLS and QUIC come from two forks maintained under `ringline-rs`: ringline-tls (ringline-rs/rustls, rustls 0.23 renamed; library `ringline_tls`) and ringline-quic-proto (ringline-rs/quinn, quinn-proto 0.11 on ringline-tls). ringline and ringline-tls-config import the TLS fork as `ringline_tls`; ringline-quic imports the QUIC fork as `ringline_quic_proto`. Integration tests use upstream `rustls` and `quinn_proto` as peers; ringline-bench's connect-bench client, ringline-benchmarks' tokio comparison clients and its HTTP/2 benchmark server use them too. A daily workflow in each fork checks for a newer upstream release on its line and opens a pull request merging it (or an issue when the merge needs a person); merge the pull request with a merge commit, then tag `v0.1.N` to publish. Publishing then opens a pull request here raising the workspace requirement to the release, when main requires an earlier 0.1.x. Design: `docs/rustls-quinn-forks-design.md`.

Wire-protocol parsing/encoding lives in **external published proto crates** (`resp-proto`, `memcache-proto`, `ping-proto`, `ketama`), not in the client crates. The client crates own the runtime integration: `Client`/`ClientBuilder`, fire/recv + write coalescing, pooling, sharding/cluster routing, metrics. (The root `ketama/` directory is an orphaned source copy, not a workspace member — the published `ketama` crate is what's consumed.)

Other top-level artifacts: `BENCHMARKS.md` (checked-in two-machine ringline-vs-tokio baseline numbers — the bar future changes are measured against), `experiments/` (declarative SystemsLab experiment specs), `docs/send-completion-design.md` (required reading before touching the send path — see Domain Invariants).

## Architecture

Ringline is a thread-per-core async I/O runtime. No work-stealing, no cross-thread task migration, all state is thread-local.

### Startup Flow

`RinglineBuilder::new(config).bind(addr).launch::<Handler>()` →
1. Validates config, ensures RLIMIT_NOFILE is sufficient (and, on io_uring, that RLIMIT_MEMLOCK covers what each worker charges to it: its `registered_regions`, plus on Linux 6.14+ its ring and one provided buffer ring per UDP socket — see `ringline/src/memlock.rs`; a process with `CAP_IPC_LOCK` in the initial user namespace is not charged); soft limits are raised when the hard limit allows, otherwise `Error::ResourceLimit` names the `ulimit` to run
2. Spawns an **acceptor thread** (if `.bind()` was called) that runs `accept4()` and round-robins fds to workers via crossbeam channels
3. Spawns **N worker threads**, each pinned to a CPU core (SMT-aware: one worker per physical core), each owning its own `Driver` + `Executor` + ring/poll instance

`Config` is **opaque** — all fields are `pub(crate)`; `ConfigBuilder` is the only construction path and validates on `build()`. Notable knobs: `workers`, `pin_to_core`/`core_offset`, accumulator sizing and `recv_direct_region`, `send_pool`/`send_zc_threshold` (default 4096)/`send_slab_slots`, timers, UDP (`udp_bind`, `udp_gro`, queue depths), subsystems (`nvme`, `direct_io`, `no_fs` — fs is on by default), `tls`/`tls_client`, `tls_handshake_timeout` (default 10 s, at most 60 s).

### Event Loop (per worker)

io_uring — `AsyncEventLoop::run()`:
1. `submit_and_wait(1)` — block until a CQE arrives
2. `drain_completions()` — decode CQEs via `OpTag` + `UserData`, dispatch (recv → accumulator append + wake task, send → dequeue next pending send, connect → store result + wake, timer → fire slot + wake)
3. `collect_wakeups()` — drain thread-local `READY_QUEUE` and the worker's cross-thread wake inbox into executor's ready list
4. `poll_ready_tasks()` — poll all Ready futures (sets `CURRENT_DRIVER` thread-local before each poll)
5. `on_tick()` — call handler's sync tick callback

The mio loop is epoll-shaped (poll with timer-heap-derived timeout → readable/writable handlers → same `collect_wakeups()`/`poll_ready_tasks()` → fire expired timers → `on_tick()`) and uses dirty-lists + a timer min-heap rather than per-iteration scans. Steps 3–4 (the portable executor) are shared.

### Key Abstractions

**`AsyncEventHandler` trait** — Users implement this. `on_accept(Connection)` returns a future that runs for the connection's lifetime. Uses RPITIT (`-> impl Future + 'static`), so implementations must use `async move {}` blocks (not `async fn`, which would borrow `&self`).

**`Connection`** — An owned connection, from `on_accept` or `connect`; `split()` gives a `SendHalf` and a `RecvHalf`, neither `Copy`. `with_data(|&[u8]| -> ParseResult)` / `with_bytes(|Bytes| -> ParseResult)` for recv (`with_data_result` is the `io::Result` form that separates a clean close from a transport error); `send()`/`send_nowait()`/`send_parts()` for send; `eof_truncated()` distinguishes a peer FIN mid-message from a clean close. Internally indexes into the driver's connection table via `(conn_index, generation)`, in the `pub(crate)` `ConnCtx`.

**`Driver`** — Owns all I/O state: the ring (or mio poll), `ConnectionTable`, buffer pools (the UDP `ProvidedBufRing`, `SendCopyPool`, `InFlightSendSlab`), `AccumulatorTable`, `TimerSlotPool`.

**`Executor`** — Owns task state: `TaskSlab` (per-connection futures), `StandaloneTaskSlab` (spawned tasks), per-connection waiters/results vectors, ready queue.

### Thread-Local State Pattern

Async futures access the driver via `CURRENT_DRIVER` thread-local (raw pointer, set before poll, cleared after). `with_state(|driver, executor| ...)` is the accessor. `try_with_state()` returns `Option` for fallible access outside the executor.

### Connection Lifecycle

Inbound: acceptor → round-robin to worker → allocate `ConnectionTable` slot → arm the hangup poll (TLS: also the handshake's receive; `on_accept` is spawned when the handshake completes) → spawn `on_accept` task (plaintext). Outbound: `connect(addr)` → allocate slot → submit connect SQE (optionally IO_LINK'd with timeout) → `ConnectFuture` resolves to a new `Connection`. On io_uring every plaintext connection, accepted or outbound, arms no ring receive: it receives directly into its accumulator, with a one-shot `RECV` armed when a read parks, and one `POLL_ADD(POLLRDHUP)` armed when it opens so a peer close is seen while nothing reads (`docs/recv-direct-design.md`). A TLS connection receives the same way, into its TLS engine's ciphertext buffer (with `tls-buffered`, a pooled buffer that `read_tls` copies from): re-armed after each completion during the handshake, then armed when a read parks (or after each completion once the hangup poll has fired).

A peer's FIN or close_notify finishes the read half and closes nothing: the task keeps the connection, may keep sending, and `Connection::peer_closed` reports the end; readers resolve `0` (`docs/half-close-design.md`). A FIN on a TLS connection whose handshake has not completed closes it, and an outbound connect resolves `UnexpectedEof`; a handshake still incomplete after `tls_handshake_timeout` closes it too, and an outbound connect resolves `TimedOut`. A reset or a read error still closes. Dropping the last half of a connection closes it (`release_half`, queued through `defer_release` when the drop is outside a task poll). Close, on both backends: only `close_connection` (and the `DriverCtx` close) moves the connection to `Lifecycle::Closing`; it also sets `ConnSendState::close_pending`, and teardown finalizes once queued sends drain (io_uring: `try_finalize_close` submits the Close SQE behind the kernel-dependent lead Domain Invariant 8 describes; mio: `drain_pending_closes` defers `finish_close`). A backend site that marks the connection closing directly leaks the slot — that was #368.

Connection state is three fields on `ConnectionState`: `read` (the TCP read half as we observed it: `Open`, `Eof { truncated }`, `Error`), `lifecycle` (`Inactive`/`Connecting`/`Open`/`Closing`), and `write` (the TCP write half as we drive it: `Open`, `ShutdownPending`, `Shutdown`). Readers ask `recv_finished()` ("resolve to EOF instead of parking?") or `close_requested()` ("is a close already pending?") rather than matching variants; a peer FIN sets `read` and requests no close, so `Eof` with `Lifecycle::Open` is a steady state. Design: `docs/connection-state-model-design.md`, `docs/half-close-design.md`.

Generation-based stale detection: `ConnId(index, generation)` prevents use-after-close when slots are reused. Completion handlers must check the generation before acting on a CQE — slots recycle while CQEs for the old occupant may still be in flight.

### Waker Implementation

Zero-allocation wakers encode the `conn_index` (or `task_idx | STANDALONE_BIT`) in the low 32 bits of the pointer and the owning worker's process-unique id in the high 32. Waking on the owning worker's thread pushes the index onto thread-local `READY_QUEUE`; waking on any other thread pushes it into that worker's inbox (registry in `runtime/waker.rs`) and, if no wake since the worker last drained it has done so, writes its wake fd. The event loop drains both into the executor's ready list.

A leaf future (recv, send, timer, disk, channel) registers its task's id and returns `waker::pending(cx)`, not `Poll::Pending`: if `cx` holds a waker other than the task's own, something other than the executor polled it, usually a combinator such as `FuturesUnordered`, and `pending` keeps that waker, once per distinct waker. `Executor::wake_task`, the path of every leaf completion except `channel.rs::wake_waiter` outside a poll, which fires them itself, fires all of the task's kept wakers, so a `FuturesUnordered` of N pending leaves costs N polls per completion. `collect_wakeups` does not fire them: `FuturesUnordered` wakes its own task when it yields after a poll budget, and firing on that wake would spin the worker. A kept waker runs where the completion runs, in the completion loop or inside another task's poll, so it must not call into ringline (#641).

### Buffer Systems

- **ProvidedBufRing** — kernel-managed recv pool for UDP (multishot recvs select buffers at completion time; io_uring only). TCP and Unix connections have no ring: a plaintext connection receives into its accumulator, and a TLS connection into its TLS engine's ciphertext buffer
- **SendCopyPool** — pre-allocated slots for copy sends (and TLS ciphertext)
- **InFlightSendSlab** — tracks scatter-gather ZC sends until kernel notification
- **RecvAccumulator** — per-connection contiguous recv buffer with O(1) advance; `with_bytes` take/put-back is O(1) via refcounted remainders (zero-copy holds even for pipelined parsing)

### UserData Encoding (64-bit CQE identification)

```
Bits 63..56: OpTag (8 bits) — operation type (RecvDirect, Send, Connect, Timer, coalesced sends, etc.)
Bits 55..32: ConnIndex (24 bits)
Bits 31..0:  Payload (32 bits) — buffer id, slab slot, timer slot, etc.
```

For pool-slot send ops (`Send`/`TlsSend`) the payload's high bits carry the
connection generation (truncated) so completion handlers can reject a CQE that
outlived its connection slot; slab-backed sends record the generation in the
slab entry instead, and the payload of `SendPollOut` is the whole generation.
See `UserData::send_payload`.

`OpTag` has grown to ~30 variants — read `completion.rs` rather than assuming the set.

## Domain Invariants (io_uring correctness rules)

These are the recurring failure modes in this codebase — the 2026-07 audit (~35 fixes, PRs #236–#244) was mostly violations of them. Check any send/recv/lifecycle change against this list:

1. **SQE memory must outlive the operation.** Any memory referenced by an SQE must stay valid until its CQE arrives — and for ZC sends, until the *notification* CQE too. That's why sends copy into `SendCopyPool` slots, and why `SendGuard`s sit in `InFlightSendSlab` until all notifications land.
2. **io_uring does not order independent SQEs.** Anything that must hit the wire in order (TLS records, partial-send resubmits) goes through the per-connection send queue, never as parallel SQEs. Concurrent TLS sends that bypass the queue interleave records and produce `bad_record_mac` at the peer.
3. **Stale CQEs are normal.** Slots recycle; every completion must be validated before touching state: connection completions against the connection generation, disk-I/O completions against their key (io_uring: subsystem, sequence, slab index; mio: a sequence). A disk-I/O key is not reissued while a future holds it (or, on mio, while its pool operation runs), and a result is stored only for a held key.
4. **CQE-skip (`IOSQE_CQE_SKIP_SUCCESS`) is unsound for pool-backed sends** — slot lifecycle needs the CQE, and short sends would be silent. See `docs/send-completion-design.md` before any send-path change.
5. **Short sends happen.** Stream sends use `MSG_DONTWAIT` (`STREAM_SEND_FLAGS`), so a send takes what the socket has room for and returns, and any new send variant must handle partial completion explicitly. The sends of a `send_chain` use `MSG_WAITALL` (`CHAIN_SEND_FLAGS`) instead, because a short part would be followed by the next one across a gap (#734). Build a chain part with `Sqe::chain_send`, `Sqe::chain_send_msg` or `Sqe::chain_send_msg_zc`; `Ring::push_sqe_chain` debug-asserts it, before a one-part chain takes the plain push.
6. **`ENOBUFS` on a buffer-select recv means the provided ring is empty** — re-arm on replenish, not in a loop. Only UDP receives through a provided ring, one per socket. Its handlers record the socket in `udp_awaiting_buffers`, and `return_udp_buffers` re-arms it once its ring has a free buffer. A re-arm on an empty ring returns `ENOBUFS` at once, so re-arming from the handler spins the worker at full CPU (#742).
7. **Errors like `EINTR`/`EBUSY`/`EAGAIN` on submit are backpressure, not failures.** A queued send whose SQE cannot be pushed is parked at its queue head and retried next iteration (`drain_send_retries`), never dropped.
8. **Closing a fixed file does not release its socket while requests that hold it are in flight.** Before Linux 6.13, those are every earlier request that uses a registered file or buffer, on any connection: a receive or hangup poll on another connection is enough to delay the FIN. From 6.13, they are the connection's own requests. Close a connection through `try_finalize_close`, which hard-links a lead ahead of the Close. Before 6.13 the lead is `shutdown(SHUT_RDWR)`, which runs on the bounded io-wq pool behind any blocking file I/O. From 6.13 it is an `ASYNC_CANCEL` of every request on the connection's fixed file, which runs inline (#581, #586). A socket parked onto another worker (`socket_handed_off`) is closed without a lead. At worker exit every connection is closed with the cancel lead, on every kernel, so a send waiting on a peer that does not read is cancelled rather than waited out; a zero-copy entry holds exit until its notification arrives, for 1 s, and the connection then closes with `SO_LINGER {on, 0}`, which discards the queued data so the notification lands. Below Linux 6.7 that option cannot be set through io_uring, and an entry whose connection closed before exit began has no socket to set it on: such an entry holds exit until the 10 s shutdown bound runs out, and its guards and the send pool's memory are then leaked, since the kernel can still read them (#607).
9. **A send that cannot finish waits in ringline, not on an io-wq thread.** A short result or `-EAGAIN` stores the send's user_data in `ConnSendState::waiting_send` and arms `SendPollOut` (`AsyncEventLoop::wait_for_room`). io_uring reports `POLLRDHUP` on every poll, so after the peer half-closes a one-shot `PollAdd(POLLOUT)` completes at once without `POLLOUT`, and retrying a send behind it spins (#603). That case moves to a multishot poll, which is edge-triggered: it reports `POLLRDHUP` once and then `POLLOUT` when room appears. A send can have room while the socket does not poll writable: `send` needs `wmem_queued < sndbuf`, and `POLLOUT` needs free space of at least `wmem_queued / 2`. A waiting send has nothing in the kernel, so whatever ends the wait must fail or resubmit it; a 1 s timer (`handle_send_backstop`) resubmits every waiting send for the cases no poll reports. A multishot poll holds the socket open past its `Close`, so `try_finalize_close` cancels it by user_data first. A `send_chain` still holds an io-wq thread while a part waits on a half-closed peer (#605, `docs/half-closed-send-wait-design.md`).

## Copy Semantics

Ringline aims to minimize data copies on the hot path. Understanding where copies happen is critical for performance work. The user-facing home for this analysis (plus per-backend syscall counting and measured numbers) is [docs/syscalls-and-copies.md](docs/syscalls-and-copies.md) — keep the two in sync when the counted paths change.

### Core Runtime Copy Counts

**Receive path** (kernel → user):

| Step | What happens | Copies |
|------|-------------|--------|
| Kernel → RecvAccumulator (plaintext, io_uring) | One-shot `RECV` into the accumulator's free space, armed when a read parks (`docs/recv-direct-design.md`) | 0 |
| Kernel → TLS engine buffer (TLS, io_uring) | One-shot `RECV` of ciphertext, armed when a read parks: into the unbuffered engine's `CiphertextBuf`, or with `tls-buffered` into a worker buffer that `read_tls` reads; the plaintext is the TLS recv row below | 0 |
| Kernel → read buffer → RecvAccumulator (mio) | `read()` into a per-worker buffer, then `extend_from_slice()` | 1 |
| Accumulator → `with_data()` callback | Borrowed `&[u8]` into accumulator. When the parser stops at an incomplete message, or `with_data` parks with nothing buffered, the accumulator moves the buffered start of the message (at most a quarter of the capacity it has grown to) to the front of its allocation (`compact_at_message_start`), so that `append` does not move most of a message longer than one `append` (a TLS record's plaintext on a TLS connection, one `read()` of up to 8192 bytes on a plaintext mio connection) once it reaches the end of the allocation. Bytes moved per plaintext byte over TLS: about 0.01 for 64 KiB messages answered one at a time (`tls_recv_compaction_rr`, both backends), 0.25–0.5 for pipelined 64 KiB frames on io_uring (`tls_recv_compaction`) | 0 |
| Accumulator → `with_bytes()` callback | `BytesMut::freeze()` → `Bytes` (O(1)), slicing via `Bytes::slice()` is O(1) refcount | 0 |
| TLS recv, unbuffered engine (default) | Ciphertext → ringline's `CiphertextBuf`: on io_uring the receive writes it there (row above), on mio `append` copies it from the read buffer; rustls decrypts in place there, and `ReadTraffic::next_record` lends the record from `CiphertextBuf` (ringline-tls 0.1.1, either TLS version); ringline copies it into the accumulator. `CiphertextBuf::make_room` also moves ciphertext: it calls `compact`, which moves the unprocessed bytes to the front of the buffer, when the tail has no room for the next receive and those bytes are no longer than the bytes processed ahead of them. Otherwise it grows the buffer. Measured on io_uring with the default 32 KiB `recv_direct_region`, at 16 KiB records and 64 KiB messages. The buffer starts at 32 KiB and had grown to 64 KiB. `compact` moved 0.25× the ciphertext received when messages were answered one at a time and 0.17–0.29× when pipelined. `tls_recv_compaction*` do not cover these figures. In a `bench-server --tls` echo on io_uring, at 64 KiB messages (256 connections, 30,000 messages/s) and 1 MiB messages (64 connections, 2,000 messages/s), samples with `make_room` on the stack, mostly its memmove, were about 0.7% of the server process's on-CPU samples (user and kernel). On mio, `append` compacts under the same condition and the cost is not measured. Neither backend is measured at 1 KiB records | 1 on io_uring, 2 on mio, + conditional |
| TLS recv, buffered engine (`tls-buffered`) | Ciphertext → rustls' deframer buffer (`read_tls`); rustls decrypts in place, then copies each record's plaintext into a new `Vec` (`take_received_plaintext`); `drain_tls_plaintext` copies that into the accumulator. Plus a ciphertext memmove in `DeframerVecBuffer::discard` of the bytes behind each processed record: measured 0.12× the payload at 16 KiB records, 2.3× at 1 KiB records | 3 + conditional |

With `tls-buffered`, TLS recv costs 3 copies on either backend: ciphertext into rustls' deframer buffer, decrypted plaintext into a per-record `Vec` (`CommonState::take_received_plaintext` → `Payload::into_vec`), and that `Vec` into the accumulator. The unbuffered engine with ringline-tls 0.1.1 makes no copy inside rustls: `take_received_plaintext` lends the in-place plaintext instead of copying it, on unbuffered connections only. So a TLS receive costs 1 copy on io_uring, where the receive writes the ciphertext into `CiphertextBuf`, and 2 on mio, where `append` copies it there (from the code; ringline-tls's copy-count test measures 0.00 bytes copied per plaintext byte inside rustls on a TLS 1.3 client connection with the ring provider; the server side, TLS 1.2 and aws-lc-rs are from the code). `note_copied` counts only ringline's own copy.

The key difference: `with_data(|&[u8]|)` provides a borrowed slice — the parser must copy any values it wants to keep. `with_bytes(|Bytes|)` provides a refcounted handle — the parser can return `Bytes::slice()` sub-references with zero copies.

**Send path** (user → kernel):

| Method | What happens | Copies |
|--------|-------------|--------|
| `send()` / `send_nowait()` | User data → `SendCopyPool` slot | 1 |
| `send_parts()` with `.copy()` only | All copy parts gathered into one `SendCopyPool` slot | 1 |
| `send_parts()` with `.guard()` only | Guard memory used in-place via `SendMsgZc` iovec. On a Unix-domain connection, which refuses `SENDMSG_ZC`, a plain `sendmsg` of the same iovecs: the kernel copies the guard's bytes into the socket, as it does for a copy send (#829) | 0 |
| `send_parts()` mixed `.copy()` + `.guard()` | Copy parts → pool; guard parts zero-copy via iovec (on a Unix-domain connection, a plain `sendmsg`, as above) | 1 (copy parts only) |
| Any send with TLS (buffered engine, `tls-buffered`) | rustls seals each record in a per-record `PrefixedPayload`; `write_tls` copies it into pool slots through `PoolWriter` (an `io::Write` adapter, no scratch `Vec`) on io_uring, or into the queued `Vec` on mio (`encrypt_for_send_mio_buffered`). `send_parts` and `send_chain` first gather their parts, guard parts included, into a `Vec` (`SendBuilder::submit_tls` for `send_parts` and `SendChainBuilder::copy` / `ChainPartsBuilder::add` for `send_chain` on io_uring; `AsyncSendBuilder` on mio), one more copy | 2; 3 through `send_parts`/`send_chain` |
| Application-data send with TLS (unbuffered engine, default) | With ringline-tls and the ring provider, a TLS 1.3 record is copied once: `WriteTraffic::encrypt` → `write_fragments` → `MessageEncrypter::encrypt_into` copies the plaintext into the pool slot (io_uring) or the queued buffer (mio) and seals it there. With the aws-lc-rs provider on an AES-GCM suite, outside FIPS mode, `encrypt_into` seals from the caller's slice into the destination (`seal_out_of_place_scatter`) and copies none of the plaintext (AWS-LC still copies its 288-byte key context per record); aws-lc-rs ChaCha20-Poly1305, or aws-lc-rs in FIPS mode, copies once as ring does. ringline's builders use ring; aws-lc-rs needs a config passed to `TlsConfig::from_rustls`. A TLS 1.2 record, or one from another provider, is sealed in a per-record `PrefixedPayload` and then copied into the destination. `send_parts` and `send_chain` first gather their parts, guard parts included, into a `Vec` (`SendBuilder::submit_tls` for `send_parts` and `SendChainBuilder::copy` / `ChainPartsBuilder::add` for `send_chain` on io_uring; `AsyncSendBuilder` on mio), one more copy | 0 (TLS 1.3, aws-lc-rs AES-GCM outside FIPS mode), 1 (other TLS 1.3 with ring or aws-lc-rs), 2 otherwise; `send_parts`/`send_chain` +1 |

The `tls-unbuffered` feature was merged (#350) claiming it took application-data
sends from 2 copies to 1. **With upstream rustls that claim was false.**
The supposed removed copy — user bytes into rustls' `sendable_plaintext` — does
not happen on an established connection: `CommonState::send_plain` (rustls
0.23.41 `src/common_state.rs`) buffers into `sendable_plaintext` only while
`!may_send_application_data`, i.e. before the handshake completes, and otherwise
calls `send_plain_non_buffering`. And the unbuffered API does not encrypt into
the destination either: `WriteTraffic::encrypt` → `write_plaintext` →
`CommonState::write_fragments` allocates a `PrefixedPayload` per record
(`Tls13MessageEncrypter::encrypt`), copies the plaintext in, seals in place, and
then `copy_from_slice`s the record into `outgoing_tls`. Two passes over the
plaintext on both engines. An allocation counter inside the measured call agrees:
263,976 bytes/op buffered vs 264,000 unbuffered at a 256 KiB payload.
ringline-tls, ringline's fork of rustls, has `write_fragments` hand the
destination to `MessageEncrypter::encrypt_into`, which removes the per-record
buffer for TLS 1.3 with the ring and aws-lc-rs providers: that path costs 1
copy, and none with aws-lc-rs on an AES-GCM suite outside FIPS mode (the send
table row above; `docs/rustls-quinn-forks-design.md`).

What the feature *does* deliver, measured in isolation on hv01 (Linux 6.12,
rustc 1.98.1, io_uring): a small (~1–2%) send-side bookkeeping win at ≥64 KiB, a 4–8%
recv-side win, and, at a 16384-byte `send_copy_slot_size`, an **extra TLS
record** whenever the payload is a multiple of the slot size (the buffered path
lets `PoolWriter` straddle one 16406-byte record across two slots; the
unbuffered path must fit a whole record inside one slot, so it emits two) —
worth +5.7% on a 16 KiB send. The default slot (16448 bytes) holds a whole
record, so at the default both engines emit one record per 16 KiB. It remains
the prerequisite for kTLS. See
[docs/tls-unbuffered-design.md](docs/tls-unbuffered-design.md) and
[docs/journal/2026-09-unbuffered-tls.md](docs/journal/2026-09-unbuffered-tls.md).

On the mio backend all of these degrade to copy sends (guards are consumed by copying).

**Zero-copy sends**: `SendGuard` keeps user memory alive until the kernel posts a ZC notification CQE confirming the DMA completed. Guards are stored in `InFlightSendSlab` entries and dropped only after all notifications arrive. On a Unix-domain connection guard parts go out with a plain `sendmsg` instead, and the guard drops when the send completes (#829). ZC only pays off above a size threshold: the runtime's `send_zc_threshold` (default 4096, validated by sweep — crossover is 1–4 KiB) routes smaller "guarded" sends through the copy path.

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

1. **Recv buffer ownership**: On io_uring a plaintext connection's receive writes into its `RecvAccumulator` directly (0 copies). A TLS connection's receive writes ciphertext into its TLS engine's buffer, and a TLS receive costs 1 to 3 copies per received byte depending on engine and backend (see the table). On mio, `read()` fills a per-worker buffer that is appended to the accumulator (1 copy). After that, `with_bytes()` enables zero-copy parsing via `Bytes::slice()`. `with_data()` requires the parser to copy out any data it needs to keep.

2. **Send buffer ownership**: Ringline must own all memory referenced by SQEs (the submission must outlive the syscall). `SendCopyPool` provides pre-allocated slots for this. `SendGuard` is the escape hatch for zero-copy — it pins user memory and holds it alive until the kernel confirms completion.

3. **TLS send copies**: encryption must read plaintext and write ciphertext, so `SendGuard` zero-copy is impossible under TLS. Application data through `send` costs 2 copies on the buffered engine and for TLS 1.2; on the unbuffered engine a TLS 1.3 record costs 1 with the ring provider, and with aws-lc-rs on ChaCha20-Poly1305 or in FIPS mode; none with aws-lc-rs on AES-GCM outside FIPS mode. `send_parts` and `send_chain` add one gather copy (see the send table). Records are serialized through the per-connection send queue for ordering.

   The unbuffered engine (the default; the `tls-buffered` feature selects the
   buffered one) uses rustls' unbuffered API for the record layer. With
   ringline-tls it seals TLS 1.3 records in the destination (1 copy with the
   ring provider, and with aws-lc-rs on ChaCha20-Poly1305 or in FIPS mode;
   none with aws-lc-rs on AES-GCM outside FIPS mode, which seals from the
   caller's slice) and receives records lent from its
   ciphertext buffer; TLS 1.2 sends still cost 2 copies. Recv costs 1 copy on
   io_uring and 2 on mio with this engine, and 3 with the buffered one.
   Handshake ciphertext on io_uring pays one copy more than the buffered
   engine (`unbuffered::drive` encodes it into a scratch `Vec`, which
   `ciphertext_to_sends` copies into pool slots) — a one-time per-connection
   cost. See `docs/tls-unbuffered-design.md` and
   `docs/rustls-quinn-forks-design.md`.

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

**ringline-redis**: `fire_get`, `fire_set`, `fire_set_with_guard`, `fire_set_ex`, `fire_set_ex_with_guard`, `fire_del`, `recv() -> CompletedOp`, `recv_ready()`

**ringline-memcache**: `fire_get`, `fire_set`, `fire_set_with_guard`, `fire_delete`, `recv() -> CompletedOp`, `recv_ready()`

### Sending while a reply is pending

`recv` takes `&mut self` and is not cancel-safe (it pops the pending op before its first await), so a task inside `recv` cannot fire. `recv_ready()` flushes and returns a `RecvReadyFuture` that does not borrow the client and resolves when bytes of the next reply have arrived or the connection has finished receiving. A caller waits on it together with its own request source, fires (and calls `recv_ready` again, which flushes) when a request is ready, and calls `recv` when it resolves. Polling it registers the task, and an arrival wakes that task by id. Design: `docs/send-while-receiving-design.md` (Option B, a split `Sender`/`Receiver`, is not implemented).

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

- **No `pub` fields on public config/value structs.** Everything is opaque: `pub(crate)` fields + builder or accessor methods (`Config`/`ConfigBuilder`, `TlsInfo`, `TlsConfig::builder`). Do not split `Config` into sub-structs; it stays an opaque flat struct.
- **Public error enums are `#[non_exhaustive]`.**
- **Don't merge or prune send-path entry points casually.** The surviving set is deliberate: `with_data` vs `with_bytes`, `send` vs `send_nowait`, `.copy()` vs `.guard()`, `send_chain` (IO_LINK), `submit_batch` (dynamic part assembly) vs `build` (static) all carry distinct semantics.
- **Breaking changes are batched into coordinated major releases** (see Release Process), not dribbled out.

## Performance Work

- Performance claims require measurement. `BENCHMARKS.md` holds two checked-in runs: a two-machine TCP echo comparison of ringline and tokio server configurations (server guest on hv02, client guest on hv01, X710 LAG, September 2026) and an older segcache run on AWS Graviton4 (June 2026). Neither matches the current code; BENCHMARKS.md says which rows. `ringline-bench`/`ringline-benchmarks` are the load generators; `experiments/` holds SystemsLab specs. Microbenches: criterion `resp_bench` in `ringline-redis`.
- Think in copies and syscalls first (see Copy Semantics). Recent wins came from removing scratch buffers, reusing encode buffers, batching guards, and eliminating per-iteration O(n) scans — not from micro-tuning.
- Watch for environment artifacts before blaming the code: NIC bandwidth caps, IRQ/flow-steering placement, and SMT sibling enumeration have all masqueraded as ringline regressions.
- The io_uring backend is the performance target; mio needs to be correct and non-pathological, not optimal.

## Release Process

Use the shared `release` skill from the custom-skills plugin (`/cs:release`; it discovers this repo's mechanism from the files below; there is no in-repo release skill). `/cs:open-pr` opens feature-branch PRs. Releases are **coordinated across all publishable crates**:

1. Bump all package versions, the workspace `ringline` dependency requirement, AND the inter-crate exact-version requirements (http→h2, grpc→h2, h3→quic, and the workspace `ringline-tls-config` requirement in the root `Cargo.toml`) — a stale `version = "0.x.0"` req excludes the new major and breaks publishing mid-sequence. Under 0.x a breaking release is `minor`, not `major`. The three `publish = false` crates (`ringline-bench`, `ringline-benchmarks`, `tools/doc-diagrams`) keep their own versions.
2. Update the committed `Cargo.lock` (CI is `--locked`).
3. Move CHANGELOG `Unreleased` → the new version (Keep a Changelog format).
4. PR commit message must start with `release: v` and name the version in `ringline/Cargo.toml`. After merge, `tag-release.yml` — a caller of the shared [`brayniac/rust-workflows`](https://github.com/brayniac/rust-workflows) `tag-release.yml@v1`, gated to `ringline-rs/ringline` — creates the `vX.Y.Z` tag → `release.yml` publishes unpublished crates to crates.io in dependency tiers.
5. After tagging, the shared workflow opens a `chore: begin next development iteration` PR bumping `ringline/Cargo.toml`, the workspace `ringline` requirement and `Cargo.lock` to the next minor's `-alpha.0` (`v0.7.0` → `0.8.0-alpha.0`; `dev-bump-package: ringline`, `dev-bump-style: minor-alpha`; the comment in the workflow file says why it is scoped). Merge it; the client crates stay at their published versions until the next coordinated release re-bumps them.

**Per-crate releases** (`ringline-<crate>-vX.Y.Z` tags, used for a satellite crate on its own cadence) are not tagged by the shared workflow. Bump the crate, land the PR, then tag the merge commit by hand and push the tag to `ringline-rs/ringline`; `release.yml` publishes on the tag.

Required secrets: `RELEASE_TOKEN` (PAT for tagging), `CARGO_REGISTRY_TOKEN` (crates.io).

### Maintenance branches and backports

`main` is development; the next release from it may be breaking. A released
line that still needs fixes gets a **maintenance branch**, `release/<major>.<minor>.x`
(e.g. `release/0.6.x`, cut from the `v0.6.3` tag), and patch releases for that
line are cut from it.

- **Fix `main` first, then backport.** Land the fix on `main`, then
  `git cherry-pick -x <merge commit>` onto a branch off `release/X.Y.x` and open
  a PR into `release/X.Y.x`. Fixes flow one way, from `main` to the maintenance
  lines, never back. `-x` records the source commit.
- **Adapt a conflict to the old line; don't pull in the new one.** A conflict
  usually means `main` has moved on around the fix. Keep the old line's code
  and apply only what the fix changes. Drop tests that exercise APIs the line
  doesn't have, and keep the fix's own tests. Say what was adapted in the PR.
- **Patch-sized only.** A fix that needs a series of `main`'s changes
  underneath it (for example the bounded-send series behind #376) is not a
  backport. Write a targeted fix for the old line, or leave it to the next
  release.
- **No breaking changes.** A maintenance line takes fixes and dependency floors
  (security pins), never a `!:` change.
- **CI runs on `release/**`** for pushes and PRs (`ci.yml`). Since io_uring code
  can't be built on macOS, a backport's CI is its verification.
- **Releasing a patch** (`vX.Y.Z` from `release/X.Y.x`):
  1. Bump the changed crate(s) only.
  2. Update `Cargo.lock`.
  3. Move the branch's `Unreleased` to `[X.Y.Z]`.
  4. Land it through a PR into the maintenance branch titled
     `release: vX.Y.Z`. The `release branches` ruleset requires PRs and
     squash merges on `release/**`, as `main`'s does. Name the PR's head
     branch outside `release/` (e.g. `prep/vX.Y.Z`): anything under
     `release/` falls under the ruleset and cannot be deleted afterwards.
  5. Once the merge commit's CI is green, tag it by hand
     (`git tag -a vX.Y.Z -m "Release vX.Y.Z"`) and push the tag.
     `release.yml` publishes; `tag-release.yml` fires only on `main`, so
     nothing on a maintenance branch tags itself.
- **Record it on `main` afterwards:** add the `[X.Y.Z]` section to `main`'s
  CHANGELOG as shipped, and drop its entries from `main`'s `Unreleased`.
  `main`'s version does not take `X.Y.Z`; the PR bumps `-alpha.N` like any
  other.
- **Versions:** `main` carries the next minor as a pre-release
  (`0.7.0-alpha.N`), and the workspace `ringline` requirement matches it.
  While `main`'s version carries `-alpha.N`, every PR to `main` other than a
  release PR, docs-only and dependency-only ones included, bumps `N` by one
  from the remote `main`'s value, in `ringline/Cargo.toml`, the workspace
  requirement and `Cargo.lock`.
  Released `X.Y.Z` versions of a maintained line exist only on
  `release/X.Y.x`, so `main` never holds a version that is also published
  from a maintenance branch.
- **Protection:** the `release branches` ruleset covers `release/**`. It
  blocks deletion and force-pushes, and requires a PR with squash merge,
  matching `main`'s ruleset.
