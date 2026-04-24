# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `ringline-quic` now emits `StreamReadable` when a stream opens with data in the first frame (previously hung).
- `ringline-h3` no longer drops body bytes when the peer's flow-control window is tight.

### Added

- `QuicEndpoint::flush()` drains pending transmits on demand.
- `UdpCtx::send_ready()` awaits a free UDP send slot.
- `H3Connection::has_pending_writes()` reports whether queued bytes are waiting for flow-control credit.

### Changed

- UDP recv now uses multishot `recvmsg` with a provided buffer ring (io_uring). New `Config::udp_recv_buffer`.
- UDP sends are now pipelined (io_uring).
- `QuicConfig` is now `Clone`.

## [ringline-redis 0.2.1] - 2026-04-18

### Changed
- `max_batch_size` knob on `ClientBuilder` controls fire command coalescing. Default is 1 (each `fire_*` sends immediately, matching pre-v0.1 behavior). Set higher for pipelined workloads to coalesce multiple commands into a single send.

## [0.1.0] - 2026-04-18

### Added
- **Cross-platform mio backend** — ringline now compiles and runs on macOS and Linux without io_uring. The backend is selected automatically via `build.rs` (io_uring on Linux 6.0+, mio elsewhere). Use `--features force-mio` to opt into mio on Linux. The public API is identical across backends. (#94–#102)
- `ringline::backend()` returns `Backend::IoUring` or `Backend::Mio` for runtime detection (#95)
- `nvme_flush()` async free function for NVMe flush operations (#93)
- Per-command byte metrics (`tx_bytes`, `rx_bytes`), `latency` on `CompletedOp`, and TTFB tracking for redis, memcache, and momento clients (#91)

### Changed
- Backend selection is automatic — no feature flags needed. `io-uring` is a target-conditional dependency (Linux only). `futures-io` is always enabled. (#95)
- **ringline-redis**: `fire_*` commands are now coalesced into a single send per pipeline batch, reducing TCP segments from N to 1 under deep pipelining. Guard values remain zero-copy via scatter-gather I/O. (#104)
- CI now tests both io_uring and mio backends, including Redis, Memcache, and public server integration tests on mio (#96–#102)

### Fixed
- Correct `send_ts` for TTFB calculation in momento multiplexed recv (#92)
- Add retry with backoff for crates.io rate limits in CI (#90)

## [0.0.5] - 2026-04-09

### Fixed
- Skip Momento integration tests in CI when `MOMENTO_ENDPOINT` secret is not configured
- Pass secrets to reusable CI workflow in release pipeline (`secrets: inherit`)

## [0.0.4] - 2026-04-09

### Fixed
- Treat empty `MOMENTO_ENDPOINT` and `MOMENTO_REGION` env vars as unset in `Credential::from_env()`
- Update workspace dependency in `tag-release.yml` dev version bump

## [0.0.3] - 2026-04-09

### Added
- Async filesystem module with native io_uring file I/O
- Async process spawning with `Command` builder
- `spawn_blocking` for offloading blocking work to a thread pool
- `CancellationToken` for structured cancellation
- `ConnStream` with `AsyncRead`/`AsyncWrite`/`AsyncBufRead` traits
- `JoinHandle` for `spawn_with_handle`
- Async oneshot and mpsc channels
- Signal handling for graceful shutdown
- Dedicated DNS resolver pool
- Unix domain socket support
- Zero-copy recv/send paths and benchmark suite with standalone bench binaries
- HTTP compression support (gzip, zstd, brotli)
- gRPC per-message compression support (gzip, zstd)
- Fire/recv pipelining API for redis, memcache, and momento clients
- `send_request()` for client-side HTTP/3 on `H3Connection`
- `ringline-http` crate with HTTP/2 and HTTP/1.1 async client
- `ringline-grpc` sans-IO gRPC client framing layer
- `ringline-h2` sans-IO HTTP/2 client framing layer
- `ringline-momento` multiplexed Momento cache client
- `ringline-ping` client crate
- `ringline-bench` benchmark suite
- Kernel `SO_TIMESTAMPING` support behind `timestamps` feature
- `sqpoll_idle_ms` option in `ConfigBuilder`
- `PingAcknowledged` event on HTTP/2 PING ACK
- Streaming response support for `ringline-http`
- Extensive test coverage: property-based CQE dispatch tests, fault injection, buffer exhaustion stress tests, TLS end-to-end, connect timeout, parse error, and integration tests

### Changed
- TLS (rustls) is now always-on; removed feature flag
- Hardened `MemoryRegion`, `RegionId`, and `UserData` types
- Audited and cleaned up `#[allow(dead_code)]` annotations; gated test-only methods with `#[cfg(test)]`
- Reduced per-request allocations in `ringline-momento` (send 4→1 copies, recv 1→0 copies)
- Use `VecDeque` for gRPC event queue

### Fixed
- Chunk oversized data in copy send path
- Handle SQE submission failures instead of silently discarding
- Correct partial send offset and validate `buffer_size` in `SendRecvBuf`
- Conditional `inc_pending_notifs` in shutdown ZC handler
- Reset streams above `last_stream_id` on GOAWAY
- Add generation check to send retry resubmission
- Drop `DiskIoFuture` waiter entry on future drop
- Mark connection disconnected on send failure in redis/memcache
- Split DATA frames exceeding remote `MAX_FRAME_SIZE` in HTTP/2
- Clear pending on error and fix HPACK table size target in momento/h2
- Consume trailer section in chunked transfer encoding
- Prevent `num_blocks=0` underflow in NVMe read/write commands
- Wake send waiter on copy retry failure
- Replenish recv buffer on stale connection CQE
- Fix non-ZC and ZC chain send resource leaks
- Retry partial ZC send resubmission on next tick when SQ full
- Unregister provided buffer ring before munmap on shutdown
- Return errors from TLS connection creation instead of panicking
- Handle timer pool exhaustion gracefully instead of panicking
- Clear waiter flags when `SendFuture`/`ConnectFuture` are dropped
- Clear pending queue on `recv()` read error in redis/memcache
- Retry accept on `ECONNABORTED`/`ECONNRESET`/`EPERM`
- Retry eventfd re-arm on SQ-full failure
- Check both flow control windows before consuming either in HTTP/2
- Only increment ZC `pending_notifs` on successful send
- Set `recv_mode` to Multi for plaintext outbound connections
- Track UDP send errors and drain ZC slab on shutdown
- Use `read_unaligned` for cmsghdr and timespec parsing
- Drop projected `Pin<&mut F>` before overwriting `MaybeDone`
- Avoid Stacked Borrows violation in `poll_ready_tasks`
- Prevent duplicate error events on frame decode failure in HTTP/2
- Propagate pool exhaustion during TLS output flush
- Return parse error on malformed HTTP/1.1 response headers
- Close connection on intermediate TLS send failure
- Wake waiters before closing connection on TLS recv error
- Return `Consumed(len)` on fatal parse errors to prevent task hang

## [0.0.2] - 2026-02-21

### Added
- `ringline-redis` — Redis client with RESP protocol, sharded pools, and Redis Cluster support
- `ringline-memcache` — Memcache client with binary protocol and ketama-based sharded pools
- `ringline-quic` — QUIC transport layer
- `ringline-h3` — HTTP/3 framing layer (QPACK, Huffman, QUIC frame codec)
- Instrumented client wrappers for Redis and Memcache with per-request latency callbacks and optional histogram metrics
- Zero-copy SET operations via `SendGuard` for both Redis and Memcache clients
- `direct_io_write` and `nvme_write` async free functions

### Changed
- Replaced local `resp-proto`, `memcache-proto`, and `ketama` crates with published crates.io dependencies

### Fixed
- Added `workflow_call` trigger to CI for reusable workflow support
- Resolved clippy `type_complexity` warnings in instrumented clients

## [0.0.1] - 2026-02-21

### Added
- Initial release
- Thread-per-core io_uring runtime with CPU pinning
- `AsyncEventHandler` trait with RPITIT `on_accept` for one-task-per-connection
- `ConnCtx` async API: `send()`, `send_nowait()`, `with_data()`, `with_bytes()`
- `ParseResult` enum for recv closure return values
- Outbound TCP connections via `connect()` and `connect_with_timeout()`
- UDP support via `on_udp_bind()` and `UdpCtx`
- Timer primitives: `sleep()`, `timeout()`, `sleep_until()`, `timeout_at()` with fallible variants
- Standalone tasks via `spawn()`
- Zero-copy sends with `SendGuard` trait and `GuardBox` inline storage
- Scatter-gather sends via `send_parts()` builder
- `ConfigBuilder` with builder pattern and `build()` validation
- `RinglineBuilder` for launching workers with optional TCP listener
- TLS via rustls (always enabled)
- NVMe passthrough via io_uring
- Direct I/O (O_DIRECT) file reads via io_uring
- `select()` / `select3()` and `join()` / `join3()` combinators
