# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `RecvAccumulator`: receiving a large response streamed across many recv
  completions no longer re-copies the entire accumulated buffer on every
  chunk (O(N·K) for an N-byte value in K chunks). Two causes: (1)
  `put_back()` now drops the empty `buf`'s handle to the allocation it
  shared with the frozen remainder (left behind by `take_frozen()`'s
  `split_to`), so `unfreeze()`'s `try_into_mut()` can recover the
  allocation and append only the new bytes instead of falling back to a
  full-remainder copy; (2) hot-path emptiness checks (`dispatch_cqe`
  zero-copy fast path, `WithDataFuture`, wait-readable) use a new
  non-merging `AccumulatorTable::is_empty()` instead of
  `data().is_empty()`, which forced a merge per recv CQE. This also makes
  the in-place-recovery path that `NeedAtLeast` (0.5.0) added to
  `unfreeze` actually reachable — until now `try_into_mut` always failed,
  so the reserve-honoring merge branch never ran. Measured with
  ringline-redis GETs of 64 MiB values (c8gn.16xlarge pair, io_uring):
  69 GB memcpy'd to receive 4.8 GB, single-connection fetch 197 ms
  (2.7 Gbps) → after the fix 0 full-remainder copies, 56 ms (9.5 Gbps,
  the per-flow wire cap); 32 connections: 15.8 → 200 Gbps (NIC line
  rate). 128 KiB pipelined workloads are unaffected (within noise).

## [0.5.0] - 2026-07-17

Coordinated release. Core `ringline` takes a breaking `ParseResult`
change; all client crates are rebuilt against it and republished
(`ringline-redis` 0.6.2, `ringline-memcache` 0.6.2, and
`ringline-ping` / `-h2` / `-h3` / `-quic` / `-http` / `-grpc` 0.5.1).

### Changed (BREAKING)

- `ParseResult` gains a `NeedAtLeast(usize)` variant and is now
  `#[non_exhaustive]`. A length-prefixed parser that has seen its header
  can announce the remaining byte count; the runtime reserves the recv
  accumulator once at full size instead of doubling through a multi-MB
  message arriving in chunks (~2× the payload in avoided memcpy). Only
  code that exhaustively matches `ParseResult` is affected — closures
  that construct it are untouched.

### Added

- `RecvAccumulator::reserve` / `AccumulatorTable::reserve`: record a
  high-water size target honored by every growth site (`append` and the
  freeze-merge path), clamped to `max_size` and cleared when the
  contents drain.
- Graceful degradation for responses larger than the provided recv ring
  (io_uring backend). A connection whose multishot recv parks on
  `ENOBUFS` with a partial message already accumulated now degrades to
  one-shot fallback recvs into pool-owned memory instead of stalling
  until buffers recycle — a parked receiver stops draining the socket,
  so the TCP window closes and the sender stalls for the park's
  duration. Plaintext accumulator-path connections only (TLS, recv
  sinks, zero-copy forward, and direct echo keep the park-until-
  replenish behavior). New metrics: `pool/recv_fallback` submissions
  and `bytes/fallback_received`; the shutdown `[ringline diag]` line
  gains `fallbacks=`. Rig-validated (64KiB ring): 4MB GET 30→216 req/s,
  16MB 1→22 req/s.
- Starved connections holding an unconsumed zero-copy buffer
  (`pending_recv_bufs`) now have the hold flushed to the accumulator on
  the replenish pass, returning its bid to the ring instead of waiting
  for the task to consume it.
- `pool/recv_parked` metric (+ `parks=` in the shutdown diag line) and a
  fix for the `ringline/ring` counter group being undersized (the
  `cqe_unknown_tag` slot never counted).

### ringline-redis 0.6.2

- Incomplete bulk-string replies return `ParseResult::NeedAtLeast`
  computed from the RESP `$<len>\r\n` header, so multi-MB values reserve
  their accumulator once instead of regrowing per chunk.

### Other client crates

- `ringline-memcache` 0.6.2, `ringline-ping` / `ringline-h2` /
  `ringline-h3` / `ringline-quic` / `ringline-http` / `ringline-grpc`
  0.5.1: rebuilt against core 0.5.0. No API changes.

## [ringline-memcache 0.6.1] - 2026-07-16

### Fixed

- Values larger than 1 MiB are no longer rejected client-side. The
  `validate_value` / `validate_value_len` checks (and the
  `MAX_VALUE_LEN` constant) were removed from the encode path —
  memcached's `-I` item-size limit is a tunable server knob, so an
  oversized value now goes on the wire and the server replies with a
  clean `SERVER_ERROR object too large for cache` instead of the client
  second-guessing it. The 250-byte `MAX_KEY_LEN` check is retained (an
  oversized key corrupts the command frame).

### Removed

- `Error::ValueTooLong` variant and the `MAX_VALUE_LEN` constant.
  Non-breaking: `Error` is `#[non_exhaustive]` and the constant is a
  `pub const` downstream can redefine.

## [ringline-redis 0.6.1] - 2026-07-16

### Fixed

- Bulk-string responses larger than 1 MiB no longer fail. `read_value()`
  switched from resp-proto's default `Value::parse_bytes` (which caps bulk
  strings at `DEFAULT_MAX_BULK_STRING_LEN`, 1 MiB) to
  `Value::parse_bytes_with_options` with `max_bulk_string_len: usize::MAX`.
  Previously a larger value from a real Redis server (Redis 7's
  `proto-max-bulk-len` defaults to 512 MiB) hit `BulkStringTooLong` →
  `Error::Protocol` → a deliberate connection close. The runtime
  `RecvAccumulator` capacity remains the genuine backstop.

## [0.4.1] - 2026-07-16

### Security

- Bumped `crossbeam-epoch` 0.9.18 → 0.9.20 in the committed lockfile for
  RUSTSEC-2026-0204 (dev-dependency via criterion; does not affect
  downstream consumers of the published crates).

## [0.4.0] - 2026-07-06

Coordinated breaking release carrying the 2026-07 full correctness audit
(~35 fixes across 11 PRs), two performance phases, and a hardware-verified
NVMe passthrough path. Crate versions: **ringline 0.4.0**;
**ringline-redis / -memcache 0.6.0**;
**ringline-ping / -http / -grpc / -quic / -h2 / -h3 0.5.0**.

### Breaking

- **Breaking:** `nvme_read` / `nvme_write` are now `unsafe fn` — the caller
  must guarantee the buffer is valid, aligned, and outlives the returned
  future. The previous safe signatures allowed safe code to hand the kernel
  a dangling buffer.
- **Breaking:** `sleep` / `timeout` now panic on timer-pool exhaustion, as
  their documentation always stated; use `try_sleep` / `try_timeout` for
  fallible acquisition.

### Fixed

- NVMe passthrough was entirely non-functional: `NVME_URING_CMD_IO` was `0`
  instead of the kernel ioctl encoding (`0xC048_4E80`), so every command
  returned `ENOTTY`. Now hardware-verified (byte-exact LBA reads vs the
  block device) with a read-only smoke test in `examples/nvme_smoke.rs`.
- Executor: waking a parked task via a cloned `std::task::Waker` was fully
  broken (lost wakeups / self-wake deadlock); mpsc channel waiters are now
  FIFO with `Receiver` drop cleanup; cancelled futures deregister their
  waiters.
- TLS (io_uring): ciphertext is serialized through the per-connection send
  queue — concurrent sends could interleave TLS records on the wire
  (`bad_record_mac` at the peer); >64 KiB sends encrypt interleaved with
  draining instead of failing at rustls's buffer cap; `EAGAIN` arms POLLOUT
  instead of dropping records.
- TLS (mio): fixed the long-standing >16 KiB busy-spin; TLS output is
  queued through pending sends with correct close-path flushing.
- Connection lifecycle: deferred-close now finalizes ZC / recv-forward
  sends (fd leaks), retry backoff re-pushes instead of wedging, accept4 is
  woken at shutdown (prompt-relaunch `EADDRINUSE`), pidfd leaks on
  `Spawn` / `WaitFuture` drop are fixed, and NOFILE sizing accounts for all
  workers on mio.
- Disk / NVMe completions: CQE keys are sequence-tagged (stale-slot
  collisions), NVMe completions with positive status words are errors
  instead of silent success, fs `stat` results are keyed consistently.
- UDP: GRO-coalesced datagrams split correctly in `recv_from` /
  `with_datagram`; recv-buffer bids replenish on error CQEs; connect
  timeout CQEs check the connection generation.
- Protocol clients: responses could be misattributed after a direct send
  (`flushed_count`); cluster topology refresh continues past dead nodes;
  TTFB is stamped after the read; redis closes the connection on protocol
  errors.
- io_uring submit: `EINTR` retries, `EBUSY` treated as backpressure.

### Added

- `ConnCtx::eof_truncated()` — distinguishes a peer FIN mid-message from a
  clean close.
- `ConfigBuilder::no_fs()` and `close_notify_timeout_ms`.
- `examples/nvme_smoke.rs` — read-only NVMe passthrough hardware check.
- `docs/send-completion-design.md` — why CQE-skip is unsound for pool-backed
  sends, MSG_WAITALL rationale, and io_uring zero-copy-RX scoping.

### Performance

- Accumulator rewind: `with_bytes` put-back is O(1) via refcounted
  remainders (pipelined parse microbenchmarks −43% to −92%); "0-copy recv"
  now holds for pipelined parsing.
- Guard batching: `MAX_GUARDS` 4→8 and chained sub-threshold guard sends
  fold into copied sends — measured **−10% client CPU at NIC line rate** on
  guarded 8 KiB SET pipelines.
- TLS sends encrypt directly into send-pool slots (3 copies → 2).
- `MSG_WAITALL` on stream sends: short sends retry in-kernel (5.19+)
  instead of a CQE → resubmit → CQE round trip.
- Event-driven `ENOBUFS` re-arm ends recv-starvation spinning; buffer
  replenishment is flushed before blocking waits.
- mio backend: per-iteration O(n) scans (pending sends, completions, both
  timer scans) replaced with dirty-lists and a timer min-heap.
- Sharded / cluster clients reuse encode buffers and use `itoa` on hot
  paths.
- SMT-aware worker pinning: one worker per physical core regardless of
  sibling enumeration order.

### Changed

- On io_uring, `udp_recv_queue_capacity` is clamped to the recv ring size —
  queued datagrams pin ring buffers, so the excess depth was unusable
  (overload now surfaces as counted drops instead of a silent stall).
- `core_offset` indexes physical cores when `core_offset + workers` fits
  the machine's physical core count (raw logical ids otherwise).

## [0.3.0] - 2026-06-25

Coordinated breaking release. Crate versions:
**ringline 0.3.0**; **ringline-redis 0.5.0**, **ringline-memcache 0.5.0**;
**ringline-ping / -http / -grpc / -quic / -h2 / -h3 0.4.0**.
Headline: the public API surface is simplified and made opaque (see Breaking),
on top of the 0.2.1 performance-audit work.

### Breaking

- **Breaking:** removed the unused `AsyncSendBuilder::build_await` and
  `AsyncSendBuilder::submit_batch_await` methods (use `build` / `submit_batch`
  with an awaited `SendFuture` if needed), and unexported the internal
  `MAX_IOVECS` / `MAX_GUARDS` constants (they are no longer part of the public API).
- **Breaking:** `Config` fields are now private; construct and configure it via
  `ConfigBuilder` (e.g. `ConfigBuilder::new().workers(8).tcp_nodelay(true).build()?`).
  Direct struct construction / field mutation and `ConfigBuilder::config_mut()` are
  removed. This ensures `Config::validate()` always runs. `Config::default()` is unchanged.
- **Breaking:** `Error` and `UdpSendError` are now `#[non_exhaustive]` (match arms must include `_`).
- **Breaking:** `TlsInfo` fields are private; read them via accessor methods
  (`protocol_version()`, `cipher_suite()`, `alpn_protocol()`, `sni_hostname()`).
- **Breaking:** construct `TlsConfig` / `TlsClientConfig` via `::new(...)` instead of struct literals;
  their fields are now private.
- **Breaking:** `WorkerConfig` and `RecvBufferConfig` are no longer exported; configure workers and
  recv buffers via the `ConfigBuilder` setters (`workers`, `pin_to_core`, `core_offset`, `recv_buffer`).

## [0.2.1] - 2026-06-13

Coordinated release of the 2026-06 performance audit:
**ringline 0.2.1**, **ringline-redis 0.4.0**, **ringline-memcache 0.4.0**.

### Removed

- The `ringline-momento` client crate has been removed.

### Added

- The memcache client gained an opt-in write-coalescing layer (`ClientBuilder::max_batch_size`):
  multiple `fire_*` commands batch into a single send, matching the redis client. Defaults to 1
  (no coalescing) so existing behavior is unchanged.
- `Config::send_zc_threshold` (and `ConfigBuilder::send_zc_threshold`) — guard
  sends with total length below this threshold (default 4096 bytes, `0` =
  always zero-copy) are gathered into the send copy pool and submitted as a
  plain `Send` instead of `SendMsgZc`.
- The send copy pool now increments the `send_exhausted` pool metric when it has
  no free slot, giving visibility into send-side backpressure (previously the
  pool returned empty silently).

### Changed

- TLS recv decrypts directly from rustls into the connection accumulator via
  `BufRead::fill_buf`/`consume`, removing the per-worker 16 KiB scratch buffer and
  one copy of every received plaintext byte (was rustls -> scratch -> accumulator,
  now rustls -> accumulator).
- redis/memcache clients gained `ClientBuilder::zc_threshold` (default 4096): `fire_set_with_guard`
  values below the threshold are copied into the coalescing send buffer so they batch like plain
  SETs instead of taking the scatter-gather guard path (which flushed every few ops), recovering
  ~17% throughput on small pipelined SET workloads. Larger values keep the zero-copy guard path.
- The io_uring event loop skips the `io_uring_enter` syscall in `flush()` when no
  SQEs are queued; deferred task_work and completions are reaped by the next
  `submit_and_wait`, removing a redundant syscall on iterations that produce no sends.
- The mio-backend TLS send path encrypts directly into the owned send buffer
  instead of encrypting into shared scratch and cloning, removing one ciphertext
  copy per TLS send.
- ringline-redis and ringline-memcache encode paths no longer heap-allocate per
  request: commands encode into a reusable per-client buffer (or directly into
  the coalescing write buffer), guard-SET prefixes append in place, and integer
  formatting uses `itoa`. Wire format is byte-identical (golden-tested).
- Small guard sends no longer pay zero-copy bookkeeping (in-flight slab entry
  plus a ZC notification CQE per send). For small values the memcpy is cheaper
  than the two-completion lifecycle, removing a small-value `SET` throughput
  plateau observed in benchmarks. Sends at or above the threshold, sends that
  don't fit a send pool slot, and TLS sends are unchanged.
- Event-loop wall-clock stall instrumentation (the `[ringline stall]` shutdown
  report) is now opt-in via the `RINGLINE_LOOP_DIAG` environment variable. The
  per-iteration `Instant::now()`/`elapsed()` reads it required are skipped by
  default, removing ~4 clock reads per event-loop iteration on the hot path.
  The `[ringline diag]` iteration-mix counters remain always-on.
- `with_bytes` zero-copy parsing avoids a per-parse heap allocation when
  stashing the unconsumed remainder: `take_frozen()` detaches via `split_to`,
  so the prepended remainder reuses the allocation's tail capacity instead of
  allocating a fresh buffer. `WithBytesFuture` also drops two redundant
  connection-table lookups per poll.
- `CancellationToken` futures register as a waiter once instead of rescanning
  the waiter list on every poll (O(1) vs O(n)).
- io_uring event-loop memory traffic reductions on the hot path: the CQE drain
  batch no longer carries the unused 16-byte `big_cqe` extended payload per CQE;
  the six per-tick send-retry drains reuse a swap-buffer instead of heap-
  allocating a fresh `Vec` whenever retries are pending (SQ-full backpressure);
  and consumed provided recv buffers are now replenished to the kernel ring at
  the end of `drain_completions` (same iteration they were consumed) instead of
  at the top of the next tick, keeping the buffer ring fuller under burst.
- The executor de-duplicates ready-queue entries per poll batch, avoiding
  redundant task-poll passes when many completions target the same connection
  in one drain.

## [0.2.0] - 2026-06-08

### Breaking

- Worker thread count now defaults to **physical core count** (read from sysfs
  topology on Linux) rather than logical CPU count. On hyperthreaded systems
  this halves the default worker count, eliminating HT contention and
  significantly improving per-core throughput. Deployments that relied on the
  logical-CPU default should set `Config::workers(n)` explicitly to restore the
  previous count. `ringline::physical_core_count()` is exported as a public
  helper for callers that want to replicate the new default. (#202)

### Fixed

- `tick_timeout_armed` is now only set to `true` when `submit_tick_timeout`
  actually succeeds. Previously the flag was set unconditionally, so a full
  submission queue at arm time would silently leave the event loop without a
  periodic wakeup timer until the next real CQE arrived.

### Added

- Event-loop diagnostics now emit a `[ringline stall]` line at shutdown alongside
  the existing `[ringline diag]` line. It reports per-worker counts and worst-case
  durations for both the kernel-wait phase (`submit_and_wait`) and the userspace
  work phase (drain, task polling, `on_tick`), split into ≥1 ms / ≥5 ms / ≥10 ms
  buckets. Useful for diagnosing tail latency from OS scheduler preemption or SQ
  contention.

## [0.1.2] - 2026-04-26

### Added

- Safe `read_into` / `write_from` interface for fs io. (#126)

## [ringline-h3 0.2.1] - 2026-04-24

### Fixed

- `H3Connection::send_data` no longer drops body bytes when the peer's flow-control window is tight. Previously the `usize` returned by `QuicEndpoint::stream_send` was ignored, so any partial-write remainder went silently into the void; now it's queued and flushed on subsequent `QuicEvent::StreamWritable` events. `stream_finish` is deferred until the queue drains. (#119)

### Added

- `H3Connection::has_pending_writes(stream)` reports whether queued bytes are waiting for flow-control credit. (#119)
- `H3Connection::send_data_bytes(stream, data: Bytes, fin)` — end-to-end zero-copy send for callers that already hold a `Bytes`. The DATA frame header is the only fresh allocation on the wire path; partial writes and queue spills stay refcounted (no `extend_from_slice`). (#120)

### Changed

- Internal send queue is now `VecDeque<Bytes>`; queued bytes stay refcounted on backpressure (no memcpy on partial writes). All control-stream and request-stream sends route through the same chunks-based path. (#120)
- `ringline-quic` dependency bumped to `0.2.1` for `stream_send_chunks` and the `WriteError` re-export.

## [ringline-quic 0.2.1] - 2026-04-24

### Fixed

- `StreamReadable` is now emitted alongside `StreamOpened` when a stream opens with data in the first frame. quinn-proto's `on_stream_frame` suppresses the Readable event in that exact case; applications waiting on `StreamReadable` before reading would hang for short one-shot messages. (#117)

### Added

- `QuicEndpoint::flush()` drains pending transmits on all connections — call it after `stream_send` / `open_*` so frames don't sit buffered until the next inbound datagram. (#117)
- `QuicEndpoint::stream_send_chunks(conn, stream, &mut [Bytes])` wraps quinn-proto's `SendStream::write_chunks` for scatter-gather zero-copy sends; partial chunks are advanced in place via `Bytes::split_to`. (#120)
- Re-exports `quinn_proto::WriteError` so downstream crates can match on `WriteError::Blocked` without taking quinn-proto as a direct dependency. (#119)

### Changed

- `QuicConfig` now derives `Clone`. All inner state is `Arc`-backed, so cloning stays cheap and one config can drive multiple per-worker endpoints. (#115)

## [0.1.1] - 2026-04-24

### Added

- `UdpCtx::send_ready()` awaits a free UDP send slot. (#116)
- `Config::udp_send_slots` controls per-socket UDP send pipeline depth (default 64). (#115)
- `Config::udp_recv_buffer` configures the dedicated provided buffer ring for UDP multishot recv. (#118)

### Changed

- UDP sends are now pipelined on the io_uring backend — up to `Config::udp_send_slots` datagrams in flight per socket. (#115)
- UDP recv now uses multishot `recvmsg` with a provided buffer ring on the io_uring backend, eliminating per-datagram SQE resubmission and the 65 KiB per-socket recv buffer. (#118)
- Upgraded `metriken` to 0.9 and switched to its built-in `ShardedCounterGroup`; the metrics module now exposes counter groups (e.g. `metrics::UDP.increment(udp::DATAGRAMS_SENT)`) instead of standalone counters. (#114)

### Fixed

- `shutdown_write` is deferred until the per-connection send queue drains, preventing FIN from racing pending sends. (#111)

### Removed

- **Breaking:** `UdpSendError::SendInFlight` variant. The slot ring made it unreachable; exhaustion now uniformly returns `UdpSendError::PoolExhausted`.

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
