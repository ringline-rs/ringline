# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [ringline-memcache 0.7.1] - 2026-09-04

Documentation-only patch release. No change to code, tests, or behavior.

## [0.6.1] - 2026-09-04

Core-only patch release: **ringline 0.6.1**. No client crate changed since
0.6.0, so they stay at their published versions (`ringline-redis` /
`-memcache` 0.7.0; `-ping` / `-http` / `-grpc` / `-quic` / `-h2` / `-h3`
0.6.0) and pick this up through their `ringline = "0.6"` requirement.

Headline is the io_uring liveness fix below -- a worker reaped no completions
at all while any task stayed runnable, which could hang a worker outright.
`submit_batch_await` also returns.

Also included, with no user-visible change: `tls.rs` is split into
`tls/mod.rs` + `tls/buffered.rs` with a new crate-private `CiphertextBuf`
(#338), groundwork for the unbuffered TLS send path designed in #339.

### Added

- `AsyncSendBuilder::submit_batch_await` is back (both backends), returning a
  `SendFuture` alongside the submitted part count. 0.3.0 (#231) removed it as
  dead code along with `build_await`; it was not dead, just used out of tree
  (crucible's cache server), and nothing in the API replaces it. A caller that
  wants to know when a scatter-gather send has completed -- to pace itself
  against the wire rather than filling the per-connection send queue as fast
  as it can build responses -- has only `send()`, which copies the payload and
  so gives up the zero-copy guard path that motivates gather sends in the
  first place, or `send_chain()`, which is `#[cfg(has_io_uring)]` and so
  unavailable to anything that also builds on mio.

  This also restores the `nowait`/await symmetry the rest of the send API has
  (`send_nowait`/`send`, `send_chain_nowait`/`send_chain`); the gather path
  was the one place a caller could submit but not await.

  A batch that is empty or carries no bytes is now rejected with
  `InvalidInput` rather than returning a future that no completion could ever
  wake (the pre-0.3.0 version rejected only the empty-`Vec` case).
  `build_await` stays removed -- it really was unused.

### Fixed

- **io_uring: a worker starved of all completions while any task stayed
  runnable.** Two individually-sound optimizations composed into a liveness
  bug. The event loop declines to block when a task is ready
  (`min_complete = u32::from(ready_queue.is_empty())`), and the io-uring
  crate's `submit_and_wait(0)` does not set `IORING_ENTER_GETEVENTS`;
  separately, `flush()` skips its syscall when the SQ is empty, on the
  reasoning that "the next `submit_and_wait(1)`" would reap. Under
  `IORING_SETUP_DEFER_TASKRUN` (on for every non-SQPOLL ring) the kernel runs
  task_work only on a GETEVENTS enter — so a task that stays runnable without
  queueing SQEs left neither path setting the flag, and the worker reaped
  **zero** CQEs for as long as that task ran: no connections accepted, no recv
  or send completions dispatched, and so no send-pool slots recycled. A
  yield-style retry loop waiting on pool capacity would wait forever, since
  only a completion can free it.

  The loop now calls the new `Ring::submit_and_get_events()` on the
  non-blocking path, which enters with GETEVENTS in the same single syscall
  (delegating to the old behavior on SQPOLL rings, which cannot enable
  DEFER_TASKRUN and post completions eagerly). `flush()`'s shortcut is
  unchanged and now genuinely holds: every event-loop ring entry carries
  GETEVENTS.

  Caught by the new `tests/ready_queue_fairness.rs`, which fails on io_uring
  before this change and passes after; the mio backend was never affected.

- Documentation: `poll_ready_tasks` in both event loops claimed that entries
  appended to `ready_queue` mid-pass come from "wake_task() called from within
  a polled future, which pushes directly to executor.ready_queue". That is true
  only of the *internal* `wake_task` path. A `std::task::Waker` -- what a
  future gets from its `Context`, and so what any yield-style self-wake uses --
  pushes onto the thread-local queue in `runtime/waker.rs` instead, and reaches
  `executor.ready_queue` only via `collect_wakeups()` after the pass has ended.
  The comment read as though a self-woken task is re-polled within the same
  pass, monopolizing the worker; it is not, and that misreading sent the
  starvation diagnosis above down the wrong path at first.

## [0.6.0] - 2026-09-03

Coordinated breaking release carrying four batched API changes (see Changed)
and memcache binary protocol support. Crate versions: **ringline 0.6.0**;
**ringline-redis / -memcache 0.7.0**;
**ringline-ping / -http / -grpc / -quic / -h2 / -h3 0.6.0**.

### Added

- `ringline-memcache`: **binary protocol support**, via
  `ClientBuilder::build_binary()`, which returns a new `BinaryClient`.
  `fire_get`/`fire_set`/`fire_set_with_guard`/`fire_delete` frame requests
  with the memcache binary protocol and responses are parsed from the 24-byte
  binary header, mapped back into the existing response representation so
  `recv()`, timing, and callbacks stay protocol-agnostic. Request/response
  correlation is FIFO (opaque is always 0), matching the ASCII path, and the
  zero-copy guarded-SET path is supported. This makes binary-only servers
  reachable and benchmarkable.

  The binary protocol implements the fire/recv pipelining API only, and that
  boundary is enforced by the type system: `BinaryClient` exposes just that
  API, so the ASCII request/response methods (`get`, `set`, `gets`, `add`,
  `replace`, `incr`, `decr`, `append`, `prepend`, `cas`, `delete`,
  `flush_all`, `version`, `set_with_guard`, `set_stream`, `get_stream`,
  `get_cas`) are absent from it rather than failing at runtime. `Client` is
  unchanged and stays ASCII; `build()` still returns one.

### Changed

- **Breaking (batched for the next release):** `ConnCtx` is no longer `Send` or
  `Sync`. Ringline is thread-per-core: each worker owns its own driver and
  `ConnectionTable`, and a `ConnCtx` is an `(index, generation)` pair into
  *that* worker's table. Moving one to another worker did not fail loudly —
  the index is still in bounds there, so it resolved against a different
  table, and a matching generation meant I/O landed on an unrelated
  connection: a silent wrong-socket write. That is now a compile error. It
  also makes capturing a `ConnCtx` in a `spawn_blocking` closure a compile
  error, which is correct (its pool threads have no driver); `spawn` is
  unaffected, as it requires only `'static`, not `Send`. No runtime cost —
  the opt-out is a zero-sized `PhantomData<*const ()>` field, which is how a
  type declines these auto traits on stable Rust (`impl !Send` remains
  nightly-only, rust-lang/rust#68318). Code that legitimately needs to reach
  another worker should send the data, not the handle.

- **Breaking (batched for the next release):** `PoolConfig` in `ringline-ping`,
  `ringline-redis`, `ringline-memcache`, and `ringline-http` is now opaque:
  construct with `PoolConfig::new(...)` (required parameters) plus chained
  setters (`connect_timeout_ms`, `tls_server_name`, and for redis
  `password`/`username`) instead of struct literals. Aligns the client crates
  with the workspace's no-public-fields API principle; adding a pool option is
  no longer a breaking change.

- **Breaking (batched for the next release):** `ringline-h2`'s `H2Error` and
  `H2Event`, and `ringline-http`'s `HttpError`, `Protocol`, `Body`, and
  `StreamingResponse`, are now `#[non_exhaustive]`, matching the other
  protocol crates' error/event enums and grow-prone value enums — adding a
  variant is no longer a breaking change. External matches on these enums
  need a wildcard arm (construction is unaffected). `ErrorCode` and `Frame`
  stay deliberately exhaustive (RFC-fixed; unknown wire values fold to
  `InternalError` / `Frame::Unknown`), and `ringline-h2`'s wire-level value
  structs (`FrameHeader`, `Priority`, `Settings`, `HeaderField`) keep their
  public fields as a documented sans-IO stance.

- **`recv_accumulator_max` now defaults to 1 GiB (was unbounded).** A peer
  that streams data without ever completing a message now gets its connection
  closed at the cap instead of growing a worker's memory without limit. The
  default is deliberately above Redis's `proto-max-bulk-len` default
  (512 MiB) because the protocol clients (`ringline-redis`,
  `ringline-memcache`) parse whole replies from the accumulator — a reply
  larger than the cap (including a large aggregate like `MGET`/`LRANGE`)
  closes the connection. Raise the cap (or restore `usize::MAX`) via
  `ConfigBuilder::recv_accumulator_max` if you expect replies above 1 GiB;
  servers facing untrusted peers should set something much smaller. Values
  below `recv_buffer_size` are now rejected at config validation.

### Fixed

- `ringline-memcache`: binary mode skipped client-side key validation, so the
  documented `MAX_KEY_LEN` (250) / `Error::KeyTooLong` contract silently did
  not hold in binary mode. Binary framing writes the key length into a
  `u16` header field, so an over-long key wasted a round trip and a key of
  64 KiB or more wrapped that field while the full key still went on the wire
  — desyncing the connection permanently. All four binary request paths
  (`fire_get`, `fire_set`, `fire_delete`, and the guarded-SET prefix) now
  validate the key before appending any bytes, so a rejected request leaves no
  partial frame in the write buffer and registers no guard or pending op.

- `ringline-grpc`: `max_message_size = usize::MAX` (the "cap disabled" idiom)
  made the gzip/zstd decompression limit wrap to zero in release builds —
  every compressed message silently decoded as an empty payload (debug builds
  panicked on the overflow). The limit now saturates.

- io_uring: after a connection's Close SQE is submitted, no new send SQEs are
  pushed for it: late CQEs (partial resubmits, POLLOUT arms) release their
  resources and fail the waiter, and new sends/`shutdown_write` from handler
  callbacks are rejected with `NotConnected` instead of racing the in-flight
  Close. The `close_submitted` flag distinguishes this from half-close (peer
  FIN with legitimate sends still flowing), which is unaffected.
- io_uring: send-family CQEs are now validated against the connection
  *generation* before touching per-connection state, closing a
  misattribution window where a Send CQE that outlived its connection slot
  (a close racing an in-flight send) could be credited to whatever
  connection reused the index — worst case resubmitting the dead
  connection's bytes onto the new occupant's socket, or spuriously
  failing/draining its sends. Pool-slot ops (`Send`/`TlsSend`/`SendPollOut`)
  carry a truncated generation in the UserData payload; slab-backed ops
  (`SendMsgZc`, coalesced, recv-forward) record it in the slab entry.
  Per-connection send state is now also reset when a slot is reactivated:
  previously a reused slot could inherit `in_flight`/`close_pending` from
  its prior occupant's orphaned close — cleanup that had accidentally
  depended on the very misattribution these checks remove.
- io_uring: closed the two producers of such orphaned CQEs. `close_connection`
  no longer cancels an active `send_chain`'s accounting — the deferred Close
  now waits for the chain's in-kernel SQEs to drain. `DriverCtx::close` no
  longer forces `in_flight = false` and submits Close directly; it defers
  through the same `close_pending` path as `close_connection`, so queued and
  in-flight sends drain first (queued bytes now reach the wire instead of
  being dropped). TLS `close_notify` is serialized through the per-connection
  send queue instead of raw linked SQEs, and its timeout deadline —
  previously dead code — now force-closes a connection whose drain is stuck.
- mio backend: a plaintext connection that overflowed `recv_accumulator_max`
  dropped the overflowing bytes and kept the connection alive in a
  read-and-discard spin instead of closing it. Overflow now closes the
  connection, matching the io_uring backend and the mio TLS path. (Latent —
  unreachable with the previous unbounded default.)

## [0.5.5] - 2026-08-19

Coordinated client release picking up parser fixes from the protocol crates.
Core `ringline` has no functional change this cycle; it is bumped to carry the
release. `ringline-redis` 0.6.7, `ringline-memcache` 0.6.6, `ringline-ping`
0.5.3. Other crates unchanged (h2/h3/quic/http/grpc 0.5.2).

### Fixed

- `ringline-redis`: `resp-proto` 0.0.2 fixes RESP line framing. Both scanners
  inspected only the first `\r` in the buffer and gave up if it was not
  followed by `\n`, so a complete, CRLF-terminated line containing a stray `\r`
  reported `Incomplete` forever and stalled the connection. Reachable in
  practice: Redis keys are binary-safe and error replies echo user-supplied
  arguments. 0.0.2 also bounds protocol line length, so a peer that never sends
  a newline can no longer make the parser buffer without limit.
- `ringline-redis`, `ringline-memcache`: `ketama` 0.0.2 rejects ring
  configurations that previously misrouted or panicked -- more than `u16::MAX`
  nodes silently wrapped shard indices, and a ring whose nodes all had weight 0
  built successfully and then panicked inside `route`.
- `ringline-memcache`: `memcache-proto` 0.0.5 makes `ParseOptions::max_line_len`
  saturate instead of overflowing.
- `ringline-ping`: `ping-proto` 0.0.2 bounds response line length.

## [0.5.4] - 2026-08-19

Coordinated release covering a core startup-lifecycle fix, an HTTP/1.1 framing
overflow found by the new fuzz CI, and a memcache ASCII parser fix pulled in
from `memcache-proto` 0.0.4. Core `ringline` 0.5.4, `ringline-http` 0.5.3,
`ringline-memcache` 0.6.5. Other client crates unchanged (`ringline-redis`
0.6.6; ping/h2/h3/quic/grpc 0.5.2).

### Added

- Fuzzing: eight cargo-fuzz/libFuzzer targets covering the wire-facing parsers
  (h2 frame/HPACK/connection, h3 frame/QPACK, gRPC message/connection, HTTP/1.1
  response), in an excluded `fuzz/` workspace with committed seed corpora, plus
  a daily fuzz CI workflow with cross-run corpus persistence (#263, #303,
  #305, #307).
- `ringline-http`: off-by-default `fuzzing` feature exposing `#[doc(hidden)]`
  wrappers for the crate-private HTTP/1.1 parsers; no internal types are
  exported and there is no behavior change without the feature (#263).

### Fixed

- `ringline-memcache`: bumped `memcache-proto` to 0.0.4, which fixes an ASCII
  response framing bug on the `ResponseBytes` path this crate uses. A response
  line containing a bare `\r` was never framed -- `find_crlf` inspected only the
  first `\r` and gave up if it was not followed by `\n` -- so a complete,
  CRLF-terminated line reported `Incomplete` forever and stalled the connection.
  0.0.4 also bounds response line length, so a peer that never sends a newline
  can no longer make the parser buffer without limit.
- `ringline` (core): listener creation is delayed until every worker has
  completed its fallible backend preparation. A startup failure now rolls back
  partial workers and runtime descriptors before `launch()` returns, allowing a
  caller to retry safely without having exposed a listening socket. Listener
  errors consequently surface only after worker startup and teardown, so errors
  such as `AddrInUse` may take longer to return than before. Errors from a worker
  event loop after the listener becomes live remain observable through its join
  handle.
- `ringline-http`: chunked-decoding arithmetic overflow on a chunk-size line
  near `usize::MAX` (e.g. `FFFFFFFFFFFFFFFc\r\n`). Reachable when
  `set_max_chunk_size` is raised to disable the cap (the default 16 MiB cap
  rejects such sizes first): debug builds panicked on peer-controlled input;
  release builds silently wrapped the chunk length. The framing offsets now use
  checked arithmetic and reject the chunk as invalid. Found by the first
  persistent-corpus fuzz CI run (#308).

## [0.5.3] - 2026-07-23

Coordinated release of two `io_uring` correctness fixes surfaced by the cachecannon
valkey-search harness (cachecannon/cachecannon#116). Core `ringline` 0.5.3 fixes a
multi-chunk send-completion wake race; `ringline-redis` 0.6.6 lifts the recv-side
collection cap. Other client crates are unchanged (`ringline-memcache` stays 0.6.4;
`-ping` / `-h2` / `-h3` / `-quic` / `-http` / `-grpc` stay 0.5.2).

### Fixed

- `ringline` (core): send-completion wake race for a logical send larger than one
  send-copy pool slot (16 KiB). Such a send is split into several chunks serialized
  through the per-connection send queue, but a connection has a single send waiter;
  it was woken on the *first* chunk's completion (a short byte count) and consumed, so
  the remaining chunks' completions found no waiter and were dropped, hanging a caller
  awaiting the full logical send. Each logical send's final chunk now carries an
  `end_of_send` marker and the waiter is woken exactly once, on that completion, with
  the whole logical byte count — while independent pipelined sends on one connection
  still each wake with their own count. Timing/kernel-sensitive: deterministic on
  Linux 6.1 aarch64, masked on 6.12 x86. (#299)
- `ringline-redis`: `read_value` (behind `Client::cmd` and `Pipeline::execute`) no
  longer caps array replies at resp-proto's 1024-element default, which surfaced as a
  `CollectionTooLarge` protocol error that closed the connection on a large `LRANGE`,
  an `FT.SEARCH` with large `k`, or a `SCAN` batch that overshot `COUNT`. The
  collection caps are lifted to a bounded `1 << 20` — not `usize::MAX`, since array
  parsing pre-allocates `Vec::with_capacity(announced_len)`, so an uncapped limit
  would be an OOM vector on a hostile announced length. (#298)

## [ringline-redis 0.6.5] - 2026-07-22

Per-crate patch release (`ringline-redis` only; other crates unchanged). Adds
RESP3 null handling to the GET reply parser so a `HELLO 3` connection classifies
a GET miss correctly instead of erroring.

### Fixed

- `ringline-redis`: `parse_get_header` now treats the RESP3 null header (`_\r\n`)
  as a GET miss (`GetHeader::Nil`), matching the RESP2 `$-1\r\n` behavior.
  Previously a GET miss on a RESP3 (`HELLO 3`) connection hit the catch-all and
  surfaced as `UnexpectedResponse`, poisoning the connection on the borrow/segments
  path. Waiting for the CRLF means all three GET drain paths (io_uring state
  machine, mio drain, sequential borrow) consume the 3-byte frame exactly, so no
  call-site changes were needed. SET/DEL were already correct via `read_value`
  (RESP3 null decoded through resp-proto's `resp3` feature). (#294)

## [0.5.2] - 2026-07-21

Coordinated minor release (additive — no breaking API changes). Core `ringline` 0.5.2 lands segmented zero-copy recv (Modes A/B/C) + occupancy; `ringline-redis` and `-memcache` 0.6.4 add the streaming/borrow clients (`recv_meta`, `get_stream`/`set_stream`, `OpKind`/`RespMeta`, memcache `get_cas`). Other client crates unchanged since 0.5.1 (`ringline-ping` / `-h2` / `-h3` / `-quic` / `-http` / `-grpc` stay 0.5.2).

### Added

- `ringline-redis`: streaming GET — `Client::get_stream(key) -> Option<ValueStream>`
  (single-connection `Client` only). The value body is delivered over the
  runtime's segmented-recv API instead of being materialized: `ValueStream`
  exposes `len()`, `discard()` (consume without a gather copy), `next_segment()`
  (owned chunks), and `collect()` (the one materialization). Bounded to the
  parsed bulk length with an error on a short FIN; dropping a stream mid-value
  poisons (closes) the connection. io_uring only. Pooled/sharded/cluster `get`
  stay materialized. (`recv_streaming` fire/recv integration is deferred.)
- `ringline-memcache`: streaming GET — `Client::get_stream(key) -> Option<StreamValue>`
  (single-connection `Client` only). Mirrors the redis streaming API for the
  memcache wire format (`VALUE <key> <flags> <bytes>\r\n<data>\r\nEND\r\n`):
  the client parses the `VALUE` header, then streams the `<bytes>` value body
  over the runtime's segmented-recv API. `StreamValue` exposes `flags()`, `len()`,
  `discard()` (consume without a gather copy), `next_segment()` (owned chunks),
  and `collect()` (the one materialization). Bounded to the parsed length with an
  error on a short FIN; dropping a stream mid-value poisons (closes) the
  connection. A miss (bare `END\r\n`) returns `Ok(None)`. io_uring only. The
  multi-key `gets(keys)` stays eager; pooled/sharded `get` stay materialized.
- `ringline-memcache`: streaming get-with-CAS —
  `Client::get_cas(key) -> Option<CasStreamValue>` (single-connection `Client`
  only). The CAS-carrying mirror of `get_stream`: issues `gets <key>`, parses the
  5-token `VALUE <key> <flags> <bytes> <cas>\r\n` header (CAS exposed via
  `CasStreamValue::cas()`), then streams the value body exactly like `get_stream`
  (bounded to `<bytes>`, `\r\nEND\r\n` trailer, short-FIN error, undrained-drop
  poison). A miss (bare `END\r\n`) returns `Ok(None)`. io_uring only.
- `ringline-redis` / `ringline-memcache`: streaming SET — `Client::set_stream`
  writes a large value from a caller-provided `SegmentSource` (a synchronous
  chunk-yielding trait, blanket-implemented for `Iterator<Item = Bytes>`) without
  gathering it into one contiguous buffer. The command framing declares the value
  length up front; the client streams chunks, then reads the reply. `len` is the
  authoritative contract: if the source yields fewer or more bytes, the connection
  is closed and `Error::LengthMismatch` is returned (a partial frame is already on
  the wire — the same poison discipline as the read side). Single-connection
  `Client` only; works on both backends (v1 copies each chunk into the send pool —
  zero-copy guarded streaming is a later optimization).
- `ConnCtx::end_segments()` — end segmented-recv delivery and restore the default
  `with_data`/`with_bytes` read path (gathering any still-held segments into the
  accumulator). io_uring only.
- `ConfigBuilder::forward_hold_cap` (default 64, 2× `MAX_IOVECS`) — per-connection
  held-buffer cap for Mode A `forward_to`. When a forwarding connection's held
  buffers reach the cap (a slow/high-latency sink, or a very large object), its
  multishot recv is cancelled so its TCP receive window closes and the source
  stops sending; the recv is re-armed once writes drain the hold below the cap.
  This bounds one slow forward so it cannot deplete the shared per-worker recv
  ring and `ENOBUFS`-starve other connections. New `forward_throttled` pool metric
  counts throttle events. io_uring only.

## [0.5.1] - 2026-07-17

Coordinated patch release. The fix is in core `ringline`; all client
crates are rebuilt against it and republished (`ringline-redis` 0.6.3,
`ringline-memcache` 0.6.3, and `ringline-ping` / `-h2` / `-h3` /
`-quic` / `-http` / `-grpc` 0.5.2). No client-crate API changes.

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
