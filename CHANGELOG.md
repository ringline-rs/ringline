# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- New crate `ringline-tls-config`, holding `TlsConfig`, `TlsClientConfig`,
  their builders and the `TlsVersion` and `CipherSuite` enums. ringline
  re-exports the types at their old paths and the crate as
  `ringline::tls_config`. `TlsConfig::builder()` takes a certificate chain
  and key, ALPN, `max_fragment_size` and the TLS versions;
  `TlsClientConfig::builder()` takes root certificates or trust anchors
  (for example `webpki_roots::TLS_SERVER_ROOTS`), ALPN, `max_fragment_size`
  and the TLS versions. Both select rustls's *ring* provider explicitly.
  `from_rustls`, `rustls_config` and `ringline::tls_config::rustls` wrap or
  expose a rustls config for what the builders do not cover, such as a
  custom verifier or client certificates. Design:
  `docs/rustls-quinn-forks-design.md`.
- io_uring: an accepted TLS connection can be parked (connection
  rebalancing, #443) once its handshake is done. Its TLS session moves to the
  adopting worker with it, including ciphertext received but not yet
  decrypted, and the handler there reads and sends without a new handshake.
  Plaintext the unbuffered engine decrypted on the send path and has not yet
  delivered counts as unread data, which blocks an offer or a park. A
  handler that already calls `offer_for_park` on TLS connections will now
  see them parked and adopted; before, they were refused. Once the park
  takes the connection, a send on the parking worker returns `NotConnected`
  until the handler's future is dropped.
- `forward_to_conn` on `ConnCtx`, `Connection` and `RecvHalf` forwards the
  next `len` received bytes to another connection on the same worker, on
  both backends. On io_uring it sends from the source's accumulator through
  the sink's send queue; on mio it copies the bytes into sends queued on the
  sink. A TLS sink is refused with `EPROTOTYPE`. On mio the source stops
  reading while the sink has `forward_hold_cap` sends queued.
- `metrics::park_abandon::RECEIVE_ARMED` (14, `op=receive_armed` on
  `ringline/park_abandoned`): a park whose install found a receive, hangup
  poll or hangup peek armed.
- `yield_now()` wakes the calling task and returns `Pending` once, so a task
  that makes many `send_nowait` calls without awaiting anything lets the
  worker poll its other queued tasks and process I/O between batches. Callers
  had each written this future themselves. Tasks woken by I/O or timers
  processed during the yield are polled after the yielding task resumes, and
  the task can resume within the same loop iteration on both backends.
  `tests/ready_queue_fairness.rs` uses it.
- io_uring: a plaintext connection, accepted or from `connect` or
  `connect_unix`, receives into its own accumulator instead of the shared
  provided buffer ring: a one-shot `RECV` into the accumulator's free space,
  armed when a read parks. There is no option to turn it off; a TLS
  connection receives directly too (see Changed). `with_data`, `with_bytes`,
  `with_data_result` and `recv_ready` read it unchanged, without the copy
  from a provided buffer. An idle connection holds a buffer of
  `ConfigBuilder::recv_direct_region` bytes (default 32 KiB), or of
  `recv_accumulator_capacity` if that is larger and at most twice the
  region; a larger message borrows a buffer from a per-worker pool of up to
  `ConfigBuilder::recv_direct_pool_max` free bytes (default 16 MiB) and gives
  it back when nothing is buffered and no `Bytes` read from it is alive. A
  `ConnStream` read arms the receive the same way. `forward_to_conn` from
  such a connection sends each
  received chunk from the accumulator through the sink's send queue,
  zero-copy at or above `send_zc_threshold`. Counters in
  `ringline/recv_direct`. `ConnCtx::is_recv_direct` (also on `Connection`
  and `RecvHalf`) tells whether a connection receives this way.
  - As a client, against Valkey and memcached with 1,000 connections (63 per
    worker), client CPU at a fixed rate was 1.8 to 6.8% lower than the ring
    at 4 KiB pipelined and larger values, and within 1% at 64 B and 4 KiB
    unpipelined. Against memcached with 16,000 connections (1,000 per
    worker) and no rate limit, client CPU per GET was 11% lower at 4 KiB
    depth 16 (two runs) and 12% lower at 64 KiB depth 1 (one run), and 2 to
    4% higher at 64 B depth 1.
  - As a RESP server with 8 workers and no rate limit, GET throughput and
    server CPU per request matched the ring within the run-to-run spread,
    and SET throughput was 6 to 13% higher. At 8,000 connections, GET p99 at
    depth 16 was higher (86 to 94 ms against 68 to 75 ms at 64 B) and
    resident memory was 0.3 to 0.6 GiB higher.
  - These runs were taken on builds without the `POLLRDHUP` poll each
    plaintext connection now arms; its cost is not measured. The server
    runs also predate the single-`sendmsg` multi-slot send. Both ringline
    arms send through the same path, so it is expected to affect them alike;
    this is not measured.
  - See `docs/recv-direct-design.md`.
- `direct_io_fsync` returns a future for an fsync of a direct I/O file. The
  fsync that `DriverCtx::direct_io_fsync` submits has no future, so a task
  could not wait for it.
- `DirectIoOpenOptions`, with `dsync`, and `open_direct_io_file_with` on
  `DriverCtx` and as a task function. A file opened with `dsync(true)` has
  `O_DSYNC`, so each write completes only once its data is on stable storage
  (on Linux).
  On a Linux block device under io_uring, the kernel sends each write with FUA
  when the device supports it, and does not flush the device's whole cache.
  On a Linux block device, the mio backend's `pwrite(2)` is followed by a
  cache flush on every write.
- `ringline-redis`, `ringline-memcache`: `Client::recv_ready` (and
  `BinaryClient::recv_ready`) sends buffered `fire_*` requests and returns a
  future that resolves when bytes of the next reply have arrived or the
  connection has finished receiving. The future does not borrow the client,
  so a caller can fire more requests while it waits, and call `recv` once it
  resolves. Returns `Error::NoPending` with nothing in flight. See
  `docs/send-while-receiving-design.md`, Option A.
- `Connection::recv_arrival` and `RecvHalf::recv_arrival` return a
  `RecvArrival`: when the first and the last byte consumed by the
  connection's most recent reader call arrived. The reader calls are
  `with_data`, `with_data_result`, `with_bytes` and `try_with_data`. An
  arrival time is the
  time of the batch in which the worker handled the receive that delivered
  the byte: one pass over the reaped completions on io_uring, or over the
  readable sockets on mio. Each TCP connection keeps a log of arrival times
  against stream offsets, of at most 1024 entries of 24 bytes. The
  `ringline/recv_arrival` metric group counts lookups outside the log and
  merges at the cap. The log is always on, at an estimated 1–3% of server
  CPU per request: in an A/B of a 64-byte echo server with an earlier
  version of the lookup, the median paired rise in server CPU per request
  was 1.3% to 3.0% in three of four closed-loop cells, at 4,096 connections
  through lower throughput at about the same server CPU time. In the
  open-loop 4,096-connection cell, where that difference would have read as
  about +2%, it measured +0.2%. With the current lookup, paired runs at one
  cell gave a median of +0.4%, too spread to exclude 2.5%, and a profile
  attributes 0.3–0.4% of the server's samples to the log's own functions.
  See `docs/recv-arrival-times-design.md`.
- `ringline-redis`, `ringline-memcache`, `ringline-ping`:
  `CommandResult::ttlb_ns`, the time from the operation's start to the
  arrival of the response's last byte.
- Three connection counters (`ringline/connections`, `op` label) count three
  ways an accepted connection can be closed before it reaches a handler:
  `accept_table_full` (the worker's connection table was full),
  `accept_register_failed` (the worker could not register the socket), and
  `accept_backlog_dropped` (the acceptor thread found every worker's accept
  queue full). On Linux, a client that has already sent data sees these
  closes as a connection reset (#598).

- `ConfigBuilder::iowq_max_workers` caps the threads in each worker's
  bounded io-wq pool. The kernel sizes that pool at
  `min(sq_entries, 4 × online CPUs)` per worker, and it runs the `shutdown`
  sent ahead of every io_uring connection close (#581) as well as
  regular-file I/O that would block. The default, 0, leaves the kernel's
  limit; a cap only lowers it. A cap at or below a worker's concurrent
  blocking file I/O delays its connection closes (#584).

- `TaskPanicPolicy` and `ConfigBuilder::task_panic_policy` choose what a task
  panic does. `Contain` (the default) catches it, drops the task and keeps the
  worker running, as before. `Shutdown` also shuts the runtime down as
  `Runtime::shutdown` does: the listeners stop accepting, every worker drains and
  exits, `Runtime::wait_on_signal` returns `Signal::TaskPanic`, and each
  worker that saw a panic returns the new `Error::TaskPanicked`. The policy
  covers connection tasks, standalone tasks, the `on_start` and `on_udp_bind`
  futures and the calls that build them, building the `on_accept` future,
  `on_tick`, `on_notify` and `spawn_blocking` closures; not
  `create_for_worker` (whose panic fails `launch()`) or a future's `Drop`
  during the shutdown drain. A task panic while `launch()` is still setting up
  its listeners fails `launch()` with `Error::TaskPanicked`. `JoinError` says
  whether a task panicked or was cancelled and carries the panic payload, so
  a caller can re-raise it; it converts into `io::Error` (#547).

- `Runtime::bound_udp_addr` / `bound_udp_addrs` report the address each UDP
  bind is bound to, with a zero port resolved, as `bound_addr` /
  `bound_addrs` already do for TCP listeners. `bound_udp_addrs` returns
  `Vec<Option<SocketAddr>>`: a connected zero-port bind gives each worker its
  own port and reports `None`.

- `RinglineBuilder::defer_listen` binds a listener without listening on it, and
  `begin_listening` / `begin_listening_all` start it from code on a worker;
  `ListenHandle` (from `Runtime::listen_handle`) does the same from any
  thread; it is `Clone`, and dropping it does not shut the runtime down. The first call opens the listener for every worker. The port is
  reserved while the gate is closed, but the kernel does not complete
  handshakes, so a TCP readiness probe fails while the server is warming up
  instead of passing against a socket nothing will service. On Linux the peer is
  refused with `ECONNREFUSED`; on macOS and the BSDs the SYN is dropped and the
  peer times out. The gate is per listener, keyed by `ListenerId`, so a health
  port can serve while a data port is held back (#534).

  ```rust
  RinglineBuilder::new(config)
      .bind(health_addr)          // serving when launch returns
      .bind(data_addr)
      .defer_listen()             // held until begin_listening
      .launch::<Handler>()?;
  ```

  Not supported with `AcceptMode::Merged` on the io_uring backend, where
  `launch()` refuses the combination. On the mio backend `Merged` already runs
  as `Pool`, so the deferral applies there.

- `ListenerId::from_index` is public. Ids follow `bind()` call order, so a
  listener can be named before any connection has arrived.
- `metrics::recv_ring::BYTES_COPIED` counts bytes copied into receive
  storage (the accumulator and queued TLS plaintext) on both backends.
- `metrics::CQE_BY_TAG`: completions processed, split by `OpTag`, with
  `metrics::cqe_tag::COUNT` sizing the group. The slot index is the tag's
  discriminant, and `CQE_BY_TAG` plus `ring::CQE_UNKNOWN_TAG` partition
  `ring::CQE_PROCESSED` exactly, so the split is arithmetic rather than a
  sample. `ring/cqe_processed` on its own is a single total, and questions
  about per-operation cost reduce to *which* completions: a 64-byte echo
  costs ~0.81 completions per operation at 4 workers and ~1.70 at 8, against
  a ceiling of one recv plus one send, and that total is equally consistent
  with recv batching, send coalescing, or both. The split answers it — both
  halves move together, because the forward path returns each received
  buffer as one send, so a buffer holding *k* pipelined requests costs one
  recv completion and one send completion. A slot whose discriminant no tag
  uses is never registered; a metrics dump reports it as `idxN` at zero
  rather than omitting it (#486).
- `ConnCtx::with_data_result`: like `with_data`, but resolves to
  `io::Result<usize>` so a handler can tell a clean peer close (`Ok(0)`)
  from a transport failure (`Err(e)`, e.g. `ConnectionReset` after an RST).
  Buffered bytes are delivered before the error, and the error is reported
  once. `with_data` is unchanged and still reports `0` for both. First PR of
  the series that lands #318 (design:
  `docs/backpressured-sends-series-design.md`).
- `ConnCtx::send_backpressured` and `BackpressuredSendFuture`: a send that
  waits for send-pool capacity instead of failing when the pool is full.
  Admission is first-come-first-served per worker, so a large message cannot
  be starved by a stream of small ones, and a message that could never fit
  the pool is rejected with `InvalidInput` before it joins the queue rather
  than waiting forever. Nothing is submitted until the future is polled, so
  dropping one you never awaited does nothing; dropping a parked one hands
  the queue to the next waiter. `send` is unchanged and still fails fast —
  use it when a full pool means you would rather shed the message than wait.
  On a TLS connection admission is sized by the *ciphertext* bound. Final PR
  of the series that lands #318.

### Changed

- ringline requires `ringline-tls` 0.1.1. On the unbuffered engine (the
  default), with the ring or aws-lc-rs provider, a TLS 1.3 send through
  `send`, `send_nowait` or `send_backpressured` costs 1 copy instead of 2:
  rustls seals the record in the send-pool slot (io_uring) or the queued
  buffer (mio). `send_parts` and `send_chain` gather their parts first and
  cost 2 instead of 3. On receive, rustls lends each decrypted record from
  ringline's ciphertext buffer instead of copying it out, on either TLS
  version and with any provider. The buffered engine is unchanged; on TLS 1.2
  `send` still costs 2 copies and `send_parts` and `send_chain` 3.
- **Breaking:** TLS and QUIC use ringline's forks of rustls and quinn-proto:
  `ringline-tls` 0.1 (ringline-rs/rustls, a fork of rustls 0.23.46) and
  `ringline-quic-proto` 0.1 (ringline-rs/quinn, quinn-proto 0.11.19 on
  ringline-tls). See `docs/rustls-quinn-forks-design.md`.
  - The builders, `TlsInfo`, `QuicConfig::builder()` and the ringline-quic
    types are unchanged.
  - The escape hatches now name the forks' types:
    `ringline::tls_config::rustls` (and `ringline_tls_config::rustls`) is
    `ringline_tls`, and `ringline_quic::proto` is `ringline_quic_proto`.
    `TlsConfig::from_rustls`, `TlsClientConfig::from_rustls` and
    `QuicConfig::from_proto` take configs built from those. A config built
    with upstream rustls or quinn-proto, or with a crate that implements
    upstream rustls's traits such as `rustls-platform-verifier`, does not
    fit; build it from the re-exported crate instead. `rustls_config()`
    and `quic_resumption()` return `ringline_tls` types, which crates that
    take upstream rustls types (tokio-rustls, quinn) do not accept.
    `TlsVersion::from_rustls` and `CipherSuite::from_rustls` take
    `ringline_tls` values.
  - ringline-quic-proto has no `platform-verifier` feature.
  - ringline, ringline-tls-config and ringline-quic no longer depend on
    `rustls-webpki` directly: ringline-tls 0.1.0 requires 0.103.16 or later
    (RUSTSEC-2026-0382) itself.
- **Breaking:** `ringline-quic`'s public API names no quinn-proto type
  outside `QuicConfig::from_proto` and the `proto` re-export.
  - `QuicConfig::builder()` takes a `TlsConfig` (`server`), a
    `TlsClientConfig` (`client`) or both, the types ringline uses for TCP.
    It sets QUIC's ALPN list (`alpn`), 0-RTT (`zero_rtt`) and the transport
    settings `max_concurrent_bidi_streams`, `max_concurrent_uni_streams`,
    `stream_receive_window`, `receive_window`, `max_idle_timeout`,
    `initial_rtt` and `migration`. ALPN and 0-RTT go on a copy of the TLS
    config. A server accepts 0-RTT by default, as quinn-proto's
    `ServerConfig::with_single_cert` does; a client sends none unless
    `zero_rtt(true)`.
  - `build()` returns `ConfigError` for a TLS config without TLS 1.3 or
    without a cipher suite for QUIC Initial packets. quinn-proto accepts a
    TLS 1.2-only config and panics on the first connection.
  - A client built with `TlsClientConfig::builder()` gets a QUIC session
    store separate from TCP's (`TlsClientConfig::quic_resumption`). rustls
    keys tickets by server name only, so a shared store let TCP and QUIC
    connections to one host take each other's tickets. A `from_rustls`
    config uses its rustls `resumption` for TCP and QUIC alike.
  - `QuicConfig::server`, `client`, `endpoint_config`, `server_config` and
    `client_config` are replaced by the builder and by
    `QuicConfig::from_proto(endpoint, server, client)`, which takes complete
    quinn-proto configs through the new `ringline_quic::proto` re-export.
  - `StreamId`, `VarInt`, `Dir`, `Side`, `ConnectError`,
    `ConnectionError`, `ReadError`, `ReadableError`, `WriteError`,
    `ConnectionStats`, `UdpStats`, `FrameStats` and `PathStats` are
    ringline-quic types. `Error`, `QuicEvent` and the `QuicEndpoint` stream
    methods use them. The stats types hold every field of quinn-proto's,
    read through accessors (`stats.path().rtt()`, `stats.udp_tx().bytes()`)
    in place of public fields. `ringline-h3` uses ringline-quic's
    `StreamId`.
  - `QuicEndpoint::close_connection` takes its code as a `VarInt`, as
    `reset_stream` and `stop_sending` do, in place of a `u32`.
  - `QuicEndpoint::connect` on an endpoint without a client config returns
    `Error::Connect(ConnectError::NoClientConfig)`; before, it returned
    `Error::ConnectionClosed`.
- **Breaking:** `TlsConfig::new(Arc<rustls::ServerConfig>)` and
  `TlsClientConfig::new(Arc<rustls::ClientConfig>)` are replaced by
  `TlsConfig::builder()` and `TlsClientConfig::builder()`, or by
  `from_rustls` with the same argument. `TlsInfo::protocol_version` returns
  `Option<TlsVersion>` and `TlsInfo::cipher_suite` returns
  `Option<CipherSuite>`; a suite the enum does not name is
  `CipherSuite::Unknown` with its IANA code (`CipherSuite::iana_code`).
- TLS 1.2 is enabled. `ringline-tls-config` enables rustls's `tls12`
  feature and the builders accept TLS 1.2 and 1.3 by default; before, a
  build negotiated TLS 1.2 only when another crate enabled the feature.
  `versions(&[TlsVersion::Tls13])` restricts a config to TLS 1.3. TLS 1.2 is
  also enabled in a config built with rustls's `ServerConfig::builder()` or
  `ClientConfig::builder()` and passed to `from_rustls`, because the `tls12`
  feature is enabled for the whole build; restrict it with
  `builder_with_protocol_versions(&[&rustls::version::TLS13])`. A TLS 1.2
  connection with an AES-GCM suite is closed after 2^24 records, because
  TLS 1.2 cannot change its keys.
- io_uring: a TLS connection receives ciphertext directly, with a one-shot
  `RECV` of up to `recv_direct_region` bytes, instead of through the
  provided-buffer ring. With the default (unbuffered) engine the receive
  writes into the buffer rustls processes records in, which removes one copy
  per received byte; with `ringline-tls` 0.1.1 a TLS receive costs 1 copy
  per received byte, from that buffer into the recv accumulator, plus
  `CiphertextBuf::compact`'s move of partial records. With
  `tls-buffered` it writes into a worker buffer that `read_tls` copies from,
  as from a provided buffer before. `ringline/recv_direct` counts TLS
  receives and their bytes. With `tls-buffered`, each TLS receive in flight
  holds a pooled buffer of `recv_direct_region` bytes; the unbuffered engine
  receives into its existing ciphertext buffer. A TLS receive that cannot be submitted
  closes the connection, as a plaintext one does; before, it was retried.
- **Breaking:** the unbuffered TLS engine (rustls' unbuffered API) is the
  default on both backends. The new `tls-buffered` feature selects the
  buffered engine; `tls-unbuffered` has no effect and is kept so builds that
  name it still resolve. The unbuffered engine now reports the SNI hostname
  (`TlsInfo::sni_hostname`): ringline clones each server config and wraps
  its certificate resolver to record the name the ClientHello carries, so a
  `ServerConfig` passed in is not the one the connection uses. On the
  unbuffered engine a TLS record cannot span send-pool slots, so a
  `send_copy_slot_size` smaller than one whole record for a configured
  rustls config is rejected: by `ConfigBuilder::build` for the server and
  client configs, and by `launch()` for a `bind_tls` listener's. One whole
  record is `F + 29` bytes, where `F` is the config's `max_fragment_size`
  minus its 5-byte header: 16413 bytes at the default fragment size, so a
  TLS config with a 16384-byte slot no longer builds. Below that size the
  engine cannot bound in advance how many slots a send uses. The default
  slot (16448 bytes) holds one whole record.
  With the `tls-buffered` feature any slot size works. On io_uring,
  handshake output pays one more copy than on the buffered engine.
- io_uring: a TLS connection's receive is armed when a read parks once
  its handshake is done, as a plaintext connection's direct receive is, so a
  task that does not read stops its peer instead of buffering up to
  `recv_accumulator_max` (1 GiB by default). During the handshake and after
  the peer closes, the receive is re-armed after each completion. A loop that polls
  `try_with_data` without ever parking a read no longer sees new bytes, as
  on a plaintext connection. A TLS connection now arms the `POLLRDHUP`
  hangup poll, so a peer FIN or reset is seen, and `is_alive` returns
  `false`, while nothing reads. The poll does not fire on a close_notify the
  peer sends without closing TCP: that alert is read when a receive next
  completes; on mio it is read when it arrives. `forward_to_conn` from
  a TLS source takes the bytes from the accumulator and sends them through
  the sink's send queue, as from a plaintext source: ordered with other
  sends on the sink, with one chunk buffered, and below `send_zc_threshold`
  copied into a pool slot. A zero-copy send of such a forward to a sink that
  does not read holds worker exit for up to its bound, as any guarded send
  does.
- **Breaking:** `metrics::park_abandon::SLOT_RECYCLED` is 12 and
  `INSTALL_FAILED` 13, after the removal of `DIRECT_ECHO`.
- **Breaking:** on io_uring, every plaintext connection, accepted or from
  `connect` or `connect_unix`, receives directly into its accumulator (see
  Added), and no option gives it the provided-buffer ring. On such a
  connection `try_with_data` returns `None` while a receive is in flight.
  Such a
  connection has a receive armed only when a read parks, and a `POLLRDHUP`
  poll armed when it opens. A FIN or reset from the peer closes a connection
  that nothing reads, and `is_alive` returns `false`. If bytes the peer sent
  before it are queued or buffered, the connection stays open until they
  have been read, and a reset is then reported to the read as an error. A
  poll that cannot be submitted is submitted again before the worker next
  waits for completions, unless the connection is being parked; a peek, once
  nothing is buffered or in flight. A FIN closes the connection even when
  the task only sends. `cancel` finishes the read half and cancels the
  receive in flight. A park (`offer_for_park`) cancels the connection's
  receive and poll before it moves the socket; the adopting worker arms the
  poll, and the reader's next parked read arms a receive.
- ringline-http's HTTP/2 connection reads with `with_data` on every backend,
  which a plaintext connection (`H2AsyncConn::from_conn` over `connect`)
  needs. Over TLS it copies as many bytes as before and allocates less.
- On io_uring, a copy send wider than one send-pool slot (`send`,
  `send_nowait`, `send_backpressured`), and TLS ciphertext from one send
  that fills two or more slots, go to the kernel as one `sendmsg` over up to
  32 of their slots when nothing else is in flight on the connection; with
  the send slab full, the first slot goes alone, as before. Before, the
  first slot always went out as a `send` of its own and the rest followed as
  one `sendmsg` after its completion.
- **Breaking:** `ringline-redis` `ShardedConfig` and `ClusterConfig` and
  `ringline-memcache` `ShardedConfig` have private fields. Build them with
  `ShardedConfig::new(servers)` or `ClusterConfig::new(seeds)` and builder
  methods: `pool_size` (sharded configs), `connect_timeout_ms` and
  `tls_server_name`. ringline-redis also has `password`
  and `username`. An `Option` field becomes a call made only when it is
  `Some`. `new` sets what a struct literal with `pool_size: 1`,
  `connect_timeout_ms: 0` and `None` options did: one connection per
  server, no connect timeout, plain TCP, no AUTH. A `pool_size` of 0 is
  still treated as 1. Adding an option to them is no longer a breaking
  change, as for `PoolConfig`.
- **Breaking:** the public config structs of `ringline`, `ringline-quic`,
  `ringline-h2` and `ringline-h3` have private fields and builder methods,
  as `Config` and `PoolConfig` do:
  - `ringline` `NvmeConfig`, `FsConfig` and `DirectIoConfig`: start from
    `Default::default()` and set `max_devices` (NVMe) or `max_files`, and
    `max_commands_in_flight`.
  - `ringline-quic` `QuicConfig`: built with `QuicConfig::builder()` (see
    the entry for the ringline-quic types above) or `QuicConfig::from_proto`,
    then `send_queue_capacity`, `max_transmit_datagrams`, `allow_mtud` and
    `rng_seed`. The builder refuses a configuration with neither a server
    nor a client TLS config, which could neither accept nor connect.
  - `ringline-h2` `Settings` and `ringline-h3` `Settings`, which decoded
    SETTINGS frames also return: each value has a getter of the field's name
    and a `with_` setter (`with_max_field_section_size`, which the h3 docs
    already named, now exists).
- `ringline` takes `bytes` from the workspace, so it requires 1.11.1 or
  later, as the other crates do. On io_uring a provided-buffer ring's
  buffers are an anonymous mapping instead of a heap `Vec`.
- **Breaking (`ringline-redis`, `ringline-memcache`, `ringline-ping`):**
  `CommandResult` is `#[non_exhaustive]`. Code outside the crates reads it
  in an `on_result` callback and can no longer construct it.
- **Breaking, behaviour (`ringline-redis`, `ringline-memcache`,
  `ringline-ping`):** `CommandResult::ttfb_ns` is `Some` for every
  instrumented operation that read a byte: the time from the operation's
  start to the arrival of the response's first byte, from `RecvArrival`. In
  0.6 it was `None` unless the removed kernel timestamp mode was on. Values
  are not comparable with ones recorded under that mode.
- **Breaking:** every worker has 65536 timer slots, and
  `ConfigBuilder::timer_slots` is removed. The pool defaulted to 256 and could
  be raised to 65535, one fewer than the 16-bit slot field in a timer's
  io_uring completion can name. At 65536 it takes about 1.7 MiB per worker.
  `ringline::TIMER_SLOTS` is the size. Remove `.timer_slots(n)` calls;
  `try_sleep` and `try_timeout` still report a full pool.
- On io_uring, consecutive queued copy sends on one connection, plaintext
  or TLS ciphertext, go out as one `sendmsg` even when they belong to
  different `send` calls (#628); before, each call took its own operation.
  Each awaited send still resolves with its own length, and one whose bytes
  are all sent resolves before the rest of the operation completes. A send
  error on a run that includes TLS ciphertext closes the connection, as a
  failed TLS chunk did before. `ringline/bytes` `sent` now counts TLS
  ciphertext sent in a coalesced run, which it did not count for
  intermediate TLS chunks. With 16-byte responses each sent by
  `send_nowait`, a client pipelining 32 requests per write cost 32 send
  operations per round before this change and 2 after; at depth 1 both
  cost 1.

- On mio, the event loop no longer waits out its idle poll timeout (10 ms
  by default) while a writable connection has sends queued. A task that
  queued a send after the loop's flush, such as one awaiting each send in
  turn, waited for that timeout before its send went out.

- An awaited send resolves with the length its caller passed. Under TLS
  that is the plaintext length: `send().await` used to report the ciphertext
  of the send's last record on io_uring and of all its records on mio, and
  `send_backpressured` the ciphertext on mio. A copy or zero-copy send
  whose completion reports zero bytes now resolves with a
  `WriteZero` error instead of `Ok(0)`, as `send_backpressured` already did.
  A `SendFuture` polled again after it resolved panics; it used to return
  `Pending` (#617).

- The per-operation completion counters (`op` label) for io_uring rename
  `send_msg_coalesced_poll_out` and `send_recv_bufs_coalesced_poll_out` to
  `send_msg_coalesced_drain` and `send_recv_bufs_coalesced_drain`, and add
  `send_msg_zc_drain`. Those operations are now plain sends, not `POLLOUT`
  polls (#603).

- **Breaking (`ringline-quic`):** the `QuicEndpoint` methods that read the
  clock now take `now: Instant` as their first argument, as `flush`,
  `handle_datagram` and `drive_timers` already did: `stream_recv`,
  `stream_recv_into`, `stream_finish`, `stop_sending`, `reset_stream`,
  `close_connection` and `send_datagram`. `batch(now)` also takes it, and the
  outermost guard flushes at that time when dropped; `BatchGuard::set_now`
  updates it for a batch held across an `.await`. The endpoint no longer
  calls `Instant::now()`, so a caller can read the clock once per event-loop
  iteration and a test can drive it on a simulated clock (#572).

- **Breaking (`ringline-h3`):** the `H3Connection` methods that can finish
  a stream, read from one or close the connection take `now: Instant` after
  the endpoint: `send_request`, `handle_quic_event`, `send_response`,
  `send_data`, `send_data_bytes` and `send_trailers` (#572).

- **Breaking:** `ConfigBuilder::sq_entries` must be at least 2: a
  connection's close pushes a linked shutdown and `Close` together (#581).
  `sq_entries(1)` now fails `build()`.

- **Breaking:** `JoinHandle` (from `spawn_with_handle`) and
  `BlockingJoinHandle` (from `spawn_blocking`) resolve to
  `Result<T, JoinError>` instead of `T`. Add `?` (in a function returning
  `io::Result`) or `.expect(..)` to existing awaits. `Err` means the task
  panicked or, for `JoinHandle`, was cancelled (#547).

- **Breaking:** `signal::Signal` is `#[non_exhaustive]` and gains
  `Signal::TaskPanic`, which `Runtime::wait_on_signal` returns when a task
  panic shuts the runtime down under `TaskPanicPolicy::Shutdown` (#547).

- An unconnected port-0 UDP bind on more than one worker now shares one
  port across the workers. A multi-worker UDP client on such a
  bind receives each reply on whichever worker the kernel delivers it to, not
  necessarily the worker that sent the request. A client with one peer per
  bind can use `bind_udp_connected`, which gives each worker its own port
  when the local port is zero. A client that talks to several peers from one
  unconnected bind has no way to get a port per worker.

- **Breaking:** `ShutdownHandle` is renamed `Runtime`, with no alias. It
  controls shutdown, listener addresses, deferred listeners, accept steering
  and registered regions, and dropping it shuts the workers down. Replace the
  type name; its methods are unchanged.

- `AsyncEventHandler::on_start`'s documentation no longer says the future runs
  before accepting begins. It runs concurrently with accepting; the doc now
  says so and points to `defer_listen` for a readiness gate. No behaviour
  change (#534).

- **Breaking:** `connect` and `connect_unix` return builders that resolve to an
  owned `Connection`. `connect_with_timeout`, `connect_tls`,
  `connect_tls_with_timeout`, and the `connect*` methods on `ConnCtx`,
  `Connection` and `SendHalf` are removed. TLS and the timeout are set on the
  builder, and `connect_unix` accepts a timeout for the first time. `UnixConnect`
  has no `tls` method, so TLS over a Unix socket does not compile (#528).

  ```rust
  let conn = connect(addr).await?;
  let conn = connect(addr).tls("example.com").timeout(d).await?;
  let conn = connect_unix(path).timeout(d).await?;
  ```

  `timeout` takes a `Duration`. `Duration::ZERO` arms a timeout that fires
  immediately, so callers that passed `0` to mean "no timeout" must omit the
  call instead. On a TLS connection the window covers the TCP connect, not the
  handshake.

- **Breaking, behaviour:** a connect builder submits on its first poll rather
  than when it is created. Two builders created and then awaited one after the
  other connect serially; pass both to `join` to connect concurrently. This
  matches `sleep` and `send_backpressured`, which also submit on first poll.

- **Breaking:** `join`, `join3`, `select` and `select3` accept `IntoFuture`
  rather than `Future`, so a builder can be passed directly. Every `Future` is
  `IntoFuture`, so existing callers are unaffected.

- **Breaking:** `ringline_redis::Client::{new, builder(..).build()}`,
  `ringline_memcache::Client::{new, build, build_binary}`,
  `ringline_ping::Client::{new, build}` and `H2Conn::from_conn` take a
  `Connection` instead of a `ConnCtx` and no longer return `Result`. Claiming
  the halves was their only fallible step.

- **Breaking:** `Pool::client` returns a `PooledClient` guard instead of an
  owned `Client`. The guard derefs to `Client`, and returns the client to its
  slot when dropped — or marks the slot disconnected if the connection is no
  longer alive, so a poisoned connection is not handed out again. Each slot owns
  its client, so a connection is split once, when it is opened, rather than on
  every checkout. Several clients can be checked out at the same time, as
  before. `client`, `connect_all`, `mark_disconnected` and `close_all` now take
  `&self`, and `lent_count` reports how many connections are checked out. `client`
  returns the new `Error::PoolExhausted` when every slot is checked out, which is
  distinct from `AllConnectionsFailed`; `connect_all` connects only the slots that
  are disconnected, so it can be called again or while clients are out (#528).

- Accept-time placement now hands a connection to an **idle** worker as soon as
  the accepting worker holds one, instead of waiting for a gap of two. The flat
  margin meant a worker first shed on its *third* connection, so when a pooled
  client opened about as many connections as there are workers the placement
  never ran at all — measured on the rack as 2 of 8 workers left idle in 3 of 3
  reps, now 0 in 9 of 9. The margin of two still applies between two non-empty
  workers. Merged accept mode only (#457).

- `Runtime::set_worker_accepting()` takes a worker out of the accept
  rotation, or puts it back, for listeners in `AcceptMode::Merged`. It re-steers
  the `SO_REUSEPORT` group with an unprivileged classic-BPF program rather than
  closing the worker's socket, because closing one resets whatever is already
  queued on it. It does **not** drain: connections already queued on that
  worker are still accepted, and live connections stay where they are. Tier 2
  of `docs/listeners-and-accept-design.md` (#443).

- Merged accept mode now places a connection at accept time instead of taking
  the kernel's 4-tuple hash: a worker that accepts while ahead of the quietest
  peer hands the raw fd over before the connection has any state. This is what
  makes `AcceptMode::Merged` viable for a pooled client, whose connections
  otherwise land by hash. Tier 1 of `docs/listeners-and-accept-design.md`
  (#443).

- `ConfigBuilder::accept_mode(AcceptMode::Merged)` gives each worker its own
  `SO_REUSEPORT` listener and a multishot accept on its own ring, removing the
  acceptor thread, the per-connection channel hop and the wake fd. Default
  stays `AcceptMode::Pool`, whose explicit round-robin placement the kernel's
  4-tuple hash does not match for a pooled client — at N connections over N
  workers roughly 1/e of workers get none. io_uring only, TCP listeners only
  (`SO_REUSEPORT` does not apply to Unix sockets, which keep their acceptor
  thread). Step 3 of `docs/listeners-and-accept-design.md` (#443).

- `RinglineBuilder::bind_tls(addr, TlsConfig)` terminates TLS on one listener
  with its own configuration, so a process can serve plaintext on one port and
  TLS on another, or two ports with different certificates. Previously
  `ConfigBuilder::tls()` was process-wide: every listener had to agree, which
  made the combination unexpressible once `bind()` could be called more than
  once. A listener bound with plain `bind()` still falls back to the
  process-wide config, so existing single-listener TLS setups are unchanged.
  Step 1b of `docs/listeners-and-accept-design.md` (#443).

- **Breaking:** `RinglineBuilder::bind()` and `bind_unix()` now **accumulate**
  listeners instead of overwriting each other, so a runtime can serve any mix of
  TCP and Unix listeners. Previously `bind_addr` was a single `Option`, calling
  both silently discarded the first, and per-connection settings were therefore
  process-global — `tcp_nodelay(true)` was accepted, documented, and then
  suppressed at run time for Unix binds. Each listener now answers for itself.

  Connections carry the [`ListenerId`] of the listener that accepted them,
  exposed as `listener()` on `ConnCtx`, `Connection` and `SendHalf` (`None` for
  outbound), so one `on_accept` can dispatch across listeners. Ids follow
  `bind()` call order. `Runtime` gains `bound_addr_of()`, `bound_addrs()`
  and `listener_count()`; `bound_addr()` still returns the first TCP listener's
  address, so single-listener callers are unaffected at the call site.

  Per-listener TLS is not included — `TlsTable` holds one server config and both
  accept paths gate on it, so keying it by listener is a separate change.
  Step 1 of `docs/listeners-and-accept-design.md` (#443).

- mio: the connection lifecycle now follows io_uring's model. A peer FIN or
  a read error requests teardown immediately (`close_connection`), and
  teardown finalizes once queued sends have drained — a response sent after
  the peer's FIN is delivered in full — after which the connection task is
  dropped. (io_uring itself commits the Close before the task can respond
  when nothing was queued at the FIN; tracked as #371.) Previously a mio task could keep running indefinitely after
  EOF. `RecvMode::Closed` is now set only by `close_connection` on both
  backends. The deferral is unbounded on mio (`close_notify_timeout_ms`
  is inert there). Design: `docs/mio-close-lifecycle-design.md`.

- Internal: connection lifecycle state is now three explicit fields on
  `ConnectionState` (`recv_arm`, `read`, `lifecycle`) instead of
  `RecvMode` doing triple duty; readers use `recv_finished()` and
  `close_requested()`. No observable change except that a connection whose
  receive was cancelled via `DriverCtx::cancel` (io_uring) can now be
  closed afterwards — it used to leak its slot — and reports
  `is_alive() == true` until it is closed. Design:
  `docs/connection-state-model-design.md`.

- Internal: the write half is explicit state on both backends
  (`ConnectionState::write`: `Open` / `ShutdownPending` / `Shutdown`),
  replacing the `shutdown_pending` flag on the send state. No policy
  change: sends after `shutdown_write` still fail at the socket. Design:
  `docs/write-half-design.md`.

### Deprecated

- `DriverCtx::connect`, `connect_unix`, `connect_with_timeout`,
  `connect_tls` and `connect_tls_with_timeout`. No task owns a connection
  opened this way, so the runtime closes it once it is established, and the
  `on_connect` callback their docs described does not exist. Call
  `ringline::connect` (or `connect_unix`) from a task instead;
  `ringline::spawn` starts one from `on_tick` or `on_notify`. They will be
  removed in the next breaking release (#579).

### Removed

- **Breaking:** on io_uring, the TCP provided-buffer ring: TCP and Unix
  connections receive directly (see Changed and Added), and only UDP
  receives through a provided ring. A worker no longer allocates the TCP
  ring's buffers (4 MiB by default) or registers the ring, whose entry array
  (one page by default) Linux 6.14+ charged to `RLIMIT_MEMLOCK`. With it go
  `ConfigBuilder::recv_buffer` and `recv_buffer_bgid`; remove those calls.
  On io_uring, `recv_direct_region` (32 KiB by default) sets the buffer an
  idle plaintext connection receives into and the most ciphertext a TLS
  connection receives at a time; a message larger than that buffer borrows
  a larger one (`recv_direct_pool_max`). On mio, accumulators now start at
  `recv_accumulator_capacity` (4 KiB by default) instead of the
  `recv_buffer` size (16 KiB by default); `recv_accumulator_capacity(16384)`
  restores 0.6's starting size. `recv_accumulator_max` must be at least 1
  instead of at least that size. `pool::BUFFER_RING_EMPTY` counts only the
  UDP ring. Also removed: the fallback receive for messages larger than the
  ring, and the receive throttle for connections whose `forward_recv_buf`
  sends held ring buffers.
  `udp_recv_buffer_bgid(0)` with UDP configured, which 0.6 refused because
  it equalled the TCP ring's default group id, is accepted.
- **Breaking:** the `ringline/pool` counters `recv_parked`, `recv_fallback`
  and `forward_throttled` (`metrics::pool::RECV_PARKED`, `RECV_FALLBACK`,
  `FORWARD_THROTTLED`), and the `fallback_received` counter of
  `ringline/bytes` (`metrics::bytes::FALLBACK_RECEIVED`), which counted the
  TCP ring. The `[ringline diag]` line of `loop_diag` loses its `parks=` and
  `fallbacks=` fields.

- **Breaking:** `ConnCtx::forward_to` and `SinkFd` (io_uring only), which
  wrote a connection's received bytes to a socket or a buffered file, and
  `ConfigBuilder::recv_segment_reserve`, which in 0.6 applied to `forward_to`
  sources and to the segment readers removed below. Nothing replaces
  `forward_to` for a sink that is not a ringline connection: read with
  `with_bytes` and write the bytes. For a connection sink use
  `forward_to_conn` (see Added). `forward_hold_cap` now has no effect on
  io_uring.
- **Breaking:** the segment readers `segments`, `recv_owned_segment`,
  `with_segments` and `end_segments` (on `ConnCtx` in 0.6, io_uring only),
  and the types only they used: `SegmentReader`, `RecvSegment`,
  `RecvOwnedSegment`, `SegChain`, `SegConsumed` and `WithSegmentsFuture`.
  They read held buffers of the provided-buffer ring, which on io_uring only
  a TLS connection receives through. Parse with `with_bytes`, whose parser
  gets the buffered bytes as one `Bytes` it can slice without copying, or
  with `with_data`.
- **Breaking:** `metrics::pool::SEGMENT_STRANDED_ADOPTED`, the
  `segment_stranded_adopted` op of `ringline/pool`, which counted bytes a
  segment reader found in the accumulator.
- **Breaking:** `enable_recv_forward`, `forward_held`, `run_direct_echo`
  (io_uring only, with `DirectEchoFuture`), `set_recv_sink` and
  `take_recv_sink`, wherever `ConnCtx`, `Connection` or `RecvHalf` had them,
  on both backends. On io_uring they read from the provided-buffer ring,
  which no connection receives through any more except a TLS one, where they
  did nothing. On mio `forward_held` worked on every connection and
  `set_recv_sink` on every plaintext one (`enable_recv_forward` did nothing),
  and code that used them there no longer compiles. Echo or forward with
  `with_data` and `send_nowait` or `forward_recv_buf`, or with
  `forward_to_conn`. A recv sink is replaced by copying out of `with_data`
  into the caller's buffer, which on mio is one copy more than the sink.
  On io_uring every replacement for `run_direct_echo` wakes a task per
  receive.
- **Breaking:** `metrics::park_abandon::DIRECT_ECHO` and the `direct_echo`
  op of `ringline/park_abandoned`.
- **Breaking:** `metrics::park_abandon::FORWARD_WRITE` and the
  `forward_write` op of `ringline/park_abandoned`. Slot 8 is unused.
- **Breaking:** `metrics::park_abandon::TLS_SESSION` and the `tls_session`
  op of `ringline/park_abandoned`, which counted parks refused for a TLS
  connection. Slot 5 is unused.
- **Breaking:** the client methods that read a value from provided-buffer
  segments, which a plaintext connection no longer has:
  ringline-redis `Client::get_stream` and `Pool::get_stream` (and
  `ValueStream`),
  `Client::recv_get_discard`, `Client::recv_get_segments` and `GetMeta`, and
  ringline-memcache `Client::get_stream` (and `StreamValue`),
  `Client::get_cas` (and `CasStreamValue`). Use `get`, or `recv_meta` in
  ringline-redis to read a GET reply without keeping the value; for a CAS
  token, ringline-memcache `gets`. ringline-redis `recv_meta` reads a GET
  reply through `with_bytes` on every connection, as it already did on
  mio. No remaining method hands a caller a value's bytes in pieces as
  they arrive; `get` and `gets` return the whole value.
- **Breaking:** the TCP kernel receive-timestamp mode is removed: the
  `timestamps` cargo features of `ringline`, `ringline-memcache`,
  `ringline-redis` and `ringline-ping`, `ConfigBuilder::timestamps`,
  `Connection::recv_timestamp` and `RecvHalf::recv_timestamp`
  (`ConnCtx::recv_timestamp` in 0.6), and `ClientBuilder::kernel_timestamps`
  in the three client crates. A connection held
  one timestamp, which each receive completion overwrote, so with pipelining
  or a task that ran late a response was timed against a later completion's
  timestamp. The send side of each measurement was a user-space
  `CLOCK_REALTIME` read. The mode also replaced the receive path under
  measurement with a separate multishot `recvmsg` handler. That handler
  copied every byte out of the provided buffer (into the accumulator, or a
  recv sink when one was set), lent no buffers, ran only on plain rings, and
  had no TLS or segmented-receive handling. A TLS connection appended
  ciphertext to its accumulator, a `forward_to` longer than the bytes
  already buffered did not complete until the peer closed and then returned
  short, and bytes held for a segment reader could be delivered after newer
  ones. UDP `recv_batch_timed` is unchanged. Client latency is timed with
  `Instant`. Remove `.timestamps(..)` and `.kernel_timestamps(..)` calls and
  the `timestamps` feature from `Cargo.toml`.

### Fixed

- io_uring: `send_chain` and `send_chain_nowait` did not check the
  handle's generation when the handle's slot held a plaintext connection. A
  stale handle (its connection closed, with or without TLS, and the slot
  reused by a plaintext connection) submitted the chain on the slot's new
  occupant, so the bytes went to that connection's socket. The completion
  handlers discarded the chain's CQEs, which carried the old generation, so
  the chain stayed active on the new occupant. Until the worker exited, the
  new occupant's own chains returned `WouldBlock`, its plain sends stayed
  queued, and its close never finished. `SendChainBuilder::finish` now
  returns `NotConnected` on a stale handle, as the TLS path already did.
- TLS: a close_notify that ringline receives in one read with the peer's
  last handshake flight was dropped. The handshake completion was reported
  and the close was not, so the connection stayed open: a peer that kept
  TCP open left the task waiting for data that never came, and on the
  buffered engine on io_uring a later FIN was reported as truncated. The
  close is now handled after the completion, on both backends and both
  engines: the task reads what arrived, then a clean EOF.
- io_uring: `send_chain` and `send_chain_nowait` on a TLS connection sent
  the chain's bytes unencrypted, so the peer saw a record it could not
  parse. The parts, guard parts included, are now gathered and encrypted
  as one send, queued behind the connection's other sends, with one
  completion for the chain. They are not linked SQEs, and `finish` does not
  return `WouldBlock` for earlier sends in flight.
- io_uring: a TLS connection closed by `ConnCtx::close()`,
  `Connection::close()` or `SendHalf::close()`, or by its handler returning,
  sends a close_notify alert before the FIN. Only `DriverCtx::close` queued
  the alert, so those paths sent a bare FIN, which the peer cannot tell from
  a truncation. The alert is queued behind any queued sends. The queue
  drains however long the peer takes, as before and as for a plaintext
  connection; only `DriverCtx::close` bounds the drain with
  `close_notify_timeout_ms`. A close the runtime makes after a receive
  error, a reset, a send that could not be pushed, or the peer closing first
  sends no alert; neither does `ConnCtx::close()` or a handler return after
  `shutdown_write`, including one still waiting for queued sends to drain.
  A TLS send made after the alert is queued returns `NotConnected`, since
  the peer discards records that follow it; on mio such a send goes out
  ahead of the alert.
- `ringline-redis`, `ringline-memcache` and `ringline-ping` `Pool::client`
  reconnect a slot whose connection is no longer alive (`is_alive()` is
  `false`) instead of handing it out. A connection the server closed while
  it sat idle in the pool was handed out, and the first command on it
  failed. With the server down, a pool whose slots have all closed now
  returns `Error::AllConnectionsFailed` from `client()` instead of a client
  whose first command fails. A close the worker has not yet seen is still
  handed out, and so, on io_uring, is a plaintext connection whose FIN
  arrived while it had unread bytes. The reconnect runs inside `client()`,
  which waits for the connect (and AUTH on redis), bounded per slot by
  `connect_timeout_ms`; with the default of 0 there is no bound.
- `ringline-redis`, `ringline-memcache`, `ringline-ping`:
  `CommandResult::rx_bytes` is 0 for an operation that fails at send. It
  reported the previous operation's byte count. The guarded SET paths
  (`ringline-redis` `set_with_guard` and `set_ex_with_guard`,
  `ringline-memcache` `set_with_guard`) record a `CommandResult` when the
  send fails, the read fails, or the server replies with an error. They
  recorded none.
- io_uring: a park offer made while the connection holds request bytes the
  handler has not read, or from inside one of its reader callbacks, is
  ignored. Such an offer stayed set, so once the handler read the request
  nothing refused the park. A handler that then awaited something other than
  the connection (a backend call, for example) could be parked mid-request,
  and the request got no reply. Offer outside reader callbacks, after the
  response is queued. A connection whose next request has always arrived by
  the time the handler offers is not parked.
  `metrics::park_diag::OFFER_DECLINED` counts ignored offers. Found by
  reading the code; not observed. Park (#443) is not in a release. (#669)
- `ringline-memcache`: a client built with `with_metrics()` and no
  `on_result` callback records the latency of `fire_*`/`recv` operations.
  It read the clock only when a callback was set, so those operations
  recorded `latency_ns = 0` in `ClientMetrics` and `CompletedOp`. Builds
  with the removed `timestamps` feature already timed them. Such a client
  now reads the clock when an operation is sent (once per batch when
  batching) and again when its response is parsed, as the sequential API
  already did. The same fix for `ringline-redis` shipped in ringline-redis
  0.7.1.
- A connection's receive accumulator gives its allocation back when the
  connection closes. An accumulator grows to the largest message its
  connection buffered, and `reset` keeps the allocation, so each slot kept
  that size until a new connection took it, and then for that connection's
  lifetime. After a 1 MiB forward echo at 512 connections on one io_uring
  worker with an incremental TCP receive ring, which no release shipped,
  RSS once every connection had closed was 791 and 874 MiB in two runs
  without this change and 276 and 336 MiB with it. Both backends.
- io_uring: the error text of a failed buffer registration names a failed
  page migration as a cause, and the `EFAULT` text names io_uring's 1 GiB
  per-buffer limit. A long-term pin migrates pages in `ZONE_MOVABLE` or in
  `MIGRATE_CMA` or `MIGRATE_ISOLATE` pageblocks before pinning them; in the
  mainline v7.0 source a failed migration returns `ENOMEM`, or a short pin
  that io_uring reports as `EFAULT`. A kernel booted with kexec handover
  (KHO) active has `MIGRATE_CMA` pageblocks even when `CmaTotal` is 0. On an
  AWS i4i running Ubuntu's 7.0 kernel, with KHO active by default and about
  8.5 GiB of such pageblocks, 6 registrations of mapped anonymous memory
  failed with `EFAULT` or `ENOMEM` in process restarts where
  `pgmigrate_fail` rose, and each succeeded when retried 1 s later. The one
  restart with no `pgmigrate_fail` increase had no failure. This is a
  correlation; no trace showed which migration failed or why. The `EFAULT`
  hint said only that the region was not mapped, and the `ENOMEM` hint
  blamed `RLIMIT_MEMLOCK` even when the limit was unlimited. Under an
  unlimited soft limit the `ENOMEM` hint now says the limit is not the
  cause.

- io_uring: a `Runtime::register_region` that the kernel refused on any worker
  left the slot unusable. Each worker recorded the region in its slot table
  before the kernel call and kept the entry when the call failed. Workers
  whose call succeeded kept the registration. The slot went back to the free
  list, so the next `register_region` got the same slot and failed on every
  worker with `InvalidInput`, and retrying a failed registration did not
  succeed. A worker whose kernel call fails now clears its table entry, and a
  failed `register_region` then releases the slot on every worker, a second
  round trip. The slot goes back to the free list only if every worker
  acknowledges the release. If a worker has exited, or its release fails, the
  slot is not returned and later registrations use other slots, so a runtime
  with an exited worker loses one slot per failed `register_region`.
  `register_region` and `unregister_region` now still reach the remaining
  workers when one worker has exited, and `unregister_region` then clears the
  slot on every running worker before returning the error.

- io_uring: a zero-copy send (`SendMsgZc`) that returned `-ENOMEM`, because
  the pages it pins did not fit under `RLIMIT_MEMLOCK`, was dropped together
  with every send queued behind it, after `send_parts` had returned `Ok`.
  The connection stayed open, so later bytes arrived with a gap. The send
  now goes out as plain `send`s from the guard's memory, and the new
  `ringline/pool` counter `send_zc_enomem` counts each fallback. From Linux
  6.15 a zero-copy send is charged `len / page_size + 2` pages while in flight,
  and from 6.14 the rings are charged to the same limit, so at the common
  8 MiB limit a guard smaller than 8 MiB can reach it. A `send_chain` with a
  guard part still fails on `-ENOMEM`, as on any send error (#642).

- io_uring: `ConfigBuilder::sqpoll(true)` works. Ring setup set
  `IORING_SETUP_COOP_TASKRUN` together with `IORING_SETUP_SQPOLL`, which the
  kernel refuses with `EINVAL`, so every worker failed to launch with
  `Error::RingSetup`. Under SQPOLL the ring is now set up without
  `COOP_TASKRUN` and `DEFER_TASKRUN`. A push to a full SQ under SQPOLL now
  waits for the SQ thread to free entries (`IORING_ENTER_SQ_WAIT`); it
  failed before, closing the connection. A flush under SQPOLL enters the
  kernel only when SQEs are queued and either the SQ thread is idle or the
  CQ has overflowed (#630).

- io_uring: workers start on Ubuntu's 6.8 kernels (6.8.0-139 and later),
  which reject `IORING_REGISTER_PBUF_RING` with `EINVAL` unless a reserved
  word is set. Registration is tried in the standard form first. Only an
  `EINVAL` on a 6.8 kernel is retried with `resv[0] = 1`. The worker's later
  registrations use that form, and unregistration tries it first and falls
  back to the standard form (#626).

- On io_uring, an awaited send could resolve with another send's result. A
  connection had one send waiter, and any send completion on it woke the
  waiter: a `send().await` behind a `send_nowait`, an unawaited chain, a
  `forward_recv_buf` or a `send_backpressured` resolved with
  that send's byte count, and the awaited send's own completion then found no
  waiter. Two awaited sends in flight at once on one connection could hang;
  on mio they resolved with each other's lengths.
  Every awaited send (`send`, `submit_batch_await`, `send_chain`) now owns
  an entry in the worker's send completion table,
  and only its own completion settles it, on both backends. Two awaited sends
  in flight at once each resolve with their own result (#617).

- `send_chain` with a closure that submits nothing, and an awaited `send` of
  no bytes, resolve `Ok(0)`. With no other send in flight on the connection
  they used to hang (#617).

- On io_uring, a second `forward_recv_buf` (on `ConnCtx` or `SendHalf`)
  called while an earlier one's send was still in flight overwrote that
  send's progress. When the earlier send completed in full, it could be
  taken for a partial send and its buffer resent from past the end of its
  data, putting stale bytes on the wire; when the earlier send was larger
  and went out in part, the rest of it could be dropped. The progress is now
  recorded when each send is submitted to the kernel (#614).

- On io_uring, a receive buffer sent in part by `forward_recv_buf` (on
  `ConnCtx` or `SendHalf`) lost the rest of its bytes when the submission
  queue was full. The buffer went back to the ring and the next send went out,
  leaving a gap in the stream. The rest is now parked at the head of the send
  queue and retried. If it still cannot be submitted, the connection is closed
  (#613).

- On io_uring, a send that filled the socket of a peer that had half-closed
  (sent its FIN) and was not reading made the worker's event loop spin until
  the peer read or the connection closed, slowing every connection on that
  worker: about 26,000 iterations a second on a Linux 6.12 host. Once the
  peer has half-closed, the kernel returns `EAGAIN` from `sendmsg` and
  completes a `POLLOUT` poll at once with `POLLRDHUP` (6.12 and 7.1), so the
  loop's `sendmsg`, poll, `sendmsg` retry never waited. Coalesced copy
  sends now answer `EAGAIN` with a plain `send` of the first unsent bytes,
  which waits for room, and then resubmit the rest. A guard
  send (`SendMsgZc`) outside `send_chain` failed with `WouldBlock` in the
  same state; it now waits and delivers as well. While a send waits on a
  half-closed socket it holds an io-wq kernel thread, as plain copy and TLS
  sends already did; #605 tracks waiting without one (#603).

- On io_uring, a worker that shut down while a coalesced copy send was
  waiting for room took 10 s to exit: the shutdown
  closed connections without cancelling their requests, and released only
  zero-copy send entries. It now cancels each connection's requests ahead of
  its close and releases those entries, so the worker exits within
  milliseconds instead of after 10 s. A zero-copy send queued to a peer that
  does not read still holds shutdown until the 10 s shutdown bound, because
  its guards stay in use until the kernel's notification (#607).

- On Linux 6.13 and later, an io_uring connection close cancels the
  connection's requests ahead of its `Close` instead of sending a
  `shutdown`. From 6.13 the kernel releases a socket removed from the
  fixed-file table once that socket's own requests complete, so cancelling
  them is enough for the `Close` to send the FIN. The cancel runs inline,
  where the shutdown ran on the bounded io-wq pool and waited behind
  blocking file I/O such as `fs::fsync`. Older kernels, and kernels whose
  version cannot be read, still send the shutdown (#586).

- A `spawn_blocking` handle or `resolve` future dropped before its result
  arrived left its pending entry in the worker until the worker exited, and
  a closure's result delivered into that entry was held until then too.
  This happened to any handle dropped early, for example a discarded
  handle, the losing branch of `select` or `timeout`, or a future owned by
  a connection's task at teardown. Each now removes its entry when dropped
  on its worker, and a result that arrives later is dropped on delivery. A
  `spawn_blocking` or `resolve` call that fails because its pool has shut
  down no longer leaves an entry either (#582).

- On io_uring with Linux 6.1–6.12, a closed connection sent no FIN while
  another connection had a request in flight. The kernel keeps a socket
  removed from the fixed-file table open until earlier requests that use a
  registered file or buffer complete, and another connection's multishot
  recv is such a request. A peer that half-closed an idle connection, or
  whose connection's task ended, saw no EOF until that request ended. The
  close now hard-links a `shutdown(SHUT_RDWR)` ahead of the `Close`. The
  kernel runs that shutdown on an io-wq thread, so a worker that closes many
  connections runs more io-wq threads. A connection parked onto another
  worker is closed without the shutdown, and so are the connections a
  worker closes when it exits (#581).

- A connection's task is dropped outside any task poll when the connection
  closes, and several futures it owned released nothing there:
  - a `sleep` or `timeout` kept its timer slot, so enough connections closed
    while waiting emptied the pool, after which `sleep` and `timeout` panic;
  - a `process::Command::spawn` future whose result arrived later kept the
    child's pidfd open;
  - a `oneshot` or `mpsc` sender, or an `mpsc` receiver or pending send,
    did not wake the task waiting on the other end, which saw the channel
    close only when something else polled it;
  - a `Child::wait` future left its waiter and result entries behind;
  - an outbound `connect` future left its connection established with no
    task to use it, until the peer closed it.

  They now queue their release, or the wake, and the event loop applies it
  before its next task-poll pass or before it waits for I/O. On mio, an
  outbound TCP or TLS connect that completes with no `ConnectFuture`
  waiting is now closed, as on io_uring; this includes a connect started
  with `DriverCtx::connect`. A child that exits after its `wait` future was
  dropped no longer leaves a result entry behind (#575).

- On io_uring, dropping a `fs::read_into` or `fs::write_from` future could
  free its buffer while the kernel was still using it, and another disk-I/O
  future could resolve with the wrong result or never resolve. A completion
  is matched to its operation by a key that repeats, and a result nothing had
  taken was taken by a later operation with the same key: one left by a
  dropped future, by an NVMe or direct-I/O operation submitted through
  `DriverCtx`, or by a future not yet polled. A key is now not reused while a
  future holds it or, on mio, while its operation is still in the disk-I/O
  pool, and a result is kept only while a future holds its key. A key
  allocation that finds every key of its slab slot held fails with an error.
  `DiskIoFuture`, `StatFuture`, `OpenFuture`, `ReadFuture` and `WriteFuture`
  now panic if polled after returning `Ready` (#574).

- A connection closed while its task awaited `fs::read_into` or
  `fs::write_from` leaked the operation's buffer for the life of the
  process. The task is dropped outside any task poll, and the buffer was
  forgotten there. The event loop now frees the buffer once the operation
  completes, as it does for a future dropped inside a task poll (#568).

- On mio, `RinglineBuilder::bind_udp_connected` /
  `ConfigBuilder::udp_bind_connected` bound the socket but never
  `connect(2)`ed it, so a datagram from any source reached the handler. The
  socket is now connected, as on io_uring, and receives only the peer's
  datagrams. As on io_uring, `launch` now fails if the connect fails (for
  example, a peer in a different address family). On macOS, `send_to` an
  address other than the peer now fails with `EISCONN` (#549).

- `SendHalf::forward_recv_buf` / `Connection::forward_recv_buf` on io_uring:
  a stale handle (its connection closed and the slot reused), called with
  the new connection's bytes, detached the new connection's accumulator and
  dropped those bytes when the send was refused. It now returns
  `NotConnected` first, as the copy path's send does. On a current handle, a
  whole-accumulator forward that the send refused (the connection closing,
  or the zero-copy send slab full) also dropped the accumulator's bytes;
  they are now put back, and once the connection's Close is submitted both
  zero-copy paths are skipped so the copy path's refusal applies.
  `SendHalf::forward_recv_buf` also gains the documentation it was missing.
  The pending-recv-buffer part of this fix shipped in 0.6.10 (#544).

- A `Waker` the runtime hands to a future only worked when woken on the
  worker thread that polled it. Woken from another thread (a plain thread or
  another worker), it pushed the task id onto that thread's own ready queue:
  that wake did not schedule the parked task, and the waking thread could
  poll an unrelated task of its own. `Waker` is `Send + Sync`, so a future
  that stores its waker and has it woken elsewhere (a channel, mutex or
  notify shared between workers) could hang. A waker now carries its
  worker's id; woken off that worker's thread, it delivers the task to the
  worker's inbox and wakes the worker. A same-thread wake takes one extra
  thread-local read. A cross-thread wake takes two locks (the registry read
  lock and the worker's inbox), and writes the worker's wake fd only if no
  other wake has since the worker last drained its inbox. A wake for a worker
  that has exited is dropped. ringline requires a 64-bit target; a const
  assert now states this at compile time (32-bit Linux builds already failed
  in `worker.rs` and io-uring) (#559).

- On io_uring with `tick_timeout_us(0)`, a worker could block forever
  instead of shutting down. `request_shutdown()` from a task always did this,
  because the loop did not check shutdown before blocking. `Runtime::shutdown`
  did it when it arrived while the worker was polling tasks: the drain after
  `flush()` reaped the shutdown wake, and the eventfd read is not re-armed
  once shutdown is set. The loop no longer blocks once shutdown is pending.

- Dropping a `ReadFuture` or `WriteFuture` (`fs::read_into`, `fs::write_from`)
  before its operation completes parks the buffer until the operation is
  done. When the worker exited first, the buffer was freed while the
  operation could still write into it: on mio a disk-I/O pool thread, on
  io_uring the kernel. Buffers still parked when the worker exits are now
  leaked instead of freed.

- On mio, `fs::close` (and `DriverCtx::close_direct_io_file`) closed the fd at
  once, while a read, write or fsync queued on the disk-I/O pool still held its
  number. If the number was reused first, the operation went to the wrong
  file: a queued write landed in a file opened after the close. The fd now
  closes once the operations queued on it have finished (#551).

- On mio, a file that was never closed stayed open after its worker exited.
  It now closes when the worker exits, or when the last operation queued on it
  finishes, if that is later (#551).

- An `OpenFuture` dropped before it resolved, including one owned by a
  connection's task when the connection closed, left its file open and its
  slot in the file table taken, on both backends, until the worker exited;
  enough of them filled the table. The file is now closed and the slot freed
  (#551).

- On mio, files opened by `fs::open` and direct I/O files, and on io_uring,
  NVMe devices and direct I/O files before they enter the fixed-file table,
  are now opened close-on-exec (#551).

- With `pin_to_core(true)`, a `core_offset` that put a worker on CPU 1024 or
  higher aborted the process: `libc::CPU_SET` panicked and the panic could
  not unwind. `launch()` now fails with an `InvalidInput` I/O error.

- On io_uring, each worker's UDP socket was created without close-on-exec,
  so a process spawned on another thread while the worker started could
  inherit it. It is now close-on-exec.

- Listener sockets were created without close-on-exec, so a process spawned
  while the runtime ran inherited them and kept the port bound after the
  runtime shut down. They are now close-on-exec.
  `Runtime::set_worker_accepting` called after `shutdown()` attached its
  steering program to a closed fd number, which another socket could have
  reused; it now acts only on sockets that are still open (#561).

- On Linux 6.14 and later, io_uring charges each ring and each provided buffer
  ring to `RLIMIT_MEMLOCK`, in addition to registered buffers. The kernel adds
  the charge to what every process of the same user has charged. The launch
  preflight counted only `registered_regions`, and once rather than once per
  worker. A config the limit could not hold passed the preflight and failed
  when a worker started: in `io_uring_setup` with a bare `ENOMEM` on 6.14+, or
  when registering its regions. The preflight now counts each worker's ring,
  provided buffer rings and regions, and skips a process with `CAP_IPC_LOCK`
  in the initial user namespace. When the soft limit is short and the hard
  limit covers the need, it raises the soft limit to the hard limit rather
  than to exactly the need, which left no room for anything else the user
  charges. An `ENOMEM` from `io_uring_setup` or a
  provided buffer ring registration on 6.14+ now names the limit and the soft
  value, and says the kernel sums the charge over every process of the user
  (#426).

- A `spawn_blocking` closure that panicked killed its pool thread and left
  the awaiting task pending forever; a few panics could leave the pool with
  no threads. The pool thread now catches the panic and the handle resolves to
  a `JoinError`. A `spawn_with_handle` task that panicked also left its
  `JoinHandle` pending forever, and so did `JoinHandle::abort` and cancelling
  through `JoinHandle::id().cancel()`; all now resolve it to a `JoinError`.
  `JoinHandle::abort` after the task had finished cancelled whatever task
  had reused its slot; it now does nothing. On mio, a panic while building
  the `on_accept` future ended the worker thread; it is now caught, as on
  io_uring, and so are panics in the calls to `on_start` and `on_udp_bind`
  (#547).

- A port-0 unconnected UDP bind (`bind_udp("…:0")`) with more than one
  worker bound each worker's socket to a different ephemeral port, so the
  bind had no single address. `launch` now resolves the port once and every
  worker binds it. The socket `launch` binds to choose the port becomes one
  worker's socket, so no datagram can arrive on a socket nothing reads.
  Connected binds (`bind_udp_connected`) with a zero port keep one port per
  worker.

- A pool result that reached no worker leaked the fd it carried. An
  `fs::open` on mio's disk-I/O pool that completed after its worker had
  exited leaked the opened file, and a `spawn` result leaked the child's
  pidfd. Both results now own their fd, so a dropped result closes it. A
  spawned child whose result reaches no worker is still not reaped; it
  remains a zombie until the ringline process exits (#546).

- Connections accepted but still queued for a worker when the runtime shut
  down were never closed: the accept channel carried the socket as a raw fd,
  so the queued connections leaked when the worker exited without draining
  it. On mio every connection queued at shutdown leaked; on io_uring only
  those queued after the worker's last drain. Each queued connection now
  owns its socket, and a worker closes the connections still queued for it
  when it exits, including one that exits while the runtime keeps running
  (#545).

- A background thread that woke a worker after the `Runtime` had dropped
  wrote into whatever file then held the wake fd's number. Dropping the
  `Runtime` closed every worker's wake fd, but blocking-pool, resolver and
  spawner threads, mio's disk-I/O threads, the acceptor and the workers
  themselves carried the fd number without owning it. A `spawn_blocking` task
  still running at shutdown therefore wrote its wake (8 bytes on io_uring, 1
  on mio) into an unrelated fd once it finished. Each of those threads now
  holds the wake fds open while it runs, so they close when the last of those
  threads exits, or the last `WakeHandle` from `worker_wake_handle()` drops,
  rather than when the `Runtime` drops. Pool threads are detached, so the wake
  fds can still be open just after `launch()` returns an error or the worker
  handles have joined; they close once those threads see shutdown. A pool
  operation that never returns, such as a `spawn_blocking` task, keeps them
  open. References are taken when threads start, never per request.

- On mio, a wake that reached a worker after it had exited raised SIGPIPE.
  That kills a process whose SIGPIPE disposition is the default; Rust programs
  ignore SIGPIPE unless they reset it. Calling `shutdown()`, joining the
  workers and then dropping the `Runtime` was enough, because the worker
  closed its wake pipe's read end on exit. The `WakeHandle` now owns both ends
  of the pipe.

- Docs: `send_backpressured`'s documented error set omitted
  `io::ErrorKind::NotConnected`, which is what a waiter actually gets when the
  connection's close is *committed* while it sits in the capacity-admission
  FIFO. A waiter there is neither in flight nor in the per-connection send
  queue, so it does not hold off `try_finalize_close`; winning capacity
  afterwards finds the Close already submitted and the send is refused. The
  documented `ConnectionAborted` covers only the teardown-first ordering, and
  which one a caller sees is a race. This is what made #518 read as a send
  resolving on a live connection (#518).

- io_uring: every event-loop iteration scanned all `max_connections` park
  drain slots, whether or not any connection was parking. The early return
  tested `park_drain.is_empty()` on a vector sized to `max_connections`,
  which is never empty. At the default of 16,000 this was 37% of a client
  worker's cycles at 64 connections and 100K req/s, and doubled cycles per
  request at pipeline depth 1. The drive now visits a list of the
  connections with a drain outstanding, so its cost follows the number of
  parks in progress. Introduced in #483; not in a release. (#514)

- io_uring: a TLS `send`, `send_nowait` or `send_parts` that ran out of
  send pool partway through encryption corrupted the connection. Slots were
  taken as records were sealed, so when the pool ran dry the records already
  sealed had spent their sequence numbers with no ciphertext on the wire:
  the call returned `Err`, the connection stayed open, and every later
  record failed `bad_record_mac` at the peer. These sends are now admitted
  against the same ciphertext bound `send_backpressured` uses, before
  anything is encrypted: `Err` while the pool is short (retryable, nothing
  committed) and `InvalidInput` for a message the whole pool could never
  hold, as on the plaintext path. On the unbuffered engine a
  `send_copy_slot_size` too small to hold one whole record is rejected at
  build or launch (see Changed), so every such send has a bound.

- Copied sends can no longer transmit a prefix and then fail. Pool slots for
  a multi-chunk copy send are reserved up front, so the send is admitted
  whole or not at all, and a submission queue that is still full after a
  submit parks the built SQE and re-pushes the same bytes rather than
  re-running the logical send. Under TLS the latter mattered most: re-running
  meant re-encrypting after rustls had already advanced its record sequence,
  which the peer sees as a gap and rejects with `bad_record_mac`.
- mio: a connection whose peer closed first, or whose read failed, was never
  torn down — the `TcpStream` stayed registered and the slot was never
  released, so every such connection permanently consumed one slot and one
  fd until `max_connections` was exhausted. `ConnCtx::close()` after EOF
  took the same early return. (#368)
- mio: while queued sends drained to a peer that had half-closed, the event
  loop re-registered READABLE interest on every iteration, which re-reported
  the peer's EOF and spun the worker at 100% CPU until the peer read.
  Interest is WRITABLE-only once the receive side is closed, and a closed
  receive side is no longer read. (found while fixing #368)
- io_uring: a response sent after the peer's FIN was never delivered when
  the send queue was empty at the FIN — `close_connection` committed the
  Close SQE synchronously, before the task was polled, so the task's send
  was refused or raced the Close. Every driver-requested close now
  finalizes from the event loop's end-of-iteration drain, where an explicit
  `close()` already did, giving the task its poll window and letting a send
  queued in it drain first. Both backends now give the same window. (#371)
- mio: `shutdown_write` with sends still queued wrote what fit, dropped the
  rest, and sent the FIN — a response larger than the socket buffer
  followed by a half-close was truncated. The FIN now goes out once the
  queue drains, as on io_uring.
- `launch()` now returns the error the failing worker actually reported
  (typed: `RingSetup`, `ResourceLimit`, `Io`) instead of whichever joined
  thread's error came first, and a panic during worker startup surfaces as
  an `Io` error naming the worker and the panic payload instead of the
  generic "worker setup failed".
- io_uring: a copied send wider than one send-pool slot is admitted
  transactionally — every slot is reserved before the first byte is copied,
  so a pool-exhaustion `Err` from `ConnCtx::send`/`send_nowait` means nothing
  was queued and the buffer may be resent (previously a prefix could already
  be on the wire, and a retry duplicated it). A send wider than the whole
  pool is refused up front with `InvalidInput`. Submission-queue pressure on
  a queued send now parks the entry and retries it on the next loop
  iteration instead of silently dropping the tail of the stream and hanging
  the awaiting `send`; persistent starvation fails the waiter and closes the
  connection, like a write error. Series PR 4 of #318 (design:
  `docs/copied-send-reservation-design.md`).

## [0.6.12] - 2026-10-21

`ringline` 0.6.12 and `ringline-quic` 0.6.2 carry the `rustls-webpki` floor
below.

### Security

- `ringline` and `ringline-quic` require `rustls-webpki` 0.103.16 or later
  for RUSTSEC-2026-0382 (certificate verification may accept distrusted
  intermediates). rustls 0.23.46 accepts 0.103.14, so the two crates depend
  on rustls-webpki directly to carry the floor to downstream resolvers.
- The workspace takes `webpki-roots` 1.0.10 or later for RUSTSEC-2026-0381
  (bundled emSign ECC Root CA - G3 allows paths through distrusted emSign
  intermediates); 0.26.x has no fixed release. Only dev-dependencies and the
  unpublished ringline-benchmarks use it. Backport of #686 (#689).

## [ringline-redis 0.7.1] - 2026-10-17

Patch release of `ringline-redis` only, for ringline 0.6.

### Added

- `ringline-redis`: `ClientBuilder::get_command` and
  `ClientBuilder::set_command` set the command names a `Client` sends in
  place of `GET` and `SET`. They apply to `fire_get`, the `fire_set*`
  methods (zero-copy guard path included), the async `get` and `set*`
  methods, `Pipeline::get` and `Pipeline::set`, `set_stream` and, on
  io_uring, `get_stream`. Only the name changes: the TTL and condition forms
  send the same `EX`, `PX` or `NX` arguments under the configured name.
  Replies are parsed and counted as GET and SET replies. A client built
  without them sends the same bytes as before: resp-proto's encoders on the
  copy paths, and a hand-written prefix that produces the same bytes on the
  guard and streaming paths. `Pool`, `ShardedClient` and `ClusterClient`
  always send `GET` and `SET`.

### Fixed

- `ringline-redis`: a client built with `with_metrics()` and no
  `on_result` callback records the latency of `fire_*`/`recv` operations.
  Without the `timestamps` feature it read the clock only when a callback
  was set, so those operations recorded `latency_ns = 0` in `ClientMetrics`,
  `CompletedOp` and `RespMeta`. Such a client now reads the clock when an
  operation is sent (once per batch when batching) and again when its
  response is parsed, as the sequential API already did. Backport of #667
  (#668).

## [0.6.11] - 2026-10-14

`ringline` 0.6.11 and `ringline-quic` 0.6.1 carry both floors below.

### Security

- The `quinn-proto` floor is raised to 0.11.19 for RUSTSEC-2026-0338,
  RUSTSEC-2026-0339, RUSTSEC-2026-0340, RUSTSEC-2026-0341, RUSTSEC-2026-0342,
  RUSTSEC-2026-0343, GHSA-53rm-773f-4q8c and GHSA-wppq-2f6r-wfvm. Downstream
  resolvers respect the pin, so they cannot land on a vulnerable 0.11.x
  through ringline-quic or ringline-h3.
- The `rustls` floor is raised to 0.23.46 for RUSTSEC-2026-0346 (`Debug`
  output of client session values exposes TLS secrets), RUSTSEC-2026-0347
  (buffered application data sent to the outer server after ECH rejection),
  RUSTSEC-2026-0348 (Brotli certificate decompression can allocate up to
  1 GiB before authentication) and RUSTSEC-2026-0349 (an unauthenticated
  ServerHello can downgrade later connections to classical key exchange).
  The `ringline` crate now takes rustls from the workspace pin; its own
  requirement was `0.23`. Of the other published crates, only `ringline-quic`
  depends on rustls outside its dev-dependencies, and every `ringline-quic`
  release before 0.6.1 predates #399; 0.6.0 requires rustls 0.23.18. So the
  0.23.45 floor from #399 reached no user of the published crates.

## [0.6.10] - 2026-10-11

### Changed

- `metriken` 0.9 → 0.11.3 (`metriken-core` 0.2 → 0.3.3). The statics in
  `ringline::metrics` are `metriken` types, so they are now 0.11's
  `ShardedCounterGroup` and `Gauge`; their methods and the values they report
  are unchanged. `metriken-core` declares `links = "metriken-core"`, so a
  build holds one `metriken-core`: a dependent still on `metriken` 0.9 must
  move to 0.11 together with this release. Until it does, Cargo resolves it
  to the previous ringline release rather than failing. Backport of #649.

### Fixed

- io_uring: `ConnCtx::forward_recv_buf` took the slot's pending recv buffer
  before checking the handle's generation, so a stale handle (its
  connection closed and the slot reused), called with the new connection's
  bytes, sent the new connection's pending recv buffer to it. It now
  returns `NotConnected` first, as the copy path's send does. Once the
  connection's Close is submitted, the zero-copy branch is skipped, so the
  copy path's refusal applies and the pending buffer stays in place.
  Backport of #570 (#544).

- io_uring and mio: `ConnCtx::close` on a stale handle, one whose slot had
  been reused by a new connection, closed that new connection. It now does
  nothing on a stale handle. The same check now guards `set_recv_sink` (a
  stale handle installed its buffer as the new connection's recv sink, so
  that connection's bytes were written into it) and `take_recv_sink` (a
  stale handle removed the new connection's sink). On io_uring it also
  guards `recv_timestamp`, which returned the new connection's timestamp.
  Backport of #540 (#535).

## [0.6.9] - 2026-09-29

### Fixed

- io_uring: a `shutdown_write()` could half-close a **different, live**
  connection. `Shutdown` names its socket as the registered-file slot
  `Fixed(conn_index)`, not as an fd, and nothing pinned the slot for the
  operation's lifetime: a `Shutdown` is not a queued send, so
  `try_finalize_close` did not count it, and its completion was discarded
  (`OpTag::Shutdown => {}`). The `Close` that frees the slot could therefore be
  submitted and complete first, the next accept could register the slot, and the
  kernel could then run the FIN against that new connection — whose next send
  failed with `EPIPE` while its peer saw a clean, early end of stream. The close
  now waits on the `Shutdown` CQE, and the SQE carries its connection generation
  so a stale completion is rejected and counted as `ringline/ring`
  `shutdown_stale` rather than clearing the new occupant's state. Measured on a
  2-CPU guest at 46/400 rounds with 16 connections, 0/400 with the shutdown
  removed, and 0/400 with this fix. Backport of #523 (#518).

## [0.6.8] - 2026-09-29

### Fixed

- io_uring: a segmented reader (`segments()`, `recv_owned_segment()`)
  installed after data had arrived never saw that data: the bytes sat in
  the accumulator, which a segmented reader does not look at, and the
  reader parked forever. Entering the segmented domain now adopts them,
  and a stranded-bytes check at the top of each segmented poll recovers
  any left behind later (counted by the `segment_stranded_adopted` pool
  metric).
  Under TLS the handshake makes this race easy to lose; it is the
  intermittent `tls_echo` hang (#423, fixed by #425 on main).

- io_uring: `forward_to` skipped bytes that were already buffered when the
  forward started. The length a forward needs comes from a header read with
  `with_data`, so the body bytes that arrived with the header sat in the
  accumulator (or pinned as the zero-copy buffer), where a forward never
  reads: later bytes were forwarded as the body and the skipped ones
  surfaced after it, or the forward hung if nothing more arrived. Those
  bytes now open the forward, and the pinned buffer's bid goes back to the
  ring instead of leaking. Found on main in #415.
- io_uring: `forward_to` on a stale handle switched the slot's new
  connection into forwarding, stranding its bytes. It is now ignored.
- io_uring: five ways a forwarding connection could stop receiving for
  good, all fixed on main in #415: the throttle flag was cleared while its
  cancel was still in flight, so nothing re-armed the recv; a cancel that
  landed on a later multishot left the connection unarmed; an ECANCELED
  carrying `IORING_CQE_F_MORE` left it marked armed; the fallback recv could
  run on a segmented connection, and a late one appended to the accumulator
  a forward never reads; and a connection parked on a dry ring was only
  re-armed on a pass that had just returned buffers.

## [0.6.7] - 2026-09-29

### Fixed

- io_uring: a TLS `send`, `send_nowait` or `send_parts` that ran out of
  send pool partway through encryption left the connection open and
  corrupt. The records already sealed had spent their sequence numbers with
  no ciphertext on the wire, so every later record failed `bad_record_mac`
  at the peer. Such a send now closes the connection and returns `Err`, as
  the docs already told callers to do. With no free slot at all, the send
  is refused before encrypting and the connection is left alone; previously
  the buffered engine took the plaintext, returned `Err`, and sent it later
  anyway, so a retry duplicated it. (0.7 turns the partway case into a
  retryable refusal too, by admitting TLS sends against a ciphertext bound;
  that needs machinery this line does not have.)

## [0.6.6] - 2026-09-29

### Fixed

- io_uring: a send that could not be pushed because the submission queue
  was still full after a submit was thrown away. On an idle connection it
  was released and the caller got `Err` -- under TLS after rustls had
  already advanced its record sequence, so every later record failed
  `bad_record_mac` at the peer. From a queued tail it was worse: the head
  was popped before pushing, and on failure the head *and every queued send
  behind it* were released, `in_flight` cleared and nobody woken, so the
  prefix was on the wire, the rest silently lost, and the waiting send
  future hung. TLS handshake responses, alerts and `close_notify` ignored
  the error. The built send is now kept at the queue head and retried next
  iteration; after two failed retries the waiter fails and the connection
  closes (#376, parking half).

- io_uring: `ConnCtx::forward_held` pushed its recv-forward `sendmsg` straight
  to the ring without looking at the connection's send state, so echoed bytes
  could overtake a plain send that was queued, in flight or parked for retry,
  or an active send chain. **Behaviour change:** it now returns `WouldBlock`
  while any earlier send is outstanding, before allocating anything; the held
  buffers stay in the hold and the next call forwards them. Await the earlier
  send first. A handler that only forwards, awaiting each forward before the
  next, is unaffected.

- io_uring: plain sends and IO_LINK send chains could overtake each other on
  one connection, putting bytes on the wire out of order; parking widened the
  window. A plain send now queues behind an active chain. **Behaviour
  change:** a chain started while earlier sends are still in flight -- plain,
  or another chain -- is refused with `WouldBlock` instead of reordering, and
  releases what it built (#494).

## [0.6.5] - 2026-09-29

### Fixed

- io_uring: a copied send larger than one send-pool slot could transmit a
  prefix and then fail. Each chunk took its slot inside the send loop, so
  when the pool ran out at chunk k, chunks 1..k-1 were already queued or on
  the wire and the caller got `Err`; a retry sent that prefix twice. Every
  slot is now reserved before the first byte is copied, so the send is
  admitted whole or not at all, and a send needing more slots than the pool
  holds is `InvalidInput` (#376, the reservation half only; its SQ-pressure
  parking is a separate change).

- io_uring: a multishot recv completion carried no connection generation, so
  one for a closed connection could be attributed to the next connection to
  reuse its slot. A late error tore the new connection down for an error it
  never saw; a late `result > 0` appended the dead connection's bytes to the
  new one's data. This could happen when the multishot's cancel was dropped
  on a full submission queue and the kernel posted its terminal completion
  after the slot was reused. `RecvMulti`/`RecvMsgMultiTs` now carry the
  generation, and a completion for another occupant is discarded, returning
  its provided buffer (#382).

- io_uring: four recv entry points acted on a stale `ConnCtx` -- one whose
  slot had been closed and reused -- against whichever connection held the
  slot now. `try_with_data` could hand the caller another connection's bytes
  and advance that connection's buffer past them; it now returns `None`.
  `with_segments` switched the other connection into segmented delivery and
  stranded its reader; the switch now happens at first poll, behind the
  generation check. `end_segments` now returns `EPIPE`, and
  `enable_recv_forward` is a no-op on a stale handle (#437).

## [0.6.4] - 2026-09-29

A patch release from 0.6.3 carrying fixes from `main`. The breaking changes
on `main` since 0.6.3 are not included; they are for 0.7.0.

### Security

- The `rustls` floor is raised to 0.23.45 for RUSTSEC-2026-0285 (TLS 1.3
  handshake messages incorrectly accepted across encryption level
  boundaries). Downstream resolvers respect the pin, so they cannot land on
  a vulnerable 0.23.x through ringline (#399).

### Fixed

- A `SendMsgZc` send that completed with an error or a zero result released
  its send-slab entry at once, but the kernel still posts a notification for
  it: `IORING_CQE_F_MORE` is set on error (`io_sendrecv_fail`) and on a zero
  result (`io_sendmsg_zc`). If the next send reused the entry first, the late
  notification decremented the new send's count -- a "notification underflow"
  panic in debug, and in release an entry that wraps or is released while the
  kernel may still hold the new send's pages. Notifications are now expected
  exactly when the main CQE carries `IORING_CQE_F_MORE` (#487, #488).

- A standalone task that ran to completion leaked its task-slab slot, so
  after `standalone_task_capacity` completions `spawn()` returned `None` for
  the life of the worker, and callers fell back to running work inline on
  the event loop. A slot now reads as polling, not empty, while its future
  is out, so `remove()` frees a finished task's slot and stays idempotent
  for one that never had a task (#478).

## [0.6.3] - 2026-09-09

### Fixed

- `RLIMIT_MEMLOCK` too low for `registered_regions` used to surface as a bare
  `Cannot allocate memory` from the kernel (io_uring pins fixed buffers against
  the memlock limit unless the process holds `CAP_IPC_LOCK`; distros default it
  to 8 MiB or 64 MiB). `launch` now checks the limit before any worker starts,
  raises the soft limit when the hard limit allows, and otherwise returns
  `Error::ResourceLimit` naming the shortfall in KiB, the `ulimit -l` /
  `LimitMEMLOCK=` fix, and the capability exemption. A region added later via
  `ShutdownHandle::register_region` gets the same guidance as an `io::Error`.
  Every kernel registration in driver setup (fixed buffers, the fixed file
  table, provided buffer rings) now reports `Error::BufferRegistration` /
  `Error::ResourceLimit` with the cause instead of `Error::Io`; the
  `BufferRegistration` variant was previously never constructed. (#361)

- io_uring test binaries on a host that refuses io_uring (e.g. Rocky 10 with
  `kernel.io_uring_disabled=2`) reported the same `RingSetup` failure once per
  test after ten retries each. The test event-loop helper now retries only
  transient errors (`ENOMEM`/`EAGAIN`/`EMFILE`/`ENFILE`) and on a structural
  one prints the message once and exits the binary. (#359)

- A refused `io_uring_setup(2)` now surfaces as `Error::RingSetup` instead of
  a bare `Error::Io(PermissionDenied)`. The message names the errno and the
  cause: for `EPERM` it reads `kernel.io_uring_disabled` and says whether the
  sysctl (`2` refuses everyone including root; `1` refuses callers outside
  `kernel.io_uring_group` without `CAP_SYS_ADMIN`) or a seccomp profile is
  responsible, and gives the `sysctl` fix; `ENOSYS`/`EINVAL` point at the
  kernel. Every variant mentions the `force-mio` feature. The `RingSetup` doc
  comment and the crate-level platform notes no longer claim
  `--no-default-features` selects mio — the backend is chosen by `build.rs`
  and `force-mio` is the only opt-out (#355).

## [ringline-memcache 0.7.2] - 2026-09-09

No changes. Published alongside the v0.6.2 workspace release because the
crate's development version was already bumped past 0.7.1.

## [0.6.2] - 2026-09-09

### Added

- `ConfigBuilder::loop_diag(bool)` (default off): gates the per-worker
  `[ringline diag]` / `[ringline stall]` shutdown lines on the io_uring
  backend. Replaces the `RINGLINE_LOOP_DIAG` environment variable, and the
  `[ringline diag]` line is no longer printed unconditionally.

- `tls-unbuffered` cargo feature (default off): drives TLS through rustls'
  unbuffered record layer (`UnbufferedConnectionCommon` /
  `WriteTraffic::encrypt`) instead of the buffered `writer()`/`write_tls()`
  API, on both backends.

  **It does not change the copy count.** Application-data sends cost 2 copies
  on both engines. The copy this feature was built to remove — user bytes into
  rustls' `sendable_plaintext` — does not happen on an established connection:
  `CommonState::send_plain` buffers there only before the handshake completes
  and otherwise calls `send_plain_non_buffering`. Nor does the unbuffered API
  encrypt into the caller's destination: `write_fragments` seals each record in
  a fresh per-record buffer and then copies it into `outgoing_tls`. Verified
  against rustls 0.23.41 and confirmed by an allocation counter inside the
  measured call (263,976 bytes/op buffered vs 264,000 unbuffered at 256 KiB).

  What it does deliver, measured in isolation on Linux/io_uring: a small
  (~1–2%) send-side bookkeeping win at payloads ≥64 KiB, a 4–8% win on the
  recv path, and no throughput or latency regression. It is also the
  prerequisite for kTLS, since rustls' `dangerous_into_kernel_connection` is
  public only on `UnbufferedClientConnection`/`UnbufferedServerConnection`.

  Known costs and limitations: a payload that is an exact multiple of
  `send_copy_slot_size` costs one **extra TLS record**, because a whole record
  must fit inside one pool slot (a 16 KiB send is ~5.7% slower for this
  reason); the io_uring handshake path (ClientHello/certificates/Finished, not
  the steady-state application-data path) pays one copy more than the buffered
  engine, since `EncodeTlsData::encode` needs one contiguous output buffer that
  can exceed a pool slot; and `TlsInfo::sni_hostname()` is always `None` for
  server connections on this engine (rustls exposes no equivalent of
  `ServerConnection::server_name()` on `UnbufferedServerConnection` — would
  need a `ClientHello` callback on `ServerConfig`, tracked as follow-on work).
  TLS recv copy count is unchanged. See `docs/tls-unbuffered-design.md`.

### Changed

- Default `send_copy_slot_size` is 16448 (was 16384) so one maximum-size TLS
  1.3 record (16406 bytes) fits in a single send pool slot. Costs 0.4% more
  send pool memory at the default slot count. (#352)

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

Also carries TLS groundwork for the unbuffered send path: the `tls.rs` split
into `tls/mod.rs` + `tls/buffered.rs` with a crate-private `CiphertextBuf`
(#338, no behavior change), the design in #339, and the allocation change
under Changed below (#341).

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

### Changed

- `CiphertextBuf` no longer zero-fills (#341). It allocated with
  `vec![0u8; n]` and grew with `resize(n, 0)`, initializing memory the peer
  had not sent -- a per-connection `memset` and real resident memory at high
  connection counts, which also forfeits the property that large provided
  buffers are RSS-free because untouched pages stay demand-paged. Now
  `Vec::with_capacity` + `reserve_exact` for the allocation and
  `extend_from_slice` for writes, holding `buf.len() == end` as a strict
  invariant, with no `unsafe`. `capacity()` reports a tracked `reserved`
  field rather than `Vec::capacity()`, so the cap assertion pins this type's
  own arithmetic rather than allocator rounding. Crate-private type: no API
  change, and TLS connections get cheaper to set up and smaller in RSS.

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
