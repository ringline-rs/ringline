use std::net::SocketAddr;

use crate::buffer::fixed::MemoryRegion;

/// Where connections are accepted.
///
/// See `docs/listeners-and-accept-design.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AcceptMode {
    /// One acceptor thread per listener, handing accepted fds to workers over
    /// a channel with explicit round-robin placement. The default.
    ///
    /// Placement is deterministic, and a worker that is full or has exited is
    /// skipped — properties the merged mode has to reconstruct.
    #[default]
    Pool,
    /// Each worker owns a `SO_REUSEPORT` listener and accepts on its own ring
    /// with multishot accept. No acceptor thread, no channel, no wake fd, and
    /// no cross-thread handoff per connection.
    ///
    /// Placement falls to the kernel's 4-tuple hash unless steered, which is
    /// uneven for a client that opens a pool of connections: at N connections
    /// over N workers roughly 1/e of workers get none. That is why this is not
    /// the default. io_uring only — the mio backend always uses [`Pool`].
    ///
    /// Not compatible with
    /// [`RinglineBuilder::defer_listen`](crate::RinglineBuilder::defer_listen);
    /// on the io_uring backend `launch()` refuses the combination.
    ///
    /// [`Pool`]: AcceptMode::Pool
    Merged,
}

/// TLS configuration. Pass a pre-built rustls ServerConfig.
#[derive(Clone)]
pub struct TlsConfig {
    /// Pre-built rustls ServerConfig. User loads certs/keys and configures ALPN etc.
    pub(crate) server_config: std::sync::Arc<rustls::ServerConfig>,
}

impl TlsConfig {
    /// Wrap a pre-built rustls `ServerConfig` (configure certs/ALPN/etc. on the rustls side).
    pub fn new(server_config: std::sync::Arc<rustls::ServerConfig>) -> Self {
        Self { server_config }
    }
}

/// TLS client configuration for outbound connections.
#[derive(Clone)]
pub struct TlsClientConfig {
    /// Pre-built rustls ClientConfig. User configures root certs, ALPN, etc.
    pub(crate) client_config: std::sync::Arc<rustls::ClientConfig>,
}

impl TlsClientConfig {
    /// Wrap a pre-built rustls `ClientConfig`.
    pub fn new(client_config: std::sync::Arc<rustls::ClientConfig>) -> Self {
        Self { client_config }
    }
}

/// Configuration for the io_uring driver.
#[derive(Clone)]
pub struct Config {
    /// Number of SQ entries. CQ will be 4x this.
    pub(crate) sq_entries: u32,
    /// Enable SQPOLL mode (kernel-side submission polling).
    pub(crate) sqpoll: bool,
    /// SQPOLL idle timeout in milliseconds.
    pub(crate) sqpoll_idle_ms: u32,
    /// Pin SQPOLL kernel thread to this CPU core. Only meaningful when sqpoll=true.
    pub(crate) sqpoll_cpu: Option<u32>,
    /// Recv buffer configuration (provided buffer ring) for TCP multishot recv.
    pub(crate) recv_buffer: RecvBufferConfig,
    /// Recv buffer configuration for UDP multishot recvmsg.
    ///
    /// UDP uses a separate provided buffer ring from TCP so the two can be
    /// sized independently. Each buffer must fit an `io_uring_recvmsg_out`
    /// header (16 bytes) + `sockaddr_storage` (128 bytes) + the datagram
    /// payload. Default: 128 buffers × 2048 bytes (room for a standard-MTU
    /// datagram plus the multishot metadata); bump `buffer_size` if you
    /// expect jumbo datagrams.
    ///
    /// `bgid` must differ from `recv_buffer.bgid` when UDP is in use.
    pub(crate) udp_recv_buffer: RecvBufferConfig,
    /// User-registered memory regions (e.g., mmap'd storage arenas).
    ///
    /// Regions listed here occupy slots `0..registered_regions.len()` at
    /// startup. The remaining slots up to [`ConfigBuilder::max_registered_regions`] are
    /// available for dynamic registration via
    /// [`Runtime::register_region`](crate::Runtime::register_region).
    pub(crate) registered_regions: Vec<MemoryRegion>,
    /// Maximum number of fixed-buffer slots to reserve in the io_uring
    /// registered-buffer table. Must be `>= registered_regions.len()`.
    ///
    /// Slots beyond the initial regions are empty until filled by
    /// [`Runtime::register_region`](crate::Runtime::register_region).
    /// Cannot be grown after launch — io_uring's registered-buffer table is
    /// fixed-size; expand by re-launching with a larger value.
    ///
    /// Default: 64.
    pub(crate) max_registered_regions: u16,
    /// Worker/thread configuration.
    pub(crate) worker: WorkerConfig,
    /// TCP listen backlog.
    pub(crate) backlog: i32,
    /// Maximum number of direct file descriptors (connections).
    pub(crate) max_connections: u32,
    /// Initial capacity for per-connection recv accumulators.
    pub(crate) recv_accumulator_capacity: usize,
    /// Upper bound on a single per-connection recv accumulator. If the
    /// application's parser keeps returning `NeedMore` while the peer
    /// streams data, the accumulator grows indefinitely; setting this
    /// closes the connection once the cap is exceeded, protecting the
    /// worker from OOM.
    ///
    /// **Default: 1 GiB.** Bounded by default so an unterminated input
    /// fails (connection closed) rather than consumes the worker's memory;
    /// `usize::MAX` disables the cap for workloads that genuinely need
    /// unbounded messages. The default is deliberately above Redis's own
    /// `proto-max-bulk-len` default (512 MiB) because the protocol client
    /// crates parse whole replies from the accumulator; servers facing
    /// untrusted peers should set something much smaller (4–16× the typical
    /// request size). Setting it too low will close legitimate
    /// slow-consumer workloads (where kernel recv CQEs batch faster than
    /// the handler runs); it must be at least `recv_buffer_size`.
    pub(crate) recv_accumulator_max: usize,
    /// Aggregate low-water reserve for segmented recv (see
    /// `docs/segmented-recv-design.md`, "Backpressure and ring safety").
    ///
    /// When a `Segmented` connection receives a provided buffer, the runtime
    /// consults the shared per-worker recv ring's live free-buffer count. If
    /// `free() <= recv_segment_reserve`, the buffer is **force-copied** into an
    /// owned `Bytes` and its bid returned to the ring immediately (Mode C at
    /// delivery) instead of being pinned as a zero-copy held segment. This
    /// guarantees a well-behaved connection is never `ENOBUFS`-starved by other
    /// connections holding segments under fan-in, at the cost of a copy while the
    /// ring is under pressure. Above the reserve, delivery stays zero-copy
    /// (pinned).
    ///
    /// Larger values reserve more headroom (copy sooner, safer under fan-in);
    /// `0` force-copies only when the ring is fully drained. Tune relative to
    /// `recv_buffer` ring_size; a value `>=` ring_size makes segmented delivery
    /// always copy. Must be `<= 65535` (the maximum provided-ring size).
    ///
    /// **Default: 64** (a quarter of the default 256-buffer recv ring).
    pub(crate) recv_segment_reserve: u32,
    /// Per-connection held-buffer cap for a Mode A `forward_to` connection (see
    /// `docs/segmented-recv-design.md`, "Mode A — Forward to an fd").
    ///
    /// A `forward_to` connection holds arriving provided buffers in-place until
    /// each is written to the sink. A slow or high-latency sink (or a very large
    /// object) would otherwise let one forwarding connection accumulate an
    /// unbounded backlog of held buffers, pinning much of the shared per-worker
    /// recv ring (and growing heap when the low-water reserve force-copies) and
    /// starving every other connection on the worker. When a forwarding
    /// connection's held-buffer count reaches this cap, the runtime cancels its
    /// multishot recv so its TCP receive window closes and the peer stops sending
    /// (natural backpressure to the source); the recv is re-armed once the hold
    /// drains below the cap as writes complete. This bounds one slow forward to at
    /// most `forward_hold_cap` held buffers.
    ///
    /// Larger values allow more recv in flight (higher single-forward throughput)
    /// at the cost of more pinned ring buffers / held heap under a slow sink;
    /// smaller values apply backpressure sooner. Must be `>= 1`.
    ///
    /// **Default: 64** (2× `MAX_IOVECS`, the per-`sendmsg` iovec bound).
    pub(crate) forward_hold_cap: usize,
    /// Fault recv and send buffer pages in at worker startup instead of on
    /// first use. See `ConfigBuilder::prefault_buffers`.
    pub(crate) prefault_buffers: bool,
    /// Bound on the per-worker accept channel. If a worker can't drain its
    /// queue fast enough, the acceptor will skip past it (and possibly
    /// close the incoming fd if every worker is full) rather than
    /// accumulating fds without backpressure. Default: 1024.
    pub(crate) accept_queue_capacity: usize,
    /// Number of connections assigned to each worker before moving to the
    /// next one. `1` (the default) gives classic round-robin. Higher values
    /// pack connections onto fewer workers at low connection counts, keeping
    /// each active worker's CQE density high enough for io_uring batching to
    /// pay off. Has no effect once total connections exceed
    /// `conn_chunk_size * num_workers` — at that point every worker is
    /// active and each gets the same number of connections as round-robin.
    ///
    /// Rule of thumb: set to the minimum connections-per-worker at which
    /// your workload sees good batching (typically 16–64). Default: 1.
    pub(crate) conn_chunk_size: usize,
    /// Number of copy-send pool slots. Each in-flight `send()` or copy part of a
    /// `send_parts()` call holds one slot until the kernel completes the send.
    /// Size this to cover your peak in-flight send count — exhaustion returns an
    /// error to the handler. Memory cost: `send_copy_count * send_copy_slot_size`.
    pub(crate) send_copy_count: u16,
    /// Size of each copy-send pool slot in bytes. A single `send()` or the
    /// combined copy parts of one `send_parts()` call must fit in one slot.
    ///
    /// The default is 16448, not 16384, so that one maximum-size TLS 1.3
    /// record fits in a single slot: 5-byte record header + 2^14 plaintext +
    /// the inner content-type byte + a 16-byte AEAD tag = 16406, rounded up to
    /// a 64-byte boundary. A 16384-byte slot is 22 bytes short of that, which
    /// forces the `tls-unbuffered` engine to shrink its plaintext chunk and
    /// emit an extra record per send (17 rather than 16 for a 256 KiB
    /// payload). Costs 64 bytes per slot — 0.4% of the pool.
    pub(crate) send_copy_slot_size: u32,
    /// Minimum total send size (bytes) for the zero-copy guard send path.
    ///
    /// Guard sends (`send_parts()` with `.guard()` parts) whose total length is
    /// **less than** this threshold are gathered into a `SendCopyPool` slot and
    /// submitted as a plain copy `Send` instead of `SendMsgZc`. For small sends
    /// the ZC bookkeeping (in-flight slab entry plus a second completion for the
    /// kernel's ZC notification) costs more than the memcpy it avoids.
    ///
    /// `0` disables the fallback (guard sends always use zero-copy).
    /// Sends at or above the threshold, or that don't fit a send pool slot,
    /// use the zero-copy path as before. Default: `4096`.
    pub(crate) send_zc_threshold: u32,
    /// Number of InFlightSendSlab slots for in-flight scatter-gather sends
    /// (i.e., `send_parts()` calls that include at least one guard).
    /// Each slot is held until all ZC notifications arrive.
    pub(crate) send_slab_slots: u16,
    /// Deadline-based flush interval in microseconds during CQE processing.
    /// When non-SQPOLL, if this many microseconds elapse since the last submit
    /// while processing a CQE batch, pending SQEs are flushed mid-iteration.
    /// 0 = disabled. Ignored when SQPOLL is active (kernel handles it).
    pub(crate) flush_interval_us: u64,
    /// Maximum time in microseconds that `submit_and_wait` will block before
    /// returning to call `on_tick`. Prevents the event loop from stalling when
    /// there are no pending completions (e.g., client-only mode between phases).
    /// 0 = no timeout (block indefinitely until a CQE arrives).
    /// Default: 1000 (1ms).
    pub(crate) tick_timeout_us: u64,
    /// Optional TLS configuration. When set, all accepted connections use TLS.
    pub(crate) tls: Option<TlsConfig>,
    /// Per-listener TLS, indexed by `ListenerId`. Populated by `launch()` from
    /// the `bind*()` calls; an entry of `None` falls back to `tls` above.
    /// Empty in client-only mode.
    pub(crate) listener_tls: Vec<Option<TlsConfig>>,
    /// Optional TLS client configuration for outbound `connect(addr).tls(..)` calls.
    pub(crate) tls_client: Option<TlsClientConfig>,
    /// Enable TCP_NODELAY on all connections (accepted and outbound).
    pub(crate) tcp_nodelay: bool,
    /// Where connections are accepted. See [`AcceptMode`].
    pub(crate) accept_mode: AcceptMode,
    /// Merged accept mode: this worker's own `SO_REUSEPORT` listener sockets,
    /// as `(listener index, fd)`. Bound but **not** listening when the worker
    /// starts — `launch()` calls `listen(2)` only once every worker has
    /// reported ready, so "listening" and "ready to serve" are the same
    /// instant. Empty in pool mode and in client-only mode.
    pub(crate) merged_accept_fds: Vec<(u32, std::os::fd::RawFd)>,
    /// Set by `launch()` after it has called `listen(2)` on every merged
    /// socket. Until then a worker must not arm an accept: accept on a
    /// bound-but-unlistening socket fails with `EINVAL`.
    pub(crate) merged_accept_live: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// This worker's index, so it can find its own slot in `worker_loads` and
    /// avoid handing a connection back to itself.
    pub(crate) worker_index: usize,
    /// Live connection count per worker, published by each worker and read by
    /// all of them when placing a newly accepted connection. Merged accept
    /// mode only — pool mode places explicitly in the acceptor thread.
    pub(crate) worker_loads: Option<std::sync::Arc<Vec<std::sync::atomic::AtomicU32>>>,
    /// Which workers are in the accept rotation. Placement must not hand a
    /// connection to a worker that has been steered out: taking it out of the
    /// rotation drops its load, which would otherwise make it the most
    /// attractive handoff target — the two mechanisms would fight.
    pub(crate) worker_accepting: Option<std::sync::Arc<Vec<std::sync::atomic::AtomicBool>>>,
    /// Every worker's accept channel and wake handle, so a worker that accepts
    /// while over its share can hand the raw fd to a less-loaded peer. Empty
    /// in pool mode, where the acceptor thread owns these.
    pub(crate) peer_accept: Vec<(
        crossbeam_channel::Sender<crate::acceptor::AcceptedConn>,
        crate::wakeup::WakeFd,
    )>,
    /// Every worker's park channel and wake handle, for handing a connection
    /// lifted off this worker to its new one (tier 3, #443).
    ///
    /// A sibling of `peer_accept` rather than a variant on it: the mio
    /// backend drains `peer_accept` too, and has neither merged accept nor
    /// park, so folding park into that type would put a permanently dead arm
    /// in a backend that cannot reach it.
    pub(crate) peer_park: Vec<(
        crossbeam_channel::Sender<crate::park::ParkedFd>,
        crate::wakeup::WakeFd,
    )>,
    /// This worker's receiving end of the park channel.
    pub(crate) park_rx: Option<crossbeam_channel::Receiver<crate::park::ParkedFd>>,
    /// Print per-worker event-loop diagnostics to stderr at shutdown: the
    /// iteration mix (`[ringline diag]`) and wait/work stall buckets
    /// (`[ringline stall]`). The stall buckets cost ~4 clock reads per
    /// iteration while enabled. io_uring backend only. Default: false.
    pub(crate) loop_diag: bool,
    /// Enable SO_TIMESTAMPING for kernel-level receive timestamps.
    /// When enabled, connections use `RecvMsgMulti` instead of `RecvMulti`
    /// to receive ancillary data containing kernel RX timestamps.
    #[cfg(feature = "timestamps")]
    pub(crate) timestamps: bool,
    /// Maximum number of SQEs per IOSQE_IO_LINK chain. 0 disables chaining.
    /// When disabled, sends exceeding MAX_IOVECS fall back to sequential
    /// round-trips (one SQE at a time via on_send_complete).
    /// Default: 16.
    pub(crate) max_chain_length: u16,
    /// Maximum number of standalone async tasks (not bound to connections)
    /// per worker. Used with [`spawn()`](crate::spawn).
    /// Default: 256.
    pub(crate) standalone_task_capacity: u32,
    /// Maximum number of concurrent timer slots per worker.
    /// Used by [`sleep()`](crate::sleep) and [`timeout()`](crate::timeout).
    /// Default: 256.
    pub(crate) timer_slots: u32,
    /// UDP bind addresses. Each worker creates its own socket with SO_REUSEPORT.
    /// Empty = no UDP sockets.
    pub(crate) udp_bind: Vec<SocketAddr>,
    /// Optional peer to `connect(2)` each UDP socket to, parallel to
    /// `udp_bind`. `None` leaves the socket unconnected (the usual UDP
    /// server case); `Some(peer)` calls `connect()` so the kernel filters
    /// incoming datagrams to that peer and the runtime can use the lighter
    /// `RecvUdp`/`SendUdp` opcodes instead of `RecvMsgUdp`/`SendMsgUdp`.
    /// Saves ~4 microseconds per round trip on single-shot client workloads.
    /// Must have the same length as `udp_bind` (enforced at validation).
    pub(crate) udp_connect_peers: Vec<Option<SocketAddr>>,
    /// Number of concurrent in-flight UDP sends per socket. Each slot owns a
    /// pre-allocated `sockaddr_storage` + `iovec` + `msghdr` triple used to
    /// submit a `sendmsg` SQE; the slot is returned to the freelist on CQE.
    /// Exhaustion returns [`crate::error::UdpSendError::PoolExhausted`].
    /// Default: 64.
    pub(crate) udp_send_slots: u16,
    /// Maximum number of datagrams buffered per UDP socket awaiting a
    /// consumer. The runtime fills this queue from `recvmsg` completions;
    /// the application's `on_udp_bind` future drains it via
    /// [`UdpCtx::recv_from`](crate::UdpCtx::recv_from). When the queue is
    /// full, additional datagrams are dropped and
    /// `udp::DATAGRAMS_DROPPED` is incremented — this guards against
    /// unbounded memory growth when the handler future stalls, panics,
    /// or returns early.
    ///
    /// Default: 1024.
    pub(crate) udp_recv_queue_capacity: usize,
    /// Enable UDP Generic Receive Offload (GRO) on bound UDP sockets.
    ///
    /// When set, the runtime calls `setsockopt(SOL_UDP, UDP_GRO)` so the
    /// kernel coalesces consecutive same-flow datagrams into one `recvmsg`
    /// delivery, carrying the per-segment size in a control message. The
    /// runtime splits the coalesced payload back into individual datagrams
    /// transparently, so [`UdpCtx::recv_batch`](crate::UdpCtx::recv_batch) /
    /// [`recv_batch_timed`](crate::UdpCtx::recv_batch_timed) callbacks still
    /// fire once per datagram. This cuts per-datagram syscall / wake overhead
    /// dramatically for high-pps flows (e.g. QUIC at large payloads).
    ///
    /// A coalesced datagram can be up to ~64 KiB, and on io_uring the
    /// recvmsg header + sockaddr + control + payload share one provided
    /// buffer, so enabling GRO requires `udp_recv_buffer.buffer_size` to be
    /// large enough to hold a full coalesced datagram (validated at startup);
    /// otherwise the kernel truncates and the datagram is dropped. Has no
    /// effect on `connect(2)`-ed UDP sockets (they use the lighter `recv`
    /// path, which carries no control message). Linux-only — a no-op on
    /// other platforms. Default: false.
    pub(crate) udp_gro: bool,
    /// Optional NVMe passthrough configuration. When set, enables NVMe device
    /// management and `IORING_OP_URING_CMD` submission for direct NVMe I/O.
    pub(crate) nvme: Option<crate::nvme::NvmeConfig>,
    /// Optional direct I/O configuration. When set, enables `O_DIRECT` file I/O
    /// via io_uring `IORING_OP_READ` / `IORING_OP_WRITE`, bypassing the page cache.
    pub(crate) direct_io: Option<crate::direct_io::DirectIoConfig>,
    /// Optional buffered filesystem I/O configuration. When set, enables async
    /// file open/read/write/stat/rename/unlink/mkdir via io_uring.
    pub(crate) fs: Option<crate::fs::FsConfig>,
    /// Number of dedicated DNS resolver threads. The resolver pool runs
    /// `getaddrinfo` on background threads, keeping blocking DNS isolated
    /// from the io_uring event loop.
    ///
    /// 0 = disabled (no resolver pool; [`resolve()`](crate::resolve) will
    /// return an error). Default: 2.
    pub(crate) resolver_threads: usize,
    /// Number of dedicated process spawner threads. The spawner pool runs
    /// `posix_spawnp` + `pidfd_open` on background threads, keeping blocking
    /// process creation isolated from the io_uring event loop.
    ///
    /// 0 = disabled (no spawner pool; [`Command::spawn()`](crate::process::Command::spawn)
    /// will return an error). Default: 1.
    pub(crate) spawner_threads: usize,
    /// Number of dedicated blocking threads. The blocking pool runs
    /// user-provided closures on low-priority (`SCHED_IDLE`) background threads,
    /// keeping CPU-bound or blocking work isolated from the io_uring event loop.
    ///
    /// 0 = disabled (no blocking pool; [`spawn_blocking()`](crate::spawn_blocking)
    /// will return an error). Default: 4.
    pub(crate) blocking_threads: usize,
    /// Number of dedicated disk I/O threads (mio backend only). The disk I/O
    /// pool executes blocking filesystem syscalls (pread, pwrite, fsync, stat,
    /// rename, unlink, mkdir) on background threads, enabling async file I/O
    /// on non-Linux platforms.
    ///
    /// 0 = disabled (filesystem/direct I/O operations return `Unsupported`).
    /// Default: 2.
    pub(crate) disk_io_threads: usize,
    /// Maximum time in milliseconds to wait for a TLS close_notify send to
    /// complete before force-closing the connection. When a TLS connection
    /// sends close_notify but the send never completes (e.g., due to pool
    /// exhaustion), this prevents the connection from hanging indefinitely.
    /// Default: 5000.
    pub(crate) close_notify_timeout_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sq_entries: 256,
            sqpoll: false,
            sqpoll_idle_ms: 1000,
            sqpoll_cpu: None,
            recv_buffer: RecvBufferConfig::default(),
            udp_recv_buffer: RecvBufferConfig {
                ring_size: 128,
                buffer_size: 2048,
                bgid: 1,
            },
            registered_regions: Vec::new(),
            max_registered_regions: 64,
            worker: WorkerConfig::default(),
            backlog: 1024,
            max_connections: 16000,
            recv_accumulator_capacity: 4096,
            recv_accumulator_max: 1024 * 1024 * 1024,
            recv_segment_reserve: 64,
            forward_hold_cap: 64,
            // Off by default while the trade is being measured: prefaulting
            // converts a latent memory cost into an immediate one, which is
            // the intent but is also a behaviour change for anything that
            // over-provisions today and never touches what it asked for.
            prefault_buffers: false,
            accept_queue_capacity: 1024,
            conn_chunk_size: 1,
            send_copy_count: 1024,
            send_copy_slot_size: 16448,
            send_zc_threshold: 4096,
            send_slab_slots: 512,
            flush_interval_us: 100,
            tick_timeout_us: 1000,
            tls: None,
            listener_tls: Vec::new(),
            tls_client: None,
            tcp_nodelay: true,
            accept_mode: AcceptMode::Pool,
            merged_accept_fds: Vec::new(),
            merged_accept_live: None,
            worker_index: 0,
            worker_loads: None,
            worker_accepting: None,
            peer_accept: Vec::new(),
            peer_park: Vec::new(),
            park_rx: None,
            loop_diag: false,
            #[cfg(feature = "timestamps")]
            timestamps: false,
            max_chain_length: 16,
            standalone_task_capacity: 256,
            timer_slots: 256,
            udp_bind: Vec::new(),
            udp_connect_peers: Vec::new(),
            udp_send_slots: 64,
            udp_recv_queue_capacity: 1024,
            udp_gro: false,
            nvme: None,
            direct_io: None,
            fs: Some(crate::fs::FsConfig::default()),
            resolver_threads: 2,
            spawner_threads: 1,
            blocking_threads: 4,
            disk_io_threads: 2,
            close_notify_timeout_ms: 5000,
        }
    }
}

impl Config {
    /// The zero-copy guard send threshold in bytes. See
    /// [`ConfigBuilder::send_zc_threshold`].
    pub fn send_zc_threshold(&self) -> u32 {
        self.send_zc_threshold
    }

    /// Validate configuration values. Returns an error if any value is out of range.
    /// A TLS connection encrypts into the same `SendCopyPool` slots that plain
    /// sends copy into, so `send_copy_slot_size` quietly carries two unrelated
    /// contracts: the chunking granularity for plain sends, and the
    /// destination for one TLS record.
    ///
    /// This rejects only the case that **cannot work at all**: the unbuffered
    /// record layer writes whole records into a slot and gives up below
    /// `MIN_ENCRYPT_DST`, so every send on every TLS connection would fail.
    /// Catching it here names the knob instead of surfacing it per-send.
    ///
    /// It deliberately does *not* enforce the larger "one whole record per
    /// slot" threshold (`F + 29`, which the shipped default clears by only 35
    /// bytes). That threshold governs whether a **bounded** send's admission
    /// bound is expressible on the unbuffered engine — see
    /// `docs/tls-premutation-bound-design.md`. Plain TLS sends work below it on
    /// both engines: the buffered engine straddles slots freely, and the
    /// unbuffered engine still encrypts, just emitting more records. This
    /// repo's own `tls_echo` tests run at 16384, 29 bytes under it. Rejecting
    /// that at startup would break working deployments to pre-empt a hazard
    /// that only reaches bounded sends, which already refuse themselves with a
    /// message naming the same knob.
    #[cfg(feature = "tls-unbuffered")]
    fn validate_tls_slot_size(&self) -> Result<(), crate::error::Error> {
        if self.tls.is_none() && self.tls_client.is_none() {
            return Ok(());
        }
        let min = crate::tls::unbuffered::MIN_ENCRYPT_DST;
        if (self.send_copy_slot_size as usize) < min {
            return Err(crate::error::Error::RingSetup(format!(
                "send_copy_slot_size is {} but the tls-unbuffered record layer cannot encrypt \
                 into a destination smaller than {min} bytes, so every TLS send would fail; \
                 raise send_copy_slot_size",
                self.send_copy_slot_size,
            )));
        }
        Ok(())
    }

    /// The buffered record layer packs ciphertext across slots through
    /// `PoolWriter`, so no slot size is too small for it to make progress.
    #[cfg(not(feature = "tls-unbuffered"))]
    fn validate_tls_slot_size(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if !self.recv_buffer.ring_size.is_power_of_two() {
            return Err(crate::error::Error::RingSetup(
                "recv_buffer.ring_size must be a power of two".into(),
            ));
        }
        if self.recv_buffer.buffer_size == 0 {
            return Err(crate::error::Error::RingSetup(
                "recv_buffer.buffer_size must be > 0".into(),
            ));
        }
        // A cap below one recv buffer would overflow on the first full
        // buffer, and some pending-buffer flush paths assume a single
        // buffer's append into an empty accumulator cannot fail.
        if self.recv_accumulator_max < self.recv_buffer.buffer_size as usize {
            return Err(crate::error::Error::RingSetup(
                "recv_accumulator_max must be >= recv_buffer_size \
                 (use usize::MAX to disable the cap)"
                    .into(),
            ));
        }
        if self.max_connections == 0 || self.max_connections >= (1 << 24) {
            return Err(crate::error::Error::RingSetup(
                "max_connections must be > 0 and < 2^24".into(),
            ));
        }
        // A zero-capacity crossbeam channel is a rendezvous channel: try_send
        // only succeeds while a receiver is blocked in recv(), and workers
        // only ever try_recv — so every accept would fail.
        if self.accept_queue_capacity == 0 {
            return Err(crate::error::Error::RingSetup(
                "accept_queue_capacity must be > 0".into(),
            ));
        }
        if self.timer_slots == 0 || self.timer_slots > 65535 {
            return Err(crate::error::Error::RingSetup(
                "timer_slots must be > 0 and <= 65535".into(),
            ));
        }
        if self.send_slab_slots == 0 {
            return Err(crate::error::Error::RingSetup(
                "send_slab_slots must be > 0".into(),
            ));
        }
        if self.send_copy_slot_size == 0 {
            return Err(crate::error::Error::RingSetup(
                "send_copy_slot_size must be > 0".into(),
            ));
        }
        if self.send_copy_count == 0 {
            return Err(crate::error::Error::RingSetup(
                "send_copy_count must be > 0".into(),
            ));
        }
        self.validate_tls_slot_size()?;
        // The provided ring can hold at most u16::MAX buffers, so a reserve above
        // that is nonsensical (it would force-copy every segmented delivery). A
        // reserve >= the configured ring_size is *allowed* (it simply makes
        // segmented delivery always copy) — it is not coupled here so small rings
        // stay valid.
        if self.recv_segment_reserve > u16::MAX as u32 {
            return Err(crate::error::Error::RingSetup(
                "recv_segment_reserve must be <= 65535 (the maximum provided-ring size)".into(),
            ));
        }
        // A cap of 0 would throttle a forward before it can hold its first
        // buffer, deadlocking the forward (nothing to write, never re-armed).
        if self.forward_hold_cap == 0 {
            return Err(crate::error::Error::RingSetup(
                "forward_hold_cap must be >= 1".into(),
            ));
        }
        if self.sq_entries == 0 || !self.sq_entries.is_power_of_two() {
            return Err(crate::error::Error::RingSetup(
                "sq_entries must be > 0 and a power of two".into(),
            ));
        }
        if self.standalone_task_capacity >= (1 << 31) {
            return Err(crate::error::Error::RingSetup(
                "standalone_task_capacity must be < 2^31".into(),
            ));
        }
        if self.registered_regions.len() > self.max_registered_regions as usize {
            return Err(crate::error::Error::RingSetup(format!(
                "registered_regions ({}) exceed max_registered_regions ({})",
                self.registered_regions.len(),
                self.max_registered_regions,
            )));
        }
        if !self.udp_bind.is_empty() && self.udp_send_slots == 0 {
            return Err(crate::error::Error::RingSetup(
                "udp_send_slots must be > 0 when udp_bind is non-empty".into(),
            ));
        }
        if !self.udp_connect_peers.is_empty() && self.udp_connect_peers.len() != self.udp_bind.len()
        {
            return Err(crate::error::Error::RingSetup(
                "udp_connect_peers length must match udp_bind length".into(),
            ));
        }
        if !self.udp_bind.is_empty() && self.udp_recv_queue_capacity == 0 {
            return Err(crate::error::Error::RingSetup(
                "udp_recv_queue_capacity must be > 0 when udp_bind is non-empty".into(),
            ));
        }
        if !self.udp_bind.is_empty() {
            if !self.udp_recv_buffer.ring_size.is_power_of_two() {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.ring_size must be a power of two".into(),
                ));
            }
            // Ceiling is 256 KiB so UDP GRO (which coalesces up to ~64 KiB of
            // payload plus the recvmsg header / sockaddr / control region into
            // one provided buffer) can be sized to fit. Non-GRO callers
            // typically stay near a single MTU.
            if self.udp_recv_buffer.buffer_size == 0 || self.udp_recv_buffer.buffer_size > (1 << 18)
            {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.buffer_size must be > 0 and <= 262144".into(),
                ));
            }
            // Each datagram occupies one buffer that also holds the
            // io_uring_recvmsg_out header (16 bytes) + sockaddr_storage
            // (128 bytes). Below that floor the kernel can't fit even a
            // zero-byte datagram plus the metadata.
            if self.udp_recv_buffer.buffer_size < 160 {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.buffer_size must be >= 160 to hold recvmsg header + sockaddr"
                        .into(),
                ));
            }
            // GRO coalesces up to ~64 KiB into a single delivery; the buffer
            // must hold that plus the recvmsg header (16) + sockaddr (128) +
            // control region, or the kernel truncates and the datagram is
            // dropped silently. Require headroom past 64 KiB.
            if self.udp_gro && self.udp_recv_buffer.buffer_size < (1 << 16) + 512 {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.buffer_size must be >= 66048 when udp_gro is enabled \
                     (a coalesced GRO datagram is up to ~64 KiB plus recvmsg metadata)"
                        .into(),
                ));
            }
            if self.udp_recv_buffer.bgid == self.recv_buffer.bgid {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.bgid must differ from recv_buffer.bgid".into(),
                ));
            }
        }
        if self.close_notify_timeout_ms == 0 || self.close_notify_timeout_ms > 60000 {
            return Err(crate::error::Error::RingSetup(
                "close_notify_timeout_ms must be > 0 and <= 60000".into(),
            ));
        }
        Ok(())
    }
}

/// Configuration for the provided buffer ring (multishot recv).
#[derive(Clone)]
pub(crate) struct RecvBufferConfig {
    /// Number of buffers in the ring (must be power of 2).
    pub ring_size: u16,
    /// Size of each buffer in bytes.
    pub buffer_size: u32,
    /// Buffer group ID for the provided buffer ring.
    pub bgid: u16,
}

impl Default for RecvBufferConfig {
    fn default() -> Self {
        Self {
            ring_size: 256,
            buffer_size: 16384,
            bgid: 0,
        }
    }
}

/// Configuration for the thread-per-core worker model.
#[derive(Clone)]
pub(crate) struct WorkerConfig {
    /// Number of worker threads.
    ///
    /// `0` (the default) auto-detects and uses the number of **physical CPU
    /// cores** — not logical CPUs. On SMT/hyperthreaded hardware this is half
    /// the value returned by `nproc` or `available_parallelism()`. Ringline's
    /// io_uring event loops are CPU-bound; two hyperthreads on the same
    /// physical core share execution units and caches, so spawning one worker
    /// per logical CPU induces contention without additional throughput.
    ///
    /// Set explicitly to override (e.g. `threads = 1` for a single-threaded
    /// server, or a larger value when you have many connections and the
    /// per-worker CPU budget is low).
    pub threads: usize,
    /// Whether to pin each worker to a CPU core.
    pub pin_to_core: bool,
    /// Starting CPU core index for pinning.
    pub core_offset: usize,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            threads: 0,
            pin_to_core: true,
            core_offset: 0,
        }
    }
}

/// Builder for [`Config`] with discoverable methods and `build()` validation.
///
/// # Example
///
/// ```rust
/// use ringline::ConfigBuilder;
///
/// let config = ConfigBuilder::default()
///     .workers(4)
///     .max_connections(8000)
///     .sq_entries(512)
///     .tcp_nodelay(true)
///     .recv_buffer(256, 4096)
///     .send_pool(512, 8192)
///     .timer_slots(1024)
///     .build()
///     .expect("invalid config");
/// ```
#[derive(Default)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new builder with default config values.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Worker settings ──────────────────────────────────────────────

    /// Set the number of worker threads. 0 = number of CPUs.
    pub fn workers(mut self, n: usize) -> Self {
        self.config.worker.threads = n;
        self
    }

    /// Enable or disable CPU core pinning.
    pub fn pin_to_core(mut self, enable: bool) -> Self {
        self.config.worker.pin_to_core = enable;
        self
    }

    /// Set the starting CPU core index for pinning.
    ///
    /// When `core_offset + worker_threads` fits within the machine's
    /// physical core count, this indexes *physical* cores and each
    /// worker is pinned to a distinct physical core's first SMT sibling
    /// (so hyperthread-adjacent CPU enumerations don't stack two workers
    /// on one core). Larger offsets are treated as raw logical CPU ids,
    /// which keeps deliberate hyperthread layouts expressible.
    pub fn core_offset(mut self, offset: usize) -> Self {
        self.config.worker.core_offset = offset;
        self
    }

    // ── Connection settings ──────────────────────────────────────────

    /// Set the maximum number of direct file descriptors (connections).
    pub fn max_connections(mut self, n: u32) -> Self {
        self.config.max_connections = n;
        self
    }

    /// Set the TCP listen backlog.
    pub fn backlog(mut self, n: i32) -> Self {
        self.config.backlog = n;
        self
    }

    /// Set the number of connections assigned to each worker before moving to
    /// the next one. `1` (the default) gives classic round-robin.
    pub fn conn_chunk_size(mut self, n: usize) -> Self {
        self.config.conn_chunk_size = n;
        self
    }

    /// Set the bound on the per-worker accept channel. Default: 1024.
    pub fn accept_queue_capacity(mut self, n: usize) -> Self {
        self.config.accept_queue_capacity = n;
        self
    }

    /// Choose where connections are accepted. Default [`AcceptMode::Pool`].
    ///
    /// [`AcceptMode::Merged`] is io_uring only; on the mio backend it is
    /// accepted and ignored, since mio has no multishot accept.
    pub fn accept_mode(mut self, mode: AcceptMode) -> Self {
        self.config.accept_mode = mode;
        self
    }

    /// Enable or disable TCP_NODELAY on all connections.
    pub fn tcp_nodelay(mut self, enable: bool) -> Self {
        self.config.tcp_nodelay = enable;
        self
    }

    // ── Diagnostics ──────────────────────────────────────────────────

    /// Print per-worker event-loop diagnostics to stderr at shutdown.
    ///
    /// Each worker prints a `[ringline diag]` line (iteration mix: dead
    /// iterations, CQEs and tasks per iteration, parks, fallbacks) and a
    /// `[ringline stall]` line (wait/work stall buckets). Recording the
    /// stall buckets costs ~4 clock reads per iteration, so this is off by
    /// default. io_uring backend only; the mio backend prints nothing.
    pub fn loop_diag(mut self, enable: bool) -> Self {
        self.config.loop_diag = enable;
        self
    }

    // ── io_uring settings ────────────────────────────────────────────

    /// Set the number of SQ entries. CQ will be 4x this. Must be a power of 2.
    pub fn sq_entries(mut self, n: u32) -> Self {
        self.config.sq_entries = n;
        self
    }

    /// Enable SQPOLL mode (kernel-side submission polling).
    pub fn sqpoll(mut self, enable: bool) -> Self {
        self.config.sqpoll = enable;
        self
    }

    /// Set SQPOLL idle timeout in milliseconds (default: 1000).
    pub fn sqpoll_idle_ms(mut self, ms: u32) -> Self {
        self.config.sqpoll_idle_ms = ms;
        self
    }

    /// Pin SQPOLL kernel thread to a specific CPU core.
    pub fn sqpoll_cpu(mut self, cpu: u32) -> Self {
        self.config.sqpoll_cpu = Some(cpu);
        self
    }

    // ── Buffer settings ──────────────────────────────────────────────

    /// Set recv buffer configuration.
    pub fn recv_buffer(mut self, ring_size: u16, buffer_size: u32) -> Self {
        self.config.recv_buffer.ring_size = ring_size;
        self.config.recv_buffer.buffer_size = buffer_size;
        self
    }

    /// Set the recv buffer group ID (bgid) for the TCP provided buffer ring.
    pub fn recv_buffer_bgid(mut self, bgid: u16) -> Self {
        self.config.recv_buffer.bgid = bgid;
        self
    }

    /// Set the initial capacity for per-connection recv accumulators.
    pub fn recv_accumulator_capacity(mut self, n: usize) -> Self {
        self.config.recv_accumulator_capacity = n;
        self
    }

    /// Set the upper bound on a single per-connection recv accumulator.
    /// The connection is closed if the cap is exceeded. Defaults to 1 GiB;
    /// `usize::MAX` disables the cap. Must be at least `recv_buffer_size`.
    ///
    /// Servers accepting data from untrusted peers should set this to
    /// 4–16× the typical request size. The parser must be able to see a
    /// complete message within the cap: protocol clients that parse whole
    /// replies from the accumulator (e.g. `ringline-redis`) need it larger
    /// than the largest reply they expect.
    pub fn recv_accumulator_max(mut self, n: usize) -> Self {
        self.config.recv_accumulator_max = n;
        self
    }

    /// Set the aggregate low-water reserve for segmented recv.
    ///
    /// When the shared per-worker recv ring's free-buffer count drops to this
    /// value or below, arriving buffers for `Segmented` connections are
    /// force-copied into owned `Bytes` (and their bids returned to the ring
    /// immediately) instead of being pinned as zero-copy held segments — so
    /// connections holding segments cannot deplete the ring and `ENOBUFS`-starve
    /// well-behaved connections under fan-in. Above the reserve, delivery stays
    /// zero-copy. `0` force-copies only when the ring is fully drained. Tune
    /// relative to the `recv_buffer` ring size; must be `<= 65535`.
    ///
    /// Default: 64 (a quarter of the default 256-buffer recv ring).
    pub fn recv_segment_reserve(mut self, reserve: u32) -> Self {
        self.config.recv_segment_reserve = reserve;
        self
    }

    /// Set the per-connection held-buffer cap for Mode A `forward_to`
    /// connections.
    ///
    /// When a forwarding connection has this many provided buffers held awaiting
    /// writes to the sink, the runtime cancels its multishot recv (closing its
    /// TCP receive window so the source stops sending) and re-arms it once the
    /// hold drains below the cap as writes complete — bounding one slow forward
    /// to `forward_hold_cap` held buffers so it cannot deplete the shared
    /// per-worker recv ring and starve other connections. Larger values allow
    /// more recv in flight (higher single-forward throughput) at the cost of more
    /// pinned ring buffers / held heap under a slow sink. Must be `>= 1`.
    ///
    /// Default: 64 (2× `MAX_IOVECS`).
    /// Fault buffer pages in at worker startup rather than on first use.
    ///
    /// The provided recv ring and the send copy pool are allocated zeroed,
    /// which means mapped but untouched: every page is the shared zero page
    /// until something writes to it. On the recv path that first write is the
    /// kernel copying an skb into the buffer, so the minor fault lands on the
    /// completion path. Enabling this walks both allocations once at startup,
    /// on the worker thread that owns them (so the pages stay NUMA-local to
    /// that worker).
    ///
    /// What it buys is predictability rather than throughput: faults stop
    /// appearing as ramp-phase p99 outliers, and RSS after startup equals RSS
    /// under load — so a ring the machine cannot back fails at launch instead
    /// of during a traffic burst, which is how `RLIMIT_NOFILE` and
    /// `RLIMIT_MEMLOCK` are already handled.
    ///
    /// What it costs is that over-provisioning stops being free. A
    /// `recv_buffer(256, 1 << 20)` ring is 256 MiB per worker whether or not
    /// the workload ever touches all of it; without this it is mostly virtual,
    /// with it the memory is resident from startup. Startup grows by roughly
    /// one pass over the allocation.
    ///
    /// **Default: false** while the trade is being measured (#416).
    pub fn prefault_buffers(mut self, enabled: bool) -> Self {
        self.config.prefault_buffers = enabled;
        self
    }

    pub fn forward_hold_cap(mut self, cap: usize) -> Self {
        self.config.forward_hold_cap = cap;
        self
    }

    /// Set the number and size of copy-send pool slots.
    ///
    /// Default: 1024 slots of 16448 bytes. One slot is consumed per chunk of a
    /// copy send regardless of how few bytes that chunk holds, so `count`
    /// bounds how many sends can be in flight per worker, and `slot_size`
    /// decides how many slots (and therefore SQEs) a large send costs.
    ///
    /// **`slot_size` also sizes TLS records.** Ciphertext is encrypted into
    /// these same slots, so the knob carries a second, less obvious contract:
    ///
    /// - One whole worst-case record is `F + 29` bytes, where `F` is rustls'
    ///   `max_fragment_size` **minus its 5-byte header** (so 16384 by default)
    ///   and 29 is the TLS 1.2 GCM overhead. The shipped default of 16448
    ///   clears that by **35 bytes**.
    /// - Below `F + 29`, plain TLS sends still work on both engines — the
    ///   buffered record layer straddles slots, and the unbuffered one emits
    ///   more records — but a **bounded** send (`send_backpressured`) can no
    ///   longer express a safe admission bound on the unbuffered engine and is
    ///   refused with an error naming this knob. See
    ///   `docs/tls-premutation-bound-design.md`.
    /// - Below 64 bytes the unbuffered record layer cannot encrypt at all;
    ///   that is rejected by [`ConfigBuilder::build`] rather than per-send.
    ///
    /// So if you lower `slot_size` for plain-send efficiency, or raise
    /// `max_fragment_size`, check it against `F + 29` first.
    pub fn send_pool(mut self, count: u16, slot_size: u32) -> Self {
        self.config.send_copy_count = count;
        self.config.send_copy_slot_size = slot_size;
        self
    }

    /// Set the zero-copy guard send threshold in bytes (0 = always zero-copy).
    pub fn send_zc_threshold(mut self, bytes: u32) -> Self {
        self.config.send_zc_threshold = bytes;
        self
    }

    /// Set the number of scatter-gather send slab slots.
    pub fn send_slab_slots(mut self, n: u16) -> Self {
        self.config.send_slab_slots = n;
        self
    }

    // ── Task/timer settings ──────────────────────────────────────────

    /// Set the maximum number of standalone async tasks per worker.
    pub fn standalone_task_capacity(mut self, n: u32) -> Self {
        self.config.standalone_task_capacity = n;
        self
    }

    /// Set the maximum number of concurrent timer slots per worker.
    pub fn timer_slots(mut self, n: u32) -> Self {
        self.config.timer_slots = n;
        self
    }

    // ── Timing settings ──────────────────────────────────────────────

    /// Set the tick timeout in microseconds. 0 = block indefinitely.
    pub fn tick_timeout_us(mut self, us: u64) -> Self {
        self.config.tick_timeout_us = us;
        self
    }

    /// Set the deadline-based flush interval in microseconds. 0 = disabled.
    pub fn flush_interval_us(mut self, us: u64) -> Self {
        self.config.flush_interval_us = us;
        self
    }

    // ── Timestamp settings ────────────────────────────────────────────

    /// Enable SO_TIMESTAMPING for kernel-level receive timestamps.
    #[cfg(feature = "timestamps")]
    pub fn timestamps(mut self, enable: bool) -> Self {
        self.config.timestamps = enable;
        self
    }

    // ── Chain settings ───────────────────────────────────────────────

    /// Set the maximum number of SQEs per IO_LINK chain. 0 disables chaining.
    pub fn max_chain_length(mut self, n: u16) -> Self {
        self.config.max_chain_length = n;
        self
    }

    // ── UDP settings ─────────────────────────────────────────────────

    /// Add a UDP bind address. Can be called multiple times. A zero port
    /// behaves as in [`RinglineBuilder::bind_udp`](crate::RinglineBuilder::bind_udp).
    pub fn udp_bind(mut self, addr: SocketAddr) -> Self {
        self.config.udp_bind.push(addr);
        self.config.udp_connect_peers.push(None);
        self
    }

    /// Add a UDP bind address that is then `connect(2)`ed to `peer`. The
    /// kernel filters incoming datagrams to `peer` and the runtime can use
    /// the lighter `RecvUdp`/`SendUdp` opcodes instead of the
    /// `RecvMsgUdp`/`SendMsgUdp` pair. Saves ~4 microseconds per round trip
    /// on single-shot client workloads. A zero local port behaves as in
    /// [`RinglineBuilder::bind_udp_connected`](crate::RinglineBuilder::bind_udp_connected).
    pub fn udp_bind_connected(mut self, local: SocketAddr, peer: SocketAddr) -> Self {
        self.config.udp_bind.push(local);
        self.config.udp_connect_peers.push(Some(peer));
        self
    }

    /// Set the number of concurrent in-flight UDP sends per socket.
    pub fn udp_send_slots(mut self, n: u16) -> Self {
        self.config.udp_send_slots = n;
        self
    }

    /// Set the UDP recv buffer configuration (ring_size, buffer_size).
    /// The `bgid` is left at its default; override it with
    /// [`udp_recv_buffer_bgid`](Self::udp_recv_buffer_bgid).
    pub fn udp_recv_buffer(mut self, ring_size: u16, buffer_size: u32) -> Self {
        self.config.udp_recv_buffer.ring_size = ring_size;
        self.config.udp_recv_buffer.buffer_size = buffer_size;
        self
    }

    /// Set the UDP recv buffer group ID (bgid). Must differ from the TCP
    /// `recv_buffer` bgid when UDP is in use.
    pub fn udp_recv_buffer_bgid(mut self, bgid: u16) -> Self {
        self.config.udp_recv_buffer.bgid = bgid;
        self
    }

    /// Set the per-UDP-socket recv queue capacity.
    ///
    /// Datagrams that arrive while the queue is full are dropped and
    /// counted in `udp::DATAGRAMS_DROPPED`. Default: 1024.
    ///
    /// On the io_uring backend each queued datagram pins one provided
    /// ring buffer until it is consumed, so the effective capacity is
    /// clamped to `udp_recv_buffer` ring_size — raise both knobs
    /// together for deeper queues. The mio backend copies datagrams into
    /// owned buffers and honors the full configured depth.
    pub fn udp_recv_queue_capacity(mut self, capacity: usize) -> Self {
        self.config.udp_recv_queue_capacity = capacity;
        self
    }

    /// Enable UDP GRO on bound UDP sockets. Remember
    /// to size `udp_recv_buffer` to hold a full coalesced datagram (~64 KiB).
    pub fn udp_gro(mut self, enabled: bool) -> Self {
        self.config.udp_gro = enabled;
        self
    }

    // ── Optional subsystems ──────────────────────────────────────────

    /// Set NVMe passthrough configuration.
    pub fn nvme(mut self, config: crate::nvme::NvmeConfig) -> Self {
        self.config.nvme = Some(config);
        self
    }

    /// Set direct I/O configuration.
    pub fn direct_io(mut self, config: crate::direct_io::DirectIoConfig) -> Self {
        self.config.direct_io = Some(config);
        self
    }

    /// Set filesystem I/O configuration.
    pub fn fs(mut self, config: crate::fs::FsConfig) -> Self {
        self.config.fs = Some(config);
        self
    }

    /// Disable filesystem I/O support entirely.
    ///
    /// `fs` defaults to enabled (unlike `nvme`/`direct_io`), so its
    /// per-worker file table and command slab are otherwise always
    /// allocated. Workloads that never touch [`crate::fs`] can reclaim
    /// that footprint; fs operations will then fail with "filesystem I/O
    /// not configured".
    pub fn no_fs(mut self) -> Self {
        self.config.fs = None;
        self
    }

    /// Set the number of DNS resolver threads. 0 = disabled.
    pub fn resolver_threads(mut self, threads: usize) -> Self {
        self.config.resolver_threads = threads;
        self
    }

    /// Set the number of process spawner threads. 0 = disabled.
    pub fn spawner_threads(mut self, threads: usize) -> Self {
        self.config.spawner_threads = threads;
        self
    }

    /// Set the number of blocking threads. 0 = disabled.
    pub fn blocking_threads(mut self, threads: usize) -> Self {
        self.config.blocking_threads = threads;
        self
    }

    /// Set the number of disk I/O threads (mio backend only). 0 = disabled.
    pub fn disk_io_threads(mut self, threads: usize) -> Self {
        self.config.disk_io_threads = threads;
        self
    }

    /// Set the TLS close_notify timeout in milliseconds. Default: 5000.
    pub fn close_notify_timeout_ms(mut self, ms: u64) -> Self {
        self.config.close_notify_timeout_ms = ms;
        self
    }

    /// Set TLS server configuration.
    pub fn tls(mut self, config: TlsConfig) -> Self {
        self.config.tls = Some(config);
        self
    }

    /// Set TLS client configuration for outbound connections.
    pub fn tls_client(mut self, config: TlsClientConfig) -> Self {
        self.config.tls_client = Some(config);
        self
    }

    // ── Memory regions ───────────────────────────────────────────────

    /// Set the user-registered memory regions occupying the initial
    /// registered-buffer slots.
    pub fn registered_regions(mut self, regions: Vec<MemoryRegion>) -> Self {
        self.config.registered_regions = regions;
        self
    }

    /// Set the maximum number of fixed-buffer slots to reserve. Must be
    /// `>= registered_regions.len()`. Default: 64.
    pub fn max_registered_regions(mut self, n: u16) -> Self {
        self.config.max_registered_regions = n;
        self
    }

    // ── Terminal ─────────────────────────────────────────────────────

    /// Validate and build the final [`Config`].
    pub fn build(self) -> Result<Config, crate::error::Error> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a Config with a single field override.
    /// Avoids clippy::field_reassign_with_default on the multi-field Config struct.
    fn config_with(f: impl FnOnce(&mut Config)) -> Config {
        let mut c = Config::default();
        f(&mut c);
        c
    }

    #[test]
    fn validate_default_config_passes() {
        Config::default()
            .validate()
            .expect("default config should be valid");
    }

    #[test]
    fn loop_diag_defaults_off_and_builder_enables_it() {
        assert!(!Config::default().loop_diag);
        let c = ConfigBuilder::new().loop_diag(true).build().unwrap();
        assert!(c.loop_diag);
    }

    #[test]
    fn default_recv_accumulator_max_is_bounded() {
        // Principle 7: growth that cannot terminate is bounded by default.
        let c = Config::default();
        assert_eq!(c.recv_accumulator_max, 1024 * 1024 * 1024);
    }

    #[test]
    fn validate_recv_accumulator_max_below_buffer_size_rejected() {
        // Also covers 0: any cap below one recv buffer is rejected.
        assert!(
            config_with(|c| c.recv_accumulator_max = 0)
                .validate()
                .is_err()
        );
        assert!(
            config_with(|c| c.recv_accumulator_max = c.recv_buffer.buffer_size as usize - 1)
                .validate()
                .is_err()
        );
        assert!(
            config_with(|c| c.recv_accumulator_max = c.recv_buffer.buffer_size as usize)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_timer_slots_zero_rejected() {
        assert!(config_with(|c| c.timer_slots = 0).validate().is_err());
    }

    #[test]
    fn validate_send_slab_slots_zero_rejected() {
        assert!(config_with(|c| c.send_slab_slots = 0).validate().is_err());
    }

    #[test]
    fn validate_accept_queue_capacity_zero_rejected() {
        // bounded(0) is a rendezvous channel; workers only try_recv, so
        // every accept would fail with the queue reported as full.
        assert!(
            config_with(|c| c.accept_queue_capacity = 0)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_buffer_size_zero_rejected() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 0)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_buffer_size_accepted_65535() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 65535)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_buffer_size_accepted_65536() {
        // 65536 is the first value that previously caused a crash; it must now be
        // accepted (the remaining-bytes counter is stored in the driver, not in the
        // 16-bit CQE payload).
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 65536)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_buffer_size_accepted_large() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 131072)
                .validate()
                .is_ok()
        );
    }

    fn udp_config_with(f: impl FnOnce(&mut Config)) -> Config {
        config_with(|c| {
            c.udp_bind = vec!["127.0.0.1:0".parse().unwrap()];
            f(c);
        })
    }

    #[test]
    fn validate_udp_gro_requires_large_buffer() {
        // Default udp buffer (2048) is far too small for a coalesced datagram.
        let err = udp_config_with(|c| c.udp_gro = true)
            .validate()
            .unwrap_err();
        assert!(format!("{err}").contains("udp_gro"));
    }

    #[test]
    fn validate_udp_gro_accepts_large_buffer() {
        udp_config_with(|c| {
            c.udp_gro = true;
            c.udp_recv_buffer.buffer_size = 1 << 17;
        })
        .validate()
        .expect("udp_gro with a 128 KiB buffer should be valid");
    }

    #[test]
    fn validate_udp_buffer_ceiling_raised() {
        // The ceiling moved from 64 KiB to 256 KiB to accommodate GRO.
        udp_config_with(|c| c.udp_recv_buffer.buffer_size = 1 << 18)
            .validate()
            .expect("256 KiB udp buffer should be accepted");
        assert!(
            udp_config_with(|c| c.udp_recv_buffer.buffer_size = (1 << 18) + 1)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_ring_size_not_power_of_two_rejected() {
        assert!(
            config_with(|c| c.recv_buffer.ring_size = 3)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_sq_entries_not_power_of_two_rejected() {
        assert!(config_with(|c| c.sq_entries = 3).validate().is_err());
    }

    #[test]
    fn validate_sq_entries_zero_rejected() {
        assert!(config_with(|c| c.sq_entries = 0).validate().is_err());
    }

    #[test]
    fn validate_max_connections_zero_rejected() {
        assert!(config_with(|c| c.max_connections = 0).validate().is_err());
    }

    #[test]
    fn validate_max_connections_too_large_rejected() {
        assert!(
            config_with(|c| c.max_connections = 1 << 24)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_timer_slots_too_large_rejected() {
        assert!(config_with(|c| c.timer_slots = 65536).validate().is_err());
    }

    #[test]
    fn validate_send_copy_slot_size_zero_rejected() {
        assert!(
            config_with(|c| c.send_copy_slot_size = 0)
                .validate()
                .is_err()
        );
    }

    /// A TLS server config with `max_fragment_size` pinned, for the slot-size
    /// checks below. The certificate is irrelevant to validation — only the
    /// fragment size is read.
    #[cfg(test)]
    fn tls_server_config(max_fragment_size: Option<usize>) -> TlsConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert);
        let mut sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key.into())
            .unwrap();
        sc.max_fragment_size = max_fragment_size;
        TlsConfig::new(std::sync::Arc::new(sc))
    }

    // The shipped default clears the TLS record minimum by 35 bytes
    // (16448 against F + 29 = 16413). That is the configuration everyone runs,
    // so it must validate.
    #[test]
    fn validate_default_slot_size_accepts_default_tls() {
        config_with(|c| c.tls = Some(tls_server_config(None)))
            .validate()
            .expect("the shipped default must accept TLS");
    }

    // Without TLS the slot size means only "chunking granularity", and a small
    // one is a legitimate tuning choice. Validation must not touch it.
    #[test]
    fn validate_small_slot_size_is_fine_without_tls() {
        config_with(|c| c.send_copy_slot_size = 512)
            .validate()
            .expect("a small slot size is only a TLS concern");
    }

    // The repo's own tls_echo tests run at 16384 — 29 bytes under the "one
    // whole record" threshold — and they pass, because plain TLS sends work
    // below it on both engines. Validation must not reject a configuration
    // that works.
    #[test]
    fn validate_accepts_a_slot_just_under_one_whole_record() {
        config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 16384;
        })
        .validate()
        .expect("16384 with TLS is in use in this repo's own tests and works");
    }

    // Likewise a slot far below the threshold: the buffered engine straddles
    // slots, and the unbuffered engine still encrypts, just in more records.
    // Only a *bounded* send needs the larger threshold, and it refuses itself.
    #[test]
    fn validate_accepts_a_small_slot_with_tls() {
        config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 4096;
        })
        .validate()
        .expect("plain TLS sends work at 4096 on both engines");
    }

    // What is rejected is the slot that cannot work at all: below
    // `MIN_ENCRYPT_DST` the unbuffered record layer refuses every encrypt, so
    // every TLS send on every connection fails. Better at startup than
    // per-send. The buffered engine has no such floor, so this is gated.
    #[test]
    #[cfg(feature = "tls-unbuffered")]
    fn validate_rejects_a_slot_the_unbuffered_engine_cannot_encrypt_into() {
        let err = config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 32;
        })
        .validate()
        .expect_err("32 is below MIN_ENCRYPT_DST");
        assert!(
            err.to_string().contains("send_copy_slot_size"),
            "the error must name the knob: {err}"
        );
    }

    // A client config reaches the same check — outbound TLS connections
    // encrypt through the same pool.
    #[test]
    #[cfg(feature = "tls-unbuffered")]
    fn validate_checks_the_client_config_too() {
        let cc: std::sync::Arc<rustls::ClientConfig> = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
            .into();
        config_with(|c| {
            c.tls_client = Some(TlsClientConfig::new(cc.clone()));
            c.send_copy_slot_size = 32;
        })
        .validate()
        .expect_err("an outbound TLS connection uses the same pool");
    }

    // Without TLS there is no floor at all: the slot size is purely a
    // plain-send tuning knob.
    #[test]
    fn validate_tiny_slot_size_is_fine_without_tls() {
        config_with(|c| c.send_copy_slot_size = 32)
            .validate()
            .expect("no TLS, no record to hold");
    }

    #[test]
    fn validate_send_copy_count_zero_rejected() {
        assert!(config_with(|c| c.send_copy_count = 0).validate().is_err());
    }

    #[test]
    fn validate_standalone_task_capacity_too_large_rejected() {
        assert!(
            config_with(|c| c.standalone_task_capacity = 1 << 31)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn send_zc_threshold_default() {
        assert_eq!(Config::default().send_zc_threshold, 4096);
    }

    #[test]
    fn send_zc_threshold_builder_zero() {
        let cfg = ConfigBuilder::default()
            .send_zc_threshold(0)
            .build()
            .expect("zero send_zc_threshold should be valid");
        assert_eq!(cfg.send_zc_threshold, 0);
    }
}
