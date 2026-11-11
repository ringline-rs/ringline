use std::net::SocketAddr;

#[cfg(any(feature = "unstable-accept", test))]
pub use crate::accept::AcceptMode;
#[cfg(not(any(feature = "unstable-accept", test)))]
use crate::accept::AcceptMode;
use crate::buffer::fixed::MemoryRegion;

pub use ringline_tls_config::{TlsClientConfig, TlsConfig};

/// A failure for a test to inject into a running worker's event loop.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestFault {
    /// Panic in the event loop.
    pub(crate) panic: std::sync::atomic::AtomicBool,
    /// Return an error from the event loop.
    pub(crate) error: std::sync::atomic::AtomicBool,
    /// Return an error from this worker's event loop, plus one. Zero is off.
    #[cfg(has_io_uring)]
    pub(crate) error_on_worker: std::sync::atomic::AtomicU32,
    /// Panic before dispatching the Nth accept completion, counting from 1.
    /// Zero is off.
    #[cfg(has_io_uring)]
    pub(crate) panic_on_accept: std::sync::atomic::AtomicU32,
    /// Panic in the drain that follows.
    #[cfg(has_io_uring)]
    pub(crate) panic_in_drain: std::sync::atomic::AtomicBool,
    /// Submit no cancels for disk commands at worker exit, standing in for
    /// an operation a cancel cannot end.
    #[cfg(has_io_uring)]
    pub(crate) keep_disk_commands_at_exit: std::sync::atomic::AtomicBool,
    /// Hold every disk-I/O pool request a thread starts until cleared, after
    /// it is marked running, standing in for a slow `pread`.
    #[cfg(not(has_io_uring))]
    pub(crate) hold_disk_io: std::sync::atomic::AtomicBool,
    /// Set by a disk-I/O pool thread once it holds a request.
    #[cfg(not(has_io_uring))]
    pub(crate) disk_io_held: std::sync::atomic::AtomicBool,
    /// Requests a disk-I/O pool thread answered without running, after the
    /// worker exited.
    #[cfg(not(has_io_uring))]
    pub(crate) disk_io_skipped: std::sync::atomic::AtomicU32,
}

#[cfg(test)]
impl TestFault {
    /// Fail as asked, once. Called by the event loops.
    pub(crate) fn check(&self) -> Result<(), crate::error::Error> {
        use std::sync::atomic::Ordering;
        if self.panic.swap(false, Ordering::AcqRel) {
            panic!("injected event loop panic");
        }
        if self.error.swap(false, Ordering::AcqRel) {
            return Err(crate::error::Error::Io(std::io::Error::other(
                "injected event loop error",
            )));
        }
        Ok(())
    }

    /// Fail as asked before dispatching a completion.
    #[cfg(has_io_uring)]
    pub(crate) fn check_cqe(&self, user_data: u64) {
        use std::sync::atomic::Ordering;
        let left = self.panic_on_accept.load(Ordering::Acquire);
        if left > 0
            && crate::completion::UserData(user_data).tag()
                == Some(crate::completion::OpTag::AcceptMulti)
        {
            self.panic_on_accept.store(left - 1, Ordering::Release);
            if left == 1 {
                panic!("injected panic in a completion handler");
            }
        }
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
    /// Upper bound on each worker's bounded io-wq pool; 0 (the default)
    /// leaves the kernel's limit.
    pub(crate) iowq_max_workers: u32,
    /// Test-only: what goes ahead of a connection's `Close`, in place of the
    /// running kernel's choice, so either kernel's close path can be tested
    /// on one host.
    #[cfg(all(test, has_io_uring))]
    pub(crate) close_lead_override: Option<crate::backend::uring::ring::CloseLead>,
    /// Recv buffer configuration for UDP multishot recvmsg.
    ///
    /// Each buffer must fit an `io_uring_recvmsg_out`
    /// header (16 bytes) + `sockaddr_storage` (128 bytes) + the datagram
    /// payload. Default: 128 buffers × 2048 bytes per socket (room for a
    /// standard-MTU datagram plus the multishot metadata); bump `buffer_size`
    /// if you expect jumbo datagrams.
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
    /// Listen backlog. The kernel caps it at `net.core.somaxconn`
    /// (`kern.ipc.somaxconn` on macOS).
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
    /// the handler runs).
    pub(crate) recv_accumulator_max: usize,
    /// Size of a direct connection's own receive buffer. See
    /// `ConfigBuilder::recv_direct_region`.
    pub(crate) recv_direct_region: usize,
    /// Arm a parked reader's direct receive after the worker's next wait. See
    /// `ConfigBuilder::defer_recv_arm`.
    pub(crate) defer_recv_arm: bool,
    /// Most bytes of free buffers a worker keeps for direct connections to
    /// borrow. See `ConfigBuilder::recv_direct_pool_max`.
    pub(crate) recv_direct_pool_max: usize,
    /// How much a connection may have queued before a forward stops reading
    /// from it. See `ConfigBuilder::forward_hold_cap`.
    pub(crate) forward_hold_cap: usize,
    /// Fault the send copy pool's pages in at worker startup instead of on
    /// first use. See `ConfigBuilder::prefault_buffers`.
    pub(crate) prefault_buffers: bool,
    /// Bound on the per-worker accept channel. If a worker can't drain its
    /// queue fast enough, the acceptor skips past it, and if every worker is
    /// full it stops accepting until one has room. Default: 1024.
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
    /// The default is 16448, not 16384, so that one whole worst-case TLS
    /// record (16413 bytes: 5-byte header + 2^14 plaintext + 8-byte explicit
    /// nonce + 16-byte tag) fits in one slot, rounded up to a 64-byte
    /// boundary. On the unbuffered TLS engine (the default) `Config::validate`
    /// rejects a smaller slot when TLS is configured; see
    /// `ConfigBuilder::send_pool`. Costs 64 bytes per slot, 0.4% of the pool.
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
    /// Number of `InFlightSendSlab` entries. A zero-copy send (`send_parts`
    /// with a guard, when the batch totals at least `send_zc_threshold`)
    /// holds one until the
    /// kernel's notification arrives. A run of two or more consecutive copy
    /// sends queued on one connection, such as the slots of a `send` wider
    /// than one slot or a TLS send's ciphertext, is sent as one `sendmsg`
    /// and holds one until that CQE; with the slab full those slots go out
    /// one per CQE instead. Guard sends fail with `Other("send slab
    /// exhausted")` while it is full. Default: 512.
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
    /// Where connections are accepted. Always `Pool` without the
    /// `unstable-accept` feature.
    pub(crate) accept_mode: AcceptMode,
    /// What a worker does when a task panics.
    pub(crate) task_panic_policy: crate::TaskPanicPolicy,
    /// Merged accept mode: every merged listener's `SO_REUSEPORT` sockets, as
    /// `(listener index, sockets)`; the worker at index `i` accepts on socket
    /// `i`. Bound but **not** listening when the worker starts — `launch()`
    /// calls `listen(2)` only once every worker has reported ready, so
    /// "listening" and "ready to serve" are the same instant. Empty in pool
    /// mode and in client-only mode.
    pub(crate) merged_listeners: Vec<(
        u32,
        std::sync::Arc<crate::listener_sockets::ListenerSockets>,
    )>,
    /// Set by `launch()` after it has called `listen(2)` on every merged
    /// socket. Until then a worker must not arm an accept: accept on a
    /// bound-but-unlistening socket fails with `EINVAL`.
    pub(crate) merged_accept_live: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Every worker's wake handle. Set by `launch()`; the worker's `Config`
    /// holds every wake fd open until the worker exits, and the mio backend
    /// passes it to the per-worker disk-I/O pool, whose threads can outlive
    /// the worker.
    pub(crate) wake_keep_alive: Option<crate::wakeup::WakeKeepAlive>,
    /// The runtime's shutdown, so a task panic under
    /// `TaskPanicPolicy::Shutdown` can trigger it. Set by `launch()`.
    pub(crate) runtime_shutdown: Option<std::sync::Arc<crate::worker::RuntimeShutdown>>,
    /// Makes a running worker fail, see [`TestFault`].
    #[cfg(test)]
    pub(crate) test_fault: Option<std::sync::Arc<TestFault>>,
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
    /// while over its share can hand the connection to a less-loaded peer. Empty
    /// in pool mode, where the acceptor thread owns these.
    pub(crate) peer_accept: Vec<(
        crate::handoff::Sender<crate::acceptor::AcceptedConn>,
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
        crate::handoff::Sender<crate::park::ParkedFd>,
        crate::wakeup::WakeFd,
    )>,
    /// Print per-worker event-loop diagnostics to stderr at shutdown: the
    /// iteration mix (`[ringline diag]`) and wait/work stall buckets
    /// (`[ringline stall]`). The stall buckets cost ~4 clock reads per
    /// iteration while enabled. io_uring backend only. Default: false.
    pub(crate) loop_diag: bool,
    /// Maximum parts in one `send_chain` (`SendChainBuilder::copy` and
    /// `ChainPartsBuilder::add` each count one). A chain that would exceed
    /// it fails with `InvalidInput`. 0 refuses every chain. It does not
    /// affect `send`, `send_nowait` or `send_parts`. Default: 16.
    pub(crate) max_chain_length: u16,
    /// Maximum number of standalone async tasks (not bound to connections)
    /// per worker. Used with [`spawn()`](crate::spawn).
    /// Default: 256.
    pub(crate) standalone_task_capacity: u32,
    /// UDP bind addresses. Each worker creates its own socket with SO_REUSEPORT.
    /// Empty = no UDP sockets.
    pub(crate) udp_bind: Vec<SocketAddr>,
    /// Optional peer to `connect(2)` each UDP socket to, parallel to
    /// `udp_bind`. `None` leaves the socket unconnected (the usual UDP
    /// server case); `Some(peer)` calls `connect()` so the kernel filters
    /// incoming datagrams to that peer, and on io_uring the runtime uses the
    /// lighter `RecvUdp`/`SendUdp` opcodes instead of `RecvMsgUdp`/`SendMsgUdp`.
    /// Saves ~4 microseconds per round trip on single-shot client workloads.
    /// Must have the same length as `udp_bind` (enforced at validation).
    pub(crate) udp_connect_peers: Vec<Option<SocketAddr>>,
    /// Sockets `launch` bound for zero-port UDP binds, parallel to
    /// `udp_bind` once `launch` has run (empty before). The first worker to
    /// set up a bind's socket takes the reserved socket as its own, and the
    /// other workers bind its port.
    pub(crate) udp_reserved: std::sync::Arc<[std::sync::Mutex<Option<std::os::fd::OwnedFd>>]>,
    /// Number of concurrent in-flight UDP sends per socket. Each slot owns a
    /// pre-allocated `sockaddr_storage` + `iovec` + `msghdr` triple used to
    /// submit a `sendmsg` SQE; the slot is returned to the freelist on CQE.
    /// Exhaustion returns [`crate::error::UdpSendError::PoolExhausted`].
    /// Default: 64.
    pub(crate) udp_send_slots: u16,
    /// Maximum number of datagrams buffered per UDP socket awaiting a
    /// consumer. The runtime fills this queue from `recvmsg` completions;
    /// the application's `on_udp_bind` future drains it via
    /// [`UdpSocket::recv_from`](crate::UdpSocket::recv_from). When the queue is
    /// full, additional datagrams are dropped and
    /// `udp::DATAGRAMS_DROPPED` is incremented — this guards against
    /// unbounded memory growth when the handler future stalls, panics,
    /// or returns early. On io_uring the capacity is clamped to the ring
    /// size. A socket at that depth stops reading, and later datagrams wait
    /// in the kernel receive buffer.
    ///
    /// Default: 1024.
    pub(crate) udp_recv_queue_capacity: usize,
    /// Enable UDP Generic Receive Offload (GRO) on bound UDP sockets.
    ///
    /// When set, the runtime calls `setsockopt(SOL_UDP, UDP_GRO)` so the
    /// kernel coalesces consecutive same-flow datagrams into one `recvmsg`
    /// delivery, carrying the per-segment size in a control message. The
    /// runtime splits the coalesced payload back into individual datagrams
    /// transparently, so [`UdpSocket::recv_batch`](crate::UdpSocket::recv_batch) /
    /// [`recv_batch_timed`](crate::UdpSocket::recv_batch_timed) callbacks still
    /// fire once per datagram. This cuts per-datagram syscall / wake overhead
    /// dramatically for high-pps flows (e.g. QUIC at large payloads).
    ///
    /// A coalesced datagram can be up to ~64 KiB, and on io_uring the
    /// recvmsg header + sockaddr + control + payload share one provided
    /// buffer, so enabling GRO requires `udp_recv_buffer.buffer_size` to be
    /// large enough to hold a full coalesced datagram (validated at startup);
    /// otherwise the kernel truncates and the datagram is dropped. On
    /// io_uring it has no effect on `connect(2)`-ed UDP sockets (they use the
    /// lighter `recv` path, which carries no control message). Linux-only —
    /// a no-op on other platforms. Default: false.
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sq_entries: 256,
            sqpoll: false,
            sqpoll_idle_ms: 1000,
            sqpoll_cpu: None,
            iowq_max_workers: 0,
            #[cfg(all(test, has_io_uring))]
            close_lead_override: None,
            udp_recv_buffer: RecvBufferConfig {
                ring_size: 128,
                buffer_size: 2048,
                bgid: 1,
            },
            registered_regions: Vec::new(),
            max_registered_regions: 64,
            worker: WorkerConfig::default(),
            backlog: 65535,
            max_connections: 16000,
            recv_accumulator_capacity: 4096,
            recv_accumulator_max: 1024 * 1024 * 1024,
            recv_direct_region: 32 * 1024,
            defer_recv_arm: false,
            recv_direct_pool_max: 16 << 20,
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
            task_panic_policy: crate::TaskPanicPolicy::Contain,
            merged_listeners: Vec::new(),
            merged_accept_live: None,
            wake_keep_alive: None,
            runtime_shutdown: None,
            #[cfg(test)]
            test_fault: None,
            worker_index: 0,
            worker_loads: None,
            worker_accepting: None,
            peer_accept: Vec::new(),
            peer_park: Vec::new(),
            loop_diag: false,
            max_chain_length: 16,
            standalone_task_capacity: 256,
            udp_bind: Vec::new(),
            udp_connect_peers: Vec::new(),
            udp_reserved: std::sync::Arc::from(Vec::new()),
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
        }
    }
}

impl Config {
    /// Take the socket `launch` reserved for UDP bind `index`, if there is
    /// one and no worker has taken it yet.
    pub(crate) fn take_udp_reserved(&self, index: usize) -> Option<std::os::fd::OwnedFd> {
        self.udp_reserved
            .get(index)?
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// The zero-copy guard send threshold in bytes. See
    /// [`ConfigBuilder::send_zc_threshold`].
    pub fn send_zc_threshold(&self) -> u32 {
        self.send_zc_threshold
    }

    /// A TLS connection encrypts into the same `SendCopyPool` slots that plain
    /// sends copy into, so `send_copy_slot_size` is also the destination for
    /// TLS records.
    ///
    /// The unbuffered record layer writes whole records into a slot and cannot
    /// split one across two. Below one whole worst-case record (`F + 29`,
    /// where `F` is the plaintext per record from the TLS config's
    /// `max_fragment_size`) a bounded send has no admission bound and is
    /// refused, on both backends, and on io_uring a plain send that finds the
    /// pool short part-way through encryption closes the connection. So the
    /// slot must hold one whole record for every TLS config this runtime
    /// uses: the server config, the client config and each `bind_tls`
    /// listener's. `MIN_ENCRYPT_DST` is a floor for configs whose fragment
    /// size makes `F + 29` smaller than it. See
    /// `docs/tls-premutation-bound-design.md`.
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_tls_slot_size(&self) -> Result<(), crate::error::Error> {
        let fragment_sizes = self
            .tls
            .iter()
            .chain(self.listener_tls.iter().flatten())
            .map(|t| t.max_fragment_size())
            .chain(self.tls_client.iter().map(|c| c.max_fragment_size()));
        let Some(record) = fragment_sizes
            .map(|f| crate::tls::plaintext_per_record(f) + crate::tls::MAX_RECORD_OVERHEAD)
            .max()
        else {
            return Ok(());
        };
        let min = record.max(crate::tls::unbuffered::MIN_ENCRYPT_DST);
        if (self.send_copy_slot_size as usize) < min {
            return Err(crate::error::Error::RingSetup(format!(
                "send_copy_slot_size is {} but the unbuffered TLS record layer needs a slot of \
                 at least {min} bytes to hold one whole TLS record for the configured \
                 max_fragment_size; raise send_copy_slot_size (ConfigBuilder::send_pool), \
                 lower max_fragment_size (TlsConfigBuilder::max_fragment_size, \
                 TlsClientConfigBuilder::max_fragment_size), or build with the \
                 tls-buffered feature",
                self.send_copy_slot_size,
            )));
        }
        Ok(())
    }

    /// The buffered record layer packs ciphertext across slots through
    /// `PoolWriter`, so no slot size is too small for it to make progress.
    #[cfg(feature = "tls-buffered")]
    fn validate_tls_slot_size(&self) -> Result<(), crate::error::Error> {
        Ok(())
    }

    /// Validate configuration values. Returns an error if any value is out of range.
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if self.recv_accumulator_max == 0 {
            return Err(crate::error::Error::RingSetup(
                "recv_accumulator_max must be > 0 (use usize::MAX to disable the cap)".into(),
            ));
        }
        if self.recv_direct_region == 0 {
            return Err(crate::error::Error::RingSetup(
                "recv_direct_region must be > 0".into(),
            ));
        }
        if self.max_connections == 0 || self.max_connections >= (1 << 24) {
            return Err(crate::error::Error::RingSetup(
                "max_connections must be > 0 and < 2^24".into(),
            ));
        }
        // A zero-capacity `handoff` channel has no buffer, so a send completes
        // only when a receiver takes it. Workers poll with try_recv and are
        // woken after a send completes, so an idle worker would not take a
        // held connection.
        if self.accept_queue_capacity == 0 {
            return Err(crate::error::Error::RingSetup(
                "accept_queue_capacity must be > 0".into(),
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
        // A cap of 0 would stop a forward's source before it queues its first
        // send, so the forward never makes progress.
        if self.forward_hold_cap == 0 {
            return Err(crate::error::Error::RingSetup(
                "forward_hold_cap must be >= 1".into(),
            ));
        }
        // A close pushes its lead (a shutdown or a cancel) and the Close as
        // one linked pair (#581, #586).
        if self.sq_entries < 2 || !self.sq_entries.is_power_of_two() {
            return Err(crate::error::Error::RingSetup(
                "sq_entries must be at least 2 and a power of two".into(),
            ));
        }
        // The kernel rejects a limit above INT_MAX.
        if self.iowq_max_workers > i32::MAX as u32 {
            return Err(crate::error::Error::RingSetup(
                "iowq_max_workers must be at most i32::MAX".into(),
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
            // Each socket has its own buffer group, numbered up from `bgid`.
            if self.udp_recv_buffer.bgid as usize + self.udp_bind.len() - 1 > u16::MAX as usize {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.bgid plus the number of UDP sockets must fit in u16".into(),
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
        }
        Ok(())
    }
}

/// Configuration for a provided buffer ring (UDP recv).
#[derive(Clone)]
pub(crate) struct RecvBufferConfig {
    /// Number of buffers in the ring (must be power of 2).
    pub ring_size: u16,
    /// Size of each buffer in bytes.
    pub buffer_size: u32,
    /// Buffer group ID of the first socket's provided buffer ring. Later
    /// sockets number up from it.
    pub bgid: u16,
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
///     .send_pool(512, 8192)
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

    /// Set the TCP listen backlog. Default: 65535.
    ///
    /// The kernel uses the smaller of this value and `net.core.somaxconn`
    /// (`kern.ipc.somaxconn` on macOS). A TCP connection the backlog has no room
    /// for is retried by the peer's TCP, which adds a second or more to its
    /// connect. On a Unix listener a non-blocking connect fails with `EAGAIN`
    /// instead.
    ///
    /// A connection in the listen queue has completed its connect, and gets no
    /// reply until a worker takes it. The runtime does not time it out.
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
    ///
    /// When every worker's channel is full, the acceptor stops accepting until
    /// one has room, and connections wait in the listen queue
    /// ([`backlog`](Self::backlog)).
    pub fn accept_queue_capacity(mut self, n: usize) -> Self {
        self.config.accept_queue_capacity = n;
        self
    }

    /// Choose where connections are accepted. Default [`AcceptMode::Pool`].
    ///
    /// [`AcceptMode::Merged`] is io_uring only; on the mio backend it is
    /// accepted and ignored, since mio has no multishot accept.
    ///
    /// Requires the `unstable-accept` feature. Outside semver.
    #[cfg(any(feature = "unstable-accept", test))]
    pub fn accept_mode(mut self, mode: AcceptMode) -> Self {
        self.config.accept_mode = mode;
        self
    }

    /// Choose what happens when a task panics. Default
    /// [`TaskPanicPolicy::Contain`](crate::TaskPanicPolicy::Contain): the panic
    /// is caught, the task is dropped and the worker keeps running.
    ///
    /// This covers connection tasks, standalone tasks, the `on_start` and
    /// `on_udp_bind` futures and the calls that build them, building the
    /// `on_accept` future, `on_tick`, `on_notify`, and
    /// [`spawn_blocking`](crate::spawn_blocking) closures. It does not cover
    /// `create_for_worker` or a future's `Drop` during the shutdown drain. A
    /// [`JoinHandle`](crate::JoinHandle) or
    /// [`BlockingJoinHandle`](crate::BlockingJoinHandle) awaiting a task that
    /// panicked resolves to a [`JoinError`](crate::JoinError) under either
    /// policy.
    pub fn task_panic_policy(mut self, policy: crate::TaskPanicPolicy) -> Self {
        self.config.task_panic_policy = policy;
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
    /// iterations, CQEs and tasks per iteration) and a `[ringline stall]` line
    /// (wait/work stall buckets). Recording the stall buckets costs ~4 clock
    /// reads per iteration, so this is off by default. io_uring backend only; the mio backend prints nothing.
    pub fn loop_diag(mut self, enable: bool) -> Self {
        self.config.loop_diag = enable;
        self
    }

    // ── io_uring settings ────────────────────────────────────────────

    /// Set the number of SQ entries. CQ will be 4x this. Must be a power of 2
    /// and at least 2.
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

    /// Cap the threads in each worker's bounded io-wq pool. Default 0, which
    /// leaves the kernel's limit, `min(sq_entries, 4 × online CPUs)`. A cap
    /// only lowers that limit: where the kernel's limit is already lower, it
    /// is left as it is.
    ///
    /// The bounded pool runs the worker's file and path operations that the
    /// kernel does not complete inline (`fs::fsync`, `fs::stat` and others),
    /// and, before Linux 6.13, the `shutdown` sent ahead of each connection
    /// close. Past the cap, work waits for a free thread, so a lower cap
    /// delays those closes further. With 32 write-and-`fsync` loops on one
    /// worker, measured on Linux 6.12 on a 16-vCPU host, where the kernel
    /// limit is 64, a cap of 16 raised the median wait for a closed
    /// connection's EOF from 0.21 ms to 11.6 ms. On every kernel,
    /// [`shutdown_write`](crate::SendHalf::shutdown_write) sends a `shutdown`
    /// that runs on this pool, and a close issued before it finishes waits
    /// for it. See the
    /// [`fs` module docs](crate::fs#blocking-file-io-and-connection-closes-io_uring).
    /// io_uring backend only; the mio backend ignores it.
    pub fn iowq_max_workers(mut self, n: u32) -> Self {
        self.config.iowq_max_workers = n;
        self
    }

    // ── Buffer settings ──────────────────────────────────────────────

    /// Set the initial capacity for per-connection recv accumulators.
    /// Defaults to 4 KiB.
    pub fn recv_accumulator_capacity(mut self, n: usize) -> Self {
        self.config.recv_accumulator_capacity = n;
        self
    }

    /// Set the upper bound on a single per-connection recv accumulator.
    /// The connection is closed if the cap is exceeded, and a reader parked
    /// on `with_data_result` then gets `io::ErrorKind::QuotaExceeded`, on
    /// plaintext and TLS connections alike. Defaults to 1 GiB;
    /// `usize::MAX` disables the cap. Must be at least 1.
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

    /// Set the size of the buffer that a plaintext connection (accepted, or
    /// from [`connect`](crate::connect) or
    /// [`connect_unix`](crate::connect_unix)) receives into on io_uring when
    /// it has nothing buffered. An idle
    /// connection of that kind holds a buffer of this size, or of
    /// [`recv_accumulator_capacity`](Self::recv_accumulator_capacity) if
    /// that is larger and at most twice this. A message that does not fit borrows a larger
    /// buffer from the worker (see
    /// [`recv_direct_pool_max`](Self::recv_direct_pool_max)), and the bytes
    /// already received for it, at most this many, are copied into it. A TLS
    /// connection receives up to this many bytes of ciphertext at a time.
    /// Defaults to 32 KiB; must be at least 1.
    pub fn recv_direct_region(mut self, n: usize) -> Self {
        self.config.recv_direct_region = n;
        self
    }

    /// Arm a parked reader's receive on a plaintext connection after the
    /// worker's next wait returns, instead of in the same submission as the
    /// sends the task queued before parking.
    ///
    /// A receive submitted before the peer's next bytes arrive finds the
    /// socket empty, and the kernel arms a poll and completes the receive
    /// later from task work. Submitted after the wait, the receive more often
    /// finds the bytes already queued and completes inline. On a two-machine
    /// echo benchmark (512 connections, 256-byte messages, 8 workers), server
    /// CPU per operation fell from 21.11 to 19.10 µs in closed loop. At 200k
    /// and 400k operations per second offered it did not fall, and syscalls
    /// per operation at 200k rose from 0.81-0.85 to 0.96-0.99.
    ///
    /// Deferring is skipped when the wait would block: if no completion is
    /// ready and the kernel holds no task work, the worker arms the deferred
    /// receives first and the blocking wait submits them. To tell, the ring
    /// is set up with `IORING_SETUP_TASKRUN_FLAG`. Under
    /// [`sqpoll`](Self::sqpoll), which cannot use that flag, the worker
    /// always defers and does not block while a deferred receive is waiting.
    ///
    /// Defaults to `false`. io_uring only; the mio backend ignores it.
    pub fn defer_recv_arm(mut self, on: bool) -> Self {
        self.config.defer_recv_arm = on;
        self
    }

    /// Set the most bytes of free buffers each worker keeps for direct
    /// connections to borrow. A direct connection receiving a message larger
    /// than [`recv_direct_region`](Self::recv_direct_region) borrows a buffer
    /// of at least 64 KiB, the smallest free one that fits, and gives it back
    /// when nothing is buffered and no value read from it is alive. When a
    /// buffer given back does not fit under this many bytes, the largest
    /// free buffers larger than it are freed to make room; if that is not
    /// enough, it is freed instead. A buffer larger than this is never kept,
    /// so a workload with values of 100 MiB reuses their buffers only with
    /// this above 100 MiB. Defaults to 16 MiB.
    pub fn recv_direct_pool_max(mut self, bytes: usize) -> Self {
        self.config.recv_direct_pool_max = bytes;
        self
    }

    /// Fault the send copy pool's pages in at worker startup rather than on
    /// first use.
    ///
    /// The pool is allocated zeroed, which means mapped but untouched: every
    /// page is the shared zero page until something writes to it, so the
    /// first send through a slot takes a minor fault. Enabling this walks the
    /// allocation once at startup, on the worker thread that owns it, so the
    /// pages stay local to that worker's NUMA node.
    ///
    /// With it, the pool's pages are resident from startup, so the pool adds
    /// nothing to RSS under load, and a pool the machine cannot back runs out
    /// of memory while the worker starts rather than during a traffic burst
    /// (as an OOM kill, not an error from `launch()`). Without it, the part of the pool no
    /// send touches stays virtual. A `send_pool(1024, 16448)` pool is about
    /// 16 MiB per worker. Startup grows by roughly one pass over the
    /// allocation.
    ///
    /// **Default: false** while the trade is being measured (#416).
    pub fn prefault_buffers(mut self, enabled: bool) -> Self {
        self.config.prefault_buffers = enabled;
        self
    }

    /// Set how much a connection may have outstanding before a forward stops
    /// reading.
    ///
    /// On mio it is the sends queued on the sink of a
    /// [`forward_to_conn`](crate::RecvHalf::forward_to_conn). On io_uring it is
    /// the send slab entries held by a connection that sends its own receive
    /// buffers with [`forward_recv_buf`](crate::SendHalf::forward_recv_buf),
    /// and it applies once the slab is over half used. The source's TCP
    /// receive window then closes, and it reads again once that no longer
    /// holds. Must be `>= 1`.
    ///
    /// The cap is per connection and applies only over half used, so one stuck
    /// peer can take half the slab and each later one `cap` entries:
    /// `1 + (send_slab_slots / 2) / cap` stuck peers on one worker fill it (5
    /// with the defaults). Peers that each hold fewer than `cap` entries are
    /// never held, however many there are. Guarded sends on that worker then
    /// fail with `send slab exhausted`, and further peers are not held, because
    /// they hold no entries.
    ///
    /// Default: 64.
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
    /// `slot_size` also sizes TLS records: ciphertext is encrypted into these
    /// same slots. One whole worst-case record is `F + 29` bytes, where `F` is
    /// rustls' `max_fragment_size` minus its 5-byte header (16384 by default)
    /// and 29 is the header plus the TLS 1.2 GCM nonce and tag, so 16413 bytes
    /// at the default fragment size. The unbuffered TLS engine (the default)
    /// cannot split a record across slots, so a `slot_size` smaller than one
    /// whole record for any configured TLS config is rejected:
    /// [`ConfigBuilder::build`] checks the server and client configs, and
    /// `launch()` checks each `bind_tls` listener's. The default of 16448
    /// holds one whole record at the default fragment size. With the
    /// `tls-buffered` feature any `slot_size` works with TLS.
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

    /// Set the maximum number of standalone async tasks per worker. Default:
    /// 256.
    ///
    /// A spawn on a full slab fails with
    /// [`WouldBlock`](std::io::ErrorKind::WouldBlock), and the
    /// `standalone_tasks_exhausted` pool counter records it. A slot frees when a
    /// task on the worker finishes, and nothing signals that.
    pub fn standalone_task_capacity(mut self, n: u32) -> Self {
        self.config.standalone_task_capacity = n;
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
    /// kernel filters incoming datagrams to `peer`, on both backends. On
    /// io_uring the runtime also uses the lighter `RecvUdp`/`SendUdp`
    /// opcodes instead of the `RecvMsgUdp`/`SendMsgUdp` pair, which saves
    /// ~4 microseconds per round trip on single-shot client workloads.
    ///
    /// `launch` returns an error if `connect(2)` fails, for example when
    /// `peer` is in a different address family from `local`. A `send_to` an
    /// address other than `peer` is sent on Linux; on macOS it fails with
    /// `EISCONN`.
    ///
    /// A zero local port behaves as in
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
    ///
    /// On io_uring every bound UDP socket has a ring of its own on each worker,
    /// so memory use is `ring_size * buffer_size` per socket and worker. A
    /// process binding many sockets should choose a small ring. On Linux 6.14+
    /// each ring also charges at least one page to `RLIMIT_MEMLOCK`.
    pub fn udp_recv_buffer(mut self, ring_size: u16, buffer_size: u32) -> Self {
        self.config.udp_recv_buffer.ring_size = ring_size;
        self.config.udp_recv_buffer.buffer_size = buffer_size;
        self
    }

    /// Set the UDP recv buffer group ID (bgid) of the first bound socket.
    /// Socket `n` uses `bgid + n`, and the last must fit in `u16`.
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
    /// clamped to `udp_recv_buffer` ring_size. At that depth the socket
    /// stops reading: later datagrams wait in its kernel receive buffer
    /// and the kernel drops what does not fit, which this counter does not
    /// see. The mio backend copies datagrams into owned buffers and
    /// honors the full configured depth.
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

    /// On mio, `disk_io_threads(0)` with the file subsystems on is refused at
    /// `build()`, since every file operation would fail; with `no_fs` it
    /// builds.
    #[cfg(not(has_io_uring))]
    #[test]
    fn disk_io_threads_zero_with_fs_is_rejected_on_mio() {
        let err = ConfigBuilder::new()
            .disk_io_threads(0)
            .build()
            .err()
            .expect("fs is on by default, so no pool to run it on is an error");
        assert!(err.to_string().contains("no_fs"), "{err}");
        let err = ConfigBuilder::new()
            .no_fs()
            .direct_io(crate::direct_io::DirectIoConfig::default())
            .disk_io_threads(0)
            .build()
            .err()
            .expect("direct I/O with no pool is an error");
        assert!(err.to_string().contains("direct_io"), "{err}");
        ConfigBuilder::new()
            .no_fs()
            .disk_io_threads(0)
            .build()
            .expect("no file subsystem needs the pool");
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
    fn validate_recv_accumulator_max_zero_rejected() {
        assert!(
            config_with(|c| c.recv_accumulator_max = 0)
                .validate()
                .is_err()
        );
        assert!(
            config_with(|c| c.recv_accumulator_max = 1)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_send_slab_slots_zero_rejected() {
        assert!(config_with(|c| c.send_slab_slots = 0).validate().is_err());
    }

    #[test]
    fn validate_accept_queue_capacity_zero_rejected() {
        // bounded(0) is a rendezvous channel, and workers only try_recv.
        assert!(
            config_with(|c| c.accept_queue_capacity = 0)
                .validate()
                .is_err()
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
    fn validate_udp_ring_size_not_power_of_two_rejected() {
        assert!(
            udp_config_with(|c| c.udp_recv_buffer.ring_size = 3)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_udp_buffer_groups_fit_in_u16() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let groups = |bgid| {
            udp_config_with(|c| {
                c.udp_bind = vec![addr; 3];
                c.udp_recv_buffer.bgid = bgid;
            })
        };
        assert!(groups(u16::MAX - 2).validate().is_ok());
        assert!(groups(u16::MAX - 1).validate().is_err());
    }

    #[test]
    fn validate_sq_entries_not_power_of_two_rejected() {
        assert!(config_with(|c| c.sq_entries = 3).validate().is_err());
    }

    #[test]
    fn validate_sq_entries_zero_rejected() {
        assert!(config_with(|c| c.sq_entries = 0).validate().is_err());
    }

    /// A close pushes its lead (a shutdown or a cancel) and the Close as one
    /// linked pair (#581, #586), which a one-entry SQ cannot hold.
    #[test]
    fn validate_sq_entries_one_rejected() {
        assert!(config_with(|c| c.sq_entries = 1).validate().is_err());
        assert!(config_with(|c| c.sq_entries = 2).validate().is_ok());
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
        let key = ringline_tls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = ringline_tls::pki_types::CertificateDer::from(cert.cert);
        let mut builder = TlsConfig::builder().cert(vec![cert_der], key.into());
        if let Some(size) = max_fragment_size {
            builder = builder.max_fragment_size(size);
        }
        builder.build().unwrap()
    }

    // The shipped default holds one whole record at the default fragment
    // size (16448 against F + 29 = 16413).
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

    // On the unbuffered engine the threshold is exactly one whole record:
    // 16413 is accepted and 16412 is not, and the error names the knob and
    // the minimum.
    #[test]
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_rejects_a_slot_below_one_whole_record() {
        config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 16413;
        })
        .validate()
        .expect("16413 holds one whole record");
        let err = config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 16412;
        })
        .validate()
        .expect_err("16412 is one byte short of a whole record");
        let msg = err.to_string();
        assert!(
            msg.contains("send_copy_slot_size") && msg.contains("16413"),
            "the error must name the knob and the minimum: {msg}"
        );
    }

    // The threshold follows the configured fragment size: at a
    // max_fragment_size of 2048 one whole record is 2043 + 29 = 2072 bytes.
    #[test]
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_threshold_follows_max_fragment_size() {
        config_with(|c| {
            c.tls = Some(tls_server_config(Some(2048)));
            c.send_copy_slot_size = 2072;
        })
        .validate()
        .expect("2072 holds one whole 2048-byte-fragment record");
        config_with(|c| {
            c.tls = Some(tls_server_config(Some(2048)));
            c.send_copy_slot_size = 2071;
        })
        .validate()
        .expect_err("2071 is one byte short");
    }

    // At the smallest fragment size rustls accepts (32, so F = 27) one whole
    // record is 56 bytes, under `MIN_ENCRYPT_DST`; the floor applies.
    #[test]
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_applies_the_min_encrypt_dst_floor() {
        config_with(|c| {
            c.tls = Some(tls_server_config(Some(32)));
            c.send_copy_slot_size = 63;
        })
        .validate()
        .expect_err("63 is below MIN_ENCRYPT_DST");
        config_with(|c| {
            c.tls = Some(tls_server_config(Some(32)));
            c.send_copy_slot_size = 64;
        })
        .validate()
        .expect("64 is MIN_ENCRYPT_DST and holds a 56-byte record");
    }

    // The buffered engine packs records across slots, so any slot works.
    #[test]
    #[cfg(feature = "tls-buffered")]
    fn validate_accepts_a_small_slot_with_buffered_tls() {
        config_with(|c| {
            c.tls = Some(tls_server_config(None));
            c.send_copy_slot_size = 32;
        })
        .validate()
        .expect("the buffered engine straddles slots");
    }

    // A client config reaches the same check: outbound TLS connections
    // encrypt through the same pool.
    #[test]
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_checks_the_client_config_too() {
        let client = |max_fragment_size: Option<usize>| {
            let mut builder = TlsClientConfig::builder();
            if let Some(size) = max_fragment_size {
                builder = builder.max_fragment_size(size);
            }
            builder.build().unwrap()
        };
        config_with(|c| {
            c.tls_client = Some(client(None));
            c.send_copy_slot_size = 16384;
        })
        .validate()
        .expect_err("an outbound TLS connection uses the same pool");
        config_with(|c| {
            c.tls_client = Some(client(Some(2048)));
            c.send_copy_slot_size = 4096;
        })
        .validate()
        .expect("4096 holds one whole 2048-byte-fragment record");
    }

    // A `bind_tls` listener's config counts, and the largest fragment size
    // among all configs sets the threshold.
    #[test]
    #[cfg(not(feature = "tls-buffered"))]
    fn validate_checks_listener_configs_too() {
        config_with(|c| {
            c.tls = Some(tls_server_config(Some(2048)));
            c.listener_tls = vec![None, Some(tls_server_config(None))];
            c.send_copy_slot_size = 4096;
        })
        .validate()
        .expect_err("the listener's default fragment size needs 16413");
        config_with(|c| {
            c.listener_tls = vec![Some(tls_server_config(Some(2048)))];
            c.send_copy_slot_size = 4096;
        })
        .validate()
        .expect("4096 holds the listener's whole record");
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
