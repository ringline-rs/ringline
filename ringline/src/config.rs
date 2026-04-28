use std::net::SocketAddr;

use crate::buffer::fixed::MemoryRegion;

/// TLS configuration. Pass a pre-built rustls ServerConfig.
#[derive(Clone)]
pub struct TlsConfig {
    /// Pre-built rustls ServerConfig. User loads certs/keys and configures ALPN etc.
    pub server_config: std::sync::Arc<rustls::ServerConfig>,
}

/// TLS client configuration for outbound connections.
#[derive(Clone)]
pub struct TlsClientConfig {
    /// Pre-built rustls ClientConfig. User configures root certs, ALPN, etc.
    pub client_config: std::sync::Arc<rustls::ClientConfig>,
}

/// Configuration for the io_uring driver.
#[derive(Clone)]
pub struct Config {
    /// Number of SQ entries. CQ will be 4x this.
    pub sq_entries: u32,
    /// Enable SQPOLL mode (kernel-side submission polling).
    pub sqpoll: bool,
    /// SQPOLL idle timeout in milliseconds.
    pub sqpoll_idle_ms: u32,
    /// Pin SQPOLL kernel thread to this CPU core. Only meaningful when sqpoll=true.
    pub sqpoll_cpu: Option<u32>,
    /// Recv buffer configuration (provided buffer ring) for TCP multishot recv.
    pub recv_buffer: RecvBufferConfig,
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
    pub udp_recv_buffer: RecvBufferConfig,
    /// User-registered memory regions (e.g., mmap'd storage arenas).
    ///
    /// Regions listed here occupy slots `0..registered_regions.len()` at
    /// startup. The remaining slots up to [`Config::max_registered_regions`] are
    /// available for dynamic registration via
    /// [`ShutdownHandle::register_region`](crate::ShutdownHandle::register_region).
    pub registered_regions: Vec<MemoryRegion>,
    /// Maximum number of fixed-buffer slots to reserve in the io_uring
    /// registered-buffer table. Must be `>= registered_regions.len()`.
    ///
    /// Slots beyond the initial regions are empty until filled by
    /// [`ShutdownHandle::register_region`](crate::ShutdownHandle::register_region).
    /// Cannot be grown after launch — io_uring's registered-buffer table is
    /// fixed-size; expand by re-launching with a larger value.
    ///
    /// Default: 64.
    pub max_registered_regions: u16,
    /// Worker/thread configuration.
    pub worker: WorkerConfig,
    /// TCP listen backlog.
    pub backlog: i32,
    /// Maximum number of direct file descriptors (connections).
    pub max_connections: u32,
    /// Initial capacity for per-connection recv accumulators.
    pub recv_accumulator_capacity: usize,
    /// Number of copy-send pool slots. Each in-flight `send()` or copy part of a
    /// `send_parts()` call holds one slot until the kernel completes the send.
    /// Size this to cover your peak in-flight send count — exhaustion returns an
    /// error to the handler. Memory cost: `send_copy_count * send_copy_slot_size`.
    pub send_copy_count: u16,
    /// Size of each copy-send pool slot in bytes. A single `send()` or the
    /// combined copy parts of one `send_parts()` call must fit in one slot.
    pub send_copy_slot_size: u32,
    /// Number of InFlightSendSlab slots for in-flight scatter-gather sends
    /// (i.e., `send_parts()` calls that include at least one guard).
    /// Each slot is held until all ZC notifications arrive.
    pub send_slab_slots: u16,
    /// Deadline-based flush interval in microseconds during CQE processing.
    /// When non-SQPOLL, if this many microseconds elapse since the last submit
    /// while processing a CQE batch, pending SQEs are flushed mid-iteration.
    /// 0 = disabled. Ignored when SQPOLL is active (kernel handles it).
    pub flush_interval_us: u64,
    /// Maximum time in microseconds that `submit_and_wait` will block before
    /// returning to call `on_tick`. Prevents the event loop from stalling when
    /// there are no pending completions (e.g., client-only mode between phases).
    /// 0 = no timeout (block indefinitely until a CQE arrives).
    /// Default: 1000 (1ms).
    pub tick_timeout_us: u64,
    /// Optional TLS configuration. When set, all accepted connections use TLS.
    pub tls: Option<TlsConfig>,
    /// Optional TLS client configuration for outbound `connect_tls()` calls.
    pub tls_client: Option<TlsClientConfig>,
    /// Enable TCP_NODELAY on all connections (accepted and outbound).
    pub tcp_nodelay: bool,
    /// Enable SO_TIMESTAMPING for kernel-level receive timestamps.
    /// When enabled, connections use `RecvMsgMulti` instead of `RecvMulti`
    /// to receive ancillary data containing kernel RX timestamps.
    #[cfg(feature = "timestamps")]
    pub timestamps: bool,
    /// Maximum number of SQEs per IOSQE_IO_LINK chain. 0 disables chaining.
    /// When disabled, sends exceeding MAX_IOVECS fall back to sequential
    /// round-trips (one SQE at a time via on_send_complete).
    /// Default: 16.
    pub max_chain_length: u16,
    /// Maximum number of standalone async tasks (not bound to connections)
    /// per worker. Used with [`spawn()`](crate::spawn).
    /// Default: 256.
    pub standalone_task_capacity: u32,
    /// Maximum number of concurrent timer slots per worker.
    /// Used by [`sleep()`](crate::sleep) and [`timeout()`](crate::timeout).
    /// Default: 256.
    pub timer_slots: u32,
    /// UDP bind addresses. Each worker creates its own socket with SO_REUSEPORT.
    /// Empty = no UDP sockets.
    pub udp_bind: Vec<SocketAddr>,
    /// Number of concurrent in-flight UDP sends per socket. Each slot owns a
    /// pre-allocated `sockaddr_storage` + `iovec` + `msghdr` triple used to
    /// submit a `sendmsg` SQE; the slot is returned to the freelist on CQE.
    /// Exhaustion returns [`crate::error::UdpSendError::PoolExhausted`].
    /// Default: 64.
    pub udp_send_slots: u16,
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
    pub udp_recv_queue_capacity: usize,
    /// Optional NVMe passthrough configuration. When set, enables NVMe device
    /// management and `IORING_OP_URING_CMD` submission for direct NVMe I/O.
    pub nvme: Option<crate::nvme::NvmeConfig>,
    /// Optional direct I/O configuration. When set, enables `O_DIRECT` file I/O
    /// via io_uring `IORING_OP_READ` / `IORING_OP_WRITE`, bypassing the page cache.
    pub direct_io: Option<crate::direct_io::DirectIoConfig>,
    /// Optional buffered filesystem I/O configuration. When set, enables async
    /// file open/read/write/stat/rename/unlink/mkdir via io_uring.
    pub fs: Option<crate::fs::FsConfig>,
    /// Number of dedicated DNS resolver threads. The resolver pool runs
    /// `getaddrinfo` on background threads, keeping blocking DNS isolated
    /// from the io_uring event loop.
    ///
    /// 0 = disabled (no resolver pool; [`resolve()`](crate::resolve) will
    /// return an error). Default: 2.
    pub resolver_threads: usize,
    /// Number of dedicated process spawner threads. The spawner pool runs
    /// `posix_spawnp` + `pidfd_open` on background threads, keeping blocking
    /// process creation isolated from the io_uring event loop.
    ///
    /// 0 = disabled (no spawner pool; [`Command::spawn()`](crate::process::Command::spawn)
    /// will return an error). Default: 1.
    pub spawner_threads: usize,
    /// Number of dedicated blocking threads. The blocking pool runs
    /// user-provided closures on low-priority (`SCHED_IDLE`) background threads,
    /// keeping CPU-bound or blocking work isolated from the io_uring event loop.
    ///
    /// 0 = disabled (no blocking pool; [`spawn_blocking()`](crate::spawn_blocking)
    /// will return an error). Default: 4.
    pub blocking_threads: usize,
    /// Number of dedicated disk I/O threads (mio backend only). The disk I/O
    /// pool executes blocking filesystem syscalls (pread, pwrite, fsync, stat,
    /// rename, unlink, mkdir) on background threads, enabling async file I/O
    /// on non-Linux platforms.
    ///
    /// 0 = disabled (filesystem/direct I/O operations return `Unsupported`).
    /// Default: 2.
    pub disk_io_threads: usize,
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
            send_copy_count: 1024,
            send_copy_slot_size: 16384,
            send_slab_slots: 512,
            flush_interval_us: 100,
            tick_timeout_us: 1000,
            tls: None,
            tls_client: None,
            tcp_nodelay: true,
            #[cfg(feature = "timestamps")]
            timestamps: false,
            max_chain_length: 16,
            standalone_task_capacity: 256,
            timer_slots: 256,
            udp_bind: Vec::new(),
            udp_send_slots: 64,
            udp_recv_queue_capacity: 1024,
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
    /// Validate configuration values. Returns an error if any value is out of range.
    pub fn validate(&self) -> Result<(), crate::error::Error> {
        if !self.recv_buffer.ring_size.is_power_of_two() {
            return Err(crate::error::Error::RingSetup(
                "recv_buffer.ring_size must be a power of two".into(),
            ));
        }
        if self.recv_buffer.buffer_size == 0 || self.recv_buffer.buffer_size > 65535 {
            return Err(crate::error::Error::RingSetup(
                "recv_buffer.buffer_size must be > 0 and <= 65535".into(),
            ));
        }
        if self.max_connections == 0 || self.max_connections >= (1 << 24) {
            return Err(crate::error::Error::RingSetup(
                "max_connections must be > 0 and < 2^24".into(),
            ));
        }
        if self.timer_slots > 65535 {
            return Err(crate::error::Error::RingSetup(
                "timer_slots must be <= 65535".into(),
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
            if self.udp_recv_buffer.buffer_size == 0 || self.udp_recv_buffer.buffer_size > 65535 {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.buffer_size must be > 0 and <= 65535".into(),
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
            if self.udp_recv_buffer.bgid == self.recv_buffer.bgid {
                return Err(crate::error::Error::RingSetup(
                    "udp_recv_buffer.bgid must differ from recv_buffer.bgid".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Configuration for the provided buffer ring (multishot recv).
#[derive(Clone)]
pub struct RecvBufferConfig {
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
pub struct WorkerConfig {
    /// Number of worker threads. 0 = number of CPUs.
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

    /// Enable or disable TCP_NODELAY on all connections.
    pub fn tcp_nodelay(mut self, enable: bool) -> Self {
        self.config.tcp_nodelay = enable;
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

    /// Set the initial capacity for per-connection recv accumulators.
    pub fn recv_accumulator_capacity(mut self, n: usize) -> Self {
        self.config.recv_accumulator_capacity = n;
        self
    }

    /// Set the number and size of copy-send pool slots.
    pub fn send_pool(mut self, count: u16, slot_size: u32) -> Self {
        self.config.send_copy_count = count;
        self.config.send_copy_slot_size = slot_size;
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

    /// Add a UDP bind address. Can be called multiple times.
    pub fn udp_bind(mut self, addr: SocketAddr) -> Self {
        self.config.udp_bind.push(addr);
        self
    }

    /// Set the number of concurrent in-flight UDP sends per socket.
    pub fn udp_send_slots(mut self, n: u16) -> Self {
        self.config.udp_send_slots = n;
        self
    }

    /// Set the UDP recv buffer configuration (ring_size, buffer_size).
    /// The `bgid` is left at its default; change it via `config_mut()` if
    /// you need to override.
    pub fn udp_recv_buffer(mut self, ring_size: u16, buffer_size: u32) -> Self {
        self.config.udp_recv_buffer.ring_size = ring_size;
        self.config.udp_recv_buffer.buffer_size = buffer_size;
        self
    }

    /// Set the per-UDP-socket recv queue capacity.
    ///
    /// Datagrams that arrive while the queue is full are dropped and
    /// counted in `udp::DATAGRAMS_DROPPED`. Default: 1024.
    pub fn udp_recv_queue_capacity(mut self, capacity: usize) -> Self {
        self.config.udp_recv_queue_capacity = capacity;
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

    // ── Escape hatch ─────────────────────────────────────────────────

    /// Get mutable access to the underlying config for fields not covered
    /// by builder methods.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
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
    fn validate_buffer_size_zero_rejected() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 0)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn validate_buffer_size_max_accepted() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 65535)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validate_buffer_size_overflow_rejected() {
        let err = config_with(|c| c.recv_buffer.buffer_size = 65536)
            .validate()
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("buffer_size"),
            "error should mention buffer_size: {msg}"
        );
    }

    #[test]
    fn validate_buffer_size_large_rejected() {
        assert!(
            config_with(|c| c.recv_buffer.buffer_size = 131072)
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
}
