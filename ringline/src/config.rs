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
    /// Recv buffer configuration (provided buffer ring).
    pub recv_buffer: RecvBufferConfig,
    /// User-registered memory regions (e.g., mmap'd storage arenas).
    pub registered_regions: Vec<MemoryRegion>,
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
    /// Optional NVMe passthrough configuration. When set, enables NVMe device
    /// management and `IORING_OP_URING_CMD` submission for direct NVMe I/O.
    pub nvme: Option<crate::nvme::NvmeConfig>,
    /// Optional direct I/O configuration. When set, enables `O_DIRECT` file I/O
    /// via io_uring `IORING_OP_READ` / `IORING_OP_WRITE`, bypassing the page cache.
    pub direct_io: Option<crate::direct_io::DirectIoConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sq_entries: 256,
            sqpoll: false,
            sqpoll_idle_ms: 1000,
            sqpoll_cpu: None,
            recv_buffer: RecvBufferConfig::default(),
            registered_regions: Vec::new(),
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
            nvme: None,
            direct_io: None,
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
