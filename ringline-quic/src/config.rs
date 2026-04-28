use std::sync::Arc;

use quinn_proto::{ClientConfig, EndpointConfig, ServerConfig};

/// Configuration for a [`QuicEndpoint`](crate::QuicEndpoint).
///
/// `Clone` lets the same configuration drive multiple per-worker endpoints
/// (e.g. one `QuicEndpoint` per ringline worker, each bound to a different
/// port via `SO_REUSEPORT`). All inner state (`endpoint_config`,
/// `server_config`, `client_config`) is `Arc`-backed, so cloning is cheap.
#[derive(Clone)]
pub struct QuicConfig {
    /// Shared endpoint configuration (connection IDs, supported versions, etc.).
    pub endpoint_config: Arc<EndpointConfig>,
    /// Server-side TLS/QUIC config. `None` for client-only endpoints.
    pub server_config: Option<Arc<ServerConfig>>,
    /// Client-side TLS/QUIC config. `None` for server-only endpoints.
    pub client_config: Option<ClientConfig>,
    /// Maximum queued outgoing packets before dropping. Default: 4096.
    pub send_queue_capacity: usize,
    /// Maximum number of datagrams quinn-proto may produce in a single
    /// `poll_transmit` call.
    ///
    /// Higher values amortise the per-call state-machine overhead across
    /// more packets, which is the easiest throughput win for sustained
    /// transfers. When > 1 quinn may pack several segments into one
    /// buffer with `Transmit::segment_size` set; ringline-quic splits
    /// those into per-datagram outbound packets internally, so consumers
    /// don't need GSO support to benefit.
    ///
    /// Default: 10 (matches the value quinn's high-level crate uses).
    pub max_transmit_datagrams: usize,
    /// Allow path MTU discovery. Default: true.
    pub allow_mtud: bool,
    /// Deterministic RNG seed for testing. Default: `None` (random).
    pub rng_seed: Option<[u8; 32]>,
}

impl QuicConfig {
    /// Create a server-only config with the given TLS server configuration.
    pub fn server(server_config: Arc<ServerConfig>) -> Self {
        Self {
            endpoint_config: Arc::new(EndpointConfig::default()),
            server_config: Some(server_config),
            client_config: None,
            send_queue_capacity: 4096,
            max_transmit_datagrams: 10,
            allow_mtud: true,
            rng_seed: None,
        }
    }

    /// Create a client-only config with the given TLS client configuration.
    pub fn client(client_config: ClientConfig) -> Self {
        Self {
            endpoint_config: Arc::new(EndpointConfig::default()),
            server_config: None,
            client_config: Some(client_config),
            send_queue_capacity: 4096,
            max_transmit_datagrams: 10,
            allow_mtud: true,
            rng_seed: None,
        }
    }
}
