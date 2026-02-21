use std::sync::Arc;

use quinn_proto::{ClientConfig, EndpointConfig, ServerConfig};

/// Configuration for a [`QuicEndpoint`](crate::QuicEndpoint).
pub struct QuicConfig {
    /// Shared endpoint configuration (connection IDs, supported versions, etc.).
    pub endpoint_config: Arc<EndpointConfig>,
    /// Server-side TLS/QUIC config. `None` for client-only endpoints.
    pub server_config: Option<Arc<ServerConfig>>,
    /// Client-side TLS/QUIC config. `None` for server-only endpoints.
    pub client_config: Option<ClientConfig>,
    /// Maximum queued outgoing packets before dropping. Default: 4096.
    pub send_queue_capacity: usize,
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
            allow_mtud: true,
            rng_seed: None,
        }
    }
}
