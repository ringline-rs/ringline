use std::fmt;
use std::time::Duration;

/// Which transport layer to use for the benchmark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Transport {
    /// TCP
    #[default]
    Tcp,
    /// UDP
    Udp,
    /// QUIC
    Quic,
}

/// Which protocol layer to benchmark.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Echo (send data, receive same data back)
    #[default]
    Echo,
    /// Request-response (send request, receive response)
    RequestResponse,
    /// Streaming (send data, receive data back)
    Streaming,
}

/// Whether TLS is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TlsConfig {
    #[default]
    None,
    Required,
}

/// Client runtime to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClientRuntime {
    /// ringline client
    #[default]
    Ringline,
    /// tokio client
    Tokio,
}

/// Server runtime to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ServerRuntime {
    /// ringline server
    #[default]
    Ringline,
    /// tokio server
    Tokio,
}

/// A benchmark definition that composes all parameters.
#[derive(Clone, Debug)]
pub struct BenchmarkDefinition {
    pub transport: Transport,
    pub protocol: Protocol,
    pub client_runtime: ClientRuntime,
    pub server_runtime: ServerRuntime,
    pub sizes: Vec<usize>,
    pub concurrencies: Vec<usize>,
    pub tls: TlsConfig,
    pub duration: Duration,
    pub warmup: Duration,
}

impl BenchmarkDefinition {
    pub fn new() -> Self {
        Self {
            transport: Transport::Tcp,
            protocol: Protocol::Echo,
            client_runtime: ClientRuntime::Ringline,
            server_runtime: ServerRuntime::Ringline,
            sizes: vec![64, 512, 4096, 32768],
            concurrencies: vec![1, 10, 50, 200],
            tls: TlsConfig::None,
            duration: Duration::from_secs(5),
            warmup: Duration::from_secs(2),
        }
    }

    /// Add a message size to benchmark.
    pub fn with_size(mut self, size: usize) -> Self {
        self.sizes.push(size);
        self
    }

    /// Add a concurrency level to benchmark.
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrencies.push(concurrency);
        self
    }

    /// Enable TLS.
    pub fn with_tls(mut self) -> Self {
        self.tls = TlsConfig::Required;
        self
    }

    /// Use tokio client.
    pub fn with_tokio_client(mut self) -> Self {
        self.client_runtime = ClientRuntime::Tokio;
        self
    }

    /// Use tokio server.
    pub fn with_tokio_server(mut self) -> Self {
        self.server_runtime = ServerRuntime::Tokio;
        self
    }

    /// Use ringline client.
    pub fn with_ringline_client(mut self) -> Self {
        self.client_runtime = ClientRuntime::Ringline;
        self
    }

    /// Use ringline server.
    pub fn with_ringline_server(mut self) -> Self {
        self.server_runtime = ServerRuntime::Ringline;
        self
    }

    /// Set the transport layer.
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Set the protocol.
    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Set the duration and warmup.
    pub fn with_timing(mut self, warmup: Duration, duration: Duration) -> Self {
        self.warmup = warmup;
        self.duration = duration;
        self
    }

    /// Generate all benchmark combinations from this definition.
    pub fn combinations(&self) -> Vec<BenchmarkCombination> {
        let mut result = Vec::new();
        for &size in &self.sizes {
            for &concurrency in &self.concurrencies {
                for tls in [TlsConfig::None, TlsConfig::Required] {
                    // Skip TLS if not required
                    if tls == TlsConfig::Required && self.tls == TlsConfig::None {
                        continue;
                    }
                    result.push(BenchmarkCombination {
                        size,
                        concurrency,
                        tls,
                    });
                }
            }
        }
        result
    }
}

impl Default for BenchmarkDefinition {
    fn default() -> Self {
        Self::new()
    }
}

/// A single benchmark combination (size + concurrency + TLS).
#[derive(Clone, Copy, Debug)]
pub struct BenchmarkCombination {
    pub size: usize,
    pub concurrency: usize,
    pub tls: TlsConfig,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Transport::Tcp => write!(f, "tcp"),
            Transport::Udp => write!(f, "udp"),
            Transport::Quic => write!(f, "quic"),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Echo => write!(f, "echo"),
            Protocol::RequestResponse => write!(f, "request-response"),
            Protocol::Streaming => write!(f, "streaming"),
        }
    }
}

impl fmt::Display for ClientRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientRuntime::Ringline => write!(f, "ringline"),
            ClientRuntime::Tokio => write!(f, "tokio"),
        }
    }
}

impl fmt::Display for ServerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRuntime::Ringline => write!(f, "ringline"),
            ServerRuntime::Tokio => write!(f, "tokio"),
        }
    }
}

impl fmt::Display for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsConfig::None => write!(f, "none"),
            TlsConfig::Required => write!(f, "tls"),
        }
    }
}
