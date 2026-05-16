use std::net::SocketAddr;
use std::sync::Mutex;

/// Manages dynamic port allocation for benchmark servers and clients.
/// Ensures no port conflicts when running benchmarks in parallel.
pub struct PortManager {
    next_port: Mutex<u16>,
}

impl PortManager {
    pub fn new(start_port: u16) -> Self {
        Self {
            next_port: Mutex::new(start_port),
        }
    }

    /// Allocate the next available port for a new socket.
    pub fn next_port(&self) -> u16 {
        let mut port = self.next_port.lock().unwrap();
        let current = *port;
        *port = port.wrapping_add(1);
        current
    }

    /// Allocate a port as a SocketAddr for IPv4 loopback.
    pub fn next_addr(&self) -> SocketAddr {
        let port = self.next_port();
        format!("127.0.0.1:{}", port).parse().unwrap()
    }
}

impl Default for PortManager {
    fn default() -> Self {
        // Start at a high port to avoid conflicts with common services
        Self::new(19400)
    }
}
