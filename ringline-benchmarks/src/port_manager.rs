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

    /// Allocate the next port counter value (no availability check).
    pub fn next_port(&self) -> u16 {
        let mut port = self.next_port.lock().unwrap();
        let current = *port;
        *port = port.wrapping_add(1);
        current
    }

    /// Allocate a loopback `SocketAddr` whose port is verified free for **both**
    /// TCP and UDP before being handed out.
    ///
    /// The benchmark runner starts and tears down hundreds of servers in one
    /// process; a port that is momentarily unbindable (e.g. a prior connection
    /// in `TIME_WAIT`, or already taken) used to be handed out blindly, the
    /// server thread would panic on `bind`, and the client would silently
    /// record 0 ops/s for that cell. Probing here — binding a throwaway
    /// `TcpListener` + `UdpSocket` and dropping them — skips such ports so the
    /// real server bind (which sets `SO_REUSEADDR`) succeeds. A tiny race
    /// remains between probe and real bind, but it is rare and `SO_REUSEADDR`
    /// covers the common case.
    pub fn next_addr(&self) -> SocketAddr {
        use std::net::{TcpListener, UdpSocket};
        // Bounded attempts so a pathological host can't spin forever.
        for _ in 0..1024 {
            let port = self.next_port();
            let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
            let tcp_ok = TcpListener::bind(addr).is_ok();
            let udp_ok = UdpSocket::bind(addr).is_ok();
            if tcp_ok && udp_ok {
                return addr;
            }
        }
        // Fall back to a raw counter value rather than failing the run.
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
