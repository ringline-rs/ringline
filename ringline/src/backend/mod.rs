// Shared sockaddr helpers used by both backends.
pub(crate) mod sockaddr;

#[allow(unused_imports)]
pub(crate) use sockaddr::sockaddr_to_peer_addr;
#[allow(unused_imports)]
pub(crate) use sockaddr::sockaddr_to_socket_addr;
pub(crate) use sockaddr::socket_addr_to_sockaddr;
pub(crate) use sockaddr::unix_path_to_sockaddr;

// ── io_uring backend (Linux 6.0+) ──────────────────────────────────────

#[cfg(has_io_uring)]
pub(crate) mod uring;

#[cfg(has_io_uring)]
pub(crate) use uring::driver::Driver;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::PendingRecvBuf;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::UdpSocketState;
#[cfg(has_io_uring)]
pub(crate) use uring::event_loop::AsyncEventLoop;
#[cfg(has_io_uring)]
pub(crate) use uring::provided::ProvidedBufRing;
#[cfg(has_io_uring)]
pub(crate) use uring::ring::Ring;

// ── mio backend (cross-platform fallback) ──────────────────────────────

#[cfg(not(has_io_uring))]
pub(crate) mod mio;

#[cfg(not(has_io_uring))]
pub(crate) use self::mio::driver::Driver;
#[cfg(not(has_io_uring))]
pub(crate) use self::mio::event_loop::AsyncEventLoop;
