#[cfg(has_io_uring)]
pub(crate) mod uring;

#[cfg(has_io_uring)]
pub(crate) use uring::driver::Driver;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::PendingRecvBuf;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::UdpSocketState;
#[cfg(has_io_uring)]
#[allow(unused_imports)]
pub(crate) use uring::driver::sockaddr_to_peer_addr;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::sockaddr_to_socket_addr;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::socket_addr_to_sockaddr;
#[cfg(has_io_uring)]
pub(crate) use uring::driver::unix_path_to_sockaddr;
#[cfg(has_io_uring)]
pub(crate) use uring::event_loop::AsyncEventLoop;
#[cfg(has_io_uring)]
pub(crate) use uring::provided::ProvidedBufRing;
#[cfg(has_io_uring)]
pub(crate) use uring::ring::Ring;

#[cfg(not(has_io_uring))]
compile_error!(
    "The mio backend is not yet implemented. \
     Build on Linux 6.0+ with the `io-uring` feature (default) to use the io_uring backend."
);
