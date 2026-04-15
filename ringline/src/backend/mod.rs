#[cfg(feature = "io-uring")]
pub(crate) mod uring;

#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::Driver;
#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::PendingRecvBuf;
#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::UdpSocketState;
#[cfg(feature = "io-uring")]
#[allow(unused_imports)]
pub(crate) use uring::driver::sockaddr_to_peer_addr;
#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::sockaddr_to_socket_addr;
#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::socket_addr_to_sockaddr;
#[cfg(feature = "io-uring")]
pub(crate) use uring::driver::unix_path_to_sockaddr;
#[cfg(feature = "io-uring")]
pub(crate) use uring::event_loop::AsyncEventLoop;
#[cfg(feature = "io-uring")]
pub(crate) use uring::provided::ProvidedBufRing;
#[cfg(feature = "io-uring")]
pub(crate) use uring::ring::Ring;

#[cfg(not(feature = "io-uring"))]
compile_error!(
    "The mio backend is not yet implemented. \
     Enable the `io-uring` feature (default) to build."
);
