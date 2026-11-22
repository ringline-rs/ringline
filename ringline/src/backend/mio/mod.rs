pub(crate) mod driver;
pub(crate) mod event_loop;

/// mio's registration wrapper for a raw fd, which mio exports per platform.
#[cfg(target_os = "hermit")]
pub(crate) use mio::hermit::SourceFd;
#[cfg(not(target_os = "hermit"))]
pub(crate) use mio::unix::SourceFd;
