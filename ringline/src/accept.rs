//! The accept mode. Public through `lib.rs` only with the `unstable-accept`
//! feature; the private module lets `Config` name the type without it.

/// Where connections are accepted.
///
/// See `docs/listeners-and-accept-design.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AcceptMode {
    /// One acceptor thread per listener, handing accepted fds to workers over
    /// a channel with explicit round-robin placement. The default.
    ///
    /// Placement is deterministic, and a worker that is full or has exited is
    /// skipped — properties the merged mode has to reconstruct.
    #[default]
    Pool,
    /// Each worker owns a `SO_REUSEPORT` listener and accepts on its own ring
    /// with multishot accept. No acceptor thread, no channel, no wake fd, and
    /// no cross-thread handoff per connection.
    ///
    /// Placement falls to the kernel's 4-tuple hash unless steered, which is
    /// uneven for a client that opens a pool of connections: at N connections
    /// over N workers roughly 1/e of workers get none. That is why this is not
    /// the default. io_uring only — the mio backend always uses [`Pool`].
    ///
    /// Not compatible with
    /// [`RinglineBuilder::defer_listen`](crate::RinglineBuilder::defer_listen);
    /// on the io_uring backend `launch()` refuses the combination.
    ///
    /// [`Pool`]: AcceptMode::Pool
    #[cfg_attr(not(feature = "unstable-accept"), allow(dead_code))]
    Merged,
}
