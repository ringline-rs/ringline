//! The accept mode. Public through `lib.rs` only with the `unstable-accept`
//! feature; the private module lets `Config` name the type without it.
//!
//! The doctests below run only with the feature off and fail if a gated item
//! becomes public.
#![cfg_attr(
    not(feature = "unstable-accept"),
    doc = r#"
```compile_fail,E0432
use ringline::AcceptMode;
```
```compile_fail,E0432
use ringline::ParkState;
```
```compile_fail,E0603
use ringline::config::AcceptMode;
```
```compile_fail,E0599
fn f(b: ringline::ConfigBuilder) -> ringline::ConfigBuilder {
    b.accept_mode(Default::default())
}
```
```compile_fail,E0599
fn f(r: &ringline::Runtime) {
    let _ = r.set_worker_accepting(0, false);
}
```
```compile_fail,E0599
fn f(c: &ringline::Connection) {
    c.offer_for_park(None);
}
```
```compile_fail,E0599
fn f(h: &ringline::RecvHalf) {
    h.offer_for_park(None);
}
```
```compile_fail,E0599
fn f(h: &ringline::SendHalf) {
    h.offer_for_park(None);
}
```
```compile_fail,E0599
fn f<H: ringline::AsyncEventHandler>() {
    let _ = H::on_adopt;
}
```
"#
)]

/// Where connections are accepted.
///
/// Requires the `unstable-accept` feature. Outside semver.
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
