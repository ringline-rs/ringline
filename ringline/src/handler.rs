use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;

use crate::buffer::send_copy::SendCopyPool;
#[cfg(has_io_uring)]
use crate::buffer::send_slab::{InFlightSendSlab, MAX_GUARDS, MAX_IOVECS};
use crate::fs::FileKind;
use crate::guard::GuardBox;

/// Per-connection send queue state.
///
/// At most one stream send operation is in the kernel per connection: one
/// SQE or one coalesced `sendmsg`. While one is in flight, later sends are queued, and the next is pushed from the
/// completion handler before control returns to the event loop.
pub(crate) struct ConnSendState {
    pub in_flight: bool,
    pub queue: VecDeque<BuiltSend>,
    /// The queue head could not be pushed (SQ still full after submit) and
    /// waits for `drain_send_retries`. Set with `in_flight = true` at every
    /// park site, cleared by any successful push and whenever the queue is
    /// released. `drain_send_retries` acts only while this is set, so a
    /// retry entry that outlives its park (another path pushed the head
    /// first) cannot push a second SQE alongside it. io_uring only; mio
    /// never parks (sends wait for writability, not for SQ room).
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub parked: bool,
    /// Teardown has been requested for this connection (peer FIN, read
    /// error, task return, or an explicit close) and is deferred until
    /// queued sends drain. Set by the driver's `close_connection` and the
    /// `DriverCtx` close on both backends, alongside `Lifecycle::Closing`.
    ///
    /// io_uring: the `Close` SQE is submitted from `try_finalize_close`,
    /// driven from the event loop's end-of-iteration drain of
    /// `pending_finalize_closes` (never inside the close request or a send
    /// or `Shutdown` completion, so the task gets its poll window —
    /// #371; the park install commits at once, see `try_finalize_close`);
    /// each send CQE registers the connection on that list again
    /// until the serialized `submit_next_queued` cycle drains the queue and
    /// the in-flight slot. mio: `drain_pending_closes` retains the entry
    /// until `pending_sends` is empty, then runs executor cleanup and
    /// `finish_close`. Without the deferral, queued bytes were silently
    /// truncated when the fd closed. The connection-level state is
    /// `Lifecycle::Closing` (`connection.rs`); this flag is its "waiting
    /// for the drain" sub-state.
    pub close_pending: bool,
    /// Whether the Close SQE for the current occupant has been submitted
    /// (deferred close finalized, or force-finalized). From this point any
    /// still-in-flight send CQE must not push new SQEs (resubmits, POLLOUT
    /// arms) for this connection — they would race the in-flight Close.
    /// Cleared by `reset_send_state` at slot reactivation. Distinct from
    /// `recv_finished()`, which also covers half-close (peer FIN with
    /// legitimate sends still flowing). Sub-state of `Lifecycle::Closing`:
    /// the Close SQE is committed.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub close_submitted: bool,
    /// Set to `CLOSE_NOTIFY_TIMEOUT` from now by `DriverCtx::close` on a TLS
    /// connection (io_uring), whether or not it queued an alert, and by
    /// `close_connection` on a connection whose handshake or connect has not
    /// completed (both backends). When the deadline passes with
    /// `close_pending` still true, the runtime closes the connection without
    /// its queued sends.
    pub close_notify_deadline: Option<std::time::Instant>,
    /// Whether a `Shutdown` for the current occupant has been requested and
    /// its CQE has not arrived: the SQE is in the kernel, or parked on
    /// `Driver::pending_shutdown_retries`.
    ///
    /// `Shutdown` names its socket as the *registered-file slot*
    /// `Fixed(conn_index)`, not as an fd, so it must not execute after that slot
    /// has been closed and handed to the next accept — the kernel would FIN
    /// the connection that now holds the slot, half-closing a live connection
    /// whose next send then fails `EPIPE` (#518). Set when the FIN is
    /// requested, before the push, so it also covers an SQE parked on
    /// `Driver::pending_shutdown_retries`; cleared by its CQE, and required by
    /// `try_finalize_close` before the `Close` that frees the slot may be
    /// submitted. Cleared by `reset_send_state` at slot reactivation, like
    /// `close_submitted`.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub shutdown_inflight: bool,
    /// The raw user_data of the send whose rest waits for room, which names its
    /// pool slot or slab entry and its completion path. Nothing of it is in the
    /// kernel. `in_flight` stays true, so nothing else sends meanwhile.
    #[cfg(has_io_uring)]
    pub waiting_send: Option<u64>,
    /// The connection's `SendPollOut`.
    #[cfg(has_io_uring)]
    pub send_poll: SendPoll,
    /// A `POLLOUT` arrived while the send was in the kernel. If that send
    /// comes back short, it does not have to wait for another.
    #[cfg(has_io_uring)]
    pub pollout_seen: bool,
    /// The send in the kernel was resubmitted on a `POLLOUT`.
    #[cfg(has_io_uring)]
    pub resubmitted_on_pollout: bool,
    /// The connection is on `Driver::send_backstop_list`.
    #[cfg(has_io_uring)]
    pub on_send_backstop: bool,
    /// A close_notify the send pool had no slot for when the close was
    /// requested: its ciphertext (unbuffered engine), or empty when rustls
    /// still holds it (buffered engine). `try_finalize_close` places it once
    /// the connection's own sends have drained, or drops it and clears the
    /// connection's `close_notify_sent`.
    #[cfg(has_io_uring)]
    pub close_notify_pending: Option<Vec<u8>>,
    /// `abort` ran for the current occupant (`SendHalf::abort`). Every send
    /// started afterwards is refused with `ConnectionAborted`
    /// ([`closing_refusal`](Self::closing_refusal)), and on mio the close
    /// skips the flush and the close_notify. Cleared by `reset_send_state`
    /// at slot reactivation (io_uring) and by `finish_close` (mio).
    pub aborted: bool,
    /// The state of the disconnect `abort` submits on a TCP connection.
    /// io_uring only.
    #[cfg(has_io_uring)]
    pub disconnect: Disconnect,
    /// The task of a `SendHalf::writable` future that waits on this
    /// connection for room in its socket. Taken when the task is woken: on
    /// io_uring by the completion that ends the wait (a `POLLOUT`, an error,
    /// a hangup or a cancel) and by the completion or push that leaves no
    /// send queued or waiting, on mio by any event on the connection and by
    /// the flush that empties its queue, and on both by `abort`, by `close`,
    /// by a close that dropping the last half requests, and at the slot's
    /// release. The future registers again if it is polled before its wait
    /// has ended.
    pub writable_task: Option<u32>,
    /// io_uring: what ended a `writable` future's wait, for its next poll,
    /// and the task it was for. The future clears its own when it starts to
    /// wait on the socket, so only an event that arrives while it waits
    /// counts.
    #[cfg(has_io_uring)]
    pub writable_event: Option<(u32, WritableEvent)>,
    /// io_uring: the resubmit of the send that waited for room, or the plain
    /// re-send of a zero-copy send that got `ENOMEM`, is on a retry list, the
    /// SQ having had no room for it: as for a queued send, a `writable`
    /// future waits until its push goes through.
    #[cfg(has_io_uring)]
    pub resubmit_queued: bool,
    /// io_uring: the registered `writable` future waits for the
    /// connection's queued and waiting sends, not yet on the socket; the
    /// completion that leaves none wakes it.
    #[cfg(has_io_uring)]
    pub writable_blocked: bool,
    /// io_uring: the state of the connection's `SendPollProbe`, the one-shot
    /// `POLLOUT` poll a `writable` future arms while the connection's
    /// `SendPollOut` is multishot.
    #[cfg(has_io_uring)]
    pub send_probe: SendProbe,
    /// io_uring: the task of a `send_buffer_size` future whose
    /// `FixedFdInstall` is in flight (`OpTag::SendBufInstall`). The completion
    /// stores `send_buf_result` and wakes it; the slot's release wakes it too.
    #[cfg(has_io_uring)]
    pub send_buf_task: Option<u32>,
    /// io_uring: `SO_SNDBUF` read by that completion, or the errno that
    /// failed it, for the future's next poll.
    #[cfg(has_io_uring)]
    pub send_buf_result: Option<Result<u32, i32>>,
    /// The connection's most recent send waited for room in the socket, so
    /// `SendAdmissionOrder::Budget` lets no send on it pass a waiting head.
    /// Kept only while the driver's `track_room_waits` is set.
    ///
    /// Both backends keep it by one rule. It is set as soon as a send waits
    /// for room, and at each completion that settles awaited sends it becomes
    /// whether any send since the previous such completion waited
    /// (`send_waited`). When every send on the connection is awaited, as a
    /// server's replies with `send_admitted` are, that is whether its most
    /// recent send waited. A send without an id ends nothing: its wait
    /// carries to the next awaited send, and the flag stays set meanwhile.
    ///
    /// What counts as having waited follows how each backend writes. On
    /// io_uring a send waited if an SQE of it came back short or with
    /// `EAGAIN` (`wait_for_room`); the sends queued behind it had not been
    /// submitted. On mio a send waited if it was queued when a `writev`
    /// returned `WouldBlock` (`waited_entries`): that write carried the
    /// queued sends, up to the 1024 iovecs one `writev` takes, and mio counts
    /// every queued send, those past the first 1024 too.
    pub room_waited: bool,
    /// A send since the last completion that settled an awaited send waited
    /// for room. On io_uring `wait_for_room` sets it and
    /// `Driver::end_logical_send` moves it into `room_waited`; on mio a send
    /// that completes after waiting sets it, and an awaited one moves it.
    /// Kept only while the driver's `track_room_waits` is set.
    pub send_waited: bool,
    /// mio: how many sends at the front of the queue were queued when a
    /// `writev` last returned `WouldBlock`, and so waited for room; each
    /// that completes counts one off. Kept only while the driver's
    /// `track_room_waits` is set.
    #[cfg(not(has_io_uring))]
    pub waited_entries: usize,
}

/// What ended a `writable` future's wait on io_uring.
#[cfg(has_io_uring)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WritableEvent {
    /// The socket reported `POLLOUT`.
    Room,
    /// A send that waited for room was resubmitted, on the `POLLOUT` the
    /// future waited for or by the backstop, or a send parked on a retry
    /// list was pushed, and it may take the room: the future looks again,
    /// from its check for queued and waiting sends, and waits for that send
    /// to leave the kernel before it arms.
    Recheck,
    /// An error, a hangup or a cancel, with its errno.
    Failed(i32),
}

/// The state of a connection's `SendPollProbe`.
#[cfg(has_io_uring)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendProbe {
    None,
    /// Queued on `Driver::pending_send_probe_retries`: the SQ was full.
    Pending,
    /// In the kernel.
    Armed,
}

/// The `IORING_OP_CONNECT` with an `AF_UNSPEC` address that `abort` submits
/// on a TCP connection: it resets the socket and purges its write queue, so
/// the zero-copy notifications of its sends land without waiting for the
/// fixed file's release.
#[cfg(has_io_uring)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Disconnect {
    /// No disconnect is pending: no abort, a Unix-domain connection, the
    /// chain carrying it was pushed, or a lone one has completed.
    None,
    /// The disconnect goes first in the `Close`'s chain:
    /// `submit_committed_close` pushes the disconnect, the close lead and the
    /// `Close` as one hard-linked chain, and retries the chain as a whole.
    WithClose,
    /// A `Shutdown` from `shutdown_write` was in flight at the abort, so the
    /// disconnect was submitted on its own: it is in the kernel or on
    /// `Driver::pending_disconnect_retries`. `try_finalize_close` holds the
    /// `Close` until its completion, which sets `None`.
    Alone,
}

/// The state of a connection's `SendPollOut`.
#[cfg(has_io_uring)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendPoll {
    None,
    /// Queued on `Driver::pending_send_pollout_retries`: the SQ was full.
    Pending,
    OneShot,
    Multi,
}

impl ConnSendState {
    pub fn new() -> Self {
        ConnSendState {
            in_flight: false,
            parked: false,
            queue: VecDeque::new(),
            close_pending: false,
            close_submitted: false,
            close_notify_deadline: None,
            shutdown_inflight: false,
            #[cfg(has_io_uring)]
            waiting_send: None,
            #[cfg(has_io_uring)]
            send_poll: SendPoll::None,
            #[cfg(has_io_uring)]
            pollout_seen: false,
            #[cfg(has_io_uring)]
            resubmitted_on_pollout: false,
            #[cfg(has_io_uring)]
            on_send_backstop: false,
            #[cfg(has_io_uring)]
            close_notify_pending: None,
            aborted: false,
            #[cfg(has_io_uring)]
            disconnect: Disconnect::None,
            writable_task: None,
            #[cfg(has_io_uring)]
            writable_event: None,
            #[cfg(has_io_uring)]
            writable_blocked: false,
            #[cfg(has_io_uring)]
            resubmit_queued: false,
            #[cfg(has_io_uring)]
            send_probe: SendProbe::None,
            #[cfg(has_io_uring)]
            send_buf_task: None,
            #[cfg(has_io_uring)]
            send_buf_result: None,
            room_waited: false,
            send_waited: false,
            #[cfg(not(has_io_uring))]
            waited_entries: 0,
        }
    }

    /// The error a new send on this connection fails with, if it is refused:
    /// `ConnectionAborted` after `abort`, and `NotConnected` once the `Close`
    /// is committed (a new send SQE would race it, and a parked one would
    /// never be re-driven).
    pub(crate) fn closing_refusal(&self) -> Option<io::Error> {
        if self.aborted {
            Some(aborted_error())
        } else if self.close_submitted {
            Some(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closing",
            ))
        } else {
            None
        }
    }
}

/// The error of a send or receive that `abort` ended.
pub(crate) fn aborted_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "connection aborted")
}

/// Identifies a connection, from `id()` on [`Connection`](crate::Connection), its
/// halves and the protocol clients.
///
/// Encodes the connection index and generation, so an id does not match a later
/// connection in the same slot until the slot's `u32` generation wraps. It
/// compares and hashes. No public method takes one except `mark_disconnected` on
/// the protocol pools. Ids are per worker, and two workers can hold equal ids, so
/// compare them or use them as keys only on the worker that owns the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId {
    pub(crate) index: u32,
    pub(crate) generation: u32,
}

impl ConnId {
    pub(crate) fn new(index: u32, generation: u32) -> Self {
        ConnId { index, generation }
    }

    /// The connection's slot index on its worker. A later connection can reuse
    /// the slot; use the whole `ConnId` to tell them apart.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// The message of a guarded send refused because its connection holds
/// `zero_copy_hold_cap` send slab entries while the slab is over half used.
#[cfg(has_io_uring)]
pub(crate) const ZERO_COPY_CAP_REFUSAL: &str =
    "send slab entries held by the connection at zero_copy_hold_cap";

/// How long a close waits for its queued sends to drain before the
/// connection is closed without them: a close after a fatal encrypt error
/// (io_uring), with its close_notify, and a close before the handshake
/// completes (both backends), with the rest of the handshake flight and any
/// alert.
pub(crate) const CLOSE_NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Identifies which listener a connection arrived on.
///
/// A runtime can bind several listeners — any mix of TCP and Unix — and every
/// one of them feeds the same [`on_accept`]. Without this a handler serving,
/// say, plaintext on one port and a Unix admin socket on another has no way to
/// tell the two apart.
///
/// Ids are assigned in `bind()` / `bind_unix()` call order, starting at 0, so
/// a caller that knows the order it bound in knows the id. Pair it with
/// [`Runtime::bound_addr_of`] to recover the address a given id landed
/// on — useful when binding port 0.
///
/// [`on_accept`]: crate::AsyncEventHandler::on_accept
/// [`Runtime::bound_addr_of`]: crate::Runtime::bound_addr_of
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListenerId(pub(crate) u32);

impl ListenerId {
    /// The listener's position in `bind()` call order, from 0.
    pub fn index(&self) -> u32 {
        self.0
    }

    /// The id of the listener at `index` in `bind()` call order.
    ///
    /// Ids follow call order, so a caller that bound in a known order can name
    /// a listener before any connection has arrived, for example to pass to
    /// [`begin_listening`](crate::begin_listening). Ids are per runtime: in a
    /// process running more than one, an id names the listener at that index
    /// in the runtime it is passed to: the calling worker's runtime for the
    /// free functions, the handle's runtime for `ListenHandle` and
    /// `Runtime` methods.
    pub fn from_index(index: u32) -> Self {
        ListenerId(index)
    }
}

impl std::fmt::Display for ListenerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "listener {}", self.0)
    }
}

// ── io_uring DriverCtx + send builders ──────────────��───────────────────
//
// The entire DriverCtx implementation and SendBuilder are io_uring-specific. On the mio backend, a minimal
// DriverCtx is provided below.

/// How many send-copy-pool slots a **bounded** send of `len` bytes on
/// `conn_index` can need, or why it can never be admitted.
///
/// This is the single definition of that number, and it exists because two
/// call sites need it to agree exactly:
///
/// - `send_backpressured`'s future passes it to `SendCompletions::enqueue`,
///   which will not release the future until the pool's free count covers it;
/// - `DriverCtx::send_bounded` then reserves (mio) or capacity-checks
///   (io_uring) against it.
///
/// If the future's number were the smaller of the two, the FIFO would admit a
/// message the backend immediately refuses. On the TLS path that refusal
/// arrives *after* rustls has mutated, and by departure 1 that closes the
/// connection rather than applying backpressure. Too large only delays. So
/// the asymmetry is the same one `CiphertextCapacity` was built around, and
/// the way to honour it is one function rather than two that agree today.
///
/// Errors are `InvalidInput` and permanent: no amount of waiting makes the
/// pool bigger, so the future must reject rather than park.
pub(crate) fn bounded_send_slots(
    pool: &SendCopyPool,
    tls_table: *mut crate::tls::TlsTable,
    conn_index: u32,
    len: usize,
) -> io::Result<usize> {
    let slot_size = pool.slot_size() as usize;
    let needed = if tls_table.is_null() {
        len.div_ceil(slot_size)
    } else {
        // SAFETY: same single-threaded borrow-splitting contract as every
        // other `tls_table` use in this module; read-only here.
        let table = unsafe { &*tls_table };
        match table.ciphertext_capacity(conn_index, len) {
            // A TLS connection is admitted against the ciphertext bound, not
            // the plaintext length (#385).
            Some(bound) => match bound.slots(slot_size) {
                Some(n) => n,
                // No bound is expressible for this slot size. Falling back to
                // the byte formula would under-estimate the unbuffered
                // engine, which is the direction that closes connections.
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "a bounded TLS send needs a send-pool slot of at least {} bytes to \
                             hold one whole record, but Config::send_copy_slot_size is \
                             {slot_size}",
                            bound.min_slot_size()
                        ),
                    ));
                }
            },
            // The table exists but this connection is plaintext.
            None => len.div_ceil(slot_size),
        }
    };
    let capacity = pool.slot_count();
    if needed > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "a bounded send of {len} bytes needs up to {needed} send-pool slots but the \
                 pool has {capacity} (raise Config::send_pool)"
            ),
        ));
    }
    Ok(needed)
}

#[cfg(has_io_uring)]
/// A short-lived borrow of driver fields, built by `Driver::make_ctx`.
pub(crate) struct DriverCtx<'a> {
    pub(crate) ring: &'a mut crate::backend::Ring,
    pub(crate) connections: &'a mut crate::connection::ConnectionTable,
    pub(crate) fixed_buffers: &'a mut crate::buffer::fixed::FixedBufferRegistry,
    pub(crate) send_copy_pool: &'a mut SendCopyPool,
    #[cfg(has_io_uring)]
    pub(crate) send_slab: &'a mut InFlightSendSlab,
    // SAFETY: Raw pointer for borrow splitting with the connection table.
    // Sound because: (1) single-threaded — DriverCtx is only created and used
    // on the worker thread that owns the Driver; (2) the pointer is derived
    // from `&mut Driver` which is live for the entire duration of any DriverCtx
    // borrow; (3) no mutable alias exists while DriverCtx holds this pointer
    // since DriverCtx borrows the other Driver fields mutably via split borrows.
    // Null when plaintext (TLS feature disabled or no TLS config).
    pub(crate) tls_table: *mut crate::tls::TlsTable,
    pub(crate) shutdown_requested: &'a mut bool,
    /// Pre-allocated sockaddr storage for outbound connect SQEs.
    pub(crate) connect_addrs: &'a mut Vec<libc::sockaddr_storage>,
    /// Whether to set TCP_NODELAY on outbound connections.
    pub(crate) tcp_nodelay: bool,
    /// Guard sends below this total length fall back to copy (0 = always ZC).
    pub(crate) send_zc_threshold: u32,
    /// Send slab entries a connection may hold before its zero-copy sends are
    /// refused, once the slab is over half used
    /// (`ConfigBuilder::zero_copy_hold_cap`).
    pub(crate) zero_copy_hold_cap: usize,
    /// The worker's connect deadlines (io_uring only).
    #[cfg(has_io_uring)]
    pub(crate) connect_deadlines:
        &'a mut crate::backend::uring::connect_deadlines::ConnectDeadlines,
    /// Per-connection send queues for serializing sends.
    pub(crate) send_queues: &'a mut Vec<ConnSendState>,
    /// Connection indices with armed `close_notify_deadline`s. See the
    /// matching field on `backend::uring::driver::Driver` — the event
    /// loop's deadline check iterates this instead of all send queues
    /// so non-TLS workloads pay zero per-iteration cost.
    pub(crate) close_notify_armed: &'a mut Vec<u32>,
    /// NVMe device table. `None` when NVMe is not configured.
    pub(crate) nvme_devices: &'a mut Option<crate::nvme::NvmeDeviceTable>,
    /// NVMe command slab. `None` when NVMe is not configured.
    pub(crate) nvme_cmd_slab: &'a mut Option<crate::nvme::NvmeCmdSlab>,
    /// Base offset in the fixed file table for NVMe device fds.
    pub(crate) nvme_fd_base: u32,
    /// Filesystem file table. `None` when fs is not configured.
    pub(crate) fs_files: &'a mut Option<crate::fs::FsFileTable>,
    /// Filesystem command slab. `None` when fs is not configured.
    pub(crate) fs_cmd_slab: &'a mut Option<crate::fs::FsCmdSlab>,
    /// Base offset in the fixed file table for filesystem file fds.
    pub(crate) fs_fd_base: u32,
    /// Direct I/O file table. `None` when direct I/O is not configured.
    pub(crate) direct_io_files: &'a mut Option<crate::fs::FsFileTable>,
    /// Direct I/O command slab. `None` when direct I/O is not configured.
    pub(crate) direct_io_cmd_slab: &'a mut Option<crate::fs::FsCmdSlab>,
    /// Base offset in the fixed file table for direct I/O file fds.
    pub(crate) direct_io_fd_base: u32,
    /// Connections whose `close_pending` was set from this ctx (e.g.
    /// `DriverCtx::close`); the event loop re-drives `try_finalize_close`
    /// for each before the iteration ends. This keeps ctx-initiated closes
    /// on the same deferred path as `close_connection` — the Close SQE is
    /// only submitted once in-flight and queued sends drain.
    pub(crate) pending_finalize_closes: &'a mut Vec<u32>,
    /// `Shutdown` SQEs the ring refused; see `Driver::pending_shutdown_retries`.
    pub(crate) pending_shutdown_retries: &'a mut Vec<(u32, u32)>,
    /// Connections whose queued head send could not be pushed (SQ still
    /// full after submit); `submit_or_queue` parks the entry here instead of
    /// failing. Same list as `backend::uring::driver::Driver::pending_send_retries`,
    /// drained by the event loop's `drain_send_retries`.
    pub(crate) pending_send_retries: &'a mut Vec<(u32, u32)>,
    /// Worker-wide bounded-send results that no CQE will carry, keyed by
    /// the id the submitting future holds. Same queue as
    /// `backend::uring::driver::Driver::settled_sends`, drained by
    /// the event loop into `Executor::complete_send`.
    ///
    /// `send_bounded` needs it for the same reason mio's `DriverCtx` has
    /// one: a `DriverCtx` is a borrow of driver fields and has no executor
    /// access, so an operation it settles synchronously has nowhere else to
    /// go.
    pub(crate) settled_sends: &'a mut std::collections::VecDeque<(
        crate::runtime::send_completion::SendId,
        io::Result<u32>,
    )>,
    /// Mirror of `Driver::capacity_released`: set when a copy-pool slot goes
    /// back to the pool so the event loop wakes the send-capacity head once
    /// per iteration rather than once per released slot.
    pub(crate) capacity_released: &'a mut bool,
    pub(crate) next_disk_io_seq: &'a mut u16,
    /// See `Driver::write_orders`.
    pub(crate) write_orders: &'a mut crate::disk_order::WriteOrders<(u32, u64)>,
    /// Set when a [`SendBuilder`] with an awaited id gave the id to
    /// `attach_send_id`. `AsyncSendBuilder::build` reads it after its
    /// closure returns: a closure that returned `Ok` without a successful
    /// `submit` left the id with nothing to settle it.
    pub(crate) parts_id_carried: bool,
}

/// The refusal of a TLS send made after this side's close_notify was queued:
/// the record would follow the alert, and the peer discards it.
#[cfg(has_io_uring)]
pub(crate) fn close_notify_sent_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "connection closing: close_notify already sent",
    )
}

#[cfg(has_io_uring)]
impl<'a> DriverCtx<'a> {
    /// Request shutdown of this worker's event loop.
    /// The worker stops at its next shutdown check. It checks once per
    /// iteration, after draining the completions its wait returned and before
    /// polling tasks.
    pub fn request_shutdown(&mut self) {
        *self.shutdown_requested = true;
    }

    /// Whether the connection is Unix-domain. The kernel refuses `SENDMSG_ZC`
    /// on a Unix socket with `EOPNOTSUPP`, so its guard sends go out as plain
    /// `sendmsg`s (#829).
    pub(crate) fn conn_is_unix(&self, conn_index: u32) -> bool {
        self.connections
            .get(conn_index)
            .is_some_and(|c| matches!(c.peer_addr, Some(crate::connection::PeerAddr::Unix(_))))
    }

    /// Get TLS session information for a connection.
    pub fn tls_info(&self, conn: ConnId) -> Option<crate::tls::TlsInfo> {
        let cs = self.connections.get(conn.index)?;
        if cs.generation != conn.generation {
            return None;
        }
        if self.tls_table.is_null() {
            return None;
        }
        let tls_table = unsafe { &*self.tls_table };
        tls_table.get_info(conn.index)
    }

    /// Encrypt a plain (not bounded) TLS send into pool-backed sends, admitting
    /// it against the ciphertext bound first.
    ///
    /// The admission is the point. `encrypt_to_sends` allocates as it seals
    /// records, so running out of pool partway left the sealed records'
    /// sequence numbers spent with no ciphertext on the wire, and every later
    /// record failed `bad_record_mac` at the peer. Checking the bound
    /// `send_backpressured` uses (`TlsTable::ciphertext_capacity`) before
    /// rustls mutates turns that into the same refusal the plaintext path
    /// gives: `Other` while the pool is short, `InvalidInput` when it never
    /// could hold the message, nothing committed either way. A plain capacity
    /// check is enough: the worker is single-threaded and nothing allocates
    /// between the check and the call.
    ///
    /// No bound is expressible for the unbuffered engine with a slot too small
    /// for one whole record. `Config::validate` rejects such a slot for every
    /// configured rustls config, so a runtime does not reach that case; if it
    /// did, the send would be attempted without a bound. If encryption fails
    /// after rustls has sealed anything, the connection is closed: by
    /// departure 1 a record gap is fatal, and leaving the connection open only
    /// lets it emit records the peer will reject.
    ///
    /// The caller has checked that `conn` is current and has TLS state.
    fn encrypt_tls_send(&mut self, conn: ConnId, data: &[u8]) -> io::Result<Vec<BuiltSend>> {
        // SAFETY: read-only probe; see the `tls_table` field's contract.
        if unsafe { (*self.tls_table).close_notify_sent(conn.index) } {
            return Err(close_notify_sent_error());
        }
        let slot_size = self.send_copy_pool.slot_size() as usize;
        // SAFETY: same single-threaded borrow-splitting contract as every
        // other `tls_table` use in this module; no other reference to the
        // table is live across this function.
        let tls_table = unsafe { &mut *self.tls_table };
        let needed = tls_table
            .ciphertext_capacity(conn.index, data.len())
            .and_then(|bound| bound.slots(slot_size));
        if let Some(needed) = needed {
            let capacity = self.send_copy_pool.slot_count();
            if needed > capacity {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "a TLS send of {} bytes needs up to {needed} send-pool slots of \
                         ciphertext but the pool has {capacity} (raise Config::send_pool)",
                        data.len()
                    ),
                ));
            }
            if self.send_copy_pool.free_count() < needed {
                crate::metrics::POOL.increment(crate::metrics::pool::SEND_EXHAUSTED);
                return Err(io::Error::other("send copy pool exhausted"));
            }
        }
        let free_before = self.send_copy_pool.free_count();
        match crate::tls::encrypt_to_sends(
            tls_table,
            self.send_copy_pool,
            conn.index,
            conn.generation,
            data,
        ) {
            Ok(sends) => {
                // If encryption took more slots than the bound, the bound is
                // wrong, and a later send it admits can run out of pool
                // mid-encryption and close the connection.
                if let Some(needed) = needed {
                    debug_assert!(
                        free_before.saturating_sub(self.send_copy_pool.free_count()) <= needed,
                        "TLS ciphertext bound beaten: admitted against {needed} slots, \
                         encryption took {}",
                        free_before.saturating_sub(self.send_copy_pool.free_count()),
                    );
                }
                Ok(sends)
            }
            Err(e) => {
                // `encrypt_to_sends` released every slot it took, but any
                // record it sealed first spent a sequence number.
                //
                // The close queues a close_notify into pool slots. Those
                // belong to no passing send, so a send that was passing a
                // head stops marking around it.
                let marking = self.send_copy_pool.pause_passing();
                self.close(conn);
                self.send_copy_pool.resume_passing(marking);
                Err(e)
            }
        }
    }

    /// Regular (copying) send — copies data into library-owned pool before SQE submission.
    ///
    /// Data larger than one send-pool slot is split across slots and queued
    /// in order. Admission is transactional: every slot is reserved before
    /// the first byte is copied, so on `Err` nothing has been queued or
    /// transmitted and the same buffer may be sent again later. A send wider
    /// than the whole pool is refused with `InvalidInput`. Submission-queue
    /// pressure is absorbed by the per-connection queue and is not an error
    /// here. The TLS branch admits against the ciphertext bound before
    /// rustls mutates, so the same holds there (see `encrypt_tls_send`,
    /// which also names the one case that stays fatal). The user-facing
    /// contract lives on `SendHalf::send`. Every public send attaches an id
    /// (`send_awaited`), so only tests call this.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn send(&mut self, conn: ConnId, data: &[u8]) -> io::Result<()> {
        self.send_inner(conn, data, None, false)
    }

    /// [`send`](Self::send), with `id` attached to the send's final chunk:
    /// its completion settles `id` with `data.len()`. On `Err` nothing was
    /// queued and `id` is the caller's to cancel.
    pub(crate) fn send_awaited(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: crate::runtime::send_completion::SendId,
    ) -> io::Result<()> {
        self.send_inner(conn, data, Some(id), false)
    }

    /// The body of `send`, `send_awaited` and `send_bounded`. `id`, if any,
    /// is attached to the send's final chunk. On a TLS connection `bounded`
    /// adds a refusal with `InvalidInput` when no ciphertext bound is
    /// expressible for the slot size, after the close_notify check, and gives
    /// an oversize send `bounded_send_slots`' message. Both re-check what the
    /// send's future already checked with `bounded_send_slots` on the same
    /// inputs.
    fn send_inner(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: Option<crate::runtime::send_completion::SendId>,
        bounded: bool,
    ) -> io::Result<()> {
        let conn_state = self
            .connections
            .get(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }
        // Aborted, or the Close already submitted — a new send SQE would
        // race it, and a parked one would never be re-driven (the retry
        // drain skips connections whose Close is committed). Same refusal as
        // `send_parts`.
        if let Some(e) = self.send_queues[conn.index as usize].closing_refusal() {
            return Err(e);
        }

        // SAFETY: read-only probe; see the `tls_table` field's contract.
        if !self.tls_table.is_null() && unsafe { (*self.tls_table).has(conn.index) } {
            if bounded {
                // SAFETY: as above.
                if unsafe { (*self.tls_table).close_notify_sent(conn.index) } {
                    return Err(close_notify_sent_error());
                }
                bounded_send_slots(self.send_copy_pool, self.tls_table, conn.index, data.len())?;
            }
            let sends = self.encrypt_tls_send(conn, data)?;
            if let Some(id) = id {
                self.attach_send_id(sends.last(), id, data.len() as u32);
            }
            // Route every ciphertext chunk through the per-connection
            // send queue: io_uring doesn't order independent SQEs, and
            // a partial-send resubmit would interleave chunks on the
            // wire (bad_record_mac at the peer). Infallible: rustls has
            // already advanced its record sequence, so the ciphertext
            // must reach the wire — SQ pressure parks it, never drops it.
            self.queue_built_sends(conn.index, sends);
            return Ok(());
        }

        let slot_size = self.send_copy_pool.slot_size() as usize;

        // Reserve every slot the buffer needs before copying the first byte.
        // Without this, pool exhaustion on chunk k left chunks 1..k-1 queued
        // (or on the wire) behind an `Err`, and a retry duplicated the prefix.
        // The reservation is a count, not popped slots, so a refusal has no
        // side effects (see `SendCopyPool::reserve_slots`).
        let needed = data.len().div_ceil(slot_size);
        let mut reservation = match self.send_copy_pool.reserve_slots(needed) {
            Ok(r) => r,
            Err(crate::buffer::send_copy::ReserveError::Exhausted) => {
                return Err(io::Error::other("send copy pool exhausted"));
            }
            Err(crate::buffer::send_copy::ReserveError::TooLarge { needed, capacity }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "send of {} bytes needs {needed} send-pool slots but the pool has \
                         {capacity} (raise Config::send_pool)",
                        data.len()
                    ),
                ));
            }
        };

        // Chunk data that exceeds the send copy slot size. Each chunk gets its
        // own pool slot; only the final chunk carries the send's id, so the
        // send settles once. A send of one chunk goes through
        // `submit_or_queue`. The chunks of a larger send are queued together
        // and then submitted by `submit_queued_run`, which sends up to 32 of
        // them as one `sendmsg` when nothing is in flight and the send slab
        // has a free entry, instead of the first slot alone.
        //
        // Both are infallible: an SQE that cannot be pushed is parked at the
        // queue head. So once the reservation is granted the whole buffer is
        // committed, in order.
        let several = needed >= 2;
        let mut chunks = data.chunks(slot_size).peekable();
        if chunks.peek().is_none()
            && let Some(id) = id
        {
            // No bytes, no SQE, no completion: settle now.
            self.settled_sends_push(id, Ok(0));
        }
        while let Some(chunk) = chunks.next() {
            let (slot, ptr, len) = self
                .send_copy_pool
                .copy_in_reserved(&mut reservation, chunk);
            let end_of_send = chunks.peek().is_none();
            if end_of_send && let Some(id) = id {
                self.send_copy_pool.set_send_id(slot, id, data.len() as u32);
            }

            let user_data = crate::completion::UserData::encode(
                crate::completion::OpTag::Send,
                conn.index,
                crate::completion::UserData::send_payload(slot, conn.generation),
            );
            let entry =
                crate::backend::uring::sqe::Sqe::stream_send(conn.index, ptr, len, user_data.raw());

            let built = BuiltSend {
                entry,
                pool_slot: slot,
                slab_idx: u16::MAX,
            };

            if several {
                self.send_queues[conn.index as usize].queue.push_back(built);
            } else {
                self.submit_or_queue(conn.index, built);
            }
        }
        if several {
            self.submit_queued_run(conn.index);
        }

        // Every promised slot was filled; this returns a zero remainder.
        self.send_copy_pool.release_reservation(reservation);
        Ok(())
    }

    /// Submit a bounded (`SendHalf::send_backpressured`) send, tagging the
    /// operation's identity onto the slot whose completion settles it.
    ///
    /// `send_awaited` plus the bounded checks in `send_inner`'s TLS branch:
    /// the same generation check, `closing_refusal`, `reserve_slots` error
    /// mappings and chunk loop, with
    /// `id` and the **logical (plaintext) length** attached to the
    /// final slot, so the completion handler can resolve exactly this
    /// operation with exactly the number the caller passed. The length
    /// travels because nothing downstream can recompute it: a TLS send's
    /// final `OpTag::Send` chunk is one ciphertext record.
    ///
    /// Admission is the caller's: the send-capacity FIFO admits this id only
    /// when `free_count()` covers `bounded_send_slots`, and this function
    /// checks the same number again before encrypting. For a TLS connection
    /// that number is the ciphertext bound (`TlsTable::ciphertext_capacity`),
    /// not the plaintext length.
    ///
    /// Unlike mio, the reservation is *not* the permit and is not held
    /// across the TLS branch. It cannot be: on io_uring `encrypt_to_sends`
    /// allocates the ciphertext's slots out of this same pool, and an
    /// outstanding reservation hides them from `alloc_raw` (see
    /// `SendCopyPool::reserve_slots`). So the TLS branch returns before the
    /// reservation, exactly as `send` does.
    ///
    /// On `Ok` exactly one completion for `id` is coming: from a send CQE,
    /// from a teardown that destroys the queued entry
    /// (`Driver::settled_sends`), or — when the message produced no
    /// SQE at all — from this call, synchronously. On `Err` nothing was
    /// queued and no completion for `id` will ever be produced, so the
    /// caller owns the failure.
    ///
    /// Departure 1 (`docs/uring-bounded-send-design.md`): a TLS failure here
    /// lands after `encrypt_to_sends` has advanced rustls' record sequence,
    /// so the connection cannot carry further records. It fails *this*
    /// operation and closes the connection.
    pub(crate) fn send_bounded(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: crate::runtime::send_completion::SendId,
    ) -> io::Result<()> {
        self.send_inner(conn, data, Some(id), true)
    }

    /// Record a bounded-send result that no completion will ever carry, and
    /// note that pool capacity came back.
    ///
    /// `DriverCtx` is a borrow of driver fields with no executor access —
    /// the same reason mio's driver owns a completion queue — so a
    /// synchronous settle goes onto `Driver::settled_sends` for the
    /// event loop to hand to `Executor::complete_send`. The queue
    /// carries successes as well as failures: what unites its entries is
    /// that no CQE is coming for them.
    fn settled_sends_push(
        &mut self,
        id: crate::runtime::send_completion::SendId,
        result: io::Result<u32>,
    ) {
        self.settled_sends.push_back((id, result));
        *self.capacity_released = true;
    }

    /// The user_data payload of a disk-I/O operation in command-slab slot
    /// `slab_idx`: the subsystem in the top 2 bits, a 14-bit sequence below
    /// it, and the slab index in the low 16. CQE handlers take the slab
    /// index from the low 16 bits, and the slab entry holds the operation's
    /// disk-I/O key. The sequence makes the user_data of an operation differ
    /// from that of an earlier one in the same slot, which a cancel of the
    /// earlier one could otherwise reach.
    pub(crate) fn disk_op_id(&mut self, kind: DiskIoKind, slab_idx: u16) -> u32 {
        let seq = *self.next_disk_io_seq;
        *self.next_disk_io_seq = seq.wrapping_add(1);
        ((kind as u32) << 30) | (((seq as u32) & 0x3FFF) << 16) | slab_idx as u32
    }

    /// Attach `id` to the resource whose completion ends `built`: its slab
    /// entry if it has one, otherwise its pool slot. `len` is what the send
    /// reports on success. With no `built` (a send that produced no SQE),
    /// `id` settles now with `len`.
    pub(crate) fn attach_send_id(
        &mut self,
        built: Option<&BuiltSend>,
        id: crate::runtime::send_completion::SendId,
        len: u32,
    ) {
        match built {
            Some(b) if b.slab_idx != u16::MAX => self.send_slab.set_send_id(b.slab_idx, id, len),
            Some(b) if b.pool_slot != u16::MAX => {
                self.send_copy_pool.set_send_id(b.pool_slot, id, len)
            }
            Some(_) => debug_assert!(false, "an awaited send without a carrier"),
            None => self.settled_sends_push(id, Ok(len)),
        }
    }

    /// Queue a batch of built sends in order through the per-connection
    /// send queue. Two or more go out as one run (`submit_queued_run`).
    /// Infallible: both paths park under SQ pressure rather than failing, so
    /// every entry is committed in order and nothing needs releasing here.
    pub(crate) fn queue_built_sends(&mut self, conn_index: u32, sends: Vec<BuiltSend>) {
        if sends.len() < 2 {
            for built in sends {
                self.submit_or_queue(conn_index, built);
            }
            return;
        }
        self.send_queues[conn_index as usize].queue.extend(sends);
        self.submit_queued_run(conn_index);
    }

    /// Submit a built send SQE, or queue it if a send is already in flight.
    ///
    /// Infallible: the entry is committed to the connection's stream on
    /// return. If the push fails (SQ still full after submit) the entry is
    /// parked at the head of the (empty) queue with `in_flight = true` and
    /// the connection is registered on `pending_send_retries`; the event
    /// loop's `drain_send_retries` re-pushes it each iteration until the ring
    /// takes it. Nothing is dropped or released here (Domain Invariant 7).
    pub(crate) fn submit_or_queue(&mut self, conn_index: u32, built: BuiltSend) {
        // A non-empty queue implies `in_flight`, which `submit_next_queued`
        // relies on.
        let state = &mut self.send_queues[conn_index as usize];
        if state.in_flight {
            state.queue.push_back(built);
            state.in_flight = true;
            return;
        }
        match unsafe { self.ring.push_sqe(&built.entry) } {
            Ok(()) => state.in_flight = true,
            Err(_) => {
                // SQ still full after submit: park at the head and retry next
                // iteration (see `drain_send_retries`). Nothing is dropped.
                state.queue.push_back(built);
                state.in_flight = true;
                state.parked = true;
                let generation = self.connections.generation(conn_index);
                self.pending_send_retries.push((conn_index, generation));
            }
        }
    }

    /// Submit the sends just queued on `conn_index`, as one `sendmsg`
    /// (`submit_coalesced_run`), or the head alone if the run cannot be
    /// coalesced. With a send already in flight they wait in the queue, as in `submit_or_queue`.
    /// Infallible in the same way: on a full SQ the head is parked and the
    /// connection goes on `pending_send_retries`.
    pub(crate) fn submit_queued_run(&mut self, conn_index: u32) {
        let ci = conn_index as usize;
        let state = &mut self.send_queues[ci];
        if state.in_flight || state.queue.is_empty() {
            state.in_flight |= !state.queue.is_empty();
            return;
        }
        state.in_flight = true;
        let generation = self.connections.generation(conn_index);
        let pushed = crate::backend::uring::driver::submit_coalesced_run(
            crate::backend::uring::driver::RunParts {
                ring: self.ring,
                send_slab: self.send_slab,
                send_copy_pool: self.send_copy_pool,
                send_queues: self.send_queues,
                pending_send_retries: self.pending_send_retries,
            },
            conn_index,
            generation,
        );
        if pushed.is_some() {
            return;
        }
        let state = &mut self.send_queues[ci];
        match unsafe { self.ring.push_sqe(&state.queue[0].entry) } {
            Ok(()) => {
                state.queue.pop_front();
            }
            Err(_) => {
                state.parked = true;
                self.pending_send_retries.push((conn_index, generation));
            }
        }
    }

    /// [`send_parts`](Self::send_parts), with `id` settled by the send's
    /// completion once `submit` queues it. `submit` refuses an empty batch
    /// with `InvalidInput`.
    pub(crate) fn send_parts_awaited(
        &mut self,
        conn: ConnId,
        id: crate::runtime::send_completion::SendId,
    ) -> SendBuilder<'_, 'a> {
        let mut builder = self.send_parts(conn);
        builder.send_id = Some(id);
        builder
    }

    /// The send-pool slots a waiting batch of `parts` on a plaintext
    /// connection waits for, or the refusal [`SendBuilder::submit`] would give it
    /// for its shape: one slot if it has copy parts, none if it has only
    /// guards. Reads the parts and consumes nothing, so a refusal can return
    /// every part.
    #[cfg(has_io_uring)]
    pub(crate) fn batch_plain_slots(&self, parts: &[SendPart<'_>]) -> io::Result<usize> {
        if parts.len() > MAX_IOVECS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 32)",
            ));
        }
        let mut copy_len = 0usize;
        let mut guards = 0usize;
        let mut total = 0u64;
        for part in parts {
            match part {
                SendPart::Copy(data) => {
                    copy_len += data.len();
                    total += data.len() as u64;
                }
                SendPart::Guard(guard) => {
                    guards += 1;
                    let (ptr, len) = guard.as_ptr_len();
                    total += u64::from(len);
                    let region = guard.region();
                    if region != crate::buffer::fixed::RegionId::UNREGISTERED {
                        self.fixed_buffers
                            .validate_region_ptr(region, ptr, len)
                            .map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                            })?;
                    }
                }
            }
        }
        if guards > MAX_GUARDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many guards (max 8)",
            ));
        }
        if total > u64::from(u32::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "send batch longer than u32::MAX bytes",
            ));
        }
        if copy_len > self.send_copy_pool.slot_size() as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "total copy data exceeds send pool slot size",
            ));
        }
        Ok(usize::from(copy_len > 0))
    }

    /// Whether [`SendBuilder::submit`] can queue a waiting batch of `parts`
    /// on plaintext connection `conn` now, checked without consuming a part:
    /// the connection checks, [`batch_plain_slots`](Self::batch_plain_slots),
    /// a free pool slot for copy parts, and, for a batch with guards that
    /// does not fit the small-send gather, a free send-slab entry the
    /// connection may take (`zero_copy_over_cap`). On `Ok`, `submit` does not
    /// refuse the batch.
    #[cfg(has_io_uring)]
    pub(crate) fn batch_plain_ready(&self, conn: ConnId, parts: &[SendPart<'_>]) -> io::Result<()> {
        let conn_state = self
            .connections
            .get(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }
        if let Some(e) = self.send_queues[conn.index as usize].closing_refusal() {
            return Err(e);
        }
        let needed = self.batch_plain_slots(parts)?;
        let free = self.send_copy_pool.free_count();
        if free < needed {
            return Err(io::Error::other("send copy pool exhausted"));
        }
        let has_guards = parts.iter().any(|p| matches!(p, SendPart::Guard(_)));
        if has_guards {
            let total: usize = parts
                .iter()
                .map(|p| match p {
                    SendPart::Copy(d) => d.len(),
                    SendPart::Guard(g) => g.as_ptr_len().1 as usize,
                })
                .sum();
            // `submit_small_gather` takes one slot when one is free and the
            // whole batch fits it; otherwise the batch needs a slab entry.
            let threshold = self.send_zc_threshold as usize;
            let gathers = threshold > 0
                && total < threshold
                && total <= self.send_copy_pool.slot_size() as usize
                && free >= 1;
            if !gathers && !self.send_slab.has_free() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "send slab exhausted",
                ));
            }
            if !gathers && self.zero_copy_over_cap(conn) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    ZERO_COPY_CAP_REFUSAL,
                ));
            }
        }
        Ok(())
    }

    /// Whether a zero-copy send on `conn` is refused: the connection holds
    /// `zero_copy_hold_cap` send slab entries and the slab is over half used.
    #[cfg(has_io_uring)]
    pub(crate) fn zero_copy_over_cap(&self, conn: ConnId) -> bool {
        self.send_slab
            .zero_copy_over_cap(conn.index, conn.generation, self.zero_copy_hold_cap)
    }

    /// Begin building a scatter-gather send with mixed copy + zero-copy guard parts.
    pub fn send_parts(&mut self, conn: ConnId) -> SendBuilder<'_, 'a> {
        SendBuilder {
            ctx: self,
            conn,
            parts: [PartSlot::Empty; MAX_IOVECS],
            part_count: 0,
            copy_slices: [(std::ptr::null(), 0); MAX_IOVECS],
            copy_count: 0,
            total_copy_len: 0,
            guards: [const { None }; crate::buffer::send_slab::MAX_GUARDS],
            guard_count: 0,
            total_len: 0,
            error: None,
            send_id: None,
            zero_copy_capped: true,
        }
    }

    /// Close a connection.
    ///
    /// The close is serialized behind the connection's outstanding work:
    /// queued and in-flight sends drain first (their bytes still reach the
    /// wire), then the deferred Close SQE is submitted by the event loop's
    /// `try_finalize_close`.
    pub fn close(&mut self, conn: ConnId) {
        if let Some(conn_state) = self.connections.get_mut(conn.index) {
            if conn_state.generation != conn.generation {
                return;
            }
            // Already closing (e.g. a task-side close raced this one):
            // re-running would queue a duplicate close_notify and, after the
            // first finalize cleared close_pending, submit a duplicate Close
            // SQE. Same guard as close_connection and the mio ctx close.
            if conn_state.close_requested() {
                return;
            }
            conn_state.lifecycle = crate::connection::Lifecycle::Closing;
            // No alert once a write shutdown has been requested: the rule
            // `Driver::queue_tls_close_notify` applies to the application's
            // close.
            let alert_allowed = matches!(conn_state.write, crate::connection::WriteHalf::Open);

            // Graceful TLS shutdown: queue close_notify ciphertext through
            // the per-connection send queue so it serializes behind any
            // in-flight sends (the linked-SQE variant is only sound when
            // the Close SQE immediately follows in the same push).
            if !self.tls_table.is_null() {
                let tls_table = unsafe { &mut *self.tls_table };
                if tls_table.has(conn.index) {
                    if alert_allowed {
                        let mut sends = Vec::new();
                        let retained = tls_table.send_close_notify_queued(
                            conn.index,
                            conn.generation,
                            self.send_copy_pool,
                            &mut sends,
                        );
                        if !sends.is_empty() {
                            self.queue_built_sends(conn.index, sends);
                        }
                        self.send_queues[conn.index as usize].close_notify_pending = retained;
                    }
                    // Arm the close_notify deadline so the event loop
                    // force-closes if the deferred Close never fires (peer
                    // stops reading and the queue can't drain). Live now
                    // that `close_pending` is actually set on this path.
                    let state = &mut self.send_queues[conn.index as usize];
                    state.close_notify_deadline =
                        Some(std::time::Instant::now() + CLOSE_NOTIFY_TIMEOUT);
                    if !self.close_notify_armed.contains(&conn.index) {
                        self.close_notify_armed.push(conn.index);
                    }
                }
            }

            // Defer the Close behind whatever is outstanding; the event loop
            // re-drives try_finalize_close before the iteration ends, and
            // each send CQE registers the connection again for that drain
            // (`defer_finalize_close`).
            self.send_queues[conn.index as usize].close_pending = true;
            if !self.pending_finalize_closes.contains(&conn.index) {
                self.pending_finalize_closes.push(conn.index);
            }
        }
    }

    /// Shutdown the write side of a connection.
    ///
    /// If a send is in flight or queued, the shutdown is deferred until the
    /// send queue drains (`submit_next_queued_inner`'s empty-queue arm
    /// submits it): io_uring does not order an
    /// independent Shutdown SQE behind those sends.
    pub fn shutdown_write(&mut self, conn: ConnId) {
        let Some(cs) = self.connections.get_mut(conn.index) else {
            return;
        };
        if cs.generation != conn.generation {
            return;
        }
        // Idempotent: a second request while pending or after the FIN is a
        // no-op. Once a close is requested, the Close and its lead end the
        // write half; no Shutdown is submitted.
        if !matches!(cs.write, crate::connection::WriteHalf::Open) || cs.close_requested() {
            return;
        }
        let idx = conn.index as usize;
        // Close already submitted — a Shutdown SQE would race it.
        if self.send_queues[idx].close_submitted {
            return;
        }
        if self.send_queues[idx].in_flight || !self.send_queues[idx].queue.is_empty() {
            // Defer until the send queue drains (submit_next_queued issues it).
            cs.write = crate::connection::WriteHalf::ShutdownPending;
        } else {
            let generation = cs.generation;
            cs.write = crate::connection::WriteHalf::Shutdown;
            // The slot must outlive the SQE, pushed or parked: see
            // `shutdown_inflight`.
            self.send_queues[idx].shutdown_inflight = true;
            if self.ring.submit_shutdown(conn.index, generation).is_err() {
                // Refused (ring backpressure): parked, and pushed again by
                // `drain_shutdown_retries`, as a refused send or Close is.
                self.pending_shutdown_retries.push((conn.index, generation));
            }
        }
    }

    /// Start an outbound TCP connection. Returns its token immediately; the
    /// caller registers the waiter that takes the connection.
    pub(crate) fn start_connect(
        &mut self,
        addr: SocketAddr,
    ) -> Result<ConnId, crate::error::Error> {
        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or(crate::error::Error::ConnectionLimitReached)?;
        let generation = self.connections.generation(conn_index);

        // Store peer address.
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(crate::connection::PeerAddr::Tcp(addr));
        }

        // Create socket.
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw_fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw_fd < 0 {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }

        // Set TCP_NODELAY if configured.
        if self.tcp_nodelay {
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Register in the direct file table, then close the original fd.
        if let Err(e) = self.ring.register_files_update(conn_index, &[raw_fd]) {
            unsafe {
                libc::close(raw_fd);
            }
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }
        unsafe {
            libc::close(raw_fd);
        }

        // Fill sockaddr_storage for the connect SQE.
        let addrlen = crate::backend::socket_addr_to_sockaddr(
            addr,
            &mut self.connect_addrs[conn_index as usize],
        );

        // Submit the async connect.
        if let Err(e) = self.ring.submit_connect(
            conn_index,
            generation,
            &self.connect_addrs[conn_index as usize] as *const _ as *const libc::sockaddr,
            addrlen,
        ) {
            // Stale fixed file entry is overwritten when the slot is reused.
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        Ok(ConnId::new(conn_index, generation))
    }

    /// Start an outbound Unix domain socket connection. Returns its token
    /// immediately; the caller registers the waiter that takes the connection.
    pub(crate) fn start_connect_unix(
        &mut self,
        path: &std::path::Path,
    ) -> Result<ConnId, crate::error::Error> {
        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or(crate::error::Error::ConnectionLimitReached)?;
        let generation = self.connections.generation(conn_index);

        // Store peer address.
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(crate::connection::PeerAddr::Unix(path.to_path_buf()));
        }

        // Create AF_UNIX socket.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw_fd < 0 {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }

        // Register in the direct file table, then close the original fd.
        if let Err(e) = self.ring.register_files_update(conn_index, &[raw_fd]) {
            unsafe {
                libc::close(raw_fd);
            }
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }
        unsafe {
            libc::close(raw_fd);
        }

        // Fill sockaddr_storage for the connect SQE.
        let addrlen = crate::backend::unix_path_to_sockaddr(
            path,
            &mut self.connect_addrs[conn_index as usize],
        );

        // Submit the async connect.
        if let Err(e) = self.ring.submit_connect(
            conn_index,
            generation,
            &self.connect_addrs[conn_index as usize] as *const _ as *const libc::sockaddr,
            addrlen,
        ) {
            // Stale fixed file entry is overwritten when the slot is reused.
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        Ok(ConnId::new(conn_index, generation))
    }

    /// Start an outbound TLS connection. Returns its token immediately; the
    /// caller registers the waiter that takes the connection once both
    /// handshakes complete.
    pub(crate) fn start_connect_tls(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<ConnId, crate::error::Error> {
        if self.tls_table.is_null() {
            return Err(crate::error::Error::RingSetup(
                "TLS not configured".to_string(),
            ));
        }
        let tls_table = unsafe { &mut *self.tls_table };
        if !tls_table.has_client_config() {
            return Err(crate::error::Error::RingSetup(
                "TLS client config not set".to_string(),
            ));
        }

        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or(crate::error::Error::ConnectionLimitReached)?;
        let generation = self.connections.generation(conn_index);

        // Store peer address.
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(crate::connection::PeerAddr::Tcp(addr));
        }

        // Create socket.
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw_fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw_fd < 0 {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }

        // Set TCP_NODELAY if configured.
        if self.tcp_nodelay {
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Register in the direct file table, then close the original fd.
        if let Err(e) = self.ring.register_files_update(conn_index, &[raw_fd]) {
            unsafe {
                libc::close(raw_fd);
            }
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }
        unsafe {
            libc::close(raw_fd);
        }

        // Create TLS client state (buffers ClientHello internally).
        let sni =
            ringline_tls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|e| {
                // Stale fixed file entry is overwritten when the slot is reused.
                let _ = self.ring.register_files_update(conn_index, &[-1]);
                self.connections.release(conn_index);
                crate::error::Error::RingSetup(format!("invalid server name: {e}"))
            })?;
        if let Err(e) = tls_table.create_client(conn_index, sni) {
            // Stale fixed file entry is overwritten when the slot is reused.
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::RingSetup(format!(
                "TLS client setup failed: {e}"
            )));
        }

        // Fill sockaddr_storage for the connect SQE.
        let addrlen = crate::backend::socket_addr_to_sockaddr(
            addr,
            &mut self.connect_addrs[conn_index as usize],
        );

        // Submit the async connect.
        if let Err(e) = self.ring.submit_connect(
            conn_index,
            generation,
            &self.connect_addrs[conn_index as usize] as *const _ as *const libc::sockaddr,
            addrlen,
        ) {
            tls_table.remove(conn_index);
            // Stale fixed file entry is overwritten when the slot is reused.
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        Ok(ConnId::new(conn_index, generation))
    }

    // ── NVMe passthrough methods ──────────────────────────────────────────

    /// Open an NVMe device for passthrough I/O.
    ///
    /// `path` must be an NVMe-generic character device (e.g., `/dev/ng0n1`).
    /// `nsid` is the NVMe namespace ID (usually 1).
    ///
    /// The device fd is registered in the io_uring fixed file table. Returns
    /// an [`NvmeDevice`](crate::nvme::NvmeDevice) handle for subsequent operations.
    pub fn open_nvme_device(
        &mut self,
        path: &str,
        nsid: u32,
    ) -> io::Result<crate::nvme::NvmeDevice> {
        let devices = self
            .nvme_devices
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;

        // Convert the path before allocating, so a bad path holds no slot.
        let c_path =
            std::ffi::CString::new(path).map_err(|_| io::Error::other("invalid device path"))?;
        let index = devices
            .allocate()
            .ok_or_else(|| io::Error::other("NVMe device table full"))?;

        // Open the NVMe-generic character device.
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            devices.release(index);
            return Err(io::Error::last_os_error());
        }

        // The logical block size, so a read knows how many bytes a command
        // transfers. A failure is kept for the reads and writes to return;
        // the device still opens, for flushes.
        let lba_size =
            crate::nvme::identify_lba_size(fd, nsid).map_err(|e| (e.kind(), e.to_string()));

        // Register in the fixed file table.
        let fd_index = self.nvme_fd_base + index as u32;
        if self.ring.register_files_update(fd_index, &[fd]).is_err() {
            devices.release(index);
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::other("failed to register NVMe fd"));
        }
        unsafe {
            libc::close(fd);
        }

        // Store device state.
        if let Some(dev) = devices.get_mut(index) {
            dev.fd_index = fd_index;
            dev.nsid = nsid;
            dev.lba_size = lba_size;
        }

        let generation = devices.get(index).map(|d| d.generation).unwrap_or(0);
        Ok(crate::nvme::NvmeDevice::new(index, generation))
    }

    /// Submit an NVMe read command.
    ///
    /// Reads `num_blocks` logical blocks starting at `lba` into the buffer
    /// at `buf_addr` with length `buf_len`.
    ///
    /// The command completes to `key`. Returns its user_data, which
    /// [`nvme_read`](crate::nvme_read)'s future cancels if it is dropped first.
    ///
    /// # Safety
    ///
    /// `buf_addr` must point to a valid, aligned buffer of at least `buf_len`
    /// bytes that remains valid and exclusively accessible until the
    /// corresponding CQE completes.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nvme_read(
        &mut self,
        device: crate::nvme::NvmeDevice,
        lba: u64,
        num_blocks: u16,
        buf_addr: u64,
        buf_len: u32,
        region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        if num_blocks == 0 {
            return Err(io::Error::other("num_blocks must be >= 1"));
        }
        let (fd_index, nsid) = self.validate_nvme_device(device)?;
        let buf_index = self.fixed_buf_index(region, buf_addr as *const u8, buf_len)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab.allocate(device.index, key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "NVMe command slab exhausted")
        })?;

        let cmd = crate::nvme::NvmeUringCmd::read(nsid, lba, num_blocks, buf_addr, buf_len);
        let op_id = self.disk_op_id(DiskIoKind::Nvme, slab_idx);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            op_id,
        );
        if let Some(slab) = self.nvme_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, buf_index, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(ud.raw())
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an NVMe write command.
    ///
    /// Writes `num_blocks` logical blocks starting at `lba` from the buffer
    /// at `buf_addr` with length `buf_len`.
    ///
    /// The command completes to `key`. Returns its user_data, which
    /// [`nvme_write`](crate::nvme_write)'s future cancels if it is dropped first.
    ///
    /// # Safety
    ///
    /// `buf_addr` must point to a valid, aligned buffer of at least `buf_len`
    /// bytes that remains valid and exclusively accessible until the
    /// corresponding CQE completes.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nvme_write(
        &mut self,
        device: crate::nvme::NvmeDevice,
        lba: u64,
        num_blocks: u16,
        buf_addr: u64,
        buf_len: u32,
        region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        if num_blocks == 0 {
            return Err(io::Error::other("num_blocks must be >= 1"));
        }
        let (fd_index, nsid) = self.validate_nvme_device(device)?;
        let buf_index = self.fixed_buf_index(region, buf_addr as *const u8, buf_len)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab.allocate(device.index, key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "NVMe command slab exhausted")
        })?;

        let cmd = crate::nvme::NvmeUringCmd::write(nsid, lba, num_blocks, buf_addr, buf_len);
        let op_id = self.disk_op_id(DiskIoKind::Nvme, slab_idx);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            op_id,
        );
        if let Some(slab) = self.nvme_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, buf_index, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(ud.raw())
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an NVMe flush command.
    ///
    /// The command completes to `key`, which
    /// [`nvme_flush`](crate::nvme_flush)'s future holds.
    pub fn nvme_flush(
        &mut self,
        device: crate::nvme::NvmeDevice,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let (fd_index, nsid) = self.validate_nvme_device(device)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab.allocate(device.index, key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "NVMe command slab exhausted")
        })?;

        let cmd = crate::nvme::NvmeUringCmd::flush(nsid);
        let op_id = self.disk_op_id(DiskIoKind::Nvme, slab_idx);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            op_id,
        );
        if let Some(slab) = self.nvme_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, None, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(())
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Close an NVMe device. The handle goes stale at once. The device's
    /// fixed-file slot is closed with `IORING_OP_CLOSE` once no command on it
    /// is in flight (at once, or by the last completion), and the table slot
    /// is free when that close completes.
    pub fn close_nvme_device(&mut self, device: crate::nvme::NvmeDevice) -> io::Result<()> {
        let (fd_index, _nsid) = self.validate_nvme_device(device)?;

        let Some(dev) = self
            .nvme_devices
            .as_mut()
            .and_then(|devices| devices.get_mut(device.index))
        else {
            return Ok(());
        };
        dev.closing = true;
        if dev.in_flight == 0 {
            self.ring.submit_fixed_close(
                fd_index,
                crate::completion::UserData::encode(
                    crate::completion::OpTag::FileClose,
                    device.index as u32,
                    crate::completion::FILE_CLOSE_NVME,
                ),
            );
        }
        Ok(())
    }

    /// The logical block size of `device`'s namespace, in bytes.
    pub(crate) fn nvme_lba_size(&self, device: crate::nvme::NvmeDevice) -> io::Result<u32> {
        self.validate_nvme_device(device)?;
        let dev = self
            .nvme_devices
            .as_ref()
            .and_then(|devices| devices.get(device.index))
            .ok_or_else(|| io::Error::other("invalid NVMe device handle"))?;
        dev.lba_size.clone().map_err(|(kind, message)| {
            io::Error::new(
                kind,
                format!("NVMe Identify Namespace failed at open: {message}"),
            )
        })
    }

    /// Validate an NVMe device handle and return (fd_index, nsid).
    fn validate_nvme_device(&self, device: crate::nvme::NvmeDevice) -> io::Result<(u32, u32)> {
        let devices = self
            .nvme_devices
            .as_ref()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let dev = devices
            .get(device.index)
            .ok_or_else(|| io::Error::other("invalid NVMe device handle"))?;
        if dev.closing || dev.generation != device.generation {
            return Err(io::Error::other("stale NVMe device handle"));
        }
        Ok((dev.fd_index, dev.nsid))
    }

    // ── fs and direct I/O files ───────────────────────────────────────────
    //
    // fs files and direct I/O files run the same code, each kind with its own
    // file table, command slab and fixed-file range (`FileKind`).

    fn file_table(&self, kind: FileKind) -> Option<&crate::fs::FsFileTable> {
        match kind {
            FileKind::Fs => self.fs_files.as_ref(),
            FileKind::DirectIo => self.direct_io_files.as_ref(),
        }
    }

    fn file_table_mut(&mut self, kind: FileKind) -> Option<&mut crate::fs::FsFileTable> {
        match kind {
            FileKind::Fs => self.fs_files.as_mut(),
            FileKind::DirectIo => self.direct_io_files.as_mut(),
        }
    }

    fn file_cmd_slab_mut(&mut self, kind: FileKind) -> Option<&mut crate::fs::FsCmdSlab> {
        match kind {
            FileKind::Fs => self.fs_cmd_slab.as_mut(),
            FileKind::DirectIo => self.direct_io_cmd_slab.as_mut(),
        }
    }

    fn file_fd_base(&self, kind: FileKind) -> u32 {
        match kind {
            FileKind::Fs => self.fs_fd_base,
            FileKind::DirectIo => self.direct_io_fd_base,
        }
    }

    /// Take a command slot for `op` on file slot `file_index`, completing to
    /// `key`, and record the SQE's user_data in it. Returns
    /// `(slab_idx, user_data)`.
    fn file_command(
        &mut self,
        kind: FileKind,
        file_index: u16,
        op: crate::fs::FsOp,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, crate::completion::UserData)> {
        let slab = self
            .file_cmd_slab_mut(kind)
            .ok_or_else(|| kind.not_configured())?;
        let slab_idx = slab
            .allocate(file_index, op, key)
            .ok_or_else(|| kind.slab_exhausted())?;
        let op_id = self.disk_op_id(kind.disk_io_kind(), slab_idx);
        let ud = crate::completion::UserData::encode(kind.op_tag(), file_index as u32, op_id);
        if let Some(slab) = self.file_cmd_slab_mut(kind) {
            slab.set_user_data(slab_idx, ud.raw());
        }
        Ok((slab_idx, ud))
    }

    /// Count a pushed read, write or fsync against its file, or release its
    /// command slot if the push failed.
    fn file_pushed(
        &mut self,
        kind: FileKind,
        file_index: u16,
        slab_idx: u16,
        pushed: io::Result<()>,
    ) -> io::Result<()> {
        match pushed {
            Ok(()) => {
                if let Some(f) = self
                    .file_table_mut(kind)
                    .and_then(|files| files.get_mut(file_index))
                {
                    f.in_flight += 1;
                }
                Ok(())
            }
            Err(e) => {
                if let Some(slab) = self.file_cmd_slab_mut(kind) {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Open `path` into a slot of `kind`'s table with an `OpenAt` that
    /// installs the file directly in the fixed file table.
    ///
    /// Returns `(file_index, generation)`; the open completes to `key`.
    fn file_open(
        &mut self,
        kind: FileKind,
        path: &std::path::Path,
        flags: i32,
        mode: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        let fd_base = self.file_fd_base(kind);
        let files = self
            .file_table_mut(kind)
            .ok_or_else(|| kind.not_configured())?;
        // Convert the path before allocating, so a bad path holds no slot.
        let c_path = crate::fs::path_to_cstring(path)?;
        let file_index = files.allocate().ok_or_else(|| kind.table_full())?;
        let generation = files.get(file_index).map(|f| f.generation).unwrap_or(0);
        let fd_index = fd_base + file_index as u32;
        if let Some(f) = files.get_mut(file_index) {
            f.fd_index = fd_index;
        }

        let (slab_idx, ud) = match self.file_command(kind, file_index, crate::fs::FsOp::Open, key) {
            Ok(command) => command,
            Err(e) => {
                if let Some(files) = self.file_table_mut(kind) {
                    files.release(file_index);
                }
                return Err(e);
            }
        };
        // The slab entry owns the path until the completion.
        let path_ptr = match self
            .file_cmd_slab_mut(kind)
            .and_then(|slab| slab.get_mut(slab_idx))
        {
            Some(entry) => entry.path.insert(c_path).as_ptr(),
            None => unreachable!("command slot {slab_idx} was allocated above"),
        };

        match unsafe {
            self.ring
                .submit_openat(fd_index, path_ptr, flags, mode, ud.raw())
        } {
            Ok(()) => Ok((file_index, generation)),
            Err(e) => {
                if let Some(slab) = self.file_cmd_slab_mut(kind) {
                    slab.release(slab_idx);
                }
                if let Some(files) = self.file_table_mut(kind) {
                    files.release(file_index);
                }
                Err(e)
            }
        }
    }

    /// The registered buffer a disk operation's memory is in: `None` for
    /// [`RegionId::UNREGISTERED`](crate::buffer::fixed::RegionId::UNREGISTERED),
    /// otherwise the region's index once `ptr..ptr + len` is checked to lie
    /// inside it. A range outside the region it names is refused with
    /// `InvalidInput`, before a command slot is taken.
    fn fixed_buf_index(
        &self,
        region: crate::buffer::fixed::RegionId,
        ptr: *const u8,
        len: u32,
    ) -> io::Result<Option<u16>> {
        if region == crate::buffer::fixed::RegionId::UNREGISTERED {
            return Ok(None);
        }
        self.fixed_buffers
            .validate_region_ptr(region, ptr, len)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(Some(region.0))
    }

    /// Submit a read that completes to `key`. Returns its user_data, which a
    /// dropped future cancels.
    ///
    /// # Safety
    /// `buf` must point to valid, writable memory of at least `len` bytes
    /// that remains valid until the completion fires.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn file_read(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        offset: u64,
        buf: *mut u8,
        len: u32,
        region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let fd_index = self.validate_file(kind, index, generation)?;
        let buf_index = self.fixed_buf_index(region, buf, len)?;
        let (slab_idx, ud) = self.file_command(kind, index, crate::fs::FsOp::Read, key)?;
        let pushed = unsafe {
            self.ring
                .submit_direct_read(fd_index, buf, len, offset, buf_index, ud)
        };
        self.file_pushed(kind, index, slab_idx, pushed)?;
        Ok(ud.raw())
    }

    /// Submit a write that completes to `key`. Returns its user_data, which a
    /// dropped future cancels.
    ///
    /// # Safety
    /// `buf` must point to valid, readable memory of at least `len` bytes
    /// that remains valid until the completion fires.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn file_write(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        offset: u64,
        buf: *const u8,
        len: u32,
        region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let fd_index = self.validate_file(kind, index, generation)?;
        let buf_index = self.fixed_buf_index(region, buf, len)?;
        let (slab_idx, ud) = self.file_command(kind, index, crate::fs::FsOp::Write, key)?;
        let pushed = unsafe {
            self.ring
                .submit_direct_write(fd_index, buf, len, offset, buf_index, ud)
        };
        self.file_pushed(kind, index, slab_idx, pushed)?;
        self.write_orders.begin_write(
            crate::disk_order::OrderKey {
                kind,
                index,
                generation,
            },
            key,
        );
        Ok(ud.raw())
    }

    /// Submit an fsync that completes to `key`.
    pub(crate) fn file_fsync(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let fd_index = self.validate_file(kind, index, generation)?;
        let (slab_idx, ud) = self.file_command(kind, index, crate::fs::FsOp::Fsync, key)?;
        // Held until the writes submitted before it on the file complete
        // (#905); counted in flight either way, so a close waits for it.
        let order = crate::disk_order::OrderKey {
            kind,
            index,
            generation,
        };
        let pushed = match self.write_orders.sync(order, (fd_index, ud.raw())) {
            Some(_) => self.ring.submit_direct_fsync(fd_index, ud),
            None => Ok(()),
        };
        self.file_pushed(kind, index, slab_idx, pushed)
    }

    /// Close a file.
    ///
    /// The handle goes stale at once. The file's fixed-file slot is closed
    /// with `IORING_OP_CLOSE` once no read, write or fsync on it is in flight:
    /// at once, or by the last completion, because an operation pushed earlier
    /// in the same task poll may not be submitted until the loop flushes, and
    /// the kernel resolves its fixed file then (#859). The table slot is free
    /// when the close completes (`AsyncEventLoop::handle_file_close`), so no
    /// open installs into the slot before the close has run.
    pub(crate) fn file_close(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
    ) -> io::Result<()> {
        let fd_index = self.validate_file(kind, index, generation)?;

        let Some(f) = self
            .file_table_mut(kind)
            .and_then(|files| files.get_mut(index))
        else {
            return Ok(());
        };
        f.closing = true;
        if f.in_flight == 0 {
            self.ring.submit_fixed_close(
                fd_index,
                crate::completion::UserData::encode(
                    crate::completion::OpTag::FileClose,
                    index as u32,
                    kind.file_close_payload(),
                ),
            );
        }
        Ok(())
    }

    /// Validate a file handle and return its fixed-file index.
    fn validate_file(&self, kind: FileKind, index: u16, generation: u32) -> io::Result<u32> {
        let files = self.file_table(kind).ok_or_else(|| kind.not_configured())?;
        let f = files.get(index).ok_or_else(|| kind.invalid_handle())?;
        if f.closing || f.generation != generation {
            return Err(kind.stale_handle());
        }
        Ok(f.fd_index)
    }

    /// Open `path` for direct I/O: `O_RDWR | O_DIRECT` and the flags of
    /// `options`.
    ///
    /// Returns `(file_index, generation)`; the open completes to `key`.
    pub(crate) fn direct_io_open(
        &mut self,
        path: &std::path::Path,
        options: crate::direct_io::DirectIoOpenOptions,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        let flags = libc::O_RDWR | libc::O_DIRECT | options.extra_flags();
        self.file_open(FileKind::DirectIo, path, flags, 0, key)
    }

    // ── Filesystem I/O methods ─────────────────────────────────────────────

    /// Open a file asynchronously via io_uring.
    ///
    /// Returns `(file_index, generation)`; the open completes to `key`.
    pub(crate) fn fs_open(
        &mut self,
        path: &std::path::Path,
        flags: crate::fs::OpenFlags,
        mode: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        self.file_open(FileKind::Fs, path, flags.0, mode, key)
    }

    /// Submit a filesystem read; see [`file_read`](Self::file_read).
    ///
    /// # Safety
    /// As for [`file_read`](Self::file_read).
    #[cfg(test)]
    pub(crate) unsafe fn fs_read(
        &mut self,
        file: crate::fs::File,
        offset: u64,
        buf: *mut u8,
        len: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let (index, generation) = (file.index, file.generation);
        unsafe {
            self.file_read(
                FileKind::Fs,
                index,
                generation,
                offset,
                buf,
                len,
                crate::buffer::fixed::RegionId::UNREGISTERED,
                key,
            )
        }
    }

    /// Submit a filesystem write; see [`file_write`](Self::file_write).
    ///
    /// # Safety
    /// As for [`file_write`](Self::file_write).
    #[cfg(test)]
    pub(crate) unsafe fn fs_write(
        &mut self,
        file: crate::fs::File,
        offset: u64,
        buf: *const u8,
        len: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let (index, generation) = (file.index, file.generation);
        unsafe {
            self.file_write(
                FileKind::Fs,
                index,
                generation,
                offset,
                buf,
                len,
                crate::buffer::fixed::RegionId::UNREGISTERED,
                key,
            )
        }
    }

    /// Submit an fsync for a filesystem file.
    #[cfg(test)]
    pub(crate) fn fs_fsync(
        &mut self,
        file: crate::fs::File,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        self.file_fsync(FileKind::Fs, file.index, file.generation, key)
    }

    /// Close a filesystem file; see [`file_close`](Self::file_close).
    #[cfg(test)]
    pub(crate) fn fs_close(&mut self, file: crate::fs::File) -> io::Result<()> {
        self.file_close(FileKind::Fs, file.index, file.generation)
    }

    /// Submit a statx via io_uring. With `nofollow`, a final symbolic link in
    /// `path` is not followed.
    ///
    /// The stat completes to `key`.
    pub(crate) fn fs_stat(
        &mut self,
        path: &std::path::Path,
        nofollow: bool,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;

        let slab = self
            .fs_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("filesystem I/O not configured"))?;
        let slab_idx = slab
            .allocate(0, crate::fs::FsOp::Statx, key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "filesystem command slab exhausted",
                )
            })?;

        // The kernel writes into the slab entry's statx buffer; the slab
        // never moves an entry, so the pointer stays valid until the CQE.
        let statx_ptr = match slab.get_mut(slab_idx) {
            Some(entry) => {
                entry.path = Some(c_path);
                &mut entry.statx_buf as *mut libc::statx
            }
            None => unreachable!("the slab entry was just allocated"),
        };

        let path_ptr = self
            .fs_cmd_slab
            .as_ref()
            .unwrap()
            .get(slab_idx)
            .unwrap()
            .path
            .as_ref()
            .unwrap()
            .as_ptr();

        let op_id = self.disk_op_id(DiskIoKind::Fs, slab_idx);
        let ud = crate::completion::UserData::encode(crate::completion::OpTag::Fs, 0, op_id);
        if let Some(slab) = self.fs_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe {
            self.ring
                .submit_statx(path_ptr, statx_ptr, nofollow, ud.raw())
        } {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(slab) = self.fs_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit a renameat via io_uring.
    pub(crate) fn fs_rename(
        &mut self,
        from: &std::path::Path,
        to: &std::path::Path,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_from = crate::fs::path_to_cstring(from)?;
        let c_to = crate::fs::path_to_cstring(to)?;

        let slab = self
            .fs_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("filesystem I/O not configured"))?;
        let slab_idx = slab
            .allocate(0, crate::fs::FsOp::Rename, key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "filesystem command slab exhausted",
                )
            })?;

        if let Some(entry) = slab.get_mut(slab_idx) {
            entry.path = Some(c_from);
            entry.path2 = Some(c_to);
        }

        let (old_ptr, new_ptr) = {
            let entry = self.fs_cmd_slab.as_ref().unwrap().get(slab_idx).unwrap();
            (
                entry.path.as_ref().unwrap().as_ptr(),
                entry.path2.as_ref().unwrap().as_ptr(),
            )
        };

        let op_id = self.disk_op_id(DiskIoKind::Fs, slab_idx);
        let ud = crate::completion::UserData::encode(crate::completion::OpTag::Fs, 0, op_id);
        if let Some(slab) = self.fs_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_renameat(old_ptr, new_ptr, ud.raw()) } {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(slab) = self.fs_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an unlinkat via io_uring.
    pub(crate) fn fs_unlink(
        &mut self,
        path: &std::path::Path,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;

        let slab = self
            .fs_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("filesystem I/O not configured"))?;
        let slab_idx = slab
            .allocate(0, crate::fs::FsOp::Unlink, key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "filesystem command slab exhausted",
                )
            })?;

        if let Some(entry) = slab.get_mut(slab_idx) {
            entry.path = Some(c_path);
        }

        let path_ptr = self
            .fs_cmd_slab
            .as_ref()
            .unwrap()
            .get(slab_idx)
            .unwrap()
            .path
            .as_ref()
            .unwrap()
            .as_ptr();

        let op_id = self.disk_op_id(DiskIoKind::Fs, slab_idx);
        let ud = crate::completion::UserData::encode(crate::completion::OpTag::Fs, 0, op_id);
        if let Some(slab) = self.fs_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_unlinkat(path_ptr, 0, ud.raw()) } {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(slab) = self.fs_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit a mkdirat via io_uring.
    pub(crate) fn fs_mkdir(
        &mut self,
        path: &std::path::Path,
        mode: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;

        let slab = self
            .fs_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("filesystem I/O not configured"))?;
        let slab_idx = slab
            .allocate(0, crate::fs::FsOp::Mkdir, key)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "filesystem command slab exhausted",
                )
            })?;

        if let Some(entry) = slab.get_mut(slab_idx) {
            entry.path = Some(c_path);
        }

        let path_ptr = self
            .fs_cmd_slab
            .as_ref()
            .unwrap()
            .get(slab_idx)
            .unwrap()
            .path
            .as_ref()
            .unwrap()
            .as_ptr();

        let op_id = self.disk_op_id(DiskIoKind::Fs, slab_idx);
        let ud = crate::completion::UserData::encode(crate::completion::OpTag::Fs, 0, op_id);
        if let Some(slab) = self.fs_cmd_slab.as_mut() {
            slab.set_user_data(slab_idx, ud.raw());
        }

        match unsafe { self.ring.submit_mkdirat(path_ptr, mode, ud.raw()) } {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(slab) = self.fs_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Arm a connect timeout on a connect that has already been submitted. Does
    /// not depend on the transport.
    ///
    /// The connect builders call this after the base connect (#528).
    ///
    /// The deadline goes into the worker's connect deadline heap, which bounds
    /// the worker's wait; nothing is submitted. A deadline past what `Instant`
    /// can hold is never reached and is not armed.
    #[cfg(has_io_uring)]
    pub(crate) fn arm_connect_timeout(&mut self, conn_index: u32, timeout_ms: u64) {
        let Some(deadline) =
            std::time::Instant::now().checked_add(std::time::Duration::from_millis(timeout_ms))
        else {
            return;
        };
        let Some(cs) = self.connections.get_mut(conn_index) else {
            return;
        };
        cs.connect_deadline = Some(deadline);
        let generation = cs.generation;
        self.connect_deadlines
            .arm(conn_index, generation, deadline, &*self.connections);
    }
}

// ── mio DriverCtx (minimal stub) ───────────────────────────────────────

#[cfg(not(has_io_uring))]
/// A short-lived borrow of driver fields, built by `Driver::make_ctx`.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
pub(crate) struct DriverCtx<'a> {
    pub(crate) connections: &'a mut crate::connection::ConnectionTable,
    pub(crate) send_copy_pool: &'a mut SendCopyPool,
    pub(crate) tls_table: *mut crate::tls::TlsTable,
    pub(crate) shutdown_requested: &'a mut bool,
    pub(crate) connect_addrs: &'a mut Vec<libc::sockaddr_storage>,
    pub(crate) tcp_nodelay: bool,
    pub(crate) send_queues: &'a mut Vec<ConnSendState>,
    /// Per-connection pending send buffers (mio backend).
    /// DriverCtx::send() pushes data here; the event loop flushes on writable.
    pub(crate) pending_sends:
        &'a mut Vec<std::collections::VecDeque<crate::backend::mio::driver::PendingSend>>,
    /// Per-connection mio TcpStream storage (for connect / shutdown_write).
    pub(crate) tcp_streams: &'a mut Vec<Option<mio::net::TcpStream>>,
    /// Mio poll instance (for registering new connections).
    pub(crate) poll: &'a mut mio::Poll,
    pub(crate) pending_closes: &'a mut Vec<u32>,
    /// Per-connection writable flag.
    pub(crate) writable: &'a mut Vec<bool>,
    /// Worker-wide bounded-send results, keyed by the id the submitting
    /// future holds (see `Driver::settled_sends`). `send_bounded`
    /// pushes here only when it completes an operation without queueing it;
    /// the normal completion comes from `Driver::flush_sends`.
    pub(crate) settled_sends: &'a mut std::collections::VecDeque<(
        crate::runtime::send_completion::SendId,
        io::Result<u32>,
    )>,
    /// Mirror of `Driver::capacity_released`: set when a copy-pool permit
    /// goes back to the pool so the event loop wakes the send-capacity head
    /// once per iteration.
    pub(crate) capacity_released: &'a mut bool,
    /// Per-connection connect timeout deadlines.
    pub(crate) connect_deadlines: &'a mut Vec<Option<std::time::Instant>>,
    pub(crate) sends_dirty: &'a mut Vec<u32>,
    pub(crate) sends_dirty_flag: &'a mut Vec<bool>,
    pub(crate) connect_pending: &'a mut u32,
    /// This worker's disk I/O pool.
    pub(crate) disk_io_pool: &'a Option<std::sync::Arc<crate::disk_io_pool::DiskIoPool>>,
    /// Per-worker disk I/O response send channel (included in each request).
    pub(crate) disk_io_tx:
        &'a Option<crossbeam_channel::Sender<crate::disk_io_pool::DiskIoResponse>>,
    /// Wake handle for this worker (used to wake after disk I/O completion).
    pub(crate) wake_handle: crate::wakeup::WakeFd,
    /// See `Driver::disk_io_wake_pending`.
    pub(crate) disk_io_wake_pending: &'a std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Keys of pool operations not yet drained; see `Driver::disk_io_in_flight`.
    pub(crate) disk_io_in_flight: &'a mut std::collections::HashMap<
        crate::runtime::DiskIoKey,
        crate::disk_io_pool::PoolSubsystem,
    >,
    /// See `Driver::disk_io_counts`.
    pub(crate) disk_io_counts: &'a mut [u16; 2],
    /// See `Driver::disk_io_limits`.
    pub(crate) disk_io_limits: [Option<u16>; 2],
    /// See `Driver::disk_io_borrowing`.
    pub(crate) disk_io_borrowing: &'a mut std::collections::HashSet<crate::runtime::DiskIoKey>,
    /// See `Driver::write_orders`.
    pub(crate) write_orders:
        &'a mut crate::disk_order::WriteOrders<crate::disk_io_pool::HeldRequest>,
    /// Filesystem file table.
    pub(crate) fs_files: &'a mut Option<crate::fs::FsFileTable>,
    /// Filesystem fds, indexed by file slot.
    pub(crate) fs_fds: &'a mut Vec<Option<std::sync::Arc<std::os::fd::OwnedFd>>>,
    /// Pending fs_open requests: maps disk-I/O key → file_index.
    pub(crate) pending_fs_opens:
        &'a mut std::collections::HashMap<crate::runtime::DiskIoKey, (FileKind, u16)>,
    /// Direct I/O file table.
    pub(crate) direct_io_files: &'a mut Option<crate::fs::FsFileTable>,
    /// Direct I/O fds, indexed by file slot.
    pub(crate) direct_io_fds: &'a mut Vec<Option<std::sync::Arc<std::os::fd::OwnedFd>>>,
}

#[cfg(not(has_io_uring))]
impl<'a> DriverCtx<'a> {
    /// Request shutdown of this worker's event loop.
    pub fn request_shutdown(&mut self) {
        *self.shutdown_requested = true;
    }

    /// Send data on a connection (copy into pending send buffer).
    ///
    /// The data is buffered in the per-connection send queue. The event loop
    /// flushes it when the socket becomes writable.
    ///
    /// On a TLS connection the data is encrypted into a `Vec` and queued the
    /// same way; nothing is written in this call. Every public send attaches
    /// an id (`send_awaited`), so only tests call this.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn send(&mut self, conn: ConnId, data: &[u8]) -> io::Result<()> {
        self.send_inner(conn, data, None)
    }

    /// [`send`](Self::send), with `id` carried on the queued entry: it
    /// settles with `data.len()` once the entry's last byte reaches the
    /// socket. On `Err` nothing was queued and `id` is the caller's to
    /// cancel.
    pub(crate) fn send_awaited(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: crate::runtime::send_completion::SendId,
    ) -> io::Result<()> {
        self.send_inner(conn, data, Some(id))
    }

    fn send_inner(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: Option<crate::runtime::send_completion::SendId>,
    ) -> io::Result<()> {
        let conn_state = self
            .connections
            .get(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }
        // As the io_uring `send`. Of the two flags `closing_refusal` reads,
        // mio sets only `aborted`.
        if let Some(e) = self.send_queues[conn.index as usize].closing_refusal() {
            return Err(e);
        }

        // TLS path: encrypt and push ciphertext into the pending send queue.
        let tls = !self.tls_table.is_null() && unsafe { (*self.tls_table).has(conn.index) };
        let bytes = if tls {
            let tls_table = unsafe { &mut *self.tls_table };
            match crate::tls::encrypt_for_send_mio(tls_table, conn.index, data) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // The record layer is finished: a record rustls sealed
                    // before the failure spent a sequence number with no
                    // ciphertext queued for it, so the next record would be
                    // `bad_record_mac` at the peer, and TLS 1.2 cannot
                    // rekey. Same rule as io_uring's `encrypt_tls_send`.
                    self.close(conn);
                    return Err(e);
                }
            }
        } else {
            data.to_vec()
        };
        let idx = conn.index as usize;
        let entry = match id {
            // Nothing to write, so nothing will complete it: settle now.
            Some(id) if bytes.is_empty() => {
                self.settled_sends.push_back((id, Ok(data.len() as u32)));
                return Ok(());
            }
            Some(id) => {
                crate::backend::mio::driver::PendingSend::awaited(bytes, id, data.len() as u32)
            }
            None if tls && bytes.is_empty() => return Ok(()),
            None => crate::backend::mio::driver::PendingSend::plain(bytes),
        };
        self.pending_sends[idx].push_back(entry);
        self.mark_send_dirty(idx);
        Ok(())
    }

    /// Queue a bounded (`send_backpressured`) send, admitting it against the
    /// copy pool first.
    ///
    /// mio never copies into pool memory — the bytes go through a `Vec` like
    /// every other mio send — so here the pool is purely the *admission
    /// budget*: the call reserves `ceil(len / slot_size)` slots and holds
    /// that reservation unfilled as the entry's permit, so the same
    /// `Config::send_pool` knob throttles bounded sends identically on both
    /// backends (`docs/mio-bounded-send-design.md`, "What a bounded send is
    /// on mio", records the decision and the alternatives).
    ///
    /// Nothing is written synchronously: admission *is* the reservation.
    /// On `Ok` the operation is queued and exactly one completion for `id`
    /// will reach `Driver::settled_sends` — `Ok(len)` when its
    /// last byte reaches the socket (`Driver::flush_sends`), `Err` if it is
    /// discarded first (`Driver::clear_pending_sends`). On `Err` nothing was
    /// reserved or queued and no completion for `id` will ever be produced,
    /// so the caller owns the failure.
    ///
    /// Called by `Admission::poll_waiting` once the
    /// send-capacity FIFO says it is this id's turn.
    pub(crate) fn send_bounded(
        &mut self,
        conn: ConnId,
        data: &[u8],
        id: crate::runtime::send_completion::SendId,
    ) -> io::Result<()> {
        let conn_state = self
            .connections
            .get(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }
        // Same refusal, kind and message as the io_uring `send`. On mio only
        // `abort` sets a flag it reads: `close_submitted` is set by the
        // io_uring close path alone (a mio close defers teardown until
        // `pending_sends` drains, and `clear_pending_sends` fails whatever is
        // still queued).
        if let Some(e) = self.send_queues[conn.index as usize].closing_refusal() {
            return Err(e);
        }

        let idx = conn.index as usize;
        let slot_size = self.send_copy_pool.slot_size() as usize;

        // A TLS connection is admitted against the *ciphertext* bound, sized
        // before rustls mutates: past the first record a shortfall would
        // close the connection instead of applying backpressure. Plain sends
        // keep the plaintext sizing they have always had.
        let tls_bound = if self.tls_table.is_null() {
            None
        } else {
            let tls_table = unsafe { &*self.tls_table };
            tls_table.ciphertext_capacity(conn.index, data.len())
        };
        // The same number `send_backpressured`'s future enqueued, by
        // construction rather than by agreement.
        let needed =
            bounded_send_slots(self.send_copy_pool, self.tls_table, conn.index, data.len())?;
        let mut permit = match self.send_copy_pool.reserve_slots(needed) {
            Ok(r) => r,
            Err(crate::buffer::send_copy::ReserveError::Exhausted) => {
                return Err(io::Error::other("send copy pool exhausted"));
            }
            Err(crate::buffer::send_copy::ReserveError::TooLarge { needed, capacity }) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "send of {} bytes needs {needed} send-pool slots but the pool has \
                         {capacity} (raise Config::send_pool)",
                        data.len()
                    ),
                ));
            }
        };

        // TLS: encrypt first, then carry the id and permit on the ciphertext
        // entry. The permit was sized by the conservative bound above; once
        // the records exist the true cost is known, so the surplus goes back
        // to the pool rather than sitting on a queued entry until it flushes.
        if let Some(bound) = tls_bound {
            let tls_table = unsafe { &mut *self.tls_table };
            let ciphertext = match crate::tls::encrypt_for_send_mio(tls_table, conn.index, data) {
                Ok(c) => c,
                Err(e) => {
                    // rustls has already advanced; nothing is queued, so
                    // give the permit back and let the caller see the
                    // error (no completion for `id` is produced). The
                    // connection is closed for the reason `send_inner`
                    // gives: a sealed record's sequence number is spent.
                    self.release_permit(permit);
                    self.close(conn);
                    return Err(e);
                }
            };
            // The tripwire. Two hazards are modelled rather than measured —
            // unbuffered record waste, and rustls draining a queued alert or
            // key_update into the same destination. A bound checked only by
            // the tests written for it drifts; if one is ever beaten, a debug
            // build says so here rather than closing a connection in
            // production.
            debug_assert!(
                ciphertext.len() <= bound.bytes(),
                "TLS ciphertext bound beaten: bounded {} bytes, rustls produced {}",
                bound.bytes(),
                ciphertext.len(),
            );
            if ciphertext.is_empty() {
                // Nothing to queue and therefore nothing that could ever
                // complete the id: settle it here.
                self.release_permit(permit);
                self.settled_sends.push_back((id, Ok(data.len() as u32)));
                return Ok(());
            }
            // `.min(needed)` cannot normally bind — the tripwire above fires
            // first if it would — but in a release build it keeps a beaten
            // bound from turning into a grow, which `shrink_reservation`
            // refuses. Holding the larger permit is the safe direction.
            let keep = ciphertext.len().div_ceil(slot_size).min(needed);
            if keep < permit.remaining() {
                self.send_copy_pool.shrink_reservation(&mut permit, keep);
                // Slots came back, so the send-capacity head may now fit.
                *self.capacity_released = true;
            }
            self.pending_sends[idx].push_back(crate::backend::mio::driver::PendingSend::bounded(
                ciphertext,
                id,
                data.len() as u32,
                permit,
            ));
            self.mark_send_dirty(idx);
            return Ok(());
        }

        if data.is_empty() {
            // A zero-length entry would produce no iovec and be swept by
            // `flush_sends`'s empty-iovec bail-out as an error. Complete it
            // here instead.
            self.release_permit(permit);
            self.settled_sends.push_back((id, Ok(0)));
            return Ok(());
        }

        self.pending_sends[idx].push_back(crate::backend::mio::driver::PendingSend::bounded(
            data.to_vec(),
            id,
            data.len() as u32,
            permit,
        ));
        self.mark_send_dirty(idx);
        Ok(())
    }

    /// Return an unfilled admission permit to the copy pool and record that
    /// capacity came back, so the event loop wakes the send-capacity head.
    fn release_permit(&mut self, permit: crate::buffer::send_copy::SlotReservation) {
        self.send_copy_pool.release_reservation(permit);
        *self.capacity_released = true;
    }

    /// Discard every queued send for `idx`, failing each bounded entry's id
    /// with `err()` and returning its permit — the `DriverCtx` form of
    /// [`crate::backend::mio::driver::Driver::clear_pending_sends`]. A bare
    /// `pending_sends[idx].clear()` would drop live `SlotReservation`s.
    fn clear_pending_sends(&mut self, idx: usize, err: impl Fn() -> io::Error) {
        crate::backend::mio::driver::clear_pending_sends_into(
            &mut self.pending_sends[idx],
            self.send_copy_pool,
            self.settled_sends,
            self.capacity_released,
            err,
        );
    }

    /// Record `idx` in the dirty-sends list so the event loop's flush pass
    /// visits it. Invariant: non-empty `pending_sends[idx]` ⇒ flag set.
    fn mark_send_dirty(&mut self, idx: usize) {
        if !self.sends_dirty_flag[idx] {
            self.sends_dirty_flag[idx] = true;
            self.sends_dirty.push(idx as u32);
        }
    }

    /// Close a connection. Marks it `Closing` and defers teardown (socket,
    /// buffers, executor cleanup, slot release) to the event loop's
    /// drain_pending_closes — releasing the slot here left the executor's
    /// parked future and waiter flags alive into the slot's next occupant.
    pub fn close(&mut self, conn: ConnId) {
        if let Some(cs) = self.connections.get_mut(conn.index) {
            if cs.generation != conn.generation {
                return;
            }
            if cs.close_requested() {
                return;
            }
            cs.lifecycle = crate::connection::Lifecycle::Closing;
        } else {
            return;
        }
        self.send_queues[conn.index as usize].close_pending = true;
        self.pending_closes.push(conn.index);
    }

    /// Get TLS session info for a connection.
    pub fn tls_info(&self, conn: ConnId) -> Option<crate::tls::TlsInfo> {
        let cs = self.connections.get(conn.index)?;
        if cs.generation != conn.generation {
            return None;
        }
        if self.tls_table.is_null() {
            return None;
        }
        let tls_table = unsafe { &*self.tls_table };
        tls_table.get_info(conn.index)
    }

    /// Shut down the write half of a connection.
    ///
    /// Issues the half-close now if nothing is queued; otherwise records
    /// `WriteHalf::ShutdownPending` and `flush_sends` issues it once the
    /// queue drains.
    pub fn shutdown_write(&mut self, conn: ConnId) {
        let idx = conn.index as usize;
        let Some(cs) = self.connections.get_mut(conn.index) else {
            return;
        };
        if cs.generation != conn.generation {
            return;
        }
        // Idempotent, and a requested close owns the socket from here on.
        if !matches!(cs.write, crate::connection::WriteHalf::Open) || cs.close_requested() {
            return;
        }
        if self.pending_sends[idx].is_empty() {
            cs.write = crate::connection::WriteHalf::Shutdown;
            if let Some(stream) = self.tcp_streams[idx].as_mut()
                && stream.shutdown(std::net::Shutdown::Write).is_err()
            {
                crate::metrics::CONNECTIONS.increment(crate::metrics::conn::SHUTDOWN_FAILED);
            }
        } else {
            // Defer the FIN until flush_sends drains the queue. Dirty the
            // queue so the flush pass visits it; the write that drains it
            // issues the shutdown.
            cs.write = crate::connection::WriteHalf::ShutdownPending;
            self.mark_send_dirty(idx);
        }
    }

    /// Start an outbound TCP connection. Returns its token immediately; the
    /// caller registers the waiter that takes the connection.
    pub(crate) fn start_connect(
        &mut self,
        addr: SocketAddr,
    ) -> Result<ConnId, crate::error::Error> {
        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or_else(|| crate::error::Error::Io(io::Error::other("connection table full")))?;

        let mut mio_stream = match mio::net::TcpStream::connect(addr) {
            Ok(s) => s,
            Err(e) => {
                self.connections.release(conn_index);
                return Err(crate::error::Error::Io(e));
            }
        };

        let token = mio::Token(conn_index as usize + 1);
        if let Err(e) = self.poll.registry().register(
            &mut mio_stream,
            token,
            crate::backend::mio::driver::STREAM_INTEREST,
        ) {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        let idx = conn_index as usize;
        self.tcp_streams[idx] = Some(mio_stream);
        self.writable[idx] = false;
        // Defensive, as at accept: a freshly allocated slot should have an
        // empty send queue, but anything left must go through the
        // permit-aware clear rather than being dropped.
        self.clear_pending_sends(idx, || {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection slot reused by a new connect",
            )
        });
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(crate::connection::PeerAddr::Tcp(addr));
        }

        let generation = self.connections.generation(conn_index);
        Ok(ConnId::new(conn_index, generation))
    }

    /// Unix domain socket connects are not implemented on mio.
    pub(crate) fn start_connect_unix(
        &mut self,
        _path: &std::path::Path,
    ) -> Result<ConnId, crate::error::Error> {
        Err(crate::error::Error::Io(io::Error::other(
            "mio connect_unix not yet implemented",
        )))
    }

    /// Arm a connect timeout on a connect that has already been submitted. Does
    /// not depend on the transport. Mirrors the io_uring method of the same
    /// name (#528).
    pub(crate) fn arm_connect_timeout(&mut self, conn_index: u32, timeout_ms: u64) {
        if self.connect_deadlines[conn_index as usize]
            .replace(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms))
            .is_none()
        {
            *self.connect_pending += 1;
        }
    }

    /// Start an outbound TLS connection. Returns its token immediately; the
    /// caller registers the waiter that takes the connection once both
    /// handshakes complete.
    pub(crate) fn start_connect_tls(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<ConnId, crate::error::Error> {
        if self.tls_table.is_null() {
            return Err(crate::error::Error::RingSetup(
                "TLS not configured".to_string(),
            ));
        }
        let tls_table = unsafe { &mut *self.tls_table };
        if !tls_table.has_client_config() {
            return Err(crate::error::Error::RingSetup(
                "TLS client config not set".to_string(),
            ));
        }

        // Perform the TCP connect first.
        let token = self.start_connect(addr)?;

        // Create TLS client state (buffers ClientHello internally). On
        // failure the already-established TCP connection must be torn down —
        // returning early here used to leak the slot and the registered
        // stream on every failed TLS connect attempt.
        let sni = match ringline_tls::pki_types::ServerName::try_from(server_name.to_owned()) {
            Ok(sni) => sni,
            Err(e) => {
                self.close(token);
                return Err(crate::error::Error::RingSetup(format!(
                    "invalid server name: {e}"
                )));
            }
        };
        if let Err(e) = tls_table.create_client(token.index, sni) {
            self.close(token);
            return Err(crate::error::Error::RingSetup(format!(
                "TLS client setup failed: {e}"
            )));
        }

        Ok(token)
    }

    /// Open an NVMe device (not supported on mio backend).
    pub fn open_nvme_device(
        &mut self,
        _path: &str,
        _nsid: u32,
    ) -> io::Result<crate::nvme::NvmeDevice> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    /// Close an NVMe device (not supported on mio backend).
    pub fn close_nvme_device(&mut self, _device: crate::nvme::NvmeDevice) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    /// NVMe read (not supported on mio backend).
    ///
    /// # Safety
    ///
    /// Mirrors the io_uring backend's contract (caller-supplied DMA address
    /// must be valid and outlive the operation); this stub always errors.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nvme_read(
        &mut self,
        _device: crate::nvme::NvmeDevice,
        _lba: u64,
        _num_blocks: u16,
        _buf_addr: u64,
        _buf_len: u32,
        _region: crate::buffer::fixed::RegionId,
        _key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    /// NVMe write (not supported on mio backend).
    ///
    /// # Safety
    ///
    /// Mirrors the io_uring backend's contract; this stub always errors.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn nvme_write(
        &mut self,
        _device: crate::nvme::NvmeDevice,
        _lba: u64,
        _num_blocks: u16,
        _buf_addr: u64,
        _buf_len: u32,
        _region: crate::buffer::fixed::RegionId,
        _key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    /// NVMe logical block size (not supported on mio backend).
    pub(crate) fn nvme_lba_size(&self, _device: crate::nvme::NvmeDevice) -> io::Result<u32> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    /// NVMe flush (not supported on mio backend).
    pub fn nvme_flush(
        &mut self,
        _device: crate::nvme::NvmeDevice,
        _key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "NVMe passthrough requires the io_uring backend",
        ))
    }

    // ── Disk-I/O pool ─────────────────────────────────────────────────

    /// Submit work to the disk I/O pool as the operation `key`.
    /// `borrows` is true when `work` reads or writes through a caller's
    /// buffer address, which worker exit must then wait for. Fails when
    /// `subsystem` is not configured, or already has its
    /// `max_commands_in_flight` operations submitted and not drained.
    fn submit_disk_io(
        &mut self,
        subsystem: crate::disk_io_pool::PoolSubsystem,
        work: Box<dyn FnOnce() -> crate::disk_io_pool::DiskIoResult + Send>,
        borrows: bool,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        self.submit_disk_io_ordered(subsystem, work, borrows, None, key)
    }

    /// [`submit_disk_io`](Self::submit_disk_io) for a write or an fsync on
    /// a file. A write is recorded in `write_orders`; an fsync is held there,
    /// not sent, until the writes submitted before it on the file complete
    /// (#905). A held fsync counts against the bound.
    fn submit_disk_io_ordered(
        &mut self,
        subsystem: crate::disk_io_pool::PoolSubsystem,
        work: Box<dyn FnOnce() -> crate::disk_io_pool::DiskIoResult + Send>,
        borrows: bool,
        order: Option<DiskOrder>,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        // An unconfigured subsystem fails first, with io_uring's error, even
        // when this worker has no pool. A missing pool with the subsystem
        // configured is unreachable through `ConfigBuilder`, which refuses it
        // on this backend.
        let limit =
            self.disk_io_limits[subsystem as usize].ok_or_else(|| subsystem.not_configured())?;
        let pool = self.disk_io_pool.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "disk I/O pool not configured")
        })?;
        let tx = self.disk_io_tx.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "disk I/O pool not configured")
        })?;
        if self.disk_io_counts[subsystem as usize] >= limit {
            return Err(subsystem.exhausted());
        }

        let to_send = match order {
            Some(DiskOrder::Sync(file)) => self.write_orders.sync(file, (key, work)),
            _ => Some((key, work)),
        };
        if let Some((key, work)) = to_send {
            crate::disk_io_pool::send_request(
                pool,
                tx,
                self.wake_handle,
                self.disk_io_wake_pending,
                key,
                work,
            )?;
        }
        self.disk_io_in_flight.insert(key, subsystem);
        self.disk_io_counts[subsystem as usize] += 1;
        if borrows {
            self.disk_io_borrowing.insert(key);
        }
        if let Some(DiskOrder::Write(file)) = order {
            self.write_orders.begin_write(file, key);
        }

        Ok(())
    }

    // ── fs and direct I/O files ───────────────────────────────────────
    //
    // fs files and direct I/O files run the same code, each kind with its own
    // file table, fd vector and pool bound (`FileKind`).

    fn file_table(&self, kind: FileKind) -> Option<&crate::fs::FsFileTable> {
        match kind {
            FileKind::Fs => self.fs_files.as_ref(),
            FileKind::DirectIo => self.direct_io_files.as_ref(),
        }
    }

    fn file_table_mut(&mut self, kind: FileKind) -> Option<&mut crate::fs::FsFileTable> {
        match kind {
            FileKind::Fs => self.fs_files.as_mut(),
            FileKind::DirectIo => self.direct_io_files.as_mut(),
        }
    }

    fn file_fds(&self, kind: FileKind) -> &[Option<std::sync::Arc<std::os::fd::OwnedFd>>] {
        match kind {
            FileKind::Fs => self.fs_fds,
            FileKind::DirectIo => self.direct_io_fds,
        }
    }

    fn file_fds_mut(
        &mut self,
        kind: FileKind,
    ) -> &mut [Option<std::sync::Arc<std::os::fd::OwnedFd>>] {
        match kind {
            FileKind::Fs => self.fs_fds,
            FileKind::DirectIo => self.direct_io_fds,
        }
    }

    /// Open `path` into a slot of `kind`'s table on the disk I/O pool. With
    /// `nocache` on macOS the pool also sets `F_NOCACHE` on the new fd.
    ///
    /// On completion the pool sends back the opened fd in
    /// `DiskIoResult::opened`; the event loop moves it into the kind's fd
    /// vector when it drains the response.
    ///
    /// Returns `(file_index, generation)`.
    fn file_open(
        &mut self,
        kind: FileKind,
        path: &std::path::Path,
        flags: i32,
        mode: u32,
        nocache: bool,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        let files = self
            .file_table_mut(kind)
            .ok_or_else(|| kind.not_configured())?;
        // Convert the path before allocating, so a bad path holds no slot.
        let c_path = crate::fs::path_to_cstring(path)?;
        let file_index = files.allocate().ok_or_else(|| kind.table_full())?;
        let generation = files.get(file_index).map(|f| f.generation).unwrap_or(0);

        #[cfg(not(target_os = "macos"))]
        let _ = nocache;
        let work = Box::new(move || {
            let fd = unsafe {
                libc::open(
                    c_path.as_ptr(),
                    flags | libc::O_CLOEXEC,
                    mode as libc::c_int,
                )
            };
            if fd < 0 {
                let errno = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                return crate::disk_io_pool::DiskIoResult {
                    result: -errno,
                    metadata: None,
                    opened: None,
                };
            }
            // macOS has no O_DIRECT; F_NOCACHE bypasses the page cache.
            #[cfg(target_os = "macos")]
            if nocache {
                unsafe {
                    libc::fcntl(fd, libc::F_NOCACHE, 1);
                }
            }
            // Return the fd as the result (positive value), and as an owned
            // fd so a result that reaches no worker closes it.
            crate::disk_io_pool::DiskIoResult {
                result: fd,
                metadata: None,
                // SAFETY: `open` returned a fresh descriptor nothing else owns.
                opened: Some(unsafe { std::os::fd::FromRawFd::from_raw_fd(fd) }),
            }
        });

        match self.submit_disk_io(kind.pool_subsystem(), work, false, key) {
            Ok(()) => {
                self.pending_fs_opens.insert(key, (kind, file_index));
                Ok((file_index, generation))
            }
            Err(e) => {
                if let Some(files) = self.file_table_mut(kind) {
                    files.release(file_index);
                }
                Err(e)
            }
        }
    }

    /// Submit a `pread` of `len` bytes at `offset` into `buf` on the pool.
    /// Nothing is cancelled on mio, so the returned cancel target is 0.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn file_read(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        offset: u64,
        buf: *mut u8,
        len: u32,
        _region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let fd = self.validate_file(kind, index, generation)?;
        let buf_addr = buf as usize;
        let work = Box::new(move || {
            let result = unsafe {
                libc::pread(
                    std::os::fd::AsRawFd::as_raw_fd(&*fd),
                    buf_addr as *mut libc::c_void,
                    len as usize,
                    offset as libc::off_t,
                )
            };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                result as i32
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        self.submit_disk_io(kind.pool_subsystem(), work, true, key)?;
        Ok(0)
    }

    /// Submit a `pwrite` of `len` bytes from `buf` at `offset` on the pool.
    /// Nothing is cancelled on mio, so the returned cancel target is 0.
    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn file_write(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        offset: u64,
        buf: *const u8,
        len: u32,
        _region: crate::buffer::fixed::RegionId,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let fd = self.validate_file(kind, index, generation)?;
        let buf_addr = buf as usize;
        let work = Box::new(move || {
            let result = unsafe {
                libc::pwrite(
                    std::os::fd::AsRawFd::as_raw_fd(&*fd),
                    buf_addr as *const libc::c_void,
                    len as usize,
                    offset as libc::off_t,
                )
            };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                result as i32
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        let order = DiskOrder::Write(crate::disk_order::OrderKey {
            kind,
            index,
            generation,
        });
        self.submit_disk_io_ordered(kind.pool_subsystem(), work, true, Some(order), key)?;
        Ok(0)
    }

    /// Submit an `fsync` on the pool, held until the writes submitted before
    /// it on the file complete (#905).
    pub(crate) fn file_fsync(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let fd = self.validate_file(kind, index, generation)?;
        let work = Box::new(move || {
            let result = unsafe { libc::fsync(std::os::fd::AsRawFd::as_raw_fd(&*fd)) };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                0
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        let order = DiskOrder::Sync(crate::disk_order::OrderKey {
            kind,
            index,
            generation,
        });
        self.submit_disk_io_ordered(kind.pool_subsystem(), work, false, Some(order), key)
    }

    /// Close a file and release its slot.
    ///
    /// The fd closes once the operations already queued on it have finished;
    /// the handle is invalid at once.
    pub(crate) fn file_close(
        &mut self,
        kind: FileKind,
        index: u16,
        generation: u32,
    ) -> io::Result<()> {
        self.validate_file(kind, index, generation)?;
        self.file_fds_mut(kind)[index as usize] = None;
        if let Some(files) = self.file_table_mut(kind) {
            files.release(index);
        }
        Ok(())
    }

    /// Validate a file handle and return a hold on its fd.
    fn validate_file(
        &self,
        kind: FileKind,
        index: u16,
        generation: u32,
    ) -> io::Result<std::sync::Arc<std::os::fd::OwnedFd>> {
        let files = self.file_table(kind).ok_or_else(|| kind.not_configured())?;
        let f = files.get(index).ok_or_else(|| kind.invalid_handle())?;
        if f.generation != generation {
            return Err(kind.stale_handle());
        }
        self.file_fds(kind)[index as usize]
            .clone()
            .ok_or_else(|| kind.fd_not_found())
    }

    /// Open `path` for direct I/O on the disk I/O pool: `O_RDWR` and the
    /// flags of `options`, with `O_DIRECT` on Linux and `F_NOCACHE` on macOS.
    ///
    /// Returns `(file_index, generation)`.
    pub(crate) fn direct_io_open(
        &mut self,
        path: &std::path::Path,
        options: crate::direct_io::DirectIoOpenOptions,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        #[cfg(target_os = "linux")]
        let flags = libc::O_RDWR | libc::O_DIRECT;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::O_RDWR;
        self.file_open(
            FileKind::DirectIo,
            path,
            flags | options.extra_flags(),
            0,
            true,
            key,
        )
    }

    // ── Filesystem I/O methods ────────────────────────────────────────

    /// Open a file via the disk I/O pool.
    ///
    /// Returns `(file_index, generation)`.
    pub(crate) fn fs_open(
        &mut self,
        path: &std::path::Path,
        flags: crate::fs::OpenFlags,
        mode: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<(u16, u32)> {
        self.file_open(FileKind::Fs, path, flags.0, mode, false, key)
    }

    /// Submit a filesystem read via the disk I/O pool.
    #[cfg(test)]
    pub(crate) unsafe fn fs_read(
        &mut self,
        file: crate::fs::File,
        offset: u64,
        buf: *mut u8,
        len: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let (index, generation) = (file.index, file.generation);
        unsafe {
            self.file_read(
                FileKind::Fs,
                index,
                generation,
                offset,
                buf,
                len,
                crate::buffer::fixed::RegionId::UNREGISTERED,
                key,
            )
        }
    }

    /// Submit a filesystem write via the disk I/O pool.
    #[cfg(test)]
    pub(crate) unsafe fn fs_write(
        &mut self,
        file: crate::fs::File,
        offset: u64,
        buf: *const u8,
        len: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<u64> {
        let (index, generation) = (file.index, file.generation);
        unsafe {
            self.file_write(
                FileKind::Fs,
                index,
                generation,
                offset,
                buf,
                len,
                crate::buffer::fixed::RegionId::UNREGISTERED,
                key,
            )
        }
    }

    /// Submit an fsync for a filesystem file via the disk I/O pool.
    #[cfg(test)]
    pub(crate) fn fs_fsync(
        &mut self,
        file: crate::fs::File,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        self.file_fsync(FileKind::Fs, file.index, file.generation, key)
    }

    /// Submit a stat via the disk I/O pool; with `nofollow`, an lstat.
    ///
    /// Uses `libc::stat` (portable) instead of `statx` (Linux-only). The
    /// result is converted to `crate::fs::Metadata` inside the pool closure
    /// and delivered via `DiskIoResponse::metadata`.
    pub(crate) fn fs_stat(
        &mut self,
        path: &std::path::Path,
        nofollow: bool,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;
        let work = Box::new(move || {
            let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
            let result = if nofollow {
                unsafe { libc::lstat(c_path.as_ptr(), &mut stat_buf) }
            } else {
                unsafe { libc::stat(c_path.as_ptr(), &mut stat_buf) }
            };
            if result < 0 {
                let errno = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO);
                crate::disk_io_pool::DiskIoResult {
                    result: -errno,
                    metadata: None,
                    opened: None,
                }
            } else {
                let metadata = crate::fs::Metadata::from_stat(&stat_buf);
                crate::disk_io_pool::DiskIoResult {
                    result: 0,
                    metadata: Some(metadata),
                    opened: None,
                }
            }
        });
        self.submit_disk_io(crate::disk_io_pool::PoolSubsystem::Fs, work, false, key)
    }

    /// Submit a rename via the disk I/O pool.
    pub(crate) fn fs_rename(
        &mut self,
        from: &std::path::Path,
        to: &std::path::Path,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_from = crate::fs::path_to_cstring(from)?;
        let c_to = crate::fs::path_to_cstring(to)?;
        let work = Box::new(move || {
            let result = unsafe { libc::rename(c_from.as_ptr(), c_to.as_ptr()) };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                0
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        self.submit_disk_io(crate::disk_io_pool::PoolSubsystem::Fs, work, false, key)
    }

    /// Submit an unlink via the disk I/O pool.
    pub(crate) fn fs_unlink(
        &mut self,
        path: &std::path::Path,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;
        let work = Box::new(move || {
            let result = unsafe { libc::unlink(c_path.as_ptr()) };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                0
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        self.submit_disk_io(crate::disk_io_pool::PoolSubsystem::Fs, work, false, key)
    }

    /// Submit a mkdir via the disk I/O pool.
    pub(crate) fn fs_mkdir(
        &mut self,
        path: &std::path::Path,
        mode: u32,
        key: crate::runtime::DiskIoKey,
    ) -> io::Result<()> {
        let c_path = crate::fs::path_to_cstring(path)?;
        let work = Box::new(move || {
            let result = unsafe { libc::mkdir(c_path.as_ptr(), mode as libc::mode_t) };
            let r = if result < 0 {
                -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            } else {
                0
            };
            crate::disk_io_pool::DiskIoResult {
                result: r,
                metadata: None,
                opened: None,
            }
        });
        self.submit_disk_io(crate::disk_io_pool::PoolSubsystem::Fs, work, false, key)
    }
}

/// A prepared send operation with its associated resources, ready for submission.
#[cfg_attr(not(has_io_uring), allow(dead_code))]
pub(crate) struct BuiltSend {
    /// The io_uring SQE to submit.
    #[cfg(has_io_uring)]
    pub entry: crate::backend::uring::sqe::Sqe,
    /// SendCopyPool slot index. u16::MAX if none.
    pub pool_slot: u16,
    /// InFlightSendSlab index. u16::MAX if none (only for SendMsgZc).
    #[cfg(has_io_uring)]
    pub slab_idx: u16,
}

/// A pre-classified part for scatter-gather sends via `submit_batch`.
///
/// Used to build mixed copy + zero-copy guard sends without the lifetime
/// constraints of the closure-based builder API.
pub enum SendPart<'a> {
    /// Data to be copied into the send pool on submit.
    Copy(&'a [u8]),
    /// Zero-copy guard — ownership is transferred to the kernel on submit.
    Guard(GuardBox),
}

#[cfg(has_io_uring)]
/// Part type in a scatter-gather send.
#[derive(Clone, Copy)]
enum PartSlot {
    Empty,
    Copy { slice_idx: u8 },
    Guard { guard_idx: u8 },
}

#[cfg(has_io_uring)]
/// Builder for scatter-gather sends with mixed copy + zero-copy guard parts.
pub struct SendBuilder<'b, 'a> {
    ctx: &'b mut DriverCtx<'a>,
    conn: ConnId,
    parts: [PartSlot; MAX_IOVECS],
    part_count: u8,
    copy_slices: [(*const u8, usize); MAX_IOVECS],
    copy_count: u8,
    total_copy_len: usize,
    guards: [Option<GuardBox>; MAX_GUARDS],
    guard_count: u8,
    total_len: u32,
    error: Option<io::Error>,
    /// Settled by the send's completion; see `submit_awaited`.
    send_id: Option<crate::runtime::send_completion::SendId>,
    /// Whether `zero_copy_hold_cap` refuses the send. Cleared by
    /// `forward_recv_buf` (`without_zero_copy_cap`), which `forward_hold_cap`
    /// bounds instead.
    zero_copy_capped: bool,
}

#[cfg(has_io_uring)]
impl<'b, 'a> SendBuilder<'b, 'a> {
    /// Exempt the send from `zero_copy_hold_cap`. A connection that forwards
    /// its receive buffers stops receiving at `forward_hold_cap` entries; a
    /// refusal below that would leave it receiving into its accumulator.
    pub(crate) fn without_zero_copy_cap(mut self) -> Self {
        self.zero_copy_capped = false;
        self
    }

    /// Add a copy part. The data will be copied into the send pool on `submit()`.
    /// The data reference must outlive the builder (guaranteed by the `'b` lifetime).
    pub fn copy(mut self, data: &'b [u8]) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 32)",
            ));
            return self;
        }
        let idx = self.copy_count;
        self.copy_slices[idx as usize] = (data.as_ptr(), data.len());
        self.copy_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Copy { slice_idx: idx };
        self.part_count += 1;
        self.total_len += data.len() as u32;
        self.total_copy_len += data.len();
        self
    }

    /// Add a zero-copy guard part. The guard keeps the memory alive until the kernel
    /// releases it via the ZC notification, or, on a Unix-domain connection, until
    /// the plain `sendmsg` that sends it completes.
    pub fn guard(mut self, guard: GuardBox) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 32)",
            ));
            return self;
        }
        if self.guard_count as usize >= MAX_GUARDS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many guards (max 8)",
            ));
            return self;
        }
        let (_, len) = guard.as_ptr_len();
        let gidx = self.guard_count;
        self.guards[gidx as usize] = Some(guard);
        self.guard_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Guard { guard_idx: gidx };
        self.part_count += 1;
        self.total_len += len;
        self
    }

    /// [`submit`](Self::submit), with `id` settled by the send's completion
    /// with the total length of its parts. On `Err` nothing was queued and
    /// `id` is the caller's to cancel.
    pub(crate) fn submit_awaited(
        mut self,
        id: crate::runtime::send_completion::SendId,
    ) -> io::Result<()> {
        self.send_id = Some(id);
        self.submit()
    }

    /// Attach the awaited id, if any, to `built`, then submit or queue it.
    fn commit(&mut self, built: BuiltSend) {
        if let Some(id) = self.send_id {
            self.ctx.attach_send_id(Some(&built), id, self.total_len);
            self.ctx.parts_id_carried = true;
        }
        self.ctx.submit_or_queue(self.conn.index, built);
    }

    /// Submit the scatter-gather send.
    ///
    /// A batch with no parts, or whose parts carry no bytes, is refused with
    /// `InvalidInput` on a live connection; a stale or closing connection is
    /// reported as `NotConnected`, or `ConnectionAborted` after `abort`, as
    /// for any batch.
    pub fn submit(mut self) -> io::Result<()> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }

        // Validate connection + generation.
        let conn_state = self
            .ctx
            .connections
            .get(self.conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != self.conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }
        // Aborted, or the Close already submitted — a new send SQE would
        // race it.
        if let Some(e) = self.ctx.send_queues[self.conn.index as usize].closing_refusal() {
            return Err(e);
        }

        // Nothing to send: build no SQE. A zero-length Send SQE completes
        // with 0, which `handle_send` reads as a failed send and drains the
        // queue behind it. A builder with an awaited id (every public one)
        // refuses the batch; one without (crate-internal) queues nothing.
        if self.part_count == 0 || self.total_len == 0 {
            if self.send_id.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty send batch",
                ));
            }
            return Ok(());
        }

        // TLS path: gather all data, encrypt, copy-send. Drop guards immediately.
        if !self.ctx.tls_table.is_null() {
            let tls_table = unsafe { &mut *self.ctx.tls_table };
            if tls_table.get_mut(self.conn.index).is_some() {
                return self.submit_tls();
            }
        }

        // No guards: gather all copy parts into one pool slot, submit as regular Send.
        if self.guard_count == 0 {
            return self.submit_copy_only();
        }

        // Small guard sends: ZC bookkeeping (slab entry + notification CQE) costs
        // more than a memcpy below the threshold. Gather everything — guard memory
        // included — into one pool slot and submit a plain Send. Guards drop
        // immediately (data is copied out before return). Falls through to the ZC
        // path when the pool is exhausted or the gather doesn't fit a slot.
        let threshold = self.ctx.send_zc_threshold;
        if threshold > 0 && self.total_len < threshold && self.submit_small_gather()? {
            return Ok(());
        }

        // With guards: build iovecs mixing copy pool subranges and guard
        // pointers, in a slab entry the connection may take.
        if self.zero_copy_capped && self.ctx.zero_copy_over_cap(self.conn) {
            return Err(io::Error::other(ZERO_COPY_CAP_REFUSAL));
        }
        self.submit_with_guards()
    }

    /// TLS fallback: gather all data into a contiguous buffer, encrypt, copy-send.
    fn submit_tls(mut self) -> io::Result<()> {
        let mut plaintext = Vec::with_capacity(self.total_len as usize);
        for i in 0..self.part_count as usize {
            match self.parts[i] {
                PartSlot::Copy { slice_idx } => {
                    let (ptr, len) = self.copy_slices[slice_idx as usize];
                    let data = unsafe { std::slice::from_raw_parts(ptr, len) };
                    plaintext.extend_from_slice(data);
                }
                PartSlot::Guard { guard_idx } => {
                    if let Some(ref g) = self.guards[guard_idx as usize] {
                        let (ptr, len) = g.as_ptr_len();
                        let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                        plaintext.extend_from_slice(data);
                    }
                }
                PartSlot::Empty => {}
            }
        }
        // Drop guards — TLS encrypted copy-send doesn't need ZC
        for g in self.guards.iter_mut() {
            *g = None;
        }
        let sends = self.ctx.encrypt_tls_send(self.conn, &plaintext)?;
        if let Some(id) = self.send_id {
            self.ctx.attach_send_id(sends.last(), id, self.total_len);
            self.ctx.parts_id_carried = true;
        }
        self.ctx.queue_built_sends(self.conn.index, sends);
        Ok(())
    }

    /// Copy-only path: gather all copy parts into one pool slot, return built SQE.
    fn build_copy_only(&mut self) -> io::Result<BuiltSend> {
        // `copy_in_gather` returns `None` for an oversize gather as well as
        // for an empty pool; only the second is retryable.
        if self.total_copy_len > self.ctx.send_copy_pool.slot_size() as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "total copy data exceeds send pool slot size",
            ));
        }
        let (slot, ptr, len) = unsafe {
            self.ctx.send_copy_pool.copy_in_gather(
                &self.copy_slices[..self.copy_count as usize],
                self.total_copy_len,
            )
        }
        .ok_or_else(|| io::Error::other("send copy pool exhausted"))?;

        let user_data = crate::completion::UserData::encode(
            crate::completion::OpTag::Send,
            self.conn.index,
            crate::completion::UserData::send_payload(slot, self.conn.generation),
        );
        let entry = crate::backend::uring::sqe::Sqe::stream_send(
            self.conn.index,
            ptr,
            len,
            user_data.raw(),
        );

        Ok(BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
        })
    }

    /// Mixed copy+guard path: allocate pool slot + slab entry, return built SQE.
    #[allow(clippy::needless_range_loop)]
    fn build_with_guards(&mut self) -> io::Result<BuiltSend> {
        let slot_size = self.ctx.send_copy_pool.slot_size() as usize;
        if self.total_copy_len > slot_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "total copy data exceeds send pool slot size",
            ));
        }

        if self.total_copy_len > 0 {
            let (slot, pool_ptr, _pool_len) = unsafe {
                self.ctx.send_copy_pool.copy_in_gather(
                    &self.copy_slices[..self.copy_count as usize],
                    self.total_copy_len,
                )
            }
            .ok_or_else(|| io::Error::other("send copy pool exhausted"))?;

            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            let mut copy_offset: usize = 0;
            for i in 0..self.part_count as usize {
                match self.parts[i] {
                    PartSlot::Copy { slice_idx } => {
                        let (_src_ptr, src_len) = self.copy_slices[slice_idx as usize];
                        iovecs[i] = libc::iovec {
                            iov_base: pool_ptr.wrapping_add(copy_offset) as *mut _,
                            iov_len: src_len,
                        };
                        copy_offset += src_len;
                    }
                    PartSlot::Guard { guard_idx } => {
                        let g = self.guards[guard_idx as usize].as_ref().unwrap();
                        let (gptr, glen) = g.as_ptr_len();
                        let region = g.region();
                        if region != crate::buffer::fixed::RegionId::UNREGISTERED {
                            self.ctx
                                .fixed_buffers
                                .validate_region_ptr(region, gptr, glen)
                                .map_err(|e| {
                                    self.ctx.send_copy_pool.release(slot);
                                    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                                })?;
                        }
                        iovecs[i] = libc::iovec {
                            iov_base: gptr as *mut _,
                            iov_len: glen as usize,
                        };
                    }
                    PartSlot::Empty => {}
                }
            }

            // Take guards out of self (moved into slab).
            let guards = std::mem::take(&mut self.guards);
            let iov_slice = &iovecs[..self.part_count as usize];
            let total_len = self.total_len;
            let (slab_idx, msg_ptr) = self
                .ctx
                .send_slab
                .allocate(
                    self.conn.index,
                    self.conn.generation,
                    iov_slice,
                    slot,
                    guards,
                    self.guard_count,
                    total_len,
                )
                .ok_or_else(|| {
                    self.ctx.send_copy_pool.release(slot);
                    io::Error::other("send slab exhausted")
                })?;

            let user_data = crate::completion::UserData::encode(
                crate::completion::OpTag::SendMsgZc,
                self.conn.index,
                slab_idx as u32,
            );
            // A Unix socket refuses `SENDMSG_ZC`: send the entry with a plain
            // `sendmsg`, and mark it so a partial send is resent the same way.
            // The completion is handled as a zero-copy send that owes no
            // notification.
            let entry = if self.ctx.conn_is_unix(self.conn.index) {
                self.ctx.send_slab.set_plain_msg(slab_idx);
                crate::backend::uring::sqe::Sqe::send_msg(self.conn.index, msg_ptr, user_data.raw())
            } else {
                crate::backend::uring::sqe::Sqe::send_msg_zc(
                    self.conn.index,
                    msg_ptr,
                    user_data.raw(),
                )
            };

            Ok(BuiltSend {
                entry,
                pool_slot: slot,
                slab_idx,
            })
        } else {
            // No copy data, only guards.
            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            for i in 0..self.part_count as usize {
                if let PartSlot::Guard { guard_idx } = self.parts[i] {
                    let g = self.guards[guard_idx as usize].as_ref().unwrap();
                    let (gptr, glen) = g.as_ptr_len();
                    let region = g.region();
                    if region != crate::buffer::fixed::RegionId::UNREGISTERED {
                        self.ctx
                            .fixed_buffers
                            .validate_region_ptr(region, gptr, glen)
                            .map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                            })?;
                    }
                    iovecs[i] = libc::iovec {
                        iov_base: gptr as *mut _,
                        iov_len: glen as usize,
                    };
                }
            }

            let guards = std::mem::take(&mut self.guards);
            let iov_slice = &iovecs[..self.part_count as usize];
            let total_len = self.total_len;
            let (slab_idx, msg_ptr) = self
                .ctx
                .send_slab
                .allocate(
                    self.conn.index,
                    self.conn.generation,
                    iov_slice,
                    u16::MAX,
                    guards,
                    self.guard_count,
                    total_len,
                )
                .ok_or_else(|| io::Error::other("send slab exhausted"))?;

            let user_data = crate::completion::UserData::encode(
                crate::completion::OpTag::SendMsgZc,
                self.conn.index,
                slab_idx as u32,
            );
            // A Unix socket refuses `SENDMSG_ZC`: send the entry with a plain
            // `sendmsg`, and mark it so a partial send is resent the same way.
            // The completion is handled as a zero-copy send that owes no
            // notification.
            let entry = if self.ctx.conn_is_unix(self.conn.index) {
                self.ctx.send_slab.set_plain_msg(slab_idx);
                crate::backend::uring::sqe::Sqe::send_msg(self.conn.index, msg_ptr, user_data.raw())
            } else {
                crate::backend::uring::sqe::Sqe::send_msg_zc(
                    self.conn.index,
                    msg_ptr,
                    user_data.raw(),
                )
            };

            Ok(BuiltSend {
                entry,
                pool_slot: u16::MAX,
                slab_idx,
            })
        }
    }

    /// Copy-only path: gather all copy parts, submit or queue.
    fn submit_copy_only(mut self) -> io::Result<()> {
        let built = self.build_copy_only()?;
        self.commit(built);
        Ok(())
    }

    /// Small-send fallback: gather all parts (copy + guard memory, in part order)
    /// into one pool slot and submit as a plain `Send`. Guard memory is copied,
    /// so the guards are dropped on return instead of being held in the slab.
    ///
    /// Returns `Ok(false)` without consuming anything when the pool has no free
    /// slot or the gather exceeds the slot size — the caller falls through to
    /// the zero-copy path.
    #[allow(clippy::needless_range_loop)]
    fn submit_small_gather(&mut self) -> io::Result<bool> {
        // Build the gather list in part order, mixing copy slices and guard memory.
        let mut slices: [(*const u8, usize); MAX_IOVECS] = [(std::ptr::null(), 0); MAX_IOVECS];
        let mut n = 0usize;
        for i in 0..self.part_count as usize {
            match self.parts[i] {
                PartSlot::Copy { slice_idx } => {
                    slices[n] = self.copy_slices[slice_idx as usize];
                    n += 1;
                }
                PartSlot::Guard { guard_idx } => {
                    let g = self.guards[guard_idx as usize]
                        .as_ref()
                        .expect("guard slot must be Some in submit_small_gather");
                    let (ptr, len) = g.as_ptr_len();
                    slices[n] = (ptr, len as usize);
                    n += 1;
                }
                PartSlot::Empty => {}
            }
        }

        // SAFETY: every (ptr, len) in `slices[..n]` is live — copy slices borrow
        // caller data that outlives the builder, guard memory is owned by
        // `self.guards` until this method returns.
        // `self.total_len` equals the sum of all gathered part lengths, so the
        // slot's `remaining` accounting matches the bytes actually copied in.
        let Some((slot, ptr, len)) = (unsafe {
            self.ctx
                .send_copy_pool
                .copy_in_gather(&slices[..n], self.total_len as usize)
        }) else {
            // Pool exhausted or gather exceeds slot size: keep guards, use ZC path.
            return Ok(false);
        };

        let user_data = crate::completion::UserData::encode(
            crate::completion::OpTag::Send,
            self.conn.index,
            crate::completion::UserData::send_payload(slot, self.conn.generation),
        );
        let entry = crate::backend::uring::sqe::Sqe::stream_send(
            self.conn.index,
            ptr,
            len,
            user_data.raw(),
        );

        let built = BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
        };
        // Data is in the pool slot now — guards can die with `self` after return.
        self.commit(built);
        Ok(true)
    }

    /// Mixed copy+guard path: submit or queue.
    fn submit_with_guards(mut self) -> io::Result<()> {
        let built = self.build_with_guards()?;
        self.commit(built);
        Ok(())
    }
}

/// The subsystem a disk operation's user_data payload names: its top two
/// bits (`DriverCtx::disk_op_id`).
#[cfg(has_io_uring)]
#[derive(Clone, Copy)]
pub(crate) enum DiskIoKind {
    Fs = 0,
    DirectIo = 1,
    Nvme = 2,
}

/// How a mio pool submission is ordered on its file (#905).
#[cfg(not(has_io_uring))]
#[derive(Clone, Copy)]
enum DiskOrder {
    Write(crate::disk_order::OrderKey),
    Sync(crate::disk_order::OrderKey),
}
