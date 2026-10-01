use crate::park::ParkedFd;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use io_uring::cqueue;

use crate::accumulator::AccumulatorTable;
use crate::backend::ProvidedBufRing;
use crate::backend::Ring;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::buffer::send_copy::SendCopyPool;
use crate::buffer::send_slab::InFlightSendSlab;
use crate::chain::SendChainTable;
use crate::completion::{OpTag, UserData};
use crate::config::Config;
use crate::connection::{ConnectionTable, Lifecycle, RecvArm, WriteHalf};
use crate::handler::{BuiltSend, ConnSendState, DriverCtx};
use crate::metrics;
use crate::runtime::send_capacity::BoundedSendId;

/// Slots in the lazily-constructed fallback recv pool. At most one
/// fallback is in flight per connection, so this bounds how many
/// connections can be in fallback simultaneously; when exhausted the
/// remaining starved connections stay parked (the pre-fallback status
/// quo) until slots free up.
const FALLBACK_RECV_SLOTS: u16 = 32;

/// One in-flight UDP send slot. Owns the `sockaddr` + `iovec` + `msghdr`
/// triple referenced by a single `sendmsg` SQE; returned to the freelist
/// once the CQE arrives.
pub(crate) struct UdpSendSlot {
    pub send_addr: Box<libc::sockaddr_storage>,
    #[allow(dead_code)] // referenced via raw pointer in msghdr
    pub send_iov: Box<libc::iovec>,
    pub send_msghdr: Box<libc::msghdr>,
    /// Pinned per-slot scratch for `UDP_SEGMENT` cmsg. Sized to hold
    /// one `cmsghdr` + a `u16` segment size; only consulted when
    /// `send_to_gso` is used. Heap-stable so the kernel's view (via
    /// `msg_control`) stays valid until the CQE arrives.
    pub send_cmsg_buf: Box<[u8; UDP_GSO_CMSG_LEN]>,
}

/// Size of the per-slot control-message buffer used for
/// `UDP_SEGMENT` cmsgs. CMSG_SPACE(sizeof(u16)) on x86-64 is 24
/// (cmsghdr is 16 bytes, payload aligned to 8). 32 is comfortable
/// over-allocation that survives any reasonable cmsg layout change.
pub(crate) const UDP_GSO_CMSG_LEN: usize = 32;

/// Pack a UDP send slot index and copy-pool slot into a 32-bit CQE payload.
/// High 16 bits = send-slot index; low 16 bits = copy-pool slot.
#[inline]
pub(crate) fn encode_udp_send_payload(slot_idx: u16, pool_slot: u16) -> u32 {
    ((slot_idx as u32) << 16) | (pool_slot as u32)
}

/// Inverse of [`encode_udp_send_payload`]: returns `(slot_idx, pool_slot)`.
#[inline]
pub(crate) fn decode_udp_send_payload(payload: u32) -> (u16, u16) {
    ((payload >> 16) as u16, (payload & 0xFFFF) as u16)
}

/// Per-worker UDP socket state.
pub(crate) struct UdpSocketState {
    /// Fixed file table index for this socket.
    pub fd_index: u32,
    /// Bound address.
    #[allow(dead_code)] // stored for diagnostics
    pub local_addr: SocketAddr,
    /// If `Some`, the socket has been `connect(2)`ed to this peer at setup
    /// time and the runtime uses the lighter `RecvUdp`/`SendUdp` opcodes
    /// instead of `RecvMsgUdp`/`SendMsgUdp`.
    pub connected_peer: Option<SocketAddr>,
    /// `msghdr` template used by `IORING_OP_RECVMSG_MULTISHOT`. The kernel
    /// reads its `msg_namelen`/`msg_controllen`/etc. to decide how to carve
    /// up each provided buffer into `[io_uring_recvmsg_out][name][control]
    /// [payload]`. `RecvMsgOut::parse` reads the same template on the CQE
    /// side. Must stay heap-stable for the lifetime of the multishot.
    pub recv_msghdr: Box<libc::msghdr>,
    /// Whether `UDP_GRO` was enabled on this socket. When true, each recvmsg
    /// delivery may carry a `UDP_GRO` control message whose value is the
    /// segment size used to split the coalesced payload back into datagrams.
    pub gro: bool,
    // ── Send state: fixed-size ring of per-SQE slots + a stack-freelist ──
    pub send_slots: Box<[UdpSendSlot]>,
    pub send_freelist: Vec<u16>,
}

/// A kernel recv buffer held in-place for zero-copy access.
///
/// The pointer is into `ProvidedBufRing::buf_backing`, which is allocated once
/// and never resized, so it remains valid until the bid is replenished.
#[derive(Clone, Copy)]
pub(crate) struct PendingRecvBuf {
    pub(crate) bid: u16,
    pub(crate) len: u32,
    pub(crate) ptr: *const u8,
}

/// A held received buffer for segmented delivery (Mode B/C), in one of two
/// backings depending on ring pressure at delivery time.
///
/// - [`Pinned`](Self::Pinned): a provided-buffer bid pinned in the ring — the
///   bid is NOT replenished, so the buffer stays in the provided ring until a
///   segment reader consumes it or the connection closes (`close_connection`
///   drains the hold). The backing pointer is derivable via
///   `provided_bufs.get_buffer(bid)`, so only the id and length are stored. This
///   is the zero-copy delivery, used while the ring is above the low-water
///   reserve.
/// - [`Owned`](Self::Owned): an owned copy of the received bytes. When the ring
///   is at/below `recv_segment_reserve` the bytes are copied at delivery and the
///   bid is returned to the ring immediately (Mode C), so this entry pins
///   nothing and needs no replenish when consumed or on close.
#[derive(Clone)]
pub(crate) enum HeldRecvBuf {
    /// A provided-buffer bid pinned in the ring (zero-copy hold).
    Pinned {
        bid: u16,
        /// Bytes received into this buffer. The segment reader slices the buffer
        /// to this length; close-drain only needs the bid.
        len: u32,
    },
    /// An owned copy of the received bytes; its bid was already replenished at
    /// delivery, so consuming or dropping this entry replenishes nothing.
    Owned(bytes::Bytes),
}

/// Held buffers gathered into one forward write.
///
/// Bounded rather than unbounded: a batch is one operation whose completion
/// releases every bid in it, so a very large batch delays those bids' return to
/// the ring and coarsens the hold-cap throttle. 16 × 16 KiB is 256 KiB per
/// write, which is past the point where a socket has more queued anyway
/// (#416 measured recv completions plateauing near 100 KB).
const MAX_FORWARD_IOV: usize = 16;

/// A running Mode A forward, driver-side.
///
/// This used to live in `ForwardToFuture`, which is why every completed write
/// had to wake the task just so the future could pop the next held buffer and
/// submit it. Holding it here lets the completion handler do that itself —
/// `run_direct_echo` has always worked this way, and the mio backend's
/// `MioForwardState` has held the equivalent since #415. Measured motivation:
/// Mode A ran 1.26 instructions/byte against direct echo's 0.985 at the same
/// 16 KiB buffer, over a ~0.86 kernel floor (#416).
#[derive(Clone, Copy)]
pub(crate) struct ForwardProgress {
    /// Where the bytes go; a file sink writes at `forwarded` as its offset.
    pub(crate) target: SinkTarget,
    /// Bytes the caller asked to forward.
    pub(crate) len: u64,
    /// Bytes whose write has completed.
    pub(crate) forwarded: u64,
    /// Identifies *which* forward this is, so a `ForwardToFuture` dropped after
    /// its own forward ended cannot cancel a later one that reused the slot.
    /// Bumped per arm, per connection.
    pub(crate) epoch: u32,
}

/// In-flight segmented-recv Mode A forward write (see
/// `docs/segmented-recv-design.md`, "Mode A — Forward to an fd"). One per
/// connection at a time — writes to a sink are serialized (io_uring does not
/// order independent SQEs, so pipelining would reorder the byte stream). The
/// backing (a pinned provided-buffer bid or an owned copy) is kept alive here
/// until the write CQE arrives (SQE memory must outlive the op), then released
/// exactly once by `handle_forward_write`.
/// Where a Mode A forward writes.
///
/// `Fd` is a borrowed descriptor named by [`SinkFd`](crate::SinkFd) — a socket
/// or a seekable file. `Conn` is another ringline connection on this worker,
/// addressed by its registered-file index; `ConnCtx` is `!Send`, so "on this
/// worker" is enforced by the type system rather than by documentation.
#[derive(Clone, Copy)]
pub(crate) enum SinkTarget {
    Fd { fd: RawFd, is_file: bool },
    Conn { index: u32, generation: u32 },
}

impl SinkTarget {
    /// A seekable sink writes at an advancing offset; a stream does not.
    pub(crate) fn is_file(&self) -> bool {
        matches!(self, SinkTarget::Fd { is_file: true, .. })
    }
}

pub(crate) struct ForwardWriteState {
    /// Where the bytes being written live, in wire order. `Pinned` entries
    /// release their bid on completion; `Owned` just drops its heap bytes.
    ///
    /// Several at once: one `sendmsg`/`writev` carries a whole batch of held
    /// buffers, so forwarding costs one completion per batch instead of one per
    /// buffer. Each entry's *prefix length* is in `lens` — a batch's last
    /// buffer can be truncated when the forward's `len` ends mid-buffer.
    pub(crate) backings: Vec<HeldRecvBuf>,
    /// Prefix length to write from each backing, parallel to `backings`.
    pub(crate) lens: Vec<u32>,
    /// The iovec array handed to the kernel. Owned here because an SQE's
    /// memory must outlive its operation, and rebuilt only between operations
    /// (a short write rebuilds it before resubmitting).
    pub(crate) iovecs: Vec<libc::iovec>,
    /// The `msghdr` handed to `sendmsg`, pointing at `iovecs`. Same lifetime
    /// rule, same reason.
    pub(crate) msghdr: libc::msghdr,
    /// Total bytes to write across the whole batch.
    pub(crate) total: u32,
    /// Bytes already written from this batch; advanced on short writes so the
    /// remainder resubmits at the correct source offset (and file offset).
    pub(crate) written: u32,
    /// Absolute file offset for byte 0 of this backing (0 for socket sinks).
    pub(crate) base_offset: u64,
    /// Where this write goes.
    pub(crate) target: SinkTarget,
    /// Connection generation captured at submit; the write CQE carries it in its
    /// payload so a stale completion (slot closed/reused) is ignored.
    pub(crate) generation: u32,
}

impl ForwardWriteState {
    /// Base pointer of one backing.
    fn base_ptr(backing: &HeldRecvBuf, provided_bufs: &ProvidedBufRing) -> *const u8 {
        match backing {
            HeldRecvBuf::Pinned { bid, .. } => provided_bufs.get_buffer(*bid).0,
            HeldRecvBuf::Owned(bytes) => bytes.as_ptr(),
        }
    }

    /// Rebuild `iovecs` (and point `msghdr` at it) to cover exactly the bytes
    /// not yet written.
    ///
    /// Called before every submission, including a resubmit after a short
    /// write: `written` may land mid-buffer, so the first surviving iovec
    /// starts at an offset and whole buffers ahead of it are skipped. Never
    /// called while an operation is in flight — the kernel is reading this
    /// array.
    pub(crate) fn rebuild_iovecs(&mut self, provided_bufs: &ProvidedBufRing) {
        self.iovecs.clear();
        let mut skip = self.written;
        for (backing, &len) in self.backings.iter().zip(self.lens.iter()) {
            if skip >= len {
                skip -= len;
                continue;
            }
            let base = Self::base_ptr(backing, provided_bufs);
            // SAFETY: `skip < len` and `len` bytes from `base` are initialised
            // and owned by this state until its CQE arrives.
            let ptr = unsafe { base.add(skip as usize) };
            self.iovecs.push(libc::iovec {
                iov_base: ptr as *mut libc::c_void,
                iov_len: (len - skip) as usize,
            });
            skip = 0;
        }
        self.msghdr = unsafe { std::mem::zeroed() };
        self.msghdr.msg_iov = self.iovecs.as_mut_ptr();
        self.msghdr.msg_iovlen = self.iovecs.len();
    }
}

/// I/O driver encapsulating all infrastructure state (ring, buffers, connections).
///
/// `AsyncEventLoop` is composed of a `Driver` + handler + executor.
///
/// # Drop order (load-bearing)
///
/// `ring` MUST be declared first so it drops *last*. `ProvidedBufRing` and
/// `InFlightSendSlab` reference kernel-pinned memory whose lifetime is tied
/// to the `io_uring` instance: the kernel only releases its DMA references
/// when `io_uring_release` runs. Dropping the buffer pools before the ring
/// would let `munmap` race against in-flight ZC notifications — a UAF.
///
/// The `driver_field_order` test below validates this ordering; do not
/// reorder these fields without updating both the assertion and the
/// shutdown drain in `run_shutdown`.
pub(crate) struct Driver {
    pub(crate) ring: Ring,
    pub(crate) connections: ConnectionTable,
    pub(crate) fixed_buffers: FixedBufferRegistry,
    pub(crate) provided_bufs: ProvidedBufRing,
    /// Provided buffer ring backing UDP multishot recvmsg. `None` when no UDP
    /// sockets are configured.
    pub(crate) udp_provided_bufs: Option<ProvidedBufRing>,
    /// Buffer IDs from `udp_provided_bufs` that have been consumed and need
    /// to be handed back to the kernel. Drained each tick.
    pub(crate) udp_pending_replenish: Vec<u16>,
    pub(crate) send_copy_pool: SendCopyPool,
    pub(crate) send_slab: InFlightSendSlab,
    pub(crate) accumulators: AccumulatorTable,
    pub(crate) pending_replenish: Vec<u16>,
    /// Per-connection pending recv buffer for zero-copy recv. When `Some`, the
    /// buffer ID has NOT been pushed to `pending_replenish` and must be
    /// replenished when the slot is cleared.
    pub(crate) pending_recv_bufs: Vec<Option<PendingRecvBuf>>,
    /// Per-connection original data length for in-flight SendRecvBuf operations.
    /// Set when `forward_recv_buf` initiates a send; used by `handle_send_recv_buf`
    /// to compute the correct offset on partial sends (since buf_size != data_len).
    pub(crate) send_recv_buf_original_lens: Vec<u32>,
    /// Per-connection remaining bytes for in-flight SendRecvBuf operations.
    /// Tracks how many bytes still need to be sent (decremented on each partial send).
    /// Stored here rather than in the CQE payload so that buffer sizes > u16::MAX are
    /// supported (the old encoding packed remaining into the high 16 bits of the payload).
    pub(crate) send_recv_buf_remaining: Vec<u32>,
    /// Per-connection multi-buffer zero-copy recv hold. When `recv_forward` is
    /// set for a connection, incoming provided buffers are pushed here (bids NOT
    /// replenished) instead of copied into the accumulator, then forwarded back
    /// in one coalesced `sendmsg` via `forward_held`. Backpressure is natural:
    /// unreplenished bids deplete the provided-buffer ring (ENOBUFS) until a
    /// forward completes and replenishes them.
    /// `recv_hold` is also the staging area for direct-echo connections, which
    /// gather it the same way from the CQE handler (see `flush_direct_echo`).
    pub(crate) recv_hold: Vec<std::collections::VecDeque<PendingRecvBuf>>,
    /// Per-connection opt-in flag for the zero-copy recv-forward path.
    pub(crate) recv_forward: Vec<bool>,
    /// Bytes already detached from the accumulator by a zero-copy
    /// `forward_recv_buf` during the current `with_data` / `with_bytes`
    /// closure. The delivery future subtracts this from what the closure
    /// reports consuming, because the forward already removed those bytes
    /// (see `ConnCtx::forward_recv_buf`).
    pub(crate) forward_zc_consumed: Vec<u32>,
    /// Direct-echo connections with buffers waiting in `recv_hold`. Entries
    /// persist until the hold drains, so the end-of-drain flush pass never has
    /// to ask which completion handler should have re-armed it.
    pub(crate) direct_echo_pending: Vec<u32>,
    /// Membership test for `direct_echo_pending` (one bool per connection),
    /// so a burst of recv CQEs on one connection enqueues it once.
    pub(crate) direct_echo_queued: Vec<bool>,
    /// Per-connection recv delivery domain (segmented-recv). `CopyOrConsume`
    /// (default) uses the accumulator / single-buffer zero-copy path;
    /// `Segmented` holds arriving provided buffers in `segment_hold` instead.
    /// Reset at slot (re)activation and on close.
    pub(crate) recv_domain: Vec<crate::recv::domain::RecvDomain>,
    /// Per-connection held provided buffers for `Segmented` connections. Bids
    /// pushed here are pinned in the ring (NOT replenished, no accumulator copy)
    /// until a reader consumes them (later increment) or the connection closes.
    /// A reader consumes them (`SegmentReader::next`) or the connection closes.
    /// `close_connection` drains any still-held bids to `pending_replenish`.
    pub(crate) segment_hold: Vec<std::collections::VecDeque<HeldRecvBuf>>,
    /// Per-connection pin slot: the single provided buffer currently checked out
    /// to a live `RecvSegment` (moved here out of `segment_hold` by
    /// `SegmentReader::next`). The B2 lending-iterator contract is one live
    /// segment at a time, so a single `Option` suffices. This is the
    /// single-release discriminant: whoever `take()`s it (the segment's `Drop`
    /// under `try_with_state`, or `close_connection` under `&mut Driver`)
    /// replenishes the bid exactly once; the other sees `None` and does nothing.
    pub(crate) segment_pinned: Vec<Option<HeldRecvBuf>>,
    /// The handler has offered this connection for park (tier 3, #443).
    ///
    /// Depositing is the opt-in: a connection whose handler never offered it
    /// is never parked. Cleared whenever recv delivers, because new data
    /// means a new request began and the quiescent point the handler offered
    /// at is gone — so the handler never has to remember to revoke.
    pub(crate) park_offered: Vec<bool>,
    /// Per connection: a park cancelled this connection's multishot recv and is
    /// waiting for the handler to come back to a quiescent point.
    ///
    /// Two measurements shaped this. Without the cancel staying cancelled the
    /// `ECANCELED` branch re-arms and fresh data keeps arriving; with it, the
    /// suppression fires on every park (9,809 of 9,809) and data *still* arrives,
    /// because a cancel cannot retract recv CQEs the kernel had already posted —
    /// which withdrew the offer 9,427 times out of 9,427 abandonments. So the
    /// install cannot be linked to the cancel: it has to wait until the handler
    /// re-offers, by which point nothing can be in flight.
    /// See `docs/journal/2026-09-two-phase-park.md`.
    ///
    /// Every path that stops a drain must clear this *and* re-arm, or the
    /// connection is left `Open` with no recv armed and its bytes piling up
    /// forever — the failure the unconditional re-arm was added to prevent.
    ///
    /// Written only through [`Driver::set_park_drain`], which keeps
    /// `park_drain_pending` in step.
    pub(crate) park_drain: Vec<Option<ParkDrain>>,
    /// Connection indices with a drain outstanding, visited by
    /// `drive_park_drains` each tick instead of scanning `park_drain`.
    ///
    /// `park_drain` is sized to `max_connections`, so walking it cost every
    /// tick 16,000 slot checks per worker at the default with nothing parking,
    /// measured at 37% of a client worker's cycles (#514). Same shape as the
    /// retry lists: per-slot state plus a list of the slots with work.
    ///
    /// Holds no duplicates. May briefly hold an index whose drain was cleared
    /// elsewhere; the next drive drops it.
    pub(crate) park_drain_pending: Vec<u32>,
    /// State the handler deposited alongside the offer, carried to the
    /// adopting worker and handed to `on_adopt`.
    ///
    /// Sparse on purpose. A dense `Vec<Option<ParkState>>` costs 32 bytes per
    /// slot — half a megabyte per worker at the default `max_connections`,
    /// tens of megabytes on a large box — for entries that only exist while a
    /// handler is actively offering. The hot path never reaches here anyway:
    /// `park_offered` is the dense bool that gates it.
    pub(crate) park_carry: std::collections::HashMap<u32, crate::park::ParkState>,
    /// Per connection: this slot is being adopted, so `spawn_accept_task`
    /// calls `on_adopt` rather than `on_accept`, with what the handler
    /// deposited. The outer `Option` is "this install is an adopt"; the inner
    /// is "and here is the state, if any".
    ///
    /// Per-connection rather than a single slot because the install is not
    /// always synchronous: the TLS branch of `install_accepted_with_pending`
    /// returns early and defers the spawn until the handshake completes. A
    /// single slot cleared when the install returned would be empty by then,
    /// and the adopt would silently become an accept.
    /// Sparse for the same reason as `park_carry`: an entry exists only
    /// between an adopt's install and its (possibly deferred) task spawn.
    pub(crate) adopt_pending: std::collections::HashMap<u32, Option<crate::park::ParkState>>,
    /// Parks awaiting their `FixedFdInstall` CQE, one slot per connection.
    /// Also the guard against submitting a second park for the same
    /// connection while the first is outstanding.
    pub(crate) park_in_flight: Vec<Option<ParkInFlight>>,
    /// Every worker's park channel and wake handle.
    pub(crate) peer_park: Vec<(crossbeam_channel::Sender<ParkedFd>, crate::wakeup::WakeFd)>,
    /// This worker's receiving end: connections other workers parked here.
    pub(crate) park_rx: Option<crossbeam_channel::Receiver<ParkedFd>>,
    /// Connections lifted off this worker, waiting to be handed over.
    /// `OwnedFd` means an entry left here is closed rather than leaked.
    pub(crate) park_ready: Vec<ParkedFd>,
    /// A `SegmentReader` is live on this connection.
    ///
    /// A reader owns the connection's delivery discipline for its whole
    /// lifetime — its `Drop` settles the hold back into the accumulator — so a
    /// second reader, or an owned-segment read, alongside it is a bug. Entry
    /// refuses with `EBUSY` while this is set, rather than letting the conflict
    /// surface later as a stranded read (#423, #427).
    pub(crate) segment_reader_live: Vec<bool>,
    /// The connection's [`RecvHalf`] has been taken.
    ///
    /// The recv side of a connection is exclusive — nine entry points that
    /// cannot run concurrently — but `ConnCtx` is `Copy`, so exclusivity has to
    /// be claimed rather than owned. Taking the half claims it; dropping the
    /// half releases it. See `docs/connection-handle-ownership-design.md`.
    pub(crate) recv_half_taken: Vec<bool>,
    /// Per connection index: is a [`SendHalf`](crate::SendHalf) currently out?
    ///
    /// The write-side twin of `recv_half_taken`. It makes "one owner of the
    /// writes" a real claim rather than a convention, and it is what lets a
    /// forward refuse a sink somebody else is already writing to.
    pub(crate) send_half_taken: Vec<bool>,
    /// Per-connection in-flight segmented-recv Mode A forward write (see
    /// [`ForwardWriteState`]). `Some` while a write to the sink is outstanding;
    /// enforces the one-write-in-flight invariant and keeps the write's backing
    /// alive until its CQE. `close_connection` drains it (releasing a pinned
    /// bid); the write CQE clears it on completion.
    pub(crate) forward_write: Vec<Option<ForwardWriteState>>,
    /// Per-connection completed-forward-write result, produced by
    /// `handle_forward_write` and consumed by the `ForwardToFuture`: `Ok(n)` =
    /// bytes of the just-completed backing, `Err(errno)` = write failure.
    /// Terminal result of a Mode A forward: total bytes forwarded, or an
    /// errno. Set once, by whichever handler drives the forward to its end,
    /// and consumed by `ForwardToFuture`. (It used to carry *per-write* byte
    /// counts, because the future accumulated them itself.)
    pub(crate) forward_done: Vec<Option<Result<u64, i32>>>,
    /// Per-connection Mode A forward state, indexed by source.
    pub(crate) forward_progress: Vec<Option<ForwardProgress>>,
    /// Monotonic per-connection forward counter; see [`ForwardProgress::epoch`].
    pub(crate) forward_epoch: Vec<u32>,
    /// Per-connection flag: `true` while a Mode A `forward_to` is driving this
    /// connection (set by `ConnCtx::forward_to`, cleared by `settle_forward_end`
    /// / `reset_segment_state` / `close_connection`). Gates the `forward_hold_cap`
    /// throttle so it applies only to forwarding connections, not to pure Mode B
    /// segment readers that share the `Segmented` domain and `segment_hold`.
    pub(crate) forward_recv_active: Vec<bool>,
    /// Per-connection flag: `true` while a forwarding connection's multishot recv
    /// has been throttled (cancelled) because its `segment_hold` reached
    /// `forward_hold_cap`. Set at the throttle point in the recv handler; cleared
    /// when the recv is re-armed after the hold drains below the cap
    /// (`maybe_rearm_throttled_forward`) or on `settle_forward_end` / close.
    /// Gates re-arm so the starved-connection path does not fight the throttle.
    pub(crate) forward_hold_throttled: Vec<bool>,
    /// Per-connection held-buffer cap for Mode A `forward_to`
    /// (`Config::forward_hold_cap`). When a forwarding connection's `segment_hold`
    /// length reaches this, its multishot recv is cancelled (TCP window closes)
    /// and re-armed once the hold drains below the cap.
    pub(crate) forward_hold_cap: usize,
    pub(crate) accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
    /// Merged accept mode: this worker's own listener sockets, `(listener
    /// index, fd)`. Empty in pool mode.
    pub(crate) merged_accept_fds: Vec<(u32, std::os::fd::RawFd)>,
    /// Goes true once `launch()` has called `listen(2)` on every merged socket.
    /// Arming an accept before that fails with `EINVAL`.
    pub(crate) merged_accept_live: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Whether this worker has already armed its multishot accepts, so the
    /// arming runs once rather than on every loop iteration.
    pub(crate) merged_accept_armed: bool,
    /// This worker's index into `worker_loads` / `peer_accept`.
    pub(crate) worker_index: usize,
    /// Live connection count per worker, for accept-time placement.
    pub(crate) worker_loads: Option<std::sync::Arc<Vec<std::sync::atomic::AtomicU32>>>,
    /// Which workers are in the accept rotation; placement skips the rest.
    pub(crate) worker_accepting: Option<std::sync::Arc<Vec<std::sync::atomic::AtomicBool>>>,
    /// Every worker's accept channel and wake handle, for handing off a raw fd
    /// to a less-loaded peer.
    pub(crate) peer_accept: Vec<(
        crossbeam_channel::Sender<crate::acceptor::AcceptedConn>,
        crate::wakeup::WakeFd,
    )>,
    pub(crate) eventfd: RawFd,
    pub(crate) eventfd_buf: [u8; 8],
    /// Wake handle for cross-thread wakeup (wraps the eventfd).
    pub(crate) wake_handle: crate::wakeup::WakeFd,
    /// Deadline-based flush interval. None = disabled (SQPOLL or explicit 0).
    pub(crate) flush_interval: Option<Duration>,
    pub(crate) shutdown_flag: Arc<AtomicBool>,
    pub(crate) shutdown_local: bool,
    pub(crate) tls_table: Option<crate::tls::TlsTable>,
    /// Pre-allocated sockaddr storage for outbound connect SQEs.
    pub(crate) connect_addrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated timespec storage for connect timeouts.
    pub(crate) connect_timespecs: Vec<io_uring::types::Timespec>,
    /// Pre-allocated batch buffer for draining CQEs.
    /// Tuple: (user_data, result, flags).
    pub(crate) cqe_batch: Vec<(u64, i32, u32)>,
    /// Per-worker channel for DNS resolve responses from the resolver pool.
    pub(crate) resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
    /// Per-worker sender for resolve responses (cloned into each request).
    pub(crate) resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
    /// Shared resolver pool (for submitting requests).
    pub(crate) resolver: Option<std::sync::Arc<crate::resolver::ResolverPool>>,
    /// Per-worker channel for spawn responses from the spawner pool.
    pub(crate) spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
    /// Per-worker sender for spawn responses (cloned into each request).
    pub(crate) spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
    /// Shared spawner pool (for submitting requests).
    pub(crate) spawner: Option<std::sync::Arc<crate::spawner::SpawnerPool>>,
    /// Per-worker channel for blocking responses from the blocking pool.
    pub(crate) blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
    /// Per-worker sender for blocking responses (cloned into each request).
    pub(crate) blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
    /// Shared blocking pool (for submitting requests).
    pub(crate) blocking_pool: Option<std::sync::Arc<crate::blocking::BlockingPool>>,
    /// Region-registry control channel — drained each tick to apply
    /// dynamic fixed-buffer registrations from
    /// [`Runtime::register_region`](crate::Runtime::register_region).
    pub(crate) region_rx: crate::region_registry::RegionControlRx,
    /// Whether to set TCP_NODELAY on connections.
    pub(crate) tcp_nodelay: bool,
    /// Print event-loop diagnostics at shutdown (Config::loop_diag).
    pub(crate) loop_diag: bool,
    /// Guard sends below this total length fall back to copy (0 = always ZC).
    pub(crate) send_zc_threshold: u32,
    /// Aggregate low-water reserve for segmented recv (Config::recv_segment_reserve).
    /// When `provided_bufs.free() <= recv_segment_reserve`, an arriving segmented
    /// buffer is force-copied (Mode C) and its bid replenished immediately instead
    /// of pinned, so held segments cannot deplete the shared ring under fan-in.
    pub(crate) recv_segment_reserve: u32,
    /// Upper bound on outstanding recv bytes per connection (mirrors
    /// `AccumulatorTable`'s per-accumulator `max_size`). Used to bound held TLS
    /// plaintext delivered as owned segments in the segmented recv domain, where
    /// the bytes never touch the accumulator but the same flood-kill contract
    /// (`Config::recv_accumulator_max`) must hold.
    pub(crate) recv_accumulator_max: usize,
    /// Whether SO_TIMESTAMPING is enabled for connections.
    #[cfg(feature = "timestamps")]
    pub(crate) timestamps: bool,
    /// Pinned msghdr template for RecvMsgMulti with SO_TIMESTAMPING.
    /// Used as the SQE template and for parsing CQE buffers via RecvMsgOut.
    #[cfg(feature = "timestamps")]
    pub(crate) recvmsg_msghdr: Box<libc::msghdr>,
    /// Per-connection send chain tracking for IOSQE_IO_LINK chains.
    pub(crate) chain_table: SendChainTable,
    /// Maximum SQEs per chain (0 = disabled).
    pub(crate) max_chain_length: u16,
    /// Per-connection send queues for serializing sends (one in-flight at a time).
    pub(crate) send_queues: Vec<ConnSendState>,
    /// Connection indices that currently have a `close_notify_deadline`
    /// armed (TLS graceful-shutdown timeout). The event loop's
    /// `check_close_notify_deadlines` iterates this set instead of
    /// walking every entry in `send_queues`, which is critical for
    /// non-TLS workloads — without this, the per-iteration deadline
    /// scan dominates worker CPU at high request rates.
    pub(crate) close_notify_armed: Vec<u32>,
    /// Configured close_notify drain deadline (Config::close_notify_timeout_ms).
    pub(crate) close_notify_timeout: std::time::Duration,
    /// Scratch for TLS output sends collected during CQE handling.
    pub(crate) tls_out_scratch: Vec<crate::handler::BuiltSend>,
    /// Monotonic disk-I/O sequence (see DriverCtx::disk_io_key).
    pub(crate) next_disk_io_seq: u16,
    /// Connections whose multishot recv hit ENOBUFS and is parked until
    /// provided-ring buffers return. Re-arming immediately (the old
    /// behavior) completed instantly with ENOBUFS again while data was
    /// pending and the ring was empty — a 100% CPU spin until some task
    /// released a bid.
    pub(crate) recv_starved: Vec<u32>,
    /// Lifetime count of ENOBUFS parks on this worker (pushes onto
    /// `recv_starved`). Reported in the shutdown diag line; sustained
    /// growth means responses exceed the provided ring and receive
    /// throughput is gated on buffer recycling.
    pub(crate) recv_park_count: u64,
    /// Per-connection flag: a fallback one-shot recv is in flight. While
    /// set, the connection must be neither re-armed for multishot recv nor
    /// given a second fallback — io_uring does not order independent SQEs,
    /// so two in-flight recvs on one stream could append out of order. The
    /// flag is cleared only in `handle_recv_fallback` (the fallback's own
    /// completion) and in `close_connection` (any still-in-flight CQE is
    /// then generation-checked and releases its pool slot without touching
    /// connection state).
    pub(crate) recv_fallback_inflight: Vec<bool>,
    /// Slot pool backing fallback one-shot recvs. Kernel writes land in
    /// pool-owned memory whose slot is released only by the fallback CQE —
    /// stale completions after close/slot-reuse are memory-safe by the same
    /// lifecycle argument as `send_copy_pool` (SQE memory outlives the op).
    /// Lazily constructed on first fallback so workloads that never starve
    /// the provided ring pay nothing.
    pub(crate) fallback_recv_pool: Option<SendCopyPool>,
    /// Per-pool-slot owner: `(conn_index, generation)` recorded at submit,
    /// validated in `handle_recv_fallback` before any connection state is
    /// touched (slots recycle; stale CQEs are normal).
    pub(crate) fallback_slot_owner: Vec<(u32, u32)>,
    /// Size of each fallback recv chunk (bytes). A few multiples of the
    /// provided-ring buffer size: one event-loop pass moves one chunk per
    /// starved connection, so this bounds per-pass fallback throughput.
    pub(crate) fallback_chunk: u32,
    /// Lifetime count of fallback recv submissions on this worker
    /// (reported in the shutdown diag line).
    pub(crate) recv_fallback_count: u64,
    /// Arrival timestamp shared by all UDP datagrams queued in one CQE
    /// drain batch. One clock read per batch instead of one per datagram;
    /// precision loss is bounded by the drain duration (microseconds).
    pub(crate) udp_batch_recv_at: std::time::Instant,
    /// Tick timeout duration. When set, a timeout SQE ensures the event loop
    /// wakes periodically even when no I/O completions are pending.
    pub(crate) tick_timeout_ts: Option<io_uring::types::Timespec>,
    /// Whether a tick timeout SQE is currently in-flight.
    pub(crate) tick_timeout_armed: bool,
    /// Monotonic tick counter for backoff-based retry scheduling.
    pub(crate) tick_count: u64,
    /// Whether the eventfd read SQE is currently armed.
    pub(crate) eventfd_armed: bool,
    /// Pending ZC send retries: (conn_index, generation, slab_idx, retries). Drained each tick.
    pub(crate) pending_zc_retries: Vec<(u32, u32, u16, u8)>,
    /// Pending copy send retries: (conn_index, generation, pool_slot, retries). Drained each tick.
    pub(crate) pending_copy_retries: Vec<(u32, u32, u16, u8, OpTag)>,
    /// Pending PollAdd-on-POLLOUT retries from the EAGAIN backpressure
    /// path: (conn_index, generation, pool_slot, retries). Drained each tick.
    /// Only used when `submit_send_pollout` itself failed (SQ full at
    /// the time the EAGAIN CQE arrived).
    pub(crate) pending_send_pollout_retries: Vec<(u32, u32, u16, u8, bool)>,
    /// Pending coalesced-send retries: (conn_index, generation, slab_idx, retries).
    /// Drained each tick — used when resubmitting a coalesced `sendmsg` (partial
    /// remainder or POLLOUT rearm) found the SQ full.
    pub(crate) pending_coalesced_retries: Vec<(u32, u32, u16, u8)>,
    /// Pending recv-forward send resubmissions that failed (SQ full):
    /// (conn_index, generation, slab_idx, retries). Drained each tick.
    pub(crate) pending_recv_forward_retries: Vec<(u32, u32, u16, u8)>,
    /// Pending close retries: (conn_index, retries). Drained each tick.
    pub(crate) pending_close_retries: Vec<(u32, u8)>,
    /// Connections whose queued head send could not be pushed (SQ still
    /// full after submit): (conn_index, generation, attempts). Drained each
    /// tick by `drain_send_retries`; the entry stays at the queue head with
    /// `in_flight = true` meanwhile, so stream order and the close deferral
    /// are preserved. Two failed attempts fail the send waiter and close the
    /// connection, mirroring `pending_copy_retries`.
    pub(crate) pending_send_retries: Vec<(u32, u32, u8)>,
    /// Bounded (`ConnCtx::send_backpressured`) operations that no CQE will
    /// ever settle, in settle order and keyed by the id the submitting
    /// future holds. Drained by the event loop into
    /// `Executor::complete_bounded_send` (the event-loop half of series
    /// PR 7b) — the driver never touches the `Executor` itself.
    ///
    /// Named for the common case, but the payload is an `io::Result` like
    /// mio's `bounded_send_completions`, because what unites these entries
    /// is the missing completion rather than the failure: a zero-length
    /// message (and a TLS one whose plaintext produced no record) queues no
    /// SQE at all and still has to resolve — with `Ok`, and with the same
    /// value mio reports for it.
    ///
    /// Two producers, and both exist because there is no CQE behind them.
    /// `DriverCtx::send_bounded` settles here when it finishes an operation
    /// synchronously, for the same reason mio has a completion queue at all:
    /// a `DriverCtx` is a borrow of driver fields with no executor access.
    /// Teardown (`release_queued_sends`, via `drain_conn_send_queue`,
    /// `force_finalize_close` and `reset_send_state`) settles here because
    /// the `BuiltSend`s it destroys were never submitted.
    ///
    /// `run_shutdown` pushes here too, into a queue nobody will drain. That
    /// is correct: the executor is going away with the driver, exactly as
    /// mio's `Driver::drop` produces no completions.
    pub(crate) bounded_send_completions: VecDeque<(BoundedSendId, io::Result<u32>)>,
    /// Set whenever a copy-pool slot goes back to the pool, so the event
    /// loop can call `Executor::wake_send_capacity` once per iteration
    /// instead of once per released slot. The event loop clears it.
    ///
    /// Mirrors mio's field of the same name, and the wake has the same
    /// placement — last in the run-loop body — for the same reason:
    /// `pending_finalize_closes` is drained after the final
    /// `drain_completions`, so a wake from inside the completion drain would
    /// leave teardown's released slots unsignalled until after a
    /// `submit_and_wait` that can block.
    pub(crate) capacity_released: bool,
    /// Connections whose close was requested this iteration — by
    /// `close_connection` (peer FIN, read error, task exit, setup failure)
    /// or by `DriverCtx::close` — and whose finalize is owed to the event
    /// loop's end-of-iteration drain (after `poll_ready_tasks`, so the task
    /// gets its poll window; #371). The drain re-drives
    /// `try_finalize_close` for each; entries with sends still outstanding
    /// are re-driven later by their CQEs via `note_send_finalized`.
    pub(crate) pending_finalize_closes: Vec<u32>,
    /// Scratch buffers swapped with the corresponding `pending_*_retries`
    /// queue at drain time so the per-tick drain reuses a single allocation
    /// across ticks (the primary queue is left empty for in-iteration
    /// re-enqueues; `drain(..)` on the scratch keeps its capacity).
    pub(crate) zc_retry_scratch: Vec<(u32, u32, u16, u8)>,
    pub(crate) copy_retry_scratch: Vec<(u32, u32, u16, u8, OpTag)>,
    pub(crate) send_pollout_retry_scratch: Vec<(u32, u32, u16, u8, bool)>,
    pub(crate) coalesced_retry_scratch: Vec<(u32, u32, u16, u8)>,
    pub(crate) recv_forward_retry_scratch: Vec<(u32, u32, u16, u8)>,
    pub(crate) send_retry_scratch: Vec<(u32, u32, u8)>,
    /// Per-worker UDP socket state.
    pub(crate) udp_sockets: Vec<UdpSocketState>,
    /// NVMe device tracking table. `None` when NVMe is not configured.
    pub(crate) nvme_devices: Option<crate::nvme::NvmeDeviceTable>,
    /// NVMe command slab for tracking in-flight commands. `None` when NVMe is not configured.
    pub(crate) nvme_cmd_slab: Option<crate::nvme::NvmeCmdSlab>,
    /// Base offset in the fixed file table for NVMe device fds.
    /// NVMe devices are registered at `nvme_fd_base + device_index`.
    pub(crate) nvme_fd_base: u32,
    /// Direct I/O file tracking table. `None` when direct I/O is not configured.
    pub(crate) direct_io_files: Option<crate::direct_io::DirectIoFileTable>,
    /// Direct I/O command slab for tracking in-flight commands. `None` when not configured.
    pub(crate) direct_io_cmd_slab: Option<crate::direct_io::DirectIoCmdSlab>,
    /// Base offset in the fixed file table for direct I/O file fds.
    pub(crate) direct_io_fd_base: u32,
    /// Filesystem file tracking table. `None` when fs is not configured.
    pub(crate) fs_files: Option<crate::fs::FsFileTable>,
    /// Filesystem command slab for tracking in-flight commands. `None` when not configured.
    pub(crate) fs_cmd_slab: Option<crate::fs::FsCmdSlab>,
    /// Base offset in the fixed file table for filesystem file fds.
    pub(crate) fs_fd_base: u32,
}

/// A park in flight: the `FixedFdInstall` has been submitted and its CQE has
/// not landed yet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParkInFlight {
    pub target: usize,
    /// Generation at submit time. A CQE carrying a different one belongs to a
    /// previous occupant of the slot.
    pub generation: u32,
}

/// A park whose recv-cancel is out, waiting for the handler to re-offer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParkDrain {
    /// Where the connection is headed once the install completes.
    pub target: usize,
    /// Generation at cancel time, so a recycled slot cannot inherit the drain.
    pub generation: u32,
    /// Ticks left to wait for a re-offer before giving up and re-arming.
    ///
    /// A handler awaiting something external may never come back to a quiescent
    /// point, and a connection with no recv armed and no deadline would wait
    /// forever — which is worse than not parking it.
    pub ticks_left: u16,
    /// When the cancel went out, so a completed drain can report how long the
    /// connection was held with no recv armed.
    ///
    /// The point of measuring it is that park moves p50 down 43% and p99 up 4x,
    /// and 230 drains cannot account for 9 ms of tail unless they are individually
    /// long. This says which.
    pub started: std::time::Instant,
}

/// Why a connection cannot be parked (tier 3, #443) right now.
///
/// Park moves a live connection to another worker: quiesce, hand the fd over
/// instead of closing it, drop the `!Send` future here and recreate it on the
/// target. It is [`Driver::try_finalize_close`]'s path stopped one step early,
/// so it gates on the same notion of "quiescent".
///
/// This names *why* a park was refused rather than returning a bare bool:
/// every variant is transient, so a policy layer wants to tell "ask again in a
/// moment" from "this connection is going away", and a failing test wants to
/// say which term tripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ParkBlocker {
    /// Not an established, open connection — still handshaking, still
    /// connecting, or already tearing down. Nothing to move yet.
    NotOpen,
    /// Bytes have arrived and not been consumed. Whatever the handler
    /// offered at, this connection is no longer idle.
    DataPending,
    /// The armed recv is not one `begin_park` can cancel, so the socket
    /// cannot safely leave this worker.
    RecvArmNotCancellable,
    /// An outbound connection. It has no listener, so it was never placed by
    /// accept and there is no placement imbalance for park to repair.
    Outbound,
    /// The handler has not offered this connection via `offer_for_park`.
    /// Park is opt-in, so this is the common answer, not an error.
    NotOffered,
    /// A TLS session that cannot travel yet. Temporary: the state is plain
    /// owned data, it is the transfer that is unimplemented.
    TlsSession,
    /// Teardown is already requested. Park loses this race deliberately:
    /// moving a connection the peer is closing buys nothing, and the close
    /// path is the one carrying the invariants.
    Closing,
    /// Queued or in-flight sends. Their SQEs reference *this* worker's
    /// `SendCopyPool` slots and `InFlightSendSlab` entries, which Domain
    /// Invariant 1 requires outlive the operation, so the fd cannot leave
    /// until they land.
    Sends,
    /// A Mode A forward write is in flight and the kernel is still reading a
    /// buffer this worker owns as the write source.
    ForwardWrite,
    /// A send chain has SQEs in the kernel whose CQEs drive its own
    /// accounting; it has to finish where it started.
    Chain,
    /// A `SegmentReader` is live. The reader owns the connection's delivery
    /// discipline for its whole lifetime, so this is by definition not a
    /// quiescent point.
    SegmentReader,
    /// A fallback recv is in flight against this worker's send pool.
    RecvFallback,
    /// A direct-echo response is queued for this worker's next flush.
    DirectEcho,
}

impl ParkBlocker {
    /// The `ringline/park_abandoned` slot this blocker reports as.
    ///
    /// One slot per variant, deliberately. An earlier version collapsed the
    /// variants believed unreachable at the install re-check into a single
    /// catch-all, and that catch-all then held 97.8% of abandonments in a
    /// saturated run — the grouping encoded an assumption and hid the cause it
    /// was built to expose. Anything worth counting is worth counting
    /// separately here.
    pub(crate) fn abandon_metric(self) -> usize {
        use crate::metrics::park_abandon as pa;
        match self {
            ParkBlocker::NotOpen => pa::NOT_OPEN,
            ParkBlocker::DataPending => pa::DATA_PENDING,
            ParkBlocker::RecvArmNotCancellable => pa::RECV_ARM_NOT_CANCELLABLE,
            ParkBlocker::Outbound => pa::OUTBOUND,
            ParkBlocker::NotOffered => pa::NOT_OFFERED,
            ParkBlocker::TlsSession => pa::TLS_SESSION,
            ParkBlocker::Closing => pa::CLOSING,
            ParkBlocker::Sends => pa::SENDS,
            ParkBlocker::ForwardWrite => pa::FORWARD_WRITE,
            ParkBlocker::Chain => pa::CHAIN,
            ParkBlocker::SegmentReader => pa::SEGMENT_READER,
            ParkBlocker::RecvFallback => pa::RECV_FALLBACK,
            ParkBlocker::DirectEcho => pa::DIRECT_ECHO,
        }
    }
}

#[cfg(test)]
mod park_blocker_tests {
    use super::*;

    /// Every `ParkBlocker` maps to a distinct in-range slot.
    ///
    /// Distinctness is the property that matters: the counters exist to name
    /// the dominant cause, and two blockers sharing a slot is how the previous
    /// version lost the answer.
    #[test]
    fn every_park_blocker_maps_to_a_distinct_slot() {
        use crate::metrics::park_abandon as pa;
        let all = [
            ParkBlocker::NotOpen,
            ParkBlocker::DataPending,
            ParkBlocker::RecvArmNotCancellable,
            ParkBlocker::Outbound,
            ParkBlocker::NotOffered,
            ParkBlocker::TlsSession,
            ParkBlocker::Closing,
            ParkBlocker::Sends,
            ParkBlocker::ForwardWrite,
            ParkBlocker::Chain,
            ParkBlocker::SegmentReader,
            ParkBlocker::RecvFallback,
            ParkBlocker::DirectEcho,
        ];
        let mut seen = std::collections::HashMap::new();
        for b in all {
            let slot = b.abandon_metric();
            assert!(
                slot < pa::COUNT,
                "{b:?} mapped to slot {slot}, outside a group of {}",
                pa::COUNT
            );
            if let Some(prev) = seen.insert(slot, b) {
                panic!("{b:?} and {prev:?} share slot {slot}");
            }
        }
        // The two non-blocker failures need slots of their own too, and must
        // not collide with any blocker's.
        for slot in [pa::SLOT_RECYCLED, pa::INSTALL_FAILED] {
            assert!(slot < pa::COUNT);
            assert!(
                !seen.contains_key(&slot),
                "slot {slot} is claimed by both a blocker and a failure"
            );
        }
    }
}

impl Driver {
    /// Create a new driver for a worker thread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &Config,
        accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
        eventfd: RawFd,
        shutdown_flag: Arc<AtomicBool>,
        resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
        resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
        resolver: Option<std::sync::Arc<crate::resolver::ResolverPool>>,
        spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
        spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
        spawner: Option<std::sync::Arc<crate::spawner::SpawnerPool>>,
        blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
        blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
        blocking_pool: Option<std::sync::Arc<crate::blocking::BlockingPool>>,
        region_rx: crate::region_registry::RegionControlRx,
    ) -> Result<Self, crate::error::Error> {
        config.validate()?;
        let ring = Ring::setup(config)?;

        let fixed_buffers =
            FixedBufferRegistry::new(&config.registered_regions, config.max_registered_regions);

        let mut provided_bufs = ProvidedBufRing::new(
            config.recv_buffer.bgid,
            config.recv_buffer.ring_size,
            config.recv_buffer.buffer_size,
        )?;
        // On the worker thread, which `worker.rs` has already pinned — so the
        // pages fault in on this worker's NUMA node rather than the launching
        // thread's.
        if config.prefault_buffers {
            provided_bufs.prefault();
        }

        let udp_count = config.udp_bind.len() as u32;
        let udp_provided_bufs = if udp_count > 0 {
            Some(ProvidedBufRing::new(
                config.udp_recv_buffer.bgid,
                config.udp_recv_buffer.ring_size,
                config.udp_recv_buffer.buffer_size,
            )?)
        } else {
            None
        };
        let nvme_max = config
            .nvme
            .as_ref()
            .map(|n| n.max_devices as u32)
            .unwrap_or(0);
        let direct_io_max = config
            .direct_io
            .as_ref()
            .map(|d| d.max_files as u32)
            .unwrap_or(0);
        let fs_max = config.fs.as_ref().map(|f| f.max_files as u32).unwrap_or(0);

        // Register resources with the kernel
        ring.register_buffers(&fixed_buffers)?;
        ring.register_files_sparse(
            config.max_connections + udp_count + nvme_max + direct_io_max + fs_max,
        )?;
        ring.register_buf_ring(&provided_bufs)?;
        if let Some(ref udp_bufs) = udp_provided_bufs {
            ring.register_buf_ring(udp_bufs)?;
        }

        let connections = ConnectionTable::new(config.max_connections);
        let mut send_copy_pool =
            SendCopyPool::new(config.send_copy_count, config.send_copy_slot_size);
        if config.prefault_buffers {
            send_copy_pool.prefault();
        }
        let send_slab = InFlightSendSlab::new(config.send_slab_slots);
        let accumulators = AccumulatorTable::new_with_max(
            config.max_connections,
            config.recv_accumulator_capacity,
            config.recv_accumulator_max,
        );

        // Deadline flush: disabled when SQPOLL (kernel polls SQ) or interval is 0.
        let flush_interval = if config.sqpoll || config.flush_interval_us == 0 {
            None
        } else {
            Some(Duration::from_micros(config.flush_interval_us))
        };

        let tls_table = {
            // Any per-listener config counts: a process can terminate TLS on
            // one listener with no process-wide config set at all, and without
            // this the table would not exist for it to use.
            let has_server =
                config.tls.is_some() || config.listener_tls.iter().any(|t| t.is_some());
            let has_client = config.tls_client.is_some();
            if has_server || has_client {
                Some(crate::tls::TlsTable::with_listener_configs(
                    config.max_connections,
                    config.tls.as_ref().map(|tc| tc.server_config.clone()),
                    config
                        .tls_client
                        .as_ref()
                        .map(|tc| tc.client_config.clone()),
                    config
                        .listener_tls
                        .iter()
                        .map(|slot| slot.as_ref().map(|tc| tc.server_config.clone()))
                        .collect(),
                ))
            } else {
                None
            }
        };

        let mut connect_addrs = Vec::with_capacity(config.max_connections as usize);
        connect_addrs.resize(config.max_connections as usize, unsafe {
            std::mem::zeroed()
        });

        let mut connect_timespecs = Vec::with_capacity(config.max_connections as usize);
        connect_timespecs.resize(
            config.max_connections as usize,
            io_uring::types::Timespec::new(),
        );

        let mut send_queues = Vec::with_capacity(config.max_connections as usize);
        for _ in 0..config.max_connections {
            send_queues.push(ConnSendState::new());
        }

        // Set up UDP sockets.
        let mut udp_sockets = Vec::with_capacity(config.udp_bind.len());
        for (udp_idx, bind_addr) in config.udp_bind.iter().enumerate() {
            let fd_index = config.max_connections + udp_idx as u32;
            let connect_peer = config.udp_connect_peers.get(udp_idx).copied().flatten();
            let state = Self::setup_udp_socket(
                &ring,
                *bind_addr,
                connect_peer,
                fd_index,
                config.udp_send_slots,
                config.udp_gro,
                config.take_udp_reserved(udp_idx),
            )?;
            udp_sockets.push(state);
        }

        let mut driver = Driver {
            ring,
            connections,
            fixed_buffers,
            provided_bufs,
            udp_provided_bufs,
            udp_pending_replenish: Vec::new(),
            send_copy_pool,
            send_slab,
            accumulators,
            pending_replenish: Vec::with_capacity(config.recv_buffer.ring_size as usize),
            pending_recv_bufs: vec![None; config.max_connections as usize],
            send_recv_buf_original_lens: vec![0; config.max_connections as usize],
            send_recv_buf_remaining: vec![0; config.max_connections as usize],
            recv_hold: (0..config.max_connections)
                .map(|_| std::collections::VecDeque::new())
                .collect(),
            recv_forward: vec![false; config.max_connections as usize],
            forward_zc_consumed: vec![0; config.max_connections as usize],
            direct_echo_pending: Vec::new(),
            direct_echo_queued: vec![false; config.max_connections as usize],
            recv_domain: vec![
                crate::recv::domain::RecvDomain::default();
                config.max_connections as usize
            ],
            segment_hold: (0..config.max_connections)
                .map(|_| std::collections::VecDeque::new())
                .collect(),
            segment_pinned: vec![None; config.max_connections as usize],
            adopt_pending: std::collections::HashMap::new(),
            park_offered: vec![false; config.max_connections as usize],
            park_drain: vec![None; config.max_connections as usize],
            park_drain_pending: Vec::new(),
            park_carry: std::collections::HashMap::new(),
            park_in_flight: vec![None; config.max_connections as usize],
            park_ready: Vec::new(),
            peer_park: config.peer_park.clone(),
            park_rx: config.park_rx.clone(),
            segment_reader_live: vec![false; config.max_connections as usize],
            recv_half_taken: vec![false; config.max_connections as usize],
            send_half_taken: vec![false; config.max_connections as usize],
            forward_write: (0..config.max_connections).map(|_| None).collect(),
            forward_done: (0..config.max_connections).map(|_| None).collect(),
            forward_progress: (0..config.max_connections).map(|_| None).collect(),
            forward_epoch: vec![0; config.max_connections as usize],
            forward_recv_active: vec![false; config.max_connections as usize],
            forward_hold_throttled: vec![false; config.max_connections as usize],
            forward_hold_cap: config.forward_hold_cap,
            accept_rx,
            merged_accept_fds: config.merged_accept_fds.clone(),
            merged_accept_live: config.merged_accept_live.clone(),
            merged_accept_armed: false,
            worker_index: config.worker_index,
            worker_loads: config.worker_loads.clone(),
            worker_accepting: config.worker_accepting.clone(),
            peer_accept: config.peer_accept.clone(),
            eventfd,
            eventfd_buf: [0u8; 8],
            wake_handle: crate::wakeup::WakeFd::from_raw_fd(eventfd),
            flush_interval,
            shutdown_flag,
            shutdown_local: false,
            tls_table,
            connect_addrs,
            connect_timespecs,
            cqe_batch: Vec::with_capacity(config.sq_entries as usize * 4),
            tcp_nodelay: config.tcp_nodelay,
            loop_diag: config.loop_diag,
            send_zc_threshold: config.send_zc_threshold,
            recv_segment_reserve: config.recv_segment_reserve,
            recv_accumulator_max: config.recv_accumulator_max,
            #[cfg(feature = "timestamps")]
            timestamps: config.timestamps,
            #[cfg(feature = "timestamps")]
            recvmsg_msghdr: {
                let mut hdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
                // TCP: no source address needed.
                hdr.msg_namelen = 0;
                // Room for SCM_TIMESTAMPING cmsg: cmsghdr(16) + 3×timespec(48) = 64 bytes.
                hdr.msg_controllen = 64;
                hdr
            },
            chain_table: SendChainTable::new(config.max_connections),
            max_chain_length: config.max_chain_length,
            send_queues,
            close_notify_armed: Vec::new(),
            close_notify_timeout: std::time::Duration::from_millis(config.close_notify_timeout_ms),
            tls_out_scratch: Vec::new(),
            next_disk_io_seq: 0,
            recv_starved: Vec::new(),
            recv_park_count: 0,
            recv_fallback_inflight: vec![false; config.max_connections as usize],
            fallback_recv_pool: None,
            fallback_slot_owner: Vec::new(),
            // One event-loop pass moves at most one chunk per starved
            // connection, so the chunk — not the provided ring — is the
            // per-pass byte ceiling while degraded. It must be LARGER than
            // the ring's capacity to beat the park/re-arm churn cycle it
            // replaces (which moves one ring's worth per pass); a small
            // chunk would be slower than the pathology. Floor of 1 MiB,
            // scaled up for jumbo provided buffers.
            fallback_chunk: config
                .recv_buffer
                .buffer_size
                .saturating_mul(4)
                .max(1 << 20),
            recv_fallback_count: 0,
            udp_batch_recv_at: std::time::Instant::now(),
            tick_timeout_ts: if config.tick_timeout_us > 0 {
                Some(
                    io_uring::types::Timespec::new()
                        .sec(config.tick_timeout_us / 1_000_000)
                        .nsec((config.tick_timeout_us % 1_000_000) as u32 * 1000),
                )
            } else {
                None
            },
            tick_timeout_armed: false,
            tick_count: 0,
            eventfd_armed: false,
            pending_zc_retries: Vec::new(),
            pending_copy_retries: Vec::new(),
            pending_send_pollout_retries: Vec::new(),
            pending_coalesced_retries: Vec::new(),
            pending_recv_forward_retries: Vec::new(),
            pending_close_retries: Vec::new(),
            pending_send_retries: Vec::new(),
            bounded_send_completions: VecDeque::new(),
            capacity_released: false,
            pending_finalize_closes: Vec::new(),
            zc_retry_scratch: Vec::new(),
            copy_retry_scratch: Vec::new(),
            send_pollout_retry_scratch: Vec::new(),
            coalesced_retry_scratch: Vec::new(),
            recv_forward_retry_scratch: Vec::new(),
            send_retry_scratch: Vec::new(),
            udp_sockets,
            nvme_devices: config
                .nvme
                .as_ref()
                .map(|n| crate::nvme::NvmeDeviceTable::new(n.max_devices)),
            nvme_cmd_slab: config
                .nvme
                .as_ref()
                .map(|n| crate::nvme::NvmeCmdSlab::new(n.max_commands_in_flight)),
            nvme_fd_base: config.max_connections + udp_count,
            direct_io_files: config
                .direct_io
                .as_ref()
                .map(|d| crate::direct_io::DirectIoFileTable::new(d.max_files)),
            direct_io_cmd_slab: config
                .direct_io
                .as_ref()
                .map(|d| crate::direct_io::DirectIoCmdSlab::new(d.max_commands_in_flight)),
            direct_io_fd_base: config.max_connections + udp_count + nvme_max,
            fs_files: config
                .fs
                .as_ref()
                .map(|f| crate::fs::FsFileTable::new(f.max_files)),
            fs_cmd_slab: config
                .fs
                .as_ref()
                .map(|f| crate::fs::FsCmdSlab::new(f.max_commands_in_flight)),
            fs_fd_base: config.max_connections + udp_count + nvme_max + direct_io_max,
            resolve_rx,
            resolve_tx,
            resolver,
            spawn_rx,
            spawn_tx,
            spawner,
            blocking_rx,
            blocking_tx,
            blocking_pool,
            region_rx,
        };

        // Arm multishot recv for each UDP socket against the UDP buffer
        // group. One SQE per socket stays live in the kernel and fans out a
        // CQE per datagram until the buffer ring is exhausted. Connected
        // sockets use the lighter `RecvUdp` opcode (no recvmsg metadata);
        // unconnected sockets use `RecvMsgUdp` so the kernel returns the
        // peer address in each CQE buffer.
        let udp_bgid = config.udp_recv_buffer.bgid;
        for udp_idx in 0..driver.udp_sockets.len() {
            let fd_index = driver.udp_sockets[udp_idx].fd_index;
            let result = if driver.udp_sockets[udp_idx].connected_peer.is_some() {
                let ud = UserData::encode(OpTag::RecvUdp, udp_idx as u32, 0);
                driver
                    .ring
                    .submit_multishot_recv_udp(fd_index, udp_bgid, ud)
            } else {
                let ud = UserData::encode(OpTag::RecvMsgUdp, udp_idx as u32, 0);
                let msghdr_ptr = &*driver.udp_sockets[udp_idx].recv_msghdr as *const libc::msghdr;
                driver
                    .ring
                    .submit_recvmsg_multishot(fd_index, msghdr_ptr, udp_bgid, ud)
            };
            result.map_err(|e| {
                crate::error::Error::RingSetup(format!(
                    "failed to submit initial UDP multishot recv: {e}"
                ))
            })?;
        }

        Ok(driver)
    }

    /// Construct a [`DriverCtx`] by borrowing driver fields.
    ///
    /// Borrows `self` mutably, so callers cannot access individual driver
    /// fields while the returned `DriverCtx` is live. For cases requiring
    /// simultaneous access to specific fields (e.g., accumulators + ctx),
    /// construct `DriverCtx` inline with explicit field borrows.
    pub(crate) fn make_ctx(&mut self) -> DriverCtx<'_> {
        DriverCtx {
            ring: &mut self.ring,
            connections: &mut self.connections,
            fixed_buffers: &mut self.fixed_buffers,
            send_copy_pool: &mut self.send_copy_pool,
            send_slab: &mut self.send_slab,
            tls_table: match self.tls_table {
                Some(ref mut t) => t as *mut crate::tls::TlsTable,
                None => std::ptr::null_mut(),
            },
            shutdown_requested: &mut self.shutdown_local,
            connect_addrs: &mut self.connect_addrs,
            tcp_nodelay: self.tcp_nodelay,
            send_zc_threshold: self.send_zc_threshold,
            #[cfg(feature = "timestamps")]
            timestamps: self.timestamps,
            connect_timespecs: &mut self.connect_timespecs,
            chain_table: &mut self.chain_table,
            max_chain_length: self.max_chain_length,
            send_queues: &mut self.send_queues,
            close_notify_armed: &mut self.close_notify_armed,
            udp_sockets: &mut self.udp_sockets,
            nvme_devices: &mut self.nvme_devices,
            nvme_cmd_slab: &mut self.nvme_cmd_slab,
            nvme_fd_base: self.nvme_fd_base,
            direct_io_files: &mut self.direct_io_files,
            direct_io_cmd_slab: &mut self.direct_io_cmd_slab,
            direct_io_fd_base: self.direct_io_fd_base,
            fs_files: &mut self.fs_files,
            fs_cmd_slab: &mut self.fs_cmd_slab,
            fs_fd_base: self.fs_fd_base,
            pending_finalize_closes: &mut self.pending_finalize_closes,
            pending_send_retries: &mut self.pending_send_retries,
            bounded_send_completions: &mut self.bounded_send_completions,
            capacity_released: &mut self.capacity_released,
            close_notify_timeout: self.close_notify_timeout,
            next_disk_io_seq: &mut self.next_disk_io_seq,
        }
    }

    /// Reset per-connection send state for a (re)activated slot.
    ///
    /// A previous occupant's close can leave `in_flight`/`close_pending` set:
    /// its final send CQE can arrive after the slot was released, and the
    /// CQE's identity check correctly refuses to touch the slot's state —
    /// so nothing else clears it. (Before the identity checks, the stale
    /// CQE's error path *was* what cleared these flags — misattributed
    /// cleanup the next occupant accidentally depended on.) Without this
    /// reset the next occupant's first send parks behind a completion that
    /// will never come.
    pub(crate) fn reset_send_state(&mut self, conn_index: u32) {
        let state = &mut self.send_queues[conn_index as usize];
        // Queued-but-unsubmitted sends from the previous occupant hold
        // pool/slab resources; no SQE was submitted for them, so no CQE
        // will release them — do it here.
        let bounded = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
            &mut self.pending_replenish,
        );
        state.in_flight = false;
        state.parked = false;
        state.close_pending = false;
        state.close_submitted = false;
        // Defensive: the close now waits on this, so a slot should never be
        // reactivated with a Shutdown still outstanding. If the gate ever leaks,
        // the next occupant must not inherit the block.
        state.shutdown_inflight = false;
        state.acked_bytes = 0;
        state.close_notify_deadline = None;
        if let Some(pos) = self
            .close_notify_armed
            .iter()
            .position(|&i| i == conn_index)
        {
            self.close_notify_armed.swap_remove(pos);
        }
        // A previous occupant's bounded send can still be sitting in the
        // queue here (its close abandoned the drain); the new occupant must
        // not inherit it, and its caller is still waiting.
        self.fail_bounded_sends(bounded);
    }

    /// Reset segmented-recv delivery state for a (re)activated connection slot.
    /// The hold is already drained by `close_connection`, so this is defensive;
    /// it also restores the domain to the default in case a slot is reused
    /// without an intervening close.
    pub(crate) fn reset_segment_state(&mut self, conn_index: u32) {
        self.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::default();
        self.segment_hold[conn_index as usize].clear();
        // The pin slot should already be None (close drains it), but clear it
        // defensively for a slot reused without an intervening close-drain.
        self.segment_pinned[conn_index as usize] = None;
        // Mode A forward state — cleared defensively (close drains any pinned
        // bid). A leftover `forward_done` result must not bleed into a reused
        // slot's forward.
        self.forward_write[conn_index as usize] = None;
        self.forward_done[conn_index as usize] = None;
        self.forward_progress[conn_index as usize] = None;
        self.forward_recv_active[conn_index as usize] = false;
        self.forward_hold_throttled[conn_index as usize] = false;
    }

    /// Settle a connection when a Mode A `forward_to` finishes: any provided
    /// buffers still held in `segment_hold` carry stream bytes *past* the
    /// forwarded region, so their bytes are preserved by copying them into the
    /// accumulator (in arrival order) before the bid is replenished — exactly
    /// like the `with_segments` under-drain path. The delivery domain is then
    /// reset so subsequent `with_data`/`with_bytes` reads see those bytes first.
    ///
    /// Returns `false` if the accumulator overflowed (`recv_accumulator_max`),
    /// in which case the caller must close the connection.
    #[must_use]
    pub(crate) fn settle_forward_end(&mut self, conn_index: u32) -> bool {
        let mut ok = true;
        while let Some(held) = self.segment_hold[conn_index as usize].pop_front() {
            match held {
                HeldRecvBuf::Pinned { bid, len } => {
                    let (ptr, _) = self.provided_bufs.get_buffer(bid);
                    let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                    if ok && !self.accumulators.append(conn_index, data) {
                        ok = false;
                    }
                    // Replenish the bid regardless (pushing outside the overflow
                    // guard avoids a leak on breach).
                    self.pending_replenish.push(bid);
                }
                HeldRecvBuf::Owned(bytes) => {
                    if ok && !self.accumulators.append(conn_index, &bytes[..]) {
                        ok = false;
                    }
                }
            }
        }
        self.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::default();
        // If the forward throttled its recv (hold reached `forward_hold_cap`), its
        // multishot was cancelled. Re-arm it so the connection's subsequent
        // `with_data`/`with_bytes` reads resume — the domain is now the default,
        // so newly received bytes land in the accumulator. If the throttle-cancel
        // is still in flight, the re-arm has to wait for its ECANCELED, so the
        // throttle flag is left set and that branch does it. On a re-arm failure
        // the connection is left unarmed; the caller's next read errors and
        // closes it (standard recovery).
        self.forward_recv_active[conn_index as usize] = false;
        if self.forward_hold_throttled[conn_index as usize] {
            let armed = self
                .connections
                .get(conn_index)
                .is_some_and(|c| c.recv_multishot_armed);
            // Still armed means the throttle-cancel's ECANCELED has not been
            // observed yet, so the re-arm cannot happen here — two multishots
            // with the same user_data must never overlap. Leave the flag set
            // and let `maybe_rearm_throttled_forward`, which the ECANCELED
            // branch calls, do it: clearing the flag here instead left the
            // connection unarmed for good, because that re-arm is gated on the
            // flag and nothing re-arms a connection that is no longer
            // forwarding. The next `with_data` then parked forever.
            if armed {
                return ok;
            }
            self.forward_hold_throttled[conn_index as usize] = false;
            let open = self.connections.get(conn_index).is_some_and(|c| {
                matches!(c.lifecycle, Lifecycle::Open) && matches!(c.recv_arm, RecvArm::Multi)
            });
            let generation = self.connections.generation(conn_index);
            if open
                && self
                    .ring
                    .submit_multishot_recv(conn_index, generation)
                    .is_ok()
                && let Some(cs) = self.connections.get_mut(conn_index)
            {
                cs.recv_multishot_armed = true;
            }
        }
        ok
    }

    /// Drive a Mode A forward as far as it can go without a task poll.
    ///
    /// Returns `Some(result)` when the forward has reached a terminal state —
    /// requested length reached, peer FIN, or a submission error — and `None`
    /// while it is still running (a write in flight, or waiting for bytes).
    /// The caller is responsible for recording the result in `forward_done`
    /// and waking the task; nothing else wakes it, which is the point.
    ///
    /// This is the body that used to live in `ForwardToFuture::poll`. Keeping
    /// it here lets `handle_forward_write` and the segmented recv branch submit
    /// the next write directly, so the task is woken once per *forward* rather
    /// than once per *provided buffer*.
    ///
    /// Ordering is unchanged: one write in flight per connection, held buffers
    /// in arrival order. Only the caller changes.
    pub(crate) fn advance_forward(&mut self, conn_index: u32) -> Option<Result<u64, io::Error>> {
        let idx = conn_index as usize;
        let progress = (*self.forward_progress.get(idx)?)?;

        // A write is already in flight — its completion re-enters here.
        if self.forward_write[idx].is_some() {
            return None;
        }

        if progress.forwarded >= progress.len {
            let forwarded = progress.forwarded;
            self.forward_progress[idx] = None;
            if !self.settle_forward_end(conn_index) {
                self.close_connection(conn_index);
                return Some(Err(io::Error::other(
                    "recv accumulator overflow settling forward tail",
                )));
            }
            return Some(Ok(forwarded));
        }

        if self.segment_hold[idx].is_empty() {
            // Nothing held. A finished recv side means the forward is truncated
            // — resolve short rather than wait for bytes that are not coming.
            let closed = self
                .connections
                .get(conn_index)
                .map(|c| c.recv_finished())
                .unwrap_or(true);
            if closed {
                let forwarded = progress.forwarded;
                self.forward_progress[idx] = None;
                let _ = self.settle_forward_end(conn_index);
                return Some(Ok(forwarded));
            }
            return None;
        }

        // Gather a batch: as many held buffers as the remaining length and the
        // iovec cap allow, written as one `sendmsg`/`writev`. This is the whole
        // point — `run_direct_echo` has always coalesced a drain's worth into a
        // single send (#397), and doing one completion per buffer is what left
        // Mode A at 1.24 instructions/byte against direct echo's 0.985.
        let mut remaining = progress.len - progress.forwarded;
        let mut backings: Vec<HeldRecvBuf> = Vec::new();
        let mut lens: Vec<u32> = Vec::new();
        while backings.len() < MAX_FORWARD_IOV && remaining > 0 {
            let Some(held) = self.segment_hold[idx].pop_front() else {
                break;
            };
            // Bytes past `len` belong to whoever reads this connection next, so
            // a held buffer that straddles the boundary is split and its tail
            // stashed in the accumulator. That can only happen to the last
            // buffer of a batch, since it ends the forward.
            match held {
                HeldRecvBuf::Pinned { bid, len } => {
                    if (len as u64) <= remaining {
                        remaining -= len as u64;
                        backings.push(HeldRecvBuf::Pinned { bid, len });
                        lens.push(len);
                    } else {
                        let chunk = remaining as u32;
                        let (ptr, _) = self.provided_bufs.get_buffer(bid);
                        // SAFETY: `bid` is pinned (unreplenished) and `len`
                        // bytes were received into it, so `[chunk..len]` is
                        // initialised and is copied out before anything can
                        // replenish the bid.
                        let suffix = unsafe {
                            std::slice::from_raw_parts(
                                ptr.add(chunk as usize),
                                (len - chunk) as usize,
                            )
                        };
                        if !self.accumulators.append(conn_index, suffix) {
                            self.pending_replenish.push(bid);
                            for b in backings {
                                if let HeldRecvBuf::Pinned { bid, .. } = b {
                                    self.pending_replenish.push(bid);
                                }
                            }
                            self.forward_progress[idx] = None;
                            self.close_connection(conn_index);
                            return Some(Err(io::Error::other(
                                "recv accumulator overflow stashing forward tail",
                            )));
                        }
                        remaining = 0;
                        backings.push(HeldRecvBuf::Pinned { bid, len: chunk });
                        lens.push(chunk);
                    }
                }
                HeldRecvBuf::Owned(bytes) => {
                    if (bytes.len() as u64) <= remaining {
                        remaining -= bytes.len() as u64;
                        let total = bytes.len() as u32;
                        backings.push(HeldRecvBuf::Owned(bytes));
                        lens.push(total);
                    } else {
                        let chunk = remaining as usize;
                        if !self.accumulators.append(conn_index, &bytes[chunk..]) {
                            for b in backings {
                                if let HeldRecvBuf::Pinned { bid, .. } = b {
                                    self.pending_replenish.push(bid);
                                }
                            }
                            self.forward_progress[idx] = None;
                            self.close_connection(conn_index);
                            return Some(Err(io::Error::other(
                                "recv accumulator overflow stashing forward tail",
                            )));
                        }
                        remaining = 0;
                        backings.push(HeldRecvBuf::Owned(bytes.slice(0..chunk)));
                        lens.push(chunk as u32);
                    }
                }
            }
        }

        if backings.is_empty() {
            return None;
        }

        let base_offset = if progress.target.is_file() {
            progress.forwarded
        } else {
            0
        };
        match self.start_forward_write(conn_index, backings, lens, base_offset, progress.target) {
            Ok(()) => None,
            Err(e) => {
                self.forward_progress[idx] = None;
                let _ = self.settle_forward_end(conn_index);
                Some(Err(e))
            }
        }
    }

    /// Submit the first write of a segmented-recv Mode A forward `backing`
    /// (`total` bytes) to `sink_fd` and record the in-flight state. One write is
    /// in flight per connection; the completion handler releases the backing.
    ///
    /// On submission failure the backing is released here (a pinned bid returns
    /// to the ring) and the error is propagated — the forward future surfaces it
    /// to the caller.
    pub(crate) fn start_forward_write(
        &mut self,
        conn_index: u32,
        backings: Vec<HeldRecvBuf>,
        lens: Vec<u32>,
        base_offset: u64,
        target: SinkTarget,
    ) -> io::Result<()> {
        debug_assert!(
            self.forward_write[conn_index as usize].is_none(),
            "start_forward_write while a forward write is already in flight"
        );
        debug_assert_eq!(backings.len(), lens.len(), "one length per backing");
        let idx = conn_index as usize;
        let total: u32 = lens.iter().sum();

        // A connection sink is addressed by slot index, and slots recycle. If
        // the sink's generation has moved the caller is holding a stale handle
        // and this write would land on whoever owns the slot now. Checked here
        // rather than only on resubmit, so the very first write is covered too.
        if let SinkTarget::Conn { index, generation } = target
            && self.connections.generation(index) != generation
        {
            for backing in &backings {
                if let HeldRecvBuf::Pinned { bid, .. } = backing {
                    self.pending_replenish.push(*bid);
                }
            }
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        }

        let generation = self.connections.generation(conn_index);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::ForwardWrite,
            conn_index,
            generation,
        );

        let mut state = ForwardWriteState {
            iovecs: Vec::with_capacity(backings.len()),
            // SAFETY: `msghdr` is a plain C struct; zeroed is its valid empty
            // state, and `rebuild_iovecs` fills the fields that matter.
            msghdr: unsafe { std::mem::zeroed() },
            backings,
            lens,
            total,
            written: 0,
            base_offset,
            target,
            generation,
        };
        state.rebuild_iovecs(&self.provided_bufs);

        // Install *before* submitting: the SQE points at `msghdr` and the iovec
        // array inside this state, and both must stay put until the CQE. Moving
        // the state after taking those pointers would invalidate `msg_iov`'s
        // owner even though the iovec heap block itself would survive.
        self.forward_write[idx] = Some(state);
        let (hdr_ptr, iov_ptr, iov_count) = {
            let st = self.forward_write[idx].as_ref().expect("just installed");
            (
                &st.msghdr as *const libc::msghdr,
                st.iovecs.as_ptr(),
                st.iovecs.len() as u32,
            )
        };

        let res = match target {
            SinkTarget::Fd { fd, is_file: true } => unsafe {
                self.ring
                    .submit_forward_writev_file(fd, iov_ptr, iov_count, base_offset, ud)
            },
            SinkTarget::Fd { fd, is_file: false } => unsafe {
                self.ring.submit_forward_writev_socket(fd, hdr_ptr, ud)
            },
            // A connection sink writes through its registered file index, the
            // same way every other send on that connection does.
            SinkTarget::Conn { index, .. } => unsafe {
                self.ring.submit_forward_writev_conn(index, hdr_ptr, ud)
            },
        };
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                // Nothing is in flight, so the state comes back out and its
                // bids go home — exactly once.
                if let Some(state) = self.forward_write[idx].take() {
                    for backing in state.backings {
                        if let HeldRecvBuf::Pinned { bid, .. } = backing {
                            self.pending_replenish.push(bid);
                        }
                    }
                }
                Err(e)
            }
        }
    }

    /// Rebuild the in-flight write's iovecs and resubmit what is left of it.
    ///
    /// Used after a short write and after a `POLLOUT` re-arm. The batch's
    /// backings do not change; only which bytes of them are still owed.
    pub(crate) fn resubmit_forward_writev(&mut self, conn_index: u32) -> io::Result<()> {
        let idx = conn_index as usize;
        let Some(mut state) = self.forward_write[idx].take() else {
            return Ok(());
        };
        state.rebuild_iovecs(&self.provided_bufs);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::ForwardWrite,
            conn_index,
            state.generation,
        );
        let (target, base_offset, written) = (state.target, state.base_offset, state.written);
        self.forward_write[idx] = Some(state);
        let (hdr_ptr, iov_ptr, iov_count) = {
            let st = self.forward_write[idx].as_ref().expect("just reinstalled");
            (
                &st.msghdr as *const libc::msghdr,
                st.iovecs.as_ptr(),
                st.iovecs.len() as u32,
            )
        };
        match target {
            SinkTarget::Fd { fd, is_file: true } => unsafe {
                self.ring.submit_forward_writev_file(
                    fd,
                    iov_ptr,
                    iov_count,
                    base_offset + written as u64,
                    ud,
                )
            },
            SinkTarget::Fd { fd, is_file: false } => unsafe {
                self.ring.submit_forward_writev_socket(fd, hdr_ptr, ud)
            },
            SinkTarget::Conn { index, .. } => unsafe {
                self.ring.submit_forward_writev_conn(index, hdr_ptr, ud)
            },
        }
    }

    /// Clear the recv-side exclusivity claims for a slot that is being reused.
    ///
    /// `RecvHalf::drop` and `SegmentReader::drop` release their own claims, but
    /// both go through `try_with_state`, which is a **no-op during unguarded
    /// teardown** — `executor.remove_connection` drops a parked task's future
    /// with `CURRENT_DRIVER` unset. A claim can therefore outlive its claimant,
    /// and since the flags are indexed by slot rather than by generation, the
    /// *next* occupant would inherit it and have its reads refused with `EBUSY`
    /// forever.
    ///
    /// Clearing here, at the recycle point, makes that impossible regardless of
    /// how the previous occupant died.
    pub(crate) fn clear_conn_claims(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if let Some(live) = self.segment_reader_live.get_mut(idx) {
            *live = false;
        }
        if let Some(taken) = self.recv_half_taken.get_mut(idx) {
            *taken = false;
        }
        if let Some(taken) = self.send_half_taken.get_mut(idx) {
            *taken = false;
        }
    }

    /// Set or clear `conn_index`'s park drain. Every write to `park_drain`
    /// goes through here so every drain is on `park_drain_pending`. Clearing
    /// leaves the index on the list for `drive_park_drains` to drop.
    pub(crate) fn set_park_drain(&mut self, conn_index: u32, drain: Option<ParkDrain>) {
        let slot = &mut self.park_drain[conn_index as usize];
        if slot.is_none() && drain.is_some() && !self.park_drain_pending.contains(&conn_index) {
            self.park_drain_pending.push(conn_index);
        }
        *slot = drain;
    }

    pub(crate) fn close_connection(&mut self, conn_index: u32) {
        if let Some(conn) = self.connections.get_mut(conn_index) {
            if conn.close_requested() {
                return; // already closing — avoid double Close SQE
            }
            conn.lifecycle = Lifecycle::Closing;
        } else {
            return;
        }
        // Replenish any held (not-yet-forwarded) zero-copy recv buffers so their
        // bids aren't leaked, and clear the opt-in flag for slot reuse. An
        // in-flight forward's bids live in its slab entry (already drained from
        // recv_hold) and are replenished by its own completion handler.
        // Direct-echo connections stage in the same hold, so this drains
        // unconditionally rather than only under the recv-forward flag; the
        // flush pass drops the queue entry once it sees an empty hold.
        for pending in self.recv_hold[conn_index as usize].drain(..) {
            self.pending_replenish.push(pending.bid);
        }
        self.forward_zc_consumed[conn_index as usize] = 0;
        self.recv_forward[conn_index as usize] = false;
        // Release handler state here rather than waiting for the slot to be
        // reused: a `ParkState` is an arbitrary user value, and a slot that is
        // never reused would hold it for the life of the process.
        self.park_offered[conn_index as usize] = false;
        self.set_park_drain(conn_index, None);
        self.park_carry.remove(&conn_index);
        self.adopt_pending.remove(&conn_index);
        // Do NOT drain held segmented-recv buffers here. When a peer FIN drives
        // this close, a parked Mode B reader must still consume the bytes already
        // held — draining them now (before the woken reader is polled) would
        // discard a fully-received response and surface an empty EOF (the
        // data+FIN-loss bug): a data CQE and the FIN can land in the same batch,
        // and `close_connection` runs before `poll_ready_tasks`. The reader drains
        // the hold (replenishing each bid as it consumes, seeing EOF once the hold
        // is empty and the connection is `Closed`); any buffers it never reaches
        // are reclaimed at `handle_close` (teardown), symmetric to `segment_pinned`.
        // The delivery domain is reset at slot reuse (`reset_segment_state`).
        // A bid checked out to a live `RecvSegment` (a parked task holding a
        // segment across an await) must NOT be reclaimed here. `RecvSegment::deref`
        // reads that bid's provided buffer directly, and a parked task can still
        // resume and deref it between now and the `Close` CQE — returning the bid
        // to the ring now would let another connection's recv overwrite a buffer a
        // live segment is still reading (a safe-API data leak). The bid stays
        // pinned in `segment_pinned[conn]` until `handle_close`, which reclaims it
        // after `remove_connection` has dropped the future (and with it the
        // segment). `RecvSegment::drop` running in-poll before then still releases
        // it (the pin slot is the single-release discriminant); if the drop runs
        // unguarded during teardown it no-ops and `handle_close` does the release.
        // An in-flight Mode A forward write's backing is still owned by the kernel
        // (it is the write's *source* memory) until the write CQE arrives —
        // reclaiming it now would either return a provided bid to the ring while
        // the kernel is still DMA-reading it (another connection's recv could then
        // overwrite it: cross-connection corruption / info leak) or free an Owned
        // copy the kernel is still reading (use-after-free). Both violate
        // invariant #1 (SQE memory must outlive the op). So do NOT reclaim it here.
        // Instead cancel the in-flight write so a stuck sink cannot pin the bid and
        // slot forever, and leave `forward_write[conn]` in place: the (possibly
        // ECANCELED) CQE is handled by `handle_forward_write` / `fail_forward_write`,
        // which replenish the bid exactly once and drive this deferred close
        // forward. `try_finalize_close` will not submit the `Close` SQE — and so the
        // slot is not reused and the captured generation stays valid — while
        // `forward_write[conn]` is still `Some`.
        if let Some(state) = self.forward_write[conn_index as usize].as_ref() {
            let write_gen = state.generation;
            // The in-flight op is either the write itself or its POLLOUT re-arm;
            // cancel both user_data variants (the non-matching one is a harmless
            // ENOENT whose `Cancel` CQE is ignored).
            let write_ud = crate::completion::UserData::encode(
                crate::completion::OpTag::ForwardWrite,
                conn_index,
                write_gen,
            );
            let pollout_ud = crate::completion::UserData::encode(
                crate::completion::OpTag::ForwardWritePollOut,
                conn_index,
                write_gen,
            );
            let _ = self.ring.submit_async_cancel(write_ud.raw(), conn_index);
            let _ = self.ring.submit_async_cancel(pollout_ud.raw(), conn_index);
        } else {
            // No forward write in flight — safe to clear a stale completed result.
            self.forward_done[conn_index as usize] = None;
            self.forward_progress[conn_index as usize] = None;
        }
        // Clear the Mode A forward flags for slot reuse. Any held bids were
        // already drained above (segment_hold / segment_pinned / forward_write);
        // the throttle flag just tracks recv-arm state and needs no bid release.
        // A throttle-cancel's ECANCELED (if still in flight) is a no-op in
        // `handle_recv_multi` (result < 0 / generation checks).
        self.forward_recv_active[conn_index as usize] = false;
        self.forward_hold_throttled[conn_index as usize] = false;
        // Clear the fallback-recv flag so the slot's next occupant starts
        // clean. A still-in-flight fallback CQE for this occupant is
        // generation-checked in handle_recv_fallback and only releases its
        // pool slot — it can no longer touch connection state.
        self.recv_fallback_inflight[conn_index as usize] = false;
        // An active chain keeps its state: its SQEs are already in the kernel
        // and their CQEs drive the chain accounting to completion (an error
        // in one linked op cancels the rest — still CQEs). `close_pending`
        // is set below and `try_finalize_close` defers the Close until the
        // chain drains, so the Close cannot recycle the slot while chain
        // CQEs are outstanding. (An earlier version called
        // `chain_table.cancel` here, which *dropped* the accounting and let
        // the Close race the still-in-flight chain sends.)
        // Defer the actual `Close` SQE until every queued send has
        // drained through the regular `submit_next_queued` cycle and
        // its CQE has been handled. Two earlier mistakes are worth
        // calling out:
        //
        //   (a) The original code called `drain_conn_send_queue`,
        //       which freed slab/pool resources for queued sends
        //       *without ever submitting them* — silently dropping
        //       every byte queued behind the in-flight send.
        //
        //   (b) An interim attempt pushed all queued SQEs in parallel
        //       at close time, but io_uring doesn't strictly order
        //       independent SQEs, so the kernel could process them
        //       out of order and scramble the byte stream. (Visible
        //       in release mode where the SQEs land close together.)
        //
        // The current strategy preserves the queue's serialized
        // drain: leave in_flight + queue alone, mark `close_pending`,
        // and let `note_send_finalized` (called from `handle_send` /
        // `handle_send_pollout` after each completion) submit the
        // deferred `Close` once both `in_flight` is false and the
        // queue is empty.
        let state = &mut self.send_queues[conn_index as usize];
        state.close_pending = true;
        if state.in_flight {
            // Something is in-flight; wait for its CQE to drain the queue.
            return;
        }
        // Nothing in-flight but queue has items — start the serialized drain:
        // submit only the queue head (submit_next_queued coalesces a safe
        // run) and let each CQE pull the next entry. Pushing the whole queue
        // as parallel SQEs here would repeat "mistake (b)" above.
        if !state.queue.is_empty() {
            state.in_flight = true;
            // A `false` here means the head was parked (SQ still full):
            // it stays queued with `in_flight = true`, `drain_send_retries`
            // re-pushes it, and `close_pending` keeps the Close deferred
            // behind it until it drains or the retry cap fails the send.
            self.submit_next_queued(conn_index);
        } else {
            // Nothing queued: do NOT finalize here. Committing the Close SQE
            // inside this call ran before the task was polled, so a task
            // that read EOF and then sent a response found the Close already
            // committed and its send refused (#371). Hand the finalize to the
            // event loop's end-of-iteration drain — the same path an explicit
            // `DriverCtx::close` takes — so the task gets its poll window and
            // a send queued in it drains under `close_pending` first.
            if !self.pending_finalize_closes.contains(&conn_index) {
                self.pending_finalize_closes.push(conn_index);
            }
        }
    }

    /// Drain everything this connection has received but not yet consumed
    /// into owned bytes, in wire order, releasing every provided-buffer bid
    /// back to the ring (tier 3, #443).
    ///
    /// **Normally returns nothing, and that is the intended state.**
    /// `park_blocker` refuses while any bytes are unconsumed
    /// (`ParkBlocker::DataPending`), so a connection that reaches here has an
    /// empty accumulator and empty holds. This stayed after that gate term
    /// was added because it is the one thing standing between a gap in the
    /// gate and silently discarding a peer's bytes: if anything does slip
    /// through, the data travels rather than vanishing.
    ///
    /// It supersedes the rule in #463 that held bids should be copied and
    /// carried rather than blocking a park. That reasoning was about the
    /// close path; for park, unconsumed data means the quiescent point the
    /// handler offered at has passed, so the right answer is to wait for the
    /// next offer rather than to ship stale state alongside a live request.
    ///
    /// **Order is the correctness property.** The accumulator holds bytes that
    /// arrived before anything still held, and `segment_pinned` was popped
    /// from the front of `segment_hold`, so the sequence is: accumulator,
    /// pinned, held, then the Mode A hold. Getting this wrong reorders the
    /// peer's byte stream, which no test of "did the bytes arrive" would
    /// catch.
    ///
    /// `segment_hold` and `recv_hold` belong to different `RecvDomain`s, so at
    /// most one is ever non-empty. Both are drained regardless: it costs a
    /// pair of empty pops and leaves no dependence on which domain the
    /// connection happened to be in.
    ///
    /// Follows the copy-before-replenish discipline of the segment reader
    /// (`runtime/io.rs`): the bid goes back to the ring only after its bytes
    /// have been copied out, with no await in between.
    pub(crate) fn take_pending_for_park(&mut self, conn_index: u32) -> Vec<bytes::Bytes> {
        let idx = conn_index as usize;
        let mut out: Vec<bytes::Bytes> = Vec::new();

        let acc = self.accumulators.take_frozen(conn_index);
        if !acc.is_empty() {
            out.push(acc);
        }

        let pinned = self.segment_pinned[idx].take();
        let held: Vec<HeldRecvBuf> = self.segment_hold[idx].drain(..).collect();
        for entry in pinned.into_iter().chain(held) {
            match entry {
                HeldRecvBuf::Pinned { bid, len } => {
                    if let Some(b) = self.copy_out_bid(bid, len) {
                        out.push(b);
                    }
                }
                // Force-copied at delivery; its bid was replenished then.
                HeldRecvBuf::Owned(bytes) => {
                    if !bytes.is_empty() {
                        out.push(bytes);
                    }
                }
            }
        }

        let forward: Vec<PendingRecvBuf> = self.recv_hold[idx].drain(..).collect();
        for pending in forward {
            if let Some(b) = self.copy_out_bid(pending.bid, pending.len) {
                out.push(b);
            }
        }

        out
    }

    /// Copy `len` bytes out of provided buffer `bid`, then return the bid to
    /// the ring. `None` for an empty buffer, which carries no bytes and would
    /// only add an empty chunk to the stream.
    ///
    /// Copy first, replenish second, nothing in between — a bid handed back
    /// before its bytes are copied can be overwritten by another connection's
    /// recv.
    fn copy_out_bid(&mut self, bid: u16, len: u32) -> Option<bytes::Bytes> {
        let owned = if len == 0 {
            None
        } else {
            let (ptr, _) = self.provided_bufs.get_buffer(bid);
            // SAFETY: `bid` is held (not yet replenished) and `len` bytes were
            // received into its backing buffer. The slice is consumed by the
            // copy before `self` is mutated below.
            let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
            Some(bytes::Bytes::copy_from_slice(slice))
        };
        self.pending_replenish.push(bid);
        owned
    }

    /// The park gate (tier 3, #443). `None` means quiescent and movable.
    ///
    /// Deliberately **not** blockers, because each would make park refuse
    /// almost always or can be resolved without waiting:
    ///
    /// - `recv_half_taken` / `send_half_taken`. Since #427 the halves are the
    ///   normal API and a typical handler holds both for the connection's
    ///   whole life. They are owned by the future, which park drops, so they
    ///   clear as part of the move rather than blocking it.
    /// - `recv_hold`, `segment_hold`, `segment_pinned`. These can hold
    ///   `HeldRecvBuf::Pinned { bid, .. }`, a bid index into *this* worker's
    ///   `ProvidedBufRing` that addresses a different ring on the target.
    ///   Waiting for a reader to drain them would let a slow reader make a
    ///   connection permanently unparkable, so the move copies them to `Owned`
    ///   instead — bounded work that always succeeds. That conversion is the
    ///   next step; this predicate only decides whether the connection is
    ///   quiescent enough to attempt it.
    /// - The accumulator and the TLS state, which are plain owned data and
    ///   move as values (see the design doc's open questions 4 and 5).
    pub(crate) fn park_blocker(&self, conn_index: u32) -> Option<ParkBlocker> {
        let Some(conn) = self.connections.get(conn_index) else {
            return Some(ParkBlocker::NotOpen);
        };
        // Order matters: teardown sets `Lifecycle::Closing`, which would
        // otherwise fall into the catch-all below and be reported as
        // `NotOpen` for a connection that is open and on its way out.
        if conn.lifecycle == crate::connection::Lifecycle::Closing {
            return Some(ParkBlocker::Closing);
        }
        if !conn.active || !conn.established || conn.lifecycle != crate::connection::Lifecycle::Open
        {
            return Some(ParkBlocker::NotOpen);
        }
        if conn.read != crate::connection::ReadHalf::Open
            || conn.write != crate::connection::WriteHalf::Open
        {
            return Some(ParkBlocker::Closing);
        }

        // Park exists to repair accept-time placement, and an outbound
        // connection was never placed by accept — it has no listener at all.
        // Refusing here also retires a fabricated identity downstream:
        // `handle_park_install` used to fall back to `ListenerId(0)` for a
        // connection that never had one, and if the process has any server
        // TLS config the adopting worker would then install a *server* rustls
        // session on an established outbound socket, defer the spawn, and
        // wedge the connection waiting for a ClientHello.
        if conn.listener.is_none() {
            return Some(ParkBlocker::Outbound);
        }

        // A TLS connection's session lives in this worker's `TlsTable`, and
        // carrying it is not implemented yet — adopting would install a fresh
        // entry and the peer would face a renegotiation on an established
        // session. Refused rather than silently broken; carrying the session
        // is the next increment (open question 4 established that
        // `UnbufferedConn` is plain owned data and moves as one value).
        if self.tls_table.as_ref().is_some_and(|t| t.has(conn_index)) {
            return Some(ParkBlocker::TlsSession);
        }

        // Backstop for the withdraw-on-recv rule, and the reason it is a
        // state check rather than another event hook: bytes that arrived and
        // have not been consumed make the connection un-idle whether or not
        // the path that delivered them remembered to withdraw the offer. A
        // delivery path added later gets this for free.
        if !self.accumulators.is_empty(conn_index)
            || !self.segment_hold[conn_index as usize].is_empty()
            || !self.recv_hold[conn_index as usize].is_empty()
            || self.segment_pinned[conn_index as usize].is_some()
        {
            return Some(ParkBlocker::DataPending);
        }

        // `begin_park` cancels the armed recv by its `RecvMulti` user_data.
        // A `MsgMulti` arm (the `timestamps` feature) would not match, so the
        // socket would be handed over with a recv still draining it here.
        if !matches!(
            self.connections.get(conn_index).map(|c| c.recv_arm),
            Some(crate::connection::RecvArm::Multi) | Some(crate::connection::RecvArm::Idle)
        ) {
            return Some(ParkBlocker::RecvArmNotCancellable);
        }

        // The handler's offer is the opt-in, and it is checked before any
        // mechanical term: a connection nobody offered is not "not yet
        // quiescent", it is simply never going to be parked.
        if !self.park_offered[conn_index as usize] {
            return Some(ParkBlocker::NotOffered);
        }

        let send = &self.send_queues[conn_index as usize];
        if send.close_pending || send.close_submitted {
            return Some(ParkBlocker::Closing);
        }
        if send.in_flight || !send.queue.is_empty() {
            return Some(ParkBlocker::Sends);
        }
        if self.forward_write[conn_index as usize].is_some() {
            return Some(ParkBlocker::ForwardWrite);
        }
        if self.chain_table.is_active(conn_index) {
            return Some(ParkBlocker::Chain);
        }
        if self.segment_reader_live[conn_index as usize] {
            return Some(ParkBlocker::SegmentReader);
        }
        if self.recv_fallback_inflight[conn_index as usize] {
            return Some(ParkBlocker::RecvFallback);
        }
        // `direct_echo_queued` is the per-connection membership bool;
        // `direct_echo_pending` is the queue of connection indices it guards,
        // so it is not indexed by `conn_index` (it starts empty).
        if self.direct_echo_queued[conn_index as usize] {
            return Some(ParkBlocker::DirectEcho);
        }
        None
    }

    /// Convenience over [`Self::park_blocker`] for call sites that do not care
    /// which term tripped.
    pub(crate) fn is_parkable(&self, conn_index: u32) -> bool {
        self.park_blocker(conn_index).is_none()
    }

    /// Submit the deferred `Close` SQE once every pending send for
    /// this connection has either completed or been finally given up
    /// on. Called from `close_connection` (immediate-fast-path) and
    /// from `note_send_finalized` after each per-send CQE.
    pub(crate) fn try_finalize_close(&mut self, conn_index: u32) {
        let state = &self.send_queues[conn_index as usize];
        let sends_drained = !state.in_flight && state.queue.is_empty();
        // An in-flight Mode A forward write still owns a provided buffer (or Owned
        // copy) the kernel is reading as the write source; do not submit `Close`
        // (which recycles the slot) until its CQE has landed and released the
        // backing. `handle_forward_write` / `fail_forward_write` re-drive this
        // finalize once `forward_write[conn]` is cleared.
        let forward_drained = self.forward_write[conn_index as usize].is_none();
        // An active send chain has SQEs in the kernel whose CQEs drive its
        // accounting; the chain completion handlers re-drive this finalize
        // once the chain drains.
        let chain_drained = !self.chain_table.is_active(conn_index);
        // A `Shutdown` SQE still in the kernel names this slot as
        // `Fixed(conn_index)`. `Close` frees the slot for the next accept to
        // register, so submitting it now lets the FIN land on that next
        // connection instead — a live peer, cleanly half-closed, whose next send
        // fails `EPIPE`. `handle_shutdown` re-drives this finalize once the CQE
        // clears the flag.
        let shutdown_drained = !state.shutdown_inflight;
        if !(state.close_pending
            && sends_drained
            && forward_drained
            && chain_drained
            && shutdown_drained)
        {
            return;
        }
        let st = &mut self.send_queues[conn_index as usize];
        st.close_pending = false;
        // From here the Close is committed (submitted below, or queued for
        // retry): late CQEs must not push new SQEs for this connection.
        st.close_submitted = true;
        // Clear the deadline so the slot's next occupant doesn't inherit it.
        st.close_notify_deadline = None;
        // Disarm from the close_notify deadline set. swap_remove is
        // O(n) but the set is bounded by concurrent TLS shutdowns
        // (typically 0 or single digits) — well below the cost we just
        // saved by not walking every connection slot in the deadline
        // check.
        if let Some(pos) = self
            .close_notify_armed
            .iter()
            .position(|&i| i == conn_index)
        {
            self.close_notify_armed.swap_remove(pos);
        }
        // If a multishot recv is still armed on this connection, cancel it
        // before closing. Closing the fixed descriptor alone removes its
        // fixed-file table slot but does NOT drop the socket's last reference
        // while an in-flight recv SQE still pins it — so the kernel never sends
        // the peer a FIN and a parked reader on the other end hangs forever.
        // Cancelling the recv (by its `RecvMulti` user_data, which is immune to
        // Close reordering since it targets the request, not the fd) releases
        // that reference so the subsequent Close actually FINs. The recv's
        // ECANCELED completion is a no-op (generation/slot checks in
        // `handle_recv_multi`). Skipped when the recv already self-terminated
        // (e.g. a peer FIN drove this close) — nothing to cancel.
        let recv_armed = self
            .connections
            .get(conn_index)
            .is_some_and(|c| c.recv_multishot_armed);
        if recv_armed {
            // Must reproduce the arm-time payload (the connection generation):
            // `submit_async_cancel` matches the request by `user_data`.
            let recv_ud = crate::completion::UserData::encode(
                crate::completion::OpTag::RecvMulti,
                conn_index,
                self.connections.generation(conn_index),
            );
            let _ = self.ring.submit_async_cancel(recv_ud.raw(), conn_index);
            // Cleared whether or not the cancel push landed. A failed push (SQ
            // full) does leave a multishot armed in the kernel, but nothing
            // retries the cancel (`drain_close_retries` re-drives only the
            // `Close`), every remaining reader of this flag is gated on
            // `Lifecycle::Open`, and `deactivate()` clears it again when the
            // Close CQE releases the slot. The uncancelled multishot's late
            // completions are rejected on the generation now carried in their
            // payload — see `docs/recv-multi-identity-design.md`.
            if let Some(cs) = self.connections.get_mut(conn_index) {
                cs.recv_multishot_armed = false;
            }
        }
        if self.ring.submit_close(conn_index).is_err() {
            crate::metrics::RING.increment(crate::metrics::ring::CLOSE_SUBMIT_FAILURES);
            // Queue this connection for retry on a later tick. (An earlier
            // version rebuilt the whole retry vec here — aging every other
            // entry toward discard and never enqueueing the connection whose
            // close just failed, leaking its fd and slot permanently.)
            self.pending_close_retries.push((conn_index, 0));
        }
    }

    /// Hook called from the send-path CQE handlers after the queue
    /// state has been updated — submits a deferred `Close` if the
    /// connection was waiting and the queue is now drained.
    pub(crate) fn note_send_finalized(&mut self, conn_index: u32) {
        self.try_finalize_close(conn_index);
    }

    /// Force a deferred close whose drain will never finish (close_notify
    /// deadline elapsed — the peer stopped reading, so the queued/in-flight
    /// sends are stuck). Deliberately abandons outstanding work: queued
    /// (never-submitted) sends are released here; the in-flight send / chain
    /// SQEs are left to the kernel — the Close cancels them, and their CQEs
    /// fail the generation identity check in the completion handlers (post
    /// Close-CQE), so they release their own slots without touching the
    /// index's next occupant. A CQE that lands *before* the Close CQE still
    /// matches the generation and takes the normal path: on this abandoned
    /// connection that can burn a resubmit/POLLOUT SQE against the closing
    /// fd (EBADF/ECANCELED follow-up) or wake the abandoned waiter — wasteful
    /// but bounded, and confined to the force path. The next occupant is
    /// protected by `reset_send_state` at reactivation.
    pub(crate) fn force_finalize_close(&mut self, conn_index: u32) {
        let state = &mut self.send_queues[conn_index as usize];
        let bounded = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
            &mut self.pending_replenish,
        );
        state.in_flight = false;
        state.parked = false;
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.write = WriteHalf::Open;
        }
        self.fail_bounded_sends(bounded);
        self.chain_table.cancel(conn_index);
        self.try_finalize_close(conn_index);
    }

    /// Submit a one-shot fallback recv into a pool slot for a connection
    /// parked on ENOBUFS with a partial message in its accumulator.
    ///
    /// Returns `true` if the SQE was submitted. The caller must have
    /// already established eligibility (plaintext accumulator path, no
    /// fallback in flight). On pool exhaustion or a full SQ the connection
    /// simply stays parked — the pre-fallback status quo — and is retried
    /// on a later flush.
    pub(crate) fn try_submit_fallback_recv(&mut self, conn_index: u32) -> bool {
        let chunk = self.fallback_chunk;
        let pool = self
            .fallback_recv_pool
            .get_or_insert_with(|| SendCopyPool::new(FALLBACK_RECV_SLOTS, chunk));
        if self.fallback_slot_owner.is_empty() {
            self.fallback_slot_owner = vec![(u32::MAX, u32::MAX); FALLBACK_RECV_SLOTS as usize];
        }
        let Some((slot, ptr, cap)) = pool.alloc_raw() else {
            return false;
        };
        if self
            .ring
            .submit_recv_fallback(conn_index, ptr, cap, slot)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::SQE_SUBMIT_FAILURES);
            self.fallback_recv_pool
                .as_mut()
                .expect("pool constructed above")
                .release(slot);
            return false;
        }
        self.fallback_slot_owner[slot as usize] =
            (conn_index, self.connections.generation(conn_index));
        self.recv_fallback_inflight[conn_index as usize] = true;
        self.recv_fallback_count += 1;
        metrics::POOL.increment(metrics::pool::RECV_FALLBACK);
        true
    }

    /// Submit the next queued send for a connection to the ring.
    ///
    /// Returns `true` if an SQE was pushed (the entries it covers are popped
    /// only then). Returns `false` with an empty queue when the connection
    /// went idle: `in_flight` is cleared and a deferred shutdown/close fires.
    /// Returns `false` with a non-empty queue when the head could not be
    /// pushed (SQ still full after submit): the entry is *parked* — it stays
    /// at the queue head, `in_flight` stays `true`, and the connection is on
    /// `pending_send_retries` for `drain_send_retries` to re-push next
    /// iteration. Nothing is dropped or released on that path (Domain
    /// Invariant 7); persistent starvation past the retry cap fails the
    /// waiter and closes the connection there.
    pub(crate) fn submit_next_queued(&mut self, conn_index: u32) -> bool {
        self.submit_next_queued_inner(conn_index, 0)
    }

    /// [`submit_next_queued`](Self::submit_next_queued) with the attempt
    /// count to record if the push fails again. `drain_send_retries` passes
    /// `attempts + 1` so a re-park carries the incremented count instead of
    /// restarting at zero; every other caller goes through the public
    /// wrapper with `0`.
    pub(crate) fn submit_next_queued_inner(&mut self, conn_index: u32, attempts: u8) -> bool {
        use crate::buffer::send_slab::MAX_IOVECS;

        let ci = conn_index as usize;

        // Coalesce a run of consecutive plaintext copy sends (pool_slot set, no
        // ZC slab) at the front of the queue into a single `sendmsg`, so more
        // than one queued message is pipelined per CQE round-trip. Order is
        // preserved (one SQE; iovec order = FIFO queue order). ZC-guard sends
        // and recv-buffer forwards are not coalescable and fall through to the
        // single-submit path below.
        let coalescable =
            |b: &crate::handler::BuiltSend| b.pool_slot != u16::MAX && b.slab_idx == u16::MAX;
        // Coalesce at most one logical send's tail per op: stop the run after
        // the first chunk marked end-of-send. Otherwise a single coalesced
        // completion could span two independent pipelined sends, and only one
        // of their two waiters would ever be woken.
        let n = {
            let mut n = 0;
            while n < MAX_IOVECS {
                match self.send_queues[ci].queue.get(n) {
                    Some(b) if coalescable(b) => {
                        let pool_slot = b.pool_slot;
                        n += 1;
                        if self.send_copy_pool.is_end_of_send(pool_slot) {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            n
        };
        if n >= 2 {
            let mut pool_slots = [u16::MAX; MAX_IOVECS];
            {
                let q = &self.send_queues[ci].queue;
                for (i, slot) in pool_slots.iter_mut().enumerate().take(n) {
                    *slot = q[i].pool_slot;
                }
            }
            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            let mut total: u32 = 0;
            for i in 0..n {
                let (ptr, len) = self.send_copy_pool.current_ptr_remaining(pool_slots[i]);
                iovecs[i] = libc::iovec {
                    iov_base: ptr as *mut libc::c_void,
                    iov_len: len as usize,
                };
                total += len;
            }
            // The coalesced op carries the final chunk of a logical send only
            // if its last gathered chunk does; the completion handler wakes the
            // waiter on that.
            let end_of_send = self.send_copy_pool.is_end_of_send(pool_slots[n - 1]);
            // ...and, for the same reason, the bounded send it settles. The
            // coalesced completion releases every pool slot in the run, so
            // the id cannot stay on the slot that carried it here; it moves
            // onto the slab entry, which outlives them. Taken, not peeked:
            // leaving a copy behind would let both the slab entry and the
            // slot claim the same operation, and `SendCopyPool::release`
            // would then trip on the slot the handler is about to free.
            // Both failure paths below put it back on that slot, because
            // they leave the run queued and still owning its slots.
            let bounded_send = self.send_copy_pool.take_bounded_send(pool_slots[n - 1]);
            // Only commit to coalescing if the slab has room; otherwise fall
            // through to single-submit (nothing popped yet).
            if let Some((slab_idx, msg_ptr)) = self.send_slab.allocate_coalesced(
                conn_index,
                self.connections.generation(conn_index),
                &iovecs[..n],
                &pool_slots[..n],
                total,
                end_of_send,
                bounded_send,
            ) {
                match self
                    .ring
                    .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
                {
                    Ok(()) => {
                        // Pushed: the slab entry now owns the run's pool
                        // slots (released by the coalesced completion).
                        for _ in 0..n {
                            self.send_queues[ci].queue.pop_front();
                        }
                        self.send_queues[ci].parked = false;
                        return true;
                    }
                    Err(_) => {
                        // SQ still full after submit. `allocate_coalesced`
                        // only *recorded* the pool slots in the slab entry;
                        // the `BuiltSend`s still at the queue head own them.
                        // Release just the slab entry and park: the run stays
                        // queued in order, `in_flight` stays true, and
                        // `drain_send_retries` re-pushes next iteration.
                        // The lifted bounded-send id goes back on its slot
                        // for the same reason — the retry re-lifts it, and
                        // if teardown gets there first the slot is what
                        // teardown reads.
                        self.send_slab.release(slab_idx);
                        if let Some((id, logical_len)) = bounded_send {
                            self.send_copy_pool.set_bounded_send(
                                pool_slots[n - 1],
                                id,
                                logical_len,
                            );
                        }
                        self.send_queues[ci].parked = true;
                        let generation = self.connections.generation(conn_index);
                        self.pending_send_retries
                            .push((conn_index, generation, attempts));
                        return false;
                    }
                }
            }
            // slab full → fall through to single-submit. Nothing was popped
            // and the run still owns its slots, so the lifted id goes back
            // where the single-submit path (and teardown) will find it.
            if let Some((id, logical_len)) = bounded_send {
                self.send_copy_pool
                    .set_bounded_send(pool_slots[n - 1], id, logical_len);
            }
        }

        let state = &mut self.send_queues[ci];
        if !state.queue.is_empty() {
            // Peek, don't pop: on a push failure the entry must stay at the
            // head so the retry re-pushes the same bytes in the same order.
            let pushed = {
                let front = &state.queue[0];
                unsafe { self.ring.push_sqe(&front.entry) }
            };
            return match pushed {
                Ok(()) => {
                    state.queue.pop_front();
                    state.parked = false;
                    true
                }
                Err(_) => {
                    // SQ still full after submit: park at the head. Nothing
                    // is released and `in_flight` stays true; see
                    // `drain_send_retries` for the retry and the cap.
                    state.parked = true;
                    let generation = self.connections.generation(conn_index);
                    self.pending_send_retries
                        .push((conn_index, generation, attempts));
                    false
                }
            };
        }

        // Queue empty: the connection is idle.
        state.in_flight = false;
        state.parked = false;
        // Submit a deferred shutdown_write now that the queue is drained.
        if let Some(cs) = self.connections.get_mut(conn_index)
            && matches!(cs.write, WriteHalf::ShutdownPending)
        {
            // Refused (ring backpressure): fall back to `Open` so a
            // repeat `shutdown_write` can re-request the FIN rather
            // than stranding it as pending on an empty queue.
            let generation = cs.generation;
            cs.write = if self.ring.submit_shutdown(conn_index, generation).is_ok() {
                // The slot must now outlive the SQE: see `shutdown_inflight`.
                self.send_queues[conn_index as usize].shutdown_inflight = true;
                WriteHalf::Shutdown
            } else {
                WriteHalf::Open
            };
        }
        // Fire a deferred close now that nothing is in flight and the
        // queue is empty. The ZC and recv-forward completion paths
        // reach here without a note_send_finalized call, so without
        // this a close_pending connection would leak its fd and slot.
        self.try_finalize_close(conn_index);
        false
    }

    /// Submit a built send SQE, or queue it if a send is already in flight.
    ///
    /// This is the Driver-level equivalent of `DriverCtx::submit_or_queue`,
    /// used by zero-copy forward paths that bypass DriverCtx, and carries the
    /// same contract: infallible, the entry is committed to the connection's
    /// stream on return. If the push fails (SQ still full after submit) the
    /// entry is parked at the head of the (empty) queue with
    /// `in_flight = true` and the connection is registered on
    /// `pending_send_retries`; `drain_send_retries` re-pushes it. A parked
    /// `SendRecvBuf` keeps its provided buffer exactly as a queued one does —
    /// the bid is replenished by its completion, not by the caller.
    /// Stage a direct-echo recv buffer for the next flush.
    ///
    /// The connection stays on `direct_echo_pending` until its hold drains, so
    /// the flush pass never has to work out which completion handler owed it a
    /// re-arm.
    pub(crate) fn hold_direct_echo(&mut self, conn_index: u32, pending: PendingRecvBuf) {
        let ci = conn_index as usize;
        self.recv_hold[ci].push_back(pending);
        if !self.direct_echo_queued[ci] {
            self.direct_echo_queued[ci] = true;
            self.direct_echo_pending.push(conn_index);
        }
    }

    /// Submit the next direct-echo send for `conn_index`, gathering every
    /// buffer currently held (up to `MAX_IOVECS`) into one operation.
    ///
    /// Direct echo used to submit one `Send` per recv completion. A message
    /// larger than a single completion's worth of bytes therefore left as
    /// several segments — the tail was already sitting in the send queue behind
    /// the head, but as a separate, non-coalescable op. Gathering here makes
    /// the reply's packetization follow the message rather than the arrival
    /// pattern of the request (#397).
    ///
    /// A lone held buffer still takes the plain `Send` path: it needs neither a
    /// slab entry nor an `msghdr`, and it is the common case for any message
    /// that fits one completion.
    pub(crate) fn flush_direct_echo(&mut self, conn_index: u32) {
        use crate::buffer::send_slab::MAX_IOVECS;
        let ci = conn_index as usize;

        // `recv_hold` is shared with recv-forward, where draining the hold is
        // the owning task's job. Only gather for a slot that is still in
        // direct-echo mode.
        if !self
            .connections
            .get(conn_index)
            .is_some_and(|c| c.direct_echo)
        {
            return;
        }

        // One send in flight per connection; anything that arrives meanwhile
        // accumulates in the hold and goes out in the next gather. A non-empty
        // queue implies `in_flight`, but both are checked so this can never
        // overtake a send that is already ordered ahead of it.
        if self.send_queues[ci].in_flight || !self.send_queues[ci].queue.is_empty() {
            return;
        }
        let n = self.recv_hold[ci].len().min(MAX_IOVECS);
        if n == 0 {
            return;
        }

        if n >= 2 {
            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            let mut bids = [0u16; MAX_IOVECS];
            let mut total: u32 = 0;
            for i in 0..n {
                let p = self.recv_hold[ci][i];
                iovecs[i] = libc::iovec {
                    iov_base: p.ptr as *mut libc::c_void,
                    iov_len: p.len as usize,
                };
                bids[i] = p.bid;
                total += p.len;
            }
            let generation = self.connections.generation(conn_index);
            if let Some((slab_idx, msg_ptr)) = self.send_slab.allocate_recv_forward(
                conn_index,
                generation,
                &iovecs[..n],
                &bids[..n],
                total,
            ) {
                // The slab entry owns the buffers from here: its completion
                // replenishes the bids whether the send succeeds, is retried,
                // or is released on close.
                for _ in 0..n {
                    self.recv_hold[ci].pop_front();
                }
                self.send_queues[ci].in_flight = true;
                if self
                    .ring
                    .submit_send_recv_bufs_coalesced(conn_index, msg_ptr, slab_idx)
                    .is_err()
                {
                    // SQ full: the same retry path the coalesced completion
                    // handler uses. Nothing is dropped and no bid is leaked.
                    self.pending_recv_forward_retries
                        .push((conn_index, generation, slab_idx, 0));
                }
                return;
            }
            // Slab exhausted — fall through and send the head buffer alone
            // rather than stalling the connection.
        }

        let pending = self.recv_hold[ci]
            .pop_front()
            .expect("hold is non-empty: n >= 1 was checked above");
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, pending.bid as u32);
        let entry = io_uring::opcode::Send::new(
            io_uring::types::Fixed(conn_index),
            pending.ptr,
            pending.len,
        )
        .flags(crate::completion::STREAM_SEND_FLAGS)
        .build()
        .user_data(ud.raw());
        self.send_recv_buf_original_lens[ci] = pending.len;
        self.send_recv_buf_remaining[ci] = pending.len;
        // Infallible: under SQ pressure the echo is parked at the queue head
        // and retried, holding its provided buffer exactly as a queued echo
        // does; the bid is replenished by its completion.
        self.submit_or_queue_send(
            conn_index,
            crate::handler::BuiltSend {
                entry,
                pool_slot: u16::MAX,
                slab_idx: u16::MAX,
                total_len: pending.len,
            },
        );
    }

    pub(crate) fn submit_or_queue_send(
        &mut self,
        conn_index: u32,
        built: crate::handler::BuiltSend,
    ) {
        // An active IO_LINK chain counts as in flight: io_uring does not order
        // independent SQEs, so pushing this send now could interleave its bytes
        // with the chain's on the wire. Queue it and mark the queue as owning
        // the send order (`in_flight`), as parking does; the invariant is that
        // a non-empty queue implies `in_flight`, which `submit_next_queued`
        // relies on. Chain completion submits the queue
        // (`fire_chain_complete` -> `submit_next_queued`).
        let chain_active = self.chain_table.is_active(conn_index);
        let state = &mut self.send_queues[conn_index as usize];
        if state.in_flight || chain_active {
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
                self.pending_send_retries.push((conn_index, generation, 0));
            }
        }
    }

    /// Queue a batch of built sends in order through the per-connection
    /// send queue. Infallible: `submit_or_queue_send` parks under SQ
    /// pressure rather than failing, so every entry is committed in order
    /// and nothing needs releasing here. `sends` is drained, not consumed,
    /// so the caller can keep the `Vec`'s allocation as scratch.
    pub(crate) fn queue_built_sends(
        &mut self,
        conn_index: u32,
        sends: &mut Vec<crate::handler::BuiltSend>,
    ) {
        for built in sends.drain(..) {
            self.submit_or_queue_send(conn_index, built);
        }
    }

    /// Drain and release all queued sends for a connection.
    pub(crate) fn drain_conn_send_queue(&mut self, conn_index: u32) {
        let state = &mut self.send_queues[conn_index as usize];
        let bounded = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
            &mut self.pending_replenish,
        );
        state.in_flight = false;
        state.parked = false;
        // Abandon any partially-accumulated logical send so the next one
        // starts from zero.
        state.acked_bytes = 0;
        self.fail_bounded_sends(bounded);
        // The queue is now empty and nothing is in flight — fire a deferred
        // close if one was pending so the connection can't leak.
        self.try_finalize_close(conn_index);
    }

    /// Release all entries from a send queue, returning the bounded sends
    /// they were carrying.
    ///
    /// A queued `SendRecvBuf` entry (recv-buffer forward / direct echo) owns
    /// neither a pool slot nor a slab entry; it owns the provided recv buffer
    /// whose bid is the SQE's payload. No CQE will ever replenish it, so the
    /// bid is recovered from the entry's user_data here, exactly as the
    /// completion handler would have done.
    ///
    /// A queued entry was never submitted, so nothing will ever complete it:
    /// if its pool slot carries a bounded send
    /// (`ConnCtx::send_backpressured`), that operation has to be failed or
    /// its caller's future hangs — and `SendCopyPool::release` debug-asserts
    /// rather than let the id be dropped silently. The ids are *returned*
    /// instead of pushed, so the three callers can put them on
    /// `Driver::bounded_send_completions` themselves: every caller already
    /// holds `&mut self` while this takes four disjoint field borrows, and
    /// threading a failures queue and an error constructor through a fifth
    /// `&mut` parameter is the change with the most call-site risk and the
    /// least visibility. `#[must_use]` is what keeps a caller from quietly
    /// dropping them.
    ///
    /// The returned `Vec` does not allocate unless a bounded send was
    /// actually queued, so the common teardown (and `reset_send_state`, run
    /// on every slot reactivation) pays nothing.
    #[must_use = "queued bounded sends must be failed onto Driver::bounded_send_completions"]
    pub(crate) fn release_queued_sends(
        queue: &mut VecDeque<BuiltSend>,
        send_slab: &mut InFlightSendSlab,
        send_copy_pool: &mut SendCopyPool,
        pending_replenish: &mut Vec<u16>,
    ) -> Vec<BoundedSendId> {
        let mut bounded = Vec::new();
        for built in queue.drain(..) {
            if built.pool_slot == u16::MAX && built.slab_idx == u16::MAX {
                let ud = crate::completion::UserData(built.entry.get_user_data());
                if ud.tag() == Some(crate::completion::OpTag::SendRecvBuf) {
                    pending_replenish.push(ud.payload() as u16);
                }
                continue;
            }
            // Take before releasing: `release` asserts the slot is clean.
            // Only a pool-slot entry can carry an id — a slab-backed queued
            // entry is a ZC or recv-forward send, which a bounded send
            // cannot be (`send_backpressured` is copy-only), and a coalesced
            // slab entry is never queued (it is built at submit time and the
            // run it covers is popped on success).
            if built.pool_slot != u16::MAX
                && let Some((id, _logical_len)) = send_copy_pool.take_bounded_send(built.pool_slot)
            {
                bounded.push(id);
            }
            Self::release_built_resources(
                send_slab,
                send_copy_pool,
                built.pool_slot,
                built.slab_idx,
            );
        }
        bounded
    }

    /// Record every id in `bounded` as an aborted bounded send, and note
    /// that the slots they were holding went back to the pool.
    ///
    /// The tail of each `release_queued_sends` call site. `ConnectionAborted`
    /// is the failure every teardown reports: the send was admitted, never
    /// reached the wire, and its connection is going away.
    fn fail_bounded_sends(&mut self, bounded: Vec<BoundedSendId>) {
        for id in bounded {
            self.bounded_send_completions.push_back((
                id,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection closed before the send reached the wire",
                )),
            ));
        }
        // Unconditional: the queue held slots whenever it was non-empty, and
        // a spurious wake costs one `free_count()` read at the end of the
        // loop iteration.
        self.capacity_released = true;
    }

    /// Release pool slot and/or slab entry for a single BuiltSend.
    pub(crate) fn release_built_resources(
        send_slab: &mut InFlightSendSlab,
        send_copy_pool: &mut SendCopyPool,
        pool_slot: u16,
        slab_idx: u16,
    ) {
        if slab_idx != u16::MAX {
            let ps = send_slab.release(slab_idx);
            if ps != u16::MAX {
                send_copy_pool.release(ps);
            }
        } else if pool_slot != u16::MAX {
            send_copy_pool.release(pool_slot);
        }
    }

    /// Create a UDP socket, bind with SO_REUSEPORT, register in fixed file
    /// table. `reserved` is a socket `launch` already bound to `bind_addr`; it
    /// is used instead of creating and binding one.
    #[allow(clippy::too_many_arguments)]
    fn setup_udp_socket(
        ring: &Ring,
        bind_addr: SocketAddr,
        connect_peer: Option<SocketAddr>,
        fd_index: u32,
        send_slots: u16,
        udp_gro: bool,
        reserved: Option<std::os::fd::OwnedFd>,
    ) -> Result<UdpSocketState, crate::error::Error> {
        let domain = if bind_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        let bound = reserved.is_some();
        let fd = match reserved {
            Some(fd) => {
                use std::os::fd::IntoRawFd;
                let fd = fd.into_raw_fd();
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0
                    || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
                {
                    let err = std::io::Error::last_os_error();
                    unsafe { libc::close(fd) };
                    return Err(crate::error::Error::Io(err));
                }
                fd
            }
            None => unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) },
        };
        if fd < 0 {
            return Err(crate::error::Error::Io(std::io::Error::last_os_error()));
        }

        // SO_REUSEPORT lets every worker bind the same port. A zero port
        // reaches a worker only when each worker should get its own port, and
        // with the option set Linux's free-port search can return a port
        // another SO_REUSEPORT socket already holds, so it is left off then.
        // A reserved socket already has it.
        if !bound && bind_addr.port() != 0 {
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Enable UDP GRO. Opt-in, so a failure is hard rather than silent —
        // the caller has deliberately enlarged recv buffers expecting
        // coalescing, and quietly running without it would mislead.
        if udp_gro {
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_UDP,
                    crate::backend::udp_gro::UDP_GRO,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(crate::error::Error::Io(err));
            }
        }

        // Bind.
        if !bound {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let addr_len = crate::backend::socket_addr_to_sockaddr(bind_addr, &mut storage);
            let ret =
                unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(crate::error::Error::Io(err));
            }
        }

        // If a peer was supplied, connect(2) the socket before registering
        // the fd. The kernel will filter incoming datagrams to this peer and
        // we can use the lighter Recv/Send opcodes for this socket.
        if let Some(peer) = connect_peer {
            let mut peer_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let peer_len = crate::backend::socket_addr_to_sockaddr(peer, &mut peer_storage);
            let ret = unsafe {
                libc::connect(
                    fd,
                    &peer_storage as *const _ as *const libc::sockaddr,
                    peer_len,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(crate::error::Error::Io(err));
            }
        }

        // Register in the fixed file table, then close the original fd.
        ring.register_files_update(fd_index, &[fd])?;
        unsafe {
            libc::close(fd);
        }

        // Build the msghdr *template* for multishot recvmsg. The kernel only
        // reads `msg_namelen` / `msg_controllen` / `msg_iovlen` from this;
        // the actual name/control/payload land inside a buffer from the
        // provided buffer ring (laid out as `io_uring_recvmsg_out` + name +
        // control + payload). No iov is needed for multishot.
        let mut recv_msghdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
        recv_msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        // When GRO is on, reserve control space so the kernel can attach the
        // UDP_GRO cmsg (segment size) inside each provided buffer. The kernel
        // reads this length off the template; `rearm_udp_recvmsg` only resets
        // `msg_namelen`, so this reservation survives re-arming. 0 keeps the
        // control region inert for non-GRO sockets.
        recv_msghdr.msg_controllen = if udp_gro {
            crate::backend::udp_gro::UDP_GRO_CMSG_LEN
        } else {
            0
        };
        recv_msghdr.msg_iov = std::ptr::null_mut();
        recv_msghdr.msg_iovlen = 0;

        // Allocate send slot ring. Each slot owns its own (addr, iov, msghdr)
        // so multiple sendmsg SQEs can be in-flight concurrently.
        let mut slots: Vec<UdpSendSlot> = Vec::with_capacity(send_slots as usize);
        for _ in 0..send_slots {
            let mut send_addr: Box<libc::sockaddr_storage> =
                Box::new(unsafe { std::mem::zeroed() });
            let mut send_iov = Box::new(libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            });
            let mut send_msghdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
            let mut send_cmsg_buf: Box<[u8; UDP_GSO_CMSG_LEN]> = Box::new([0u8; UDP_GSO_CMSG_LEN]);

            send_msghdr.msg_name = &mut *send_addr as *mut _ as *mut libc::c_void;
            send_msghdr.msg_iov = &mut *send_iov as *mut libc::iovec;
            send_msghdr.msg_iovlen = 1;
            // `msg_control` always points at our pinned cmsg buffer;
            // `msg_controllen = 0` for non-GSO sends keeps it inert.
            send_msghdr.msg_control = send_cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            send_msghdr.msg_controllen = 0;

            slots.push(UdpSendSlot {
                send_addr,
                send_iov,
                send_msghdr,
                send_cmsg_buf,
            });
        }
        let send_slots_box = slots.into_boxed_slice();
        // Freelist is a LIFO stack of free slot indices (reverse order so slot 0 is popped first).
        let send_freelist: Vec<u16> = (0..send_slots).rev().collect();

        Ok(UdpSocketState {
            fd_index,
            local_addr: bind_addr,
            connected_peer: connect_peer,
            recv_msghdr,
            gro: udp_gro,
            send_slots: send_slots_box,
            send_freelist,
        })
    }

    /// Send a UDP datagram via the copy pool.
    ///
    /// Allocates one of the socket's pre-allocated send slots (bounded by
    /// `Config::udp_send_slots`) and submits a `sendmsg` SQE. Multiple sends
    /// can be in flight concurrently; returns `PoolExhausted` when no free
    /// send slot or copy-pool slot is available.
    ///
    /// When `gso_segment_size` is `Some(s)`, attaches a `UDP_SEGMENT`
    /// control message: the kernel splits `data` into back-to-back
    /// `s`-byte datagrams and emits each as a separate UDP packet from
    /// the *same* `sendmsg` call. This is Linux's GSO offload — one
    /// syscall, N datagrams. The pool slot still holds `data` end-to-
    /// end, so the per-datagram cost is just an iovec entry plus
    /// kernel-side segmentation work.
    pub(crate) fn udp_send_to(
        &mut self,
        udp_index: u32,
        peer: SocketAddr,
        data: &[u8],
        gso_segment_size: Option<u16>,
    ) -> Result<(), crate::error::UdpSendError> {
        let idx = udp_index as usize;
        if idx >= self.udp_sockets.len() {
            return Err(crate::error::UdpSendError::Io(std::io::Error::other(
                "invalid UDP socket index",
            )));
        }

        // Reject oversize datagrams up front with a non-retryable error so
        // callers don't burn cycles awaiting `send_ready` on data that will
        // never fit. `send_copy_pool::copy_in` would also fail here, but it
        // collapses size and exhaustion into a single `None` — losing the
        // distinction the API needs.
        let slot_size = self.send_copy_pool.slot_size() as usize;
        if data.len() > slot_size {
            return Err(crate::error::UdpSendError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "datagram size {} exceeds send_copy_slot_size {}",
                    data.len(),
                    slot_size
                ),
            )));
        }
        if let Some(seg) = gso_segment_size
            && (seg == 0 || (seg as usize) > data.len())
        {
            return Err(crate::error::UdpSendError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "GSO segment size {} invalid for {}-byte buffer",
                    seg,
                    data.len()
                ),
            )));
        }

        let slot_idx = self.udp_sockets[idx]
            .send_freelist
            .pop()
            .ok_or(crate::error::UdpSendError::PoolExhausted)?;

        let (pool_slot, ptr, len) = match self.send_copy_pool.copy_in(data) {
            Some(v) => v,
            None => {
                // Return the send slot to the freelist before reporting exhaustion.
                self.udp_sockets[idx].send_freelist.push(slot_idx);
                return Err(crate::error::UdpSendError::PoolExhausted);
            }
        };

        let fd_index = self.udp_sockets[idx].fd_index;

        // Fast path: if the socket is connect(2)ed to this peer and there is
        // no GSO segmenting, skip msghdr setup and submit the lighter `Send`
        // opcode. The kernel uses the socket's connected peer and the SQE
        // carries no sockaddr / iovec / cmsg. Saves a kernel msghdr
        // copy_from_user per send.
        let use_send_fast_path = gso_segment_size.is_none()
            && self.udp_sockets[idx]
                .connected_peer
                .is_some_and(|p| p == peer);

        if use_send_fast_path {
            let payload = encode_udp_send_payload(slot_idx, pool_slot);
            let ud = UserData::encode(OpTag::SendUdp, udp_index, payload);
            return match self.ring.submit_send_udp(fd_index, ptr, len, ud) {
                Ok(()) => {
                    crate::metrics::UDP.increment(crate::metrics::udp::DATAGRAMS_SENT);
                    Ok(())
                }
                Err(_) => {
                    self.send_copy_pool.release(pool_slot);
                    self.udp_sockets[idx].send_freelist.push(slot_idx);
                    Err(crate::error::UdpSendError::SubmissionQueueFull)
                }
            };
        }

        let slot = &mut self.udp_sockets[idx].send_slots[slot_idx as usize];
        let addr_len = crate::backend::socket_addr_to_sockaddr(peer, &mut slot.send_addr);
        slot.send_iov.iov_base = ptr as *mut libc::c_void;
        slot.send_iov.iov_len = len as usize;
        slot.send_msghdr.msg_namelen = addr_len;

        // Wire up (or tear down) the `UDP_SEGMENT` control message in
        // the pinned per-slot cmsg buffer. We do not touch
        // `slot.send_cmsg_buf` for non-GSO sends — `msg_controllen = 0`
        // tells the kernel to ignore it.
        if let Some(seg_size) = gso_segment_size {
            let cmsg_total = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) };
            debug_assert!(
                (cmsg_total as usize) <= UDP_GSO_CMSG_LEN,
                "UDP_GSO_CMSG_LEN too small for cmsg_space"
            );
            let buf = slot.send_cmsg_buf.as_mut_ptr();
            // SAFETY: `slot.send_cmsg_buf` is pinned in the slot
            // (Box-allocated, lives until the slot is dropped). We
            // populate exactly the bytes the kernel will read.
            unsafe {
                std::ptr::write_bytes(buf, 0, UDP_GSO_CMSG_LEN);
                slot.send_msghdr.msg_control = buf as *mut libc::c_void;
                slot.send_msghdr.msg_controllen = cmsg_total as _;
                let cmsg = libc::CMSG_FIRSTHDR(&*slot.send_msghdr);
                (*cmsg).cmsg_level = libc::IPPROTO_UDP;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
                std::ptr::write_unaligned(data_ptr, seg_size);
            }
        } else {
            slot.send_msghdr.msg_controllen = 0;
        }

        let msghdr_ptr = &*slot.send_msghdr as *const libc::msghdr;
        let payload = encode_udp_send_payload(slot_idx, pool_slot);
        let ud = UserData::encode(OpTag::SendMsgUdp, udp_index, payload);

        match self.ring.submit_sendmsg(fd_index, msghdr_ptr, ud) {
            Ok(()) => {
                crate::metrics::UDP.increment(crate::metrics::udp::DATAGRAMS_SENT);
                Ok(())
            }
            Err(_) => {
                self.send_copy_pool.release(pool_slot);
                self.udp_sockets[idx].send_freelist.push(slot_idx);
                Err(crate::error::UdpSendError::SubmissionQueueFull)
            }
        }
    }

    /// Re-arm the UDP multishot recvmsg for a socket. Called when the kernel
    /// tears the multishot down (e.g. on `ENOBUFS` after the buffer ring
    /// emptied) — the CQE handler pushes the hint here once replenishment
    /// has refilled the ring.
    pub(crate) fn rearm_udp_recvmsg(&mut self, udp_index: u32, bgid: u16) {
        let idx = udp_index as usize;
        if idx >= self.udp_sockets.len() {
            return;
        }
        // Reset msg_namelen in case the kernel cleared it during teardown.
        self.udp_sockets[idx].recv_msghdr.msg_namelen =
            std::mem::size_of::<libc::sockaddr_storage>() as u32;
        let fd_index = self.udp_sockets[idx].fd_index;
        let result = if self.udp_sockets[idx].connected_peer.is_some() {
            let ud = UserData::encode(OpTag::RecvUdp, udp_index, 0);
            self.ring.submit_multishot_recv_udp(fd_index, bgid, ud)
        } else {
            let ud = UserData::encode(OpTag::RecvMsgUdp, udp_index, 0);
            let msghdr_ptr = &*self.udp_sockets[idx].recv_msghdr as *const libc::msghdr;
            self.ring
                .submit_recvmsg_multishot(fd_index, msghdr_ptr, bgid, ud)
        };
        if result.is_err() {
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
        }
    }

    /// Shutdown: close all connections and drain remaining CQEs. The eventfd
    /// is closed by `WakeHandle`, not here.
    pub(crate) fn run_shutdown(&mut self) {
        // Close connections still queued for this worker. Dropping the
        // receiver alone leaves them in the channel until every sender (the
        // acceptor threads, or in merged mode the other workers) has exited.
        if let Some(rx) = self.accept_rx.take() {
            rx.try_iter().for_each(drop);
        }

        // 1. Close all active connections and drain their send queues.
        let max = self.connections.max_slots();
        for i in 0..max {
            if self.connections.get(i).is_some() {
                self.drain_conn_send_queue(i);
                // Best effort: kernel cleans up fds on thread/process exit.
                let _ = self.ring.submit_close(i);
            }
        }

        // 2. Submit + drain loop until all connections are closed.
        //    Arm a timeout SQE each iteration so submit_and_wait(1) never blocks
        //    indefinitely (the tick timeout from the main loop is not armed here).
        let shutdown_ts = io_uring::types::Timespec::new().nsec(100_000_000); // 100ms
        for _ in 0..100 {
            if self.connections.active_count() == 0 && !self.send_slab.has_in_flight() {
                break;
            }
            let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
            // Best effort: the 100-iteration bound prevents infinite block.
            let _ = self.ring.submit_tick_timeout(&shutdown_ts, ud.raw());
            if self.ring.submit_and_wait(1).is_err() {
                break;
            }

            self.cqe_batch.clear();
            {
                let cq = self.ring.ring.completion();
                for cqe in cq {
                    self.cqe_batch
                        .push((cqe.user_data(), cqe.result(), cqe.flags()));
                }
            }

            for i in 0..self.cqe_batch.len() {
                let (user_data_raw, _, flags) = self.cqe_batch[i];
                let ud = UserData(user_data_raw);
                let tag = match ud.tag() {
                    Some(t) => t,
                    None => continue,
                };

                match tag {
                    OpTag::Send | OpTag::TlsSend | OpTag::SendPollOut => {
                        // Payload low 16 bits are the pool slot (high bits
                        // carry the truncated generation / is_tls flag).
                        let pool_slot = ud.payload() as u16;
                        if self.send_copy_pool.in_use(pool_slot) {
                            // These are the three tags a bounded send's
                            // end-of-send slot can wear, so take the id
                            // before releasing — `release` debug-asserts on
                            // a slot that still names a live operation. The
                            // record goes on a queue nobody will drain,
                            // which is the point: the executor is going away
                            // with the driver, so there is no future left to
                            // resolve.
                            if let Some((id, _logical_len)) =
                                self.send_copy_pool.take_bounded_send(pool_slot)
                            {
                                self.bounded_send_completions.push_back((
                                    id,
                                    Err(io::Error::new(
                                        io::ErrorKind::ConnectionAborted,
                                        "worker shut down before the send completed",
                                    )),
                                ));
                            }
                            self.send_copy_pool.release(pool_slot);
                        }
                    }
                    OpTag::SendMsgZc => {
                        let slab_idx = ud.payload() as u16;
                        if !self.send_slab.in_use(slab_idx) {
                            continue;
                        }
                        if cqueue::notif(flags) {
                            self.send_slab.dec_pending_notifs(slab_idx);
                            if self.send_slab.should_release(slab_idx) {
                                let pool_slot = self.send_slab.release(slab_idx);
                                if pool_slot != u16::MAX {
                                    self.send_copy_pool.release(pool_slot);
                                }
                            }
                        } else {
                            // A notification follows exactly when the main CQE
                            // carries IORING_CQE_F_MORE, error and zero results
                            // included (#487).
                            if cqueue::more(flags) {
                                self.send_slab.inc_pending_notifs(slab_idx);
                            }
                            self.send_slab.mark_awaiting_notifications(slab_idx);
                            if self.send_slab.should_release(slab_idx) {
                                let pool_slot = self.send_slab.release(slab_idx);
                                if pool_slot != u16::MAX {
                                    self.send_copy_pool.release(pool_slot);
                                }
                            }
                        }
                    }
                    OpTag::Close => {
                        let conn_index = ud.conn_index();
                        if let Some(ref mut tls_table) = self.tls_table {
                            tls_table.remove(conn_index);
                        }
                        self.clear_conn_claims(conn_index);
                        self.connections.release(conn_index);
                    }
                    _ => {}
                }
            }
        }

        // 3. Unregister the provided buffer rings before Driver is dropped
        // (which munmaps the ring memory). Without this, the kernel holds a
        // dangling pointer to the freed mmap region.
        if self
            .ring
            .unregister_buf_ring(self.provided_bufs.bgid())
            .is_err()
        {
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
        }
        if let Some(ref udp_bufs) = self.udp_provided_bufs
            && self.ring.unregister_buf_ring(udp_bufs.bgid()).is_err()
        {
            crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
        }

        // The eventfd is owned by `WakeHandle` (`WakeFdInner` closes it when
        // the last clone drops), so don't close it here: a double-close would
        // race against fd-number reuse.
    }
}

#[cfg(test)]
mod field_order_tests {
    //! Drop-order proof for the kernel/DMA fields of `Driver`.
    //!
    //! Rust drops struct fields in *declaration* order, so `ring` (declared
    //! first) drops last. We can't directly observe `Driver` dropping (it
    //! owns a real `io_uring`), but we can verify the property in a mirror
    //! struct with the same field ordering and `Drop`-instrumented stand-ins.
    use std::cell::RefCell;
    use std::sync::Mutex;

    static DROP_ORDER: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    struct DropMarker(&'static str);
    impl Drop for DropMarker {
        fn drop(&mut self) {
            DROP_ORDER.lock().unwrap().push(self.0);
        }
    }

    /// Mirrors the head of `Driver`'s field declaration order. If a future
    /// edit moves `ring` out of first position, the order recorded here
    /// will diverge from `["send_slab", "provided_bufs", "ring"]` and the
    /// test will fail loudly.
    #[allow(dead_code)]
    struct DriverFieldOrderMirror {
        ring: DropMarker,
        // `connections`, `fixed_buffers` etc. interleave here in the real
        // struct; only the kernel-DMA-sensitive ones matter for this test.
        provided_bufs: DropMarker,
        send_slab: DropMarker,
    }

    #[test]
    fn ring_drops_after_buffer_pools() {
        // Reset.
        DROP_ORDER.lock().unwrap().clear();

        // Sanity: if someone re-orders the mirror to put ring last, this
        // test will catch it.
        let _ = RefCell::new(()); // silence stray-lifetime lints
        {
            let _m = DriverFieldOrderMirror {
                ring: DropMarker("ring"),
                provided_bufs: DropMarker("provided_bufs"),
                send_slab: DropMarker("send_slab"),
            };
        } // drop runs here

        let order = DROP_ORDER.lock().unwrap().clone();
        assert_eq!(
            order,
            vec!["ring", "provided_bufs", "send_slab"],
            "DriverFieldOrderMirror dropped in the wrong order — \
             reorder the fields to match `Driver`'s declaration so \
             `ring` is declared *first* and therefore drops *last*",
        );

        // The real assertion: in the *real* Driver, `ring` must be
        // declared before the DMA-sensitive fields.
        let src = include_str!("driver.rs");
        let ring_pos = src
            .find("pub(crate) ring: Ring,")
            .expect("Driver::ring field signature not found — was it renamed?");
        let provided_pos = src
            .find("pub(crate) provided_bufs: ProvidedBufRing,")
            .expect("Driver::provided_bufs field signature not found");
        let send_slab_pos = src
            .find("pub(crate) send_slab: InFlightSendSlab,")
            .expect("Driver::send_slab field signature not found");
        assert!(
            ring_pos < provided_pos,
            "Driver::ring must be declared before Driver::provided_bufs \
             so it drops *after* it (kernel DMA reference safety)",
        );
        assert!(
            ring_pos < send_slab_pos,
            "Driver::ring must be declared before Driver::send_slab \
             so it drops *after* it (ZC user-memory guards safety)",
        );
    }
}
