use crate::park::ParkedFd;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::backend::uring::abi::cqueue;

use crate::accumulator::AccumulatorTable;
use crate::backend::ProvidedBufRing;
use crate::backend::Ring;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::buffer::send_copy::SendCopyPool;
use crate::buffer::send_slab::InFlightSendSlab;
use crate::chain::SendChainTable;
use crate::completion::{OpTag, UserData};
use crate::config::Config;
use crate::connection::{ConnectionTable, Lifecycle, ReadHalf, WriteHalf};
use crate::handler::{BuiltSend, ConnSendState, DriverCtx, SendPoll};
use crate::metrics;
use crate::runtime::send_completion::SendId;

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

/// What an adopted connection brings from the worker that parked it.
pub(crate) struct Adopt {
    /// What the handler deposited via `offer_for_park`.
    pub(crate) state: Option<crate::park::ParkState>,
    /// The TLS state of a TLS connection.
    pub(crate) tls: Option<crate::tls::TlsConn>,
}

/// An in-flight direct receive: the connection it was armed for and the
/// buffer the kernel writes into, behind its existing contents.
pub(crate) struct DirectRecv {
    pub(crate) conn_index: u32,
    pub(crate) generation: u32,
    pub(crate) buf: DirectRecvBuf,
}

/// The buffer a direct receive writes into.
pub(crate) enum DirectRecvBuf {
    /// A plaintext connection's accumulator buffer.
    Accumulator(bytes::BytesMut),
    /// A TLS connection's receive ([`tls_recv_arm`](crate::tls::tls_recv_arm)):
    /// the buffer it owns with the buffered engine, `None` with the
    /// unbuffered engine, which receives into the connection's own
    /// ciphertext buffer. If the connection's TLS state is dropped while the
    /// receive is in flight, that buffer's allocation is moved here
    /// ([`release_tls_state`](Driver::release_tls_state)).
    Tls(Option<Vec<u8>>),
}

/// How long worker exit gives a peer to take the data of a zero-copy send
/// before it closes the connection with an RST (#607).
const ABORT_AFTER: std::time::Duration = std::time::Duration::from_secs(1);

/// The longest worker exit waits for connections to close, send slab entries
/// to be released and fs, direct I/O and NVMe commands to complete.
const SHUTDOWN_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

impl Driver {
    /// Whether a connection that forwards its receive buffers should stop
    /// receiving: it holds `forward_hold_cap` send slab entries, and the slab
    /// is over half used. A connection alone on the worker can queue as much as
    /// half the slab, because a peer that writes a large batch before reading
    /// is not stuck, and holding it would stall both sides for good.
    pub(crate) fn forward_recv_over_cap(&self, conn_index: u32) -> bool {
        let generation = self.connections.generation(conn_index);
        self.send_slab.over_half_used()
            && self.send_slab.held_by(conn_index, generation) >= self.forward_hold_cap
    }

    /// Arm a direct receive on `conn_index` if it is a direct connection (a
    /// plaintext TCP or Unix connection) or a TLS connection, open, and has
    /// none in flight, no park of it is pending, and `forward_recv_over_cap` does
    /// not hold it. Called by a receive future that parks, after its parser has seen every buffered
    /// byte: the receive detaches the accumulator's buffer, so arming earlier
    /// would hide buffered bytes from the parser until more arrive. A TLS
    /// connection's receive writes up to `recv_direct_region` bytes of
    /// ciphertext where its TLS engine says
    /// ([`tls_recv_arm`](crate::tls::tls_recv_arm)); it is also armed during
    /// the handshake and after a hangup (see `rearms_after_completion`).
    ///
    /// `need` is the parser's `NeedAtLeast` value, if it returned one. When
    /// it is at least `recv_direct_region`, a plaintext connection's buffer is
    /// first grown to hold the rest of the message. A receive that returns
    /// less wakes the task like any other, and its parser sees the bytes so
    /// far.
    ///
    /// On a push failure, with the accumulator at `recv_accumulator_max`, or
    /// with a TLS engine that has no room for ciphertext, the connection is
    /// closed, as for an accumulator overflow, and this returns `true`: the
    /// caller wakes the task so its read resolves.
    pub(crate) fn arm_direct_recv_or_close(
        &mut self,
        conn_index: u32,
        need: Option<usize>,
    ) -> bool {
        let Some(cs) = self.connections.get(conn_index) else {
            return false;
        };
        let tls = self.tls_table.as_ref().is_some_and(|t| t.has(conn_index));
        if !(cs.recv_direct || tls)
            || cs.recv_direct_armed
            || !matches!(cs.lifecycle, Lifecycle::Open)
            || cs.recv_finished()
        {
            return false;
        }
        // A pending park moves the socket to another worker once nothing is
        // armed on it here; a receive armed now would read bytes meant for
        // that worker. The reader stays parked, and an abandoned park wakes
        // it (`rearm_direct_after_park`).
        if self.park_pending(conn_index) {
            return false;
        }
        // A peer that does not read keeps these slab entries. Receiving no more
        // closes its window, and `resume_forward_recvs` arms the receive when
        // that changes.
        let ci = conn_index as usize;
        if self.forwards_recv_buf[ci] && self.forward_recv_over_cap(conn_index) {
            if !self.forward_recv_held[ci] {
                self.forward_recv_held[ci] = true;
                self.forward_recv_held_conns.push(conn_index);
            }
            return false;
        }
        let generation = cs.generation;
        let (buf, ptr, len, held, known) = if tls {
            let Some(target) = self
                .tls_table
                .as_mut()
                .and_then(|t| crate::tls::tls_recv_arm(t, conn_index, self.recv_direct_region))
            else {
                self.abort_recv(
                    conn_index,
                    io::Error::new(
                        io::ErrorKind::QuotaExceeded,
                        "TLS receive buffer full before the record was read",
                    ),
                );
                return true;
            };
            (
                DirectRecvBuf::Tls(target.buf),
                target.ptr,
                target.len,
                0,
                false,
            )
        } else {
            let Some((mut buf, len, known)) =
                self.accumulators
                    .detach_for_recv(conn_index, self.recv_direct_region, need)
            else {
                self.abort_recv(conn_index, crate::accumulator::recv_cap_exceeded());
                return true;
            };
            let held = buf.len();
            // SAFETY: `len` bytes are reserved behind the buffer's length.
            let ptr = unsafe { buf.as_mut_ptr().add(held) };
            (DirectRecvBuf::Accumulator(buf), ptr, len, held, known)
        };
        let slot = match self.direct_recv_free.pop() {
            Some(slot) => slot,
            None => {
                self.direct_recvs.push(None);
                (self.direct_recvs.len() - 1) as u32
            }
        };
        if self
            .ring
            .submit_recv_direct(conn_index, ptr, len as u32, slot)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            match buf {
                // SAFETY: nothing was submitted, so nothing was written.
                DirectRecvBuf::Accumulator(buf) => unsafe {
                    self.accumulators.attach_received(conn_index, buf, 0)
                },
                DirectRecvBuf::Tls(buf) => {
                    if let Some(t) = self.tls_table.as_mut() {
                        crate::tls::tls_recv_cancel(t, conn_index, buf);
                    }
                }
            }
            self.direct_recv_free.push(slot);
            self.abort_recv(
                conn_index,
                io::Error::other("the receive could not be submitted to the ring"),
            );
            return true;
        }
        self.direct_recvs[slot as usize] = Some(DirectRecv {
            conn_index,
            generation,
            buf,
        });
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.recv_direct_armed = true;
            cs.recv_direct_held = held;
            cs.recv_direct_slot = slot;
        }
        metrics::RECV_DIRECT.increment(metrics::recv_direct::ARMED);
        if known {
            metrics::RECV_DIRECT.increment(metrics::recv_direct::KNOWN_LENGTH);
        }
        false
    }

    /// Drop `conn_index`'s TLS state. If a receive into its ciphertext
    /// buffer is in flight, the buffer's allocation moves to the receive's
    /// `direct_recvs` entry first, so it is freed when the receive completes
    /// rather than while the kernel may still write into it.
    pub(crate) fn release_tls_state(&mut self, conn_index: u32) {
        let Some(tls_table) = self.tls_table.as_mut() else {
            return;
        };
        if let Some(allocation) = crate::tls::tls_take_recv_allocation(tls_table, conn_index) {
            let entry = self.connections.get(conn_index).and_then(|cs| {
                if !cs.recv_direct_armed {
                    return None;
                }
                self.direct_recvs
                    .get_mut(cs.recv_direct_slot as usize)?
                    .as_mut()
                    .filter(|e| e.conn_index == conn_index && e.generation == cs.generation)
            });
            match entry {
                Some(DirectRecv {
                    buf: DirectRecvBuf::Tls(slot @ None),
                    ..
                }) => *slot = Some(allocation),
                _ => {
                    // No entry to hold it: leak it rather than free memory a
                    // receive may write into.
                    debug_assert!(false, "a TLS receive in flight without its entry");
                    std::mem::forget(allocation);
                }
            }
        }
        tls_table.remove(conn_index);
    }

    /// Arm `conn_index`'s hangup poll (`OpTag::HangupPoll`) once it is
    /// open, on a direct or a TLS connection. Both arm a receive only when a
    /// read parks (a TLS connection once its handshake is done), so without
    /// the poll a peer FIN or reset is not seen until a receive completes, and
    /// while no read is parked none may be in flight. If the
    /// SQE cannot be pushed, the failure is counted in
    /// `ring::RECV_ARM_FAILURES` and the connection goes on
    /// `hangup_poll_retries`, so `retry_hangup_polls` submits the poll again.
    pub(crate) fn arm_hangup_poll(&mut self, conn_index: u32) {
        let Some(cs) = self.connections.get(conn_index) else {
            return;
        };
        let tls = self.tls_table.as_ref().is_some_and(|t| t.has(conn_index));
        if !(cs.recv_direct || tls) || cs.hangup_poll_armed || cs.recv_finished() {
            return;
        }
        let generation = cs.generation;
        if self
            .ring
            .submit_hangup_poll(conn_index, generation)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            if let Some(cs) = self.connections.get_mut(conn_index)
                && !cs.hangup_poll_retry
            {
                cs.hangup_poll_retry = true;
                self.hangup_poll_retries.push((conn_index, generation));
            }
            return;
        }
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.hangup_poll_armed = true;
            cs.hangup_poll_retry = false;
        }
    }

    /// Close `conn_index` because its receive cannot be armed, and record
    /// `err` on `recv_aborts` for its reader. `read` is set first, so the
    /// close reads as a failure and not as the peer's close.
    fn abort_recv(&mut self, conn_index: u32, err: io::Error) {
        let generation = self.connections.generation(conn_index);
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.read = ReadHalf::Error;
        }
        self.recv_aborts.push_back((conn_index, generation, err));
        self.close_connection(conn_index);
    }

    /// Take the aborts recorded by [`arm_direct_recv_or_close`](Self::arm_direct_recv_or_close)
    /// since the last call, for the caller to hand to `Executor::fail_recv`.
    pub(crate) fn take_recv_aborts(&mut self) -> VecDeque<(u32, u32, io::Error)> {
        std::mem::take(&mut self.recv_aborts)
    }

    /// Whether a TLS connection's receive that completed should be re-armed
    /// at once: during the handshake and after its hangup poll has completed.
    /// Otherwise its next parked read arms the receive, so a task that does
    /// not read stops its peer. False for a connection with no TLS state,
    /// such as one whose completion closed it.
    pub(crate) fn rearms_after_completion(&self, conn_index: u32) -> bool {
        let tls = self.tls_table.as_ref().is_some_and(|t| t.has(conn_index));
        if !tls {
            return false;
        }
        self.connections
            .get(conn_index)
            .is_some_and(|c| !c.established || c.hangup_seen)
    }

    /// Submit a hangup peek on `conn_index` (`OpTag::HangupPeek`) and record
    /// it as in flight. Returns whether it was pushed; a failure is counted
    /// in `ring::RECV_ARM_FAILURES`.
    pub(crate) fn submit_hangup_peek(&mut self, conn_index: u32) -> bool {
        let generation = self.connections.generation(conn_index);
        let buf = self.hangup_peek_buf.as_mut_ptr();
        if self
            .ring
            .submit_hangup_peek(conn_index, generation, buf)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            return false;
        }
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.hangup_peek_armed = true;
        }
        true
    }
}

/// I/O driver encapsulating all infrastructure state (ring, buffers, connections).
///
/// `AsyncEventLoop` is composed of a `Driver` + handler + executor.
///
/// # Drop order
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
    /// Provided buffer rings backing UDP multishot recvmsg, one per socket and
    /// indexed like `udp_sockets`. A socket that runs out of buffers stops
    /// reading, and the others are unaffected.
    pub(crate) udp_provided_bufs: Vec<ProvidedBufRing>,
    /// `(udp_index, bid)` of buffers that have been consumed and need to be
    /// handed back to the kernel. Drained each loop pass.
    pub(crate) udp_pending_replenish: Vec<(u32, u16)>,
    /// Sockets to re-arm: their multishot ended with `ENOBUFS` and waits for a
    /// buffer, or an earlier re-arm could not be submitted.
    pub(crate) udp_awaiting_buffers: Vec<u32>,
    pub(crate) send_copy_pool: SendCopyPool,
    pub(crate) send_slab: InFlightSendSlab,
    pub(crate) accumulators: AccumulatorTable,
    /// Bytes already detached from the accumulator by a zero-copy
    /// `forward_recv_buf` during the current `with_data` / `with_bytes`
    /// closure. The delivery future subtracts this from what the closure
    /// reports consuming, because the forward already removed those bytes
    /// (see `ConnCtx::forward_recv_buf`).
    pub(crate) forward_zc_consumed: Vec<u32>,
    /// Send slab entries a connection that forwards its receive buffers may
    /// hold before it stops receiving, once the slab is over half used. See
    /// `ConfigBuilder::forward_hold_cap`.
    pub(crate) forward_hold_cap: usize,
    /// Per-connection: a `forward_recv_buf` of the whole accumulator has
    /// queued a send.
    pub(crate) forwards_recv_buf: Vec<bool>,
    /// Per-connection: a parked read found `forward_recv_over_cap` true and
    /// armed no receive, so the peer's window closes.
    pub(crate) forward_recv_held: Vec<bool>,
    /// The connections with `forward_recv_held` set, rechecked each loop
    /// iteration.
    pub(crate) forward_recv_held_conns: Vec<u32>,
    /// Per-connection receive arrival log (`recv::arrival`).
    pub(crate) arrival: Vec<crate::recv::arrival::ArrivalLog>,
    /// The current completion batch, whose time the arrival logs record. A
    /// batch begins in `drain_completions` after each reap.
    pub(crate) recv_batch: crate::recv::arrival::BatchClock,
    /// The handler has offered this connection for park (tier 3, #443).
    ///
    /// Depositing is the opt-in: a connection whose handler never offered it
    /// is never parked. Cleared whenever recv delivers, because new data
    /// means a new request began and the quiescent point the handler offered
    /// at is gone — so the handler never has to remember to revoke. Set only
    /// through `offer_park`, which declines while bytes are unread or while
    /// the innermost running reader callback is this connection's.
    pub(crate) park_offered: Vec<bool>,
    /// Per connection: a park cancelled this connection's receive and hangup
    /// poll and is waiting for the handler to come back to a quiescent point.
    ///
    /// A cancel cannot retract completions the kernel had already posted, so
    /// the install is not linked to the cancel: it waits until the handler
    /// re-offers and nothing is armed. See
    /// `docs/journal/2026-09-two-phase-park.md`.
    ///
    /// Every path that stops a drain must clear this and give the connection
    /// back its hangup poll (`rearm_direct_after_park`).
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
    pub(crate) peer_park: Vec<(crate::handoff::Sender<ParkedFd>, crate::wakeup::WakeFd)>,
    /// This worker's receiving end: connections other workers parked here.
    pub(crate) park_rx: Option<crate::handoff::Receiver<ParkedFd>>,
    /// Connections lifted off this worker, waiting to be handed over.
    /// `OwnedFd` means an entry left here is closed rather than leaked.
    pub(crate) park_ready: Vec<ParkedFd>,
    /// Per connection index: is a [`RecvHalf`] out? Set when the connection is
    /// delivered and cleared when the half drops. The last half to go closes
    /// the connection (`release_half`).
    pub(crate) recv_half_taken: Vec<bool>,
    /// Per connection index: is a [`SendHalf`](crate::SendHalf) currently out?
    ///
    /// The write-side twin of `recv_half_taken`.
    pub(crate) send_half_taken: Vec<bool>,
    pub(crate) accept_rx: Option<crate::handoff::Receiver<crate::acceptor::AcceptedConn>>,
    /// Merged accept mode: every merged listener's sockets, `(listener index,
    /// sockets)`. This worker accepts on socket `worker_index` of each, and
    /// holds them open until it exits. Empty in pool mode.
    pub(crate) merged_listeners: Vec<(
        u32,
        std::sync::Arc<crate::listener_sockets::ListenerSockets>,
    )>,
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
        crate::handoff::Sender<crate::acceptor::AcceptedConn>,
        crate::wakeup::WakeFd,
    )>,
    /// This worker's wake eventfd, read by the ring. Not owned: the worker's
    /// `WakeHandle` owns it, and `Config::wake_keep_alive` holds that handle
    /// until the worker exits.
    pub(crate) eventfd: RawFd,
    pub(crate) eventfd_buf: [u8; 8],
    /// Wake handle for cross-thread wakeup (wraps the eventfd).
    pub(crate) wake_handle: crate::wakeup::WakeFd,
    /// Deadline-based flush interval. None = disabled (SQPOLL or explicit 0).
    pub(crate) flush_interval: Option<Duration>,
    pub(crate) shutdown_flag: Arc<AtomicBool>,
    pub(crate) shutdown_local: bool,
    /// Handles task panics caught on this worker, under the runtime's policy.
    pub(crate) panic_reporter: crate::task_panic::PanicReporter,
    #[cfg(test)]
    pub(crate) test_fault: Option<std::sync::Arc<crate::config::TestFault>>,
    pub(crate) tls_table: Option<crate::tls::TlsTable>,
    /// Pre-allocated sockaddr storage for outbound connect SQEs.
    pub(crate) connect_addrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated timespec storage for connect timeouts.
    pub(crate) connect_timespecs: Vec<crate::backend::uring::abi::Timespec>,
    /// Pre-allocated batch buffer for draining CQEs.
    /// Tuple: (user_data, result, flags).
    pub(crate) cqe_batch: Vec<(u64, i32, u32)>,
    /// How many of `cqe_batch`'s completions have been dispatched. After a
    /// panic in a handler, `run_shutdown` handles the ones after it, and when
    /// `run_shutdown` panics, `close_fds_in_unhandled_completions` closes the
    /// fds among them. What the panicking handler held, such as an accepted
    /// fd, is lost.
    pub(crate) cqe_cursor: usize,
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
    /// Scratch for TLS output sends collected during CQE handling.
    pub(crate) tls_out_scratch: Vec<crate::handler::BuiltSend>,
    /// Monotonic disk-I/O sequence (see DriverCtx::disk_io_key).
    pub(crate) next_disk_io_seq: u16,
    /// Buffers of in-flight direct receives,
    /// indexed by the `RecvDirect` payload. An entry holds the accumulator
    /// buffer the kernel writes into and is removed only by that receive's
    /// completion, so the memory outlives the operation across close and
    /// slot reuse (Domain Invariant 1). `None` is a free index
    /// (`direct_recv_free`).
    pub(crate) direct_recvs: Vec<Option<DirectRecv>>,
    pub(crate) direct_recv_free: Vec<u32>,
    /// Destination of every hangup peek (`OpTag::HangupPeek`). The byte is
    /// never read; it only has to stay valid while a peek is in flight, which
    /// a buffer the driver owns does.
    pub(crate) hangup_peek_buf: Box<[u8; 1]>,
    /// `(conn_index, generation)` of direct connections that need another
    /// hangup peek once their bytes are read
    /// (`ConnectionState::hangup_recheck`). A connection goes on it when:
    ///
    /// - a hangup peek found bytes queued ahead of the end of the stream;
    /// - a hangup peek found the end with bytes buffered or a receive in
    ///   flight;
    /// - the hangup poll completed with a receive in flight;
    /// - the peek the hangup poll triggered could not be submitted.
    ///
    /// `recheck_hangups` peeks again once `hangup_recheck_due` is set and
    /// nothing is buffered, armed or parking, so the end is seen even if no
    /// read parks after the bytes are consumed.
    pub(crate) hangup_rechecks: Vec<(u32, u32)>,
    /// `(conn_index, generation)` of direct connections whose hangup poll
    /// could not be submitted (`ConnectionState::hangup_poll_retry`).
    /// `retry_hangup_polls` submits it again while no park is pending, and
    /// drops the entry once it is armed.
    pub(crate) hangup_poll_retries: Vec<(u32, u32)>,
    /// `Config::recv_direct_region`.
    pub(crate) recv_direct_region: usize,
    /// `Config::defer_recv_arm`.
    pub(crate) defer_recv_arm: bool,
    /// Receives `park_recv` deferred under `defer_recv_arm`, as
    /// `(conn_index, generation, need)`. `arm_deferred_recvs` arms them before
    /// a wait that would block, or after the next wait.
    pub(crate) deferred_recv_arms: Vec<(u32, u32, Option<usize>)>,
    /// Arrival timestamp shared by all UDP datagrams queued in one CQE
    /// drain batch. One clock read per batch instead of one per datagram;
    /// precision loss is bounded by the drain duration (microseconds).
    pub(crate) udp_batch_recv_at: std::time::Instant,
    /// Tick timeout duration. When set, a timeout SQE ensures the event loop
    /// wakes periodically even when no I/O completions are pending.
    pub(crate) tick_timeout_ts: Option<crate::backend::uring::abi::Timespec>,
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
    /// `SendPollOut`s the SQ had no room for: (conn_index, generation, multi).
    /// Drained each tick.
    pub(crate) pending_send_pollout_retries: Vec<(u32, u32, bool)>,
    /// Connections with a send waiting for room, as (conn_index, generation),
    /// for `handle_send_backstop`. An entry leaves when the timer finds nothing
    /// waiting.
    pub(crate) send_backstop_list: Vec<(u32, u32)>,
    /// Scratch swapped with `send_backstop_list` while the timer walks it.
    pub(crate) send_backstop_scratch: Vec<(u32, u32)>,
    /// The `SendBackstop` timer's interval.
    pub(crate) send_backstop_ts: crate::backend::uring::abi::Timespec,
    /// Whether the `SendBackstop` timer is armed.
    pub(crate) send_backstop_armed: bool,
    /// Pending coalesced-send retries: (conn_index, generation, slab_idx, retries).
    /// Drained each tick — used when resubmitting a coalesced `sendmsg` found
    /// the SQ full.
    pub(crate) pending_coalesced_retries: Vec<(u32, u32, u16, u8)>,
    /// Pending close retries: (conn_index, retries). Drained each tick.
    pub(crate) pending_close_retries: Vec<(u32, u8)>,
    /// `Shutdown` SQEs the ring refused: (conn_index, generation). The write
    /// half already reads `Shutdown` and `shutdown_inflight` is set, so the
    /// Close waits for the FIN; `drain_shutdown_retries` pushes each again
    /// on the close-retry backoff and drops one whose slot has been released
    /// (its generation changed): nothing waits on the flag for a released
    /// slot, and `reset_send_state` clears it at reactivation.
    pub(crate) pending_shutdown_retries: Vec<(u32, u32)>,
    /// Connections whose queued head send could not be pushed (SQ still
    /// full after submit): (conn_index, generation, attempts). Drained each
    /// tick by `drain_send_retries`; the entry stays at the queue head with
    /// `in_flight = true` meanwhile, so stream order and the close deferral
    /// are preserved. Two failed attempts fail the queued sends and close the
    /// connection, mirroring `pending_copy_retries`.
    pub(crate) pending_send_retries: Vec<(u32, u32, u8)>,
    /// Awaited sends that no CQE will ever settle, in settle order and keyed
    /// by the id the submitting future holds. Drained by the event loop into
    /// `Executor::complete_send`; the driver never touches the `Executor`
    /// itself.
    ///
    /// The payload is an `io::Result`, as in mio's `settled_sends`, because
    /// what unites these entries is the missing completion, not a failure: a zero-length
    /// message (and a TLS one whose plaintext produced no record) queues no
    /// SQE at all and still has to resolve — with `Ok`, and with the same
    /// value mio reports for it.
    ///
    /// Two producers, and both exist because there is no CQE behind them.
    /// `DriverCtx::send_awaited`, `SendBuilder::submit_awaited` and
    /// `DriverCtx::send_bounded` settle here when they finish a send
    /// synchronously, for the same reason mio has a completion queue at all:
    /// a `DriverCtx` is a borrow of driver fields with no executor access.
    /// Teardown (`release_queued_sends`, via `drain_conn_send_queue`,
    /// `force_finalize_close` and `reset_send_state`) settles here because
    /// the `BuiltSend`s it destroys were never submitted.
    ///
    /// `run_shutdown` pushes here too, into a queue nobody will drain. That
    /// is correct: the executor is going away with the driver, exactly as
    /// mio's `Driver::drop` produces no completions.
    pub(crate) settled_sends: VecDeque<(SendId, io::Result<u32>)>,
    /// Connections `arm_direct_recv_or_close` closed because it could not arm
    /// their receive — no room under `recv_accumulator_max` or in the TLS
    /// engine's buffer, or the SQE could not be pushed — with the error the
    /// reader is owed, keyed by `(conn_index, generation)`. Drained by the
    /// caller into `Executor::fail_recv` before the woken reader is polled;
    /// the driver never touches the `Executor` itself.
    pub(crate) recv_aborts: VecDeque<(u32, u32, io::Error)>,
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
    /// Connections whose Close is owed to the event loop's end-of-iteration
    /// drain, which runs `try_finalize_close` for each. `close_connection`
    /// (read error, task exit, setup failure) registers a
    /// connection when it requests its close with nothing outstanding,
    /// `DriverCtx::close` whenever it requests one, and
    /// `defer_finalize_close` registers it from the completion that drains
    /// its sends, chain or `Shutdown`. The drain runs
    /// after `poll_ready_tasks`, so a task woken in the same iteration is
    /// polled, and a send it queues drains, before the Close is committed
    /// (#371).
    pub(crate) pending_finalize_closes: Vec<u32>,
    /// Scratch buffers swapped with the corresponding `pending_*_retries`
    /// queue at drain time so the per-tick drain reuses a single allocation
    /// across ticks (the primary queue is left empty for in-iteration
    /// re-enqueues; `drain(..)` on the scratch keeps its capacity).
    pub(crate) zc_retry_scratch: Vec<(u32, u32, u16, u8)>,
    pub(crate) copy_retry_scratch: Vec<(u32, u32, u16, u8, OpTag)>,
    pub(crate) coalesced_retry_scratch: Vec<(u32, u32, u16, u8)>,
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
    /// Set by [`run_shutdown`](Self::run_shutdown) when an fs, direct I/O or
    /// NVMe command was still in flight at its bound. The kernel can still use
    /// the command's buffer, statx box or path, so the worker leaks its event
    /// loop instead of dropping it (#824).
    pub(crate) disk_io_outstanding: bool,
}

/// A park in flight: the `FixedFdInstall` has been submitted and its CQE has
/// not landed yet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParkInFlight {
    pub target: usize,
    /// Generation at submit time, the one the install CQE carries. The entry
    /// is set for the slot's current generation and cleared by
    /// `clear_conn_claims` when `handle_close` or `run_shutdown` releases the
    /// slot; the other release sites free a slot allocated in the same call,
    /// which no park has reached. So it is always the slot's current
    /// occupant's.
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
    /// An outbound connection. It has no listener, so it was never placed by
    /// accept and there is no placement imbalance for park to repair.
    Outbound,
    /// The handler has not offered this connection via `offer_for_park`.
    /// Park is opt-in, so this is the common answer, not an error.
    NotOffered,
    /// Teardown is already requested, or the read or write half is finished.
    /// Park loses this race deliberately: moving a connection that is closing
    /// or half-closed buys nothing, and the close path is the one carrying
    /// the invariants.
    Closing,
    /// Queued or in-flight sends. Their SQEs reference *this* worker's
    /// `SendCopyPool` slots and `InFlightSendSlab` entries, which Domain
    /// Invariant 1 requires outlive the operation, so the fd cannot leave
    /// until they land.
    Sends,
    /// A send chain has SQEs in the kernel whose CQEs drive its own
    /// accounting; it has to finish where it started.
    Chain,
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
            ParkBlocker::Outbound => pa::OUTBOUND,
            ParkBlocker::NotOffered => pa::NOT_OFFERED,
            ParkBlocker::Closing => pa::CLOSING,
            ParkBlocker::Sends => pa::SENDS,
            ParkBlocker::Chain => pa::CHAIN,
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
            ParkBlocker::Outbound,
            ParkBlocker::NotOffered,
            ParkBlocker::Closing,
            ParkBlocker::Sends,
            ParkBlocker::Chain,
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
        accept_rx: Option<crate::handoff::Receiver<crate::acceptor::AcceptedConn>>,
        park_rx: Option<crate::handoff::Receiver<ParkedFd>>,
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
        let mut ring = Ring::setup(config)?;

        let fixed_buffers =
            FixedBufferRegistry::new(&config.registered_regions, config.max_registered_regions);

        let udp_count = config.udp_bind.len() as u32;
        let udp_provided_bufs = (0..udp_count)
            .map(|i| {
                ProvidedBufRing::new(
                    config.udp_recv_buffer.bgid + i as u16,
                    config.udp_recv_buffer.ring_size,
                    config.udp_recv_buffer.buffer_size,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        for udp_bufs in &udp_provided_bufs {
            ring.register_buf_ring(udp_bufs)?;
        }

        let connections = ConnectionTable::new(config.max_connections);
        let mut send_copy_pool =
            SendCopyPool::new(config.send_copy_count, config.send_copy_slot_size);
        if config.prefault_buffers {
            send_copy_pool.prefault();
        }
        let send_slab = InFlightSendSlab::new(config.send_slab_slots);
        let mut accumulators = AccumulatorTable::new_with_max(
            config.max_connections,
            config.recv_accumulator_capacity,
            config.recv_accumulator_max,
        );
        accumulators.set_direct_pool_max(config.recv_direct_pool_max);

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
                    config.tls.as_ref().map(|tc| tc.rustls_config().clone()),
                    config
                        .tls_client
                        .as_ref()
                        .map(|tc| tc.rustls_config().clone()),
                    config
                        .listener_tls
                        .iter()
                        .map(|slot| slot.as_ref().map(|tc| tc.rustls_config().clone()))
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
            crate::backend::uring::abi::Timespec::new(),
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
            udp_provided_bufs,
            udp_pending_replenish: Vec::new(),
            udp_awaiting_buffers: Vec::new(),
            send_copy_pool,
            send_slab,
            accumulators,
            forward_zc_consumed: vec![0; config.max_connections as usize],
            forward_hold_cap: config.forward_hold_cap,
            forwards_recv_buf: vec![false; config.max_connections as usize],
            forward_recv_held: vec![false; config.max_connections as usize],
            forward_recv_held_conns: Vec::new(),
            arrival: (0..config.max_connections)
                .map(|_| crate::recv::arrival::ArrivalLog::default())
                .collect(),
            recv_batch: crate::recv::arrival::BatchClock::new(),
            adopt_pending: std::collections::HashMap::new(),
            park_offered: vec![false; config.max_connections as usize],
            park_drain: vec![None; config.max_connections as usize],
            park_drain_pending: Vec::new(),
            park_carry: std::collections::HashMap::new(),
            park_in_flight: vec![None; config.max_connections as usize],
            park_ready: Vec::new(),
            peer_park: config.peer_park.clone(),
            park_rx,
            recv_half_taken: vec![false; config.max_connections as usize],
            send_half_taken: vec![false; config.max_connections as usize],
            accept_rx,
            merged_listeners: config.merged_listeners.clone(),
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
            #[cfg(test)]
            test_fault: config.test_fault.clone(),
            panic_reporter: crate::task_panic::PanicReporter::new(
                config.task_panic_policy,
                shutdown_flag.clone(),
                config.runtime_shutdown.clone(),
            ),
            shutdown_flag,
            shutdown_local: false,
            tls_table,
            connect_addrs,
            connect_timespecs,
            cqe_batch: Vec::with_capacity(config.sq_entries as usize * 4),
            cqe_cursor: 0,
            tcp_nodelay: config.tcp_nodelay,
            loop_diag: config.loop_diag,
            send_zc_threshold: config.send_zc_threshold,
            chain_table: SendChainTable::new(config.max_connections),
            max_chain_length: config.max_chain_length,
            send_queues,
            close_notify_armed: Vec::new(),
            tls_out_scratch: Vec::new(),
            next_disk_io_seq: 0,
            direct_recvs: Vec::new(),
            direct_recv_free: Vec::new(),
            hangup_peek_buf: Box::new([0]),
            hangup_rechecks: Vec::new(),
            hangup_poll_retries: Vec::new(),
            recv_direct_region: config.recv_direct_region,
            defer_recv_arm: config.defer_recv_arm,
            deferred_recv_arms: Vec::new(),
            udp_batch_recv_at: std::time::Instant::now(),
            tick_timeout_ts: if config.tick_timeout_us > 0 {
                Some(
                    crate::backend::uring::abi::Timespec::new()
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
            send_backstop_list: Vec::new(),
            send_backstop_scratch: Vec::new(),
            send_backstop_ts: crate::backend::uring::abi::Timespec::new().sec(1),
            send_backstop_armed: false,
            pending_coalesced_retries: Vec::new(),
            pending_close_retries: Vec::new(),
            pending_shutdown_retries: Vec::new(),
            pending_send_retries: Vec::new(),
            settled_sends: VecDeque::new(),
            recv_aborts: VecDeque::new(),
            capacity_released: false,
            pending_finalize_closes: Vec::new(),
            zc_retry_scratch: Vec::new(),
            copy_retry_scratch: Vec::new(),
            coalesced_retry_scratch: Vec::new(),
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
            disk_io_outstanding: false,
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
        // CQE per datagram until the socket's buffer ring is exhausted. Connected
        // sockets use the lighter `RecvUdp` opcode (no recvmsg metadata);
        // unconnected sockets use `RecvMsgUdp` so the kernel returns the
        // peer address in each CQE buffer.
        for udp_idx in 0..driver.udp_sockets.len() {
            let udp_bgid = driver.udp_provided_bufs[udp_idx].bgid();
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
            connect_timespecs: &mut self.connect_timespecs,
            chain_table: &mut self.chain_table,
            max_chain_length: self.max_chain_length,
            send_queues: &mut self.send_queues,
            close_notify_armed: &mut self.close_notify_armed,
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
            pending_shutdown_retries: &mut self.pending_shutdown_retries,
            pending_send_retries: &mut self.pending_send_retries,
            settled_sends: &mut self.settled_sends,
            capacity_released: &mut self.capacity_released,
            next_disk_io_seq: &mut self.next_disk_io_seq,
            tls_chain_carried: false,
        }
    }

    /// Reset per-connection send state for a (re)activated slot.
    ///
    /// A previous occupant's close can leave `in_flight`/`close_pending` set:
    /// its final send CQE can arrive after the slot was released, and the
    /// CQE's identity check correctly refuses to touch the slot's state —
    /// so nothing else clears it. Without this reset the next occupant's
    /// first send parks behind a completion that will never come.
    pub(crate) fn reset_send_state(&mut self, conn_index: u32) {
        self.forwards_recv_buf[conn_index as usize] = false;
        self.forward_recv_held[conn_index as usize] = false;
        let state = &mut self.send_queues[conn_index as usize];
        // Queued-but-unsubmitted sends from the previous occupant hold
        // pool/slab resources; no SQE was submitted for them, so no CQE
        // will release them — do it here.
        let had_queue = !state.queue.is_empty();
        let settles = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
        );
        state.in_flight = false;
        state.parked = false;
        state.close_pending = false;
        state.close_submitted = false;
        // Defensive: the close now waits on this, so a slot should never be
        // reactivated with a Shutdown still outstanding. If the gate ever leaks,
        // the next occupant must not inherit the block.
        state.shutdown_inflight = false;
        state.close_notify_pending = None;
        state.waiting_send = None;
        state.send_poll = SendPoll::None;
        state.pollout_seen = false;
        state.resubmitted_on_pollout = false;
        state.on_send_backstop = false;
        self.disarm_close_notify_deadline(conn_index);
        // A previous occupant's awaited send can still be sitting in the
        // queue here (its close abandoned the drain); the new occupant must
        // not inherit it, and its caller is still waiting.
        self.fail_send_ids(settles, had_queue);
    }

    /// Clear both half flags, and the park in flight, for a slot being
    /// recycled.
    ///
    /// A half dropped with the task at `handle_close` clears its own flag
    /// (`release_half`, under `with_driver_state`). An occupant that died
    /// without dropping a half, one whose `on_accept` panicked while building
    /// the future, leaves its flags set, and since the flags are indexed by
    /// slot rather than by generation, the next occupant would inherit them.
    ///
    /// Clearing here, at the recycle point, makes that impossible regardless of
    /// how the previous occupant died.
    ///
    /// A park in flight is likewise indexed by slot. `begin_park` refuses a
    /// slot with an entry, so one left by the previous occupant would hold
    /// off the next occupant's park until its CQE lands; `handle_park_install`
    /// checks the generation before it reads the entry, so a CQE that lands
    /// after the clear touches nothing on the slot.
    pub(crate) fn clear_conn_claims(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if let Some(taken) = self.recv_half_taken.get_mut(idx) {
            *taken = false;
        }
        if let Some(taken) = self.send_half_taken.get_mut(idx) {
            *taken = false;
        }
        if let Some(park) = self.park_in_flight.get_mut(idx) {
            *park = None;
        }
    }

    /// Whether a park of the connection is draining (`park_drain`) or its
    /// install is in flight (`park_in_flight`, for the connection's current
    /// generation). While draining, a cancel for its receive has been
    /// submitted; while the install is in flight, no receive is armed. Arms
    /// are refused while this holds.
    pub(crate) fn park_pending(&self, conn_index: u32) -> bool {
        let ci = conn_index as usize;
        let generation = self.connections.generation(conn_index);
        self.park_drain.get(ci).is_some_and(|d| d.is_some())
            || self
                .park_in_flight
                .get(ci)
                .is_some_and(|p| p.is_some_and(|p| p.generation == generation))
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

    /// Request the close of `conn_index`: mark it `Closing`, set
    /// `close_pending`, and leave its send queue to drain through
    /// `submit_next_queued`. The send handlers register the connection for
    /// the end-of-iteration drain (`defer_finalize_close`); with nothing
    /// queued or in flight, this method registers it itself. The drain's
    /// `try_finalize_close` commits the Close once no send, chain or
    /// `Shutdown` is outstanding. Park state is released here, since a slot
    /// that is never reused would hold a `ParkState` for the life of the
    /// process.
    pub(crate) fn close_connection(&mut self, conn_index: u32) {
        if let Some(conn) = self.connections.get_mut(conn_index) {
            if conn.close_requested() {
                return; // already closing — avoid double Close SQE
            }
            conn.lifecycle = Lifecycle::Closing;
        } else {
            return;
        }
        self.forward_zc_consumed[conn_index as usize] = 0;
        // Release handler state here rather than waiting for the slot to be
        // reused: a `ParkState` is an arbitrary user value, and a slot that is
        // never reused would hold it for the life of the process.
        self.park_offered[conn_index as usize] = false;
        self.set_park_drain(conn_index, None);
        self.park_carry.remove(&conn_index);
        self.adopt_pending.remove(&conn_index);
        // An active chain keeps its state: its SQEs are in the kernel and
        // their CQEs drive the chain accounting (an error in one linked op
        // cancels the rest, still with CQEs); `try_finalize_close` waits for
        // it, so the Close cannot recycle the slot under them. Cancelling
        // the chain here would drop that accounting.
        // The queue is neither released nor submitted here: entries not yet
        // submitted carry bytes the peer is owed, and io_uring does not
        // order independent SQEs (Domain Invariant 2), so they go out one
        // at a time through `submit_next_queued`.
        let state = &mut self.send_queues[conn_index as usize];
        state.close_pending = true;
        if state.in_flight {
            // Something is in-flight; wait for its CQE to drain the queue.
            return;
        }
        // Nothing in-flight but queue has items — start the serialized drain:
        // submit only the queue head (submit_next_queued coalesces a safe
        // run) and let each CQE pull the next entry. Pushing the whole queue
        // as parallel SQEs here would let the kernel reorder them (Domain
        // Invariant 2).
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

    /// Drain the accumulator into owned bytes (tier 3, #443).
    ///
    /// Normally returns nothing. `park_blocker` refuses while any bytes are
    /// unconsumed (`ParkBlocker::DataPending`), so a connection that reaches
    /// here has an empty accumulator. If bytes do get past that check, they
    /// travel with the park instead of being discarded.
    pub(crate) fn take_pending_for_park(&mut self, conn_index: u32) -> Vec<bytes::Bytes> {
        let acc = self.accumulators.take_frozen(conn_index);
        if acc.is_empty() {
            Vec::new()
        } else {
            vec![acc]
        }
    }

    /// Bytes the connection holds that no consumer has taken: the
    /// accumulator and the bytes in the buffer a direct receive holds
    /// (`recv_direct_held`).
    ///
    /// The arrival log takes the first unread stream offset as
    /// `delivered - recv_buffered`.
    pub(crate) fn recv_buffered(&self, conn_index: u32) -> usize {
        self.accumulators.len(conn_index)
            + self
                .connections
                .get(conn_index)
                .map_or(0, |c| c.recv_direct_held)
    }

    /// Record `n` bytes delivered to the connection in the current batch.
    /// Runs before the bytes are placed anywhere.
    pub(crate) fn record_arrival(&mut self, conn_index: u32, n: usize) {
        if n == 0 {
            return;
        }
        self.arrival_trim_if_due(conn_index);
        self.arrival_add(conn_index, n);
    }

    /// Step 1 of a record: trim the arrival log if it is due, using the
    /// current `delivered` and `recv_buffered`.
    pub(crate) fn arrival_trim_if_due(&mut self, conn_index: u32) {
        if self.arrival[conn_index as usize].trim_due() {
            let unread = self.arrival[conn_index as usize]
                .delivered()
                .saturating_sub(self.recv_buffered(conn_index) as u64);
            self.arrival[conn_index as usize].trim(unread);
        }
    }

    /// Start recording a TLS feed: step 1 of a record, then the
    /// `recv_buffered` count the feed's plaintext is measured against.
    pub(crate) fn arrival_feed_start(&mut self, conn_index: u32) -> usize {
        self.arrival_trim_if_due(conn_index);
        self.recv_buffered(conn_index)
    }

    /// Finish recording a TLS feed: add the growth of `recv_buffered` since
    /// [`arrival_feed_start`](Self::arrival_feed_start) returned `before`,
    /// which is the plaintext the feed delivered.
    pub(crate) fn arrival_feed_end(&mut self, conn_index: u32, before: usize) {
        let plaintext = self.recv_buffered(conn_index).saturating_sub(before);
        self.arrival_add(conn_index, plaintext);
    }

    /// Step 2 of a record: add `n` bytes at the current batch's time.
    pub(crate) fn arrival_add(&mut self, conn_index: u32, n: usize) {
        self.arrival[conn_index as usize].add(n as u64, &mut self.recv_batch);
    }

    /// Whether the connection holds received bytes that no consumer has
    /// finished with: `recv_buffered` is nonzero, or its TLS engine holds
    /// decrypted plaintext not yet delivered to the accumulator.
    /// `park_blocker` refuses a park while this holds
    /// (`ParkBlocker::DataPending`), and `offer_park` declines an offer.
    pub(crate) fn holds_unread(&self, conn_index: u32) -> bool {
        self.recv_buffered(conn_index) > 0
            || self
                .tls_table
                .as_ref()
                .is_some_and(|t| t.has_undelivered_plaintext(conn_index))
    }

    /// Record a handler's park offer, with the state to carry
    /// (`ConnCtx::offer_for_park`). Returns whether the offer stands.
    ///
    /// The offer is declined, and any earlier offer and deposit cleared,
    /// while the connection holds unread bytes, or while the connection's
    /// reader callback is the innermost one running on this thread. Either
    /// way the handler may be partway through a request, so the offer is not
    /// treated as made at an idle point (#669). An offer that stands
    /// therefore means the driver held no unread bytes when it was made, and
    /// arriving bytes withdraw it (`withdraw_park_offer`).
    pub(crate) fn offer_park(
        &mut self,
        conn_index: u32,
        state: Option<crate::park::ParkState>,
    ) -> bool {
        let idx = conn_index as usize;
        if self.holds_unread(conn_index) || crate::runtime::io::in_reader_callback(conn_index) {
            self.park_offered[idx] = false;
            self.park_carry.remove(&conn_index);
            crate::metrics::PARK_DIAG.increment(crate::metrics::park_diag::OFFER_DECLINED);
            return false;
        }
        self.park_offered[idx] = true;
        match state {
            Some(s) => {
                self.park_carry.insert(conn_index, s);
            }
            // An offer with nothing to carry still clears any earlier
            // deposit, so a stale one is never shipped.
            None => {
                self.park_carry.remove(&conn_index);
            }
        }
        true
    }

    /// The park gate (tier 3, #443). `None` means quiescent and movable.
    ///
    /// `recv_half_taken` / `send_half_taken` are deliberately not blockers.
    /// Since #427 the halves are the normal API and a typical handler holds
    /// both for the connection's whole life. They are owned by the future,
    /// which park drops, so they clear as part of the move rather than
    /// blocking it.
    ///
    /// Unread bytes block as `ParkBlocker::DataPending` (`holds_unread`).
    ///
    /// A TLS connection's state moves with it (`ParkedFd::tls`), including
    /// any ciphertext received but not yet processed.
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
        // A hangup peek took the socket's error and kept it here for the read
        // that finds the end. The socket no longer holds it, so moving the
        // connection would turn that error into a clean end of stream.
        if conn.hangup_error != 0 {
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

        // Backstop for the withdraw-on-recv rule, and the reason it is a
        // state check rather than another event hook: bytes that arrived and
        // have not been consumed make the connection un-idle whether or not
        // the path that delivered them remembered to withdraw the offer. A
        // delivery path added later gets this for free.
        if self.holds_unread(conn_index) {
            return Some(ParkBlocker::DataPending);
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
        if self.chain_table.is_active(conn_index) {
            return Some(ParkBlocker::Chain);
        }
        None
    }

    /// Convenience over [`Self::park_blocker`] for call sites that do not care
    /// which term tripped.
    pub(crate) fn is_parkable(&self, conn_index: u32) -> bool {
        self.park_blocker(conn_index).is_none()
    }

    /// What goes ahead of this connection's `Close`: the ring's choice for
    /// the running kernel ([`CloseLead`](super::ring::CloseLead)), or nothing
    /// for a socket handed to another worker, which must stay open.
    pub(crate) fn close_lead(&self, conn_index: u32) -> super::ring::CloseLead {
        let handed_off = self
            .connections
            .get(conn_index)
            .is_some_and(|c| c.socket_handed_off);
        if handed_off {
            super::ring::CloseLead::Nothing
        } else {
            self.ring.close_lead()
        }
    }

    /// Disarm `conn_index`'s close_notify deadline: clear it and take the
    /// connection off `close_notify_armed`. `swap_remove` is O(n) over a set
    /// bounded by the concurrent TLS shutdowns.
    pub(crate) fn disarm_close_notify_deadline(&mut self, conn_index: u32) {
        self.send_queues[conn_index as usize].close_notify_deadline = None;
        if let Some(pos) = self
            .close_notify_armed
            .iter()
            .position(|&i| i == conn_index)
        {
            self.close_notify_armed.swap_remove(pos);
        }
    }

    /// Submit the deferred `Close` SQE once every pending send, send chain and
    /// `Shutdown` for this connection has finished.
    ///
    /// Called from the event loop's end-of-iteration drain of
    /// `pending_finalize_closes`, from `force_finalize_close`, and from the
    /// park install, which commits the Close of a handed-off socket at once.
    /// The send, chain and `Shutdown` completion handlers do not call this:
    /// they call `defer_finalize_close`, so that when the last gating CQE
    /// lands in the same batch as a read error, the Close is committed after
    /// the task woken by the error has been polled.
    pub(crate) fn try_finalize_close(&mut self, conn_index: u32) {
        let state = &self.send_queues[conn_index as usize];
        let sends_drained = !state.in_flight && state.queue.is_empty();
        // An active send chain has SQEs in the kernel whose CQEs drive its
        // accounting; the chain completion handlers register the connection
        // for the drain once the chain drains.
        let chain_drained = !self.chain_table.is_active(conn_index);
        // A `Shutdown` SQE still in the kernel names this slot as
        // `Fixed(conn_index)`. `Close` frees the slot for the next accept to
        // register, so submitting it now lets the FIN land on that next
        // connection instead — a live peer, cleanly half-closed, whose next send
        // fails `EPIPE`. `handle_shutdown` registers the connection for the
        // drain once the CQE clears the flag.
        let shutdown_drained = !state.shutdown_inflight;
        if !(state.close_pending && sends_drained && chain_drained && shutdown_drained) {
            return;
        }
        // A close_notify the pool had no slot for at the close goes out now
        // if it can; its completion registers the connection for the drain
        // again, and the Close is committed then.
        if self.place_retained_close_notify(conn_index) {
            return;
        }
        let st = &mut self.send_queues[conn_index as usize];
        st.close_pending = false;
        // From here the Close is committed (submitted below, or queued for
        // retry): late CQEs must not push new SQEs for this connection.
        st.close_submitted = true;
        // Clear the deadline so the slot's next occupant doesn't inherit it.
        self.disarm_close_notify_deadline(conn_index);
        if self.submit_committed_close(conn_index).is_err() {
            crate::metrics::RING.increment(crate::metrics::ring::CLOSE_SUBMIT_FAILURES);
            // Queue this connection for retry on a later tick. (An earlier
            // version rebuilt the whole retry vec here — aging every other
            // entry toward discard and never enqueueing the connection whose
            // close just failed, leaking its fd and slot permanently.)
            self.pending_close_retries.push((conn_index, 0));
        }
    }

    /// Submit the `Close` of a connection whose close is committed, after
    /// cancelling its `SendPollOut`: a poll holds the socket open past the
    /// `Close`, and a multishot one outlives a shutdown lead. On an error the
    /// caller retries this; a cancel that went through is not repeated.
    pub(crate) fn submit_committed_close(&mut self, conn_index: u32) -> io::Result<()> {
        let generation = self.connections.generation(conn_index);
        let state = &mut self.send_queues[conn_index as usize];
        if matches!(state.send_poll, SendPoll::OneShot | SendPoll::Multi) {
            self.ring
                .submit_cancel_send_pollout(conn_index, generation)?;
        }
        state.send_poll = SendPoll::None;
        let lead = self.close_lead(conn_index);
        self.ring.submit_close(conn_index, lead)
    }

    /// Register a connection whose close is pending on
    /// `pending_finalize_closes`, so the event loop's end-of-iteration drain
    /// runs `try_finalize_close` for it after this iteration's task poll.
    /// Called from the completion handlers once the queue state has been
    /// updated. Does nothing for a connection whose close is not pending or
    /// is already committed.
    pub(crate) fn defer_finalize_close(&mut self, conn_index: u32) {
        if !self.send_queues[conn_index as usize].close_pending {
            return;
        }
        if !self.pending_finalize_closes.contains(&conn_index) {
            self.pending_finalize_closes.push(conn_index);
        }
    }

    /// Force a deferred close whose drain will never finish (close_notify
    /// deadline elapsed — the peer stopped reading, so the queued/in-flight
    /// sends are stuck). Deliberately abandons outstanding work: queued
    /// (never-submitted) sends are released here; the in-flight send / chain
    /// SQEs are left to the kernel. The Close does not cancel them; the
    /// `CloseLead` linked ahead of it ends them (a shutdown before Linux
    /// 6.13, a cancel from 6.13). Their CQEs (`-ECANCELED`, `EPIPE`, or a
    /// partial count) usually land before the Close CQE. They then find
    /// `close_submitted` set, release their slot or slab entry, and fail
    /// their send without pushing an SQE. A CQE that lands after the Close CQE
    /// fails the generation check and releases only its own slot. The next
    /// occupant is protected by `reset_send_state` at reactivation. A send
    /// waiting for room has only its poll in the kernel: `try_finalize_close`
    /// cancels that, and the poll's CQE or `handle_close` fails the send. A
    /// `Shutdown` in the kernel, or parked on `pending_shutdown_retries`,
    /// still holds the Close until its CQE lands; `handle_shutdown` then
    /// registers the connection for the end-of-iteration drain, which
    /// commits it. The deadline is disarmed here, so this runs once per
    /// close.
    pub(crate) fn force_finalize_close(&mut self, conn_index: u32) {
        // The drain is stuck, so a retained alert would stall the same way:
        // drop it with the queued sends.
        if self.send_queues[conn_index as usize]
            .close_notify_pending
            .take()
            .is_some()
        {
            self.drop_retained_close_notify_flag(conn_index);
        }
        let state = &mut self.send_queues[conn_index as usize];
        let had_queue = !state.queue.is_empty();
        let settles = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
        );
        state.in_flight = false;
        state.parked = false;
        // The sends a `ShutdownPending` waited behind were released above,
        // so no `Shutdown` will be issued for it (`submit_next_queued`
        // issues a pending one when the queue empties, and a late send CQE
        // can reach it after the Close). A `Shutdown` already in the kernel,
        // or parked on `pending_shutdown_retries`, stays recorded:
        // `try_finalize_close` waits for its CQE, and a repeat
        // `shutdown_write` must not submit a second one.
        if let Some(cs) = self.connections.get_mut(conn_index)
            && matches!(cs.write, WriteHalf::ShutdownPending)
        {
            cs.write = WriteHalf::Open;
        }
        self.fail_send_ids(settles, had_queue);
        // The chain's slots come back with its CQEs, which report them.
        if let Some(id) = self.chain_table.cancel(conn_index) {
            self.fail_send_ids(vec![id], false);
        }
        // Disarm whether or not the Close commits now: the queue is
        // abandoned, and if a `Shutdown` holds the Close its CQE commits it.
        self.disarm_close_notify_deadline(conn_index);
        self.try_finalize_close(conn_index);
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
    /// queued sends and closes the connection there.
    pub(crate) fn submit_next_queued(&mut self, conn_index: u32) -> bool {
        // Clear the finished send's wait state.
        let state = &mut self.send_queues[conn_index as usize];
        state.pollout_seen = false;
        state.resubmitted_on_pollout = false;
        self.submit_next_queued_inner(conn_index, 0)
    }

    /// [`submit_next_queued`](Self::submit_next_queued) with the attempt
    /// count to record if the push fails again. `drain_send_retries` passes
    /// `attempts + 1` so a re-park carries the incremented count instead of
    /// restarting at zero; every other caller goes through the public
    /// wrapper with `0`.
    pub(crate) fn submit_next_queued_inner(&mut self, conn_index: u32, attempts: u8) -> bool {
        let ci = conn_index as usize;

        let generation = self.connections.generation(conn_index);
        if let Some(pushed) = submit_coalesced_run(
            RunParts {
                ring: &mut self.ring,
                send_slab: &mut self.send_slab,
                send_copy_pool: &mut self.send_copy_pool,
                send_queues: &mut self.send_queues,
                pending_send_retries: &mut self.pending_send_retries,
            },
            conn_index,
            generation,
            attempts,
        ) {
            return pushed;
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
            let generation = cs.generation;
            cs.write = WriteHalf::Shutdown;
            // The slot must now outlive the SQE, pushed or parked: see
            // `shutdown_inflight`.
            self.send_queues[conn_index as usize].shutdown_inflight = true;
            if self.ring.submit_shutdown(conn_index, generation).is_err() {
                // Refused (ring backpressure): parked, and pushed again by
                // `drain_shutdown_retries`, as a refused send or Close is.
                self.pending_shutdown_retries.push((conn_index, generation));
            }
        }
        // Register a deferred close now that nothing is in flight and the
        // queue is empty. The ZC completion path reaches here without a
        // `defer_finalize_close` call of its own, so without this a
        // close_pending connection would leak its fd and slot.
        self.defer_finalize_close(conn_index);
        false
    }

    /// Submit a built send SQE, or queue it if a send is already in flight.
    ///
    /// This is the Driver-level equivalent of `DriverCtx::submit_or_queue`,
    /// used by `queue_built_sends`, and carries the same contract:
    /// infallible, the entry is committed to the connection's stream on
    /// return. If the push fails (SQ still full after submit) the entry is
    /// parked at the head of the (empty) queue with `in_flight = true` and
    /// the connection is registered on `pending_send_retries`;
    /// `drain_send_retries` re-pushes it.
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
            Ok(()) => {
                state.in_flight = true;
            }
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

    /// Close a connection the application asked to close (`ConnCtx::close`, or
    /// its task finishing). A TLS connection first queues its close_notify, so
    /// the peer can tell the close from a truncation. A close the backend makes
    /// after a receive error, a reset or a failed send CQE goes through
    /// [`close_connection`](Self::close_connection) and sends no alert; an
    /// encryption failure closes through `DriverCtx::close`, which queues one
    /// while the write half is open.
    pub(crate) fn close_connection_graceful(&mut self, conn_index: u32) {
        if self
            .connections
            .get(conn_index)
            .is_some_and(|c| !c.close_requested())
        {
            self.queue_tls_close_notify(conn_index);
        }
        self.close_connection(conn_index);
    }

    /// Queue a TLS connection's close_notify alert through its send queue, so
    /// it goes out after any queued sends and ahead of the FIN. No deadline is
    /// armed: the queue drains however long the peer takes, as for a plaintext
    /// connection. Does nothing for a plaintext connection, a socket handed off
    /// to another worker, or one whose write side is shut down or has a
    /// shutdown pending behind its queued sends.
    fn queue_tls_close_notify(&mut self, conn_index: u32) {
        if self.connections.get(conn_index).is_some_and(|c| {
            c.socket_handed_off || !matches!(c.write, crate::connection::WriteHalf::Open)
        }) {
            return;
        }
        let generation = self.connections.generation(conn_index);
        let mut sends = Vec::new();
        let retained = match self.tls_table.as_mut() {
            Some(tls) if tls.has(conn_index) => tls.send_close_notify_queued(
                conn_index,
                generation,
                &mut self.send_copy_pool,
                &mut sends,
            ),
            _ => return,
        };
        if !sends.is_empty() {
            self.queue_built_sends(conn_index, &mut sends);
        }
        // No slot for the alert now: `try_finalize_close` places it once this
        // connection's own sends have drained and given their slots back.
        self.send_queues[conn_index as usize].close_notify_pending = retained;
    }

    /// Place the close_notify a close found no pool slot for, now that the
    /// connection's own sends have drained. Returns `true` when the alert was
    /// queued, so the Close must wait for its completion. When the pool is
    /// still exhausted the alert is dropped: the Close goes ahead behind a
    /// bare FIN, `pool::CLOSE_NOTIFY_DROPPED` counts it, and the connection
    /// no longer records the alert as sent.
    fn place_retained_close_notify(&mut self, conn_index: u32) -> bool {
        let Some(retained) = self.send_queues[conn_index as usize]
            .close_notify_pending
            .take()
        else {
            return false;
        };
        let generation = self.connections.generation(conn_index);
        let mut sends = Vec::new();
        let placed = match self.tls_table.as_mut() {
            Some(tls) => tls.retry_close_notify_queued(
                conn_index,
                generation,
                &mut self.send_copy_pool,
                &retained,
                &mut sends,
            ),
            None => false,
        };
        if placed {
            if sends.is_empty() {
                // Nothing left to place: on the buffered engine a receive's
                // feed can drain rustls' output, the alert with it, between
                // the close and this drain. The alert is not dropped, so it
                // is not counted, and the Close goes ahead.
                return false;
            }
            self.queue_built_sends(conn_index, &mut sends);
            return true;
        }
        self.drop_retained_close_notify_flag(conn_index);
        false
    }

    /// Count a dropped close_notify and clear the connection's sent flag.
    fn drop_retained_close_notify_flag(&mut self, conn_index: u32) {
        crate::metrics::POOL.increment(crate::metrics::pool::CLOSE_NOTIFY_DROPPED);
        if let Some(tls) = self.tls_table.as_mut() {
            tls.close_notify_dropped(conn_index);
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
        let had_queue = !state.queue.is_empty();
        let settles = Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
        );
        state.in_flight = false;
        state.parked = false;
        // Fail the awaited sends the drained entries carried.
        self.fail_send_ids(settles, had_queue);
        // The queue is now empty and nothing is in flight: register a
        // deferred close, if one is pending, for the end-of-iteration drain,
        // so the connection does not leak. Worker exit clears
        // `close_pending` before calling this and submits its own Close.
        self.defer_finalize_close(conn_index);
    }

    /// Release all entries from a send queue, returning the awaited sends
    /// they were carrying.
    ///
    /// A queued entry was never submitted, so nothing will ever complete it:
    /// if its pool slot or slab entry carries an awaited send, that send has
    /// to be failed or its caller's future hangs — and
    /// `SendCopyPool::release` debug-asserts rather than let the id be
    /// dropped silently. The ids are *returned*
    /// instead of pushed, so the three callers can put them on
    /// `Driver::settled_sends` themselves: every caller already
    /// holds `&mut self` while this takes three disjoint field borrows, and
    /// threading a failures queue and an error constructor through a fifth
    /// `&mut` parameter is the change with the most call-site risk and the
    /// least visibility. `#[must_use]` is what keeps a caller from quietly
    /// dropping them.
    ///
    /// The returned `Vec` does not allocate unless an awaited send was
    /// actually queued, so the common teardown (and `reset_send_state`, run
    /// on every slot reactivation) pays nothing.
    #[must_use = "queued awaited sends must be failed onto Driver::settled_sends"]
    pub(crate) fn release_queued_sends(
        queue: &mut VecDeque<BuiltSend>,
        send_slab: &mut InFlightSendSlab,
        send_copy_pool: &mut SendCopyPool,
    ) -> Vec<SendId> {
        let mut ids = Vec::new();
        for built in queue.drain(..) {
            if built.pool_slot == u16::MAX && built.slab_idx == u16::MAX {
                continue;
            }
            // Take before releasing: `release` asserts the slot is clean,
            // and the slab clears its id silently. A queued slab entry is an
            // awaited zero-copy batch; a pool slot is any other awaited send.
            // (A coalesced slab entry is never queued: it is built at submit
            // time and the run it covers is popped on success.)
            if built.slab_idx != u16::MAX {
                ids.extend(send_slab.take_sends(built.slab_idx).map(|(id, _)| id));
            }
            if built.pool_slot != u16::MAX
                && let Some((id, _logical_len)) = send_copy_pool.take_send_id(built.pool_slot)
            {
                ids.push(id);
            }
            Self::release_built_resources(
                send_slab,
                send_copy_pool,
                built.pool_slot,
                built.slab_idx,
            );
        }
        ids
    }

    /// Record every send in `ids` as aborted and, when `released_capacity`,
    /// note that slots went back to the pool.
    ///
    /// The tail of each `release_queued_sends` call site, which passes
    /// whether the queue had entries: an unawaited entry holds a slot and
    /// carries no id, so an empty `ids` does not mean no slot was released.
    /// A queue of guard-only zero-copy entries sets the flag without
    /// returning a pool slot. `ConnectionAborted` is the failure every
    /// teardown reports: the send was accepted, never reached the wire, and
    /// its connection is going away.
    fn fail_send_ids(&mut self, ids: Vec<SendId>, released_capacity: bool) {
        for id in ids {
            self.settled_sends.push_back((
                id,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection closed before the send reached the wire",
                )),
            ));
        }
        if released_capacity {
            self.capacity_released = true;
        }
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
            None => unsafe {
                libc::socket(
                    domain,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    0,
                )
            },
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

    /// Handle the end of a socket's UDP multishot. `ENOBUFS` waits for a buffer,
    /// because a re-arm on an empty ring returns `ENOBUFS` at once. `ECANCELED`
    /// is a quiet teardown during shutdown.
    pub(crate) fn on_udp_recv_ended(&mut self, udp_index: u32, errno: i32) {
        match errno {
            libc::ECANCELED => {}
            libc::ENOBUFS => {
                crate::metrics::POOL.increment(crate::metrics::pool::BUFFER_RING_EMPTY);
                self.udp_awaiting_buffers.push(udp_index);
            }
            _ => self.rearm_udp_recvmsg(udp_index),
        }
    }

    /// Return consumed buffers to their rings, and re-arm the sockets that were
    /// waiting for one.
    pub(crate) fn return_udp_buffers(&mut self) {
        for (udp_index, bid) in self.udp_pending_replenish.drain(..) {
            self.udp_provided_bufs[udp_index as usize].replenish_batch(&[bid]);
        }
        let mut awaiting = std::mem::take(&mut self.udp_awaiting_buffers);
        awaiting.retain(|&udp_index| {
            let free = self.udp_provided_bufs[udp_index as usize].free() > 0;
            if free {
                self.rearm_udp_recvmsg(udp_index);
            }
            !free
        });
        awaiting.append(&mut self.udp_awaiting_buffers);
        self.udp_awaiting_buffers = awaiting;
    }

    /// Whether a socket is left to re-arm with a buffer free for it: its re-arm
    /// failed in `return_udp_buffers`, and the worker should retry, not block.
    pub(crate) fn udp_rearm_due(&self) -> bool {
        self.udp_awaiting_buffers
            .iter()
            .any(|&udp_index| self.udp_provided_bufs[udp_index as usize].free() > 0)
    }

    /// Re-arm the UDP multishot recvmsg for a socket. A submission that fails
    /// stays in `udp_awaiting_buffers`, for `return_udp_buffers` to retry once
    /// the ring has a free buffer.
    pub(crate) fn rearm_udp_recvmsg(&mut self, udp_index: u32) {
        let idx = udp_index as usize;
        if idx >= self.udp_sockets.len() {
            return;
        }
        let bgid = self.udp_provided_bufs[idx].bgid();
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
            self.udp_awaiting_buffers.push(udp_index);
        }
    }

    /// At shutdown, release a send's pool slot, settling any awaited send it
    /// carries as aborted.
    fn release_slot_at_shutdown(&mut self, pool_slot: u16) {
        if !self.send_copy_pool.in_use(pool_slot) {
            return;
        }
        // Take the id before releasing: `release` debug-asserts on a slot that
        // still names a live operation. The record goes on a queue nobody will
        // drain: the executor is going away with the driver, so there is no
        // future left to resolve.
        if let Some((id, _logical_len)) = self.send_copy_pool.take_send_id(pool_slot) {
            self.settled_sends.push_back((
                id,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "worker shut down before the send completed",
                )),
            ));
        }
        self.send_copy_pool.release(pool_slot);
    }

    /// Release a zero-copy entry with no operation in the kernel at worker
    /// exit, once any notification its earlier operations owe has landed.
    fn release_zc_at_shutdown(&mut self, slab_idx: u16) {
        if !self.send_slab.in_use(slab_idx) {
            return;
        }
        self.send_slab.mark_awaiting_notifications(slab_idx);
        if self.send_slab.should_release(slab_idx) {
            let pool_slot = self.send_slab.release(slab_idx);
            if pool_slot != u16::MAX {
                self.send_copy_pool.release(pool_slot);
            }
        }
    }

    /// At shutdown, release a coalesced copy send's slab entry and its pool
    /// slots, settling any awaited send it carries as aborted.
    fn release_coalesced_at_shutdown(&mut self, slab_idx: u16) {
        if !self.send_slab.in_use(slab_idx) {
            return;
        }
        for (id, _logical_len) in self.send_slab.take_sends(slab_idx) {
            self.settled_sends.push_back((
                id,
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "worker shut down before the send completed",
                )),
            ));
        }
        let mut slots = [u16::MAX; crate::buffer::send_slab::MAX_IOVECS];
        let mut n = 0;
        for &slot in self.send_slab.coalesced_pool_slots(slab_idx) {
            slots[n] = slot;
            n += 1;
        }
        for &slot in &slots[..n] {
            self.send_copy_pool.release(slot);
        }
        self.send_slab.release(slab_idx);
    }

    /// Handle one completion in `run_shutdown`.
    fn handle_shutdown_cqe(
        &mut self,
        user_data_raw: u64,
        result: i32,
        flags: u32,
        timeout_armed: &mut bool,
    ) {
        let ud = UserData(user_data_raw);
        let Some(tag) = ud.tag() else {
            return;
        };
        match tag {
            OpTag::TickTimeout => *timeout_armed = false,
            OpTag::Send | OpTag::TlsSend => {
                self.release_slot_at_shutdown(UserData::send_payload_slot(ud.payload()));
            }
            // Nothing is resubmitted at shutdown, so a partial
            // completion releases too.
            OpTag::SendMsgCoalesced => {
                self.release_coalesced_at_shutdown(ud.payload() as u16);
            }
            // A drain is a plain `send` on the same entry: its CQE
            // carries no notification flags, so it releases like a
            // main CQE that has no notification to wait for.
            OpTag::SendMsgZc | OpTag::SendMsgZcDrain => {
                let slab_idx = ud.payload() as u16;
                if !self.send_slab.in_use(slab_idx) {
                    return;
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
            // The cancel lead ended the receive; the kernel is done
            // with the buffer. If the connection is still this
            // generation and has TLS state, end the receive in that
            // state (`tls_recv_cancel`), so the Close's
            // `release_tls_state` finds none in flight. Otherwise the
            // entry's buffer is freed here.
            OpTag::RecvDirect => {
                let slot = ud.payload() as usize;
                let Some(entry) = self.direct_recvs.get_mut(slot).and_then(Option::take) else {
                    return;
                };
                self.direct_recv_free.push(slot as u32);
                if let Some(cs) = self.connections.get_mut(entry.conn_index)
                    && cs.generation == entry.generation
                {
                    cs.recv_direct_armed = false;
                    if let DirectRecvBuf::Tls(buf) = entry.buf
                        && let Some(t) = self.tls_table.as_mut()
                        && t.has(entry.conn_index)
                    {
                        crate::tls::tls_recv_cancel(t, entry.conn_index, buf);
                    }
                }
            }
            OpTag::Close => {
                let conn_index = ud.conn_index();
                // Both counters follow `established`, as in `handle_close`.
                let was_established = self
                    .connections
                    .get(conn_index)
                    .is_some_and(|c| c.established);
                self.release_tls_state(conn_index);
                self.clear_conn_claims(conn_index);
                self.connections.release(conn_index);
                if was_established {
                    metrics::CONNECTIONS.increment(metrics::conn::CLOSED);
                    metrics::CONNECTIONS_ACTIVE.decrement();
                }
            }
            // A disk command's completion: the kernel is done with its
            // memory. No task is polled again, so nothing is delivered.
            OpTag::Fs => {
                let slab_idx = ud.payload() as u16;
                if let Some(slab) = self.fs_cmd_slab.as_mut()
                    && slab.in_use(slab_idx)
                {
                    slab.release(slab_idx);
                }
            }
            OpTag::DirectIo => {
                let slab_idx = ud.payload() as u16;
                if let Some(slab) = self.direct_io_cmd_slab.as_mut()
                    && slab.in_use(slab_idx)
                {
                    slab.release(slab_idx);
                }
            }
            OpTag::NvmeCmd => {
                let slab_idx = ud.payload() as u16;
                if let Some(slab) = self.nvme_cmd_slab.as_mut()
                    && slab.in_use(slab_idx)
                {
                    slab.release(slab_idx);
                }
            }
            // Merged accept: nothing will serve the connection.
            OpTag::AcceptMulti if result >= 0 => unsafe {
                libc::close(result);
            },
            // A park's install: the fd is a second reference to a socket
            // whose Close `run_shutdown` submits, and no worker adopts it
            // at exit. Left open it holds the socket past the Close, so the
            // peer sees no FIN (#800).
            OpTag::ParkInstall if result >= 0 => unsafe {
                libc::close(result);
            },
            _ => {}
        }
    }

    /// Close the connections queued for this worker. Dropping a receiver
    /// drops what is queued, and a peer's next send fails with
    /// `Disconnected` (`crate::handoff`).
    fn close_queued_connections(&mut self) {
        drop(self.accept_rx.take());
        drop(self.park_rx.take());
    }

    /// Close the fds delivered by completions this worker has not handled:
    /// the fd of an accepted connection (`AcceptMulti`) or of a park's
    /// install (`ParkInstall`), which the kernel installed in this process
    /// when the operation completed. Reads the batch from its cursor and
    /// reaps the completions in the ring's queue, and handles nothing else.
    /// For a worker that leaks this driver after a panic in its drain:
    /// closing the ring leaves such an fd open, with nothing to serve or
    /// close its connection.
    pub(crate) fn close_fds_in_unhandled_completions(&mut self) {
        let cursor = self.cqe_cursor.min(self.cqe_batch.len());
        let mut batch = std::mem::take(&mut self.cqe_batch);
        batch.drain(..cursor);
        self.ring.reap(&mut batch);
        for (user_data_raw, result, _) in batch {
            if result >= 0
                && matches!(
                    UserData(user_data_raw).tag(),
                    Some(OpTag::AcceptMulti | OpTag::ParkInstall)
                )
            {
                // Safety: the completion installed this fd and no handler
                // has read the completion.
                unsafe {
                    libc::close(result);
                }
            }
        }
    }

    /// Release what other threads wait on, for a worker that leaks this driver.
    pub(crate) fn release_shared(&mut self) {
        self.close_queued_connections();
        let (_, closed) = crossbeam_channel::bounded(0);
        let region_rx = std::mem::replace(&mut self.region_rx, closed);
        // Each queued message holds an ack sender its registrar waits on.
        region_rx.try_iter().for_each(drop);
        self.merged_listeners.clear();
    }

    /// Whether an fs, direct I/O or NVMe command has not completed. Its
    /// operation can still read or write memory this worker owns.
    fn disk_commands_in_flight(&self) -> bool {
        self.fs_cmd_slab.as_ref().is_some_and(|s| s.has_in_flight())
            || self
                .direct_io_cmd_slab
                .as_ref()
                .is_some_and(|s| s.has_in_flight())
            || self
                .nvme_cmd_slab
                .as_ref()
                .is_some_and(|s| s.has_in_flight())
    }

    /// Shutdown: close all connections and drain remaining CQEs. The eventfd
    /// is closed by `WakeHandle`, not here.
    pub(crate) fn run_shutdown(&mut self) {
        // Close connections still queued for this worker.
        self.close_queued_connections();

        // 1. Release entries parked on a retry list: their submit found the
        //    SQ full, so no operation is in flight and no CQE will release
        //    them. A zero-copy entry still waits for any notification its
        //    earlier operations owe.
        for (_, _, slab_idx, _) in std::mem::take(&mut self.pending_coalesced_retries) {
            self.release_coalesced_at_shutdown(slab_idx);
        }
        for (_, _, slab_idx, _) in std::mem::take(&mut self.pending_zc_retries) {
            self.release_zc_at_shutdown(slab_idx);
        }
        // A parked `Shutdown` has nothing in the kernel either, and the
        // Close below ends the socket.
        self.pending_shutdown_retries.clear();
        // A send waiting for room has nothing in the kernel either.
        let max = self.connections.max_slots();
        for i in 0..max {
            let Some(raw) = self.send_queues[i as usize].waiting_send.take() else {
                continue;
            };
            let ud = UserData(raw);
            match ud.tag() {
                Some(OpTag::Send | OpTag::TlsSend) => {
                    self.release_slot_at_shutdown(UserData::send_payload_slot(ud.payload()));
                }
                Some(OpTag::SendMsgCoalesced) => {
                    self.release_coalesced_at_shutdown(ud.payload() as u16);
                }
                _ => self.release_zc_at_shutdown(ud.payload() as u16),
            }
        }

        // 2. Close all active connections and drain their send queues.
        let mut holding_sends = Vec::new();
        let mut cancels_to_retry = Vec::new();
        for i in 0..max {
            if self.connections.get(i).is_some() {
                // Clear a deferred close so draining does not submit it with
                // a shutdown; the Close below replaces it.
                self.send_queues[i as usize].close_pending = false;
                self.drain_conn_send_queue(i);
                // Cancel the connection's requests ahead of the Close. A
                // send waiting for a peer that does not read would otherwise
                // never complete, and the loop below would wait out its full
                // bound for it. `IORING_ASYNC_CANCEL_FD_FIXED` is in Linux
                // 6.0, below the 6.1 io_uring minimum. No shutdown: each peer
                // gets a FIN once the socket is released, or an RST if
                // received data was unread.
                //
                // A connection still holding slab entries stays open for now.
                // A zero-copy entry waits for the peer to take its data, and
                // once the socket is closed nothing can give up on that.
                let generation = self.connections.generation(i);
                if self.send_slab.held_by(i, generation) > 0 {
                    if self.ring.submit_cancel_all(i).is_err() {
                        cancels_to_retry.push(i);
                    }
                    holding_sends.push(i);
                } else if self
                    .ring
                    .submit_close(i, super::ring::CloseLead::CancelAll)
                    .is_err()
                {
                    // The push was refused (the SQ still full after a
                    // submit, or the submit failed). The loop below submits
                    // this connection's Close with the same lead, since it
                    // holds no slab entry, and tries again on a refusal.
                    holding_sends.push(i);
                }
            }
        }

        // 3. Submit + drain loop until every connection's Close has
        //    completed, every slab entry is released and every fs, direct I/O
        //    and NVMe command has completed, for at most `SHUTDOWN_BOUND`.
        //    Keep one timeout SQE armed so submit_and_wait(1) never blocks
        //    indefinitely (the tick timeout from the main loop is not armed
        //    here). A pass ends at any CQE, so neither the pass count nor one
        //    timeout per pass measures time.
        //
        //    A zero-copy entry is released only once its notifications land,
        //    and the kernel posts those when the peer has acknowledged the data
        //    and the kernel has freed it. A connection whose entries are not
        //    released within `ABORT_AFTER` is closed with an RST, whether its
        //    peer stopped reading or is reading slowly. The RST discards the
        //    queued data, so the notifications land. Such an entry holds the
        //    loop for its whole bound on a kernel without `setsockopt` through
        //    io_uring (below 6.7), or when its connection had closed before
        //    exit began, so nothing can abort it. Its guards and the send pool's
        //    memory are then leaked, because the kernel can still read them.
        let shutdown_ts = crate::backend::uring::abi::Timespec::new().nsec(100_000_000); // 100ms
        let started = std::time::Instant::now();
        let mut timeout_armed = false;
        // A panic in a handler left these undispatched.
        // In place, with the cursor kept up to date: a panic here leaves
        // the rest of the tail for `close_fds_in_unhandled_completions`.
        let cursor = self.cqe_cursor.min(self.cqe_batch.len());
        for i in cursor..self.cqe_batch.len() {
            let (user_data_raw, result, flags) = self.cqe_batch[i];
            self.cqe_cursor = i + 1;
            self.handle_shutdown_cqe(user_data_raw, result, flags, &mut timeout_armed);
        }
        while started.elapsed() < SHUTDOWN_BOUND {
            for i in std::mem::take(&mut cancels_to_retry) {
                if self.ring.submit_cancel_all(i).is_err() {
                    cancels_to_retry.push(i);
                }
            }
            for i in std::mem::take(&mut holding_sends) {
                let held = self.send_slab.held_by(i, self.connections.generation(i)) > 0;
                let lead = match (held, started.elapsed() >= ABORT_AFTER) {
                    (false, _) => super::ring::CloseLead::CancelAll,
                    (true, true) => super::ring::CloseLead::Abort,
                    (true, false) => {
                        holding_sends.push(i);
                        continue;
                    }
                };
                // A full SQ tries again next round.
                if self.ring.submit_close(i, lead).is_err() {
                    holding_sends.push(i);
                }
            }
            if self.connections.active_count() == 0
                && !self.send_slab.has_in_flight()
                && self.direct_recvs.iter().all(Option::is_none)
                && !self.disk_commands_in_flight()
            {
                break;
            }
            if !timeout_armed {
                let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
                timeout_armed = self
                    .ring
                    .submit_tick_timeout(&shutdown_ts, ud.raw())
                    .is_ok();
            }
            if self.ring.submit_and_wait(1).is_err() {
                break;
            }

            self.cqe_batch.clear();
            self.cqe_cursor = 0;
            self.ring.reap(&mut self.cqe_batch);

            for i in 0..self.cqe_batch.len() {
                let (user_data_raw, result, flags) = self.cqe_batch[i];
                self.cqe_cursor = i + 1;
                self.handle_shutdown_cqe(user_data_raw, result, flags, &mut timeout_armed);
            }
        }

        if self.send_slab.has_in_flight() {
            self.send_slab.leak_in_flight();
            self.send_copy_pool.leak_backing();
        }
        // The memory of a disk command still in flight is spread over this
        // driver (statx box, path) and the tasks (the caller's buffer behind
        // `fs::read`, `direct_io_read`, `nvme_read` and their writes), so the
        // worker leaks the whole event loop rather than this one entry.
        self.disk_io_outstanding = self.disk_commands_in_flight();

        // 4. Unregister the UDP provided buffer rings before Driver is dropped
        // (which munmaps the ring memory). Unregistering releases the
        // kernel's pin on the ring pages.
        for udp_bufs in &self.udp_provided_bufs {
            if self.ring.unregister_buf_ring(udp_bufs.bgid()).is_err() {
                crate::metrics::RING.increment(crate::metrics::ring::SQE_SUBMIT_FAILURES);
            }
        }

        // The eventfd is owned by `WakeHandle` (`WakeFdInner` closes it when
        // the last clone drops), so don't close it here: a double-close would
        // race against fd-number reuse.
    }
}

/// The driver state that [`submit_coalesced_run`] reads and changes,
/// borrowed from the `Driver` or from a `DriverCtx`.
pub(crate) struct RunParts<'a> {
    pub(crate) ring: &'a mut crate::backend::Ring,
    pub(crate) send_slab: &'a mut crate::buffer::send_slab::InFlightSendSlab,
    pub(crate) send_copy_pool: &'a mut crate::buffer::send_copy::SendCopyPool,
    pub(crate) send_queues: &'a mut [crate::handler::ConnSendState],
    pub(crate) pending_send_retries: &'a mut Vec<(u32, u32, u8)>,
}

/// Submit the run of consecutive copy sends at the head of `conn_index`'s
/// send queue as one `sendmsg`. Returns `None` when the head is not a run
/// of at least two or the send slab is full, with nothing changed, and the
/// caller submits the head alone. Returns `Some(true)` when the run was
/// pushed and popped off the queue, and `Some(false)` when the SQ was full:
/// the run stays queued, parked, and on `pending_send_retries` with
/// `attempts`.
pub(crate) fn submit_coalesced_run(
    p: RunParts<'_>,
    conn_index: u32,
    generation: u32,
    attempts: u8,
) -> Option<bool> {
    use crate::buffer::send_slab::MAX_IOVECS;

    let ci = conn_index as usize;
    // Coalesce a run of consecutive copy sends (pool_slot set, no ZC
    // slab), plaintext or TLS ciphertext, at the front of the queue into a
    // single `sendmsg`, so more than one queued send is pipelined per CQE
    // round-trip (#628). Order is preserved (one SQE; iovec order = FIFO
    // queue order), which keeps TLS records in sequence. ZC-guard sends
    // and recv-buffer forwards are not coalescable and fall through to the
    // single-submit path below. A run can span several logical sends: the
    // slab entry records each one's id and where its bytes end, and the
    // completion settles each with its own result.
    let coalescable =
        |b: &crate::handler::BuiltSend| b.pool_slot != u16::MAX && b.slab_idx == u16::MAX;
    let n = p.send_queues[ci]
        .queue
        .iter()
        .take(MAX_IOVECS)
        .take_while(|b| coalescable(b))
        .count();
    if n >= 2 {
        let mut pool_slots = [u16::MAX; MAX_IOVECS];
        {
            let q = &p.send_queues[ci].queue;
            for (i, slot) in pool_slots.iter_mut().enumerate().take(n) {
                *slot = q[i].pool_slot;
            }
        }
        let mut iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        }; MAX_IOVECS];
        let mut total: u32 = 0;
        // The awaited sends the run settles, lifted off the final slots
        // that carry them (see below), each with where its bytes end in
        // the run, and the slot each came from.
        let mut sends = [None; MAX_IOVECS];
        let mut send_count = 0;
        for i in 0..n {
            let (ptr, len) = p.send_copy_pool.current_ptr_remaining(pool_slots[i]);
            iovecs[i] = libc::iovec {
                iov_base: ptr as *mut libc::c_void,
                iov_len: len as usize,
            };
            total += len;
            if let Some((id, logical_len)) = p.send_copy_pool.take_send_id(pool_slots[i]) {
                sends[send_count] = Some((pool_slots[i], id, logical_len, total));
                send_count += 1;
            }
        }
        // Put every lifted id back on its slot, for the paths that leave
        // the run queued and still owning its slots.
        let restore = |pool: &mut crate::buffer::send_copy::SendCopyPool| {
            for &(slot, id, logical_len, _) in sends[..send_count].iter().flatten() {
                pool.set_send_id(slot, id, logical_len);
            }
        };
        // The coalesced completion releases every pool slot in the run, so
        // an id cannot stay on the final slot that carried it; it
        // moves onto the slab entry, which outlives them. Taken, not
        // peeked: leaving a copy behind would let both the slab entry and
        // the slot claim the same operation, and `SendCopyPool::release`
        // would then trip on the slot the handler is about to free.
        // Both failure paths below put the ids back (`restore`), because
        // they leave the run queued and still owning its slots.
        //
        // Only commit to coalescing if the slab has room; otherwise fall
        // through to single-submit (nothing popped yet).
        if let Some((slab_idx, msg_ptr)) = p.send_slab.allocate_coalesced(
            conn_index,
            generation,
            &iovecs[..n],
            &pool_slots[..n],
            total,
            sends[..send_count]
                .iter()
                .flatten()
                .map(|&(_, id, logical_len, end)| (id, logical_len, end)),
        ) {
            match p
                .ring
                .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
            {
                Ok(()) => {
                    // Pushed: the slab entry now owns the run's pool
                    // slots (released by the coalesced completion).
                    for _ in 0..n {
                        p.send_queues[ci].queue.pop_front();
                    }
                    p.send_queues[ci].parked = false;
                    return Some(true);
                }
                Err(_) => {
                    // SQ still full after submit. `allocate_coalesced`
                    // only *recorded* the pool slots in the slab entry;
                    // the `BuiltSend`s still at the queue head own them.
                    // Release just the slab entry and park: the run stays
                    // queued in order, `in_flight` stays true, and
                    // `drain_send_retries` re-pushes next iteration.
                    // The lifted send id goes back on its slot
                    // for the same reason — the retry re-lifts it, and
                    // if teardown gets there first the slot is what
                    // teardown reads.
                    p.send_slab.release(slab_idx);
                    restore(p.send_copy_pool);
                    p.send_queues[ci].parked = true;
                    p.pending_send_retries
                        .push((conn_index, generation, attempts));
                    return Some(false);
                }
            }
        }
        // slab full → fall through to single-submit. Nothing was popped
        // and the run still owns its slots, so the lifted ids go back
        // where the single-submit path (and teardown) will find them.
        restore(p.send_copy_pool);
    }
    None
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
    /// will diverge from `["ring", "udp_provided_bufs", "send_slab"]` and the
    /// test will fail loudly.
    #[allow(dead_code)]
    struct DriverFieldOrderMirror {
        ring: DropMarker,
        // `connections`, `fixed_buffers` etc. interleave here in the real
        // struct; only the kernel-DMA-sensitive ones matter for this test.
        udp_provided_bufs: DropMarker,
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
                udp_provided_bufs: DropMarker("udp_provided_bufs"),
                send_slab: DropMarker("send_slab"),
            };
        } // drop runs here

        let order = DROP_ORDER.lock().unwrap().clone();
        assert_eq!(
            order,
            vec!["ring", "udp_provided_bufs", "send_slab"],
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
            .find("pub(crate) udp_provided_bufs: Vec<ProvidedBufRing>,")
            .expect("Driver::udp_provided_bufs field signature not found");
        let send_slab_pos = src
            .find("pub(crate) send_slab: InFlightSendSlab,")
            .expect("Driver::send_slab field signature not found");
        assert!(
            ring_pos < provided_pos,
            "Driver::ring must be declared before Driver::udp_provided_bufs \
             so it drops *after* it (kernel DMA reference safety)",
        );
        assert!(
            ring_pos < send_slab_pos,
            "Driver::ring must be declared before Driver::send_slab \
             so it drops *after* it (ZC user-memory guards safety)",
        );
    }
}
