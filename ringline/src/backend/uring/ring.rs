use std::io;
use std::os::fd::RawFd;

use crate::backend::ProvidedBufRing;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::completion::{OpTag, UserData};
use crate::config::Config;
use crate::error::Error;
use crate::memlock::KernelVersion;
use crate::nvme::{NVME_URING_CMD_IO, NvmeUringCmd};

use super::engine::{ActiveEngine, Engine, RingKind};
use super::sqe::{self, Link, Op, Sqe};

/// The first kernel that releases a socket removed from the fixed-file table
/// once that socket's own requests have completed. Earlier kernels release
/// removed files in order, so any earlier request on a registered file or
/// buffer, on any connection, holds the socket open (#581).
const FIXED_FILES_RELEASED_PER_FILE_SINCE: KernelVersion = KernelVersion {
    major: 6,
    minor: 13,
};

/// Whether a ring setup error is ENOMEM from `io_uring_setup` or from
/// registering the provided buffer ring.
///
/// On Linux 6.14+ both are charged to RLIMIT_MEMLOCK, and a dropped ring's
/// charge is released asynchronously, so tests that set up rings in quick
/// succession can fail this way until earlier rings are freed (#589). The
/// errors carry only a message, built by `describe_ring_setup_failure` and
/// `provided_ring_failure`, so this reads the errno name from it.
#[cfg(test)]
pub(crate) fn is_memlock_enomem(err: &Error) -> bool {
    match err {
        Error::RingSetup(msg) => {
            msg.starts_with("io_uring_setup(2): ") && msg.contains(" (ENOMEM)")
        }
        Error::BufferRegistration(msg) => {
            msg.starts_with("provided buffer ring ") && msg.contains(" (ENOMEM)")
        }
        _ => false,
    }
}

/// What is hard-linked ahead of a connection's `Close`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseLead {
    /// The `Close` alone: a socket handed to another worker, which must stay
    /// open.
    Nothing,
    /// `shutdown(SHUT_RDWR)`, before Linux 6.13. Requests on any connection
    /// can hold the socket open after the `Close`; the shutdown queues the
    /// FIN regardless, and ends this connection's own requests. It runs on
    /// the bounded io-wq pool (#581, #586).
    Shutdown,
    /// Cancel every request on the connection's fixed file. Used for every
    /// close from Linux 6.13: from 6.13 only this connection's requests hold
    /// the socket open, so the `Close` sends the FIN once they have ended, or
    /// an RST if received data is unread. Also used at worker exit on every
    /// kernel (`Driver::run_shutdown`). The cancel runs inline (#586).
    CancelAll,
}

/// The [`CloseLead`] for a connection close on `kernel`: [`Shutdown`] before
/// Linux 6.13 or on a kernel whose version is unknown, [`CancelAll`] from
/// 6.13.
///
/// [`Shutdown`]: CloseLead::Shutdown
/// [`CancelAll`]: CloseLead::CancelAll
pub(crate) fn close_lead_for(kernel: Option<KernelVersion>) -> CloseLead {
    if kernel.is_none_or(|k| k < FIXED_FILES_RELEASED_PER_FILE_SINCE) {
        CloseLead::Shutdown
    } else {
        CloseLead::CancelAll
    }
}

/// The driver's submission interface: builds an [`Sqe`] for each operation
/// and pushes it to the engine.
pub struct Ring {
    pub(crate) engine: ActiveEngine,
    /// Recv buffer group ID for multishot recv.
    bgid: u16,
    /// Test-only: the last operation pushed through `push_sqe`, so a test
    /// can check which operation a handler submitted.
    #[cfg(test)]
    pub(crate) last_pushed: Option<Sqe>,
    /// Test-only: the registered file index of the last drain `send`, which
    /// `last_pushed` does not show.
    #[cfg(test)]
    pub(crate) last_drain_index: Option<u32>,
}

impl Ring {
    /// Set up the engine for `config`.
    pub fn setup(config: &Config) -> Result<Self, Error> {
        Ok(Ring {
            engine: ActiveEngine::setup(config)?,
            bgid: config.recv_buffer.bgid,
            #[cfg(test)]
            last_pushed: None,
            #[cfg(test)]
            last_drain_index: None,
        })
    }

    /// Whether this kernel can return a registered fd to the process table,
    /// and so whether park (tier 3, #443) is available. See
    /// [`Engine::supports_park`].
    #[allow(dead_code)] // first caller lands with the handover (#443 step 5c)
    pub(crate) fn supports_park(&self) -> bool {
        self.engine.supports_park()
    }

    /// What goes ahead of a connection's `Close` on the running kernel. See
    /// [`close_lead_for`].
    pub(crate) fn close_lead(&self) -> CloseLead {
        self.engine.close_lead()
    }

    /// See [`Engine::register_buffers`].
    pub fn register_buffers(&self, registry: &FixedBufferRegistry) -> Result<(), Error> {
        self.engine.register_buffers(registry)
    }

    /// See [`Engine::register_buffers_update_one`].
    ///
    /// # Safety
    ///
    /// As [`Engine::register_buffers_update_one`].
    pub unsafe fn register_buffers_update_one(
        &self,
        slot: u16,
        iov: libc::iovec,
    ) -> io::Result<()> {
        unsafe { self.engine.register_buffers_update_one(slot, iov) }
    }

    /// See [`Engine::register_files_sparse`].
    pub fn register_files_sparse(&self, count: u32) -> Result<(), Error> {
        self.engine.register_files_sparse(count)
    }

    /// See [`Engine::register_files_update`].
    pub fn register_files_update(&self, offset: u32, fds: &[RawFd]) -> io::Result<()> {
        self.engine.register_files_update(offset, fds)
    }

    /// See [`Engine::register_buf_ring`].
    pub fn register_buf_ring(
        &mut self,
        provided: &ProvidedBufRing,
        kind: RingKind,
    ) -> Result<(), Error> {
        self.engine.register_buf_ring(provided, kind)
    }

    /// See [`Engine::unregister_buf_ring`].
    pub fn unregister_buf_ring(&self, bgid: u16) -> io::Result<()> {
        self.engine.unregister_buf_ring(bgid)
    }

    /// See [`Engine::submit_and_wait`].
    pub fn submit_and_wait(&self, min_complete: u32) -> io::Result<()> {
        self.engine.submit_and_wait(min_complete)
    }

    /// See [`Engine::submit_and_get_events`].
    pub fn submit_and_get_events(&self) -> io::Result<()> {
        self.engine.submit_and_get_events()
    }

    /// See [`Engine::flush`].
    pub fn flush(&self) -> io::Result<()> {
        self.engine.flush()
    }

    /// See [`Engine::reap`].
    pub(crate) fn reap(&mut self, out: &mut Vec<(u64, i32, u32)>) {
        self.engine.reap(out);
    }

    /// See [`Engine::sq_len`].
    #[cfg(test)]
    pub(crate) fn sq_len(&mut self) -> usize {
        self.engine.sq_len()
    }

    /// See [`Engine::force_push_failures`].
    #[cfg(test)]
    pub(crate) fn force_push_failures(&mut self, count: usize) {
        self.engine.force_push_failures(count);
    }

    /// Post a completion with `user_data` and `result`, as if an operation
    /// had completed. See [`Engine::inject`].
    #[cfg(test)]
    pub(crate) fn submit_nop_inject(&mut self, user_data: u64, result: i32) -> io::Result<()> {
        self.engine.inject(user_data, result, false)
    }

    /// As [`submit_nop_inject`](Self::submit_nop_inject), linked to the next
    /// entry pushed.
    #[cfg(test)]
    pub(crate) fn submit_nop_inject_linked(
        &mut self,
        user_data: u64,
        result: i32,
    ) -> io::Result<()> {
        self.engine.inject(user_data, result, true)
    }

    /// Re-probe an arbitrary opcode; see
    /// `engine::uring::UringEngine::probe_supported`.
    #[cfg(all(test, uring_engine))]
    pub(crate) fn probe_supported(&self, code: u8) -> bool {
        self.engine.probe_supported(code)
    }

    /// The calling thread's io-wq limits; see
    /// `engine::uring::UringEngine::iowq_max_workers`.
    #[cfg(all(test, uring_engine))]
    pub(crate) fn iowq_max_workers(&self) -> io::Result<[u32; 2]> {
        self.engine.iowq_max_workers()
    }
    /// Submit a multishot recvmsg with provided buffer ring for a connection.
    /// Used when SO_TIMESTAMPING is enabled to receive cmsg ancillary data
    /// (kernel timestamps) alongside TCP payload.
    ///
    /// `generation` is the connection's generation at arm time and is carried
    /// whole in the payload — see `Ring::submit_multishot_recv` for why.
    /// Any cancel targeting this request must encode the same payload.
    #[cfg(feature = "timestamps")]
    pub fn submit_multishot_recvmsg(
        &mut self,
        conn_index: u32,
        generation: u32,
        msghdr: *const libc::msghdr,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::RecvMsgMultiTs, conn_index, generation);
        let entry = Sqe::new(
            Op::RecvMsgMulti {
                fd: sqe::Fd::Fixed(conn_index),
                msg: msghdr,
                buf_group: self.bgid,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a one-shot fallback recv into fallback-pool memory for a
    /// connection whose multishot recv is parked on ENOBUFS. The pool slot
    /// is carried in the payload and released by `handle_recv_fallback`;
    /// the pool owns `ptr` until that CQE arrives (SQE memory outlives the
    /// operation even across close/slot-reuse).
    pub fn submit_recv_fallback(
        &mut self,
        conn_index: u32,
        ptr: *mut u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::RecvFallback, conn_index, pool_slot as u32);
        let entry = Sqe::new(
            Op::Recv {
                fd: sqe::Fd::Fixed(conn_index),
                buf: ptr,
                len,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a multishot recv with provided buffer ring for a connection.
    ///
    /// `generation` is the connection's generation at arm time. It occupies the
    /// whole 32-bit payload (an exact match, unlike the truncated send-family
    /// generations), so `handle_recv_multi` can reject a completion that
    /// outlived its connection slot: a multishot can survive the fixed-file
    /// `Close` (its cancel is best-effort and is dropped when the SQ is full),
    /// and without this the terminal `-ECONNRESET` would be misattributed to
    /// whichever connection next occupies the index.
    ///
    /// Any cancel targeting this request must encode the same payload — a
    /// cancel matches by `user_data`.
    ///
    /// `limit` is the arm's total byte limit (`Op::RecvMulti`), 0 for none;
    /// `Driver::recv_arm_limit` chooses it.
    pub fn submit_multishot_recv(
        &mut self,
        conn_index: u32,
        generation: u32,
        limit: u32,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::RecvMulti, conn_index, generation);
        let entry = Sqe::new(
            Op::RecvMulti {
                fd: sqe::Fd::Fixed(conn_index),
                buf_group: self.bgid,
                limit,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Arm a multishot accept on a listener this worker owns (merged accept
    /// mode).
    ///
    /// The `conn_index` field of the user_data carries the **listener index**,
    /// not a connection: no slot exists until a CQE arrives. One CQE per
    /// accepted connection; `IORING_CQE_F_MORE` means the arm is still live,
    /// and its absence means re-arm.
    ///
    /// The listener fd is a plain fd, not a fixed-file index — listeners live
    /// outside the connection table, whose fixed slots are indexed by
    /// `conn_index`.
    ///
    /// No `sockaddr` comes back with a multishot accept (the kernel has
    /// nowhere per-completion to put it), so the caller must `getpeername(2)`
    /// on the accepted fd to learn the peer.
    pub fn submit_accept_multi(&mut self, listener_index: u32, listen_fd: RawFd) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::AcceptMulti, listener_index, 0);
        // The same flags `accept_nonblock` passes to `accept4` on the pool
        // path. Multishot accept defaults to zero, so without this the merged
        // path is the one place in the runtime that hands out an fd which
        // survives `exec` and blocks on a direct read (#460).
        let entry = Sqe::new(
            Op::AcceptMulti {
                fd: sqe::Fd::Raw(listen_fd),
                flags: libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a copied send. The data must be in a SendCopyPool slot.
    /// The pool slot index is stored in the payload for release on CQE.
    pub fn submit_send_copied(
        &mut self,
        conn_index: u32,
        generation: u32,
        ptr: *const u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(pool_slot, generation),
        );
        let entry = Sqe::new(
            Op::Send {
                fd: sqe::Fd::Fixed(conn_index),
                buf: ptr,
                len,
                flags: crate::completion::STREAM_SEND_FLAGS,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a SendMsgZc operation.
    /// The slab index is stored in the payload for lookup on CQE.
    pub fn submit_send_msg_zc(
        &mut self,
        conn_index: u32,
        msg: *const libc::msghdr,
        slab_idx: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        let entry = Sqe::new(
            Op::SendMsgZc {
                fd: sqe::Fd::Fixed(conn_index),
                msg,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a coalesced copy send (plaintext or TLS ciphertext): one plain
    /// (non-ZC) `sendmsg` whose
    /// iovecs gather several queued sends. The slab index is in the payload.
    pub fn submit_send_msg_coalesced(
        &mut self,
        conn_index: u32,
        msg: *const libc::msghdr,
        slab_idx: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        let entry = Sqe::new(
            Op::SendMsg {
                fd: sqe::Fd::Fixed(conn_index),
                msg,
                flags: crate::completion::STREAM_SEND_FLAGS as u32,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a plain `send` of `len` bytes at `ptr` on a registered file,
    /// after a vectored send returned `-EAGAIN`.
    ///
    /// io_uring reports `POLLRDHUP` on every poll, so once the peer has
    /// half-closed a `POLLOUT` poll completes at once and the vectored send
    /// fails with `-EAGAIN` again (#603). A `send` waits until the socket has
    /// room; in that state it runs on an io-wq worker thread (#605). `user_data`
    /// names the operation whose completion handler takes the result as a
    /// partial write.
    ///
    /// # Safety
    /// The `len` bytes at `ptr` must stay valid until the CQE arrives.
    pub unsafe fn submit_drain_send_fixed(
        &mut self,
        index: u32,
        ptr: *const u8,
        len: u32,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Send {
                fd: sqe::Fd::Fixed(index),
                buf: ptr,
                len,
                flags: crate::completion::STREAM_SEND_FLAGS,
            },
            user_data.raw(),
        );
        #[cfg(test)]
        {
            self.last_drain_index = Some(index);
        }
        unsafe { self.push_sqe(&entry) }
    }

    /// As [`submit_drain_send_fixed`](Self::submit_drain_send_fixed), on a raw
    /// descriptor.
    ///
    /// # Safety
    /// The `len` bytes at `ptr` must stay valid until the CQE arrives.
    pub unsafe fn submit_drain_send_fd(
        &mut self,
        fd: RawFd,
        ptr: *const u8,
        len: u32,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Send {
                fd: sqe::Fd::Raw(fd),
                buf: ptr,
                len,
                flags: crate::completion::STREAM_SEND_FLAGS,
            },
            user_data.raw(),
        );
        unsafe { self.push_sqe(&entry) }
    }

    /// Submit a zero-copy recv-forward send: one plain (non-ZC) `sendmsg` whose
    /// iovecs point directly into held provided recv buffers. The slab index is
    /// in the payload; the slab entry holds the bids to replenish on completion.
    pub fn submit_send_recv_bufs_coalesced(
        &mut self,
        conn_index: u32,
        msg: *const libc::msghdr,
        slab_idx: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::SendRecvBufsCoalesced, conn_index, slab_idx as u32);
        let entry = Sqe::new(
            Op::SendMsg {
                fd: sqe::Fd::Fixed(conn_index),
                msg,
                flags: crate::completion::STREAM_SEND_FLAGS as u32,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a **gathered** Mode A forward write to a socket sink: several
    /// held provided buffers in one `sendmsg`.
    ///
    /// This is what makes forwarding cost one completion per *batch* rather
    /// than one per provided buffer — the asymmetry `run_direct_echo` has
    /// always exploited by gathering a drain's worth into a single send (#397).
    /// Ordering is preserved: `sendmsg` writes the iovecs in order, and the
    /// caller still keeps one write in flight per connection.
    ///
    /// # Safety
    /// `msghdr`, the iovec array it points at, and every buffer those iovecs
    /// point at must stay valid until the CQE arrives. The driver owns all
    /// three in `ForwardWriteState`, which is neither moved nor rebuilt while a
    /// write is in flight.
    pub unsafe fn submit_forward_writev_socket(
        &mut self,
        fd: RawFd,
        msghdr: *const libc::msghdr,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::SendMsg {
                fd: sqe::Fd::Raw(fd),
                msg: msghdr,
                flags: crate::completion::STREAM_SEND_FLAGS as u32,
            },
            user_data.raw(),
        );
        unsafe { self.push_sqe(&entry) }
    }

    /// Gathered Mode A forward write to another **connection** on this worker,
    /// through its registered file index. See
    /// [`submit_forward_writev_socket`](Self::submit_forward_writev_socket).
    ///
    /// # Safety
    /// As `submit_forward_writev_socket`, plus: the sink connection's slot must
    /// not be recycled before the CQE, which the caller checks by generation.
    pub unsafe fn submit_forward_writev_conn(
        &mut self,
        sink_index: u32,
        msghdr: *const libc::msghdr,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::SendMsg {
                fd: sqe::Fd::Fixed(sink_index),
                msg: msghdr,
                flags: crate::completion::STREAM_SEND_FLAGS as u32,
            },
            user_data.raw(),
        );
        unsafe { self.push_sqe(&entry) }
    }

    /// Gathered Mode A forward write to a **file** sink, at `offset`.
    ///
    /// `writev` rather than `sendmsg`: a file sink has an offset and no message
    /// semantics.
    ///
    /// # Safety
    /// The iovec array and the buffers it points at must stay valid until the
    /// CQE arrives; the driver owns both.
    pub unsafe fn submit_forward_writev_file(
        &mut self,
        fd: RawFd,
        iovecs: *const libc::iovec,
        count: u32,
        offset: u64,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Writev {
                fd: sqe::Fd::Raw(fd),
                iovecs,
                count,
                offset,
            },
            user_data.raw(),
        );
        unsafe { self.push_sqe(&entry) }
    }

    /// Submit a TLS-internal send (handshake, alert). Uses OpTag::TlsSend
    /// so the CQE handler releases the pool slot without calling on_send_complete.
    pub fn submit_tls_send(
        &mut self,
        conn_index: u32,
        generation: u32,
        ptr: *const u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(
            OpTag::TlsSend,
            conn_index,
            UserData::send_payload(pool_slot, generation),
        );
        let entry = Sqe::new(
            Op::Send {
                fd: sqe::Fd::Fixed(conn_index),
                buf: ptr,
                len,
                flags: crate::completion::STREAM_SEND_FLAGS,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit an eventfd read (8 bytes).
    pub fn submit_eventfd_read(&mut self, eventfd: RawFd, buf: *mut u8) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::EventFdRead, 0, 0);
        let entry = Sqe::new(
            Op::Read {
                fd: sqe::Fd::Raw(eventfd),
                buf,
                len: 8,
                offset: 0,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a close for a direct file descriptor.
    pub fn submit_close(&mut self, conn_index: u32, lead: CloseLead) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Close, conn_index, 0);
        let close = Sqe::new(
            Op::Close {
                fd: sqe::Fd::Fixed(conn_index),
            },
            user_data.raw(),
        );
        // A socket removed from the fixed-file table stays open until the
        // requests holding it complete: before Linux 6.13, earlier requests
        // on any registered file or buffer; from 6.13, this connection's own
        // requests. See `CloseLead`. The lead is hard-linked, so the Close
        // runs after it even when it fails. `push_sqe_pair` pushes both
        // together, so a submit cannot separate them. Config validation
        // guarantees an SQ of at least two entries.
        let first = match lead {
            CloseLead::Nothing => {
                unsafe {
                    self.push_sqe(&close)?;
                }
                return Ok(());
            }
            CloseLead::Shutdown => Sqe::new(
                Op::Shutdown {
                    fd: sqe::Fd::Fixed(conn_index),
                    how: libc::SHUT_RDWR,
                },
                UserData::encode(OpTag::CloseShutdown, conn_index, 0).raw(),
            ),
            CloseLead::CancelAll => Sqe::new(
                Op::CancelFdAll {
                    fd: sqe::Fd::Fixed(conn_index),
                },
                UserData::encode(OpTag::CloseCancel, conn_index, 0).raw(),
            ),
        };
        let first = first.link(Link::Hard);
        unsafe { self.engine.push_pair(&first, &close) }
    }

    /// Submit an async connect for a direct file descriptor.
    pub fn submit_connect(
        &mut self,
        conn_index: u32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Connect, conn_index, 0);
        let entry = Sqe::new(
            Op::Connect {
                fd: sqe::Fd::Fixed(conn_index),
                addr,
                addrlen,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a timeout SQE. The timespec must remain valid until the CQE arrives.
    pub fn submit_timeout(
        &mut self,
        timespec: *const crate::backend::uring::abi::Timespec,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Timeout {
                ts: timespec,
                abs: false,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit an absolute timeout SQE. The timespec contains absolute
    /// `CLOCK_MONOTONIC` seconds/nanoseconds. The timespec must remain valid
    /// until the CQE arrives.
    pub fn submit_timeout_abs(
        &mut self,
        timespec: *const crate::backend::uring::abi::Timespec,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Timeout {
                ts: timespec,
                abs: true,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit an async cancel targeting a specific user_data value.
    /// Recover a real fd for a registered connection, so it can be handed to
    /// another worker (tier 3, #443).
    ///
    /// When `cancel_recv_user_data` is given, an `AsyncCancel` for the armed
    /// multishot recv is pushed first with `IOSQE_IO_LINK`, so the kernel
    /// runs it *before* the install. That ordering is load-bearing: an armed
    /// multishot recv pins the socket independently of the fixed-file table
    /// (see `try_finalize_close`), so a recv left armed on this worker would
    /// keep consuming bytes from a socket already handed to another one.
    ///
    /// A link is all-or-nothing: if the cancel fails — most likely `ENOENT`
    /// because the recv self-terminated between the check and the kernel
    /// running it — the install is completed with `ECANCELED` instead. The
    /// caller treats that as "abandon this park and try again later", which
    /// is the correct outcome rather than an error: park is best-effort.
    /// Cancel a connection's multishot recv ahead of a park.
    ///
    /// Not linked to the install any more. A cancel cannot retract recv CQEs the
    /// kernel has already posted, so an install linked behind it lands while
    /// those are still being delivered and finds the handler's offer already
    /// withdrawn — measured at 9,427 of 9,427 abandonments. The install is
    /// submitted separately, once the handler has drained and re-offered.
    pub fn submit_park_recv_cancel(
        &mut self,
        conn_index: u32,
        cancel_recv_user_data: u64,
    ) -> io::Result<()> {
        let cancel_ud = UserData::encode(OpTag::Cancel, conn_index, 0);
        let cancel = Sqe::new(
            Op::Cancel {
                target: cancel_recv_user_data,
            },
            cancel_ud.raw(),
        );
        unsafe {
            self.push_sqe(&cancel)?;
        }
        Ok(())
    }

    /// Recover a real fd for a connection whose recv is already cancelled.
    pub fn submit_park_install(&mut self, conn_index: u32, generation: u32) -> io::Result<()> {
        let ud = UserData::encode(OpTag::ParkInstall, conn_index, generation);
        let entry = Sqe::new(Op::FixedFdInstall { index: conn_index }, ud.raw());
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    pub fn submit_async_cancel(
        &mut self,
        target_user_data: u64,
        conn_index: u32,
    ) -> io::Result<()> {
        let ud = UserData::encode(OpTag::Cancel, conn_index, 0);
        let entry = Sqe::new(
            Op::Cancel {
                target: target_user_data,
            },
            ud.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a shutdown(SHUT_WR) for a connection.
    pub fn submit_shutdown(&mut self, conn_index: u32, generation: u32) -> io::Result<()> {
        // The generation rides in the payload so the completion can reject a
        // CQE that outlived its connection slot (domain invariant 3). It used
        // to be a bare 0, and the completion was `{}`.
        let user_data = UserData::encode(OpTag::Shutdown, conn_index, generation);
        let entry = Sqe::new(
            Op::Shutdown {
                fd: sqe::Fd::Fixed(conn_index),
                how: libc::SHUT_WR,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a multishot recvmsg for a UDP socket backed by a provided buffer ring.
    ///
    /// `msghdr` is used as a *template* by the kernel to decide how to lay out
    /// each datagram inside the ring buffer it picks (name / control / payload
    /// regions). It must remain valid for as long as the multishot is armed.
    /// Use [`crate::backend::uring::abi::RecvMsgOut::parse`] on the provided
    /// buffer each completion selects to extract the datagram.
    pub fn submit_recvmsg_multishot(
        &mut self,
        fd_index: u32,
        msghdr: *const libc::msghdr,
        bgid: u16,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::RecvMsgMulti {
                fd: sqe::Fd::Fixed(fd_index),
                msg: msghdr,
                buf_group: bgid,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a sendmsg (copying) for a UDP socket with destination address.
    pub fn submit_sendmsg(
        &mut self,
        fd_index: u32,
        msghdr: *const libc::msghdr,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::SendMsg {
                fd: sqe::Fd::Fixed(fd_index),
                msg: msghdr,
                flags: 0,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a multishot Recv (no peer info, kernel uses the socket's
    /// connected peer) for a UDP socket. Lighter than `RecvMsgMulti` —
    /// the CQE buffer contains only the payload, no `io_uring_recvmsg_out`
    /// header or sockaddr. The socket must already be `connect(2)`ed.
    pub fn submit_multishot_recv_udp(
        &mut self,
        fd_index: u32,
        bgid: u16,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::RecvMulti {
                fd: sqe::Fd::Fixed(fd_index),
                buf_group: bgid,
                limit: 0,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a single-shot Send for a connected UDP socket. The data lives
    /// in a `send_copy_pool` slot; the slot index is in the payload of
    /// `user_data` so the CQE handler can release it.
    pub fn submit_send_udp(
        &mut self,
        fd_index: u32,
        ptr: *const u8,
        len: u32,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Send {
                fd: sqe::Fd::Fixed(fd_index),
                buf: ptr,
                len,
                flags: 0,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a PollAdd for a raw file descriptor (e.g., pidfd for process exit).
    pub fn submit_poll_add(&mut self, fd: RawFd, mask: u32, ud: u64) -> io::Result<()> {
        let entry = Sqe::new(
            Op::PollAdd {
                fd: sqe::Fd::Raw(fd),
                mask,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a one-shot PollAdd on `POLLOUT` for a fixed-table TCP fd
    /// after a Send returned `-EAGAIN`. The CQE encodes `pool_slot` so
    /// the handler can resubmit the original send from where it
    /// stopped. (`current_ptr_remaining(pool_slot)` gives the right
    /// `(ptr, len)` to retry with.)
    pub fn submit_send_pollout(
        &mut self,
        conn_index: u32,
        generation: u32,
        pool_slot: u16,
        is_tls: bool,
    ) -> io::Result<()> {
        // Payload: pool_slot in the low 16 bits, is_tls flag in bit 16, and
        // the connection generation's low 15 bits in bits 17..31 so the
        // POLLOUT handler resubmits on the right completion path and can
        // reject a CQE that outlived its connection slot.
        let payload = UserData::send_pollout_payload(pool_slot, is_tls, generation);
        let user_data = UserData::encode(OpTag::SendPollOut, conn_index, payload);
        let entry = Sqe::new(
            Op::PollAdd {
                fd: sqe::Fd::Fixed(conn_index),
                mask: libc::POLLOUT as u32,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a timeout SQE that fires after the given duration.
    /// Produces a CQE with the given user_data when it fires (-ETIME)
    /// or is cancelled (-ECANCELED).
    pub fn submit_tick_timeout(
        &mut self,
        ts: *const crate::backend::uring::abi::Timespec,
        user_data: u64,
    ) -> io::Result<()> {
        let entry = Sqe::new(Op::Timeout { ts, abs: false }, user_data);
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Push an operation to the submission queue.
    ///
    /// # Safety
    /// The operation's pointers must stay valid until its completion
    /// arrives, and for `SendMsgZc` until its notification.
    pub(crate) unsafe fn push_sqe(&mut self, sqe: &Sqe) -> io::Result<()> {
        unsafe {
            self.engine.push(sqe)?;
        }
        #[cfg(test)]
        {
            self.last_pushed = Some(*sqe);
        }
        Ok(())
    }

    /// Push a chain of linked SQEs atomically.
    ///
    /// Sets `IOSQE_IO_LINK` on all entries except the last, so the kernel
    /// executes them sequentially. The engine queues them contiguously
    /// (`Engine::push_chain`).
    ///
    /// # Safety
    /// All SQEs must reference valid memory for the lifetime of their operations.
    pub(crate) unsafe fn push_sqe_chain(&mut self, entries: &mut [Sqe]) -> io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries.len() == 1 {
            return unsafe { self.push_sqe(&entries[0]) };
        }

        // Link every entry to the next, except the last.
        let last = entries.len() - 1;
        for entry in entries[..last].iter_mut() {
            debug_assert_eq!(entry.link, Link::None, "a chain sets its own links");
            entry.link = Link::Soft;
        }

        unsafe { self.engine.push_chain(entries) }
    }

    /// Submit an NVMe passthrough command via `IORING_OP_URING_CMD`.
    ///
    /// The `fd_index` must be a fixed file table index pointing to an opened
    /// NVMe-generic character device (`/dev/ng<X>n<Y>`).
    ///
    /// # Safety
    /// The buffer referenced by `cmd.addr` / `cmd.data_len` must remain valid
    /// until the CQE arrives.
    pub unsafe fn submit_nvme_cmd(
        &mut self,
        fd_index: u32,
        cmd: &NvmeUringCmd,
        user_data: UserData,
    ) -> io::Result<()> {
        let cmd_bytes = cmd.to_bytes();
        let entry = Sqe::new(
            Op::UringCmd80 {
                fd: sqe::Fd::Fixed(fd_index),
                cmd_op: NVME_URING_CMD_IO,
                cmd: cmd_bytes,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a direct I/O read via `IORING_OP_READ`.
    ///
    /// The `fd_index` must be a fixed file table index pointing to a file
    /// opened with `O_DIRECT`.
    ///
    /// # Safety
    /// The buffer at `buf` with length `len` must remain valid and properly
    /// aligned until the CQE arrives. For `O_DIRECT`, the buffer address,
    /// length, and file offset must all be aligned to the logical block size.
    pub unsafe fn submit_direct_read(
        &mut self,
        fd_index: u32,
        buf: *mut u8,
        len: u32,
        offset: u64,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Read {
                fd: sqe::Fd::Fixed(fd_index),
                buf,
                len,
                offset,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a direct I/O write via `IORING_OP_WRITE`.
    ///
    /// The `fd_index` must be a fixed file table index pointing to a file
    /// opened with `O_DIRECT`.
    ///
    /// # Safety
    /// The buffer at `buf` with length `len` must remain valid and properly
    /// aligned until the CQE arrives. For `O_DIRECT`, the buffer address,
    /// length, and file offset must all be aligned to the logical block size.
    pub unsafe fn submit_direct_write(
        &mut self,
        fd_index: u32,
        buf: *const u8,
        len: u32,
        offset: u64,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Write {
                fd: sqe::Fd::Fixed(fd_index),
                buf,
                len,
                offset,
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit an fsync via `IORING_OP_FSYNC`.
    ///
    /// The `fd_index` must be a fixed file table index pointing to an opened file.
    pub fn submit_direct_fsync(&mut self, fd_index: u32, user_data: UserData) -> io::Result<()> {
        let entry = Sqe::new(
            Op::Fsync {
                fd: sqe::Fd::Fixed(fd_index),
            },
            user_data.raw(),
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    // ── Filesystem I/O submission methods ──────────────────────────────

    /// Submit an openat via io_uring. The fd is installed directly into the
    /// fixed file table at `fd_index`.
    ///
    /// # Safety
    /// `pathname` must point to a valid null-terminated C string that remains
    /// valid until the CQE arrives.
    pub unsafe fn submit_openat(
        &mut self,
        fd_index: u32,
        pathname: *const libc::c_char,
        flags: i32,
        mode: u32,
        ud: u64,
    ) -> io::Result<()> {
        // `Sqe::encode` builds the destination slot again and relies on
        // this check.
        if fd_index > sqe::MAX_FILE_INDEX {
            return Err(io::Error::other("invalid fd_index for openat"));
        }
        let entry = Sqe::new(
            Op::OpenAt {
                path: pathname,
                flags,
                mode,
                file_index: fd_index,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a statx via io_uring.
    ///
    /// # Safety
    /// `pathname` must point to a valid null-terminated C string and `statxbuf`
    /// must point to valid memory, both remaining valid until the CQE arrives.
    pub unsafe fn submit_statx(
        &mut self,
        pathname: *const libc::c_char,
        statxbuf: *mut libc::statx,
        ud: u64,
    ) -> io::Result<()> {
        // STATX_BASIC_STATS = 0x7ff
        let entry = Sqe::new(
            Op::Statx {
                path: pathname,
                buf: statxbuf,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a renameat via io_uring.
    ///
    /// # Safety
    /// `oldpath` and `newpath` must point to valid null-terminated C strings
    /// that remain valid until the CQE arrives.
    pub unsafe fn submit_renameat(
        &mut self,
        oldpath: *const libc::c_char,
        newpath: *const libc::c_char,
        ud: u64,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::RenameAt {
                old: oldpath,
                new: newpath,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit an unlinkat via io_uring.
    ///
    /// # Safety
    /// `pathname` must point to a valid null-terminated C string that remains
    /// valid until the CQE arrives.
    pub unsafe fn submit_unlinkat(
        &mut self,
        pathname: *const libc::c_char,
        flags: i32,
        ud: u64,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::UnlinkAt {
                path: pathname,
                flags,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }

    /// Submit a mkdirat via io_uring.
    ///
    /// # Safety
    /// `pathname` must point to a valid null-terminated C string that remains
    /// valid until the CQE arrives.
    pub unsafe fn submit_mkdirat(
        &mut self,
        pathname: *const libc::c_char,
        mode: u32,
        ud: u64,
    ) -> io::Result<()> {
        let entry = Sqe::new(
            Op::MkDirAt {
                path: pathname,
                mode,
            },
            ud,
        );
        unsafe {
            self.push_sqe(&entry)?;
        }
        Ok(())
    }
}

#[cfg(all(test, uring_engine))]
mod tests {
    use super::*;
    use crate::backend::uring::engine::uring::{
        IORING_REGISTER_PBUF_RING, IORING_UNREGISTER_PBUF_RING, PBUF_RESV_INVERTED_ON,
        pbuf_ring_register, provided_ring_failure, retry_with_resv_set,
    };
    use crate::config::ConfigBuilder;
    use crate::memlock::KernelVersion;

    fn ring_with(cap: Option<u32>) -> Ring {
        let mut builder = ConfigBuilder::new().workers(1).sq_entries(256);
        if let Some(cap) = cap {
            builder = builder.iowq_max_workers(cap);
        }
        let config = builder.build().expect("valid config");
        // Up to 5 s for earlier rings' memlock charge to be released (#589).
        for _ in 0..50 {
            match Ring::setup(&config) {
                Err(e) if is_memlock_enomem(&e) => {
                    std::thread::sleep(std::time::Duration::from_millis(100))
                }
                result => return result.expect("ring"),
            }
        }
        Ring::setup(&config).expect("ring")
    }

    fn online_cpus() -> u32 {
        // SAFETY: sysconf has no preconditions.
        unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) as u32 }
    }

    /// The `resv[0]` retry (#626) runs only for `EINVAL` on 6.8.
    #[test]
    fn resv_retry_only_for_einval_on_6_8() {
        let k = |major, minor| Some(KernelVersion { major, minor });
        let einval = io::Error::from_raw_os_error(libc::EINVAL);
        let enomem = io::Error::from_raw_os_error(libc::ENOMEM);
        assert!(retry_with_resv_set(&einval, k(6, 8)));
        assert!(!retry_with_resv_set(&enomem, k(6, 8)));
        for kernel in [k(6, 1), k(6, 7), k(6, 9), k(6, 12), k(7, 1), None] {
            assert!(!retry_with_resv_set(&einval, kernel), "{kernel:?}");
        }
    }

    /// Two provided buffer rings register and unregister on the running
    /// kernel, as a worker with UDP does. On a kernel other than 6.8 the
    /// standard form is used throughout.
    #[test]
    fn provided_rings_register_and_unregister() {
        // Declared before the ring, so they are unmapped after it drops.
        let tcp = ProvidedBufRing::new(5, 8, 4096).expect("tcp ring");
        let udp = ProvidedBufRing::new(6, 8, 4096).expect("udp ring");
        let mut ring = ring_with(None);
        ring.register_buf_ring(&tcp, RingKind::Plain)
            .expect("register tcp ring");
        ring.register_buf_ring(&udp, RingKind::Plain)
            .expect("register udp ring");
        if KernelVersion::current() != Some(PBUF_RESV_INVERTED_ON) {
            assert!(!ring.engine.pbuf_resv_set());
        }
        ring.unregister_buf_ring(5).expect("unregister tcp ring");
        ring.unregister_buf_ring(6).expect("unregister udp ring");
        // Unregistered, so the group can be registered again.
        ring.register_buf_ring(&tcp, RingKind::Plain)
            .expect("register tcp ring again");
        ring.unregister_buf_ring(5)
            .expect("unregister tcp ring again");
    }

    /// `incremental_buffers` matches what registration does: an
    /// incremental ring registers and unregisters when it reports true and
    /// is refused with `EINVAL` when it reports false. Kernels from 6.12
    /// support it.
    #[test]
    fn incremental_buffers_matches_registration() {
        // Declared before the ring, so it is unmapped after it drops.
        let provided = ProvidedBufRing::new(9, 8, 4096).expect("provided ring");
        let mut ring = ring_with(None);
        let supported = ring.engine.incremental_buffers().expect("probe");
        // The answer is cached and stable.
        assert_eq!(ring.engine.incremental_buffers().expect("probe"), supported);
        if KernelVersion::current()
            >= Some(KernelVersion {
                major: 6,
                minor: 12,
            })
        {
            assert!(supported, "6.12+ supports IOU_PBUF_RING_INC");
        }
        match ring.register_buf_ring(&provided, RingKind::Incremental) {
            Ok(()) => {
                assert!(supported);
                ring.unregister_buf_ring(9).expect("unregister");
            }
            Err(e) => {
                assert!(!supported, "registration refused: {e}");
                assert!(e.to_string().contains("EINVAL"), "{e}");
            }
        }
    }

    /// The raw `io_uring_register` call behind the `resv[0]` retry (#626)
    /// registers, unregisters and re-registers a ring, in whichever form the
    /// running kernel accepts: zeroed reserved words, or on a 6.8 kernel that
    /// refuses those, `resv[0]` set. Where zeroed words are accepted, a
    /// registration with `resv[0]` set is refused. A correct kernel refuses a
    /// nonzero word in any slot, so this cannot tell which slot `resv0` is
    /// written to; the size assertion on `BufReg` and its field order cover
    /// that. Unregistration is checked in the same form as registration,
    /// which is stricter than `unregister_buf_ring`'s fallback; Ubuntu
    /// 6.8.0-142 accepts `resv[0]` set for both.
    #[test]
    fn raw_pbuf_registration_round_trips() {
        // Declared before the ring, so it is unmapped after the ring drops.
        let provided = ProvidedBufRing::new(7, 8, 4096).expect("provided ring");
        let ring = ring_with(None);
        let fd = ring.engine.raw_fd();
        let (addr, entries) = (provided.ring_addr(), provided.ring_entries());
        // Safety: `provided` outlives the ring and so every registration.
        unsafe {
            let resv0 =
                match pbuf_ring_register(fd, IORING_REGISTER_PBUF_RING, addr, entries, 7, 0, 0) {
                    Ok(()) => 0,
                    Err(e) if retry_with_resv_set(&e, KernelVersion::current()) => {
                        pbuf_ring_register(fd, IORING_REGISTER_PBUF_RING, addr, entries, 7, 0, 1)
                            .expect("register with resv[0] set");
                        1
                    }
                    Err(e) => panic!("register: {e}"),
                };
            pbuf_ring_register(fd, IORING_UNREGISTER_PBUF_RING, 0, 0, 7, 0, resv0)
                .expect("unregister");
            pbuf_ring_register(fd, IORING_REGISTER_PBUF_RING, addr, entries, 7, 0, resv0)
                .expect("register again");
            if resv0 == 0 {
                assert_eq!(
                    pbuf_ring_register(fd, IORING_REGISTER_PBUF_RING, addr, entries, 8, 0, 1)
                        .map_err(|e| e.raw_os_error()),
                    Err(Some(libc::EINVAL))
                );
            }
            pbuf_ring_register(fd, IORING_UNREGISTER_PBUF_RING, 0, 0, 7, 0, resv0)
                .expect("unregister");
        }
    }

    /// The transient-ENOMEM check matches the messages ring setup and
    /// provided-ring registration build for that errno, and nothing else.
    #[test]
    fn is_memlock_enomem_reads_the_errno_from_the_message() {
        let probe = crate::error::RingSetupProbe::default();
        let enomem =
            Error::ring_setup_with_probe(io::Error::from_raw_os_error(libc::ENOMEM), &probe);
        let eperm = Error::ring_setup_with_probe(io::Error::from_raw_os_error(libc::EPERM), &probe);
        assert!(is_memlock_enomem(&enomem), "{enomem}");
        assert!(!is_memlock_enomem(&eperm), "{eperm}");
        assert!(!is_memlock_enomem(&Error::Io(
            io::Error::from_raw_os_error(libc::ENOMEM)
        )));
        let provided =
            |errno| provided_ring_failure(&io::Error::from_raw_os_error(errno), 0, 16, &probe);
        assert!(is_memlock_enomem(&provided(libc::ENOMEM)));
        assert!(!is_memlock_enomem(&provided(libc::EINVAL)));
    }

    /// The kernel's own bounded limit on this host.
    fn kernel_default() -> u32 {
        256.min(4 * online_cpus())
    }

    /// The default config leaves the kernel's limit.
    #[test]
    fn the_default_leaves_the_kernel_limit() {
        let ring = ring_with(None);
        assert_eq!(ring.iowq_max_workers().expect("query")[0], kernel_default());
    }

    #[test]
    fn a_configured_cap_reaches_the_kernel() {
        let ring = ring_with(Some(2));
        assert_eq!(ring.iowq_max_workers().expect("query")[0], 2);
    }

    /// A cap above the kernel's limit does not raise it.
    #[test]
    fn a_cap_above_the_kernel_limit_leaves_it() {
        let ring = ring_with(Some(100_000));
        assert_eq!(ring.iowq_max_workers().expect("query")[0], kernel_default());
    }

    /// A shutdown goes ahead of a close before 6.13 and on an unknown kernel,
    /// a cancel of the connection's requests from 6.13 (#586).
    #[test]
    fn a_close_leads_with_a_shutdown_before_6_13_and_a_cancel_after() {
        let k = |major, minor| Some(KernelVersion { major, minor });
        assert_eq!(close_lead_for(k(6, 1)), CloseLead::Shutdown);
        assert_eq!(close_lead_for(k(6, 12)), CloseLead::Shutdown);
        assert_eq!(close_lead_for(k(6, 13)), CloseLead::CancelAll);
        assert_eq!(close_lead_for(k(7, 1)), CloseLead::CancelAll);
        assert_eq!(close_lead_for(None), CloseLead::Shutdown);
    }

    /// The ring decides from the running kernel.
    #[test]
    fn the_ring_decides_the_close_lead_from_the_running_kernel() {
        let ring = ring_with(None);
        assert_eq!(ring.close_lead(), close_lead_for(KernelVersion::current()));
    }

    /// A cap of 0 registers nothing.
    #[test]
    fn a_zero_cap_leaves_the_kernel_default() {
        let ring = ring_with(Some(0));
        assert_eq!(ring.iowq_max_workers().expect("query")[0], kernel_default());
    }
}
