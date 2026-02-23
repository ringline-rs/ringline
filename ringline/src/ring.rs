use std::io;
use std::os::fd::RawFd;

use io_uring::cqueue;
use io_uring::squeue;
use io_uring::types::{Fd, Fixed};
use io_uring::{IoUring, opcode};

use crate::buffer::fixed::FixedBufferRegistry;
use crate::buffer::provided::ProvidedBufRing;
use crate::completion::{OpTag, UserData};
use crate::config::Config;
use crate::nvme::{NVME_URING_CMD_IO, NvmeUringCmd};

/// Wrapper around IoUring providing high-level SQE submission helpers.
///
/// The ring uses 128-byte SQEs and 32-byte CQEs (`IoUring<Entry128, Entry32>`)
/// to support NVMe passthrough via `IORING_OP_URING_CMD` / `UringCmd80`.
/// Standard network opcodes produce 64-byte `Entry` values which are
/// automatically converted to `Entry128` (zero-padded) via `Into`.
///
/// Memory overhead of Big SQE/CQE: +32 KB per worker with default config
/// (256 SQ × 64B extra + 1024 CQ × 16B extra), negligible relative to the
/// ~20 MB of buffer pools allocated per worker.
pub struct Ring {
    pub(crate) ring: IoUring<squeue::Entry128, cqueue::Entry32>,
    /// Recv buffer group ID for multishot recv.
    bgid: u16,
}

impl Ring {
    /// Create and configure the io_uring instance.
    pub fn setup(config: &Config) -> io::Result<Self> {
        let cq_entries = config
            .sq_entries
            .checked_mul(4)
            .unwrap_or(config.sq_entries);

        let mut builder = IoUring::<squeue::Entry128, cqueue::Entry32>::builder();
        builder.setup_cqsize(cq_entries);
        builder.setup_coop_taskrun();
        builder.setup_single_issuer();

        if config.sqpoll {
            builder.setup_sqpoll(config.sqpoll_idle_ms);
            if let Some(cpu) = config.sqpoll_cpu {
                builder.setup_sqpoll_cpu(cpu);
            }
            // DEFER_TASKRUN is incompatible with SQPOLL (kernel returns EINVAL).
        } else {
            builder.setup_defer_taskrun();
        }

        let ring = builder.build(config.sq_entries)?;

        Ok(Ring {
            ring,
            bgid: config.recv_buffer.bgid,
        })
    }

    /// Register fixed buffers (user memory regions).
    pub fn register_buffers(&self, registry: &FixedBufferRegistry) -> io::Result<()> {
        let iovecs = registry.iovecs();
        if iovecs.is_empty() {
            return Ok(());
        }
        // Safety: iovecs point to valid memory that outlives the registration.
        unsafe {
            self.ring.submitter().register_buffers(iovecs)?;
        }
        Ok(())
    }

    /// Register a sparse file table for direct descriptors.
    pub fn register_files_sparse(&self, count: u32) -> io::Result<()> {
        self.ring.submitter().register_files_sparse(count)?;
        Ok(())
    }

    /// Update registered file table at given offset.
    pub fn register_files_update(&self, offset: u32, fds: &[RawFd]) -> io::Result<()> {
        self.ring.submitter().register_files_update(offset, fds)?;
        Ok(())
    }

    /// Register the provided buffer ring with the kernel.
    pub fn register_buf_ring(&self, provided: &ProvidedBufRing) -> io::Result<()> {
        // Safety: ring_addr points to valid mmap'd memory that outlives the registration.
        unsafe {
            self.ring.submitter().register_buf_ring_with_flags(
                provided.ring_addr(),
                provided.ring_entries() as u16,
                provided.bgid(),
                0,
            )?;
        }
        Ok(())
    }

    /// Submit a multishot recvmsg with provided buffer ring for a connection.
    /// Used when SO_TIMESTAMPING is enabled to receive cmsg ancillary data
    /// (kernel timestamps) alongside TCP payload.
    #[cfg(feature = "timestamps")]
    pub fn submit_multishot_recvmsg(
        &mut self,
        conn_index: u32,
        msghdr: *const libc::msghdr,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::RecvMsgMultiTs, conn_index, 0);
        let entry = opcode::RecvMsgMulti::new(Fixed(conn_index), msghdr, self.bgid)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a multishot recv with provided buffer ring for a connection.
    pub fn submit_multishot_recv(&mut self, conn_index: u32) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        let entry = opcode::RecvMulti::new(Fixed(conn_index), self.bgid)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a copied send. The data must be in a SendCopyPool slot.
    /// The pool slot index is stored in the payload for release on CQE.
    pub fn submit_send_copied(
        &mut self,
        conn_index: u32,
        ptr: *const u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Send, conn_index, pool_slot as u32);
        let entry = opcode::Send::new(Fixed(conn_index), ptr, len)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
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
        let entry = opcode::SendMsgZc::new(Fixed(conn_index), msg)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a TLS-internal send (handshake, alert). Uses OpTag::TlsSend
    /// so the CQE handler releases the pool slot without calling on_send_complete.
    pub fn submit_tls_send(
        &mut self,
        conn_index: u32,
        ptr: *const u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::TlsSend, conn_index, pool_slot as u32);
        let entry = opcode::Send::new(Fixed(conn_index), ptr, len)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a TLS-internal send with IOSQE_IO_LINK. Used for close_notify
    /// so the subsequent Close SQE is chained and only runs after the send completes.
    pub fn submit_tls_send_linked(
        &mut self,
        conn_index: u32,
        ptr: *const u8,
        len: u32,
        pool_slot: u16,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::TlsSend, conn_index, pool_slot as u32);
        let entry = opcode::Send::new(Fixed(conn_index), ptr, len)
            .build()
            .user_data(user_data.raw())
            .flags(io_uring::squeue::Flags::IO_LINK);
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit an eventfd read (8 bytes).
    pub fn submit_eventfd_read(&mut self, eventfd: RawFd, buf: *mut u8) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::EventFdRead, 0, 0);
        let entry = opcode::Read::new(Fd(eventfd), buf, 8)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a close for a direct file descriptor.
    pub fn submit_close(&mut self, conn_index: u32) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Close, conn_index, 0);
        let entry = opcode::Close::new(Fixed(conn_index))
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit an async connect for a direct file descriptor.
    pub fn submit_connect(
        &mut self,
        conn_index: u32,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Connect, conn_index, 0);
        let entry = opcode::Connect::new(Fixed(conn_index), addr, addrlen)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a timeout SQE. The timespec must remain valid until the CQE arrives.
    pub fn submit_timeout(
        &mut self,
        timespec: *const io_uring::types::Timespec,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = opcode::Timeout::new(timespec)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit an absolute timeout SQE. The timespec contains absolute
    /// `CLOCK_MONOTONIC` seconds/nanoseconds. The timespec must remain valid
    /// until the CQE arrives.
    pub fn submit_timeout_abs(
        &mut self,
        timespec: *const io_uring::types::Timespec,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = opcode::Timeout::new(timespec)
            .flags(io_uring::types::TimeoutFlags::ABS)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit an async cancel targeting a specific user_data value.
    pub fn submit_async_cancel(
        &mut self,
        target_user_data: u64,
        conn_index: u32,
    ) -> io::Result<()> {
        let ud = UserData::encode(OpTag::Cancel, conn_index, 0);
        let entry = opcode::AsyncCancel::new(target_user_data)
            .build()
            .user_data(ud.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a shutdown(SHUT_WR) for a connection.
    pub fn submit_shutdown(&mut self, conn_index: u32) -> io::Result<()> {
        let user_data = UserData::encode(OpTag::Shutdown, conn_index, 0);
        let entry = opcode::Shutdown::new(Fixed(conn_index), libc::SHUT_WR)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit a recvmsg for a UDP socket (single-shot with pre-allocated buffer).
    pub fn submit_recvmsg(
        &mut self,
        fd_index: u32,
        msghdr: *mut libc::msghdr,
        user_data: UserData,
    ) -> io::Result<()> {
        let entry = opcode::RecvMsg::new(Fixed(fd_index), msghdr)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
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
        let entry = opcode::SendMsg::new(Fixed(fd_index), msghdr)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit all pending SQEs and wait for at least `min_complete` CQEs.
    pub fn submit_and_wait(&self, min_complete: u32) -> io::Result<()> {
        self.ring
            .submitter()
            .submit_and_wait(min_complete as usize)?;
        Ok(())
    }

    /// Submit a timeout SQE that fires after the given duration.
    /// Produces a CQE with the given user_data when it fires (-ETIME)
    /// or is cancelled (-ECANCELED).
    pub fn submit_tick_timeout(
        &mut self,
        ts: *const io_uring::types::Timespec,
        user_data: u64,
    ) -> io::Result<()> {
        let entry = opcode::Timeout::new(ts).build().user_data(user_data);
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit pending SQEs without waiting. Used for mid-iteration flush.
    pub fn flush(&self) -> io::Result<()> {
        self.ring.submit()?;
        Ok(())
    }

    /// Push a standard SQE to the submission queue.
    ///
    /// The 64-byte `Entry` is automatically converted to `Entry128` (zero-padded)
    /// for the Big SQE ring.
    ///
    /// # Safety
    /// The SQE must reference valid memory for the lifetime of the operation.
    pub(crate) unsafe fn push_sqe(&mut self, entry: squeue::Entry) -> io::Result<()> {
        let entry128: squeue::Entry128 = entry.into();
        unsafe {
            self.push_sqe128(entry128)?;
        }
        Ok(())
    }

    /// Push a 128-byte SQE to the submission queue.
    ///
    /// Used directly for NVMe passthrough (`UringCmd80`) which produces
    /// `Entry128` natively.
    ///
    /// # Safety
    /// The SQE must reference valid memory for the lifetime of the operation.
    pub(crate) unsafe fn push_sqe128(&mut self, entry: squeue::Entry128) -> io::Result<()> {
        // Try to push; if SQ is full, submit first to make room.
        unsafe {
            if self.ring.submission().push(&entry).is_err() {
                self.ring.submit()?;
                if self.ring.submission().push(&entry).is_err() {
                    crate::metrics::SQE_SUBMIT_FAILURES.increment();
                    return Err(io::Error::other("SQ still full after submit"));
                }
            }
        }
        Ok(())
    }

    /// Push a chain of linked SQEs atomically.
    ///
    /// Sets `IOSQE_IO_LINK` on all entries except the last, so the kernel
    /// executes them sequentially. All entries are pushed via `push_multiple`
    /// to guarantee contiguous placement in the SQ.
    ///
    /// # Safety
    /// All SQEs must reference valid memory for the lifetime of their operations.
    pub(crate) unsafe fn push_sqe_chain(
        &mut self,
        entries: &mut [squeue::Entry],
    ) -> io::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries.len() == 1 {
            return unsafe { self.push_sqe(entries[0].clone()) };
        }

        // Set IO_LINK on all entries except the last.
        let last = entries.len() - 1;
        for entry in entries[..last].iter_mut() {
            *entry = entry.clone().flags(io_uring::squeue::Flags::IO_LINK);
        }

        // Convert to Entry128 for the Big SQ ring.
        let entries128: Vec<squeue::Entry128> = entries.iter().map(|e| e.clone().into()).collect();

        // Ensure enough room in the SQ for the entire chain.
        {
            let sq = self.ring.submission();
            if sq.capacity() - sq.len() < entries128.len() {
                drop(sq);
                self.ring.submit()?;
                let sq = self.ring.submission();
                if sq.capacity() - sq.len() < entries128.len() {
                    return Err(io::Error::other("SQ too small for chain"));
                }
            }
        }

        // Atomic push of the entire chain.
        unsafe {
            self.ring
                .submission()
                .push_multiple(&entries128)
                .map_err(|_| io::Error::other("SQ full after flush for chain"))?;
        }
        Ok(())
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
        let entry = opcode::UringCmd80::new(Fixed(fd_index), NVME_URING_CMD_IO)
            .cmd(cmd_bytes)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe128(entry)?;
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
        let entry = opcode::Read::new(Fixed(fd_index), buf, len)
            .offset(offset)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
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
        let entry = opcode::Write::new(Fixed(fd_index), buf, len)
            .offset(offset)
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }

    /// Submit an fsync via `IORING_OP_FSYNC`.
    ///
    /// The `fd_index` must be a fixed file table index pointing to an opened file.
    pub fn submit_direct_fsync(&mut self, fd_index: u32, user_data: UserData) -> io::Result<()> {
        let entry = opcode::Fsync::new(Fixed(fd_index))
            .build()
            .user_data(user_data.raw());
        unsafe {
            self.push_sqe(entry)?;
        }
        Ok(())
    }
}
