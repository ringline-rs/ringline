//! A ringline-owned submission: what to do, on which file, and how to tag
//! the completion.
//!
//! The driver describes every operation as an [`Sqe`], and the engine
//! encodes it when it is pushed. Only `engine/uring.rs` builds an
//! `io_uring::squeue::Entry`.

use std::os::fd::RawFd;

/// The largest fixed-file slot an `OpenAt` can install into: the kernel
/// encodes the slot as `index + 1`, and `IORING_FILE_INDEX_ALLOC` (`!0`)
/// asks it to choose one.
pub(crate) const MAX_FILE_INDEX: u32 = u32::MAX - 2;

/// The file an operation targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fd {
    /// A slot in the ring's registered file table.
    Fixed(u32),
    /// A plain file descriptor.
    Raw(RawFd),
}

/// How an operation is linked to the next one pushed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Link {
    None,
    /// `IOSQE_IO_LINK`: the next op runs only if this one succeeds.
    Soft,
    /// `IOSQE_IO_HARDLINK`: the next op runs whatever this one's result.
    Hard,
}

/// One operation and its arguments. Pointers must stay valid until the
/// operation's completion arrives, and for `SendMsgZc` until its
/// notification (Domain Invariant 1).
#[derive(Clone, Copy, Debug)]
pub(crate) enum Op {
    /// Multishot recv selecting from provided-buffer group `buf_group`.
    /// A nonzero `limit` ends the arm once it has received that many bytes
    /// (`sqe->optlen`, Linux 6.17+; older kernels fail the arm with
    /// `EINVAL`). The last completion before the end has `F_MORE` clear and
    /// may overshoot the limit by up to one buffer. 0 is no limit.
    RecvMulti {
        fd: Fd,
        buf_group: u16,
        limit: u32,
    },
    /// Multishot recvmsg selecting from `buf_group`, laid out by `msg`.
    RecvMsgMulti {
        fd: Fd,
        msg: *const libc::msghdr,
        buf_group: u16,
    },
    /// One-shot recv into `buf`.
    Recv {
        fd: Fd,
        buf: *mut u8,
        len: u32,
    },
    /// Multishot accept; `flags` are `accept4(2)` flags.
    AcceptMulti {
        fd: Fd,
        flags: i32,
    },
    Send {
        fd: Fd,
        buf: *const u8,
        len: u32,
        flags: i32,
    },
    SendMsg {
        fd: Fd,
        msg: *const libc::msghdr,
        flags: u32,
    },
    SendMsgZc {
        fd: Fd,
        msg: *const libc::msghdr,
    },
    Writev {
        fd: Fd,
        iovecs: *const libc::iovec,
        count: u32,
        offset: u64,
    },
    Read {
        fd: Fd,
        buf: *mut u8,
        len: u32,
        offset: u64,
    },
    Write {
        fd: Fd,
        buf: *const u8,
        len: u32,
        offset: u64,
    },
    Fsync {
        fd: Fd,
    },
    Close {
        fd: Fd,
    },
    Shutdown {
        fd: Fd,
        how: i32,
    },
    /// Cancel every request on `fd` (`ASYNC_CANCEL` with `FD | ALL`).
    CancelFdAll {
        fd: Fd,
    },
    /// Cancel the request whose user_data is exactly `target`.
    Cancel {
        target: u64,
    },
    Connect {
        fd: Fd,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    },
    /// A timeout, relative or (`abs`) absolute `CLOCK_MONOTONIC`.
    Timeout {
        ts: *const super::abi::Timespec,
        abs: bool,
    },
    /// Install a real fd for registered file `index` (`FIXED_FD_INSTALL`).
    FixedFdInstall {
        index: u32,
    },
    PollAdd {
        fd: Fd,
        mask: u32,
    },
    /// `openat(AT_FDCWD, …)`, installing the result into registered slot
    /// `file_index`.
    OpenAt {
        path: *const libc::c_char,
        flags: i32,
        mode: u32,
        file_index: u32,
    },
    /// `statx(AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS)`.
    Statx {
        path: *const libc::c_char,
        buf: *mut libc::statx,
    },
    RenameAt {
        old: *const libc::c_char,
        new: *const libc::c_char,
    },
    UnlinkAt {
        path: *const libc::c_char,
        flags: i32,
    },
    MkDirAt {
        path: *const libc::c_char,
        mode: u32,
    },
    /// NVMe passthrough (`URING_CMD`, `cmd_op`) with an 80-byte command.
    UringCmd80 {
        fd: Fd,
        cmd_op: u32,
        cmd: [u8; 80],
    },
}

/// An operation, its completion tag and its link to the next operation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Sqe {
    pub(crate) op: Op,
    pub(crate) user_data: u64,
    pub(crate) link: Link,
}

impl Sqe {
    pub(crate) fn new(op: Op, user_data: u64) -> Self {
        Sqe {
            op,
            user_data,
            link: Link::None,
        }
    }

    /// A stream send of `len` bytes at `buf` on registered file `index`,
    /// with `MSG_WAITALL` (Domain Invariant 5).
    pub(crate) fn stream_send(index: u32, buf: *const u8, len: u32, user_data: u64) -> Self {
        Sqe::new(
            Op::Send {
                fd: Fd::Fixed(index),
                buf,
                len,
                flags: crate::completion::STREAM_SEND_FLAGS,
            },
            user_data,
        )
    }

    /// A zero-copy `sendmsg` on registered file `index`.
    pub(crate) fn send_msg_zc(index: u32, msg: *const libc::msghdr, user_data: u64) -> Self {
        Sqe::new(
            Op::SendMsgZc {
                fd: Fd::Fixed(index),
                msg,
            },
            user_data,
        )
    }

    pub(crate) fn link(mut self, link: Link) -> Self {
        self.link = link;
        self
    }
}
