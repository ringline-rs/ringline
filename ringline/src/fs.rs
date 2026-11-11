//! Async filesystem I/O.
//!
//! Provides buffered file read/write and metadata operations (stat,
//! symlink_metadata, rename, remove, mkdir). Apart from [`close`], which is
//! synchronous, file operations do not block the worker thread: on io_uring
//! the kernel completes them inline or on its own threads (see below); on mio
//! they run on a thread pool.
//!
//! Operations are independent of each other on both backends, including
//! operations on one file: io_uring does not order independent submissions,
//! and the mio pool's threads take requests from one queue. A write is in the
//! file when its future resolves, not when `write` returns, and [`fsync`]
//! covers the writes whose futures have resolved when it is called. To order
//! two operations, await the first before submitting the second.
//!
//! On io_uring a call that finds the ring's submission queue full submits the
//! queue inline before pushing (under [`sqpoll`](crate::ConfigBuilder::sqpoll)
//! it waits for the SQ thread to free an entry); if that submit
//! (`io_uring_enter(2)`) fails, for example with `Interrupted`, `EBUSY` or
//! `EAGAIN`, the call returns the error and leaves nothing in flight. The
//! submission queue holds `sq_entries` entries per worker, shared by every
//! operation on it.
//!
//! ## Blocking file I/O and connection closes (io_uring)
//!
//! When the kernel cannot finish an io_uring operation without blocking, it
//! runs the operation on io-wq: kernel threads that belong to the thread that
//! submitted it, which is the ringline worker, or its SQPOLL thread when
//! [`sqpoll`](crate::ConfigBuilder::sqpoll) is set. io-wq keeps two pools.
//! File and path operations go to the bounded one, whose size limit is given
//! below. These are the pool operations:
//!
//! - always: [`fsync`], [`stat`], [`symlink_metadata`], [`rename`],
//!   [`remove`], [`mkdir`], and [`open`] with `CREATE` or `TRUNCATE`
//!   (including [`create`]);
//! - on overlayfs (the usual root filesystem of a Docker or Kubernetes
//!   container; a mounted volume usually is not) and tmpfs: every read and
//!   write;
//! - on a filesystem that cannot run buffered writes asynchronously, such as
//!   ext4 or f2fs (XFS and btrfs can): every write;
//! - otherwise, opens, reads and writes the kernel cannot finish without
//!   blocking, except that a buffered read that misses the page cache on
//!   ext4, XFS or btrfs waits for the page in task work rather than on the
//!   pool.
//!
//! [`direct_io_fsync`](crate::direct_io_fsync) always
//! uses the pool too. Direct I/O reads and writes use it always on overlayfs
//! and tmpfs, and elsewhere when they would block.
//!
//! The pool has `min(sq_entries, 4 × the host's online CPUs)` threads per
//! worker; a container's CPU limit does not lower it. With the default
//! [`sq_entries`](crate::ConfigBuilder::sq_entries) of 4096 that is 4 × the
//! CPU count on hosts with up to 1024 CPUs.
//! [`ConfigBuilder::iowq_max_workers`](crate::ConfigBuilder::iowq_max_workers)
//! lowers it.
//!
//! Before Linux 6.13, or when ringline cannot read the kernel version, each
//! connection close runs a `shutdown` on the same pool first. Pool operations
//! on the worker therefore delay its closes. The peer's FIN arrives late, and
//! the connection's slot stays in use until the close completes, counting
//! against the worker's connection limit. Measured on Linux 6.12 on a
//! 16-vCPU VM, with one worker running 32 concurrent write-and-`fsync` loops
//! on separate files, the wait for a closed connection's EOF was:
//!
//! | pool size         | file I/O | p50     | p99     |
//! |-------------------|----------|---------|---------|
//! | 64 (kernel limit) | none     | 0.20 ms | 0.44 ms |
//! | 64 (kernel limit) | 32 loops | 0.21 ms | 11.8 ms |
//! | 16                | 32 loops | 11.6 ms | 37.6 ms |
//! | 4                 | 32 loops | 28.2 ms | 82.3 ms |
//!
//! On these kernels:
//!
//! - Upgrade to Linux 6.13 or later if you can. From 6.13 a close does not
//!   use the pool.
//! - Keep the number of pool operations a worker has in flight below the
//!   pool size, and do not set `iowq_max_workers` below that count. Writes to
//!   the same file run one at a time and count once; `fsync` calls do not,
//!   even on the same file. This shortens the delay; it does not remove it
//!   (the `64 (kernel limit)`, `32 loops` row above).
//! - Move the heaviest file I/O, such as an `fsync` loop, to `std::fs::File`
//!   inside [`spawn_blocking`](crate::spawn_blocking), which does not use
//!   io_uring. A ringline [`File`] cannot be used there. That pool is shared
//!   by all workers, has 4 threads by default
//!   ([`ConfigBuilder::blocking_threads`](crate::ConfigBuilder::blocking_threads)),
//!   and runs at `SCHED_IDLE`, so on a busy host its work waits until a CPU
//!   is idle.
//!
//! On every kernel, `shutdown_write` (on
//! [`Connection`](crate::Connection::shutdown_write) or
//! [`SendHalf`](crate::SendHalf::shutdown_write)) sends a `shutdown` that
//! runs on the pool. A close issued before that `shutdown` finishes waits for
//! it.
//!
//! On the mio backend, file I/O runs on a separate thread pool and a close
//! does not wait for it.

use std::ffi::CString;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;

use crate::runtime::CURRENT_TASK_ID;
use crate::runtime::io::{CURRENT_DRIVER, DiskIoFuture, with_state};
use crate::runtime::waker::pending;

/// Opaque handle to an opened file.
///
/// The handle names a slot in the table of the worker that opened it, so it is
/// not `Send`: use it on that worker. Another worker's table can hold a
/// different file in the same slot. A handler is created on its worker's
/// thread and stays there, so it can keep a handle in a field.
///
/// ```
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<ringline::fs::File>();
/// ```
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::fs::File>();
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct File {
    pub(crate) index: u16,
    pub(crate) generation: u32,
    /// Makes the handle `!Send`.
    _not_send: PhantomData<*const ()>,
}

impl std::fmt::Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .finish()
    }
}

impl File {
    pub(crate) fn new(index: u16, generation: u32) -> Self {
        File {
            index,
            generation,
            _not_send: PhantomData,
        }
    }

    /// Returns the file slot index.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// Flags for [`open()`]: one access mode, combined with `|` with any of the
/// other flags.
///
/// The access modes are the `open(2)` values, not bits: `READ` is 0 and
/// `WRITE` is 1, so `READ | WRITE` is `WRITE`, which opens the file
/// write-only and fails every read with `EBADF`. The read-write mode is
/// [`READ_WRITE`](Self::READ_WRITE).
///
/// ```
/// use ringline::fs::OpenFlags;
/// assert_eq!(OpenFlags::READ | OpenFlags::WRITE, OpenFlags::WRITE);
/// assert_ne!(OpenFlags::READ_WRITE, OpenFlags::WRITE);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub(crate) i32);

impl OpenFlags {
    /// Open for reading only (`O_RDONLY`).
    pub const READ: Self = Self(libc::O_RDONLY);
    /// Open for writing only (`O_WRONLY`).
    pub const WRITE: Self = Self(libc::O_WRONLY);
    /// Open for reading and writing (`O_RDWR`).
    pub const READ_WRITE: Self = Self(libc::O_RDWR);
    /// Create the file if it does not exist (`O_CREAT`), with the permission
    /// bits [`open()`]'s `mode` gives.
    pub const CREATE: Self = Self(libc::O_CREAT);
    /// Truncate an existing regular file to zero length (`O_TRUNC`).
    pub const TRUNCATE: Self = Self(libc::O_TRUNC);
    /// Append every write to the end of the file (`O_APPEND`). On Linux the
    /// `offset` argument of [`write()`] and [`write_from()`] is then ignored, on
    /// both backends; on macOS `pwrite` writes at `offset` regardless.
    pub const APPEND: Self = Self(libc::O_APPEND);
}

impl std::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// File metadata returned by [`stat()`] and [`symlink_metadata()`].
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Size in bytes (`st_size`). For a symbolic link from
    /// [`symlink_metadata()`], the length of the path it holds.
    pub size: u64,
    /// `st_mode`: the file type bits (`S_IFMT`), the setuid, setgid and
    /// sticky bits, and the permission bits.
    pub mode: u32,
    /// Owner's user ID.
    pub uid: u32,
    /// Owner's group ID.
    pub gid: u32,
    /// Last access time, as the time since the Unix epoch. A time before 1970
    /// has negative seconds, which are cast to `u64` and wrap.
    pub atime: Duration,
    /// Last modification time, as the time since the Unix epoch. A time before
    /// 1970 has negative seconds, which are cast to `u64` and wrap.
    pub mtime: Duration,
    /// Last status change time, as the time since the Unix epoch. A time before
    /// 1970 has negative seconds, which are cast to `u64` and wrap.
    pub ctime: Duration,
    /// A regular file.
    pub is_file: bool,
    /// A directory.
    pub is_dir: bool,
    /// A symbolic link. Only [`symlink_metadata()`] reports one; [`stat()`]
    /// follows the link.
    pub is_symlink: bool,
}

impl Metadata {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_statx(stx: &libc::statx) -> Self {
        Metadata {
            size: stx.stx_size,
            mode: stx.stx_mode as u32,
            uid: stx.stx_uid,
            gid: stx.stx_gid,
            atime: Duration::new(stx.stx_atime.tv_sec as u64, stx.stx_atime.tv_nsec),
            mtime: Duration::new(stx.stx_mtime.tv_sec as u64, stx.stx_mtime.tv_nsec),
            ctime: Duration::new(stx.stx_ctime.tv_sec as u64, stx.stx_ctime.tv_nsec),
            is_file: (stx.stx_mode & libc::S_IFMT as u16) == libc::S_IFREG as u16,
            is_dir: (stx.stx_mode & libc::S_IFMT as u16) == libc::S_IFDIR as u16,
            is_symlink: (stx.stx_mode & libc::S_IFMT as u16) == libc::S_IFLNK as u16,
        }
    }

    /// Construct `Metadata` from a POSIX `libc::stat` result.
    ///
    /// Used by the mio backend's disk I/O pool for `fs_stat` on platforms
    /// that don't have `statx` (e.g., macOS).
    #[cfg(not(has_io_uring))]
    #[allow(clippy::unnecessary_cast)]
    pub(crate) fn from_stat(st: &libc::stat) -> Self {
        #[cfg(target_os = "macos")]
        let (atime, mtime, ctime) = (
            Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
            Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
            Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
        );
        #[cfg(target_os = "linux")]
        let (atime, mtime, ctime) = (
            Duration::new(st.st_atime as u64, st.st_atime_nsec as u32),
            Duration::new(st.st_mtime as u64, st.st_mtime_nsec as u32),
            Duration::new(st.st_ctime as u64, st.st_ctime_nsec as u32),
        );
        Metadata {
            size: st.st_size as u64,
            mode: st.st_mode as u32,
            uid: st.st_uid,
            gid: st.st_gid,
            atime,
            mtime,
            ctime,
            is_file: (st.st_mode & libc::S_IFMT) == libc::S_IFREG,
            is_dir: (st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
            is_symlink: (st.st_mode & libc::S_IFMT) == libc::S_IFLNK,
        }
    }
}

/// Configuration for async filesystem I/O.
#[derive(Clone, Debug)]
pub struct FsConfig {
    /// Maximum number of files that can be opened simultaneously.
    pub(crate) max_files: u16,
    /// Maximum I/O commands in flight across all files per worker.
    pub(crate) max_commands_in_flight: u16,
}

impl Default for FsConfig {
    fn default() -> Self {
        FsConfig {
            max_files: 64,
            max_commands_in_flight: 256,
        }
    }
}

impl FsConfig {
    /// Set the most files open at once on each worker. Defaults to 64.
    pub fn max_files(mut self, max_files: u16) -> Self {
        self.max_files = max_files;
        self
    }

    /// Set the most I/O commands in flight across all files, per worker. Defaults to 256.
    ///
    /// Every operation of this module except `close` counts from submission
    /// until its completion is processed. One submitted at the limit fails
    /// with `filesystem command slab exhausted`, on both backends.
    ///
    /// On io_uring each command slot has 16,384 operation keys. A future holds
    /// one from submission until it takes its result or is dropped on the
    /// worker that created it. A future that is neither polled to completion
    /// nor dropped keeps its key after its command completes, and one dropped
    /// on another thread keeps it for the life of that worker. The slot freed
    /// last is reused first, so in a serial workload 16,384 such futures make
    /// every later operation fail with `every disk-I/O key for this slab slot
    /// is held by a future`, until one of them takes its result or is dropped
    /// on that worker, while other slots are free.
    pub fn max_commands_in_flight(mut self, max_commands_in_flight: u16) -> Self {
        self.max_commands_in_flight = max_commands_in_flight;
        self
    }
}

/// Operation type for tracking what kind of fs I/O was submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FsOp {
    Open,
    Read,
    Write,
    Fsync,
    Close,
    Statx,
    Rename,
    Unlink,
    Mkdir,
}

/// Per-file state tracked by the driver.
pub(crate) struct FsFileState {
    /// Index in the io_uring fixed file table. Unused on mio, where the fd
    /// lives in the driver's `fs_fds`.
    pub fd_index: u32,
    /// Whether this slot is in use.
    pub active: bool,
    /// Generation counter for stale-handle detection.
    pub generation: u32,
    /// Number of read, write and fsync commands pushed to the SQ and not
    /// completed (io_uring).
    pub in_flight: u32,
    /// `close` was called while commands were in flight (io_uring): the
    /// handle is refused, and the last completion unregisters the file and
    /// releases the slot (#859).
    pub closing: bool,
}

impl FsFileState {
    pub fn new() -> Self {
        FsFileState {
            fd_index: u32::MAX,
            active: false,
            generation: 0,
            in_flight: 0,
            closing: false,
        }
    }
}

/// Tracks filesystem file slots with allocation/release.
pub(crate) struct FsFileTable {
    slots: Vec<FsFileState>,
    free_list: Vec<u16>,
}

impl FsFileTable {
    pub fn new(max_files: u16) -> Self {
        let mut slots = Vec::with_capacity(max_files as usize);
        let mut free_list = Vec::with_capacity(max_files as usize);
        for i in (0..max_files).rev() {
            slots.push(FsFileState::new());
            free_list.push(i);
        }
        FsFileTable { slots, free_list }
    }

    pub fn allocate(&mut self) -> Option<u16> {
        let index = self.free_list.pop()?;
        let slot = &mut self.slots[index as usize];
        slot.active = true;
        Some(index)
    }

    pub fn release(&mut self, index: u16) {
        let slot = &mut self.slots[index as usize];
        slot.active = false;
        slot.fd_index = u32::MAX;
        slot.in_flight = 0;
        slot.closing = false;
        slot.generation = slot.generation.wrapping_add(1);
        self.free_list.push(index);
    }

    pub fn get(&self, index: u16) -> Option<&FsFileState> {
        self.slots.get(index as usize).filter(|s| s.active)
    }

    pub fn get_mut(&mut self, index: u16) -> Option<&mut FsFileState> {
        self.slots.get_mut(index as usize).filter(|s| s.active)
    }
}

/// Per-command tracking entry in the command slab.
pub(crate) struct FsCmdEntry {
    file_index: u16,
    pub(crate) op: FsOp,
    in_use: bool,
    /// The SQE's user_data, recorded before the SQE is pushed.
    user_data: u64,
    /// Owned path for open/stat/unlink/mkdir (kept alive until CQE).
    pub path: Option<CString>,
    /// Second path for rename (kept alive until CQE).
    pub path2: Option<CString>,
    /// The statx buffer of a stat; the kernel writes it until the CQE through
    /// a pointer into this entry.
    #[cfg(target_os = "linux")]
    pub statx_buf: libc::statx,
}

/// Tracks in-flight filesystem commands for resource cleanup on completion.
pub(crate) struct FsCmdSlab {
    /// Filled in `new` and never resized: an in-flight stat holds a pointer
    /// into its entry.
    entries: Vec<FsCmdEntry>,
    free_list: Vec<u16>,
}

impl FsCmdSlab {
    pub fn new(capacity: u16) -> Self {
        let mut entries = Vec::with_capacity(capacity as usize);
        let mut free_list = Vec::with_capacity(capacity as usize);
        for i in (0..capacity).rev() {
            entries.push(FsCmdEntry {
                file_index: 0,
                op: FsOp::Read,
                in_use: false,
                user_data: 0,
                path: None,
                path2: None,
                #[cfg(target_os = "linux")]
                statx_buf: unsafe { std::mem::zeroed() },
            });
            free_list.push(i);
        }
        FsCmdSlab { entries, free_list }
    }

    /// Allocate a command slot. Returns the slab index.
    pub fn allocate(&mut self, file_index: u16, op: FsOp) -> Option<u16> {
        let idx = self.free_list.pop()?;
        let entry = &mut self.entries[idx as usize];
        entry.file_index = file_index;
        entry.op = op;
        entry.in_use = true;
        Some(idx)
    }

    /// Release a command slot. Returns (file_index, op).
    pub fn release(&mut self, idx: u16) -> (u16, FsOp) {
        let entry = &mut self.entries[idx as usize];
        let file_index = entry.file_index;
        let op = entry.op;
        entry.in_use = false;
        entry.path = None;
        entry.path2 = None;
        self.free_list.push(idx);
        (file_index, op)
    }

    pub fn in_use(&self, idx: u16) -> bool {
        self.entries.get(idx as usize).is_some_and(|e| e.in_use)
    }

    /// Whether any command holds a slot, so its operation has not completed.
    pub fn has_in_flight(&self) -> bool {
        self.free_list.len() < self.entries.len()
    }

    /// Record the user_data of slot `idx`'s SQE, which worker exit cancels.
    pub fn set_user_data(&mut self, idx: u16, user_data: u64) {
        self.entries[idx as usize].user_data = user_data;
    }

    /// The user_data of every command that holds a slot.
    pub fn in_flight_user_data(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .filter(|e| e.in_use)
            .map(|e| e.user_data)
    }

    /// Get a reference to an entry (must be in use).
    pub fn get(&self, idx: u16) -> Option<&FsCmdEntry> {
        self.entries.get(idx as usize).filter(|e| e.in_use)
    }

    /// Get a mutable reference to an entry (must be in use).
    pub fn get_mut(&mut self, idx: u16) -> Option<&mut FsCmdEntry> {
        self.entries.get_mut(idx as usize).filter(|e| e.in_use)
    }
}

// ── Helper: convert Path to CString ───────────────────────────────────

pub(crate) fn path_to_cstring(path: &std::path::Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::other("path contains null byte"))
}

// ── Async public API ──────────────────────────────────────────────────

/// Open a file.
///
/// On io_uring this can run on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring)
/// for when.
///
/// `flags` is one access mode with any other [`OpenFlags`] or'ed in;
/// `mode` is the permission bits (for example `0o644`) a file created with
/// [`OpenFlags::CREATE`] gets, less the process umask, and is ignored
/// otherwise.
///
/// Returns an [`OpenFuture`] that resolves to a [`File`] handle on success.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open(
    path: impl AsRef<std::path::Path>,
    flags: OpenFlags,
    mode: u32,
) -> io::Result<OpenFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let (file_index, generation, seq) = ctx.fs_open(path.as_ref(), flags, mode)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(OpenFuture {
            seq,
            file_index,
            generation,
            done: false,
            owner: crate::runtime::waker::current_worker(),
        })
    })
}

/// Create a file (shorthand for open with CREATE | WRITE | TRUNCATE, mode 0o644).
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn create(path: impl AsRef<std::path::Path>) -> io::Result<OpenFuture> {
    open(
        path,
        OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
        0o644,
    )
}

/// Future that resolves to a [`File`] handle when the open completes.
///
/// Dropping it before it resolves closes the file and frees its slot, on the
/// event loop's next iteration if the open has completed, otherwise when it
/// completes.
///
/// Polled from a task on another worker it stays pending until a task on the
/// owning worker drives it; polled outside the ringline executor it panics.
/// Dropped on a thread other than the owning worker, it leaves the file open
/// and its slot taken until the owning worker exits.
pub struct OpenFuture {
    seq: u32,
    file_index: u16,
    generation: u32,
    /// Set once `poll` has returned `Ready`: the caller owns the outcome.
    done: bool,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl Future for OpenFuture {
    type Output = io::Result<File>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<File>> {
        assert!(!self.done, "OpenFuture polled after completion");
        let poll = with_state(|_driver, executor| {
            // On another worker `seq` names that worker's entry, and the
            // result is not there.
            if self.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            match executor.poll_disk_io(self.seq, task_id) {
                Some((result, _)) if result < 0 => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some(_) => Poll::Ready(Ok(File::new(self.file_index, self.generation))),
                None => pending(cx),
            }
        });
        if poll.is_ready() {
            self.done = true;
        }
        poll
    }
}

impl Drop for OpenFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds `seq`. Dropped elsewhere
        // (the future is `Send`), the file and its slot stay open there (#575).
        if self.done || crate::runtime::waker::current_worker() != self.owner {
            return;
        }
        // Queued rather than handled here: a connection's task is dropped
        // outside any task poll, where the driver is not reachable. The event
        // loop releases the queue on its next iteration. A queue left at
        // worker exit is dropped with the driver's file table.
        let _ = ORPHANED_OPENS.try_with(|orphans| {
            orphans
                .borrow_mut()
                .push((self.seq, self.file_index, self.generation));
        });
    }
}

thread_local! {
    // Opens whose `OpenFuture` was dropped before it resolved, as `(disk I/O
    // key, file slot, generation)`. Nothing holds a handle to these files.
    static ORPHANED_OPENS: std::cell::RefCell<Vec<(u32, u16, u32)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    // Disk-I/O keys of operations whose future (`DiskIoFuture`,
    // `StatFuture`) was dropped outside the executor, before it resolved.
    static ORPHANED_KEYS: std::cell::RefCell<Vec<u32>> =
        const { std::cell::RefCell::new(Vec::new()) };
    // Buffers of reads and writes whose future was dropped outside the
    // executor, before it resolved.
    static ORPHANED_BUFFERS: std::cell::RefCell<OrphanedBuffers> =
        const { std::cell::RefCell::new(OrphanedBuffers(Vec::new())) };
}

/// Buffers of abandoned reads and writes, as `(disk I/O key, file slot,
/// buffer)`, waiting for the event loop to park or drop them.
struct OrphanedBuffers(Vec<(u32, u16, BytesMut)>);

impl Drop for OrphanedBuffers {
    fn drop(&mut self) {
        // Dropped when the worker thread exits. The operations may still be
        // using these buffers, so leak them, as the executor does with parked
        // buffers at exit.
        for (_, _, buf) in self.0.drain(..) {
            std::mem::forget(buf);
        }
    }
}

/// Release what futures dropped outside the executor queued. First the
/// timer slots, spawns, pidfd waits, connects, and blocking and resolve
/// entries queued by [`crate::runtime::defer_release`]; then what dropped fs
/// futures queued:
/// drop abandoned operations' results, or stop tracking their keys so the
/// results are discarded on arrival; close the files of abandoned opens and
/// free their slots; and park or drop the buffers of abandoned reads and
/// writes. Called by the event loop at the start of every task-poll pass,
/// after the first pass, and before the worker waits for I/O.
///
/// An open that has completed is closed now. One still in flight is marked
/// abandoned (`Executor::abandon_disk_io_open`), and its completion handler
/// closes it. A buffer whose operation has completed is dropped now; one still
/// in flight is parked (`DiskIoEntry::Parked`) until the completion arrives.
pub(crate) fn release_orphans(
    driver: &mut crate::backend::Driver,
    executor: &mut crate::runtime::Executor,
) {
    // Timer slots, spawns, pidfd waits, connects, and blocking and resolve
    // entries of futures dropped outside the executor (#575, #582).
    crate::runtime::release_orphans(driver, executor);

    let keys = ORPHANED_KEYS.with(|orphans| std::mem::take(&mut *orphans.borrow_mut()));
    for seq in keys {
        executor.abandon_disk_io(seq);
    }

    let buffers = ORPHANED_BUFFERS.with(|orphans| {
        let mut orphans = orphans.borrow_mut();
        if orphans.0.is_empty() {
            Vec::new()
        } else {
            std::mem::take(&mut orphans.0)
        }
    });
    for (seq, file_index, buf) in buffers {
        park_buffer(driver, executor, seq, file_index, buf);
    }

    let orphans = ORPHANED_OPENS.with(|orphans| {
        let mut orphans = orphans.borrow_mut();
        if orphans.is_empty() {
            Vec::new()
        } else {
            std::mem::take(&mut *orphans)
        }
    });
    for (seq, index, generation) in orphans {
        match executor.take_disk_io_result(seq) {
            Some(result) if result >= 0 => {
                let _ = driver.make_ctx().fs_close(File::new(index, generation));
            }
            // The open failed, and its slot is already free.
            Some(_) => {}
            None => executor.abandon_disk_io_open(seq),
        }
    }
}

/// Read from a file at the given offset.
///
/// On io_uring this can run on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring)
/// for when.
///
/// Returns a [`DiskIoFuture`] whose output is the number of bytes read.
///
/// # Safety
///
/// `buf` must point to writable memory of at least `len` bytes that remains
/// valid until the operation completes. The operation keeps using the memory
/// after the future is dropped, and a dropped future gives no way to learn
/// when the operation completes, so after a drop the memory must not be freed
/// or reused: leak it, or use an owned-buffer variant where one exists (#825).
/// Here that is [`read_into`].
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn read(file: File, offset: u64, buf: *mut u8, len: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: the outer `read()` is already unsafe, and the caller
        // guarantees the buffer invariants.
        #[allow(unused_unsafe)]
        let seq = unsafe { ctx.fs_read(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Write to a file at the given offset.
///
/// On io_uring this can run on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring)
/// for when.
///
/// Returns a [`DiskIoFuture`] whose output is the number of bytes written.
///
/// # Safety
///
/// `buf` must point to readable memory of at least `len` bytes that remains
/// valid until the operation completes. The operation keeps using the memory
/// after the future is dropped, and a dropped future gives no way to learn
/// when the operation completes, so after a drop the memory must not be freed
/// or reused: leak it, or use an owned-buffer variant where one exists (#825).
/// Here that is [`write_from`].
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn write(file: File, offset: u64, buf: *const u8, len: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: the outer `write()` is already unsafe, and the caller
        // guarantees the buffer invariants.
        #[allow(unused_unsafe)]
        let seq = unsafe { ctx.fs_write(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

// ── Safe owned-buffer API ─────────────────────────────────────────────

/// Read from a file at the given offset into a [`BytesMut`].
///
/// On io_uring this can run on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring)
/// for when.
///
/// The kernel writes into `buf`'s spare capacity (`buf.capacity() - buf.len()`).
/// On success, the returned future yields `(Ok(n), buf)` with `buf.len()` extended
/// by `n` bytes. On failure, the buffer is returned unchanged alongside the error.
///
/// If the future is dropped before the I/O completes, the buffer is kept
/// until the operation completes and then freed. On io_uring a best-effort
/// `ASYNC_CANCEL` is also submitted. If the worker exits first, or the future
/// is dropped on a thread other than the worker that created it, the buffer
/// is leaked.
///
/// Returns [`io::ErrorKind::InvalidInput`] if `buf` has no spare capacity
/// or if spare capacity exceeds `u32::MAX`. A spare capacity above
/// `i32::MAX` is refused by macOS with `EINVAL` and read short by Linux,
/// which reads at most `0x7ffff000` bytes per call.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn read_into(file: File, offset: u64, mut buf: BytesMut) -> io::Result<ReadFuture> {
    let initial_len = buf.len();
    let cap = buf.capacity();
    if initial_len >= cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BytesMut has no spare capacity",
        ));
    }
    let spare = cap - initial_len;
    if spare > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "spare capacity exceeds u32::MAX",
        ));
    }
    // Safety: `as_mut_ptr().add(initial_len)` points into the spare region of
    // the BytesMut's backing allocation. The future owns `buf` (or parks it on
    // drop), so the allocation outlives the kernel's use of the pointer.
    let ptr = unsafe { buf.as_mut_ptr().add(initial_len) };
    let len = spare as u32;
    let file_index = file.index;
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: caller-side invariant is upheld by ReadFuture's ownership +
        // parking on drop (see ReadFuture::Drop).
        let seq = unsafe { ctx.fs_read(file, offset, ptr, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(ReadFuture {
            seq,
            file_index,
            initial_len,
            buf: Some(buf),
            owner: crate::runtime::waker::current_worker(),
        })
    })
}

/// Write to a file at the given offset from a [`BytesMut`].
///
/// On io_uring this can run on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring)
/// for when.
///
/// The kernel reads `buf.len()` bytes starting at `buf.as_ptr()`. The future
/// yields `(io::Result<usize>, buf)` — the buffer is returned unchanged.
///
/// If the future is dropped before the I/O completes, the buffer is kept
/// until the operation completes and then freed. On io_uring a best-effort
/// `ASYNC_CANCEL` is also submitted. If the worker exits first, or the future
/// is dropped on a thread other than the worker that created it, the buffer
/// is leaked.
///
/// Returns [`io::ErrorKind::InvalidInput`] if `buf.len() > u32::MAX`. A
/// length above `i32::MAX` is refused by macOS with `EINVAL` and written
/// short by Linux, which writes at most `0x7ffff000` bytes per call.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn write_from(file: File, offset: u64, buf: BytesMut) -> io::Result<WriteFuture> {
    let len = buf.len();
    if len > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "buffer len exceeds u32::MAX",
        ));
    }
    let ptr = buf.as_ptr();
    let len_u32 = len as u32;
    let file_index = file.index;
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        // Safety: caller-side invariant is upheld by WriteFuture's ownership +
        // parking on drop (see WriteFuture::Drop).
        let seq = unsafe { ctx.fs_write(file, offset, ptr, len_u32)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(WriteFuture {
            seq,
            file_index,
            buf: Some(buf),
            owner: crate::runtime::waker::current_worker(),
        })
    })
}

/// Future returned by [`read_into()`].
///
/// Resolves to `(io::Result<usize>, BytesMut)`. On success `buf.len()` is
/// extended by the number of bytes read.
///
/// Polled from a task on another worker it stays pending until a task on the
/// owning worker drives it; polled outside the ringline executor it panics.
/// Dropped on a thread other than the owning worker, it leaks the buffer and
/// leaves its result slot on the owning worker taken until that worker exits.
pub struct ReadFuture {
    seq: u32,
    file_index: u16,
    initial_len: usize,
    buf: Option<BytesMut>,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl Future for ReadFuture {
    type Output = (io::Result<usize>, BytesMut);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        assert!(me.buf.is_some(), "ReadFuture polled after completion");
        with_state(|_driver, executor| {
            // On another worker `seq` names that worker's entry, and the
            // result is not there.
            if me.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            match executor.poll_disk_io(me.seq, task_id) {
                Some((result, _)) if result < 0 => {
                    let buf = me.buf.take().expect("ReadFuture polled after completion");
                    Poll::Ready((Err(io::Error::from_raw_os_error(-result)), buf))
                }
                Some((result, _)) => {
                    let mut buf = me.buf.take().expect("ReadFuture polled after completion");
                    let n = result as usize;
                    let max_n = buf.capacity() - me.initial_len;
                    let n = n.min(max_n);
                    // Safety: kernel wrote `n` bytes into the spare region
                    // [initial_len, initial_len + n), initializing them.
                    unsafe { buf.set_len(me.initial_len + n) };
                    Poll::Ready((Ok(n), buf))
                }
                None => pending(cx),
            }
        })
    }
}

impl Drop for ReadFuture {
    fn drop(&mut self) {
        let Some(buf) = self.buf.take() else { return };
        drop_buffer(self.owner, self.seq, self.file_index, buf);
    }
}

/// Future returned by [`write_from()`].
///
/// Resolves to `(io::Result<usize>, BytesMut)`. The buffer is returned
/// unchanged regardless of success or failure.
///
/// Polled from a task on another worker it stays pending until a task on the
/// owning worker drives it; polled outside the ringline executor it panics.
/// Dropped on a thread other than the owning worker, it leaks the buffer and
/// leaves its result slot on the owning worker taken until that worker exits.
pub struct WriteFuture {
    seq: u32,
    file_index: u16,
    buf: Option<BytesMut>,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl Future for WriteFuture {
    type Output = (io::Result<usize>, BytesMut);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        assert!(me.buf.is_some(), "WriteFuture polled after completion");
        with_state(|_driver, executor| {
            // On another worker `seq` names that worker's entry, and the
            // result is not there.
            if me.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            match executor.poll_disk_io(me.seq, task_id) {
                Some((result, _)) if result < 0 => {
                    let buf = me.buf.take().expect("WriteFuture polled after completion");
                    Poll::Ready((Err(io::Error::from_raw_os_error(-result)), buf))
                }
                Some((result, _)) => {
                    let buf = me.buf.take().expect("WriteFuture polled after completion");
                    Poll::Ready((Ok(result as usize), buf))
                }
                None => pending(cx),
            }
        })
    }
}

impl Drop for WriteFuture {
    fn drop(&mut self) {
        let Some(buf) = self.buf.take() else { return };
        drop_buffer(self.owner, self.seq, self.file_index, buf);
    }
}

/// Drop-side handler shared by [`ReadFuture`] and [`WriteFuture`]. Only the
/// owning worker's executor tracks `seq`; dropped on another thread (the
/// futures are `Send`), the operation may still be using `buf` and no
/// executor here can park it, so it is leaked (#575).
fn drop_buffer(owner: u32, seq: u32, file_index: u16, buf: BytesMut) {
    if crate::runtime::waker::current_worker() == owner {
        park_or_drop(seq, file_index, buf);
    } else {
        std::mem::forget(buf);
    }
}

/// Called from [`ReadFuture`] and [`WriteFuture`] drops. Inside a task poll
/// it calls [`park_buffer`]. Outside one (a connection's task dropped at
/// teardown) it queues the buffer on `ORPHANED_BUFFERS`, which
/// [`release_orphans`] passes to `park_buffer`.
fn park_or_drop(seq: u32, file_index: u16, buf: BytesMut) {
    let Some(mut non_null) = CURRENT_DRIVER.with(|c| c.get()) else {
        // Outside the executor: a connection's task is dropped outside any
        // task poll. Queue the buffer; the event loop releases it after its
        // next task-poll pass.
        // If the queue is gone (the thread is exiting), leak the buffer
        // rather than free memory the operation may still write into.
        let mut pending = Some(buf);
        let _ = ORPHANED_BUFFERS.try_with(|orphans| {
            if let Some(buf) = pending.take() {
                orphans.borrow_mut().0.push((seq, file_index, buf));
            }
        });
        if let Some(buf) = pending {
            std::mem::forget(buf);
        }
        return;
    };
    let state = unsafe { non_null.as_mut() };
    let driver = unsafe { &mut *state.driver.as_mut() };
    let executor = unsafe { &mut *state.executor.as_mut() };
    park_buffer(driver, executor, seq, file_index, buf);
}

/// Drop `buf` if its operation has completed (its result has arrived),
/// otherwise park it under `seq`; `wake_disk_io` frees it when the
/// operation completes.
///
/// On io_uring, also submit a best-effort `ASYNC_CANCEL` to speed up the
/// completion, which then arrives with `-ECANCELED` or the natural result.
/// On mio the disk-I/O pool thread runs the operation, which may not have
/// started yet, and there is nothing to cancel.
#[cfg_attr(not(has_io_uring), allow(unused_variables))]
fn park_buffer(
    driver: &mut crate::backend::Driver,
    executor: &mut crate::runtime::Executor,
    seq: u32,
    file_index: u16,
    buf: BytesMut,
) {
    if executor.take_disk_io_result(seq).is_some() {
        // The operation has completed and released the buffer.
        drop(buf);
        return;
    }
    executor.park_disk_io(seq, buf);
    #[cfg(has_io_uring)]
    {
        let target = crate::completion::UserData::encode(
            crate::completion::OpTag::Fs,
            file_index as u32,
            seq,
        );
        // The cancel CQE handler is a no-op (event_loop.rs), so the
        // conn_index encoded into the cancel SQE's own user_data is
        // unused — pass 0 to satisfy `UserData::encode`'s 24-bit guard.
        let _ = driver.ring.submit_async_cancel(target.raw(), 0);
    }
}

/// Fsync a file: `fsync(2)`, which persists the writes to it whose futures
/// have resolved. A write whose future has not resolved may not be covered;
/// await it first. On macOS `fsync(2)` does not flush the drive's own cache.
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn fsync(file: File) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_fsync(file)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Close a file handle.
///
/// Synchronous: on success the handle is invalid when this returns. A read,
/// write or fsync already issued on it completes against the file. On
/// io_uring the file leaves the ring's fixed-file table and its slot is freed
/// when this returns or, if such operations are in flight, when the last of
/// them completes. On mio the slot is free when this returns, and the fd
/// closes once the operations already queued on it have finished.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn close(file: File) -> io::Result<()> {
    with_state(|driver, _| {
        let mut ctx = driver.make_ctx();
        ctx.fs_close(file)
    })
}

/// Get file metadata (stat) for a path. A symbolic link is followed, so the
/// metadata is the target's and [`Metadata::is_symlink`] is false; see
/// [`symlink_metadata`] for the link's own.
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// Returns a [`StatFuture`] that resolves to [`Metadata`] on success.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn stat(path: impl AsRef<std::path::Path>) -> io::Result<StatFuture> {
    stat_with(path.as_ref(), false)
}

/// Get file metadata for a path without following a final symbolic link
/// (`lstat`; on io_uring a statx with `AT_SYMLINK_NOFOLLOW`). If the path
/// names a link, the metadata is the link's own and [`Metadata::is_symlink`]
/// is true; a trailing `/` makes the link be followed, as it does for `lstat`.
/// Any other path gives what [`stat`] gives.
///
/// Runs where [`stat`] runs, with the same effect on connection closes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn symlink_metadata(path: impl AsRef<std::path::Path>) -> io::Result<StatFuture> {
    stat_with(path.as_ref(), true)
}

fn stat_with(path: &std::path::Path, nofollow: bool) -> io::Result<StatFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_stat(path, nofollow)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(StatFuture {
            seq,
            done: false,
            owner: crate::runtime::waker::current_worker(),
        })
    })
}

/// Future that resolves to the file's [`Metadata`]. Dropping it before it
/// resolves discards the result.
///
/// Polled from a task on another worker it stays pending until a task on the
/// owning worker drives it; polled outside the ringline executor it panics.
/// Dropped on a thread other than the owning worker, it leaves its result slot
/// on the owning worker taken until that worker exits.
// On io_uring the statx buffer is the command slab entry's, and on
// completion the handler converts it to `Metadata` and delivers it with the
// result. On mio the disk-I/O pool returns the `Metadata`.
pub struct StatFuture {
    seq: u32,
    /// Set once `poll` has returned `Ready`: the result has been taken.
    done: bool,
    /// The worker whose executor holds `seq`.
    owner: u32,
}

impl Future for StatFuture {
    type Output = io::Result<Metadata>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<Metadata>> {
        assert!(!self.done, "StatFuture polled after completion");
        let poll = with_state(|_driver, executor| {
            // On another worker `seq` names that worker's entry, and the
            // result is not there.
            if self.owner != crate::runtime::waker::current_worker() {
                return pending(cx);
            }
            let task_id = CURRENT_TASK_ID.with(|c| c.get());
            match executor.poll_disk_io(self.seq, task_id) {
                Some((result, _)) if result < 0 => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some((_, Some(metadata))) => Poll::Ready(Ok(metadata)),
                // Unreachable: a successful stat's completion carries its
                // metadata.
                Some((_, None)) => Poll::Ready(Err(io::Error::other("stat result missing"))),
                None => pending(cx),
            }
        });
        if poll.is_ready() {
            self.done = true;
        }
        poll
    }
}

impl Drop for StatFuture {
    fn drop(&mut self) {
        // Only the owning worker's executor holds the key. Dropped elsewhere
        // (the future is `Send`), the key stays held there (#575).
        if !self.done && crate::runtime::waker::current_worker() == self.owner {
            abandon_disk_io_key(self.seq);
        }
    }
}

/// Forget a disk-I/O operation whose future was dropped before it resolved,
/// so its key and result are not held for the life of the worker (#574).
/// Inside a task poll this calls [`Executor::abandon_disk_io`]; outside one
/// (a connection's task dropped at teardown) it queues the key for
/// [`release_orphans`].
///
/// [`Executor::abandon_disk_io`]: crate::runtime::Executor::abandon_disk_io
pub(crate) fn abandon_disk_io_key(seq: u32) {
    match CURRENT_DRIVER.with(|c| c.get()) {
        Some(mut non_null) => {
            let state = unsafe { non_null.as_mut() };
            let executor = unsafe { &mut *state.executor.as_mut() };
            executor.abandon_disk_io(seq);
        }
        None => {
            let _ = ORPHANED_KEYS.try_with(|orphans| orphans.borrow_mut().push(seq));
        }
    }
}

/// Rename a file.
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn rename(
    from: impl AsRef<std::path::Path>,
    to: impl AsRef<std::path::Path>,
) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_rename(from.as_ref(), to.as_ref())?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Remove a file (unlink).
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn remove(path: impl AsRef<std::path::Path>) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_unlink(path.as_ref())?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

/// Create a directory.
///
/// On io_uring this always runs on the worker's io-wq pool; before Linux 6.13
/// that can delay the worker's connection closes. See
/// [the module docs](self#blocking-file-io-and-connection-closes-io_uring).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn mkdir(path: impl AsRef<std::path::Path>, mode: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_mkdir(path.as_ref(), mode)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.wait_disk_io(seq, task_id);
        Ok(DiskIoFuture::new(seq))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_each_field_and_default_keeps_the_rest() {
        let d = FsConfig::default();
        assert_eq!((d.max_files, d.max_commands_in_flight), (64, 256));
        let c = FsConfig::default().max_files(3).max_commands_in_flight(7);
        assert_eq!((c.max_files, c.max_commands_in_flight), (3, 7));
    }

    #[test]
    fn file_table_alloc_release() {
        let mut table = FsFileTable::new(4);
        let a = table.allocate().unwrap();
        let b = table.allocate().unwrap();
        assert_ne!(a, b);
        assert!(table.get(a).is_some());

        table.release(a);
        assert!(table.get(a).is_none());

        // Re-allocate reuses the slot.
        let c = table.allocate().unwrap();
        assert_eq!(c, a);
        // Generation incremented.
        assert_eq!(table.get(c).unwrap().generation, 1);
    }

    /// A slot reused 65,536 times does not repeat its first generation, so a
    /// handle kept from the first open stays stale (#862).
    #[test]
    fn generation_does_not_repeat_after_65536_releases() {
        let mut table = FsFileTable::new(1);
        let index = table.allocate().unwrap();
        let first = table.get(index).unwrap().generation;
        for _ in 0..65_536 {
            table.release(index);
            assert_eq!(table.allocate(), Some(index));
        }
        assert_ne!(table.get(index).unwrap().generation, first);
    }

    #[test]
    fn cmd_slab_alloc_release() {
        let mut slab = FsCmdSlab::new(8);
        let a = slab.allocate(0, FsOp::Read).unwrap();
        let b = slab.allocate(1, FsOp::Write).unwrap();
        assert!(slab.in_use(a));
        assert!(slab.in_use(b));

        let (file, op) = slab.release(a);
        assert_eq!(file, 0);
        assert_eq!(op, FsOp::Read);
        assert!(!slab.in_use(a));

        let (file, op) = slab.release(b);
        assert_eq!(file, 1);
        assert_eq!(op, FsOp::Write);
    }

    #[test]
    fn cmd_slab_clears_owned_data_on_release() {
        let mut slab = FsCmdSlab::new(4);
        let a = slab.allocate(0, FsOp::Statx).unwrap();
        {
            let entry = slab.get_mut(a).unwrap();
            entry.path = Some(CString::new("/tmp/test").unwrap());
        }
        slab.release(a);
        // After release, the entry is not in use and its path is None.
        // We can verify by re-allocating and checking.
        let b = slab.allocate(0, FsOp::Read).unwrap();
        assert_eq!(b, a);
        let entry = slab.get(b).unwrap();
        assert!(entry.path.is_none());
    }

    #[test]
    fn file_table_exhaustion() {
        let mut table = FsFileTable::new(2);
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_none());
    }
}
