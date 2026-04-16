//! Async filesystem I/O via io_uring.
//!
//! Provides buffered file read/write and metadata operations (stat, rename,
//! unlink, mkdir) using native io_uring opcodes — no blocking syscalls.

use std::ffi::CString;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::runtime::CURRENT_TASK_ID;
use crate::runtime::io::{CURRENT_DRIVER, DiskIoFuture, with_state};

/// Opaque handle to an opened file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
    pub(crate) index: u16,
    pub(crate) generation: u16,
}

impl File {
    /// Returns the file slot index.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// Flags for [`open()`].
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags(pub(crate) i32);

impl OpenFlags {
    pub const READ: Self = Self(libc::O_RDONLY);
    pub const WRITE: Self = Self(libc::O_WRONLY);
    pub const READ_WRITE: Self = Self(libc::O_RDWR);
    pub const CREATE: Self = Self(libc::O_CREAT);
    pub const TRUNCATE: Self = Self(libc::O_TRUNC);
    pub const APPEND: Self = Self(libc::O_APPEND);
}

impl std::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// File metadata returned by [`stat()`].
#[derive(Debug, Clone)]
pub struct Metadata {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: Duration,
    pub mtime: Duration,
    pub ctime: Duration,
    pub is_file: bool,
    pub is_dir: bool,
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
}

/// Configuration for async filesystem I/O.
#[derive(Clone, Debug)]
pub struct FsConfig {
    /// Maximum number of files that can be opened simultaneously.
    pub max_files: u16,
    /// Maximum I/O commands in flight across all files per worker.
    pub max_commands_in_flight: u16,
}

impl Default for FsConfig {
    fn default() -> Self {
        FsConfig {
            max_files: 64,
            max_commands_in_flight: 256,
        }
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
    /// Index in the io_uring fixed file table.
    pub fd_index: u32,
    /// Whether this slot is in use.
    pub active: bool,
    /// Generation counter for stale-handle detection.
    pub generation: u16,
    /// Number of commands currently in flight.
    pub in_flight: u32,
}

impl FsFileState {
    pub fn new() -> Self {
        FsFileState {
            fd_index: u32::MAX,
            active: false,
            generation: 0,
            in_flight: 0,
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
    /// Owned path for open/stat/unlink/mkdir (kept alive until CQE).
    pub path: Option<CString>,
    /// Second path for rename (kept alive until CQE).
    pub path2: Option<CString>,
    /// Heap-allocated statx buffer (kept alive until CQE).
    #[cfg(target_os = "linux")]
    pub statx_buf: Option<Box<libc::statx>>,
}

/// Tracks in-flight filesystem commands for resource cleanup on completion.
pub(crate) struct FsCmdSlab {
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
                path: None,
                path2: None,
                #[cfg(target_os = "linux")]
                statx_buf: None,
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
        #[cfg(target_os = "linux")]
        {
            entry.statx_buf = None;
        }
        self.free_list.push(idx);
        (file_index, op)
    }

    pub fn in_use(&self, idx: u16) -> bool {
        self.entries.get(idx as usize).is_some_and(|e| e.in_use)
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

/// Open a file asynchronously via io_uring.
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
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(OpenFuture {
            seq,
            file_index,
            generation,
        })
    })
}

/// Create a file (shorthand for open with CREATE | WRITE | TRUNCATE, mode 0o644).
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
pub struct OpenFuture {
    seq: u32,
    file_index: u16,
    generation: u16,
}

impl Future for OpenFuture {
    type Output = io::Result<File>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<File>> {
        with_state(
            |_driver, executor| match executor.disk_io_results.remove(&self.seq) {
                Some(result) if result < 0 => {
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some(_) => Poll::Ready(Ok(File {
                    index: self.file_index,
                    generation: self.generation,
                })),
                None => {
                    let task_id = CURRENT_TASK_ID.with(|c| c.get());
                    executor.disk_io_waiters.insert(self.seq, task_id);
                    Poll::Pending
                }
            },
        )
    }
}

impl Drop for OpenFuture {
    fn drop(&mut self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let executor = unsafe { &mut *state.executor };
        executor.disk_io_waiters.remove(&self.seq);
    }
}

/// Read from a file at the given offset.
///
/// Returns a [`DiskIoFuture`] whose output is the number of bytes read.
///
/// # Safety
///
/// `buf` must point to writable memory of at least `len` bytes that remains
/// valid until the returned future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn read(file: File, offset: u64, buf: *mut u8, len: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = unsafe { ctx.fs_read(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

/// Write to a file at the given offset.
///
/// Returns a [`DiskIoFuture`] whose output is the number of bytes written.
///
/// # Safety
///
/// `buf` must point to readable memory of at least `len` bytes that remains
/// valid until the returned future completes.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub unsafe fn write(file: File, offset: u64, buf: *const u8, len: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = unsafe { ctx.fs_write(file, offset, buf, len)? };
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

/// Fsync a file, flushing all data and metadata to disk.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn fsync(file: File) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_fsync(file)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

/// Close a file handle.
///
/// This is synchronous — it deregisters the fd from the fixed file table
/// and releases the file slot. No SQE is needed.
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

/// Get file metadata (stat) for a path.
///
/// Returns a [`StatFuture`] that resolves to [`Metadata`] on success.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn stat(path: impl AsRef<std::path::Path>) -> io::Result<StatFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_stat(path.as_ref())?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(StatFuture { seq })
    })
}

/// Future that resolves to [`Metadata`] when the stat completes.
///
/// The statx buffer is owned by the command slab entry. On CQE completion,
/// the handler converts it to [`Metadata`] and stores it in
/// `Executor::fs_stat_results` before releasing the slab entry.
pub struct StatFuture {
    seq: u32,
}

impl Future for StatFuture {
    type Output = io::Result<Metadata>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<Metadata>> {
        with_state(|_driver, executor| {
            // First check if there's a normal error result (negative).
            match executor.disk_io_results.remove(&self.seq) {
                Some(result) if result < 0 => {
                    // Also remove any stat result that might have been stored.
                    executor.fs_stat_results.remove(&self.seq);
                    Poll::Ready(Err(io::Error::from_raw_os_error(-result)))
                }
                Some(_) => {
                    // Success — read the Metadata from the stat results map.
                    match executor.fs_stat_results.remove(&self.seq) {
                        Some(metadata) => Poll::Ready(Ok(metadata)),
                        None => {
                            // Should not happen — handle_fs stores it before waking.
                            Poll::Ready(Err(io::Error::other("stat result missing")))
                        }
                    }
                }
                None => {
                    let task_id = CURRENT_TASK_ID.with(|c| c.get());
                    executor.disk_io_waiters.insert(self.seq, task_id);
                    Poll::Pending
                }
            }
        })
    }
}

impl Drop for StatFuture {
    fn drop(&mut self) {
        let ptr = CURRENT_DRIVER.with(|c| c.get());
        if ptr.is_null() {
            return;
        }
        let state = unsafe { &mut *ptr };
        let executor = unsafe { &mut *state.executor };
        executor.disk_io_waiters.remove(&self.seq);
        executor.fs_stat_results.remove(&self.seq);
    }
}

/// Rename a file.
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
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

/// Remove a file (unlink).
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn remove(path: impl AsRef<std::path::Path>) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_unlink(path.as_ref())?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

/// Create a directory.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn mkdir(path: impl AsRef<std::path::Path>, mode: u32) -> io::Result<DiskIoFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let seq = ctx.fs_mkdir(path.as_ref(), mode)?;
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        executor.disk_io_waiters.insert(seq, task_id);
        Ok(DiskIoFuture { seq })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            #[cfg(target_os = "linux")]
            {
                entry.statx_buf = Some(Box::new(unsafe { std::mem::zeroed() }));
            }
        }
        slab.release(a);
        // After release, the entry is not in use but the path/statx_buf should be None.
        // We can verify by re-allocating and checking.
        let b = slab.allocate(0, FsOp::Read).unwrap();
        assert_eq!(b, a);
        let entry = slab.get(b).unwrap();
        assert!(entry.path.is_none());
        #[cfg(target_os = "linux")]
        assert!(entry.statx_buf.is_none());
    }

    #[test]
    fn file_table_exhaustion() {
        let mut table = FsFileTable::new(2);
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_none());
    }
}
