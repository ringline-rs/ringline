//! Direct I/O: reads, writes and fsync on a file or block device opened
//! with `O_DIRECT`, which bypasses the page cache.
//!
//! On io_uring the operations are `IORING_OP_READ`, `IORING_OP_WRITE` and
//! `IORING_OP_FSYNC` on a fixed file. On mio they are `pread`, `pwrite` and
//! `fsync` on the disk-I/O pool, with `F_NOCACHE` in place of `O_DIRECT` on
//! macOS. On io_uring a call that finds the ring's submission queue full
//! submits the queue inline before pushing, and returns the error if that
//! submit fails, leaving nothing in flight (see the `fs` module docs).
//!
//! # Alignment requirements
//!
//! With `O_DIRECT` (Linux) the buffer address, the length and the file
//! offset of a read or write must each be a multiple of the device's logical
//! block size (typically 512 or 4096 bytes), or the kernel returns `EINVAL`.
//! `F_NOCACHE` on macOS has no such requirement.

use std::marker::PhantomData;

/// The operation a command slab entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectIoOp {
    Read,
    Write,
    Fsync,
}

/// Options for opening a direct I/O file, passed to
/// [`crate::open_direct_io_file_with`].
///
/// The default opens the file as
/// [`crate::open_direct_io_file`] does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectIoOpenOptions {
    dsync: bool,
}

impl DirectIoOpenOptions {
    /// Options that open the file as [`crate::open_direct_io_file`]
    /// does.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open with `O_DSYNC`, so a write completes only once the kernel has sent
    /// its data to the device (on Linux, to stable storage).
    ///
    /// On a Linux block device, io_uring sends each write with the FUA bit
    /// set; when the device does not support FUA, the kernel follows the write
    /// with a cache flush. The mio backend writes with `pwrite(2)`, and for
    /// that call the kernel also flushes the device's cache after every write.
    /// The kernel sends no FUA and no flush when the device reports a
    /// write-through cache (`/sys/block/<dev>/queue/write_cache`). On a file in
    /// a filesystem, each write also commits the metadata needed to read it
    /// back. On macOS the write reaches the drive but the drive's own cache is
    /// not flushed, as with `fsync(2)`.
    #[must_use]
    pub fn dsync(mut self, dsync: bool) -> Self {
        self.dsync = dsync;
        self
    }

    /// The `open(2)` flags these options add to `O_RDWR`, `O_CLOEXEC` and the
    /// backend's direct I/O flag.
    pub(crate) fn extra_flags(&self) -> libc::c_int {
        if self.dsync { libc::O_DSYNC } else { 0 }
    }
}

/// Opaque handle to an opened direct I/O file.
///
/// Returned by [`crate::open_direct_io_file`] and used to identify the
/// file in subsequent read/write/fsync/close calls. The handle includes a
/// generation counter for stale-handle detection.
///
/// The handle names a slot in the table of the worker that opened it, so it is
/// not `Send`: use it on that worker. Another worker's table can hold a
/// different file in the same slot. A handler is created on its worker's
/// thread and stays there, so it can keep a handle in a field.
///
/// ```
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<ringline::direct_io::DirectIoFile>();
/// ```
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::direct_io::DirectIoFile>();
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DirectIoFile {
    pub(crate) index: u16,
    pub(crate) generation: u32,
    /// Makes the handle `!Send`.
    _not_send: PhantomData<*const ()>,
}

impl std::fmt::Debug for DirectIoFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectIoFile")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .finish()
    }
}

impl DirectIoFile {
    pub(crate) fn new(index: u16, generation: u32) -> Self {
        DirectIoFile {
            index,
            generation,
            _not_send: PhantomData,
        }
    }

    /// Returns the file slot index. Useful for indexing into per-file arrays.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// Per-file state tracked by the driver.
pub(crate) struct DirectIoFileState {
    /// Index in the io_uring fixed file table. Unused on mio, where the fd
    /// lives in the driver's `direct_io_fds`.
    pub fd_index: u32,
    /// Whether this slot is in use.
    pub active: bool,
    /// Generation counter for stale-handle detection.
    pub generation: u32,
    /// Number of commands currently in flight.
    pub in_flight: u32,
    /// Closed with commands in flight: the last completion unregisters the
    /// file, because a queued SQE resolves its fixed-file index at submission.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub closing: bool,
}

impl DirectIoFileState {
    pub fn new() -> Self {
        DirectIoFileState {
            fd_index: u32::MAX,
            active: false,
            generation: 0,
            in_flight: 0,
            closing: false,
        }
    }
}

/// Tracks direct I/O file slots with allocation/release.
pub(crate) struct DirectIoFileTable {
    slots: Vec<DirectIoFileState>,
    free_list: Vec<u16>,
}

impl DirectIoFileTable {
    pub fn new(max_files: u16) -> Self {
        let mut slots = Vec::with_capacity(max_files as usize);
        let mut free_list = Vec::with_capacity(max_files as usize);
        for i in (0..max_files).rev() {
            slots.push(DirectIoFileState::new());
            free_list.push(i);
        }
        DirectIoFileTable { slots, free_list }
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

    pub fn get(&self, index: u16) -> Option<&DirectIoFileState> {
        self.slots.get(index as usize).filter(|s| s.active)
    }

    pub fn get_mut(&mut self, index: u16) -> Option<&mut DirectIoFileState> {
        self.slots.get_mut(index as usize).filter(|s| s.active)
    }
}

/// Per-command tracking entry in the command slab.
struct DirectIoCmdEntry {
    /// File slot index.
    file_index: u16,
    /// Operation type (read, write, fsync).
    op: DirectIoOp,
    /// Whether this slot is in use.
    in_use: bool,
    /// The SQE's user_data, recorded before the SQE is pushed.
    user_data: u64,
}

/// Tracks in-flight direct I/O commands for resource cleanup on completion.
pub(crate) struct DirectIoCmdSlab {
    entries: Vec<DirectIoCmdEntry>,
    free_list: Vec<u16>,
}

impl DirectIoCmdSlab {
    pub fn new(capacity: u16) -> Self {
        let mut entries = Vec::with_capacity(capacity as usize);
        let mut free_list = Vec::with_capacity(capacity as usize);
        for i in (0..capacity).rev() {
            entries.push(DirectIoCmdEntry {
                file_index: 0,
                op: DirectIoOp::Read,
                in_use: false,
                user_data: 0,
            });
            free_list.push(i);
        }
        DirectIoCmdSlab { entries, free_list }
    }

    /// Allocate a command slot. Returns the slab index.
    pub fn allocate(&mut self, file_index: u16, op: DirectIoOp) -> Option<u16> {
        let idx = self.free_list.pop()?;
        let entry = &mut self.entries[idx as usize];
        entry.file_index = file_index;
        entry.op = op;
        entry.in_use = true;
        Some(idx)
    }

    /// Release a command slot. Returns (file_index, op).
    pub fn release(&mut self, idx: u16) -> (u16, DirectIoOp) {
        let entry = &mut self.entries[idx as usize];
        let file_index = entry.file_index;
        let op = entry.op;
        entry.in_use = false;
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
}

/// Configuration for direct I/O support.
///
/// When present in [`Config`](crate::config::Config), enables direct I/O file
/// management and allocates file/command tracking structures.
#[derive(Clone, Debug)]
pub struct DirectIoConfig {
    /// Maximum number of files that can be opened simultaneously.
    pub(crate) max_files: u16,
    /// Maximum I/O commands in flight across all files per worker.
    pub(crate) max_commands_in_flight: u16,
}

impl Default for DirectIoConfig {
    fn default() -> Self {
        DirectIoConfig {
            max_files: 8,
            max_commands_in_flight: 256,
        }
    }
}

impl DirectIoConfig {
    /// Set the most files open at once on each worker. Defaults to 8.
    pub fn max_files(mut self, max_files: u16) -> Self {
        self.max_files = max_files;
        self
    }

    /// Set the most I/O commands in flight across all files, per worker. Defaults to 256.
    ///
    /// Reads, writes and fsyncs count from submission until their completion
    /// is processed. One submitted at the limit fails with
    /// `direct I/O command slab exhausted`, on both backends.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_each_field_and_default_keeps_the_rest() {
        let d = DirectIoConfig::default();
        assert_eq!((d.max_files, d.max_commands_in_flight), (8, 256));
        let c = DirectIoConfig::default()
            .max_files(3)
            .max_commands_in_flight(7);
        assert_eq!((c.max_files, c.max_commands_in_flight), (3, 7));
    }

    #[test]
    fn dsync_adds_o_dsync_and_the_default_adds_nothing() {
        assert_eq!(DirectIoOpenOptions::new().extra_flags(), 0);
        assert_eq!(
            DirectIoOpenOptions::new().dsync(true).extra_flags(),
            libc::O_DSYNC
        );
        assert_eq!(
            DirectIoOpenOptions::new()
                .dsync(true)
                .dsync(false)
                .extra_flags(),
            0
        );
    }

    #[test]
    fn file_table_alloc_release() {
        let mut table = DirectIoFileTable::new(4);
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
        let mut table = DirectIoFileTable::new(1);
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
        let mut slab = DirectIoCmdSlab::new(8);
        let a = slab.allocate(0, DirectIoOp::Read).unwrap();
        let b = slab.allocate(1, DirectIoOp::Write).unwrap();
        assert!(slab.in_use(a));
        assert!(slab.in_use(b));

        let (file, op) = slab.release(a);
        assert_eq!(file, 0);
        assert_eq!(op, DirectIoOp::Read);
        assert!(!slab.in_use(a));

        let (file, op) = slab.release(b);
        assert_eq!(file, 1);
        assert_eq!(op, DirectIoOp::Write);
    }

    #[test]
    fn cmd_slab_fsync() {
        let mut slab = DirectIoCmdSlab::new(4);
        let a = slab.allocate(2, DirectIoOp::Fsync).unwrap();
        let (file, op) = slab.release(a);
        assert_eq!(file, 2);
        assert_eq!(op, DirectIoOp::Fsync);
    }

    #[test]
    fn file_table_exhaustion() {
        let mut table = DirectIoFileTable::new(2);
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_some());
        assert!(table.allocate().is_none());
    }
}
