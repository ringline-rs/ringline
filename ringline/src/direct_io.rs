//! Direct I/O: reads, writes and fsync on a file or block device opened
//! with `O_DIRECT`, which bypasses the page cache.
//!
//! Enabled with [`ConfigBuilder::direct_io`](crate::ConfigBuilder::direct_io).
//! A [`DirectIoFile`] is a separate type from [`fs::File`](crate::fs::File):
//! [`read_into`] and [`write_from`] take only buffers that implement
//! [`IoBufAligned`], whose memory starts at a multiple of
//! [`DIRECT_IO_ALIGN`](crate::buf::DIRECT_IO_ALIGN) bytes, such as an
//! [`AlignedBuf`](crate::buf::AlignedBuf), or an
//! [`AlignedBytes`](crate::buf::AlignedBytes) for a write source the caller
//! keeps a handle to. Direct I/O files have their own file table and
//! in-flight bound, sized by [`DirectIoConfig`], apart from fs's.
//!
//! On io_uring the open is an `IORING_OP_OPENAT` that installs the file in
//! the fixed file table, the operations are `IORING_OP_READ`,
//! `IORING_OP_WRITE` and `IORING_OP_FSYNC` on that fixed file, and a close is
//! an `IORING_OP_CLOSE`. On mio they are `open`, `pread`, `pwrite` and
//! `fsync` on the disk-I/O pool, with `F_NOCACHE` set after the open in place
//! of `O_DIRECT` on macOS. Nothing blocks the worker thread. The operations
//! behave as the [`fs`](crate::fs) functions of the same names do: a dropped
//! future keeps its buffer until the kernel is done with it, reads and writes
//! are independent of each other, and [`fsync`] waits for the writes
//! submitted before it on the same handle (see the `fs` module docs for
//! these, and for when the kernel runs an operation on its io-wq pool).
//!
//! # Alignment requirements
//!
//! With `O_DIRECT` (Linux) the address of a read's or write's memory, its
//! length and the file offset must each be a multiple of the device's logical
//! block size (typically 512 or 4096 bytes), or the kernel returns `EINVAL`.
//! [`IoBufAligned`] covers the start of the buffer, which meets the address
//! requirement for either block size. A read writes at `bytes_init()` bytes
//! past that start, so that length must also be a multiple of the block size,
//! as must the length transferred and `offset`; the caller chooses those.
//! `F_NOCACHE` on macOS has no alignment requirement.

use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::buf::{IoBufAligned, IoBufMut};
use crate::fs::{FileKind, ReadFuture, WriteFuture, submit_with_key};
use crate::runtime::io::{DiskIoFuture, with_state};

/// Configuration for direct I/O, passed to
/// [`ConfigBuilder::direct_io`](crate::ConfigBuilder::direct_io).
///
/// Each worker gets a file table and command slab of its own for direct I/O
/// files, apart from fs's, so the two do not take each other's slots.
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

    /// Set the most I/O commands in flight across all files, per worker.
    /// Defaults to 256.
    ///
    /// Every operation of this module except `close` counts from submission
    /// until its completion is processed, the open included. One submitted at
    /// the limit fails with an error of kind `WouldBlock`, `direct I/O
    /// command slab exhausted`, on both backends.
    pub fn max_commands_in_flight(mut self, max_commands_in_flight: u16) -> Self {
        self.max_commands_in_flight = max_commands_in_flight;
        self
    }
}

/// Options for opening a direct I/O file, passed to [`open_with`].
///
/// The default opens the file as [`open`] does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectIoOpenOptions {
    dsync: bool,
}

impl DirectIoOpenOptions {
    /// Options that open the file as [`open`] does.
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

    /// The `open(2)` flags these options add to `O_RDWR` and the backend's
    /// direct I/O flag.
    pub(crate) fn extra_flags(&self) -> libc::c_int {
        if self.dsync { libc::O_DSYNC } else { 0 }
    }
}

/// Opaque handle to an opened direct I/O file.
///
/// Returned by [`open`] and [`open_with`] through their [`OpenFuture`], and
/// passed to [`read_into`], [`write_from`], [`fsync`] and [`close`]. The
/// handle includes a generation counter for stale-handle detection.
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

/// Open a file or block device for direct I/O: `O_RDWR | O_DIRECT` on
/// Linux, `O_RDWR` with `F_NOCACHE` on macOS.
///
/// The open does not block the worker thread: on io_uring it is an
/// `IORING_OP_OPENAT` into the fixed file table, and on mio it runs on the
/// disk-I/O pool. It holds a command slot until it completes. A filesystem
/// that does not support `O_DIRECT` refuses the open with `EINVAL`.
///
/// Returns an [`OpenFuture`] that resolves to a [`DirectIoFile`] on
/// success.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open(path: impl AsRef<std::path::Path>) -> io::Result<OpenFuture> {
    open_with(path, DirectIoOpenOptions::new())
}

/// Open a file for direct I/O as [`open`] does, with `options` added to its
/// flags.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn open_with(
    path: impl AsRef<std::path::Path>,
    options: DirectIoOpenOptions,
) -> io::Result<OpenFuture> {
    with_state(|driver, executor| {
        let mut ctx = driver.make_ctx();
        let (key, (file_index, generation)) = submit_with_key(executor, |key| {
            ctx.direct_io_open(path.as_ref(), options, key)
        })?;
        Ok(OpenFuture {
            state: crate::fs::OpenState::new(FileKind::DirectIo, key, file_index, generation),
        })
    })
}

/// Future that resolves to a [`DirectIoFile`] when the open completes.
///
/// Dropping it before it resolves closes the file: on the event loop's next
/// iteration if the open has completed, otherwise when it completes. The slot
/// is free once the close completes; on io_uring that is an
/// `IORING_OP_CLOSE`, so an open right after the drop can find the table
/// full.
///
/// Polled from a task on another worker it stays pending until a task on the
/// owning worker drives it; polled outside the ringline executor it panics.
/// Dropped on a thread other than the owning worker, it leaves the file open
/// and its slot taken until the owning worker exits.
pub struct OpenFuture {
    state: crate::fs::OpenState,
}

impl Future for OpenFuture {
    type Output = io::Result<DirectIoFile>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<DirectIoFile>> {
        self.state
            .poll_open(cx)
            .map_ok(|(index, generation)| DirectIoFile::new(index, generation))
    }
}

/// Read from `file` at `offset` into `buf`'s spare capacity.
///
/// As [`fs::read_into`](crate::fs::read_into), except that `buf` must
/// implement [`IoBufAligned`]: the kernel writes into the
/// `bytes_total() - bytes_init()` bytes that start `bytes_init()` bytes past
/// the buffer's aligned start, and the future yields `(io::Result<usize>,
/// buf)` with the initialized length extended by the bytes read. See the
/// [module docs](self#alignment-requirements) for the lengths and offsets
/// `O_DIRECT` accepts.
///
/// # Panics
///
/// Panics if called outside the ringline async executor, unless `buf` is
/// refused before submission (no spare capacity, or more than `u32::MAX`
/// bytes of it).
pub fn read_into<B: IoBufMut + IoBufAligned>(
    file: DirectIoFile,
    offset: u64,
    buf: B,
) -> ReadFuture<B> {
    crate::fs::read_into_file(FileKind::DirectIo, file.index, file.generation, offset, buf)
}

/// Write `buf`'s initialized bytes to `file` at `offset`.
///
/// As [`fs::write_from`](crate::fs::write_from), except that `buf` must
/// implement [`IoBufAligned`]. The future yields `(io::Result<usize>, buf)`.
/// See the [module docs](self#alignment-requirements) for the lengths and
/// offsets `O_DIRECT` accepts.
///
/// An [`AlignedBuf`](crate::buf::AlignedBuf) is accepted, and so is the
/// [`AlignedBytes`](crate::buf::AlignedBytes) its `freeze` returns, which the
/// caller can clone to keep a handle while the write is in flight:
///
/// ```no_run
/// # async fn write(file: ringline::direct_io::DirectIoFile) {
/// let block = ringline::buf::AlignedBuf::zeroed(4096, 4096);
/// let (n, _block) = ringline::direct_io::write_from(file, 0, block).await;
/// # let _ = n;
/// let shared = ringline::buf::AlignedBuf::zeroed(4096, 4096).freeze();
/// let kept = shared.clone();
/// let (n, _shared) = ringline::direct_io::write_from(file, 4096, shared).await;
/// # let _ = (n, kept);
/// # }
/// ```
///
/// A `Vec<u8>`, whose memory has no alignment guarantee, does not compile:
///
/// ```compile_fail
/// # async fn write(file: ringline::direct_io::DirectIoFile) {
/// let block = vec![0u8; 4096];
/// let (n, _block) = ringline::direct_io::write_from(file, 0, block).await;
/// # let _ = n;
/// # }
/// ```
///
/// # Panics
///
/// Panics if called outside the ringline async executor, unless `buf` is
/// refused before submission (more than `u32::MAX` initialized bytes).
pub fn write_from<B: IoBufAligned>(file: DirectIoFile, offset: u64, buf: B) -> WriteFuture<B> {
    crate::fs::write_from_file(FileKind::DirectIo, file.index, file.generation, offset, buf)
}

/// Fsync a direct I/O file and return a future for the result.
///
/// The fsync waits in ringline, not submitted, until every write submitted
/// before it through `file` has completed, as [`fs::fsync`](crate::fs::fsync)
/// does; writes through another handle opened on the same path are not
/// waited for. Once it runs, the future resolves to `Ok(0)` when every write
/// to the file that completed before then is on stable storage. On a Linux
/// block device this sends the device a cache flush, which persists
/// everything in its volatile write cache and not only this file's writes;
/// the kernel skips the flush when the device reports a write-through cache.
/// To make individual writes durable without flushing the whole cache, open
/// the file with [`DirectIoOpenOptions::dsync`].
///
/// On io_uring the kernel runs an fsync on an io-wq worker thread. On mio it
/// is `fsync(2)` on the disk I/O pool; on macOS that call does not flush the
/// drive's own cache.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn fsync(file: DirectIoFile) -> io::Result<DiskIoFuture> {
    crate::fs::fsync_file(FileKind::DirectIo, file.index, file.generation)
}

/// Close a direct I/O file handle.
///
/// As [`fs::close`](crate::fs::close): the handle is invalid when this
/// returns, a read, write or fsync already issued on it completes against
/// the file, and on io_uring the table slot is free once the file's
/// `IORING_OP_CLOSE` completes, so until then an open can fail with
/// `direct I/O file table full`.
///
/// # Panics
///
/// Panics if called outside the ringline async executor.
pub fn close(file: DirectIoFile) -> io::Result<()> {
    crate::fs::close_file(FileKind::DirectIo, file.index, file.generation)
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
}
