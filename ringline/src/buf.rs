//! Buffers that disk operations take by value.
//!
//! [`fs::read_into`](crate::fs::read_into) and [`nvme_read`](crate::nvme_read)
//! take an [`IoBufMut`] and write into its spare capacity;
//! [`fs::write_from`](crate::fs::write_from) and
//! [`nvme_write`](crate::nvme_write) take an [`IoBuf`] and send its initialized
//! bytes. The future returns the buffer with the result. If the future is
//! dropped before the operation completes, ringline keeps the buffer until the
//! kernel has completed the operation and then drops it, so the memory the
//! kernel uses stays valid either way.
//!
//! ringline implements the traits for `Vec<u8>`, [`BytesMut`], [`Bytes`]
//! ([`IoBuf`], not [`IoBufMut`]), [`AlignedBuf`] and [`AlignedBytes`]
//! ([`IoBuf`], not [`IoBufMut`]).
//! [`crate::direct_io`] needs memory aligned to the device's logical block
//! size, which `Vec<u8>` and `BytesMut` do not guarantee, so its reads and
//! writes take only an [`IoBufAligned`] buffer; ringline implements that
//! trait for [`AlignedBuf`] and [`AlignedBytes`]. [`AlignedBuf::freeze`]
//! turns an `AlignedBuf` into an `AlignedBytes`, whose clones share the
//! allocation; a [`Bytes`] made from it is not an `IoBufAligned`. NVMe
//! passthrough copies a buffer whose address is not 4-byte aligned through a
//! bounce buffer.
//!
//! An application with its own memory (a slot of an arena, a range of a
//! larger buffer, memory pinned by another component) implements the traits
//! for a type that owns its claim on that memory. If that memory is in a
//! region registered with
//! [`Runtime::register_region`](crate::Runtime::register_region), the type
//! returns the region from [`IoBuf::region`], and on io_uring its reads and
//! writes use the registered buffer instead of pinning its pages for each
//! operation.

use std::alloc::Layout;
use std::ptr::NonNull;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

/// Memory a disk operation reads from: the source of a write.
///
/// A write sends the `bytes_init()` bytes at `stable_ptr()`.
///
/// # Safety
///
/// While ringline holds the value, which lasts until the kernel has completed
/// the operation even when the future that took it is dropped:
///
/// - `stable_ptr()` returns the same pointer each time it is called, and the
///   pointer stays valid when the value is moved, so the memory is not stored
///   inline in the value;
/// - the `bytes_init()` bytes at `stable_ptr()` are initialized and stay
///   valid for reads;
/// - nothing writes to those bytes;
/// - `bytes_init()` returns the same value on every call (for an
///   [`IoBufMut`], until ringline calls `set_init`).
///
/// Dropping the value may free the memory: ringline drops it only after the
/// operation has completed. The drop must not call into ringline (spawn,
/// start an operation, drop a `Connection` or another operation's future):
/// ringline may drop the value while it completes other operations, outside
/// any task.
pub unsafe trait IoBuf: 'static {
    /// A pointer to the start of the buffer's memory.
    fn stable_ptr(&self) -> *const u8;

    /// The number of initialized bytes at [`stable_ptr`](Self::stable_ptr).
    fn bytes_init(&self) -> usize;

    /// The registered region the buffer's memory is in, or
    /// [`RegionId::UNREGISTERED`](crate::RegionId::UNREGISTERED) (the
    /// default).
    ///
    /// On io_uring, a read or write from a buffer that names a region is
    /// submitted as `IORING_OP_READ_FIXED` / `IORING_OP_WRITE_FIXED` (for
    /// NVMe, `IORING_URING_CMD_FIXED`) with the region's index, so the
    /// kernel does not pin and unpin the buffer's pages for each operation.
    /// ringline checks that the operation's range lies inside the region and
    /// otherwise refuses it with
    /// [`InvalidInput`](std::io::ErrorKind::InvalidInput); an
    /// operation refused that way returns the buffer as other refusals do.
    /// [`Runtime::register_region`](crate::Runtime::register_region) returns
    /// the `RegionId`, which names the region on every worker. The mio
    /// backend ignores the region.
    ///
    /// Return the same value on every call while ringline holds the value.
    fn region(&self) -> crate::RegionId {
        crate::RegionId::UNREGISTERED
    }
}

/// Memory a disk operation writes into: the destination of a read.
///
/// A read writes into the spare capacity, the `bytes_total() - bytes_init()`
/// bytes that start `bytes_init()` bytes after `stable_mut_ptr()`, and on
/// success ringline calls [`set_init`](Self::set_init) with the new initialized
/// length.
///
/// # Safety
///
/// The requirements of [`IoBuf`], and, while ringline holds the value:
///
/// - `stable_mut_ptr()` returns `stable_ptr()` cast to `*mut u8`;
/// - the `bytes_total()` bytes at `stable_mut_ptr()` stay valid for writes;
/// - nothing else reads or writes those bytes;
/// - `bytes_total()` returns the same value on every call, at least
///   `bytes_init()`.
pub unsafe trait IoBufMut: IoBuf {
    /// A pointer to the start of the buffer's memory.
    fn stable_mut_ptr(&mut self) -> *mut u8;

    /// The buffer's capacity in bytes, initialized or not.
    fn bytes_total(&self) -> usize;

    /// Record that the first `pos` bytes are initialized.
    ///
    /// # Safety
    ///
    /// The first `pos` bytes at `stable_mut_ptr()` are initialized, and `pos`
    /// is at most `bytes_total()`.
    unsafe fn set_init(&mut self, pos: usize);
}

unsafe impl IoBuf for Vec<u8> {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.len()
    }
}

unsafe impl IoBufMut for Vec<u8> {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }

    fn bytes_total(&self) -> usize {
        self.capacity()
    }

    unsafe fn set_init(&mut self, pos: usize) {
        if pos > self.len() {
            // Safety: the caller promises `pos` bytes are initialized and
            // `pos <= capacity`.
            unsafe { self.set_len(pos) };
        }
    }
}

unsafe impl IoBuf for BytesMut {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.len()
    }
}

unsafe impl IoBufMut for BytesMut {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_ptr()
    }

    fn bytes_total(&self) -> usize {
        self.capacity()
    }

    unsafe fn set_init(&mut self, pos: usize) {
        if pos > self.len() {
            // Safety: the caller promises `pos` bytes are initialized and
            // `pos <= capacity`.
            unsafe { self.set_len(pos) };
        }
    }
}

// A `Bytes` is immutable and its memory is freed only when the last handle
// drops, so the handle ringline holds keeps the memory valid.
unsafe impl IoBuf for Bytes {
    fn stable_ptr(&self) -> *const u8 {
        self.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.len()
    }
}

/// The alignment, in bytes, of the start of every [`IoBufAligned`] buffer:
/// a multiple of the usual logical block sizes for `O_DIRECT`, 512 and 4096
/// bytes.
pub const DIRECT_IO_ALIGN: usize = 4096;

/// Memory whose start is aligned for direct I/O: the buffers
/// [`direct_io::read_into`](crate::direct_io::read_into) and
/// [`direct_io::write_from`](crate::direct_io::write_from) take.
///
/// # Safety
///
/// The requirements of [`IoBuf`], and `stable_ptr()` is a multiple of
/// [`DIRECT_IO_ALIGN`].
pub unsafe trait IoBufAligned: IoBuf {}

/// A heap buffer whose start is aligned to a chosen power of two, and to at
/// least [`DIRECT_IO_ALIGN`], for direct I/O and NVMe.
///
/// With `O_DIRECT` (Linux) the address of a read's or write's memory, its
/// length and the file offset must each be a multiple of the device's logical
/// block size (typically 512 or 4096 bytes). Every `AlignedBuf` starts at a
/// multiple of [`DIRECT_IO_ALIGN`], which satisfies the address requirement
/// for either block size, so it implements [`IoBufAligned`]; the caller
/// chooses lengths and offsets.
///
/// Like `Vec<u8>`, it has a capacity and an initialized length, and derefs to
/// the initialized bytes. Its capacity is fixed at allocation.
pub struct AlignedBuf {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
    align: usize,
}

// Safety: `AlignedBuf` owns its allocation exclusively, as `Vec<u8>` does.
unsafe impl Send for AlignedBuf {}
// Safety: shared access only reads.
unsafe impl Sync for AlignedBuf {}

impl AlignedBuf {
    /// An empty buffer with room for `capacity` bytes, starting at an address
    /// that is a multiple of `align` and of [`DIRECT_IO_ALIGN`].
    ///
    /// # Panics
    ///
    /// Panics if `align` is not a power of two or if `capacity` rounded up to
    /// the larger of `align` and [`DIRECT_IO_ALIGN`] overflows `isize`. Aborts
    /// if the allocation fails, as `Vec` does.
    pub fn with_capacity(capacity: usize, align: usize) -> Self {
        Self::allocate(capacity, align, false)
    }

    /// A buffer of `len` zero bytes, starting at an address that is a multiple
    /// of `align` and of [`DIRECT_IO_ALIGN`].
    ///
    /// # Panics
    ///
    /// As [`with_capacity`](Self::with_capacity).
    pub fn zeroed(len: usize, align: usize) -> Self {
        let mut buf = Self::allocate(len, align, true);
        buf.len = len;
        buf
    }

    fn allocate(capacity: usize, align: usize, zeroed: bool) -> Self {
        assert!(
            align.is_power_of_two(),
            "AlignedBuf: align must be a power of two"
        );
        // A multiple of `DIRECT_IO_ALIGN` is a multiple of every smaller
        // power of two, so raising `align` keeps the caller's guarantee.
        let align = align.max(DIRECT_IO_ALIGN);
        let layout = Layout::from_size_align(capacity, align)
            .expect("AlignedBuf: capacity rounded up to the alignment overflows isize");
        let ptr = if capacity == 0 {
            // A dangling pointer at the alignment: nothing is allocated.
            NonNull::new(align as *mut u8).expect("align is nonzero")
        } else {
            // Safety: the layout's size is nonzero.
            let raw = unsafe {
                if zeroed {
                    std::alloc::alloc_zeroed(layout)
                } else {
                    std::alloc::alloc(layout)
                }
            };
            NonNull::new(raw).unwrap_or_else(|| std::alloc::handle_alloc_error(layout))
        };
        AlignedBuf {
            ptr,
            len: 0,
            cap: capacity,
            align,
        }
    }

    /// The number of initialized bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are initialized.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// The alignment of the buffer's start, in bytes: the `align` it was
    /// created with, or [`DIRECT_IO_ALIGN`] if that is larger.
    pub fn alignment(&self) -> usize {
        self.align
    }

    /// Set the initialized length to 0. The capacity is unchanged.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Shorten the initialized length to `len`; a longer `len` changes
    /// nothing.
    pub fn truncate(&mut self, len: usize) {
        self.len = self.len.min(len);
    }

    /// Set the initialized length.
    ///
    /// # Safety
    ///
    /// `len` is at most the capacity, and the first `len` bytes are
    /// initialized.
    pub unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.cap);
        self.len = len;
    }

    /// Append `data`.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has less than `data.len()` bytes of spare
    /// capacity.
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        assert!(
            data.len() <= self.cap - self.len,
            "AlignedBuf: {} bytes do not fit in {} of spare capacity",
            data.len(),
            self.cap - self.len
        );
        // Safety: the destination is inside the allocation and does not
        // overlap `data`, which `&mut self` excludes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.ptr.as_ptr().add(self.len),
                data.len(),
            );
        }
        self.len += data.len();
    }

    /// Convert into an [`AlignedBytes`] of the initialized bytes, which keeps
    /// the allocation and its alignment. Clones of it share the allocation,
    /// so the caller can keep a handle to a buffer while a write from it is
    /// in flight.
    pub fn freeze(self) -> AlignedBytes {
        AlignedBytes {
            buf: Arc::new(self),
        }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        if self.cap != 0 {
            // Safety: allocated in `allocate` with this layout.
            unsafe {
                std::alloc::dealloc(
                    self.ptr.as_ptr(),
                    Layout::from_size_align_unchecked(self.cap, self.align),
                );
            }
        }
    }
}

impl std::ops::Deref for AlignedBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // Safety: the first `len` bytes are initialized.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl std::ops::DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // Safety: the first `len` bytes are initialized, and `&mut self` is
        // exclusive.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl AsRef<[u8]> for AlignedBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Equal when the initialized bytes are equal, whatever the capacity or
/// alignment.
impl PartialEq for AlignedBuf {
    fn eq(&self, other: &Self) -> bool {
        self[..] == other[..]
    }
}

impl Eq for AlignedBuf {}

/// Hashes the initialized bytes, as `[u8]` does.
impl std::hash::Hash for AlignedBuf {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self[..].hash(state);
    }
}

impl std::fmt::Debug for AlignedBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBuf")
            .field("len", &self.len)
            .field("capacity", &self.cap)
            .field("alignment", &self.align)
            .finish()
    }
}

unsafe impl IoBuf for AlignedBuf {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.len
    }
}

// Safety: `allocate` aligns every buffer, the empty one included, to at
// least `DIRECT_IO_ALIGN`.
unsafe impl IoBufAligned for AlignedBuf {}

unsafe impl IoBufMut for AlignedBuf {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    fn bytes_total(&self) -> usize {
        self.cap
    }

    unsafe fn set_init(&mut self, pos: usize) {
        if pos > self.len {
            self.len = pos;
        }
    }
}

/// The initialized bytes of an [`AlignedBuf`], immutable and shared by its
/// clones, from [`AlignedBuf::freeze`].
///
/// It implements [`IoBuf`] and [`IoBufAligned`], so it is a source for
/// [`direct_io::write_from`](crate::direct_io::write_from) as well as for
/// `fs` and NVMe writes. A clone is a reference count increment; the
/// allocation is freed when the last clone drops.
/// [`Bytes::from`] converts one into a [`Bytes`] without copying, and
/// [`try_into_mut`](Self::try_into_mut) recovers the `AlignedBuf` from the
/// last clone.
#[derive(Clone)]
pub struct AlignedBytes {
    buf: Arc<AlignedBuf>,
}

impl AlignedBytes {
    /// The number of bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether there are no bytes.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The alignment of the start, in bytes, as [`AlignedBuf::alignment`].
    pub fn alignment(&self) -> usize {
        self.buf.alignment()
    }

    /// The `AlignedBuf` back, with its initialized length and capacity, if
    /// this is the only handle to it; otherwise `self`.
    pub fn try_into_mut(self) -> Result<AlignedBuf, Self> {
        Arc::try_unwrap(self.buf).map_err(|buf| AlignedBytes { buf })
    }
}

impl std::ops::Deref for AlignedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl AsRef<[u8]> for AlignedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Equal when the bytes are equal, whatever the alignment, as for
/// [`AlignedBuf`].
impl PartialEq for AlignedBytes {
    fn eq(&self, other: &Self) -> bool {
        self[..] == other[..]
    }
}

impl Eq for AlignedBytes {}

/// Hashes the bytes, as `[u8]` and [`Bytes`] do.
impl std::hash::Hash for AlignedBytes {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self[..].hash(state);
    }
}

impl std::fmt::Debug for AlignedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlignedBytes")
            .field("len", &self.buf.len)
            .field("alignment", &self.buf.align)
            .finish()
    }
}

impl From<AlignedBytes> for Bytes {
    /// A [`Bytes`] over the same allocation; the allocation is freed when
    /// the last `Bytes` and `AlignedBytes` handle drops.
    fn from(bytes: AlignedBytes) -> Bytes {
        Bytes::from_owner(bytes)
    }
}

// Safety: the `Arc` keeps the allocation alive while ringline holds the
// handle, its address does not change when the handle moves, and no handle
// can write to it (`try_into_mut` needs the only handle, which ringline
// holds during an operation).
unsafe impl IoBuf for AlignedBytes {
    fn stable_ptr(&self) -> *const u8 {
        self.buf.ptr.as_ptr()
    }

    fn bytes_init(&self) -> usize {
        self.buf.len
    }
}

// Safety: the start is the `AlignedBuf`'s, which is aligned to at least
// `DIRECT_IO_ALIGN`.
unsafe impl IoBufAligned for AlignedBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_buf_starts_at_its_alignment() {
        for align in [1, 512, 4096, 1 << 16] {
            for cap in [0, 1, 4096, 10_000] {
                let buf = AlignedBuf::with_capacity(cap, align);
                assert_eq!(
                    buf.stable_ptr() as usize % align,
                    0,
                    "align {align} cap {cap}"
                );
                assert_eq!((buf.len(), buf.capacity()), (0, cap));
            }
        }
    }

    #[test]
    fn aligned_buf_starts_at_a_multiple_of_direct_io_align_for_any_align() {
        for align in [1, 2, 512, 4096, 1 << 16] {
            for cap in [0, 1, 4096] {
                let buf = AlignedBuf::with_capacity(cap, align);
                assert_eq!(buf.stable_ptr() as usize % DIRECT_IO_ALIGN, 0);
                assert_eq!(buf.alignment(), align.max(DIRECT_IO_ALIGN));
                let zeroed = AlignedBuf::zeroed(cap, align);
                assert_eq!(zeroed.stable_ptr() as usize % DIRECT_IO_ALIGN, 0);
            }
        }
    }

    #[test]
    fn aligned_buf_zeroed_is_initialized() {
        let buf = AlignedBuf::zeroed(8192, 4096);
        assert_eq!(buf.len(), 8192);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn aligned_buf_set_init_only_grows() {
        let mut buf = AlignedBuf::zeroed(16, 16);
        unsafe { buf.set_init(4) };
        assert_eq!(buf.len(), 16, "set_init never shortens");
        buf.clear();
        unsafe { buf.set_init(4) };
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn aligned_buf_freeze_keeps_the_allocation() {
        let mut buf = AlignedBuf::with_capacity(4096, 4096);
        buf.extend_from_slice(b"hello");
        let ptr = buf.stable_ptr();
        let bytes = buf.freeze();
        assert_eq!(&bytes[..], b"hello");
        assert_eq!(bytes.stable_ptr(), ptr);
        assert_eq!(bytes.clone().stable_ptr(), ptr, "a clone shares it");
        assert_eq!(Bytes::from(bytes).as_ptr(), ptr, "so does the Bytes");
    }

    fn hash_of<T: std::hash::Hash + ?Sized>(value: &T) -> u64 {
        use std::hash::{BuildHasher, BuildHasherDefault};
        BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default().hash_one(value)
    }

    fn filled(data: &[u8], cap: usize, align: usize) -> AlignedBuf {
        let mut buf = AlignedBuf::with_capacity(cap, align);
        buf.extend_from_slice(data);
        buf
    }

    /// Two separate allocations with the same bytes, at different capacities
    /// and alignments, are equal and hash alike, and hash as the bytes do.
    #[test]
    fn equal_bytes_in_separate_buffers_are_equal_and_hash_alike() {
        let a = filled(b"hello", 4096, 4096);
        let b = filled(b"hello", 8192, 1 << 16);
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_eq!(hash_of(&a), hash_of(&b"hello"[..]));
        assert_ne!(a, filled(b"world", 4096, 4096));

        let (a, b) = (a.freeze(), b.freeze());
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_eq!(hash_of(&a), hash_of(&Bytes::from_static(b"hello")));
        assert_ne!(a, filled(b"world", 4096, 4096).freeze());
    }

    #[test]
    fn aligned_bytes_gives_the_buffer_back_from_its_last_handle() {
        let mut buf = AlignedBuf::with_capacity(4096, 4096);
        buf.extend_from_slice(b"hello");
        let ptr = buf.stable_ptr();
        let bytes = buf.freeze();
        let other = bytes.clone();
        let bytes = bytes.try_into_mut().expect_err("a clone is alive");
        drop(other);
        let buf = bytes.try_into_mut().expect("the last handle");
        assert_eq!((buf.stable_ptr(), &buf[..]), (ptr, &b"hello"[..]));
        assert_eq!(buf.capacity(), 4096);
    }

    #[test]
    #[should_panic(expected = "do not fit")]
    fn aligned_buf_extend_past_capacity_panics() {
        let mut buf = AlignedBuf::with_capacity(4, 8);
        buf.extend_from_slice(b"hello");
    }

    #[test]
    #[should_panic(expected = "power of two")]
    fn aligned_buf_rejects_a_non_power_of_two() {
        let _ = AlignedBuf::with_capacity(16, 3);
    }
}
