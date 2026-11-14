//! Buffers that disk operations take by value.
//!
//! [`fs::read_into`](crate::fs::read_into), [`direct_io_read`](crate::direct_io_read)
//! and [`nvme_read`](crate::nvme_read) take an [`IoBufMut`] and write into its
//! spare capacity; [`fs::write_from`](crate::fs::write_from),
//! [`direct_io_write`](crate::direct_io_write) and
//! [`nvme_write`](crate::nvme_write) take an [`IoBuf`] and send its initialized
//! bytes. The future returns the buffer with the result. If the future is
//! dropped before the operation completes, ringline keeps the buffer until the
//! kernel has completed the operation and then drops it, so the memory the
//! kernel uses stays valid either way.
//!
//! ringline implements the traits for `Vec<u8>`, [`BytesMut`], [`Bytes`]
//! ([`IoBuf`] only) and [`AlignedBuf`]. Direct I/O needs memory aligned to the
//! device's logical block size, which `Vec<u8>` and `BytesMut` do not
//! guarantee; NVMe passthrough copies a buffer whose address is not 4-byte
//! aligned through a bounce buffer. [`AlignedBuf`] allocates at
//! a chosen alignment, and [`AlignedBuf::freeze`] turns one into an aligned
//! [`Bytes`].
//!
//! An application with its own memory (a slot of an arena, a range of a
//! larger buffer, memory pinned by another component) implements the traits
//! for a type that owns its claim on that memory.

use std::alloc::Layout;
use std::ptr::NonNull;

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

/// A heap buffer whose start is aligned to a chosen power of two, for direct
/// I/O and NVMe.
///
/// With `O_DIRECT` (Linux) the address of a read's or write's memory, its
/// length and the file offset must each be a multiple of the device's logical
/// block size (typically 512 or 4096 bytes). `AlignedBuf::with_capacity(len, 4096)`
/// satisfies the address requirement for either block size; the caller
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
    /// that is a multiple of `align`.
    ///
    /// # Panics
    ///
    /// Panics if `align` is not a power of two, if `capacity` rounded up to
    /// `align` overflows `isize`, or if the allocation fails.
    pub fn with_capacity(capacity: usize, align: usize) -> Self {
        Self::allocate(capacity, align, false)
    }

    /// A buffer of `len` zero bytes, starting at an address that is a multiple
    /// of `align`.
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
        let layout = Layout::from_size_align(capacity, align)
            .expect("AlignedBuf: align must be a power of two and the size must fit isize");
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

    /// The alignment of the buffer's start, in bytes.
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

    /// Convert into a [`Bytes`] of the initialized bytes, which keeps the
    /// allocation and its alignment, for an [`IoBuf`] write that the caller
    /// also keeps a handle to.
    pub fn freeze(self) -> Bytes {
        Bytes::from_owner(self)
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
        assert_eq!(bytes.as_ptr(), ptr);
        assert_eq!(bytes.stable_ptr() as usize % 4096, 0);
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
