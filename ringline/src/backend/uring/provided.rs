use std::io;
use std::ptr;
use std::sync::atomic::{self, AtomicU16};

/// A ring-mapped provided buffer ring for multishot recv operations.
///
/// The kernel picks a buffer from this ring at completion time.
/// We replenish buffers after processing to keep the ring full.
pub struct ProvidedBufRing {
    /// Pointer to the mmap'd ring (shared with kernel).
    ring_ptr: *mut u8,
    /// Size of the mmap'd ring region.
    ring_mmap_len: usize,
    /// Backing memory for all buffers.
    buf_backing: Vec<u8>,
    /// Buffer group ID.
    bgid: u16,
    /// Number of buffers (must be power of 2).
    ring_size: u16,
    /// Size of each buffer.
    buf_size: u32,
    /// Current tail index (we write, kernel reads).
    tail: u16,
    /// Mask for ring index wrapping.
    mask: u16,
}

/// An io_uring buf_ring entry (matches kernel struct io_uring_buf).
#[repr(C)]
struct BufRingEntry {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
}

impl ProvidedBufRing {
    /// Size of a single ring entry.
    const ENTRY_SIZE: usize = std::mem::size_of::<BufRingEntry>();

    /// Create a new provided buffer ring.
    ///
    /// `ring_size` must be a power of 2.
    /// The ring memory is mmap'd so the kernel can access it directly.
    pub fn new(bgid: u16, ring_size: u16, buf_size: u32) -> io::Result<Self> {
        assert!(ring_size.is_power_of_two(), "ring_size must be power of 2");

        let ring_mmap_len = ring_size as usize * Self::ENTRY_SIZE;
        let buf_backing = vec![0u8; ring_size as usize * buf_size as usize];

        // mmap anonymous memory for the ring (page-aligned, shared with kernel)
        let ring_ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                ring_mmap_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        if ring_ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        let mut ring = ProvidedBufRing {
            ring_ptr: ring_ptr as *mut u8,
            ring_mmap_len,
            buf_backing,
            bgid,
            ring_size,
            buf_size,
            tail: 0,
            mask: ring_size - 1,
        };

        // Pre-fill the ring with all buffers
        for i in 0..ring_size {
            ring.push_entry(i);
        }
        // Make entries visible to kernel
        ring.commit_tail();

        Ok(ring)
    }

    /// Get the ring pointer for `register_buf_ring()`.
    pub fn ring_addr(&self) -> u64 {
        self.ring_ptr as u64
    }

    /// Get the buffer group ID.
    pub fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Get the ring size (number of entries).
    pub fn ring_entries(&self) -> u32 {
        self.ring_size as u32
    }

    /// Size in bytes of each buffer in this ring.
    pub fn buf_size_bytes(&self) -> u32 {
        self.buf_size
    }

    /// Get a pointer and length for a buffer by its ID.
    pub fn get_buffer(&self, bid: u16) -> (*const u8, u32) {
        let offset = bid as usize * self.buf_size as usize;
        let ptr = unsafe { self.buf_backing.as_ptr().add(offset) };
        (ptr, self.buf_size)
    }

    /// Batch replenish multiple buffers.
    pub fn replenish_batch(&mut self, bids: &[u16]) {
        for &bid in bids {
            self.push_entry(bid);
        }
        if !bids.is_empty() {
            self.commit_tail();
        }
    }

    fn push_entry(&mut self, bid: u16) {
        let ring_idx = (self.tail & self.mask) as usize;
        let entry_ptr = unsafe {
            self.ring_ptr
                .add(ring_idx * Self::ENTRY_SIZE)
                .cast::<BufRingEntry>()
        };
        let buf_offset = bid as usize * self.buf_size as usize;
        let buf_addr = unsafe { self.buf_backing.as_ptr().add(buf_offset) };
        unsafe {
            ptr::write(
                entry_ptr,
                BufRingEntry {
                    addr: buf_addr as u64,
                    len: self.buf_size,
                    bid,
                    resv: 0,
                },
            );
        }
        self.tail = self.tail.wrapping_add(1);
    }

    fn commit_tail(&self) {
        // The tail is at offset 14 within the ring header. The kernel overlays
        // the header with bufs[0]: struct io_uring_buf_ring { union {
        //   struct { u64 resv1; u32 resv2; u16 resv3; u16 tail; };
        //   struct io_uring_buf bufs[0]; }; };
        // io_uring_buf: { u64 addr(0); u32 len(8); u16 bid(12); u16 resv(14); }
        // So tail = bufs[0].resv = offset 14.
        let tail_ptr = unsafe { self.ring_ptr.add(14).cast::<AtomicU16>() };
        unsafe {
            (*tail_ptr).store(self.tail, atomic::Ordering::Release);
        }
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        if !self.ring_ptr.is_null() {
            unsafe {
                libc::munmap(self.ring_ptr as *mut _, self.ring_mmap_len);
            }
        }
    }
}

// Safety: The ring is only accessed from a single worker thread.
unsafe impl Send for ProvidedBufRing {}

/// Number of provided-buffer size classes.
///
/// Class 0 mirrors the configured `recv_buffer` exactly (so existing ring/buf
/// tuning and the preserved throughput baseline still apply); classes 1+ are
/// larger fixed-size buffers reserved for the (future) adaptive recv path.
/// Every connection is pinned to class 0 today (see `Driver::recv_class`), so
/// classes 1/2 are registered with the kernel but currently unused.
const NUM_SIZE_CLASSES: usize = 3;

/// A set of provided-buffer rings, one per size class, each with a distinct
/// `bgid`. Class 0 is the configured recv buffer; classes 1+ are hardcoded
/// larger buffers.
///
/// NOTE (config surface): the class-1/2 geometries below are hardcoded for
/// now. Lifting them into `Config` is a later phase.
pub struct SizeClassRings {
    rings: Vec<ProvidedBufRing>,
}

impl SizeClassRings {
    /// Create the per-class provided buffer rings.
    ///
    /// Class 0 is built from `(bgid_base, ring_size, buffer_size)` — i.e. the
    /// configured `recv_buffer` — so it is byte-for-byte identical to the
    /// single ring this replaces. Classes 1/2 use hardcoded larger buffers.
    ///
    /// The class bgids occupy the contiguous range
    /// `[bgid_base, bgid_base + NUM_SIZE_CLASSES)`.
    pub fn new(bgid_base: u16, ring_size: u16, buffer_size: u32) -> io::Result<Self> {
        // Document the bgid range consumed by the size classes. Config
        // validation currently only guards `udp_recv_buffer.bgid !=
        // recv_buffer.bgid` (== bgid_base); it does NOT yet account for the
        // extra class bgids (bgid_base + 1, bgid_base + 2). Widening config
        // validation to reserve this whole range is a later phase.
        debug_assert!(
            bgid_base.checked_add(NUM_SIZE_CLASSES as u16 - 1).is_some(),
            "size-class bgids [{}, {}] overflow u16",
            bgid_base,
            bgid_base as u32 + NUM_SIZE_CLASSES as u32 - 1
        );
        let rings = vec![
            // class 0: the configured recv_buffer (preserves the baseline).
            ProvidedBufRing::new(bgid_base, ring_size, buffer_size)?,
            // class 1: hardcoded 128 × 64 KiB.
            ProvidedBufRing::new(bgid_base + 1, 128, 65536)?,
            // class 2: hardcoded 64 × 256 KiB.
            ProvidedBufRing::new(bgid_base + 2, 64, 262144)?,
        ];
        debug_assert_eq!(rings.len(), NUM_SIZE_CLASSES);
        Ok(SizeClassRings { rings })
    }

    /// Number of size classes.
    pub fn num_classes(&self) -> usize {
        self.rings.len()
    }

    /// Buffer group ID for a size class.
    pub fn bgid(&self, class: usize) -> u16 {
        self.rings[class].bgid()
    }

    /// Buffer size in bytes for a size class.
    pub fn buffer_size(&self, class: usize) -> u32 {
        self.rings[class].buf_size_bytes()
    }

    /// Ring entry count for a size class.
    #[allow(dead_code)] // symmetry with ProvidedBufRing; used by diagnostics/tests
    pub fn ring_entries(&self, class: usize) -> u32 {
        self.rings[class].ring_entries()
    }

    /// Pointer and length for a buffer within a size class.
    pub fn get_buffer(&self, class: usize, bid: u16) -> (*const u8, u32) {
        self.rings[class].get_buffer(bid)
    }

    /// Batch replenish buffers into a size class.
    pub fn replenish_batch(&mut self, class: usize, bids: &[u16]) {
        self.rings[class].replenish_batch(bids);
    }

    /// Iterate every class ring (for kernel registration / unregistration).
    pub fn rings(&self) -> impl Iterator<Item = &ProvidedBufRing> {
        self.rings.iter()
    }
}
