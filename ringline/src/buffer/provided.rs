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

    /// Get a pointer and length for a buffer by its ID.
    pub fn get_buffer(&self, bid: u16) -> (*const u8, u32) {
        let offset = bid as usize * self.buf_size as usize;
        let ptr = unsafe { self.buf_backing.as_ptr().add(offset) };
        (ptr, self.buf_size)
    }

    /// Replenish a single buffer back into the ring after processing.
    #[allow(dead_code)]
    pub fn replenish(&mut self, bid: u16) {
        self.push_entry(bid);
        self.commit_tail();
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
