use std::io;
use std::ptr;
use std::sync::atomic::{self, AtomicU16};

use super::ring_memory::RingMemory;

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
    mem: RingMemory,
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
    /// Buffers out of the ring: handed to a completion and not yet
    /// returned. `ring_size - outstanding` buffers are free in the ring for
    /// the kernel to pick. Maintained by `on_handout` and `replenish_batch`.
    outstanding: u32,
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
        let mem = RingMemory::new(ring_size as usize * buf_size as usize)?;

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
            mem,
            bgid,
            ring_size,
            buf_size,
            tail: 0,
            mask: ring_size - 1,
            outstanding: 0,
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

    /// Record that the kernel handed one buffer to a completion (consumed one
    /// from the ring). Call exactly once per recv completion that selected a
    /// buffer, before it is processed, and balance it with `replenish_batch`.
    #[inline]
    pub fn on_handout(&mut self) {
        self.outstanding += 1;
        debug_assert!(
            self.outstanding <= self.ring_size as u32,
            "provided-ring handout exceeds ring size ({} > {})",
            self.outstanding,
            self.ring_size
        );
    }

    /// Buffers currently available in the ring for the kernel to select.
    pub fn free(&self) -> u32 {
        self.ring_entries().saturating_sub(self.outstanding)
    }

    /// Get a pointer and length for a buffer by its ID.
    pub fn get_buffer(&self, bid: u16) -> (*const u8, u32) {
        let offset = bid as usize * self.buf_size as usize;
        let ptr = unsafe { self.mem.as_ptr().add(offset) as *const u8 };
        (ptr, self.buf_size)
    }

    /// Batch replenish multiple buffers counted out by `on_handout`. Returns
    /// them to the ring and accounts them against `outstanding`.
    pub fn replenish_batch(&mut self, bids: &[u16]) {
        for &bid in bids {
            self.push_entry(bid);
        }
        if !bids.is_empty() {
            // Tripwire: replenishing more buffers than are outstanding means a bid
            // was returned to the ring more than once (a double-replenish).
            // `saturating_sub` keeps the count from underflowing in release; this
            // catches the bug in debug and tests.
            debug_assert!(
                self.outstanding >= bids.len() as u32,
                "double-replenish: returning {} buffers but only {} outstanding",
                bids.len(),
                self.outstanding,
            );
            self.outstanding = self.outstanding.saturating_sub(bids.len() as u32);
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
        let buf_addr = unsafe { self.mem.as_ptr().add(buf_offset) };
        // `resv` is not written: in entry 0 it is the tail the kernel reads
        // (see `commit_tail`), and writing it would publish a tail before
        // `commit_tail` does. liburing's `io_uring_buf_ring_add` writes the
        // same three fields.
        unsafe {
            ptr::addr_of_mut!((*entry_ptr).addr).write(buf_addr as u64);
            ptr::addr_of_mut!((*entry_ptr).len).write(self.buf_size);
            ptr::addr_of_mut!((*entry_ptr).bid).write(bid);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupancy_tracks_handout_and_replenish() {
        let mut ring = ProvidedBufRing::new(0, 8, 4096).expect("ring");
        // All 8 buffers start free (pre-filled), none outstanding.
        assert_eq!(ring.ring_entries(), 8);
        assert_eq!(ring.free(), 8);

        // Hand out 3.
        for _ in 0..3 {
            ring.on_handout();
        }
        assert_eq!(ring.free(), 5);

        // Replenish 2 (bids are arbitrary here; accounting is by count).
        ring.replenish_batch(&[0, 1]);
        assert_eq!(ring.free(), 7);

        // Replenish the last outstanding one.
        ring.replenish_batch(&[2]);
        assert_eq!(ring.free(), 8);
    }

    /// Replenishing more than are outstanding is a double-replenish; the debug
    /// tripwire fires in debug builds (where tests normally run).
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "double-replenish")]
    fn double_replenish_trips_debug_assert() {
        let mut ring = ProvidedBufRing::new(0, 4, 4096).expect("ring");
        // Nothing outstanding → returning 3 buffers is a double-replenish.
        ring.replenish_batch(&[0, 1, 2]);
    }

    /// In release builds (tripwire compiled out) the `saturating_sub` still keeps
    /// `free()` from underflowing.
    #[test]
    #[cfg(not(debug_assertions))]
    fn replenish_saturates_never_underflows() {
        let mut ring = ProvidedBufRing::new(0, 4, 4096).expect("ring");
        ring.replenish_batch(&[0, 1, 2]);
        assert_eq!(ring.free(), 4);
        assert_eq!(ring.ring_entries(), 4);
    }

    /// The tail the kernel reads, at offset 14 of ring entry 0.
    fn committed_tail(ring: &ProvidedBufRing) -> u16 {
        // Safety: the ring mapping is at least one entry long.
        unsafe { (*ring.ring_ptr.add(14).cast::<AtomicU16>()).load(atomic::Ordering::Acquire) }
    }

    /// Writing ring entry 0 must leave the committed tail alone: it is the
    /// same two bytes as that entry's `resv`, and the kernel reads it before
    /// `commit_tail` runs whenever it selects a buffer on another thread
    /// (SQPOLL).
    #[test]
    fn writing_entry_zero_leaves_the_committed_tail() {
        let mut ring = ProvidedBufRing::new(0, 4, 4096).expect("ring");
        assert_eq!(committed_tail(&ring), 4);
        for _ in 0..4 {
            ring.on_handout();
        }
        // The next entry written is ring index 4 & 3 = 0.
        ring.push_entry(0);
        assert_eq!(committed_tail(&ring), 4, "push_entry wrote the tail");
        ring.commit_tail();
        assert_eq!(committed_tail(&ring), 5);
    }

    /// The kernel acts on the tail `push_entry` leaves in ring entry 0. With
    /// every buffer handed out and entry 0 written but not committed, a recv
    /// that selects a buffer must find none; a tail of 0 read as 65532 free
    /// entries would hand it entry 1, a buffer the application still holds.
    #[cfg(uring_engine)]
    #[test]
    fn the_kernel_selects_no_buffer_before_commit_tail() {
        use crate::backend::uring::engine::uring::{
            IORING_REGISTER_PBUF_RING, pbuf_ring_register, retry_with_resv_set,
        };
        use crate::memlock::KernelVersion;
        use io_uring::{IoUring, opcode, squeue, types};
        use std::os::fd::AsRawFd;

        const BGID: u16 = 9;
        let mut provided = ProvidedBufRing::new(BGID, 4, 4096).expect("provided ring");
        // Ring setup and registration are charged to the user's locked memory,
        // shared with test processes running alongside, so ENOMEM is retried
        // for up to 5 s as `make_test_loop` does (#589).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let retry = |e: &std::io::Error| {
            let again =
                e.raw_os_error() == Some(libc::ENOMEM) && std::time::Instant::now() < deadline;
            if again {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            again
        };
        let mut ring = loop {
            match IoUring::new(8) {
                Ok(ring) => break ring,
                Err(e) if retry(&e) => {}
                Err(e) => panic!("io_uring: {e}"),
            }
        };
        let (addr, entries) = (provided.ring_addr(), provided.ring_entries());
        let fd = ring.as_raw_fd();
        let mut resv0 = 0;
        loop {
            // Safety: `provided` outlives `ring`, which is dropped first.
            let registered = unsafe {
                pbuf_ring_register(fd, IORING_REGISTER_PBUF_RING, addr, entries, BGID, 0, resv0)
            };
            match registered {
                Ok(()) => break,
                Err(e) if resv0 == 0 && retry_with_resv_set(&e, KernelVersion::current()) => {
                    resv0 = 1;
                }
                Err(e) if retry(&e) => {}
                Err(e) => panic!("register: {e}"),
            }
        }
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(server.local_addr().unwrap()).unwrap();
        let recv = |ring: &mut IoUring, n: usize| -> Vec<i32> {
            for i in 0..n {
                client.send(b"x").unwrap();
                let sqe =
                    opcode::Recv::new(types::Fd(server.as_raw_fd()), std::ptr::null_mut(), 4096)
                        .buf_group(BGID)
                        .build()
                        .flags(squeue::Flags::BUFFER_SELECT)
                        .user_data(i as u64);
                // Safety: the recv selects its buffer from `provided`, which
                // outlives the ring.
                unsafe { ring.submission().push(&sqe).unwrap() };
            }
            ring.submit_and_wait(n).unwrap();
            ring.completion().map(|c| c.result()).collect()
        };
        // Hand out every buffer.
        let taken = recv(&mut ring, 4);
        assert!(taken.iter().all(|&r| r == 1), "{taken:?}");
        for _ in 0..4 {
            provided.on_handout();
        }
        // Return bid 0 to ring index 0, without committing the tail.
        provided.push_entry(0);
        let results = recv(&mut ring, 2);
        assert_eq!(
            results,
            vec![-libc::ENOBUFS, -libc::ENOBUFS],
            "the kernel selected a buffer the committed tail does not offer"
        );
        drop(ring);
    }

    #[test]
    fn free_reaches_zero_when_fully_drained() {
        let mut ring = ProvidedBufRing::new(0, 4, 4096).expect("ring");
        for _ in 0..4 {
            ring.on_handout();
        }
        assert_eq!(ring.free(), 0);
    }
}
