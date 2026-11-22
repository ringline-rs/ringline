/// A user-registered memory region (e.g., mmap'd storage arena).
///
/// # Safety
///
/// The caller must ensure:
/// - `ptr` is valid for reads and writes of `len` bytes.
/// - The memory remains mapped and valid for the entire lifetime of the
///   runtime (i.e., until all workers shut down).
/// - No other code frees or unmaps the region while the driver holds it.
#[derive(Clone)]
pub struct MemoryRegion {
    ptr: *mut u8,
    len: usize,
    /// Whether `/proc/self/smaps` showed the region to be in base pages only
    /// when it was registered (`smaps::base_pages_in`). Set by the
    /// registration, never by the caller.
    pub(crate) base_pages: bool,
}

impl MemoryRegion {
    /// Create a new memory region from a raw pointer and length.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and valid for reads/writes of `len` bytes.
    /// - The memory must remain mapped for the lifetime of the runtime.
    /// - The caller retains ownership and must not free/unmap the memory
    ///   until after the runtime is dropped.
    pub unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        debug_assert!(!ptr.is_null(), "MemoryRegion: ptr must not be null");
        MemoryRegion {
            ptr,
            len,
            base_pages: false,
        }
    }

    /// Get the pointer to the memory region.
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the length of the memory region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the memory region has zero length.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// Safety: Memory regions are managed by the user and must outlive the driver.
unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

/// Identifies a registered memory region (index into the iovec array).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionId(pub(crate) u16);

impl RegionId {
    /// Sentinel for memory not in a registered io_uring region: the default
    /// of `IoBuf::region`. A guard or disk buffer that returns it is
    /// submitted without the range check and without a fixed-buffer index.
    pub const UNREGISTERED: Self = RegionId(u16::MAX);
}

/// Whether guard-only sends from one registered region name the region's
/// buffer (`IORING_RECVSEND_FIXED_BUF`)
/// ([`ConfigBuilder::fixed_buffer_sends`](crate::ConfigBuilder::fixed_buffer_sends)),
/// as [`Runtime::region_fixed_buffer_sends`](crate::Runtime::region_fixed_buffer_sends)
/// reports it for a region and
/// [`Runtime::fixed_buffer_sends`](crate::Runtime::fixed_buffer_sends) for
/// regions not in base pages only.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FixedBufferSends {
    /// A send of one guard in a registered region names that region's
    /// buffer (`SEND_ZC`), and the kernel does not look up and pin its pages.
    /// With `multi_guard`, so does a send of several guards that all lie in
    /// one region (`SENDMSG_ZC`, which takes the flag from Linux 6.15).
    Enabled {
        /// Sends of several guards in one region name its buffer too.
        multi_guard: bool,
    },
    /// [`ConfigBuilder::fixed_buffer_sends`](crate::ConfigBuilder::fixed_buffer_sends)
    /// is `false`.
    Disabled,
    /// The backend is mio, or the kernel refuses `IORING_RECVSEND_FIXED_BUF`
    /// on `SEND_ZC`.
    Unsupported,
    /// The kernel charges a send from a registered buffer that lies in a huge
    /// page to the socket's send buffer by the send's offset in the page, up
    /// to the page's size, instead of by the bytes sent. Sending from it would
    /// exhaust the send buffer and stall the connection. Linux 6.3 and later
    /// show this unless they carry the fix to `io_sg_from_iter`'s charge
    /// (<https://lore.kernel.org/io-uring/20261119232935.1708458-1-thiery.louis@gmail.com/>).
    Overcharged,
    /// The probe could not decide, for the reason given: for example, no
    /// transparent huge page was available for its buffer, or
    /// `RLIMIT_MEMLOCK` had no room to register it. Fixed sends stay off.
    Inconclusive(String),
}

/// Registry of user-registered memory regions for io_uring fixed buffers.
///
/// The iovec array is sized to `max_regions` at construction time and matches
/// the kernel's sparse registered-buffer table. Unoccupied slots have a null
/// `iov_base`; occupied slots point at user memory.
pub struct FixedBufferRegistry {
    /// Full-size iovec array. `iov_base == null` indicates an empty slot.
    iovecs: Vec<libc::iovec>,
    /// `MemoryRegion::base_pages` of the region in each slot, `false` for an
    /// empty slot.
    base_pages: Vec<bool>,
}

impl FixedBufferRegistry {
    /// Create a new registry sized for `max_regions` slots, with `initial`
    /// regions occupying the first `initial.len()` slots.
    ///
    /// Panics if `initial.len() > max_regions`.
    pub fn new(initial: &[MemoryRegion], max_regions: u16) -> Self {
        let max = max_regions as usize;
        assert!(
            initial.len() <= max,
            "initial regions ({}) exceed max_regions ({max})",
            initial.len(),
        );
        let mut iovecs = vec![
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            };
            max
        ];
        let mut base_pages = vec![false; max];
        for (slot, region) in initial.iter().enumerate() {
            iovecs[slot] = libc::iovec {
                iov_base: region.ptr() as *mut _,
                iov_len: region.len(),
            };
            base_pages[slot] = region.base_pages;
        }
        FixedBufferRegistry { iovecs, base_pages }
    }

    /// Get the full iovec slice, including empty slots. Used by the kernel
    /// sparse-registration path.
    pub fn iovecs(&self) -> &[libc::iovec] {
        &self.iovecs
    }

    /// Returns true if the slot is currently occupied.
    #[allow(dead_code)] // unused on the mio backend
    pub fn is_occupied(&self, slot: u16) -> bool {
        self.iovecs
            .get(slot as usize)
            .is_some_and(|iov| !iov.iov_base.is_null())
    }

    /// Place a region in the given slot. The slot must be empty.
    ///
    /// Returns `Err` if the slot is out of range or already occupied.
    pub fn set_slot(
        &mut self,
        slot: u16,
        region: &MemoryRegion,
    ) -> Result<(), crate::error::Error> {
        let idx = slot as usize;
        if idx >= self.iovecs.len() {
            return Err(crate::error::Error::InvalidRegion);
        }
        if !self.iovecs[idx].iov_base.is_null() {
            return Err(crate::error::Error::InvalidRegion);
        }
        self.iovecs[idx] = libc::iovec {
            iov_base: region.ptr() as *mut _,
            iov_len: region.len(),
        };
        self.base_pages[idx] = region.base_pages;
        Ok(())
    }

    /// Whether the region in `slot` was shown to be in base pages only when
    /// it was registered; `false` for an empty slot.
    #[allow(dead_code)] // unused on the mio backend
    pub(crate) fn base_pages(&self, slot: u16) -> bool {
        self.base_pages.get(slot as usize).copied().unwrap_or(false)
    }

    /// Clear the given slot. Returns `Err` if out of range or already empty.
    pub fn clear_slot(&mut self, slot: u16) -> Result<(), crate::error::Error> {
        let idx = slot as usize;
        if idx >= self.iovecs.len() {
            return Err(crate::error::Error::InvalidRegion);
        }
        if self.iovecs[idx].iov_base.is_null() {
            return Err(crate::error::Error::InvalidRegion);
        }
        self.iovecs[idx] = libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        };
        self.base_pages[idx] = false;
        Ok(())
    }

    /// Get the iovec at a slot, if occupied.
    #[allow(dead_code)] // public on registry surface, currently unused outside tests
    pub fn iovec_at(&self, slot: u16) -> Option<libc::iovec> {
        self.iovecs
            .get(slot as usize)
            .copied()
            .filter(|iov| !iov.iov_base.is_null())
    }

    /// Total number of slots (occupied or not). Equal to `max_regions`.
    #[cfg(test)]
    pub fn total_count(&self) -> usize {
        self.iovecs.len()
    }

    /// Get the RegionId for a user-registered region by its slot index, if
    /// occupied.
    #[cfg(test)]
    pub fn region_id(&self, slot: u16) -> Option<RegionId> {
        if self.is_occupied(slot) {
            Some(RegionId(slot))
        } else {
            None
        }
    }

    /// Validate that a pointer + length falls within the specified region.
    pub fn validate_region_ptr(
        &self,
        region: RegionId,
        ptr: *const u8,
        len: u32,
    ) -> Result<(), crate::error::Error> {
        let iovec_idx = region.0 as usize;
        if iovec_idx >= self.iovecs.len() {
            return Err(crate::error::Error::InvalidRegion);
        }
        let iov = &self.iovecs[iovec_idx];
        if iov.iov_base.is_null() {
            return Err(crate::error::Error::InvalidRegion);
        }
        let region_start = iov.iov_base as usize;
        let region_end = region_start + iov.iov_len;
        let ptr_start = ptr as usize;
        let ptr_end = ptr_start + len as usize;
        if ptr_start < region_start || ptr_end > region_end {
            return Err(crate::error::Error::PointerOutOfRegion);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry() {
        let reg = FixedBufferRegistry::new(&[], 4);
        assert_eq!(reg.total_count(), 4);
        assert_eq!(reg.region_id(0), None);
    }

    #[test]
    fn region_id_mapping() {
        let mut backing = vec![0u8; 4096];
        let regions = vec![unsafe { MemoryRegion::new(backing.as_mut_ptr(), 4096) }];
        let reg = FixedBufferRegistry::new(&regions, 4);
        assert_eq!(reg.region_id(0), Some(RegionId(0)));
        assert_eq!(reg.region_id(1), None);
        assert_eq!(reg.total_count(), 4);
    }

    #[test]
    fn validate_region_ptr_ok() {
        let mut backing = vec![0u8; 4096];
        let ptr = backing.as_mut_ptr();
        let regions = vec![unsafe { MemoryRegion::new(ptr, 4096) }];
        let reg = FixedBufferRegistry::new(&regions, 4);
        let rid = reg.region_id(0).unwrap();

        // Pointer at start
        assert!(reg.validate_region_ptr(rid, ptr, 100).is_ok());
        // Pointer at end
        assert!(
            reg.validate_region_ptr(rid, unsafe { ptr.add(4000) }, 96)
                .is_ok()
        );
    }

    #[test]
    fn validate_region_ptr_out_of_bounds() {
        let mut backing = vec![0u8; 4096];
        let ptr = backing.as_mut_ptr();
        let regions = vec![unsafe { MemoryRegion::new(ptr, 4096) }];
        let reg = FixedBufferRegistry::new(&regions, 4);
        let rid = reg.region_id(0).unwrap();

        // Past end
        assert!(
            reg.validate_region_ptr(rid, unsafe { ptr.add(4000) }, 200)
                .is_err()
        );
    }

    #[test]
    fn validate_region_ptr_empty_slot() {
        let reg = FixedBufferRegistry::new(&[], 4);
        // Slot 0 is empty — validation must reject any pointer.
        let dummy: u8 = 0;
        assert!(
            reg.validate_region_ptr(RegionId(0), &dummy as *const u8, 1)
                .is_err()
        );
    }

    #[test]
    fn iovecs_layout() {
        let mut backing1 = vec![0u8; 4096];
        let mut backing2 = vec![0u8; 8192];
        let regions = vec![
            unsafe { MemoryRegion::new(backing1.as_mut_ptr(), 4096) },
            unsafe { MemoryRegion::new(backing2.as_mut_ptr(), 8192) },
        ];
        let reg = FixedBufferRegistry::new(&regions, 8);
        assert_eq!(reg.total_count(), 8);
        assert_eq!(reg.iovecs()[0].iov_len, 4096);
        assert_eq!(reg.iovecs()[1].iov_len, 8192);
        assert!(reg.iovecs()[2].iov_base.is_null());
        assert_eq!(reg.region_id(0), Some(RegionId(0)));
        assert_eq!(reg.region_id(1), Some(RegionId(1)));
        assert_eq!(reg.region_id(2), None);
    }

    #[test]
    fn set_and_clear_slot() {
        let mut backing = vec![0u8; 4096];
        let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), 4096) };
        let mut reg = FixedBufferRegistry::new(&[], 4);

        // Set slot 2.
        reg.set_slot(2, &region).unwrap();
        assert!(reg.is_occupied(2));
        assert_eq!(reg.iovec_at(2).map(|i| i.iov_len), Some(4096));

        // Setting an already-occupied slot fails.
        assert!(reg.set_slot(2, &region).is_err());

        // Clearing works once.
        reg.clear_slot(2).unwrap();
        assert!(!reg.is_occupied(2));
        assert!(reg.clear_slot(2).is_err());

        // Out-of-range slot rejects.
        assert!(reg.set_slot(99, &region).is_err());
        assert!(reg.clear_slot(99).is_err());
    }
}
