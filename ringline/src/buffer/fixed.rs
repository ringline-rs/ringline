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
        MemoryRegion { ptr, len }
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
    /// Sentinel for guards whose memory is not in a registered io_uring region.
    /// Guards with this region skip pointer validation in `submit_with_guards`.
    pub const UNREGISTERED: Self = RegionId(u16::MAX);
}

/// Registry of user-registered memory regions for io_uring fixed buffers.
///
/// The iovec array contains only user-registered regions (no library-managed send buffers).
pub struct FixedBufferRegistry {
    iovecs: Vec<libc::iovec>,
    #[allow(dead_code)] // used by test-only region_id()
    region_count: u16,
}

impl FixedBufferRegistry {
    /// Create a new registry from user-registered memory regions.
    pub fn new(regions: &[MemoryRegion]) -> Self {
        let mut iovecs = Vec::with_capacity(regions.len());
        for region in regions {
            iovecs.push(libc::iovec {
                iov_base: region.ptr() as *mut _,
                iov_len: region.len(),
            });
        }
        FixedBufferRegistry {
            iovecs,
            region_count: regions.len() as u16,
        }
    }

    /// Get the iovecs slice for `register_buffers()`.
    pub fn iovecs(&self) -> &[libc::iovec] {
        &self.iovecs
    }

    /// Total number of registered iovecs.
    #[cfg(test)]
    pub fn total_count(&self) -> usize {
        self.iovecs.len()
    }

    /// Get the RegionId for a user-registered region by its index (0-based).
    #[cfg(test)]
    pub fn region_id(&self, region_index: u16) -> Option<RegionId> {
        if region_index < self.region_count {
            Some(RegionId(region_index))
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
        let reg = FixedBufferRegistry::new(&[]);
        assert_eq!(reg.total_count(), 0);
        assert_eq!(reg.region_id(0), None);
    }

    #[test]
    fn region_id_mapping() {
        let mut backing = vec![0u8; 4096];
        let regions = vec![unsafe { MemoryRegion::new(backing.as_mut_ptr(), 4096) }];
        let reg = FixedBufferRegistry::new(&regions);
        assert_eq!(reg.region_id(0), Some(RegionId(0)));
        assert_eq!(reg.region_id(1), None);
        assert_eq!(reg.total_count(), 1);
    }

    #[test]
    fn validate_region_ptr_ok() {
        let mut backing = vec![0u8; 4096];
        let ptr = backing.as_mut_ptr();
        let regions = vec![unsafe { MemoryRegion::new(ptr, 4096) }];
        let reg = FixedBufferRegistry::new(&regions);
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
        let reg = FixedBufferRegistry::new(&regions);
        let rid = reg.region_id(0).unwrap();

        // Past end
        assert!(
            reg.validate_region_ptr(rid, unsafe { ptr.add(4000) }, 200)
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
        let reg = FixedBufferRegistry::new(&regions);
        assert_eq!(reg.total_count(), 2);
        assert_eq!(reg.iovecs()[0].iov_len, 4096);
        assert_eq!(reg.iovecs()[1].iov_len, 8192);
        assert_eq!(reg.region_id(0), Some(RegionId(0)));
        assert_eq!(reg.region_id(1), Some(RegionId(1)));
        assert_eq!(reg.region_id(2), None);
    }
}
