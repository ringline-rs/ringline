use crate::guard::GuardBox;

pub const MAX_IOVECS: usize = 8;
pub const MAX_GUARDS: usize = 4;

/// Slab for in-flight scatter-gather sends with zero-copy guards.
///
/// Each entry tracks iovecs (copy parts + guard parts), an msghdr for the kernel,
/// a pool slot for copied data, and the guards that keep registered memory alive
/// until ZC notifications arrive.
pub struct InFlightSendSlab {
    entries: Vec<InFlightSendEntry>,
    free_list: Vec<u16>,
}

struct InFlightSendEntry {
    iovecs: [libc::iovec; MAX_IOVECS],
    iov_count: u8,
    /// Index into iovecs where the next resubmit starts (advances on partial send).
    iov_start: u8,
    msghdr: libc::msghdr,
    /// SendCopyPool slot index. u16::MAX means no pool slot.
    pool_slot: u16,
    guards: [Option<GuardBox>; MAX_GUARDS],
    guard_count: u8,
    conn_index: u32,
    total_len: u32,
    pending_notifs: u8,
    awaiting_notifications: bool,
    in_use: bool,
}

impl InFlightSendSlab {
    /// Create a slab with `capacity` slots.
    pub fn new(capacity: u16) -> Self {
        let mut entries = Vec::with_capacity(capacity as usize);
        for _ in 0..capacity {
            entries.push(InFlightSendEntry {
                iovecs: [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; MAX_IOVECS],
                iov_count: 0,
                iov_start: 0,
                msghdr: unsafe { std::mem::zeroed() },
                pool_slot: u16::MAX,
                guards: [None, None, None, None],
                guard_count: 0,
                conn_index: 0,
                total_len: 0,
                pending_notifs: 0,
                awaiting_notifications: false,
                in_use: false,
            });
        }
        let free_list: Vec<u16> = (0..capacity).rev().collect();
        InFlightSendSlab { entries, free_list }
    }

    /// Allocate a slot, store iovecs/guards, and return (slab_index, msghdr_ptr).
    /// Returns `None` if the slab is full.
    ///
    /// `iovecs_slice` must have length <= MAX_IOVECS.
    /// `guards` is an array of `Option<GuardBox>` to move into the entry.
    /// `guard_count` is the number of Some guards.
    pub fn allocate(
        &mut self,
        conn_index: u32,
        iovecs_slice: &[libc::iovec],
        pool_slot: u16,
        guards: [Option<GuardBox>; MAX_GUARDS],
        guard_count: u8,
        total_len: u32,
    ) -> Option<(u16, *const libc::msghdr)> {
        debug_assert!(iovecs_slice.len() <= MAX_IOVECS);
        let idx = self.free_list.pop()?;
        let entry = &mut self.entries[idx as usize];

        // Copy iovecs
        for (i, iov) in iovecs_slice.iter().enumerate() {
            entry.iovecs[i] = *iov;
        }
        entry.iov_count = iovecs_slice.len() as u8;
        entry.iov_start = 0;
        entry.pool_slot = pool_slot;
        entry.guards = guards;
        entry.guard_count = guard_count;
        entry.conn_index = conn_index;
        entry.total_len = total_len;
        entry.pending_notifs = 0;
        entry.awaiting_notifications = false;
        entry.in_use = true;

        // Build msghdr
        entry.msghdr = unsafe { std::mem::zeroed() };
        entry.msghdr.msg_iov = entry.iovecs.as_mut_ptr();
        entry.msghdr.msg_iovlen = entry.iov_count as _;

        Some((idx, &entry.msghdr as *const libc::msghdr))
    }

    /// Advance past `bytes_sent` bytes in the iovec array.
    /// Returns `Some(msghdr_ptr)` if there are remaining bytes to send (partial resubmit).
    /// Returns `None` if all data has been sent.
    #[allow(clippy::mut_range_bound)]
    pub fn try_advance(&mut self, idx: u16, bytes_sent: u32) -> Option<*const libc::msghdr> {
        let entry = &mut self.entries[idx as usize];
        debug_assert!(entry.in_use);

        let mut skip = bytes_sent as usize;
        let count = entry.iov_count as usize;
        let mut new_start = entry.iov_start as usize;

        for i in new_start..count {
            if skip >= entry.iovecs[i].iov_len {
                skip -= entry.iovecs[i].iov_len;
                new_start = i + 1;
            } else {
                // Partial iovec — adjust in place
                entry.iovecs[i].iov_base =
                    (entry.iovecs[i].iov_base as *mut u8).wrapping_add(skip) as *mut _;
                entry.iovecs[i].iov_len -= skip;
                new_start = i;
                break;
            }
        }

        entry.iov_start = new_start as u8;

        if new_start >= count {
            return None; // Fully sent
        }

        // Rebuild msghdr for remaining iovecs
        entry.msghdr.msg_iov = entry.iovecs[new_start..].as_mut_ptr();
        entry.msghdr.msg_iovlen = (count - new_start) as _;

        Some(&entry.msghdr as *const libc::msghdr)
    }

    /// Increment pending notification count for an entry.
    pub fn inc_pending_notifs(&mut self, idx: u16) {
        self.entries[idx as usize].pending_notifs += 1;
    }

    /// Decrement pending notification count. Returns the new count.
    pub fn dec_pending_notifs(&mut self, idx: u16) -> u8 {
        let entry = &mut self.entries[idx as usize];
        debug_assert!(
            entry.pending_notifs > 0,
            "notification underflow for slab entry {idx}"
        );
        entry.pending_notifs -= 1;
        entry.pending_notifs
    }

    /// Mark that the operation CQE has been received and we're waiting for notifications.
    pub fn mark_awaiting_notifications(&mut self, idx: u16) {
        self.entries[idx as usize].awaiting_notifications = true;
    }

    /// Check if this entry should be released (all notifications received after operation complete).
    pub fn should_release(&self, idx: u16) -> bool {
        let entry = &self.entries[idx as usize];
        entry.pending_notifs == 0 && entry.awaiting_notifications
    }

    /// Release a slab entry. Drops guards, returns the pool_slot, pushes to free list.
    pub fn release(&mut self, idx: u16) -> u16 {
        let entry = &mut self.entries[idx as usize];
        debug_assert!(entry.in_use);

        let pool_slot = entry.pool_slot;

        // Drop all guards
        for g in entry.guards.iter_mut() {
            *g = None;
        }
        entry.guard_count = 0;
        entry.pool_slot = u16::MAX;
        entry.in_use = false;
        entry.awaiting_notifications = false;
        entry.pending_notifs = 0;

        self.free_list.push(idx);
        pool_slot
    }

    /// Get the total original send length for an entry.
    pub fn total_len(&self, idx: u16) -> u32 {
        self.entries[idx as usize].total_len
    }

    /// Get the connection index for an entry.
    pub fn conn_index(&self, idx: u16) -> u32 {
        self.entries[idx as usize].conn_index
    }

    /// Check if an entry is in use.
    pub fn in_use(&self, idx: u16) -> bool {
        self.entries[idx as usize].in_use
    }

    /// Number of free slots.
    pub fn free_count(&self) -> usize {
        self.free_list.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::fixed::RegionId;
    use crate::guard::SendGuard;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TestGuard {
        ptr: *const u8,
        len: u32,
        region: RegionId,
        drop_counter: Arc<AtomicU32>,
    }

    unsafe impl Send for TestGuard {}

    impl SendGuard for TestGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.ptr, self.len)
        }
        fn region(&self) -> RegionId {
            self.region
        }
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            self.drop_counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn allocate_and_release() {
        let mut slab = InFlightSendSlab::new(4);
        assert_eq!(slab.free_count(), 4);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards: [Option<GuardBox>; MAX_GUARDS] = [None, None, None, None];
        let (idx, ptr) = slab
            .allocate(42, &iovecs, u16::MAX, guards, 0, 100)
            .unwrap();
        assert_eq!(slab.free_count(), 3);
        assert!(!ptr.is_null());
        assert_eq!(slab.conn_index(idx), 42);
        assert_eq!(slab.total_len(idx), 100);

        let pool_slot = slab.release(idx);
        assert_eq!(pool_slot, u16::MAX);
        assert_eq!(slab.free_count(), 4);
    }

    #[test]
    fn partial_advance() {
        let mut slab = InFlightSendSlab::new(4);

        let mut data1 = [1u8; 50];
        let mut data2 = [2u8; 30];
        let mut data3 = [3u8; 20];

        let iovecs = [
            libc::iovec {
                iov_base: data1.as_mut_ptr() as *mut _,
                iov_len: 50,
            },
            libc::iovec {
                iov_base: data2.as_mut_ptr() as *mut _,
                iov_len: 30,
            },
            libc::iovec {
                iov_base: data3.as_mut_ptr() as *mut _,
                iov_len: 20,
            },
        ];

        let guards: [Option<GuardBox>; MAX_GUARDS] = [None, None, None, None];
        let (idx, _) = slab.allocate(0, &iovecs, u16::MAX, guards, 0, 100).unwrap();

        // Partial send: 50 bytes (entire first iovec)
        let result = slab.try_advance(idx, 50);
        assert!(result.is_some());

        // Partial send: 10 bytes (partial second iovec)
        let result = slab.try_advance(idx, 10);
        assert!(result.is_some());

        // Partial send: 20 + 20 = 40 bytes (rest of second + all of third)
        let result = slab.try_advance(idx, 40);
        assert!(result.is_none()); // Fully sent

        slab.release(idx);
    }

    #[test]
    fn notification_counting() {
        let mut slab = InFlightSendSlab::new(4);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards: [Option<GuardBox>; MAX_GUARDS] = [None, None, None, None];
        let (idx, _) = slab.allocate(0, &iovecs, u16::MAX, guards, 0, 100).unwrap();

        slab.inc_pending_notifs(idx);
        slab.inc_pending_notifs(idx);
        assert!(!slab.should_release(idx));

        slab.mark_awaiting_notifications(idx);
        assert!(!slab.should_release(idx));

        assert_eq!(slab.dec_pending_notifs(idx), 1);
        assert!(!slab.should_release(idx));

        assert_eq!(slab.dec_pending_notifs(idx), 0);
        assert!(slab.should_release(idx));

        slab.release(idx);
    }

    #[test]
    fn multi_guard_drop() {
        let counter = Arc::new(AtomicU32::new(0));
        let data = [0u8; 10];

        let mut slab = InFlightSendSlab::new(4);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 10,
        }];

        let g1 = GuardBox::new(TestGuard {
            ptr: data.as_ptr(),
            len: 10,
            region: RegionId(0),
            drop_counter: counter.clone(),
        });
        let g2 = GuardBox::new(TestGuard {
            ptr: data.as_ptr(),
            len: 10,
            region: RegionId(0),
            drop_counter: counter.clone(),
        });

        let guards: [Option<GuardBox>; MAX_GUARDS] = [Some(g1), Some(g2), None, None];
        let (idx, _) = slab.allocate(0, &iovecs, 5, guards, 2, 10).unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
        let pool_slot = slab.release(idx);
        assert_eq!(pool_slot, 5);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn exhaust_slab() {
        let mut slab = InFlightSendSlab::new(1);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 10,
        }];
        let guards: [Option<GuardBox>; MAX_GUARDS] = [None, None, None, None];
        let _ = slab.allocate(0, &iovecs, u16::MAX, guards, 0, 10).unwrap();

        let guards2: [Option<GuardBox>; MAX_GUARDS] = [None, None, None, None];
        assert!(
            slab.allocate(0, &iovecs, u16::MAX, guards2, 0, 10)
                .is_none()
        );
    }
}
