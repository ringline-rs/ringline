use std::mem::{self, MaybeUninit};

use crate::buffer::fixed::RegionId;

/// Trait for user-provided zero-copy send guards.
///
/// The guard owns, or keeps alive, the bytes a send transmits without copying
/// them. The runtime holds it until the kernel's zero-copy notification
/// arrives, or, on a Unix-domain connection (io_uring) and on the mio backend,
/// until the send has copied the bytes. Implement this for cache or storage
/// types whose values are sent in place.
///
/// The runtime reads [`as_bytes`](Self::as_bytes) for the kernel after the
/// guard is stored where it stays until it is dropped, and does not move the
/// guard, call it again, or give out `&mut` access to it until then. A guard
/// whose bytes are inside the guard value itself, or that is moved between
/// calls, is therefore sent from where it lives at the send.
///
/// `as_bytes` must return the same bytes on every call. The runtime may call
/// it more than once for one send, and the protocol clients encode the length
/// into a request header before the send reads the bytes. A guard that
/// returns different bytes produces a wrong send or a malformed request; it
/// does not make the runtime read memory the guard does not own.
///
/// A guard over memory that Rust does not track, such as a value in a
/// registered region kept alive by a reference count, builds the slice with
/// `unsafe { std::slice::from_raw_parts(..) }` inside `as_bytes`, and that
/// `unsafe` block is where it states why the memory stays valid and unwritten
/// while the guard is alive.
pub trait SendGuard: Send + 'static {
    /// The bytes to send. At most `u32::MAX` bytes; a send refuses a longer
    /// slice with `InvalidInput`.
    fn as_bytes(&self) -> &[u8];
    /// The registered memory region this data belongs to, or
    /// [`RegionId::UNREGISTERED`]. When every guard of a send names the same
    /// registered region, the send may reference the region's slot until it
    /// completes; see
    /// [`Runtime::unregister_region`](crate::Runtime::unregister_region). A
    /// send refuses a guard whose bytes are not inside the region it names.
    fn region(&self) -> RegionId;
}

/// VTable for type-erased GuardBox.
struct GuardVTable {
    drop_fn: unsafe fn(*mut u8),
    as_bytes_fn: unsafe fn(*const u8) -> *const [u8],
    region_fn: unsafe fn(*const u8) -> RegionId,
}

/// Inline type-erased storage for a `SendGuard` (64 bytes max, 8-byte aligned).
/// Avoids heap allocation for typical guards (~48 bytes).
pub struct GuardBox {
    storage: [MaybeUninit<u64>; 8], // 64 bytes, 8-byte aligned
    vtable: &'static GuardVTable,
}

// Safety: GuardBox only stores `SendGuard: Send` types.
unsafe impl Send for GuardBox {}

impl GuardBox {
    /// Create a new `GuardBox` from a concrete `SendGuard`.
    ///
    /// # Panics
    /// Panics if `size_of::<G>() > 64` or `align_of::<G>() > 8`.
    pub fn new<G: SendGuard>(guard: G) -> Self {
        assert!(
            mem::size_of::<G>() <= 64,
            "SendGuard type {} is {} bytes, max 64",
            std::any::type_name::<G>(),
            mem::size_of::<G>(),
        );
        assert!(
            mem::align_of::<G>() <= 8,
            "SendGuard type {} has alignment {}, max 8",
            std::any::type_name::<G>(),
            mem::align_of::<G>(),
        );

        let mut storage: [MaybeUninit<u64>; 8] = [MaybeUninit::uninit(); 8];

        // Safety: We checked size <= 64 and alignment <= 8 above.
        // [MaybeUninit<u64>; 8] is 64 bytes with 8-byte alignment.
        unsafe {
            let ptr = storage.as_mut_ptr() as *mut G;
            ptr.write(guard);
        }

        GuardBox {
            storage,
            vtable: vtable_for::<G>(),
        }
    }

    /// The guarded bytes: [`SendGuard::as_bytes`] of the boxed guard.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `storage` holds a live `G` (written in `new`, dropped only
        // in `Drop`), and the slice `as_bytes_fn` returns borrows that `G`, so
        // it lives as long as `&self`.
        unsafe { &*(self.vtable.as_bytes_fn)(self.storage.as_ptr() as *const u8) }
    }

    /// Get the region ID of the guarded data.
    pub fn region(&self) -> RegionId {
        unsafe { (self.vtable.region_fn)(self.storage.as_ptr() as *const u8) }
    }
}

impl Drop for GuardBox {
    fn drop(&mut self) {
        let drop_fn = self.vtable.drop_fn;
        let ptr = self.storage.as_mut_ptr() as *mut u8;
        // `Drop` is user code, and a worker can run it from a completion
        // handler, where a panic would end the worker.
        if crate::runtime::waker::on_worker() {
            let dropped =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe { drop_fn(ptr) }));
            if let Err(payload) = dropped {
                crate::task_panic::note_guard_drop_panic(payload);
            }
        } else {
            unsafe { drop_fn(ptr) }
        }
    }
}

unsafe fn guard_drop<G: SendGuard>(ptr: *mut u8) {
    unsafe { std::ptr::drop_in_place(ptr as *mut G) };
}

unsafe fn guard_as_bytes<G: SendGuard>(ptr: *const u8) -> *const [u8] {
    let guard = unsafe { &*(ptr as *const G) };
    guard.as_bytes()
}

unsafe fn guard_region<G: SendGuard>(ptr: *const u8) -> RegionId {
    let guard = unsafe { &*(ptr as *const G) };
    guard.region()
}

fn vtable_for<G: SendGuard>() -> &'static GuardVTable {
    trait HasVTable {
        const VTABLE: GuardVTable;
    }
    impl<G: SendGuard> HasVTable for G {
        const VTABLE: GuardVTable = GuardVTable {
            drop_fn: guard_drop::<G>,
            as_bytes_fn: guard_as_bytes::<G>,
            region_fn: guard_region::<G>,
        };
    }
    &<G as HasVTable>::VTABLE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestGuard {
        data: Arc<[u8]>,
        region: RegionId,
        dropped: Arc<AtomicBool>,
    }

    impl SendGuard for TestGuard {
        fn as_bytes(&self) -> &[u8] {
            &self.data
        }
        fn region(&self) -> RegionId {
            self.region
        }
    }

    impl Drop for TestGuard {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn round_trip_bytes_region() {
        let data: Arc<[u8]> = Arc::from(&[1u8, 2, 3, 4, 5][..]);
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = TestGuard {
            data: data.clone(),
            region: RegionId(42),
            dropped: dropped.clone(),
        };

        let boxed = GuardBox::new(guard);
        assert_eq!(boxed.as_bytes().as_ptr(), data.as_ptr());
        assert_eq!(boxed.as_bytes(), &[1, 2, 3, 4, 5]);
        assert_eq!(boxed.region(), RegionId(42));
        assert!(!dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn drop_runs() {
        let dropped = Arc::new(AtomicBool::new(false));
        {
            let guard = TestGuard {
                data: Arc::from(&[0u8; 10][..]),
                region: RegionId(0),
                dropped: dropped.clone(),
            };
            let _boxed = GuardBox::new(guard);
            assert!(!dropped.load(Ordering::SeqCst));
        }
        assert!(dropped.load(Ordering::SeqCst));
    }

    /// Zero-size guard (no data stored, just region tracking).
    struct ZeroSizeGuard;

    impl SendGuard for ZeroSizeGuard {
        fn as_bytes(&self) -> &[u8] {
            &[]
        }
        fn region(&self) -> RegionId {
            RegionId(99)
        }
    }

    #[test]
    fn zero_size_guard() {
        assert_eq!(std::mem::size_of::<ZeroSizeGuard>(), 0);
        let boxed = GuardBox::new(ZeroSizeGuard);
        assert!(boxed.as_bytes().is_empty());
        assert_eq!(boxed.region(), RegionId(99));
    }

    /// Guard that uses the full 64 bytes and holds its bytes inline.
    #[repr(C)]
    struct MaxSizeGuard {
        data: [u8; 64],
    }

    impl SendGuard for MaxSizeGuard {
        fn as_bytes(&self) -> &[u8] {
            &self.data
        }
        fn region(&self) -> RegionId {
            RegionId(1)
        }
    }

    #[test]
    fn max_size_guard_reads_its_inline_bytes_where_it_is_stored() {
        let boxed = GuardBox::new(MaxSizeGuard { data: [0xAB; 64] });
        let bytes = boxed.as_bytes();
        assert_eq!(bytes.len(), 64);
        assert!(bytes.iter().all(|&b| b == 0xAB));
        let storage = boxed.storage.as_ptr() as *const u8;
        assert_eq!(bytes.as_ptr(), storage);
    }
}
