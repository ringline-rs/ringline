//! Fault buffer pages in before traffic arrives, or, for a buffer that is
//! not prefaulted, advise the kernel not to back it with transparent huge
//! pages (`no_huge_pages`).
//!
//! `vec![0u8; n]` goes through `alloc_zeroed`, which for a large allocation
//! hands back mapped-but-untouched pages: the mapping exists, but every page is
//! the shared zero page until something writes to it. The first write takes a
//! minor fault. For the send copy pool, the only buffer prefaulted, that write
//! is the first send through a slot.
//!
//! Prefaulting moves that cost to launch:
//!
//! - **Latency.** Faults stop appearing in the ramp, where they show up as p99
//!   and p999 outliers rather than as a throughput number.
//! - **Memory.** The pool's pages are resident from startup, so the pool adds
//!   nothing to RSS under load, and a pool the machine cannot back runs out
//!   of memory while the worker starts rather than during a traffic burst
//!   (as an OOM kill, not an error from `launch()`).
//! - **NUMA.** First touch decides the node. Ringline builds each worker's
//!   driver after `pin_to_core` (see `worker.rs`), so prefaulting from the
//!   constructor keeps every worker's buffers on its own node. Prefaulting from
//!   an unpinned launching thread would pull every worker's buffers onto one
//!   node, so this must stay on the worker thread.
//!
//! The cost is that the whole pool is resident from startup, whether or not
//! the workload uses every slot.

/// Page size, or 4096 if the platform will not say.
///
/// A stride smaller than the true page size only does redundant writes; a
/// larger one would skip pages and silently prefault nothing. 4096 is the
/// smallest page on every platform ringline runs on, so the fallback is safe.
fn page_size() -> usize {
    // Hermit's libc has no sysconf; its base page is 4096.
    #[cfg(target_os = "hermit")]
    return 4096;
    // SAFETY: `sysconf` with a valid name has no preconditions.
    #[cfg(not(target_os = "hermit"))]
    {
        let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if n > 0 { n as usize } else { 4096 }
    }
}

/// Touch every page of `buf` so its pages are resident and private.
///
/// Writes one zero byte per page. The buffer's contents are unchanged — the
/// pages are already zero — so this is safe to call on a live allocation, and
/// callers do it once at construction.
pub(crate) fn prefault(buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    let step = page_size();
    let ptr = buf.as_mut_ptr();
    let len = buf.len();
    let mut off = 0;
    while off < len {
        // SAFETY: `off < len`, so `ptr.add(off)` is within the allocation and
        // writable through the `&mut` borrow. The write is volatile because a
        // plain store of 0 to a zeroed page that nothing subsequently reads is
        // exactly the store an optimizer is entitled to delete — and deleting
        // it would leave the page untouched, which is the whole thing this
        // function exists to prevent.
        unsafe { std::ptr::write_volatile(ptr.add(off), 0) };
        off += step;
    }
    // The final page of a buffer whose length is not a multiple of the page
    // size is covered by the loop above only if it holds a stride boundary;
    // touch the last byte so a partial trailing page is not left cold.
    // SAFETY: `len > 0`, so `len - 1` is a valid offset.
    unsafe { std::ptr::write_volatile(ptr.add(len - 1), 0) };
}

/// Advise the kernel not to back `buf` with transparent huge pages
/// (`MADV_NOHUGEPAGE`), over the whole pages inside it.
///
/// Under THP `always`, the first write to a 2 MiB-aligned range of an
/// anonymous mapping can fault in a whole huge page, and khugepaged can
/// collapse a range with one touched page into one. A send writes the first
/// bytes of a slot, so a pool of large slots used for small sends becomes
/// resident in 2 MiB pieces (#936 has measurements). The advice is ignored
/// where it fails, as on a kernel built without THP. No-op off Linux.
///
/// The advice applies to the memory, not to the allocation. A buffer that
/// the allocator served from its heap rather than a mapping of its own
/// leaves the advice on that heap range after it is freed, for whatever
/// the allocator puts there next. On 64-bit glibc, an allocation below
/// 32 MiB comes from the heap only after glibc has freed a mapped
/// allocation of at least that size; one of 32 MiB or more is always
/// mapped on its own.
pub(crate) fn no_huge_pages(buf: &mut [u8]) {
    #[cfg(target_os = "linux")]
    {
        let page = page_size();
        let addr = buf.as_mut_ptr() as usize;
        let start = addr.next_multiple_of(page);
        let end = (addr + buf.len()) / page * page;
        if end > start {
            // SAFETY: `start..end` is whole pages inside `buf`'s allocation;
            // `MADV_NOHUGEPAGE` changes no contents.
            unsafe {
                libc::madvise(
                    start as *mut libc::c_void,
                    end - start,
                    libc::MADV_NOHUGEPAGE,
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = buf;
}

/// The `VmFlags` line of the mapping in `/proc/self/smaps` that holds `addr`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn vm_flags(addr: usize) -> String {
    let smaps = std::fs::read_to_string("/proc/self/smaps").expect("read smaps");
    let mut inside = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ')
            && let Some((lo, hi)) = range.split_once('-')
            && let (Ok(lo), Ok(hi)) = (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
        {
            inside = (lo..hi).contains(&addr);
            continue;
        }
        if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
            return flags.to_owned();
        }
    }
    panic!("no mapping holds {addr:#x}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pages are resident afterwards, and were not before.
    ///
    /// `mincore` answers exactly the question this module exists to change, so
    /// the test asserts on residency rather than on "it ran". The "before"
    /// half matters as much as the "after": without it, a platform that
    /// eagerly populated every mapping would pass while prefaulting did
    /// nothing at all.
    #[test]
    #[cfg(target_os = "linux")]
    fn prefault_makes_pages_resident() {
        let page = page_size();
        let pages = 512;
        let len = page * pages;

        // Map the memory directly instead of using `vec![0u8; _]`.
        //
        // A zeroed Vec is *usually* fresh mmap'd zero pages, which is what this
        // test needs, but not reliably: glibc raises `M_MMAP_THRESHOLD`
        // dynamically as it observes freed mmap'd blocks, so after enough
        // allocations in the test process a 2 MiB request is served from an
        // already-faulted heap arena instead. The cold-allocation precondition
        // below then fails with 512/512 pages resident, and the test reports a
        // failure that says nothing about prefaulting. That depends on the
        // allocation history of whatever ran first, which is why it fired in
        // `Test` on one commit and `Test (tls-unbuffered)` on another.
        //
        // An anonymous private mapping without MAP_POPULATE is cold by
        // definition, and it is also what prefaulting exists to warm.
        //
        // SAFETY: a fresh anonymous mapping; the length is non-zero and page
        // aligned, and the result is checked against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(
            ptr,
            libc::MAP_FAILED,
            "mmap failed: {}",
            std::io::Error::last_os_error()
        );
        let ptr = ptr as *mut u8;
        // Returned by mmap, so already page aligned.
        struct Unmap(*mut u8, usize);
        impl Drop for Unmap {
            fn drop(&mut self) {
                // SAFETY: the mapping this guard owns, unmapped exactly once.
                unsafe { libc::munmap(self.0 as *mut libc::c_void, self.1) };
            }
        }
        let _unmap = Unmap(ptr, len);

        let resident = |ptr: *mut u8, len: usize| -> usize {
            let mut vec = vec![0u8; len / page];
            // SAFETY: `ptr` is page-aligned and `len` bytes from it are inside
            // the live allocation; `vec` has one byte per page, as required.
            let rc = unsafe { libc::mincore(ptr as *mut libc::c_void, len, vec.as_mut_ptr()) };
            assert_eq!(rc, 0, "mincore failed: {}", std::io::Error::last_os_error());
            vec.iter().filter(|b| *b & 1 == 1).count()
        };

        // Exactly zero, not merely "mostly cold": an untouched anonymous mapping
        // has no pages allocated, so this is guaranteed rather than typical. The
        // strict form is the point — it fails immediately if the allocation ever
        // goes back to `vec![0u8; _]`, whose residency depends on the allocator's
        // history and cannot be relied on.
        let before = resident(ptr, len);
        assert_eq!(
            before, 0,
            "a fresh anonymous mapping must be entirely cold, found {before}/{pages} \
             pages resident — if this allocation is not coming straight from mmap, \
             the test cannot show prefaulting does anything"
        );

        // SAFETY: the slice covers `len` bytes from an aligned offset inside
        // the allocation, which outlives it.
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
        prefault(slice);

        let after = resident(ptr, len);
        assert_eq!(
            after, pages,
            "every page must be resident after prefaulting; {after}/{pages} are"
        );
    }

    /// Prefaulting does not disturb the contents it faults in.
    #[test]
    fn prefault_leaves_the_buffer_zeroed() {
        let mut buf = vec![0u8; 1024 * 1024 + 7];
        prefault(&mut buf);
        assert!(buf.iter().all(|b| *b == 0));
    }

    /// A buffer shorter than a page, and an empty one, must not fault or
    /// over-run.
    #[test]
    fn prefault_handles_small_and_empty_buffers() {
        let mut empty: Vec<u8> = Vec::new();
        prefault(&mut empty);

        let mut tiny = vec![0u8; 3];
        prefault(&mut tiny);
        assert_eq!(tiny, [0, 0, 0]);
    }
}
