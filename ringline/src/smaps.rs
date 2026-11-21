//! Reading `/proc/self/smaps` for what a range of memory is mapped with, and
//! the kernel's transparent huge page settings.

use std::path::Path;
use std::sync::OnceLock;

/// The kernel's transparent huge page settings.
const THP: &str = "/sys/kernel/mm/transparent_hugepage";

/// Whether every byte of `start..start + len` is mapped by private anonymous
/// memory that `/proc/self/smaps` shows cannot be in huge pages: each mapping
/// that overlaps the range has inode 0, carries `nh` (`MADV_NOHUGEPAGE`) and
/// not `ht` (hugetlb) in `VmFlags`, and has no PMD-mapped huge page
/// (`AnonHugePages`, `ShmemPmdMapped` and `FilePmdMapped` all 0). A gap in
/// the range, or an empty range, is not. Without `thp` (a kernel built
/// without transparent huge pages, where `MADV_NOHUGEPAGE` fails and `nh`
/// never appears), `nh` is not required.
///
/// `smaps` shows PMD-mapped huge pages but not smaller multi-page folios
/// (mTHP). `MADV_NOHUGEPAGE` stops new ones, and does not split those already
/// faulted in, so the range must be advised before it is first touched.
pub(crate) fn base_pages_in(smaps: &str, start: usize, len: usize, thp: bool) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    if len == 0 {
        return false;
    }
    let mut covered = start;
    let mut lines = smaps.lines().peekable();
    while let Some(header) = lines.next() {
        let Some((vstart, vend, inode)) = parse_header(header) else {
            continue;
        };
        // The mapping's field lines, up to the next header.
        let mut fields = Vec::new();
        while let Some(line) = lines.peek() {
            if parse_header(line).is_some() {
                break;
            }
            fields.push(lines.next().unwrap_or_default());
        }
        if vend <= start || vstart >= end {
            continue;
        }
        if vstart > covered || inode != 0 || !no_huge_pages(&fields, thp) {
            return false;
        }
        covered = covered.max(vend);
        if covered >= end {
            return true;
        }
    }
    false
}

/// `start-end perms offset dev inode [path]`, as hexadecimal addresses and a
/// decimal inode.
fn parse_header(line: &str) -> Option<(usize, usize, u64)> {
    let mut parts = line.split_ascii_whitespace();
    let (start, end) = parts.next()?.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    let perms = parts.next()?;
    if perms.len() != 4 {
        return None;
    }
    let _offset = parts.next()?;
    let _dev = parts.next()?;
    let inode = parts.next()?.parse().ok()?;
    Some((start, end, inode))
}

fn no_huge_pages(fields: &[&str], thp: bool) -> bool {
    let mut advised = !thp;
    for line in fields {
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            let flags: Vec<&str> = flags.split_ascii_whitespace().collect();
            if flags.contains(&"ht") {
                return false;
            }
            if thp {
                advised = flags.contains(&"nh");
            }
        } else if let Some((name, value)) = line.split_once(':')
            && matches!(name, "AnonHugePages" | "ShmemPmdMapped" | "FilePmdMapped")
            && value.trim().trim_end_matches("kB").trim() != "0"
        {
            return false;
        }
    }
    advised
}

/// Whether the kernel has transparent huge pages: `MADV_NOHUGEPAGE` on a
/// scratch mapping does not fail with `EINVAL`, which it does on a kernel
/// built without them. Decided once per process. Asks the kernel, not
/// sysfs, which a container may not mount.
pub(crate) fn thp_configured() -> bool {
    static THP_CONFIGURED: OnceLock<bool> = OnceLock::new();
    *THP_CONFIGURED.get_or_init(|| {
        // SAFETY: a new private anonymous mapping of one page, checked, and
        // unmapped below.
        unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return true;
            }
            #[cfg(target_os = "linux")]
            let refused = libc::madvise(ptr, 4096, libc::MADV_NOHUGEPAGE) != 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL);
            #[cfg(not(target_os = "linux"))]
            let refused = true;
            libc::munmap(ptr, 4096);
            !refused
        }
    })
}

/// Whether the kernel faults multi-page folios smaller than a PMD (mTHP)
/// into anonymous memory not advised `MADV_HUGEPAGE`: a
/// `hugepages-<size>kB/enabled` below `hpage_pmd_size` set to `always`, or to
/// `inherit` with the top-level `enabled` set to `always`.
pub(crate) fn small_folios_always() -> bool {
    let read = |path: &str| std::fs::read_to_string(Path::new(THP).join(path)).ok();
    let Some(pmd) = read("hpage_pmd_size").and_then(|s| s.trim().parse::<u64>().ok()) else {
        return false;
    };
    let top = read("enabled");
    let Ok(dir) = std::fs::read_dir(THP) else {
        return false;
    };
    dir.flatten().any(|entry| {
        let name = entry.file_name();
        let Some(kib) = name.to_str().and_then(|n| {
            n.strip_prefix("hugepages-")?
                .strip_suffix("kB")?
                .parse::<u64>()
                .ok()
        }) else {
            return false;
        };
        let enabled = read(&format!("{}/enabled", name.to_string_lossy()));
        kib * 1024 < pmd && faults_always(enabled.as_deref(), top.as_deref())
    })
}

/// Whether a size whose `enabled` file reads `size` is faulted in without
/// `MADV_HUGEPAGE`, given the top-level `enabled` file `top`. Each file names
/// its setting in brackets, as in `always [madvise] never`.
fn faults_always(size: Option<&str>, top: Option<&str>) -> bool {
    let selected = |text: Option<&str>| {
        let text = text?;
        let start = text.find('[')? + 1;
        let end = start + text[start..].find(']')?;
        Some(text[start..end].to_string())
    };
    match selected(size).as_deref() {
        Some("always") => true,
        Some("inherit") => selected(top).as_deref() == Some("always"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vma(start: usize, end: usize, inode: u64, huge_kib: usize, flags: &str) -> String {
        format!(
            "{start:x}-{end:x} rw-p 00000000 00:00 {inode} \n\
             Size:               {} kB\n\
             AnonHugePages:      {huge_kib} kB\n\
             ShmemPmdMapped:        0 kB\n\
             FilePmdMapped:         0 kB\n\
             VmFlags: rd wr mr mw me ac {flags}\n",
            (end - start) / 1024
        )
    }

    const A: usize = 0x7f00_0000_0000;
    const M: usize = 1 << 20;

    #[test]
    fn an_advised_anonymous_mapping_is_base_pages() {
        let smaps = vma(A, A + 4 * M, 0, 0, "nh");
        assert!(base_pages_in(&smaps, A + M, 2 * M, true));
        assert!(base_pages_in(&smaps, A, 4 * M, true));
    }

    #[test]
    fn adjacent_mappings_cover_a_range_together() {
        let smaps = vma(A, A + 2 * M, 0, 0, "nh") + &vma(A + 2 * M, A + 4 * M, 0, 0, "nh");
        assert!(base_pages_in(&smaps, A + M, 2 * M, true));
    }

    #[test]
    fn anything_else_is_not() {
        let advised = vma(A, A + 4 * M, 0, 0, "nh");
        assert!(
            !base_pages_in(&vma(A, A + 4 * M, 0, 0, "hg"), A, M, true),
            "no nh"
        );
        assert!(
            !base_pages_in(&vma(A, A + 4 * M, 0, 2048, "nh"), A, M, true),
            "a huge page"
        );
        assert!(
            !base_pages_in(&vma(A, A + 4 * M, 0, 0, "nh ht"), A, M, true),
            "hugetlb"
        );
        assert!(
            !base_pages_in(&vma(A, A + 4 * M, 42, 0, "nh"), A, M, true),
            "a file or shmem"
        );
        assert!(
            !base_pages_in(&advised, A + 3 * M, 2 * M, true),
            "runs past the mapping"
        );
        assert!(!base_pages_in(&advised, A, 0, true), "empty");
        let gap = vma(A, A + M, 0, 0, "nh") + &vma(A + 2 * M, A + 4 * M, 0, 0, "nh");
        assert!(!base_pages_in(&gap, A, 3 * M, true), "a gap");
        let one_unadvised = vma(A, A + 2 * M, 0, 0, "nh") + &vma(A + 2 * M, A + 4 * M, 0, 0, "");
        assert!(
            !base_pages_in(&one_unadvised, A, 4 * M, true),
            "one mapping unadvised"
        );
    }

    /// Without transparent huge pages `nh` is not required; hugetlb, files
    /// and huge pages still are not base pages.
    #[test]
    fn without_thp_nh_is_not_required() {
        assert!(base_pages_in(&vma(A, A + 4 * M, 0, 0, ""), A, M, false));
        assert!(!base_pages_in(&vma(A, A + 4 * M, 0, 0, "ht"), A, M, false));
        assert!(!base_pages_in(&vma(A, A + 4 * M, 42, 0, ""), A, M, false));
    }

    #[test]
    fn small_folios_fault_on_always_or_inherited_always() {
        let always = Some("[always] inherit madvise never");
        let inherit = Some("always [inherit] madvise never");
        let madvise = Some("always inherit [madvise] never");
        assert!(faults_always(always, None));
        assert!(faults_always(inherit, Some("[always] madvise never")));
        assert!(!faults_always(inherit, Some("always [madvise] never")));
        assert!(!faults_always(madvise, Some("[always] madvise never")));
        assert!(!faults_always(None, Some("[always] madvise never")));
    }

    /// Lines from a real smaps, a named anonymous mapping and a file mapping
    /// with a path that contains spaces.
    #[test]
    fn real_header_forms_parse() {
        let smaps = format!(
            "{A:x}-{:x} rw-p 00000000 00:00 0                          [anon:arena]\n\
             AnonHugePages:         0 kB\n\
             VmFlags: rd wr mr mw me ac sd nh\n\
             {:x}-{:x} r--p 00000000 103:02 1234                     /tmp/a b c\n\
             AnonHugePages:         0 kB\n\
             VmFlags: rd mr mw me sd nh\n",
            A + M,
            A + M,
            A + 2 * M
        );
        assert!(base_pages_in(&smaps, A, M, true));
        assert!(!base_pages_in(&smaps, A, 2 * M, true));
    }

    /// The test binary's own memory, on Linux: an advised mapping is base
    /// pages, and the same mapping without the advice is not.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process() {
        let len = 4 << 20;
        // SAFETY: a new private anonymous mapping, checked, and unmapped below.
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
        assert_ne!(ptr, libc::MAP_FAILED);
        let read = || std::fs::read_to_string("/proc/self/smaps").unwrap();
        assert!(!base_pages_in(&read(), ptr as usize, len, true));
        // SAFETY: the mapping above.
        unsafe {
            libc::madvise(ptr, len, libc::MADV_NOHUGEPAGE);
            std::ptr::write_bytes(ptr.cast::<u8>(), 1, len);
        }
        assert!(base_pages_in(&read(), ptr as usize, len, true));
        // SAFETY: the mapping above.
        unsafe { libc::munmap(ptr, len) };
    }
}
