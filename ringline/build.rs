fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let force_mio = std::env::var("CARGO_FEATURE_FORCE_MIO").is_ok();

    // `has_io_uring` selects the io_uring driver; `uring_engine` runs it on
    // the kernel's io_uring. `RINGLINE_STUB_ENGINE=1` builds the driver on
    // a stub engine instead, so the driver compiles and lints without
    // `UringEngine`.
    println!("cargo:rerun-if-env-changed=RINGLINE_STUB_ENGINE");
    // Printing any rerun-if line drops cargo's default of rerunning on every
    // package change; keep rerunning on source edits, so a target dir reused
    // across a kernel upgrade picks up the new kernel at the next edit.
    println!("cargo:rerun-if-changed=src");
    let stub_engine = std::env::var("RINGLINE_STUB_ENGINE").is_ok_and(|v| v == "1");
    if target_os == "linux" && !force_mio && kernel_version_sufficient() {
        println!("cargo:rustc-cfg=has_io_uring");
        if !stub_engine {
            println!("cargo:rustc-cfg=uring_engine");
        }
    }
}

/// Check that the build host's kernel is 6.8+. Worker exit resets a
/// connection whose zero-copy send a non-reading peer holds by setting
/// `SO_LINGER` on its fixed file through io_uring's setsockopt command (6.7),
/// and park returns a fixed file to the process with
/// `IORING_OP_FIXED_FD_INSTALL` (6.8). `IORING_SETUP_DEFER_TASKRUN` and
/// `IORING_OP_SENDMSG_ZC` are 6.1; multishot recv, provided buffers and
/// `SINGLE_ISSUER` are 6.0. Launch refuses a running kernel below 6.8 the
/// same way (`worker::check_kernel_floor`).
///
/// On a Linux build host this reads the host's kernel, which may differ from
/// the target's: a 6.1 host builds mio even for a 6.8 target. When the file
/// cannot be read (a non-Linux host, or `/proc` not mounted) the cfg is
/// emitted, and launch refuses a target kernel below the floor
/// (`worker::check_kernel_floor`).
fn kernel_version_sufficient() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        // Not on Linux (cross-compile from macOS) or /proc not mounted.
        // Optimistically enable — the io-uring crate itself will fail to
        // compile if the target truly cannot support it.
        return true;
    };
    let mut parts = release.trim().split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|s| {
            // Strip trailing non-digit suffix (e.g., "0-generic" → "0").
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .unwrap_or(0);
    (major, minor) >= (6, 8)
}
