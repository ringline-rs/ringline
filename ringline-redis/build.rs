// Mirror `ringline`'s backend detection so this crate can conditionally compile
// io_uring-only consumers (the streaming `get_stream` / `ValueStream` API, which
// builds on `ConnCtx::recv_owned_segment` — a `#[cfg(has_io_uring)]` method).
//
// The emitted `has_io_uring` cfg MUST match the backend `ringline` was built
// with for the same cargo invocation:
//   - default Linux 6.0+ build  → io_uring backend → `has_io_uring`
//   - `--features force-mio`    → mio backend      → no cfg (our feature forwards
//                                                     to `ringline/force-mio`, so
//                                                     `CARGO_FEATURE_FORCE_MIO` is
//                                                     set here too)
//   - non-Linux (macOS)         → mio backend      → no cfg
//
// Cargo auto-registers cfgs set via `cargo:rustc-cfg` for check-cfg, so no
// explicit `cargo::rustc-check-cfg` line is needed (matches `ringline/build.rs`).
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let force_mio = std::env::var("CARGO_FEATURE_FORCE_MIO").is_ok();

    if target_os == "linux" && !force_mio && kernel_version_sufficient() {
        println!("cargo:rustc-cfg=has_io_uring");
    }
}

/// Check that the running kernel is 6.0+ (required for the multishot-recv +
/// provided-buffer features segmented recv depends on). Kept identical to
/// `ringline/build.rs`.
fn kernel_version_sufficient() -> bool {
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        // Not on Linux (cross-compile from macOS) or /proc not mounted.
        // Optimistically enable — `ringline` itself gates the real backend.
        return true;
    };
    let mut parts = release.trim().split('.');
    let major: u32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = parts
        .next()
        .and_then(|s| {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
        .unwrap_or(0);
    (major, minor) >= (6, 0)
}
