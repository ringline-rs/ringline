//! libc items that differ on Hermit: constants and structs libc's Hermit
//! module lacks, the token pair that replaces pipes, and the file calls the
//! mio backend's disk pool makes. On other targets each item is libc's own,
//! or a thin wrapper over it; on Hermit each item's comment states what it
//! does.

use std::io;
use std::os::fd::RawFd;

#[cfg(not(target_os = "hermit"))]
pub(crate) use libc::{AF_UNIX, O_CLOEXEC, O_DSYNC, linger, sockaddr_un};

/// Hermit has no Unix-domain sockets. No Hermit socket reports this family,
/// so a match on it never succeeds, and binding a Unix listener fails at
/// `socket(2)`.
#[cfg(target_os = "hermit")]
pub(crate) const AF_UNIX: libc::c_int = 255;

/// The layout of a BSD `sockaddr_un`, which Hermit's `sockaddr` follows
/// (`ss_len` before the family). Only built for Unix paths, which Hermit
/// refuses before a socket exists.
#[cfg(target_os = "hermit")]
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct sockaddr_un {
    pub sun_len: u8,
    pub sun_family: libc::sa_family_t,
    pub sun_path: [libc::c_char; 104],
}

/// Hermit's `open` has no `O_DSYNC`, so the flag is dropped there and a
/// write returns without waiting for the storage under the file.
#[cfg(target_os = "hermit")]
pub(crate) const O_DSYNC: libc::c_int = 0;

/// `struct linger` as Linux and the BSDs define it. Hermit's libc has the
/// `SO_LINGER` option but not the struct.
#[cfg(target_os = "hermit")]
#[repr(C)]
#[allow(non_camel_case_types)]
pub(crate) struct linger {
    pub l_onoff: libc::c_int,
    pub l_linger: libc::c_int,
}

/// A non-blocking `(read end, write end)` pair that carries tokens: each
/// [`write_token`] is returned by exactly one [`read_token`].
///
/// On Hermit, which has no pipes, both ends are one semaphore eventfd (the
/// write end a `dup` of it), so each read takes one from the counter.
#[cfg(target_os = "hermit")]
pub(crate) fn token_pair() -> io::Result<(RawFd, RawFd)> {
    let flags = libc::EFD_NONBLOCK | libc::EFD_CLOEXEC | libc::EFD_SEMAPHORE;
    let fd = unsafe { libc::eventfd(0, flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok((fd, dup))
}

/// Write one token to the write end of a [`token_pair`] or pipe. Best effort:
/// a full pipe already holds a token for the reader.
pub(crate) fn write_token(fd: RawFd) {
    #[cfg(target_os = "hermit")]
    let token = 1u64.to_ne_bytes();
    #[cfg(not(target_os = "hermit"))]
    let token = [1u8];
    unsafe {
        libc::write(fd, token.as_ptr().cast(), token.len());
    }
}

/// Read one token from a non-blocking [`token_pair`] or pipe. False when
/// there is none, because another reader took it first.
pub(crate) fn read_token(fd: RawFd) -> bool {
    #[cfg(target_os = "hermit")]
    let mut buf = [0u8; 8];
    #[cfg(not(target_os = "hermit"))]
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    n == buf.len() as isize
}

/// The error a file operation reports on Hermit where the kernel has no
/// equivalent.
#[cfg(target_os = "hermit")]
fn no_file_io() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOSYS)
}

/// Kernel calls that `hermit-abi` exports and libc's Hermit module does not
/// declare. Each returns a negative errno on failure.
#[cfg(target_os = "hermit")]
mod hermit_sys {
    unsafe extern "C" {
        pub(super) fn sys_lseek(fd: i32, offset: isize, whence: i32) -> isize;
        pub(super) fn sys_fsync(fd: i32) -> i32;
    }
}

/// Ringkern's positional calls, which stock Hermit does not have: a build
/// with the `ringkern` feature that does file I/O needs a Ringkern kernel to
/// link. Each returns the count or a negative errno (`ENOSYS` for a file
/// system without them), and neither uses nor moves the file position.
#[cfg(all(target_os = "hermit", feature = "ringkern"))]
mod ringkern_sys {
    unsafe extern "C" {
        pub(super) fn sys_pread(fd: i32, buf: *mut u8, len: usize, offset: isize) -> isize;
        pub(super) fn sys_pwrite(fd: i32, buf: *const u8, len: usize, offset: isize) -> isize;
    }
}

/// A Hermit kernel call's return value: the value, or the negative errno it
/// carries as an error.
#[cfg(target_os = "hermit")]
fn hermit_result(ret: isize) -> io::Result<usize> {
    if ret < 0 {
        Err(io::Error::from_raw_os_error(-ret as i32))
    } else {
        Ok(ret as usize)
    }
}

/// Stock Hermit has no `pread` or `pwrite`, and Ringkern has none for some
/// file systems. Each positional call made without them seeks and then
/// reads or writes while holding this lock, so no other positional call
/// moves the file position in between. Every positional call that takes the
/// seek path takes it; a `read`, `write` or `lseek` made outside these
/// functions on the same fd can still move the position.
#[cfg(target_os = "hermit")]
static POSITIONED: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Moves `fd`'s position to `offset`. The caller holds [`POSITIONED`].
#[cfg(target_os = "hermit")]
fn seek_to(fd: RawFd, offset: u64) -> io::Result<()> {
    let offset = isize::try_from(offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SEEK_SET is 0 in hermit-abi.
    hermit_result(unsafe { hermit_sys::sys_lseek(fd, offset, 0) }).map(|_| ())
}

/// `fd`'s length. The caller holds [`POSITIONED`], since a seek to the end
/// moves the position.
///
/// The larger of `fstat`'s `st_size` and a seek to the end: a Hermit RAM
/// file created with data from the image reports `st_size` 0 until it
/// grows, and a seek to the end may be unsupported on some file systems.
#[cfg(target_os = "hermit")]
fn file_len(fd: RawFd) -> io::Result<u64> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let stat = hermit_result(unsafe { libc::fstat(fd, &mut st) } as isize)
        .map(|_| u64::try_from(st.st_size).unwrap_or(0));
    // SEEK_END is 2 in hermit-abi.
    let end = hermit_result(unsafe { hermit_sys::sys_lseek(fd, 0, 2) }).map(|n| n as u64);
    match (stat, end) {
        (Ok(a), Ok(b)) => Ok(a.max(b)),
        (Ok(n), Err(_)) | (Err(_), Ok(n)) => Ok(n),
        (Err(e), Err(_)) => Err(e),
    }
}

/// `pread(2)`.
///
/// On Hermit with the `ringkern` feature, Ringkern's `sys_pread`, which
/// neither uses nor moves the file position, without Ringline's
/// process-wide lock. A file whose file system has no `sys_pread` (Ringkern
/// returns `ENOSYS`), or an offset above `isize::MAX`, takes the path below.
///
/// On Hermit otherwise, a seek and a read under a process-wide lock. A read
/// at or past the end returns 0 without seeking to `offset`, since a Hermit
/// RAM file grows when its position is set past its end.
pub(crate) fn pread(fd: RawFd, buf: *mut u8, len: usize, offset: u64) -> io::Result<usize> {
    #[cfg(target_os = "hermit")]
    {
        #[cfg(feature = "ringkern")]
        if let Ok(at) = isize::try_from(offset) {
            match hermit_result(unsafe { ringkern_sys::sys_pread(fd, buf, len, at) }) {
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                result => return result,
            }
        }
        let _guard = POSITIONED.lock().unwrap_or_else(|e| e.into_inner());
        if len == 0 || offset >= file_len(fd)? {
            return Ok(0);
        }
        seek_to(fd, offset)?;
        hermit_result(unsafe { libc::read(fd, buf, len) })
    }
    #[cfg(not(target_os = "hermit"))]
    {
        let n = unsafe { libc::pread(fd, buf.cast(), len, offset as libc::off_t) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// `pwrite(2)`.
///
/// On Hermit with the `ringkern` feature, Ringkern's `sys_pwrite`, with the
/// same fallback as [`pread`].
///
/// On Hermit otherwise, a seek and a write under a process-wide lock (see
/// [`pread`]). A zero-length write returns 0 without seeking, so it does not
/// extend the file.
pub(crate) fn pwrite(fd: RawFd, buf: *const u8, len: usize, offset: u64) -> io::Result<usize> {
    #[cfg(target_os = "hermit")]
    {
        #[cfg(feature = "ringkern")]
        if let Ok(at) = isize::try_from(offset) {
            match hermit_result(unsafe { ringkern_sys::sys_pwrite(fd, buf, len, at) }) {
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
                result => return result,
            }
        }
        if len == 0 {
            return Ok(0);
        }
        let _guard = POSITIONED.lock().unwrap_or_else(|e| e.into_inner());
        seek_to(fd, offset)?;
        hermit_result(unsafe { libc::write(fd, buf, len) })
    }
    #[cfg(not(target_os = "hermit"))]
    {
        let n = unsafe { libc::pwrite(fd, buf.cast(), len, offset as libc::off_t) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}

/// `fsync(2)`.
pub(crate) fn fsync(fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "hermit")]
    {
        hermit_result(unsafe { hermit_sys::sys_fsync(fd) } as isize).map(|_| ())
    }
    #[cfg(not(target_os = "hermit"))]
    {
        if unsafe { libc::fsync(fd) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// `rename(2)`. Hermit's kernel has no rename; there it fails with `ENOSYS`.
pub(crate) fn rename(from: &std::ffi::CStr, to: &std::ffi::CStr) -> io::Result<()> {
    #[cfg(target_os = "hermit")]
    {
        let _ = (from, to);
        Err(no_file_io())
    }
    #[cfg(not(target_os = "hermit"))]
    {
        if unsafe { libc::rename(from.as_ptr(), to.as_ptr()) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// `open(2)`, close-on-exec. Hermit cannot exec, so there the flag is not
/// passed.
pub(crate) fn open(path: &std::ffi::CStr, flags: libc::c_int, mode: u32) -> io::Result<RawFd> {
    #[cfg(target_os = "hermit")]
    {
        let fd = unsafe { libc::open(path.as_ptr(), flags, mode as libc::mode_t) };
        hermit_result(fd as isize).map(|fd| fd as RawFd)
    }
    #[cfg(not(target_os = "hermit"))]
    {
        let fd = unsafe { libc::open(path.as_ptr(), flags | O_CLOEXEC, mode as libc::c_uint) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(fd)
        }
    }
}
