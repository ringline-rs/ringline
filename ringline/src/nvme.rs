//! NVMe io_uring passthrough types and helpers.
//!
//! This module provides the types needed to submit NVMe commands via
//! `IORING_OP_URING_CMD` (io_uring passthrough). Commands are submitted
//! on NVMe-generic character devices (`/dev/ng<X>n<Y>`), bypassing the
//! filesystem and block layer entirely.
//!
//! # Kernel requirements
//!
//! - Linux 5.19+ for `IORING_OP_URING_CMD`
//! - Linux 6.8+, the io_uring backend's floor
//! - NVMe device accessible via `/dev/ng*` (requires `CAP_SYS_ADMIN` or udev rules)
//!
//! io_uring only: on the mio backend every NVMe call fails with `Unsupported`
//! (`nvme_read` and `nvme_write` resolve to it).
//! On io_uring a call that finds the ring's submission queue full submits the
//! queue inline before pushing, and if that submit fails, queues the command
//! and pushes it again later (see the `fs` module docs).

use std::marker::PhantomData;

/// NVM command set opcode: flush.
pub const NVME_CMD_FLUSH: u8 = 0x00;
/// NVM command set opcode: write.
pub const NVME_CMD_WRITE: u8 = 0x01;
/// NVM command set opcode: read.
pub const NVME_CMD_READ: u8 = 0x02;

/// NVMe uring_cmd opcode passed as `cmd_op` to `IORING_OP_URING_CMD`.
///
/// This is the kernel's `NVME_URING_CMD_IO = _IOWR('N', 0x80, struct
/// nvme_uring_cmd)` ioctl encoding: dir=RW (3) << 30 | size (72) << 16 |
/// 'N' (0x4E) << 8 | nr (0x80). The NVMe driver dispatches `uring_cmd` on
/// this value; anything else (e.g. a literal 0) returns `ENOTTY`.
pub const NVME_URING_CMD_IO: u32 = 0xC048_4E80;

/// NVMe command structure for io_uring passthrough.
///
/// This matches the kernel's `struct nvme_uring_cmd` (72 bytes).
/// It is embedded in the 80-byte command area of a Big SQE (`UringCmd80`).
///
/// # Layout
///
/// The structure maps directly to NVMe command dwords, with `addr` and
/// `data_len` specifying the data buffer for read/write commands.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeUringCmd {
    /// NVMe command opcode (e.g., 0x02 for Read, 0x01 for Write).
    pub opcode: u8,
    /// Command flags.
    pub flags: u8,
    /// Reserved.
    pub rsvd1: u16,
    /// Namespace ID (usually 1).
    pub nsid: u32,
    /// Command dword 2.
    pub cdw2: u32,
    /// Command dword 3.
    pub cdw3: u32,
    /// Metadata buffer address (0 if unused).
    pub metadata: u64,
    /// Data buffer address (userspace virtual address).
    pub addr: u64,
    /// Metadata length in bytes.
    pub metadata_len: u32,
    /// Data length in bytes.
    pub data_len: u32,
    /// Command dword 10 (start LBA low 32 bits for read/write).
    pub cdw10: u32,
    /// Command dword 11 (start LBA high 32 bits for read/write).
    pub cdw11: u32,
    /// Command dword 12 (number of logical blocks - 1, plus flags).
    pub cdw12: u32,
    /// Command dword 13.
    pub cdw13: u32,
    /// Command dword 14.
    pub cdw14: u32,
    /// Command dword 15.
    pub cdw15: u32,
    /// Timeout in milliseconds (0 = default).
    pub timeout_ms: u32,
    /// Reserved.
    pub rsvd2: u32,
}

const _: () = assert!(std::mem::size_of::<NvmeUringCmd>() == 72);
const _: () = assert!(std::mem::size_of::<NvmeUringCmd>() <= 80);

impl NvmeUringCmd {
    /// Build an NVMe Read command.
    ///
    /// # Arguments
    /// - `nsid`: Namespace ID (usually 1)
    /// - `lba`: Starting logical block address
    /// - `num_blocks`: Number of blocks to read (1-based; 1 = one block)
    /// - `buf_addr`: Userspace buffer address for the read data
    /// - `buf_len`: Buffer length in bytes
    ///
    /// # Panics
    ///
    /// Panics if `num_blocks` is 0.
    pub fn read(nsid: u32, lba: u64, num_blocks: u16, buf_addr: u64, buf_len: u32) -> Self {
        NvmeUringCmd {
            opcode: NVME_CMD_READ,
            flags: 0,
            rsvd1: 0,
            nsid,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            addr: buf_addr,
            metadata_len: 0,
            data_len: buf_len,
            cdw10: lba as u32,         // SLBA low
            cdw11: (lba >> 32) as u32, // SLBA high
            cdw12: num_blocks.checked_sub(1).expect("num_blocks must be >= 1") as u32, // NLB (0-based)
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
            timeout_ms: 0,
            rsvd2: 0,
        }
    }

    /// Build an NVMe Write command.
    ///
    /// # Arguments
    /// - `nsid`: Namespace ID (usually 1)
    /// - `lba`: Starting logical block address
    /// - `num_blocks`: Number of blocks to write (1-based; 1 = one block)
    /// - `buf_addr`: Userspace buffer address containing write data
    /// - `buf_len`: Buffer length in bytes
    ///
    /// # Panics
    ///
    /// Panics if `num_blocks` is 0.
    pub fn write(nsid: u32, lba: u64, num_blocks: u16, buf_addr: u64, buf_len: u32) -> Self {
        NvmeUringCmd {
            opcode: NVME_CMD_WRITE,
            flags: 0,
            rsvd1: 0,
            nsid,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            addr: buf_addr,
            metadata_len: 0,
            data_len: buf_len,
            cdw10: lba as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: num_blocks.checked_sub(1).expect("num_blocks must be >= 1") as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
            timeout_ms: 0,
            rsvd2: 0,
        }
    }

    /// Build an NVMe Flush command.
    pub fn flush(nsid: u32) -> Self {
        NvmeUringCmd {
            opcode: NVME_CMD_FLUSH,
            flags: 0,
            rsvd1: 0,
            nsid,
            cdw2: 0,
            cdw3: 0,
            metadata: 0,
            addr: 0,
            metadata_len: 0,
            data_len: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
            timeout_ms: 0,
            rsvd2: 0,
        }
    }

    /// Serialize to a byte array for embedding in `UringCmd80`.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut buf = [0u8; 80];
        // Safety: NvmeUringCmd is repr(C) and 72 bytes, fits in 80.
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const Self as *const u8,
                buf.as_mut_ptr(),
                std::mem::size_of::<Self>(),
            );
        }
        buf
    }
}

/// Opaque handle to an opened NVMe device.
///
/// Returned by [`crate::open_nvme_device`] and used to identify the
/// device in subsequent read/write/close calls. The handle includes a
/// generation counter for stale-handle detection.
///
/// The handle names a slot in the table of the worker that opened it, so it is
/// not `Send`: use it on that worker. Another worker's table can hold a
/// different device in the same slot. A handler is created on its worker's
/// thread and stays there, so it can keep a handle in a field.
///
/// ```
/// fn assert_copy<T: Copy>() {}
/// assert_copy::<ringline::nvme::NvmeDevice>();
/// ```
///
/// ```compile_fail
/// fn assert_send<T: Send>() {}
/// assert_send::<ringline::nvme::NvmeDevice>();
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NvmeDevice {
    pub(crate) index: u16,
    pub(crate) generation: u32,
    /// Makes the handle `!Send`.
    _not_send: PhantomData<*const ()>,
}

impl std::fmt::Debug for NvmeDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NvmeDevice")
            .field("index", &self.index)
            .field("generation", &self.generation)
            .finish()
    }
}

impl NvmeDevice {
    pub(crate) fn new(index: u16, generation: u32) -> Self {
        NvmeDevice {
            index,
            generation,
            _not_send: PhantomData,
        }
    }

    /// Returns the device slot index. Useful for indexing into per-device arrays.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// `NVME_IOCTL_ADMIN_CMD`: `_IOWR('N', 0x41, struct nvme_passthru_cmd)`.
const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xC048_4E41;

/// Admin opcode: Identify.
const NVME_ADMIN_IDENTIFY: u8 = 0x06;

/// `struct nvme_passthru_cmd` (`include/uapi/linux/nvme_ioctl.h`), 72 bytes.
#[repr(C)]
#[derive(Default)]
struct NvmePassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

/// The logical block size of namespace `nsid` on the NVMe-generic character
/// device `fd`, from Identify Namespace (CNS 0) through
/// `NVME_IOCTL_ADMIN_CMD`. Below Linux 6.2 it needs `CAP_SYS_ADMIN`, as
/// every NVMe passthrough command does there; from 6.2 the kernel allows it
/// without (`nvme_cmd_allowed`).
#[cfg_attr(not(has_io_uring), allow(dead_code))]
pub(crate) fn identify_lba_size(fd: libc::c_int, nsid: u32) -> std::io::Result<u32> {
    let mut data = vec![0u8; 4096];
    let mut cmd = NvmePassthruCmd {
        opcode: NVME_ADMIN_IDENTIFY,
        nsid,
        addr: data.as_mut_ptr() as u64,
        data_len: data.len() as u32,
        // CNS 0: Identify Namespace.
        cdw10: 0,
        ..Default::default()
    };
    // Safety: `cmd` is a valid `nvme_passthru_cmd` whose `addr` points to
    // `data_len` writable bytes that outlive the synchronous ioctl.
    let ret = unsafe { libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD as _, &mut cmd) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if ret > 0 {
        // The device failed the command: the ioctl returns its status field.
        return Err(std::io::Error::other(NvmeStatus((ret & 0x7FFF) as u16)));
    }
    lba_size_from_identify(&data)
}

/// The logical block size an Identify Namespace data structure gives for its
/// formatted LBA format: FLBAS (byte 26) selects an entry of the LBA format
/// list at byte 128 (4 bytes each), whose LBADS (byte 2 of the entry) is
/// log2 of the size. A format with metadata (MS, bytes 0 and 1 of the entry,
/// nonzero) is refused.
pub(crate) fn lba_size_from_identify(data: &[u8]) -> std::io::Result<u32> {
    let invalid = |what: &str| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("NVMe Identify Namespace: {what}"),
        )
    };
    if data.len() < 4096 {
        return Err(invalid("data shorter than 4096 bytes"));
    }
    let nlbaf = data[25] as usize;
    let flbas = data[26];
    // Bits 3:0 are the low bits of the format index; bits 6:5 the high bits
    // when there are more than 16 formats.
    let index = (flbas & 0x0f) as usize | ((((flbas >> 5) & 0x03) as usize) << 4);
    if index > nlbaf {
        return Err(invalid("formatted LBA index beyond the format list"));
    }
    let format = &data[128 + 4 * index..][..4];
    // MS: metadata bytes per block. Passthrough reads and writes here carry
    // no metadata pointer, and with extended LBAs the device would move more
    // than `num_blocks * LBA size` bytes.
    if u16::from_le_bytes([format[0], format[1]]) != 0 {
        return Err(invalid(
            "the formatted LBA format has metadata, which passthrough reads and writes do not carry",
        ));
    }
    let lbads = format[2];
    // LBADS below 9 (512 bytes) is not a supported format.
    if !(9..=31).contains(&lbads) {
        return Err(invalid("LBA data size out of range"));
    }
    Ok(1u32 << lbads)
}

/// Per-device state tracked by the driver.
pub(crate) struct NvmeDeviceState {
    /// Index in the io_uring fixed file table.
    pub fd_index: u32,
    /// NVMe namespace ID (usually 1).
    pub nsid: u32,
    /// Whether this slot is in use.
    pub active: bool,
    /// Generation counter for stale-handle detection.
    pub generation: u32,
    /// Number of commands currently in flight.
    pub in_flight: u32,
    /// `close_nvme_device` was called: the handle is refused. The slot is
    /// closed with `IORING_OP_CLOSE` once no command is in flight, because a
    /// queued SQE resolves its fixed-file index at submission, and the table
    /// slot is released when that close completes.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub closing: bool,
    /// The namespace's logical block size in bytes, from Identify Namespace
    /// at open (`identify_lba_size`), or the error that command returned.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub lba_size: Result<u32, (std::io::ErrorKind, String)>,
}

impl NvmeDeviceState {
    pub fn new() -> Self {
        NvmeDeviceState {
            fd_index: u32::MAX,
            nsid: 1,
            active: false,
            generation: 0,
            in_flight: 0,
            closing: false,
            lba_size: Err((std::io::ErrorKind::Other, "not open".into())),
        }
    }
}

/// Tracks NVMe device slots with allocation/release.
pub(crate) struct NvmeDeviceTable {
    slots: Vec<NvmeDeviceState>,
    free_list: Vec<u16>,
}

impl NvmeDeviceTable {
    pub fn new(max_devices: u16) -> Self {
        let mut slots = Vec::with_capacity(max_devices as usize);
        let mut free_list = Vec::with_capacity(max_devices as usize);
        for i in (0..max_devices).rev() {
            slots.push(NvmeDeviceState::new());
            free_list.push(i);
        }
        NvmeDeviceTable { slots, free_list }
    }

    pub fn allocate(&mut self) -> Option<u16> {
        let index = self.free_list.pop()?;
        let slot = &mut self.slots[index as usize];
        slot.active = true;
        Some(index)
    }

    pub fn release(&mut self, index: u16) {
        let slot = &mut self.slots[index as usize];
        slot.active = false;
        slot.fd_index = u32::MAX;
        slot.in_flight = 0;
        slot.closing = false;
        slot.generation = slot.generation.wrapping_add(1);
        self.free_list.push(index);
    }

    pub fn get(&self, index: u16) -> Option<&NvmeDeviceState> {
        self.slots.get(index as usize).filter(|s| s.active)
    }

    pub fn get_mut(&mut self, index: u16) -> Option<&mut NvmeDeviceState> {
        self.slots.get_mut(index as usize).filter(|s| s.active)
    }
}

/// Tracks in-flight NVMe commands for resource cleanup on completion.
pub(crate) struct NvmeCmdSlab {
    entries: Vec<NvmeCmdEntry>,
    free_list: Vec<u16>,
}

/// Per-command tracking entry.
struct NvmeCmdEntry {
    /// Device slot index.
    device_index: u16,
    /// Whether this slot is in use.
    in_use: bool,
    /// The SQE's user_data, recorded before the SQE is pushed.
    user_data: u64,
}

impl NvmeCmdSlab {
    pub fn new(capacity: u16) -> Self {
        let mut entries = Vec::with_capacity(capacity as usize);
        let mut free_list = Vec::with_capacity(capacity as usize);
        for i in (0..capacity).rev() {
            entries.push(NvmeCmdEntry {
                device_index: 0,
                in_use: false,
                user_data: 0,
            });
            free_list.push(i);
        }
        NvmeCmdSlab { entries, free_list }
    }

    /// Allocate a command slot. Returns the slab index.
    pub fn allocate(&mut self, device_index: u16) -> Option<u16> {
        let idx = self.free_list.pop()?;
        let entry = &mut self.entries[idx as usize];
        entry.device_index = device_index;
        entry.in_use = true;
        Some(idx)
    }

    /// Release a command slot. Returns the device index.
    pub fn release(&mut self, idx: u16) -> u16 {
        let entry = &mut self.entries[idx as usize];
        let device_index = entry.device_index;
        entry.in_use = false;
        self.free_list.push(idx);
        device_index
    }

    #[cfg(test)]
    pub fn device_index(&self, idx: u16) -> u16 {
        self.entries[idx as usize].device_index
    }

    pub fn in_use(&self, idx: u16) -> bool {
        self.entries.get(idx as usize).is_some_and(|e| e.in_use)
    }

    /// Whether any command holds a slot, so its operation has not completed.
    pub fn has_in_flight(&self) -> bool {
        self.free_list.len() < self.entries.len()
    }

    /// Record the user_data of slot `idx`'s SQE, which worker exit cancels.
    pub fn set_user_data(&mut self, idx: u16, user_data: u64) {
        self.entries[idx as usize].user_data = user_data;
    }

    /// The user_data of every command that holds a slot.
    pub fn in_flight_user_data(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .filter(|e| e.in_use)
            .map(|e| e.user_data)
    }
}

/// The status word of an NVMe command the device failed.
///
/// The inner error of the `io::Error` of kind `Other` that [`nvme_read`](crate::nvme_read),
/// [`nvme_write`](crate::nvme_write) and [`nvme_flush`](crate::nvme_flush)
/// resolve to for such a command: `error.get_ref()` or `error.into_inner()`
/// gives it, and it downcasts to this type. It is not in the `source()` chain.
/// A command that failed in transport resolves to the errno's `io::Error`
/// instead. The word is the 15-bit status field of the completion queue
/// entry: status code type in bits 8 to 10, status code in bits 0 to 7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeStatus(u16);

impl NvmeStatus {
    /// The status word.
    pub fn word(&self) -> u16 {
        self.0
    }

    /// Bits 8 to 10: the status code type (0 generic, 1 command-specific,
    /// 2 media and data integrity, 3 path, 7 vendor-specific).
    pub fn code_type(&self) -> u8 {
        ((self.0 >> 8) & 0x7) as u8
    }

    /// Bits 0 to 7: the status code within its type.
    pub fn code(&self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

impl std::fmt::Display for NvmeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NVMe status 0x{:x}", self.0)
    }
}

impl std::error::Error for NvmeStatus {}

/// Below this (negated) the disk-I/O result of an NVMe command is an errno;
/// at or above it, a status word.
const STATUS_RESULT_BASE: i32 = 0x1_0000;

/// The disk-I/O result of an NVMe command's `cqe->res`: 0 and a negative
/// errno pass through, and a positive status word (the device failed the
/// command) becomes a negative value at or below `-0x1_0000`, past every
/// errno, so the result stays an error and keeps the word.
pub(crate) fn status_result(res: i32) -> i32 {
    if res > 0 {
        -(STATUS_RESULT_BASE | (res & 0xFFFF))
    } else {
        res
    }
}

/// The error a negative disk-I/O result of an NVMe command resolves to.
pub(crate) fn error_from_result(result: i32) -> std::io::Error {
    debug_assert!(result < 0);
    if result <= -STATUS_RESULT_BASE {
        let word = ((-result) & 0xFFFF) as u16;
        std::io::Error::other(NvmeStatus(word))
    } else {
        std::io::Error::from_raw_os_error(-result)
    }
}

/// Configuration for NVMe passthrough support.
///
/// When present in [`Config`](crate::config::Config), enables NVMe device
/// management and allocates device/command tracking structures.
#[derive(Clone, Debug)]
pub struct NvmeConfig {
    /// Maximum number of NVMe devices that can be opened simultaneously.
    pub(crate) max_devices: u16,
    /// Maximum NVMe commands in flight across all devices per worker.
    pub(crate) max_commands_in_flight: u16,
}

impl Default for NvmeConfig {
    fn default() -> Self {
        NvmeConfig {
            max_devices: 4,
            max_commands_in_flight: 256,
        }
    }
}

impl NvmeConfig {
    /// Set the most NVMe devices open at once on each worker. Defaults to 4.
    pub fn max_devices(mut self, max_devices: u16) -> Self {
        self.max_devices = max_devices;
        self
    }

    /// Set the most NVMe commands in flight across all devices, per worker. Defaults to 256.
    ///
    /// One submitted at the limit fails with an error of kind `WouldBlock`,
    /// `NVMe command slab exhausted`.
    ///
    /// Each command slot has 16,384 operation keys. A future holds one from
    /// submission until it takes its result or is dropped on the worker that
    /// created it. A future that is neither polled to completion nor dropped
    /// keeps its key after its command completes, and one dropped on another
    /// thread keeps it for the life of that worker. The slot freed last is
    /// reused first, so in a serial workload 16,384 such futures make every
    /// later operation fail with `every disk-I/O key for this slab slot is held
    /// by a future`, until one of them takes its result or is dropped on that
    /// worker, while other slots are free.
    pub fn max_commands_in_flight(mut self, max_commands_in_flight: u16) -> Self {
        self.max_commands_in_flight = max_commands_in_flight;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A positive `cqe->res` is the status word the device returned; it
    /// resolves to an error that carries the word. Zero and a negative errno
    /// resolve as before.
    #[test]
    fn a_status_word_reaches_the_caller_as_the_errors_inner_error() {
        assert_eq!(status_result(0), 0);
        assert_eq!(status_result(-libc::EINVAL), -libc::EINVAL);
        let encoded = status_result(0x281);
        assert!(encoded < 0, "a status word is an error");
        let err = error_from_result(encoded);
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let status = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<NvmeStatus>())
            .copied()
            .expect("the error's inner error is the status word");
        assert_eq!(status.word(), 0x281);
        assert_eq!(status.code_type(), 2, "media and data integrity");
        assert_eq!(status.code(), 0x81, "unrecovered read error");
        assert_eq!(err.to_string(), "NVMe status 0x281");
        let errno = error_from_result(-libc::EINVAL);
        assert_eq!(errno.raw_os_error(), Some(libc::EINVAL));
        assert!(errno.get_ref().is_none());
    }

    #[test]
    fn builder_sets_each_field_and_default_keeps_the_rest() {
        let d = NvmeConfig::default();
        assert_eq!((d.max_devices, d.max_commands_in_flight), (4, 256));
        let c = NvmeConfig::default()
            .max_devices(2)
            .max_commands_in_flight(32);
        assert_eq!((c.max_devices, c.max_commands_in_flight), (2, 32));
    }

    fn identify_with(nlbaf: u8, flbas: u8, formats: &[(usize, u8)]) -> Vec<u8> {
        let mut data = vec![0u8; 4096];
        data[25] = nlbaf;
        data[26] = flbas;
        for &(index, lbads) in formats {
            data[128 + 4 * index + 2] = lbads;
        }
        data
    }

    #[test]
    fn lba_size_comes_from_the_formatted_lba_format() {
        // Format 0 is 512 bytes, format 1 (formatted) is 4096.
        let data = identify_with(1, 1, &[(0, 9), (1, 12)]);
        assert_eq!(lba_size_from_identify(&data).unwrap(), 4096);
        let data = identify_with(1, 0, &[(0, 9), (1, 12)]);
        assert_eq!(lba_size_from_identify(&data).unwrap(), 512);
    }

    #[test]
    fn lba_size_reads_the_high_bits_of_the_format_index() {
        // FLBAS bits 6:5 = 1, bits 3:0 = 2: format 18.
        let data = identify_with(20, (1 << 5) | 2, &[(2, 9), (18, 12)]);
        assert_eq!(lba_size_from_identify(&data).unwrap(), 4096);
    }

    #[test]
    fn lba_size_refuses_a_format_with_metadata() {
        let mut data = identify_with(1, 1, &[(0, 9), (1, 9)]);
        // Format 1: 512 bytes plus 8 bytes of metadata.
        data[128 + 4] = 8;
        let err = lba_size_from_identify(&data).unwrap_err();
        assert!(err.to_string().contains("metadata"), "{err}");
        // Format 0, without metadata, is accepted.
        data[26] = 0;
        assert_eq!(lba_size_from_identify(&data).unwrap(), 512);
    }

    #[test]
    fn lba_size_rejects_malformed_identify_data() {
        assert!(lba_size_from_identify(&[0u8; 512]).is_err(), "short");
        let data = identify_with(0, 1, &[(1, 12)]);
        assert!(lba_size_from_identify(&data).is_err(), "index beyond NLBAF");
        let data = identify_with(0, 0, &[(0, 0)]);
        assert!(lba_size_from_identify(&data).is_err(), "LBADS 0");
    }

    #[test]
    fn nvme_ioctl_admin_cmd_encodes_its_struct_size() {
        assert_eq!(std::mem::size_of::<NvmePassthruCmd>(), 72);
        let ioc: libc::c_ulong = (3 << 30) | (72 << 16) | ((b'N' as libc::c_ulong) << 8) | 0x41;
        assert_eq!(NVME_IOCTL_ADMIN_CMD, ioc);
    }

    #[test]
    fn nvme_uring_cmd_size() {
        assert_eq!(std::mem::size_of::<NvmeUringCmd>(), 72);
    }

    #[test]
    fn nvme_uring_cmd_fits_in_80_bytes() {
        assert!(std::mem::size_of::<NvmeUringCmd>() <= 80);
    }

    #[test]
    fn read_command_fields() {
        let cmd = NvmeUringCmd::read(1, 0x1000, 8, 0xDEAD_BEEF, 4096);
        assert_eq!(cmd.opcode, NVME_CMD_READ);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.cdw10, 0x1000); // LBA low
        assert_eq!(cmd.cdw11, 0); // LBA high
        assert_eq!(cmd.cdw12, 7); // NLB = num_blocks - 1
        assert_eq!(cmd.addr, 0xDEAD_BEEF);
        assert_eq!(cmd.data_len, 4096);
    }

    #[test]
    fn write_command_fields() {
        let cmd = NvmeUringCmd::write(1, 0x2000_0000_0000, 1, 0xCAFE, 512);
        assert_eq!(cmd.opcode, NVME_CMD_WRITE);
        assert_eq!(cmd.cdw10, 0); // LBA low (0x2000_0000_0000 & 0xFFFF_FFFF)
        assert_eq!(cmd.cdw11, 0x2000); // LBA high
        assert_eq!(cmd.cdw12, 0); // NLB = 0 (one block)
    }

    #[test]
    fn flush_command() {
        let cmd = NvmeUringCmd::flush(1);
        assert_eq!(cmd.opcode, NVME_CMD_FLUSH);
        assert_eq!(cmd.nsid, 1);
        assert_eq!(cmd.addr, 0);
        assert_eq!(cmd.data_len, 0);
    }

    #[test]
    fn to_bytes_roundtrip() {
        let cmd = NvmeUringCmd::read(1, 42, 1, 0x1234, 512);
        let bytes = cmd.to_bytes();
        let recovered: NvmeUringCmd =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const _) };
        assert_eq!(recovered.opcode, NVME_CMD_READ);
        assert_eq!(recovered.nsid, 1);
        assert_eq!(recovered.cdw10, 42);
        assert_eq!(recovered.addr, 0x1234);
    }

    #[test]
    fn device_table_alloc_release() {
        let mut table = NvmeDeviceTable::new(4);
        let a = table.allocate().unwrap();
        let b = table.allocate().unwrap();
        assert_ne!(a, b);
        assert!(table.get(a).is_some());

        table.release(a);
        assert!(table.get(a).is_none());

        // Re-allocate reuses the slot.
        let c = table.allocate().unwrap();
        assert_eq!(c, a);
        // Generation incremented.
        assert_eq!(table.get(c).unwrap().generation, 1);
    }

    /// A slot reused 65,536 times does not repeat its first generation, so a
    /// handle kept from the first open stays stale (#862).
    #[test]
    fn generation_does_not_repeat_after_65536_releases() {
        let mut table = NvmeDeviceTable::new(1);
        let index = table.allocate().unwrap();
        let first = table.get(index).unwrap().generation;
        for _ in 0..65_536 {
            table.release(index);
            assert_eq!(table.allocate(), Some(index));
        }
        assert_ne!(table.get(index).unwrap().generation, first);
    }

    #[test]
    fn cmd_slab_alloc_release() {
        let mut slab = NvmeCmdSlab::new(8);
        let a = slab.allocate(0).unwrap();
        let b = slab.allocate(1).unwrap();
        assert!(slab.in_use(a));
        assert!(slab.in_use(b));
        assert_eq!(slab.device_index(a), 0);
        assert_eq!(slab.device_index(b), 1);

        let dev = slab.release(a);
        assert_eq!(dev, 0);
        assert!(!slab.in_use(a));
    }

    #[test]
    #[should_panic(expected = "num_blocks must be >= 1")]
    fn read_zero_blocks_panics() {
        NvmeUringCmd::read(1, 0, 0, 0x1234, 0);
    }

    #[test]
    #[should_panic(expected = "num_blocks must be >= 1")]
    fn write_zero_blocks_panics() {
        NvmeUringCmd::write(1, 0, 0, 0x1234, 0);
    }

    #[test]
    fn read_one_block_has_nlb_zero() {
        let cmd = NvmeUringCmd::read(1, 42, 1, 0x1234, 512);
        assert_eq!(cmd.cdw12, 0, "NLB for 1 block should be 0 (0-based)");
    }

    #[test]
    fn write_max_blocks_has_correct_nlb() {
        let cmd = NvmeUringCmd::write(1, 0, u16::MAX, 0x1234, 512);
        assert_eq!(cmd.cdw12, (u16::MAX - 1) as u32);
    }
}
