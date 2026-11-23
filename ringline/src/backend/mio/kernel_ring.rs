//! Ringkern's completion ring, used by the mio backend on Hermit with the
//! `ringkern` feature for reads and writes on block devices.
//!
//! The worker submits each read or write as a ring operation whose
//! `user_data` is its disk-I/O key, instead of sending it to the disk-I/O
//! pool. The ring's descriptor is registered with mio as [`RING_TOKEN`] and
//! polls readable while completions wait; the event loop reaps them in
//! `drain_channels`, where pool responses are handled, so the bounds, the
//! fsync ordering and the exit wait apply to both. Ringkern runs ring
//! operations only on its NVMe block device (`/dev/nvme0n1`); every other
//! file, and every fsync, stays on the pool, as does a transfer longer than
//! [`MAX_LEN`].
//!
//! Each file's first read or write calls `fstat` on the worker to find
//! whether it is a block device. A write's data is copied when its command
//! reaches one of the kernel driver's slots: inside `sys_ring_enter`, on the
//! worker, if a slot is free, and otherwise when one frees, after
//! `sys_ring_enter` has returned; the buffer stays borrowed until the
//! completion is reaped.

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::fs::FileKind;
use crate::sys::{RingCqe, RingSqe};

/// The mio token of the ring's descriptor. Connection tokens are
/// `index + 1` and UDP tokens start at `udp_token_base`, both far below.
pub(crate) const RING_TOKEN: mio::Token = mio::Token(usize::MAX - 1);

/// Completions moved out per `sys_ring_enter` while reaping.
const REAP_BATCH: usize = 64;

/// The longest read or write Ringkern's ring accepts (its `RING_MAX_LEN`);
/// a longer one goes to the pool.
pub(crate) const MAX_LEN: u32 = 0x7fff_f000;

pub(crate) struct KernelRing {
    fd: OwnedFd,
    /// Whether a file, by kind, slot and generation, is a block device,
    /// which ring operations support. Filled on a file's first read or
    /// write and dropped when it closes.
    block_device: HashMap<(FileKind, u16, u32), bool>,
    /// Keys of the operations submitted and not yet reaped.
    in_flight: HashSet<u64>,
    /// Whether the descriptor's readable interest is registered with mio.
    /// mio's poll selector drops it once it reports the descriptor.
    pub(crate) armed: bool,
    cqes: Vec<RingCqe>,
}

impl KernelRing {
    /// A ring that holds `entries` operations submitted and not yet reaped,
    /// at most 4096: the sum of the subsystems' `max_commands_in_flight`, so
    /// the bounds keep it from filling unless that sum is above 4096. A
    /// submission to a full ring fails as one past a subsystem's bound does.
    pub(crate) fn new(entries: u32) -> io::Result<Self> {
        Ok(Self {
            fd: crate::sys::ring_setup(entries.clamp(1, 4096))?,
            block_device: HashMap::new(),
            in_flight: HashSet::new(),
            armed: false,
            cqes: vec![RingCqe::default(); REAP_BATCH],
        })
    }

    pub(crate) fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Whether `fd`, the file `(kind, index, generation)`, takes ring
    /// operations: whether it is a block device.
    pub(crate) fn takes(&mut self, kind: FileKind, index: u16, generation: u32, fd: RawFd) -> bool {
        *self
            .block_device
            .entry((kind, index, generation))
            .or_insert_with(|| {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let stat = unsafe { libc::fstat(fd, &mut st) };
                stat == 0 && st.st_mode & libc::S_IFMT == libc::S_IFBLK
            })
    }

    /// Forget what [`takes`](Self::takes) recorded for slot `index`.
    pub(crate) fn forget(&mut self, kind: FileKind, index: u16) {
        self.block_device
            .retain(|&(k, i, _), _| !(k == kind && i == index));
    }

    /// Submit one operation.
    pub(crate) fn submit(&mut self, sqe: RingSqe) -> io::Result<()> {
        crate::sys::ring_enter(self.fd(), &[sqe], &mut [], 0)?;
        self.in_flight.insert(sqe.user_data);
        Ok(())
    }

    /// Whether an operation submitted is not yet reaped.
    pub(crate) fn has_in_flight(&self) -> bool {
        !self.in_flight.is_empty()
    }

    /// Move every waiting completion into `out` as `(key, result)`, waiting
    /// for at least one if `wait` and an operation is in flight.
    pub(crate) fn reap(&mut self, out: &mut Vec<(u64, i32)>, wait: bool) -> io::Result<()> {
        let mut min = usize::from(wait && self.has_in_flight());
        loop {
            let n = crate::sys::ring_enter(self.fd(), &[], &mut self.cqes, min)?;
            for c in &self.cqes[..n] {
                self.in_flight.remove(&c.user_data);
                out.push((c.user_data, c.result as i32));
            }
            if n < self.cqes.len() {
                return Ok(());
            }
            min = 0;
        }
    }
}
