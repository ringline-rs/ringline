//! Cross-thread control plane for dynamic fixed-buffer region registration.
//!
//! Each worker owns a [`RegionControlRx`] that the event loop drains once per
//! tick. [`Runtime::register_region`](crate::Runtime::register_region)
//! and [`Runtime::unregister_region`](crate::Runtime::unregister_region)
//! send a [`RegionControlMsg`] to every worker, wake them via their
//! [`WakeHandle`](crate::WakeHandle), and block until every worker that
//! received the message has acked it or exited.
//!
//! Slot indices are coherent across workers: the registrar picks a slot, then
//! every worker writes the same iovec into the same `RegionId`. A failed
//! register is followed by a `Release` broadcast, which clears the slot on
//! any worker that holds it.

use std::io;
use std::sync::Mutex;

use crossbeam_channel::{Receiver, Sender, bounded, unbounded};

use crate::buffer::fixed::{MemoryRegion, RegionId};
use crate::wakeup::WakeHandle;

/// A control message dispatched to every worker for a region operation.
pub(crate) enum RegionControlMsg {
    Register {
        slot: u16,
        region: MemoryRegion,
        ack: Sender<io::Result<()>>,
    },
    Unregister {
        slot: u16,
        ack: Sender<io::Result<()>>,
    },
    /// Clear the slot if this worker holds a region in it; a no-op if the
    /// slot is empty. Sent after a failed `Register`, which can leave the
    /// region registered on some workers and not others.
    Release {
        slot: u16,
        ack: Sender<io::Result<()>>,
    },
}

/// The bytes of base pages `region` touches, which is what the kernel charges
/// for it unless it is on huge pages.
pub(crate) fn page_rounded(region: &MemoryRegion) -> u64 {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u64;
    let start = region.ptr() as u64;
    ((start + region.len() as u64).div_ceil(page) - start / page) * page
}

/// Per-worker receiver. The event loop owns this and drains it each tick.
pub(crate) type RegionControlRx = Receiver<RegionControlMsg>;

/// Shared registrar held by [`Runtime`]. Owns the slot allocator and
/// the per-worker senders.
pub(crate) struct RegionRegistrar {
    inner: Mutex<RegistrarInner>,
    workers: Vec<Sender<RegionControlMsg>>,
    wake_handles: Vec<WakeHandle>,
}

struct RegistrarInner {
    /// Stack of free slot indices, popped on `register`, pushed on `unregister`.
    free_slots: Vec<u16>,
    /// The length of the region in each slot, rounded out to base pages, 0
    /// for a free slot. A failed register with `ENOMEM` reports their sum,
    /// which io_uring has charged once for each worker's ring. A region whose
    /// registration is still in progress on another thread is not in it.
    bytes: Vec<u64>,
    /// `MemoryRegion::base_pages` of the region in each slot, `false` for a
    /// free slot.
    base_pages: Vec<bool>,
}

impl RegionRegistrar {
    /// Build a registrar with `max_slots` total capacity, where the first
    /// `reserved.len()` slots are pre-occupied by the initial
    /// `Config::registered_regions`, whose lengths `reserved` holds.
    pub(crate) fn new(
        max_slots: u16,
        reserved: &[(u64, bool)],
        workers: Vec<Sender<RegionControlMsg>>,
        wake_handles: Vec<WakeHandle>,
    ) -> Self {
        debug_assert!(reserved.len() <= max_slots as usize);
        debug_assert_eq!(workers.len(), wake_handles.len());
        // Free list ordered so smaller slots come out first.
        let free_slots: Vec<u16> = (reserved.len() as u16..max_slots).rev().collect();
        let mut bytes = vec![0; max_slots as usize];
        let mut base_pages = vec![false; max_slots as usize];
        for (slot, &(len, base)) in reserved.iter().enumerate() {
            bytes[slot] = len;
            base_pages[slot] = base;
        }
        RegionRegistrar {
            inner: Mutex::new(RegistrarInner {
                free_slots,
                bytes,
                base_pages,
            }),
            workers,
            wake_handles,
        }
    }

    /// Allocate a slot, broadcast a `Register` message to every worker, and
    /// block until all workers ack. On any worker error the first error is
    /// returned and a `Release` is broadcast. The slot goes back to the free
    /// list only if every worker acks the release. If a worker's control
    /// channel is disconnected, or its release fails, the slot is not
    /// returned to the free list and later registrations use other slots.
    pub(crate) fn register(&self, region: MemoryRegion) -> io::Result<RegionId> {
        let slot = {
            let mut inner = self.inner.lock().expect("registrar mutex poisoned");
            inner
                .free_slots
                .pop()
                .ok_or_else(|| io::Error::other("registered-region table is full"))?
        };

        match self.broadcast(|ack| RegionControlMsg::Register {
            slot,
            region: region.clone(),
            ack,
        }) {
            Ok(()) => {
                let mut inner = self.inner.lock().expect("registrar mutex poisoned");
                inner.bytes[slot as usize] = page_rounded(&region);
                inner.base_pages[slot as usize] = region.base_pages;
                Ok(RegionId(slot))
            }
            Err(e) => {
                let e = self.with_charge(e, page_rounded(&region));
                if self
                    .broadcast(|ack| RegionControlMsg::Release { slot, ack })
                    .is_ok()
                {
                    self.return_slot(slot);
                }
                Err(e)
            }
        }
    }

    /// Whether the region registered as `id` was shown to be in base pages
    /// only; `None` when `id` names no registered region.
    #[cfg_attr(not(has_io_uring), allow(dead_code))]
    pub(crate) fn base_pages(&self, id: RegionId) -> Option<bool> {
        let inner = self.inner.lock().expect("registrar mutex poisoned");
        let slot = id.0 as usize;
        if slot >= inner.bytes.len() || inner.bytes[slot] == 0 {
            return None;
        }
        Some(inner.base_pages[slot])
    }

    /// Add the regions already registered to an `ENOMEM` from a register of
    /// `adding` bytes, when `RLIMIT_MEMLOCK` is finite. The workers' error
    /// names only the one buffer, which alone is usually within the limit.
    fn with_charge(&self, e: io::Error, adding: u64) -> io::Error {
        #[cfg(has_io_uring)]
        {
            let limit = crate::error::MemlockLimit::read().ok();
            self.with_charge_under(e, adding, limit.as_ref())
        }
        #[cfg(not(has_io_uring))]
        {
            let _ = adding;
            e
        }
    }

    #[cfg(any(has_io_uring, test))]
    fn with_charge_under(
        &self,
        e: io::Error,
        adding: u64,
        limit: Option<&crate::error::MemlockLimit>,
    ) -> io::Error {
        let Some(limit) = limit.filter(|_| e.kind() == io::ErrorKind::OutOfMemory) else {
            return e;
        };
        let (held, regions) = {
            let inner = self.inner.lock().expect("registrar mutex poisoned");
            (
                inner.bytes.iter().sum::<u64>(),
                inner.bytes.iter().filter(|&&b| b > 0).count(),
            )
        };
        match crate::error::describe_region_charge(held, regions, self.workers.len(), adding, limit)
        {
            Some(context) => io::Error::new(e.kind(), format!("{e} {context}")),
            None => e,
        }
    }

    /// Broadcast an `Unregister` message and block until every worker acks.
    /// On success the slot returns to the free list.
    pub(crate) fn unregister(&self, id: RegionId) -> io::Result<()> {
        if id == RegionId::UNREGISTERED {
            return Err(io::Error::other("cannot unregister UNREGISTERED sentinel"));
        }
        let slot = id.0;
        self.broadcast(|ack| RegionControlMsg::Unregister { slot, ack })?;
        let mut inner = self.inner.lock().expect("registrar mutex poisoned");
        inner.bytes[slot as usize] = 0;
        inner.base_pages[slot as usize] = false;
        drop(inner);
        self.return_slot(slot);
        Ok(())
    }

    fn broadcast(
        &self,
        mut build: impl FnMut(Sender<io::Result<()>>) -> RegionControlMsg,
    ) -> io::Result<()> {
        let n = self.workers.len();
        let (ack_tx, ack_rx) = bounded(n);

        // A failed send (the worker's receiver has been dropped) is recorded as
        // the error and the remaining workers still get the message, so a
        // `Release` reaches every running worker. The failed message drops its ack sender, so the
        // collection below sees one fewer ack and then a disconnect.
        let mut first_err: Option<io::Error> = None;
        for (tx, wake) in self.workers.iter().zip(&self.wake_handles) {
            // Each message carries its own ack sender so workers can reply
            // independently without coordinating with each other.
            let msg = build(ack_tx.clone());
            if tx.send(msg).is_err() {
                first_err
                    .get_or_insert_with(|| io::Error::other("worker control channel disconnected"));
                continue;
            }
            wake.wake();
        }
        drop(ack_tx);

        // Collect every ack; surface the first error encountered while still
        // draining the rest so no worker is left blocked on a send.
        for _ in 0..n {
            match ack_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) if first_err.is_none() => first_err = Some(e),
                Ok(Err(_)) => {}
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(io::Error::other(
                            "worker terminated before acknowledging region update",
                        ));
                    }
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn return_slot(&self, slot: u16) {
        let mut inner = self.inner.lock().expect("registrar mutex poisoned");
        inner.free_slots.push(slot);
    }
}

/// Build per-worker sender/receiver pairs for the region control channel.
pub(crate) fn build_worker_channels(
    num_workers: usize,
) -> (Vec<Sender<RegionControlMsg>>, Vec<RegionControlRx>) {
    let mut txs = Vec::with_capacity(num_workers);
    let mut rxs = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        let (tx, rx) = unbounded();
        txs.push(tx);
        rxs.push(rx);
    }
    (txs, rxs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::thread;

    /// A worker that keeps a slot table the way the event loop does, without
    /// a ring. `fail_registers` is how many `Register` messages it refuses,
    /// without recording the slot, before it starts accepting them.
    fn fake_worker(rx: RegionControlRx, mut fail_registers: usize) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut held: HashSet<u16> = HashSet::new();
            for msg in rx {
                match msg {
                    RegionControlMsg::Register { slot, ack, .. } => {
                        let r = if held.contains(&slot) {
                            Err(io::Error::new(io::ErrorKind::InvalidInput, "slot occupied"))
                        } else if fail_registers > 0 {
                            fail_registers -= 1;
                            Err(io::Error::from_raw_os_error(libc::EFAULT))
                        } else {
                            held.insert(slot);
                            Ok(())
                        };
                        let _ = ack.send(r);
                    }
                    RegionControlMsg::Unregister { slot, ack } => {
                        let r = if held.remove(&slot) {
                            Ok(())
                        } else {
                            Err(io::Error::new(io::ErrorKind::InvalidInput, "slot empty"))
                        };
                        let _ = ack.send(r);
                    }
                    RegionControlMsg::Release { slot, ack } => {
                        held.remove(&slot);
                        let _ = ack.send(Ok(()));
                    }
                }
            }
        })
    }

    /// An `ENOMEM` from a register names the regions already registered and
    /// the total the rings need, counting each region once per worker.
    #[test]
    fn enomem_register_reports_the_regions_already_charged() {
        let (txs, rxs) = build_worker_channels(2);
        let wakes = (0..2)
            .map(|_| crate::wakeup::create_wake_fd().unwrap().1)
            .collect();
        let registrar = RegionRegistrar::new(4, &[(4096, false)], txs, wakes);
        let workers: Vec<_> = rxs.into_iter().map(|rx| fake_worker(rx, 0)).collect();

        let mut backing = [0u8; 8192];
        let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), backing.len()) };
        let rounded = page_rounded(&region);
        assert!(rounded >= 8192 && rounded.is_multiple_of(4096), "{rounded}");
        let id = registrar.register(region).unwrap();

        let limit = crate::error::MemlockLimit {
            soft: 16384,
            hard: 16384,
        };
        let oom = io::Error::new(io::ErrorKind::OutOfMemory, "ENOMEM from a worker");
        let text = registrar
            .with_charge_under(oom, 1024, Some(&limit))
            .to_string();
        assert!(text.starts_with("ENOMEM from a worker "), "{text}");
        // The reserved 4096 bytes plus the region in whole pages, on each of
        // 2 rings, then with 1024 bytes more.
        let held = 4096 + rounded;
        let want = format!("2 registered region(s) of {} KiB", held / 1024);
        assert!(text.contains(&want), "{text}");
        let want = format!("charged {} KiB", 2 * held / 1024);
        assert!(text.contains(&want), "{text}");
        let want = format!("the rings need {} KiB", (2 * (held + 1024)) / 1024);
        assert!(text.contains(&want), "{text}");

        // Unregistering removes the region from the count.
        registrar.unregister(id).unwrap();
        let oom = io::Error::new(io::ErrorKind::OutOfMemory, "ENOMEM from a worker");
        let text = registrar
            .with_charge_under(oom, 1024, Some(&limit))
            .to_string();
        assert!(text.contains("1 registered region(s) of 4 KiB"), "{text}");

        // Other errors, and an unlimited soft limit, pass through unchanged.
        let efault = io::Error::from_raw_os_error(libc::EFAULT);
        let e = registrar.with_charge_under(efault, 1024, Some(&limit));
        assert_eq!(e.raw_os_error(), Some(libc::EFAULT));
        let unlimited = crate::error::MemlockLimit {
            soft: libc::RLIM_INFINITY,
            hard: libc::RLIM_INFINITY,
        };
        let oom = io::Error::new(io::ErrorKind::OutOfMemory, "ENOMEM from a worker");
        let text = registrar
            .with_charge_under(oom, 1024, Some(&unlimited))
            .to_string();
        assert_eq!(text, "ENOMEM from a worker");

        drop(registrar);
        for w in workers {
            w.join().unwrap();
        }
    }

    /// A register that fails on one worker and succeeds on another leaves
    /// the slot usable: the retry gets the same slot and succeeds on both.
    #[test]
    fn failed_register_on_one_worker_releases_the_slot_everywhere() {
        let (txs, rxs) = build_worker_channels(2);
        let wakes = (0..2)
            .map(|_| crate::wakeup::create_wake_fd().unwrap().1)
            .collect();
        let registrar = RegionRegistrar::new(4, &[], txs, wakes);
        let mut rxs = rxs.into_iter();
        let ok = fake_worker(rxs.next().unwrap(), 0);
        let failing = fake_worker(rxs.next().unwrap(), 1);

        let mut backing = [0u8; 64];
        let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), backing.len()) };
        let err = registrar.register(region.clone()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EFAULT));

        let id = registrar
            .register(region)
            .expect("retry after a failed register");
        assert_eq!(id, RegionId(0), "the released slot is reused");
        registrar.unregister(id).unwrap();

        drop(registrar);
        ok.join().unwrap();
        failing.join().unwrap();
    }
}
