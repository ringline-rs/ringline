use std::io;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::time::Instant;

use crate::backend::uring::abi::cqueue;
use crate::handler::SendPoll;

use crate::backend::Driver;
use crate::backend::sockaddr_to_socket_addr;
use crate::chain::ChainEvent;
use crate::completion::{OpTag, UserData};
use crate::connection::{Lifecycle, ReadHalf};
use crate::metrics;
use crate::runtime::handler::AsyncEventHandler;
use crate::runtime::io::{ConnCtx, DriverState, UdpSocket, set_driver_state_guarded};
use crate::runtime::send_completion::SendId;
use crate::runtime::task::Park;
use crate::runtime::waker::{STANDALONE_BIT, conn_waker, standalone_waker};
use crate::runtime::{CURRENT_TASK_ID, Executor, TimerSlotPool};

/// Async event loop that reuses `Driver` infrastructure with an `Executor`
/// for polling connection futures instead of push-based callbacks.
pub(crate) struct AsyncEventLoop<A: AsyncEventHandler> {
    driver: Driver,
    handler: A,
    executor: Executor,
}

/// Hand off only on a real imbalance. A margin of one would ping-pong
/// connections between workers that differ by a single connection, and every
/// handoff costs a channel send and a wake on the far side.
const HANDOFF_MARGIN: u32 = 2;

/// How far above the least-loaded worker this one must sit before it will
/// park an established connection (tier 3, #443).
///
/// Deliberately wider than [`HANDOFF_MARGIN`]. Tier 1 places a connection
/// that does not exist yet and costs an integer; tier 3 moves a live one and
/// costs a round trip through the kernel plus a handler restart. Letting the
/// cheap mechanism act first, and only escalating when it could not keep up,
/// is also what stops the two fighting: at this gap tier 1 has already been
/// placing everything it sees onto the same target and the imbalance is
/// standing rather than transient.
const PARK_MARGIN: u32 = 8;

/// A worker will not park below this many connections.
///
/// Without a floor, the last few connections ping-pong: a worker at 1 is
/// always "above" a worker at 0 by whatever margin, so the pair never
/// settles. It also stops a quiet server draining workers to nothing and
/// then re-accepting onto them.
const PARK_FLOOR: u32 = 4;

/// Most parks one worker will start per [`Self::on_tick`] (tier 3, #443).
///
/// Park is a repair, not a scheduler. Moving one connection per tick
/// converges a standing imbalance over a few hundred milliseconds while
/// keeping the cost per tick bounded and leaving the load table time to
/// reflect each move — a burst would decide every park from the same stale
/// snapshot, which is how tier 1 first produced a thundering herd.
const PARK_PER_TICK: usize = 1;

/// Ticks a drained park waits for the handler to re-offer before giving up.
///
/// A handler that reaches a quiescent point re-offers on its very next poll, so
/// this only has to outlast the in-flight recv CQEs the cancel could not retract
/// plus one handler turn. It exists because a handler awaiting something
/// external may never come back, and a connection with no recv armed and no
/// deadline would wait forever — worse than not parking it.
const PARK_DRAIN_TICKS: u16 = 64;

/// Pick a worker to park a connection onto, or `None` to stay put.
///
/// Pure, like [`choose_placement`], so the policy can be tested without a
/// ring. It answers only "should this worker shed, and to whom" — *which*
/// connection to move is a separate question, and the answer there is
/// whichever one the handler offered.
fn choose_park_target(loads: &[u32], accepting: &[bool], me: usize, mine: u32) -> Option<usize> {
    // A worker steered out of the accept rotation (tier 2) has a falling load
    // precisely because it is being drained. Parking onto it would put back
    // what steering just took out — the same trap `choose_placement` names.
    let (min_idx, min_load) = loads
        .iter()
        .copied()
        .enumerate()
        .filter(|&(i, _)| accepting.get(i).copied().unwrap_or(true))
        .min_by_key(|&(_, l)| l)?;

    if min_idx == me || mine <= PARK_FLOOR {
        return None;
    }
    // Compared against the *target's* load, not the mean: the question is
    // whether moving one connection helps this pair, and a mean would keep
    // firing while every worker was already within a connection of it.
    if mine >= min_load.saturating_add(PARK_MARGIN) {
        Some(min_idx)
    } else {
        None
    }
}

/// Where a newly accepted connection should be served: `None` for "here",
/// otherwise the index of a peer far enough below this worker to be worth the
/// handoff.
///
/// Pure so it can be tested directly. The emergent distribution this produces
/// is a property of a heuristic under real timing and belongs in the rack A/B
/// (`docs/listeners-and-accept-design.md`, "Measurement"), not in an assertion
/// here — an earlier version of this test asserted a spread bound and was
/// flaky in both directions.
fn choose_placement(loads: &[u32], accepting: &[bool], me: usize, mine: u32) -> Option<usize> {
    // Only consider workers still in the accept rotation. A worker steered out
    // (tier 2) stops receiving from the kernel, so its load falls — and without
    // this filter that drop would make it the *most* attractive handoff target,
    // so placement would put back exactly what steering took out.
    let (min_idx, min_load) = loads
        .iter()
        .copied()
        .enumerate()
        .filter(|&(i, _)| accepting.get(i).copied().unwrap_or(true))
        .min_by_key(|&(_, l)| l)?;
    // An idle worker is qualitatively different from a merely quiet one:
    // handing it this connection cannot make anything worse, and refusing to
    // is how tier 1 came to do nothing at all in the case it exists for.
    //
    // `mine` is this worker's count *before* installing the arrival, so a
    // margin of 2 means a worker first sheds on its **third** connection. When
    // a pooled client opens about as many connections as there are workers,
    // almost nobody receives a third — so placement never fired, and the rack
    // measured 2 of 8 workers left idle in 3 of 3 reps (#457, #456). Dropping
    // the margin to 1 against an idle worker lets a worker shed its *second*
    // connection, which is the one that matters at that scale.
    //
    // The margin of 2 still applies between two non-empty workers, so the
    // ping-pong it exists to prevent is unaffected.
    let margin = if min_load == 0 { 1 } else { HANDOFF_MARGIN };
    if min_idx != me && mine >= min_load.saturating_add(margin) {
        Some(min_idx)
    } else {
        None
    }
}

impl<A: AsyncEventHandler> AsyncEventLoop<A> {
    /// Report the panics caught in the `Drop` of removed futures.
    fn report_drop_panics(&mut self) {
        for payload in self.executor.take_drop_panics() {
            self.driver.panic_reporter.report("task drop", &*payload);
        }
    }

    /// Drop every task at worker exit and report panics in their `Drop`.
    pub(crate) fn drop_tasks(&mut self) {
        self.executor.drop_tasks();
        // Results delivered after their futures went.
        if let Some(rx) = self.driver.blocking_rx.take() {
            for response in rx.try_iter() {
                self.executor.task_slab.drop_noting_panic(response);
            }
            // Dropping it discards a response sent since the loop above.
            self.executor.task_slab.drop_noting_panic(rx);
        }
        self.report_drop_panics();
    }

    /// Report that this worker stopped for `cause`.
    pub(crate) fn report_worker_exit(&self, worker: usize, cause: &str) {
        self.driver.panic_reporter.report_worker_exit(worker, cause);
    }

    /// Report that this worker's drain has ended.
    pub(crate) fn report_worker_drained(&self, worker: usize) {
        self.driver.panic_reporter.report_worker_drained(worker);
    }

    /// Close connections and wait for the kernel to finish with their memory,
    /// after `run` ended with an error or a panic.
    pub(crate) fn drain_after_failure(&mut self) {
        #[cfg(test)]
        if let Some(fault) = &self.driver.test_fault
            && fault
                .panic_in_drain
                .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            panic!("injected drain panic");
        }
        self.driver.run_shutdown();
    }

    /// Whether the drain ended with an fs, direct I/O or NVMe command still in
    /// flight. The kernel can still use memory the event loop and its tasks
    /// own, so the caller must leak it, through [`close_ring`](Self::close_ring)
    /// (#824).
    pub(crate) fn memory_in_use_at_exit(&self) -> bool {
        self.driver.disk_io_outstanding
    }

    /// Tear the ring down after
    /// [`drain_after_failure`](Self::drain_after_failure) panicked, or after a
    /// drain that left a command in flight
    /// ([`memory_in_use_at_exit`](Self::memory_in_use_at_exit)). The kernel
    /// ends the ring's operations and closes its sockets. Those operations can
    /// use the heap memory this event loop owns until they end, so the caller
    /// leaks it. What other threads are waiting on is released here, and the
    /// fds delivered by completions this loop never handled are closed: an
    /// accepted connection is an ordinary fd, which closing the ring leaves
    /// open.
    ///
    /// # Safety
    /// The ring is dropped here, so the caller must leak this event loop.
    pub(crate) unsafe fn close_ring(&mut self) {
        self.driver.close_fds_in_unhandled_completions();
        self.driver.release_shared();
        self.executor.wakes.deregister();
        // The blocking, resolver and spawner pools are shared by the workers
        // and their threads exit when the last reference goes. The kernel uses
        // none of their memory, so release this loop's references now rather
        // than keep the threads for the life of the process.
        self.driver.blocking_pool = None;
        self.driver.resolver = None;
        self.driver.spawner = None;
        self.driver.blocking_tx = None;
        self.driver.resolve_tx = None;
        self.driver.spawn_tx = None;
        // Safety: the caller's contract.
        unsafe { std::ptr::drop_in_place(&mut self.driver.ring) };
    }

    /// The first task panic recorded under `TaskPanicPolicy::Shutdown`.
    pub(crate) fn take_task_panic(&mut self) -> Option<crate::JoinError> {
        self.driver.panic_reporter.take()
    }

    /// Create a new async event loop for a worker thread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &crate::config::Config,
        handler: A,
        accept_rx: Option<crate::handoff::Receiver<crate::acceptor::AcceptedConn>>,
        park_rx: Option<crate::handoff::Receiver<crate::park::ParkedFd>>,
        eventfd: std::os::fd::RawFd,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
        resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
        resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
        resolver: Option<std::sync::Arc<crate::resolver::ResolverPool>>,
        spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
        spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
        spawner: Option<std::sync::Arc<crate::spawner::SpawnerPool>>,
        blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
        blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
        blocking_pool: Option<std::sync::Arc<crate::blocking::BlockingPool>>,
        region_rx: crate::region_registry::RegionControlRx,
    ) -> Result<Self, crate::error::Error> {
        let driver = Driver::new(
            config,
            accept_rx,
            park_rx,
            eventfd,
            shutdown_flag,
            resolve_rx,
            resolve_tx,
            resolver,
            spawn_rx,
            spawn_tx,
            spawner,
            blocking_rx,
            blocking_tx,
            blocking_pool,
            region_rx,
        )?;
        // On io_uring the recv queue holds kernel ring buffer bids
        // (`PendingUdpBuf::Kernel`), so each queued datagram pins one
        // buffer of its socket's provided ring until the task consumes it.
        // Capacity beyond the ring size is unusable: the ring runs out first.
        // (The mio backend copies into owned buffers and keeps the full
        // configured depth.)
        let udp_queue_capacity = config
            .udp_recv_queue_capacity
            .min(config.udp_recv_buffer.ring_size as usize);
        let executor = Executor::new(
            config.max_connections,
            config.standalone_task_capacity,
            crate::runtime::TIMER_SLOTS,
            config.udp_bind.len() as u32,
            udp_queue_capacity,
        );
        // A waker woken off this thread rings the worker's own wake fd.
        if let Some(handle) = config
            .wake_keep_alive
            .as_ref()
            .and_then(|handles| handles.get(config.worker_index))
        {
            executor.wakes.set_wake_handle(handle.clone());
        }
        Ok(AsyncEventLoop {
            driver,
            handler,
            executor,
        })
    }

    /// Complete the fallible backend setup known before the runtime is ready.
    ///
    /// The eventfd-read SQE points into this event loop, so the caller must not
    /// move it between this method and `run()`. `run()` can still return an
    /// error after the listener becomes live.
    pub(crate) fn prepare_run(&mut self) -> Result<(), crate::error::Error> {
        // Always arm eventfd read — needed for shutdown wakeup even in client-only mode.
        self.driver
            .ring
            .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr())?;
        self.driver.eventfd_armed = true;

        // Kick the eventfd so the first submit_and_wait(1) returns immediately.
        let kick: u64 = 1;
        unsafe {
            libc::write(
                self.driver.eventfd,
                &kick as *const u64 as *const libc::c_void,
                8,
            );
        }

        Ok(())
    }

    /// Run the async event loop. Blocks the current thread.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
        // Merged accept mode arms here rather than at construction: the
        // listener sockets are bound but not listening until every worker has
        // reported ready, and an accept on a non-listening socket is EINVAL.
        self.arm_merged_accepts();

        // Spawn UDP handler tasks for each bound UDP socket.
        for udp_idx in 0..self.driver.udp_sockets.len() {
            let udp_socket = UdpSocket::new(udp_idx as u32);
            // A panic while building the future is a task panic too.
            let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.handler.on_udp_bind(udp_socket)
            }));
            let future = match built {
                Ok(future) => future,
                Err(payload) => {
                    self.driver
                        .panic_reporter
                        .report("handler on_udp_bind", &*payload);
                    None
                }
            };
            if let Some(future) = future
                && let Some(idx) = self.executor.standalone_slab.spawn(future)
            {
                self.executor.ready_queue.push_back(idx | STANDALONE_BIT);
            }
        }

        // Spawn on_start task (client-only entry point).
        // A panic while building the future is a task panic too.
        let built =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.handler.on_start()));
        let future = match built {
            Ok(future) => future,
            Err(payload) => {
                self.driver
                    .panic_reporter
                    .report("handler on_start", &*payload);
                None
            }
        };
        if let Some(future) = future
            && let Some(idx) = self.executor.standalone_slab.spawn(future)
        {
            self.executor.ready_queue.push_back(idx | STANDALONE_BIT);
        }

        // Event-loop diagnostics are opt-in via `Config::loop_diag`. When
        // enabled, the wall-clock stall instrumentation (~4 clock reads per
        // iteration) records wait/work stall buckets, and both the
        // `[ringline diag]` iteration-mix line and the `[ringline stall]`
        // line print at shutdown. The iteration-mix counters below are
        // always maintained (a few u64 adds per iteration); only the
        // clock reads and the output are gated.
        let loop_diag = self.driver.loop_diag;

        // ── Diagnostic counters (printed to stderr at shutdown) ────────────────
        // These measure the event-loop iteration mix to help diagnose client
        // throughput deficits.
        let mut diag_iters: u64 = 0;
        let mut diag_dead_iters: u64 = 0; // iters where no tasks were polled in first poll_ready_tasks
        let mut diag_cqes_1st: u64 = 0; // CQEs from first drain_completions (after submit_and_wait)
        let mut diag_cqes_2nd: u64 = 0; // CQEs from second drain_completions (after flush)
        let mut diag_tasks_1st: u64 = 0; // tasks polled in first poll_ready_tasks
        let mut diag_tasks_fp: u64 = 0; // tasks polled in fast-path poll_ready_tasks

        // ── Latency stall counters ─────────────────────────────────────────────
        // "wait"  = time blocked inside submit_and_wait (kernel side).
        // "work"  = rest of the iteration (drain, tasks, flush, on_tick).
        // Buckets count iterations where that phase exceeded the threshold.
        // max values record the single worst observation.
        let mut diag_wait_ge_1ms: u64 = 0;
        let mut diag_wait_ge_5ms: u64 = 0;
        let mut diag_wait_ge_10ms: u64 = 0;
        let mut diag_wait_ns_max: u64 = 0;
        let mut diag_work_ge_1ms: u64 = 0;
        let mut diag_work_ge_5ms: u64 = 0;
        let mut diag_work_ge_10ms: u64 = 0;
        let mut diag_work_ns_max: u64 = 0;

        loop {
            // Only read the clock when stall instrumentation is enabled.
            let iter_start = if loop_diag {
                Some(std::time::Instant::now())
            } else {
                None
            };

            // Retry eventfd re-arm if a previous attempt failed (SQ was full).
            if !self.driver.eventfd_armed && !self.driver.shutdown_flag.load(Ordering::Relaxed) {
                self.driver.eventfd_armed = self
                    .driver
                    .ring
                    .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr())
                    .is_ok();
            }

            // Arm a tick timeout before blocking.
            // Only mark as armed if the SQE was actually submitted — if the SQ
            // is full the submission silently fails, and leaving armed=false
            // ensures we retry on the next iteration rather than calling
            // submit_and_wait without any timeout in the ring.
            if !self.driver.tick_timeout_armed
                && let Some(ref ts) = self.driver.tick_timeout_ts
            {
                let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
                if self
                    .driver
                    .ring
                    .submit_tick_timeout(ts as *const _, ud.raw())
                    .is_ok()
                {
                    self.driver.tick_timeout_armed = true;
                }
            }

            // A wait with `tick_timeout_us = 0` has no timer of its own. As
            // above, a full SQ leaves this unarmed for the next iteration.
            if !self.driver.send_backstop_armed && !self.driver.send_backstop_list.is_empty() {
                let ud = UserData::encode(OpTag::SendBackstop, 0, 0);
                let ts = &raw const self.driver.send_backstop_ts;
                self.driver.send_backstop_armed =
                    self.driver.ring.submit_tick_timeout(ts, ud.raw()).is_ok();
            }

            // Without a tick timeout the wait can block indefinitely, and with
            // one longer than 10 ms a deadline would be checked late, so the
            // earliest handshake deadline arms a timer of its own. As above, a
            // full SQ leaves this unarmed for the next iteration.
            if self.driver.handshake_timer_used
                && !self.driver.handshake_timer_armed
                && let Some(deadline) = self.driver.handshake_deadlines.next_deadline()
            {
                let wait = deadline.saturating_duration_since(std::time::Instant::now());
                self.driver.handshake_timer_ts = crate::backend::uring::abi::Timespec::new()
                    .sec(wait.as_secs())
                    .nsec(wait.subsec_nanos());
                let ud = UserData::encode(OpTag::HandshakeDeadline, 0, 0);
                let ts = &raw const self.driver.handshake_timer_ts;
                self.driver.handshake_timer_armed =
                    self.driver.ring.submit_tick_timeout(ts, ud.raw()).is_ok();
            }

            // The blocking wait itself is always performed; only the timing
            // around it is gated on `loop_diag`.
            let wait_start = if loop_diag {
                Some(std::time::Instant::now())
            } else {
                None
            };
            #[cfg(test)]
            if let Some(fault) = &self.driver.test_fault {
                fault.check()?;
                if fault
                    .error_on_worker
                    .compare_exchange(
                        self.driver.worker_index as u32 + 1,
                        0,
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Err(crate::error::Error::Io(std::io::Error::other(
                        "injected event loop error",
                    )));
                }
            }
            // Don't block while tasks are already runnable (self-wakes
            // collected after the last poll pass, tasks woken from
            // on_tick): submit SQEs but return immediately so the ready
            // queue is polled now instead of after the next CQE or tick
            // timeout (indefinitely, with tick_timeout_us = 0).
            //
            // First release what futures dropped at a close since the last
            // poll pass queued, so an idle worker does not hold it until its
            // next completion; the wait below submits any timer cancels.
            crate::fs::release_orphans(&mut self.driver, &mut self.executor);
            self.executor.collect_wakeups();
            // Tasks have read what they will read in this pass. The wait below
            // submits any re-arm, so a socket that ran out of buffers receives
            // again without another completion to wake the worker.
            self.driver.return_udp_buffers();
            self.resume_forward_recvs();
            // A task polled in the second pass may have consumed the bytes
            // ahead of a hangup; peek before blocking rather than at the next
            // completion.
            self.recheck_hangups();
            // Under `defer_recv_arm`, a wait with no completion pending would
            // block, and arming the deferred receives after it would take a
            // second, non-blocking pass. Arm them now instead; this enter
            // submits them.
            if self.driver.defer_recv_arm
                && !self.driver.deferred_recv_arms.is_empty()
                && !self.driver.ring.completion_pending()
            {
                self.arm_deferred_recvs();
            }
            // Declining to block still has to reap: under DEFER_TASKRUN the
            // kernel runs task_work only on a GETEVENTS enter, and
            // `submit_and_wait(0)` carries no such flag. Going through
            // `submit_and_get_events` (same single syscall) keeps completions
            // flowing while a task is runnable — otherwise a task that stays
            // runnable without queueing SQEs (so `flush()` takes its empty-SQ
            // shortcut) starves the whole worker of completions.
            if self.may_block() {
                self.driver.ring.submit_and_wait(1)?;
            } else {
                self.driver.ring.submit_and_get_events()?;
            }
            let mut wait_ns: u64 = 0;
            if let Some(start) = wait_start {
                wait_ns = start.elapsed().as_nanos() as u64;
                if wait_ns >= 1_000_000 {
                    diag_wait_ge_1ms += 1;
                }
                if wait_ns >= 5_000_000 {
                    diag_wait_ge_5ms += 1;
                }
                if wait_ns >= 10_000_000 {
                    diag_wait_ge_10ms += 1;
                }
                if wait_ns > diag_wait_ns_max {
                    diag_wait_ns_max = wait_ns;
                }
            }

            self.drain_completions();
            diag_cqes_1st += self.driver.cqe_batch.len() as u64;
            self.arm_deferred_recvs();
            // `handle_park_install` fills `park_ready` from the completions
            // just drained. Hand those over in the same iteration: the
            // connections have already left this worker and only the
            // `OwnedFd` is keeping their sockets alive.
            self.drain_park_ready();

            // Check for shutdown after processing completions.
            if self.driver.shutdown_local || self.driver.shutdown_flag.load(Ordering::Relaxed) {
                // Print per-worker diagnostics before exiting.
                if loop_diag {
                    let dead_pct = if diag_iters > 0 {
                        100.0 * diag_dead_iters as f64 / diag_iters as f64
                    } else {
                        0.0
                    };
                    eprintln!(
                        "[ringline diag] iters={diag_iters} dead={diag_dead_iters} ({dead_pct:.1}%) \
                         cqes_1st_avg={:.2} cqes_2nd_avg={:.2} \
                         tasks_1st_avg={:.2} tasks_fp_avg={:.2}",
                        diag_cqes_1st as f64 / diag_iters.max(1) as f64,
                        diag_cqes_2nd as f64 / diag_iters.max(1) as f64,
                        diag_tasks_1st as f64 / diag_iters.max(1) as f64,
                        diag_tasks_fp as f64 / diag_iters.max(1) as f64,
                    );
                    eprintln!(
                        "[ringline stall] \
                         wait_ge_1ms={diag_wait_ge_1ms} wait_ge_5ms={diag_wait_ge_5ms} \
                         wait_ge_10ms={diag_wait_ge_10ms} wait_max={:.1}ms | \
                         work_ge_1ms={diag_work_ge_1ms} work_ge_5ms={diag_work_ge_5ms} \
                         work_ge_10ms={diag_work_ge_10ms} work_max={:.1}ms",
                        diag_wait_ns_max as f64 / 1_000_000.0,
                        diag_work_ns_max as f64 / 1_000_000.0,
                    );
                }
                self.driver.run_shutdown();
                return Ok(());
            }

            // Drain pending region-registry updates dispatched from
            // `Runtime::register_region` / `unregister_region`. Each
            // message is applied to this worker's ring + registry and then
            // acknowledged so the registrar can return to its caller.
            self.drain_region_control();
            // Retry send/close submissions that failed on a previous tick
            // (SQ was full). The SQ has been flushed by submit_and_wait above.
            self.drain_zc_retries();
            self.drain_coalesced_retries();
            self.drain_copy_retries();
            self.drain_send_retries();
            self.drain_close_retries();
            self.drain_shutdown_retries();
            self.drain_send_pollout_retries();
            self.driver.tick_count += 1;

            // Check close_notify deadlines: force-close a TLS connection whose
            // close requested a close_notify and whose Close is still not
            // committed (`close_pending`) when the deadline elapses.
            self.check_close_notify_deadlines();
            self.check_handshake_deadlines();

            // Drain waker-based ready queue (from wakers fired during poll).
            self.executor.collect_wakeups();

            // Poll all ready tasks.
            let tasks_before = self.executor.ready_queue.len();
            self.poll_ready_tasks();
            // Release what futures dropped outside the executor left behind
            // (timer slots, spawns, pidfd waits, connects, blocking and resolve
            // entries, abandoned operations' results, abandoned opens' files,
            // abandoned reads' and writes' buffers). Before the flush below
            // submits this pass's SQEs, so an open whose future was dropped
            // during the pass is marked abandoned before it can complete.
            crate::fs::release_orphans(&mut self.driver, &mut self.executor);
            self.recheck_hangups();
            diag_tasks_1st += tasks_before as u64;
            if tasks_before == 0 {
                diag_dead_iters += 1;
            }

            // Flush any SQEs enqueued by poll_ready_tasks (e.g., client sends).
            // flush() does two things:
            //   1. submit() — delivers the SQEs to the kernel.
            //   2. enter(GETEVENTS, min=0) — triggers DEFER_TASKRUN task_work
            //      so deferred CQEs (send completions, recv arrivals) are
            //      posted to the CQ ring *before* flush() returns.
            // This means the drain_completions() below sees those CQEs
            // inline, eliminating the "dead" submit_and_wait(1) iteration
            // that would otherwise burn a full event-loop cycle just to
            // process send CQEs that wake no tasks (`send_nowait` sends
            // settle nothing).
            let _ = self.driver.ring.flush();

            // Non-blocking drain: consume the CQEs (primarily send completions)
            // that flush()'s GETEVENTS step posted to the CQ ring.
            // For send_nowait the pool slot is freed here and nothing is
            // settled. Draining inline collapses the two-iteration
            // pattern (dead send-CQE iter + live recv-CQE iter) down to one.
            self.drain_completions();
            diag_cqes_2nd += self.driver.cqe_batch.len() as u64;

            // If the drain woke any tasks (recv CQEs that arrived while we
            // were running tasks and were flushed by the GETEVENTS enter),
            // run them now so their sends land in the SQ before we block.
            if !self.executor.ready_queue.is_empty() {
                diag_tasks_fp += self.executor.ready_queue.len() as u64;
                self.poll_ready_tasks();
                let _ = self.driver.ring.flush();
            }

            // on_tick callback (synchronous). Set the executor's
            // driver_state thread-local so user code that calls
            // `ringline::spawn()` / wakers / `with_state` works from
            // inside the handler.
            let handler = &mut self.handler;
            let driver_ptr = &mut self.driver as *mut Driver;
            let executor_ptr = &mut self.executor as *mut crate::runtime::Executor;
            let mut driver_state = DriverState {
                driver: unsafe { NonNull::new_unchecked(driver_ptr) },
                executor: unsafe { NonNull::new_unchecked(executor_ptr) },
            };
            let guard = unsafe { set_driver_state_guarded(&mut driver_state) };
            // catch_unwind keeps a panic in user tick code from unwinding past
            // the guard's scope with futures observing a dangling
            // CURRENT_DRIVER, and from killing the worker.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_tick();
            }));
            if let Err(payload) = result {
                // SAFETY: the handler call has ended, so this is the only reference.
                unsafe {
                    (*driver_ptr)
                        .panic_reporter
                        .report("handler on_tick", &*payload)
                };
            }
            drop(guard);

            // Rebalance after the handler's tick, not before: the tick is
            // where a handler typically finishes work and offers a connection,
            // so running first would act on last iteration's offers and always
            // be one tick stale. After the guard, because `begin_park` takes
            // `&mut self` and the guard holds a raw pointer to the driver.
            self.drive_park_drains();
            self.maybe_park_one();

            self.finalize_pending_closes();

            // Hand the executor every send result that no CQE carried. Two
            // producers fill this queue and both of them have run by now:
            // the awaited send APIs, from `poll_ready_tasks`
            // and from `on_tick` (a message that queued no SQE at all), and
            // teardown, from any `drain_conn_send_queue` /
            // `force_finalize_close` / `reset_send_state` above — including
            // the `try_finalize_close` pass immediately preceding. Draining
            // once, here, is therefore the single point that covers all of
            // them, and nothing waits on it: `complete_send` wakes
            // the owner straight onto `Executor::ready_queue`, which the top
            // of the next iteration collects *before* deciding whether to
            // block, so a settled send is polled without a `submit_and_wait`
            // in between.
            self.drain_settled_sends();
            self.report_drop_panics();

            // One send-capacity wake per iteration, last — same placement,
            // and for the same reason, as the mio loop (#381). Copy-pool
            // slots come back at many points above (every send-family CQE
            // handler, the retry drains, `drain_conn_send_queue`, the
            // teardown inside `pending_finalize_closes`), and each of those
            // sets `capacity_released` rather than touching the executor.
            // Waking from inside `drain_completions` instead would leave the
            // slots that teardown released here unsignalled until after the
            // next `submit_and_wait`, which can block indefinitely — and a
            // parked bounded send would stall behind it.
            self.wake_capacity_if_released();

            // Record work-phase (everything except the blocking wait) duration.
            if let Some(start) = iter_start {
                // wait_ns was filled by the wait_start guard above — iter_start
                // and wait_start are Some iff loop_diag, so it is never stale
                // here. saturating_sub guards the (monotonic-clock-impossible)
                // elapsed < wait_ns edge so a skew can't produce a huge bucket.
                let work_ns = (start.elapsed().as_nanos() as u64).saturating_sub(wait_ns);
                if work_ns >= 1_000_000 {
                    diag_work_ge_1ms += 1;
                }
                if work_ns >= 5_000_000 {
                    diag_work_ge_5ms += 1;
                }
                if work_ns >= 10_000_000 {
                    diag_work_ge_10ms += 1;
                }
                if work_ns > diag_work_ns_max {
                    diag_work_ns_max = work_ns;
                }
            }

            diag_iters += 1;
        }
    }

    /// Apply any pending region register/unregister messages from the
    /// runtime registrar. Each message is acked individually; the registrar
    /// blocks on its caller until every worker reports.
    fn drain_region_control(&mut self) {
        use crate::region_registry::RegionControlMsg;
        // try_iter returns immediately when the channel is empty.
        loop {
            let msg = match self.driver.region_rx.try_recv() {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg {
                RegionControlMsg::Register { slot, region, ack } => {
                    let result = match self.driver.fixed_buffers.set_slot(slot, &region) {
                        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
                        Ok(()) => {
                            let iov = libc::iovec {
                                iov_base: region.ptr() as *mut _,
                                iov_len: region.len(),
                            };
                            // Safety: caller of `register_region` guarantees the
                            // region outlives the registration.
                            let r =
                                unsafe { self.driver.ring.register_buffers_update_one(slot, iov) };
                            if r.is_err() {
                                // IORING_REGISTER_BUFFERS_UPDATE does not
                                // change the kernel slot when it fails, so the
                                // kernel slot is still empty. Clear the table
                                // entry that set_slot just wrote.
                                let _ = self.driver.fixed_buffers.clear_slot(slot);
                            }
                            r
                        }
                    };
                    let _ = ack.send(result);
                }
                RegionControlMsg::Unregister { slot, ack } => {
                    let _ = ack.send(self.clear_region_slot(slot));
                }
                RegionControlMsg::Release { slot, ack } => {
                    let result = if self.driver.fixed_buffers.is_occupied(slot) {
                        self.clear_region_slot(slot)
                    } else {
                        Ok(())
                    };
                    let _ = ack.send(result);
                }
            }
        }
    }

    /// Clear the table entry, then the kernel slot. Returns `InvalidInput` if
    /// the table slot is already empty. If the kernel call fails, the table
    /// slot stays empty and the kernel slot keeps the region; the registrar
    /// then does not reuse the slot.
    fn clear_region_slot(&mut self, slot: u16) -> io::Result<()> {
        self.driver
            .fixed_buffers
            .clear_slot(slot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
            .and_then(|()| {
                let iov = libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                };
                // Safety: clearing a slot does not reference any user
                // memory; iov is null/zero.
                unsafe { self.driver.ring.register_buffers_update_one(slot, iov) }
            })
    }

    /// Poll all tasks in the ready queue (both connection and standalone tasks).
    fn poll_ready_tasks(&mut self) {
        // First release what futures dropped outside the executor left
        // behind (for example, a closed connection's timer slot), so tasks
        // polled in this pass can reuse it.
        crate::fs::release_orphans(&mut self.driver, &mut self.executor);
        // Form raw pointers once and access driver/executor exclusively through
        // them for the duration of this method. This avoids Stacked Borrows
        // violations: accessing self.driver or self.executor directly after
        // forming these pointers would invalidate them, but futures dereference
        // them via with_state() during poll.
        let driver = &mut self.driver as *mut Driver;
        let executor = &mut self.executor as *mut Executor;

        // Safety: NonNull::new_unchecked is safe because we have valid pointers
        // from &mut self.driver and &mut self.executor above.
        let mut driver_state = DriverState {
            driver: unsafe { NonNull::new_unchecked(driver) },
            executor: unsafe { NonNull::new_unchecked(executor) },
        };
        let driver_state_guard = unsafe { set_driver_state_guarded(&mut driver_state) };

        // Safety: we have exclusive access to driver/executor via self, and
        // only access them through these raw pointers until the guard drops.
        let driver = unsafe { &mut *driver };
        let executor = unsafe { &mut *executor };

        // Per-batch dedup: collapse duplicate ready-queue entries that were
        // present at the START of this poll_ready_tasks call. N CQEs for the
        // same connection landing in one drain_completions batch push N copies
        // of the same id; without dedup, the second through Nth entries each
        // build a waker, set CURRENT_TASK_ID, and call take_ready → None —
        // pure overhead.
        //
        // Safety argument for lost-wakeup freedom:
        //
        // Dedup applies ONLY to entries at indices < initial_len (captured
        // before the loop). Entries appended to ready_queue *during* this call
        // have i >= initial_len and bypass the dedup check entirely — they are
        // processed unconditionally.
        //
        // Only the *internal* wake path appends mid-pass: executor.wake_task()
        // pushes straight onto executor.ready_queue (and, for the task being
        // polled right now, records the wake in its slot, so the poll loop
        // re-queues it after parking). A std::task::Waker does NOT — what a
        // future gets from its Context pushes onto the thread-local queue (or,
        // from another thread, the worker's inbox) in runtime/waker.rs, which
        // only reaches executor.ready_queue via
        // collect_wakeups() once this pass has ended. So a future that wakes
        // itself through its Context (the usual "yield to the executor"
        // pattern, `yield_now`) is not polled again within this pass. It is
        // polled in the next pass: the fast path after flush() and
        // drain_completions() in this iteration, or the next iteration.
        // tests/ready_queue_fairness.rs pins that it does not starve the
        // worker.
        //
        // This boundary is essential: without it, a future that parks itself
        // and then is immediately re-woken by another task in the same batch
        // (e.g. A wakes B, B's continuation wakes A) would be suppressed by
        // the dedup bit set for A's first occurrence, causing a lost wakeup.
        // With the boundary, only the initial-batch duplicates (from the drain)
        // are collapsed; in-flight wakeups from the futures themselves are
        // always honored.
        //
        // STANDALONE_BIT separates the two dedup arrays so a standalone task
        // and a connection task with the same low-bit index are never confused.
        // Arrays are pre-allocated in Executor (zero per-call heap allocation).
        // Bits are reset by scanning only the initial-batch slice.

        let initial_len = executor.ready_queue.len();

        let mut i = 0;
        while i < executor.ready_queue.len() {
            let raw_id = executor.ready_queue[i];
            let in_initial_batch = i < initial_len;
            i += 1;

            if raw_id & STANDALONE_BIT != 0 {
                // Standalone task.
                let task_idx = (raw_id & !STANDALONE_BIT) as usize;
                if in_initial_batch && task_idx < executor.poll_dedup_standalone.len() {
                    if executor.poll_dedup_standalone[task_idx] {
                        // Duplicate in initial batch — skip.
                        continue;
                    }
                    executor.poll_dedup_standalone[task_idx] = true;
                }
                let task_idx = task_idx as u32;
                if let Some(mut fut) = executor.standalone_slab.take_ready(task_idx) {
                    let waker = standalone_waker(executor.wakes.id(), task_idx);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(raw_id));
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        fut.as_mut().poll(&mut cx)
                    }));
                    match result {
                        Ok(std::task::Poll::Ready(())) => {
                            executor.standalone_slab.remove(task_idx);
                            if let Some(payload) = crate::task_panic::drop_caught(fut) {
                                driver.panic_reporter.report("standalone task", &*payload);
                            }
                        }
                        Ok(std::task::Poll::Pending) => {
                            match executor.standalone_slab.park(task_idx, fut) {
                                Park::Parked => {}
                                // Woken during the poll: its slot read `Polling`.
                                Park::Woken => executor.ready_queue.push_back(raw_id),
                                // It cancelled itself. `Drop` is user code, and a
                                // panic in it must not end the worker.
                                Park::Cancelled(fut) => {
                                    let dropped = crate::task_panic::drop_caught(fut);
                                    executor.standalone_slab.remove(task_idx);
                                    if let Some(payload) = dropped {
                                        driver.panic_reporter.report("standalone task", &*payload);
                                    }
                                }
                            }
                        }
                        Err(payload) => {
                            // Drop the future, free the slot, and hand the
                            // panic to `panic_reporter`, which decides under
                            // the policy whether the worker keeps running. An
                            // uncaught panic here would end the worker thread
                            // and every connection on it.
                            let dropped = crate::task_panic::drop_caught(fut);
                            executor.standalone_slab.remove(task_idx);
                            driver.panic_reporter.report("standalone task", &*payload);
                            if let Some(payload) = dropped {
                                driver.panic_reporter.report("standalone task", &*payload);
                            }
                        }
                    }
                }
            } else {
                // Connection task.
                let conn_index = raw_id as usize;
                if in_initial_batch && conn_index < executor.poll_dedup_conn.len() {
                    if executor.poll_dedup_conn[conn_index] {
                        // Duplicate in initial batch — skip.
                        continue;
                    }
                    executor.poll_dedup_conn[conn_index] = true;
                }
                let conn_index = conn_index as u32;
                if let Some(mut fut) = executor.task_slab.take_ready(conn_index) {
                    let waker = conn_waker(executor.wakes.id(), conn_index);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(conn_index));
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        fut.as_mut().poll(&mut cx)
                    }));
                    match result {
                        Ok(std::task::Poll::Ready(())) => {
                            // Task completed — connection handler is done.
                            driver.close_connection_graceful(conn_index);
                            executor.remove_connection_task(conn_index);
                            if let Some(payload) = crate::task_panic::drop_caught(fut) {
                                driver.panic_reporter.report(
                                    &format!("connection task (connection {conn_index} closed)"),
                                    &*payload,
                                );
                            }
                        }
                        Ok(std::task::Poll::Pending) => {
                            // Woken during the poll: its slot read `Polling`.
                            if executor.task_slab.park(conn_index, fut) {
                                executor.ready_queue.push_back(conn_index);
                            }
                        }
                        Err(payload) => {
                            // A panicking connection handler tears down the
                            // connection but must not take the worker
                            // thread with it.
                            // Close first: a half owned by a top-level `Select`
                            // drops below, after `catch_unwind`
                            // returned, and would otherwise send close_notify.
                            driver.close_connection(conn_index);
                            let dropped = crate::task_panic::drop_caught(fut);
                            executor.remove_connection_task(conn_index);
                            let site = format!("connection task (connection {conn_index} closed)");
                            driver.panic_reporter.report(&site, &*payload);
                            if let Some(payload) = dropped {
                                driver.panic_reporter.report(&site, &*payload);
                            }
                        }
                    }
                }
            }
        }

        // Reset dedup bits for the initial-batch entries only (those are the
        // only ones whose bits could have been set). Zero extra allocation —
        // we index into the ready_queue we already hold.
        let reset_end = initial_len.min(executor.ready_queue.len());
        for idx in 0..reset_end {
            let raw_id = executor.ready_queue[idx];
            if raw_id & STANDALONE_BIT != 0 {
                let task_idx = (raw_id & !STANDALONE_BIT) as usize;
                if task_idx < executor.poll_dedup_standalone.len() {
                    executor.poll_dedup_standalone[task_idx] = false;
                }
            } else {
                let conn_index = raw_id as usize;
                if conn_index < executor.poll_dedup_conn.len() {
                    executor.poll_dedup_conn[conn_index] = false;
                }
            }
        }

        drop(driver_state_guard);

        // Clear processed entries.
        executor.ready_queue.clear();

        // Drain any wakeups that happened during polling.
        executor.collect_wakeups();
    }

    fn drain_completions(&mut self) {
        // One arrival timestamp per batch for queued UDP datagrams (a vDSO
        // clock call per packet showed up on the hot path).
        if !self.driver.udp_sockets.is_empty() {
            self.driver.udp_batch_recv_at = std::time::Instant::now();
        }
        self.driver.cqe_batch.clear();
        self.driver.cqe_cursor = 0;

        self.driver.ring.reap(&mut self.driver.cqe_batch);
        // The completions just reaped are one batch: the receives among them
        // share one arrival time, read by the first.
        self.driver.recv_batch.begin();

        if let Some(interval) = self.driver.flush_interval {
            let mut last_flush = Instant::now();
            for i in 0..self.driver.cqe_batch.len() {
                let (user_data_raw, result, flags) = self.driver.cqe_batch[i];
                #[cfg(test)]
                if let Some(fault) = &self.driver.test_fault {
                    fault.check_cqe(user_data_raw);
                }
                self.driver.cqe_cursor = i + 1;
                self.dispatch_cqe(user_data_raw, result, flags);
                // Check the clock every 16 CQEs to amortise Instant::now() cost.
                if (i & 0xF) == 0xF {
                    let now = Instant::now();
                    if now.duration_since(last_flush) >= interval {
                        // Best effort latency optimization; SQEs submitted by next submit_and_wait.
                        let _ = self.driver.ring.flush();
                        last_flush = now;
                    }
                }
            }
        } else {
            for i in 0..self.driver.cqe_batch.len() {
                let (user_data_raw, result, flags) = self.driver.cqe_batch[i];
                #[cfg(test)]
                if let Some(fault) = &self.driver.test_fault {
                    fault.check_cqe(user_data_raw);
                }
                self.driver.cqe_cursor = i + 1;
                self.dispatch_cqe(user_data_raw, result, flags);
            }
        }
    }

    /// Commit every close registered on `pending_finalize_closes` this
    /// iteration: by `close_connection` from a CQE handler or the task-exit
    /// arm, by `DriverCtx::close` from a task, or by `defer_finalize_close`
    /// from the completion that drained the connection's sends, chain or
    /// `Shutdown`. Runs after `poll_ready_tasks`, so a task woken by a read
    /// error is polled, and a send it queues drains, before the Close is
    /// committed (#371). `try_finalize_close` is guarded: a connection with
    /// sends, a chain or a `Shutdown` still outstanding is dropped from the
    /// list here and registered again by the completion that drains it.
    fn finalize_pending_closes(&mut self) {
        if self.driver.pending_finalize_closes.is_empty() {
            return;
        }
        let mut pending = std::mem::take(&mut self.driver.pending_finalize_closes);
        for conn_index in pending.drain(..) {
            self.driver.try_finalize_close(conn_index);
        }
        self.driver.pending_finalize_closes = pending;
    }

    /// Whether the run loop may block in `submit_and_wait(1)`. It may not while a
    /// task is runnable, while a close released by the orphan drain awaits the
    /// end-of-iteration drain, while a UDP re-arm is due, or once shutdown is
    /// pending.
    ///
    /// Pending closes: `release_orphans` at the top of the iteration can push to
    /// `pending_finalize_closes`, and only the drain at the end of the iteration
    /// submits the Close. With no tick timeout, a blocking wait would hold that
    /// Close until the next completion.
    ///
    /// Shutdown: the shutdown check in the run loop runs only after the wait.
    /// `request_shutdown()` sets `shutdown_local` without writing the eventfd.
    /// A `Runtime::shutdown` wake can already have been reaped by the drain
    /// after `flush()`, and the eventfd read is not re-armed once
    /// `shutdown_flag` is set. With no tick timeout, a blocking wait would
    /// never return in either case.
    ///
    /// UDP re-arms: `return_udp_buffers` retries a re-arm that could not be
    /// submitted, and with no tick timeout a blocking wait could outlast every
    /// other completion.
    ///
    /// Deferred receives: the pre-wait arm skips them when
    /// `completion_pending()` is true, which can mean task work that posts no
    /// completion, so a blocking wait could hold an unarmed deferred receive
    /// until an unrelated completion arrives.
    fn may_block(&self) -> bool {
        let shutting_down =
            self.driver.shutdown_local || self.driver.shutdown_flag.load(Ordering::Relaxed);
        self.executor.ready_queue.is_empty()
            && self.driver.pending_finalize_closes.is_empty()
            && self.driver.deferred_recv_arms.is_empty()
            && !self.driver.udp_rearm_due()
            && !shutting_down
    }

    /// Arm the receives `park_recv` deferred (`Config::defer_recv_arm`), for
    /// connections still in the slot they were deferred in whose reader is
    /// still parked. An arm that closes the connection wakes the reader.
    fn arm_deferred_recvs(&mut self) {
        if self.driver.deferred_recv_arms.is_empty() {
            return;
        }
        let mut arms = std::mem::take(&mut self.driver.deferred_recv_arms);
        // Newest first: a reader that parked twice arms with its latest
        // `need`, and the older entry finds the receive armed.
        for &(conn_index, generation, need) in arms.iter().rev() {
            if self.driver.connections.generation(conn_index) != generation
                || !self.executor.recv_waiters[conn_index as usize]
            {
                continue;
            }
            if self.arm_direct_recv(conn_index, need) {
                self.executor.wake_recv(conn_index);
            }
        }
        arms.clear();
        if self.driver.deferred_recv_arms.is_empty() {
            self.driver.deferred_recv_arms = arms;
        }
    }

    /// Completion of a direct receive (`OpTag::RecvDirect`).
    ///
    /// The payload is the `direct_recvs` entry holding the accumulator
    /// buffer the kernel wrote into. The entry is removed here and only
    /// here. A completion whose connection closed, or whose slot now holds
    /// another connection, passes the buffer to `recycle_direct`: a buffer
    /// of at least 64 KiB for which `DirectPool::put` finds room stays in
    /// the pool, and any other is freed. For a live connection, the buffer
    /// goes back into the accumulator with the received bytes behind its
    /// contents, including on EOF and errors, so the bytes received before
    /// stay readable. The arrival is recorded before the bytes are placed,
    /// while `recv_direct_held` still counts the bytes the buffer held.
    fn handle_recv_direct(&mut self, ud: UserData, result: i32) {
        let slot = ud.payload() as usize;
        let Some(entry) = self
            .driver
            .direct_recvs
            .get_mut(slot)
            .and_then(Option::take)
        else {
            return;
        };
        self.driver.direct_recv_free.push(slot as u32);
        let conn_index = entry.conn_index;
        let live = self.driver.connections.get(conn_index).is_some_and(|c| {
            c.generation == entry.generation && matches!(c.lifecycle, Lifecycle::Open)
        });
        if let Some(cs) = self.driver.connections.get_mut(conn_index)
            && cs.generation == entry.generation
        {
            cs.recv_direct_armed = false;
        }
        let buf = match entry.buf {
            crate::backend::uring::driver::DirectRecvBuf::Accumulator(buf) => buf,
            crate::backend::uring::driver::DirectRecvBuf::Tls(buf) => {
                if !live {
                    metrics::RECV_DIRECT.increment(metrics::recv_direct::STALE);
                    // A closing connection still has its TLS state: end the
                    // receive there (`tls_recv_cancel`) so `release_tls_state`
                    // finds none in flight. Once the state is gone, `buf`
                    // holds whatever the receive owned and drops here.
                    let same = self.driver.connections.generation(conn_index) == entry.generation;
                    if same
                        && let Some(t) =
                            self.driver.tls_table.as_mut().filter(|t| t.has(conn_index))
                    {
                        crate::tls::tls_recv_cancel(t, conn_index, buf);
                    }
                    return;
                }
                self.handle_tls_recv_direct(conn_index, entry.generation, buf, result);
                return;
            }
        };
        if !live {
            if let Some(cs) = self.driver.connections.get_mut(conn_index)
                && cs.generation == entry.generation
            {
                cs.recv_direct_held = 0;
            }
            metrics::RECV_DIRECT.increment(metrics::recv_direct::STALE);
            self.driver.accumulators.recycle_direct(buf);
            return;
        }
        let received = result.max(0) as usize;
        if result > 0 {
            self.driver.record_arrival(conn_index, received);
        }
        // SAFETY: a non-negative result is the number of bytes the kernel
        // wrote at the buffer's length; a negative one wrote none.
        unsafe {
            self.driver
                .accumulators
                .attach_received(conn_index, buf, received);
        }
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_direct_held = 0;
        }
        if result > 0 {
            metrics::BYTES.add(metrics::bytes::RECEIVED, received as u64);
            metrics::RECV_DIRECT.add(metrics::recv_direct::BYTES, received as u64);
            if let Some(cs) = self.driver.connections.get_mut(conn_index)
                && cs.hangup_recheck
            {
                cs.hangup_recheck_due = true;
            }
            self.withdraw_park_offer(conn_index);
            self.executor.wake_recv(conn_index);
            return;
        }
        // A hangup peek took the socket's pending error: this end of the
        // stream is that error, not a FIN.
        let result = match self.driver.connections.get(conn_index) {
            Some(cs) if result == 0 && cs.hangup_error != 0 => -cs.hangup_error,
            _ => result,
        };
        if result == 0 {
            // Peer FIN: the read half is finished and the connection stays
            // open for its task (`docs/half-close-design.md`). `truncated`
            // is the TLS case, which a direct connection is not.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.note_eof(false);
            }
            self.executor.wake_recv(conn_index);
            return;
        }
        if -result == libc::ECANCELED {
            // Cancelled with the connection open: the task re-arms when it
            // parks again.
            self.executor.wake_recv(conn_index);
            return;
        }
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.read = ReadHalf::Error;
        }
        self.executor.fail_recv(
            conn_index,
            entry.generation,
            io::Error::from_raw_os_error(-result),
        );
        self.driver.close_connection(conn_index);
    }

    /// Act on what feeding received ciphertext to a TLS connection
    /// produced: finish the handshake (wake the connect waiter or spawn the
    /// accept task), wake the reader, record the peer's close_notify as the
    /// end of the read half, or close the connection on an error.
    fn apply_tls_recv_result(&mut self, conn_index: u32, result: crate::tls::TlsRecvResult) {
        match result {
            crate::tls::TlsRecvResult::HandshakeJustCompleted { peer_closed } => {
                let is_outbound = self
                    .driver
                    .connections
                    .get(conn_index)
                    .map(|c| c.outbound)
                    .unwrap_or(false);

                if is_outbound {
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.established = true;
                    }
                    // Counted in with `established`; `handle_close` counts out.
                    metrics::CONNECTIONS_ACTIVE.increment();
                    // Wake connect waiter.
                    self.executor.wake_connect(conn_index, Ok(()));
                } else {
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.established = true;
                    }
                    metrics::CONNECTIONS.increment(metrics::conn::ACCEPTED);
                    metrics::CONNECTIONS_ACTIVE.increment();
                    // Spawn async task for accepted connection.
                    self.spawn_accept_task(conn_index);
                }

                // Wake recv waiter if data accumulated during handshake.
                self.executor.wake_recv(conn_index);

                // The peer's close_notify came in the same feed as its
                // last handshake flight. Handle it as the `Closed` arm
                // does: the task reads what arrived, then EOF.
                if peer_closed && let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.note_eof(false);
                }
            }
            crate::tls::TlsRecvResult::Ok => {
                self.executor.wake_recv(conn_index);
            }
            crate::tls::TlsRecvResult::Error(err) => {
                let established = self
                    .driver
                    .connections
                    .get(conn_index)
                    .map(|c| c.established)
                    .unwrap_or(false);
                if !established {
                    // No task reads yet: an outbound connect takes the
                    // failure; a failed inbound handshake has nobody to tell.
                    let err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, err);
                    self.executor.wake_connect(conn_index, Err(err));
                    self.driver.close_connection(conn_index);
                } else {
                    self.abort_connection(conn_index, err);
                }
            }
            crate::tls::TlsRecvResult::Closed => {
                // The peer's close_notify ends the read half; the
                // connection stays open for its task.
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.note_eof(false);
                }
                self.executor.wake_recv(conn_index);
            }
        }
    }

    /// Completion of a live TLS connection's direct receive
    /// (`tls_recv_arm`): `buf` is what the receive owned, and `result` the
    /// bytes the kernel wrote, or an error. The bytes are fed to the engine,
    /// and the receive is re-armed while the handshake runs or after a hangup
    /// (`rearms_after_completion`); otherwise the next parked read arms it.
    /// Every path ends the receive in the engine.
    fn handle_tls_recv_direct(
        &mut self,
        conn_index: u32,
        generation: u32,
        buf: Option<Vec<u8>>,
        result: i32,
    ) {
        if result <= 0 {
            if let Some(t) = self.driver.tls_table.as_mut() {
                crate::tls::tls_recv_cancel(t, conn_index, buf);
            }
            if result == 0 {
                // TCP FIN. Only a clean end of stream if the peer's
                // close_notify was processed first; otherwise a truncation,
                // which reads resolve to as `UnexpectedEof`.
                let close_notify_seen = self
                    .driver
                    .tls_table
                    .as_mut()
                    .and_then(|t| t.get_mut(conn_index))
                    .map(|tc| tc.peer_sent_close_notify);
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.note_eof(close_notify_seen == Some(false));
                }
                let established = self
                    .driver
                    .connections
                    .get(conn_index)
                    .is_some_and(|c| c.established);
                if !established {
                    // The handshake has not completed, so no task holds the
                    // connection and nothing else would close it. Close it
                    // here. An outbound connect resolves with
                    // `handshake_eof()`; an inbound connection has no task to
                    // report to.
                    self.executor
                        .wake_connect(conn_index, Err(crate::tls::handshake_eof()));
                    self.driver.close_connection(conn_index);
                    return;
                }
                self.executor.wake_recv(conn_index);
                return;
            }
            if -result == libc::ECANCELED {
                // Cancelled with the connection open, by a park: the task re-arms when it
                // parks again.
                self.executor.wake_recv(conn_index);
                return;
            }
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.read = ReadHalf::Error;
            }
            let established = self
                .driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.established);
            if !established {
                self.executor
                    .wake_connect(conn_index, Err(io::Error::from_raw_os_error(-result)));
            }
            self.executor.fail_recv(
                conn_index,
                generation,
                io::Error::from_raw_os_error(-result),
            );
            self.driver.close_connection(conn_index);
            return;
        }
        let received = result as usize;
        metrics::BYTES.add(metrics::bytes::RECEIVED, received as u64);
        metrics::RECV_DIRECT.add(metrics::recv_direct::BYTES, received as u64);
        self.withdraw_park_offer(conn_index);
        // The feed's plaintext is recorded as the growth of `recv_buffered`,
        // all at this batch's time.
        let buffered_before_feed = self.driver.arrival_feed_start(conn_index);
        let Some(tls_table) = self.driver.tls_table.as_mut() else {
            return;
        };
        // SAFETY: the receive came from `tls_recv_arm` for this connection,
        // and the kernel wrote `received` bytes at its target, within the
        // length it was armed with.
        let tls_result = unsafe {
            crate::tls::feed_tls_received(
                tls_table,
                &mut self.driver.accumulators,
                &mut self.driver.send_copy_pool,
                conn_index,
                generation,
                buf,
                received,
                &mut self.driver.tls_out_scratch,
            )
        };
        self.driver
            .arrival_feed_end(conn_index, buffered_before_feed);
        // TLS output (handshake responses, alerts) goes through the send
        // queue, including on the error path, where an alert should still go
        // out before the close.
        if !self.driver.tls_out_scratch.is_empty() {
            let mut sends = std::mem::take(&mut self.driver.tls_out_scratch);
            self.driver.queue_built_sends(conn_index, &mut sends);
            self.driver.tls_out_scratch = sends;
        }
        self.apply_tls_recv_result(conn_index, tls_result);
        if self.driver.rearms_after_completion(conn_index) && self.arm_direct_recv(conn_index, None)
        {
            self.executor.wake_recv(conn_index);
        }
    }

    /// [`Driver::arm_direct_recv_or_close`], then hand any abort it recorded
    /// to the executor, so the reader it woke finds the error when polled.
    /// Every arm from the event loop goes through here; the one from a task
    /// poll (`park_recv`) drains the aborts itself.
    fn arm_direct_recv(&mut self, conn_index: u32, need: Option<usize>) -> bool {
        let closed = self.driver.arm_direct_recv_or_close(conn_index, need);
        if closed {
            for (index, generation, err) in self.driver.take_recv_aborts() {
                self.executor.fail_recv(index, generation, err);
            }
        }
        closed
    }

    /// Completion of a direct or TLS connection's hangup poll
    /// (`OpTag::HangupPoll`): the peer sent a FIN or a reset, or the socket
    /// has an error. On a TLS connection it sets `hangup_seen` and arms a
    /// receive, which is then re-armed after each completion until the end
    /// is read. On a direct connection: with a receive in flight, that
    /// receive sees it, and the
    /// connection goes on `hangup_rechecks` in case the receive returns bytes
    /// queued ahead of the end. With none, the hangup peek finds out whether
    /// bytes are queued ahead of it.
    /// `-ECANCELED` comes from the close's cancel lead or worker shutdown and
    /// changes nothing.
    fn handle_hangup_poll(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let Some(cs) = self.driver.connections.get_mut(conn_index) else {
            return;
        };
        if cs.generation != ud.payload() {
            return;
        }
        cs.hangup_poll_armed = false;
        if result < 0 || !matches!(cs.lifecycle, Lifecycle::Open) || cs.recv_finished() {
            return;
        }
        if !cs.recv_direct {
            // A TLS connection reads the rest of the stream through its
            // receive: re-armed after every completion from here until it reads
            // the close_notify, returns 0 at the FIN, or fails.
            cs.hangup_seen = true;
            if self.arm_direct_recv(conn_index, None) {
                self.executor.wake_recv(conn_index);
            }
            return;
        }
        if cs.hangup_peek_armed {
            return;
        }
        if cs.recv_direct_armed {
            // The receive returns the queued bytes or the end. If it returns
            // bytes, the recheck peeks once they are read and nothing is
            // armed, whether or not a read parks again.
            cs.hangup_recheck_due = true;
            if !cs.hangup_recheck {
                cs.hangup_recheck = true;
                let generation = cs.generation;
                self.driver.hangup_rechecks.push((conn_index, generation));
            }
            return;
        }
        // A pending park waits for nothing to be armed. The hangup stays
        // pending on the socket: the adopting worker's poll, or this one
        // re-armed when the park is abandoned, completes at once.
        if self.driver.park_pending(conn_index) {
            return;
        }
        // A peek that cannot be pushed is submitted again by the recheck.
        if !self.driver.submit_hangup_peek(conn_index)
            && let Some(cs) = self.driver.connections.get_mut(conn_index)
        {
            cs.hangup_recheck_due = true;
            if !cs.hangup_recheck {
                cs.hangup_recheck = true;
                let generation = cs.generation;
                self.driver.hangup_rechecks.push((conn_index, generation));
            }
        }
    }

    /// Completion of a hangup peek (`OpTag::HangupPeek`). A positive result
    /// means bytes are queued ahead of the end of the stream: they stay in
    /// the socket with it, the connection goes on `hangup_rechecks`, and a
    /// reader's receives deliver the bytes and then the end. Otherwise (0,
    /// the FIN alone, or an error) the stream has ended with nothing left in
    /// the socket. If no receive is in flight and nothing is buffered, the
    /// end is recorded on the read half, as a parked read would record it,
    /// and an error also closes the connection. Otherwise the connection
    /// goes on `hangup_rechecks`: buffered bytes stay readable, and once
    /// they are read the recheck peeks again. A peek error is kept in
    /// `hangup_error`, because the peek cleared the socket's pending error
    /// and whatever later finds the end has to report it.
    fn handle_hangup_peek(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let Some(cs) = self.driver.connections.get_mut(conn_index) else {
            return;
        };
        if cs.generation != ud.payload() {
            return;
        }
        cs.hangup_peek_armed = false;
        if !matches!(cs.lifecycle, Lifecycle::Open)
            || cs.recv_finished()
            || matches!(-result, libc::ECANCELED | libc::EAGAIN | libc::EINTR)
        {
            return;
        }
        if result > 0 {
            cs.hangup_recheck_due = false;
            if !cs.hangup_recheck {
                cs.hangup_recheck = true;
                let generation = cs.generation;
                self.driver.hangup_rechecks.push((conn_index, generation));
            }
            return;
        }
        if cs.recv_direct_armed || self.driver.recv_buffered(conn_index) > 0 {
            // The end stays unseen until the buffered bytes are read; the
            // recheck peeks again then, whether or not a read parks.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                if result < 0 {
                    cs.hangup_error = -result;
                }
                cs.hangup_recheck_due = true;
                if !cs.hangup_recheck {
                    cs.hangup_recheck = true;
                    let generation = cs.generation;
                    self.driver.hangup_rechecks.push((conn_index, generation));
                }
            }
            return;
        }
        // An earlier peek may have taken the socket's error.
        let result = match self.driver.connections.get(conn_index) {
            Some(cs) if result == 0 && cs.hangup_error != 0 => -cs.hangup_error,
            _ => result,
        };
        metrics::RECV_DIRECT.increment(metrics::recv_direct::HANGUP);
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            if result == 0 {
                cs.note_eof(false);
            } else {
                cs.read = ReadHalf::Error;
            }
        }
        if result < 0 {
            self.executor.fail_recv(
                conn_index,
                ud.payload(),
                io::Error::from_raw_os_error(-result),
            );
            self.driver.close_connection(conn_index);
        }
        self.executor.wake_recv(conn_index);
    }

    /// Submit the hangup polls that could not be submitted
    /// (`Driver::hangup_poll_retries`), skipping connections with a park
    /// pending. Drops entries whose poll is armed and connections that
    /// closed, were recycled or finished reading.
    fn retry_hangup_polls(&mut self) {
        if self.driver.hangup_poll_retries.is_empty() {
            return;
        }
        let mut list = std::mem::take(&mut self.driver.hangup_poll_retries);
        list.retain(|&(conn_index, generation)| {
            let Some(cs) = self.driver.connections.get(conn_index) else {
                return false;
            };
            if cs.generation != generation || !cs.hangup_poll_retry {
                return false;
            }
            if !matches!(cs.lifecycle, Lifecycle::Open) || cs.recv_finished() {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.hangup_poll_retry = false;
                }
                return false;
            }
            if self.driver.park_pending(conn_index) {
                return true;
            }
            // Clears `hangup_poll_retry` once the poll is armed; a failed
            // push leaves the entry, and pushes no second one.
            self.driver.arm_hangup_poll(conn_index);
            self.driver
                .connections
                .get(conn_index)
                .is_some_and(|cs| cs.hangup_poll_retry)
        });
        list.append(&mut self.driver.hangup_poll_retries);
        self.driver.hangup_poll_retries = list;
    }

    /// Submit owed hangup polls (`retry_hangup_polls`), then peek again on
    /// the connections in `hangup_rechecks` whose `hangup_recheck_due` is
    /// set, once nothing is buffered, armed or parking. The end of the
    /// stream behind bytes already delivered is then recorded on the read
    /// half even if no read parks after they are consumed. Drops connections
    /// that closed, were recycled or finished reading.
    fn recheck_hangups(&mut self) {
        self.retry_hangup_polls();
        if self.driver.hangup_rechecks.is_empty() {
            return;
        }
        let mut list = std::mem::take(&mut self.driver.hangup_rechecks);
        list.retain(|&(conn_index, generation)| {
            let Some(cs) = self.driver.connections.get(conn_index) else {
                return false;
            };
            if cs.generation != generation {
                return false;
            }
            if !matches!(cs.lifecycle, Lifecycle::Open) || cs.recv_finished() {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.hangup_recheck = false;
                    cs.hangup_recheck_due = false;
                }
                return false;
            }
            if cs.hangup_recheck_due
                && !cs.recv_direct_armed
                && !cs.hangup_peek_armed
                && self.driver.recv_buffered(conn_index) == 0
                && !self.driver.park_pending(conn_index)
                && self.driver.submit_hangup_peek(conn_index)
                && let Some(cs) = self.driver.connections.get_mut(conn_index)
            {
                cs.hangup_recheck_due = false;
            }
            true
        });
        // Entries added while this ran went onto the list swapped in.
        list.append(&mut self.driver.hangup_rechecks);
        self.driver.hangup_rechecks = list;
    }

    fn dispatch_cqe(&mut self, user_data_raw: u64, result: i32, flags: u32) {
        metrics::RING.increment(metrics::ring::CQE_PROCESSED);
        let ud = UserData(user_data_raw);
        let tag = match ud.tag() {
            Some(t) => t,
            None => {
                // Unknown OpTag — most likely a future enum reorder or a
                // corrupted CQE. In debug builds, panic so the bug surfaces;
                // in release, swallow but increment the metric so it's at
                // least observable.
                debug_assert!(
                    false,
                    "dispatch_cqe: unknown OpTag {:#x} in user_data {:#x}",
                    (user_data_raw >> 56) & 0xFF,
                    user_data_raw,
                );
                metrics::RING.increment(metrics::ring::CQE_UNKNOWN_TAG);
                return;
            }
        };
        // Split the total by operation, because every question about
        // per-operation cost is really "which completions". The slot is the
        // discriminant; an unknown tag returned above and is counted by
        // CQE_UNKNOWN_TAG instead, so this and that counter partition
        // CQE_PROCESSED exactly.
        metrics::CQE_BY_TAG.increment(tag as usize);

        match tag {
            OpTag::AcceptMulti => self.handle_accept_multi(ud, result, flags),
            OpTag::ParkInstall => self.handle_park_install(ud, result),
            OpTag::RecvDirect => self.handle_recv_direct(ud, result),
            OpTag::HangupPoll => self.handle_hangup_poll(ud, result),
            OpTag::HangupPeek => self.handle_hangup_peek(ud, result),
            OpTag::Send => self.handle_send(ud, result),
            OpTag::SendMsgZc => self.handle_send_msg_zc(ud, result, flags),
            OpTag::Close => self.handle_close(ud),
            OpTag::Shutdown => self.handle_shutdown(ud, result),
            // The `Close` CQE releases the slot. A failure of this lead
            // changes nothing and is not counted: `ENOTCONN` when the socket
            // is already in `TCP_CLOSE` (reset, failed connect, or both FINs
            // exchanged).
            OpTag::CloseShutdown => {}
            // Ignored likewise: the `Close` CQE releases the slot. The
            // cancelled requests' own CQEs arrive with `-ECANCELED`, usually
            // before the Close CQE, and take each handler's
            // `close_submitted` or closing-connection path.
            OpTag::CloseCancel => {}
            OpTag::EventFdRead => self.handle_eventfd_read(),
            OpTag::TlsSend => self.handle_tls_send(ud, result),
            OpTag::Connect => self.handle_connect(ud, result),
            OpTag::Timeout => self.handle_timeout(ud, result),
            OpTag::Cancel => {}
            OpTag::TickTimeout => {
                self.driver.tick_timeout_armed = false;
                // Republish the load: connections closing is the other way this
                // worker's count moves, and without this a worker that shed all
                // its work would still look busy to its peers.
                self.publish_load();
            }
            OpTag::Timer => self.handle_timer(ud, result),
            OpTag::RecvMsgUdp => self.handle_recv_msg_udp(ud, result, flags),
            OpTag::SendMsgUdp => self.handle_send_msg_udp(ud, result),
            OpTag::RecvUdp => self.handle_recv_udp(ud, result, flags),
            OpTag::SendUdp => self.handle_send_udp(ud, result),
            OpTag::NvmeCmd => self.handle_nvme_cmd(ud, result),
            OpTag::DirectIo => self.handle_direct_io(ud, result),
            OpTag::Fs => self.handle_fs(ud, result),
            OpTag::PidfdPoll => self.handle_pidfd_poll(ud, result),
            OpTag::SendPollOut => self.handle_send_pollout(ud, result, flags),
            OpTag::SendBackstop => self.handle_send_backstop(),
            // The loop checks the deadlines on every iteration; the timer
            // only ends the wait.
            OpTag::HandshakeDeadline => self.driver.handshake_timer_armed = false,
            OpTag::SendMsgCoalesced => self.handle_send_msg_coalesced(ud, result),
            // No notification follows a plain `send`.
            OpTag::SendMsgZcDrain => self.handle_send_msg_zc(ud, result, 0),
        }
    }

    /// Install an accepted fd into a connection slot and start serving it.
    ///
    /// Shared by the two ways a connection arrives: the acceptor channel (pool
    /// mode) and a multishot accept CQE (merged mode). Consumes `raw_fd` — it
    /// is registered into the fixed-file table and then closed, or closed on
    /// any failure along the way.
    /// Hand every lifted-off connection to the worker it was parked for.
    ///
    /// A connection in `park_ready` has already left this worker: its slot is
    /// released and its future dropped. Only the `OwnedFd` keeps the socket
    /// alive, so an entry dropped here closes a live client connection. That
    /// is why a full channel puts the entry back rather than discarding it —
    /// the target is busy, not gone, and the next iteration will retry.
    ///
    /// A disconnected channel is the one case with no recovery: the target
    /// worker has exited, so the connection is dropped and the peer sees the
    /// close. Nothing else can happen to it.
    fn drain_park_ready(&mut self) {
        if self.driver.park_ready.is_empty() {
            return;
        }
        let mut retry = Vec::new();
        for parked in std::mem::take(&mut self.driver.park_ready) {
            let Some((tx, wake)) = self.driver.peer_park.get(parked.target) else {
                continue; // no such worker; `parked` drops and closes.
            };
            match tx.try_send(parked) {
                Ok(()) => wake.wake(),
                Err(crate::handoff::TrySendError::Full(p)) => retry.push(p),
                // Target gone: nothing to retry onto.
                Err(crate::handoff::TrySendError::Disconnected(_)) => {}
            }
        }
        self.driver.park_ready = retry;
    }

    /// Adopt connections other workers parked onto this one.
    ///
    /// The parking worker installed the fd only once nothing was armed on the
    /// socket there: its receive and hangup poll had ended
    /// (`drive_park_drains`).
    /// That is what makes it safe to arm here: no other worker is still
    /// reading this socket.
    fn drain_adopted(&mut self) {
        let Some(rx) = self.driver.park_rx.take() else {
            return;
        };
        while let Ok(parked) = rx.try_recv() {
            let crate::park::ParkedFd {
                fd,
                listener,
                peer,
                pending,
                state,
                tls,
                ..
            } = parked;
            // `install_accepted_with_pending` registers the fd and closes this
            // handle, exactly as it does for a freshly accepted one.
            let raw = std::os::fd::IntoRawFd::into_raw_fd(fd);
            metrics::CONNECTIONS.increment(metrics::conn::ADOPTED);
            self.install_accepted_with_pending(
                raw,
                listener,
                peer,
                pending,
                Some(crate::backend::uring::driver::Adopt { state, tls }),
            );
        }
        self.driver.park_rx = Some(rx);
    }

    /// Withdraw a park offer because bytes arrived (tier 3, #443).
    ///
    /// Arriving bytes mean a new request has begun, so the quiescent point the
    /// handler offered at is gone. This is what makes `offer_for_park` a
    /// one-shot: the handler offers once when idle and never has to remember
    /// to revoke.
    ///
    /// **Every path that delivers bytes to a connection must call this**.
    /// `park_blocker` also returns `ParkBlocker::DataPending` while bytes are
    /// unconsumed, so a path that misses this call cannot park the connection
    /// while those bytes sit in the accumulator or a direct receive's
    /// buffer.
    fn withdraw_park_offer(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        // Read first: the common case is no offer, and a predictable branch
        // beats two stores on every delivery.
        if self.driver.park_offered.get(idx).copied().unwrap_or(false) {
            // Data reached a connection whose recv was cancelled for a park.
            // If this tracks `not_offered`, the cancel is not stopping delivery.
            if self.driver.park_drain.get(idx).and_then(|d| *d).is_some() {
                metrics::PARK_DIAG.increment(metrics::park_diag::WITHDRAW_WHILE_DRAINING);
            }
            self.driver.park_offered[idx] = false;
            self.driver.park_carry.remove(&conn_index);
        }
    }

    /// Consider rebalancing one connection off this worker (tier 3, #443).
    ///
    /// Called once per tick rather than per completion: park repairs a
    /// *standing* imbalance, and a decision made on every CQE would act on
    /// load-table noise.
    ///
    /// Does nothing at all unless the kernel supports the fd recovery park
    /// needs, this worker knows the other workers' loads (merged accept mode),
    /// and some handler has offered a connection. In pool mode — the default —
    /// placement is round-robin and there is no imbalance to repair, so this
    /// returns immediately.
    /// Finish the parks whose recv-cancel is out, and time out the rest.
    ///
    /// A draining connection has no recv armed, so nothing can reach it once the
    /// CQEs that were already posted have been delivered. When the handler comes
    /// back to a quiescent point and re-offers, the install can go out and
    /// cannot lose the race. That ordering is the whole of phase 2; linking the
    /// install to the cancel is what made 9,427 of 9,427 abandonments
    /// (`docs/journal/2026-09-two-phase-park.md`).
    fn drive_park_drains(&mut self) {
        if self.driver.park_drain_pending.is_empty() {
            return;
        }
        // Visit the list, not `park_drain`: that is sized to `max_connections`
        // and walking it every tick was most of an idle worker's cycles (#514).
        let mut pending = std::mem::take(&mut self.driver.park_drain_pending);
        for &conn_index in &pending {
            let Some(drain) = self.driver.park_drain[conn_index as usize] else {
                continue;
            };
            // A recycled slot must not inherit someone else's drain.
            if self.driver.connections.generation(conn_index) != drain.generation {
                self.driver.set_park_drain(conn_index, None);
                metrics::PARK_DIAG.increment(metrics::park_diag::DRAIN_STALE);
                continue;
            }
            // Still parkable *and* offered again: the handler is back at a
            // quiescent point with fresh state deposited, which is exactly the
            // condition the install needs. The install goes out only with no
            // receive armed, so it also waits for this park's cancel to end
            // the receive.
            let armed =
                self.driver.connections.get(conn_index).is_some_and(|c| {
                    c.recv_direct_armed || c.hangup_poll_armed || c.hangup_peek_armed
                });
            if !armed && self.driver.park_blocker(conn_index).is_none() {
                if self
                    .driver
                    .ring
                    .submit_park_install(conn_index, drain.generation)
                    .is_err()
                {
                    // Backpressure: keep the drain and retry next tick.
                    continue;
                }
                self.driver.set_park_drain(conn_index, None);
                self.driver.park_in_flight[conn_index as usize] =
                    Some(crate::backend::uring::driver::ParkInFlight {
                        target: drain.target,
                        generation: drain.generation,
                    });
                metrics::PARK_DIAG.increment(metrics::park_diag::INSTALL_AFTER_DRAIN);
                // How long the connection sat with no recv armed. One
                // `Instant::now()` per completed park, not per tick.
                let held_us = drain
                    .started
                    .elapsed()
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64;
                metrics::PARK_DRAIN_US.increment(metrics::park_drain_us::bucket(held_us));
                continue;
            }
            // Not ready yet. Spend a tick; on the last one give the connection
            // its recv back rather than leaving it stranded.
            match drain.ticks_left.checked_sub(1) {
                Some(0) | None => {
                    metrics::PARK_DIAG.increment(metrics::park_diag::DRAIN_TIMEOUT);
                    self.abandon_park_drain(conn_index);
                }
                Some(left) => {
                    self.driver.set_park_drain(
                        conn_index,
                        Some(crate::backend::uring::driver::ParkDrain {
                            ticks_left: left,
                            ..drain
                        }),
                    );
                }
            }
        }
        // Keep the drains still outstanding, in order, plus any started while
        // this ran (they went onto the list we swapped in).
        pending.retain(|&i| self.driver.park_drain[i as usize].is_some());
        for i in std::mem::take(&mut self.driver.park_drain_pending) {
            if !pending.contains(&i) {
                pending.push(i);
            }
        }
        self.driver.park_drain_pending = pending;
    }

    fn maybe_park_one(&mut self) {
        if !self.driver.ring.supports_park() || self.driver.park_offered.is_empty() {
            return;
        }
        let Some(loads) = self.driver.worker_loads.clone() else {
            return;
        };
        if self.driver.peer_park.len() != loads.len() {
            return;
        }
        let me = self.driver.worker_index;
        let snapshot: Vec<u32> = loads
            .iter()
            .map(|l| l.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        let accepting: Vec<bool> = match self.driver.worker_accepting {
            Some(ref flags) => flags
                .iter()
                .map(|f| f.load(std::sync::atomic::Ordering::Relaxed))
                .collect(),
            None => vec![true; snapshot.len()],
        };
        let mine = snapshot.get(me).copied().unwrap_or(0);
        let Some(target) = choose_park_target(&snapshot, &accepting, me, mine) else {
            return;
        };

        // Which connection: one the handler offered. That is the whole of the
        // "prefer idle connections" guardrail — an offer is only made at a
        // quiescent point, and it is withdrawn the moment bytes arrive, so an
        // offered connection is idle by construction rather than by estimate.
        let mut started = 0usize;
        for conn_index in 0..self.driver.park_offered.len() as u32 {
            if started >= PARK_PER_TICK {
                break;
            }
            if !self.driver.park_offered[conn_index as usize] {
                continue;
            }
            if self.begin_park(conn_index, target) {
                started += 1;
                // Claim the slot on the target's behalf immediately. The load
                // table is only refreshed when a worker publishes, so without
                // this every park in a burst would read the same stale
                // snapshot and pile onto one target — the thundering herd
                // tier 1 already hit (#457).
                loads[target].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Begin parking `conn_index` onto worker `target` (tier 3, #443).
    ///
    /// Recovering the fd is asynchronous, so this only submits; the decision
    /// to actually move is taken in [`Self::handle_park_install`] once the
    /// CQE lands. Returns whether the submission went out.
    fn begin_park(&mut self, conn_index: u32, target: usize) -> bool {
        if !self.driver.ring.supports_park() {
            return false;
        }
        if target == self.driver.worker_index {
            return false;
        }
        if self.driver.park_in_flight[conn_index as usize].is_some() {
            return false;
        }
        if !self.driver.is_parkable(conn_index) {
            return false;
        }
        // A hangup peek completes at once and may close the connection; the
        // next tick decides once it has.
        if self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.hangup_peek_armed)
        {
            return false;
        }
        let generation = self.driver.connections.generation(conn_index);

        // Cancel what is armed on the socket before the install. A receive
        // left armed here would keep reading a socket that now belongs to
        // another worker. A connection has the direct receive of a parked
        // read, if one is in flight, and its hangup poll.
        let mut cancel_targets = [0u64; 2];
        let mut cancel_count = 0;
        if let Some(c) = self.driver.connections.get(conn_index) {
            use crate::completion::{OpTag, UserData};
            if c.recv_direct_armed {
                cancel_targets[cancel_count] =
                    UserData::encode(OpTag::RecvDirect, conn_index, c.recv_direct_slot).raw();
                cancel_count += 1;
            }
            if c.hangup_poll_armed {
                cancel_targets[cancel_count] =
                    UserData::encode(OpTag::HangupPoll, conn_index, generation).raw();
                cancel_count += 1;
            }
        }

        // Phase 1: cancel the recv and wait. The install is NOT submitted here
        // and NOT linked to the cancel — a cancel cannot retract recv CQEs the
        // kernel already posted, so an install behind it lands while those are
        // still being delivered and finds the offer withdrawn. Measured: that
        // accounted for 9,427 of 9,427 abandonments.
        match cancel_count {
            1.. => {
                // SQ pressure is backpressure, not failure (Invariant 7). A
                // first cancel that fails leaves nothing changed. A second
                // that fails leaves its target armed, so the drain waits for
                // it until `DRAIN_TIMEOUT` abandons the park and re-arms.
                if self
                    .driver
                    .ring
                    .submit_park_recv_cancel(conn_index, cancel_targets[0])
                    .is_err()
                {
                    return false;
                }
                for &t in &cancel_targets[1..cancel_count] {
                    let _ = self.driver.ring.submit_park_recv_cancel(conn_index, t);
                }
                metrics::PARK_DIAG.increment(metrics::park_diag::CANCEL_SUBMITTED);
                self.driver.set_park_drain(
                    conn_index,
                    Some(crate::backend::uring::driver::ParkDrain {
                        target,
                        generation,
                        ticks_left: PARK_DRAIN_TICKS,
                        started: std::time::Instant::now(),
                    }),
                );
            }
            0 => {
                // Nothing armed to cancel, so nothing can arrive: install now.
                metrics::PARK_DIAG.increment(metrics::park_diag::CANCEL_ABSENT);
                if self
                    .driver
                    .ring
                    .submit_park_install(conn_index, generation)
                    .is_err()
                {
                    return false;
                }
                self.driver.park_in_flight[conn_index as usize] =
                    Some(crate::backend::uring::driver::ParkInFlight { target, generation });
            }
        }
        metrics::CONNECTIONS.increment(metrics::conn::PARK_STARTED);
        true
    }

    /// Give up on a draining park: clear the flag and put the recv back.
    ///
    /// The `ECANCELED` branch skips its re-arms while `park_drain` is set, so
    /// whoever stops the park owes the connection a recv. Missing one leaves it
    /// `Open` with nothing armed and its bytes piling up forever, which is the
    /// failure the unconditional re-arm existed to prevent.
    fn abandon_park_drain(&mut self, conn_index: u32) {
        if self
            .driver
            .park_drain
            .get(conn_index as usize)
            .and_then(|d| *d)
            .is_none()
        {
            return;
        }
        self.driver.set_park_drain(conn_index, None);
        self.rearm_direct_after_park(conn_index);
    }

    /// The `FixedFdInstall` CQE: decide whether the park still makes sense.
    ///
    /// The connection was quiescent when the install was submitted, but it
    /// stayed fully live across the round trip — data can have arrived, the
    /// peer can have sent FIN, the handler can have queued a send, and the
    /// slot can even have been recycled. So the gate is re-checked here, and
    /// anything short of "still parkable" abandons the move.
    ///
    /// `result` is a real fd on success. Every abandon path must close it:
    /// it is a second reference to the socket, and leaking it would keep the
    /// peer from ever seeing a FIN.
    fn handle_park_install(&mut self, ud: crate::completion::UserData, result: i32) {
        let conn_index = ud.conn_index();
        let generation = ud.payload();
        // The slot may have been recycled while the install was in flight.
        // The payload is the generation at submit, checked before anything on
        // the slot is touched (Domain Invariant 3): a park in flight, a drain
        // or an armed poll found here belongs to the slot's current occupant,
        // not to the connection this CQE answers.
        if self.driver.connections.generation(conn_index) != generation {
            metrics::PARK_ABANDONED.increment(metrics::park_abandon::SLOT_RECYCLED);
            // A second reference to the previous occupant's socket.
            if result >= 0 {
                unsafe { libc::close(result) };
            }
            return;
        }
        let Some(in_flight) = self.driver.park_in_flight[conn_index as usize].take() else {
            // No park outstanding: a stray or duplicated CQE. Still close the
            // fd, or the socket reference leaks.
            if result >= 0 {
                unsafe { libc::close(result) };
            }
            // A draining flag with no park behind it would strand the
            // connection with no recv armed, so put it back either way.
            self.abandon_park_drain(conn_index);
            return;
        };

        // An entry is set for the slot's current generation and cleared when
        // the slot is released, so it is the one this CQE answers.
        debug_assert_eq!(in_flight.generation, generation);

        // A failed install. Not an error: park is best-effort and policy can
        // try again later. Re-arm the hangup poll and wake the reader.
        if result < 0 {
            metrics::PARK_ABANDONED.increment(metrics::park_abandon::INSTALL_FAILED);
            self.rearm_direct_after_park(conn_index);
            return;
        }
        // SAFETY: a non-negative `FixedFdInstall` result is a fresh fd owned
        // by this process; nothing else holds it.
        let fd = {
            use std::os::fd::FromRawFd;
            unsafe { std::os::fd::OwnedFd::from_raw_fd(result) }
        };

        // Quiesce can have broken across the round trip. Record *which* gate
        // closed: `park_started` minus `park_completed` is a large number under
        // load and on its own it cannot say why, which left the dominant cause
        // a matter of inference rather than measurement.
        if let Some(blocker) = self.driver.park_blocker(conn_index) {
            metrics::PARK_ABANDONED.increment(blocker.abandon_metric());
            self.rearm_direct_after_park(conn_index);
            return; // `fd` drops.
        }
        // The install went out with nothing armed, and arms are refused while
        // the park is pending. One armed now would read on this worker after
        // the socket moved, so the park is abandoned instead.
        if self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.recv_direct_armed || c.hangup_poll_armed || c.hangup_peek_armed)
        {
            debug_assert!(false, "a receive was armed while the park was pending");
            metrics::PARK_ABANDONED.increment(metrics::park_abandon::RECEIVE_ARMED);
            self.rearm_direct_after_park(conn_index);
            return; // `fd` drops.
        }

        let (listener, peer) = match self.driver.connections.get(conn_index) {
            // `park_blocker` refuses a connection with no listener
            // (`ParkBlocker::Outbound`), so this is unreachable rather than a
            // default. Fabricating `ListenerId(0)` here is what let an
            // outbound connection be adopted onto a TLS listener's identity.
            Some(cs) if cs.listener.is_some() => (
                cs.listener.expect("checked by the guard above"),
                cs.peer_addr
                    .clone()
                    .unwrap_or(crate::connection::PeerAddr::Tcp(
                        std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                    )),
            ),
            // No slot, or an outbound connection that slipped past the gate:
            // either way `fd` drops and closes this reference.
            _ => return,
        };
        let pending = self.driver.take_pending_for_park(conn_index);
        let state = self.driver.park_carry.remove(&conn_index);
        // A TLS connection's session and unprocessed ciphertext move with
        // it. No receive is in flight (checked above), so the ciphertext
        // buffer is not being written into.
        let tls = self
            .driver
            .tls_table
            .as_mut()
            .and_then(|t| t.take(conn_index));

        // Ordinary teardown. It closes the fixed-file entry and drops the
        // handler future, but does *not* FIN: `fd` above is a second
        // reference keeping the socket open, and `socket_handed_off` keeps
        // the close from shutting the socket down. A connection with a
        // pending shutdown could not have passed the gate, so no FIN is
        // queued.
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.socket_handed_off = true;
        }
        self.driver.close_connection(conn_index);
        // The socket belongs to the target worker from here. Commit the Close
        // now so every send path refuses (`close_submitted`) instead of
        // queueing bytes, unencrypted once the TLS state has left, onto it.
        // The gate guaranteed no sends, chain or shutdown, so this sets
        // `close_submitted` and pushes the Close, or queues it on
        // `pending_close_retries` when the SQ is full.
        self.driver.try_finalize_close(conn_index);
        debug_assert!(self.driver.send_queues[conn_index as usize].close_submitted);

        metrics::CONNECTIONS.increment(metrics::conn::PARK_COMPLETED);
        self.driver.park_ready.push(crate::park::ParkedFd {
            fd,
            listener,
            peer,
            pending,
            state,
            tls,
            target: in_flight.target,
        });
    }

    fn install_accepted(
        &mut self,
        raw_fd: std::os::fd::RawFd,
        listener: crate::ListenerId,
        peer_addr: crate::connection::PeerAddr,
    ) {
        self.install_accepted_with_pending(raw_fd, listener, peer_addr, Vec::new(), None)
    }

    /// As [`Self::install_accepted`], but seeds the accumulator with bytes
    /// that arrived before the connection got here — the unconsumed remainder
    /// carried by a park (tier 3, #443).
    ///
    /// Seeded before any receive is armed (at install for a TLS listener, the
    /// first parked read for a plaintext one), so a handler polled on this
    /// worker sees the carried bytes ahead of anything the new receive
    /// delivers. Appending after would put freshly received bytes in front of
    /// older ones and reorder the peer's stream.
    fn install_accepted_with_pending(
        &mut self,
        raw_fd: std::os::fd::RawFd,
        listener: crate::ListenerId,
        peer_addr: crate::connection::PeerAddr,
        pending: Vec<bytes::Bytes>,
        // `Some` when this install is an adopt: what the handler deposited,
        // recorded per connection for the spawn, and the TLS state that
        // moved with the connection.
        adopt: Option<crate::backend::uring::driver::Adopt>,
    ) {
        // An adopted connection already ran a handler on the worker that
        // parked it, so a close here is not a drop at accept.
        let fresh_accept = adopt.is_none();
        let conn_index = match self.driver.connections.allocate() {
            Some(idx) => idx,
            None => {
                if fresh_accept {
                    metrics::CONNECTIONS.increment(metrics::conn::ACCEPT_TABLE_FULL);
                }
                unsafe {
                    libc::close(raw_fd);
                }
                return;
            }
        };

        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.peer_addr = Some(peer_addr);
            cs.listener = Some(listener);
        }

        if self
            .driver
            .ring
            .register_files_update(conn_index, &[raw_fd])
            .is_err()
        {
            if fresh_accept {
                metrics::CONNECTIONS.increment(metrics::conn::ACCEPT_REGISTER_FAILED);
            }
            self.driver.connections.release(conn_index);
            unsafe {
                libc::close(raw_fd);
            }
            return;
        }
        unsafe {
            libc::close(raw_fd);
        }

        self.driver.accumulators.reset(conn_index);
        self.driver.arrival[conn_index as usize].clear();
        self.driver.reset_send_state(conn_index);
        // A slot is recycled by generation, so without this a new occupant
        // would inherit the previous one's park offer — and its state.
        self.driver.park_offered[conn_index as usize] = false;
        // Cleared, never re-armed here: on the handover path the fd has left
        // this worker, and on the adopt path the caller arms recv itself.
        self.driver.set_park_drain(conn_index, None);
        self.driver.park_carry.remove(&conn_index);
        let adopted_tls = match adopt {
            Some(crate::backend::uring::driver::Adopt { state, tls }) => {
                self.driver.adopt_pending.insert(conn_index, state);
                tls
            }
            None => {
                self.driver.adopt_pending.remove(&conn_index);
                None
            }
        };
        // Bytes a park carried arrive here at this batch's time.
        // `park_blocker` refuses a connection with bytes buffered, so this is
        // normally zero.
        self.driver
            .record_arrival(conn_index, pending.iter().map(bytes::Bytes::len).sum());
        for chunk in &pending {
            self.driver.accumulators.append(conn_index, chunk);
        }
        // An adopted TLS connection brings its established session: install
        // it and start the handler, as for an established plaintext one. Its
        // first parked read arms a receive.
        if let Some(tls) = adopted_tls {
            let Some(tls_table) = self.driver.tls_table.as_mut() else {
                // No TLS on this worker: the session has nowhere to go.
                self.driver.close_connection(conn_index);
                return;
            };
            tls_table.install(conn_index, tls);
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.established = true;
            }
            self.driver.arm_hangup_poll(conn_index);
            metrics::CONNECTIONS.increment(metrics::conn::ACCEPTED);
            metrics::CONNECTIONS_ACTIVE.increment();
            self.spawn_accept_task(conn_index);
            return;
        }
        let tls_listener = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has_server_config_for(Some(listener)));
        // A TLS connection's receive and hangup poll are armed below, once its
        // TLS state exists.
        if !tls_listener && let Some(cs) = self.driver.connections.get_mut(conn_index) {
            // A plaintext connection receives directly into its accumulator.
            // Its receive is armed by its first parked read, and its hangup
            // poll below, once it is open.
            cs.recv_direct = true;
        }

        // TLS path: defer accept until handshake completes.
        if let Some(ref mut tls_table) = self.driver.tls_table
            && tls_table.has_server_config_for(Some(listener))
        {
            if tls_table.create(conn_index, Some(listener)).is_err() {
                self.driver.close_connection(conn_index);
                return;
            }
            let generation = self.driver.connections.generation(conn_index);
            let driver = &mut self.driver;
            driver
                .handshake_deadlines
                .arm(conn_index, generation, |i, g| {
                    crate::tls::handshake_deadline::in_progress(&driver.connections, i, g)
                });
            // The handshake's receives are armed after each completion; once
            // it is done, a parked read arms them. The hangup poll covers a
            // peer close while nothing reads.
            let _ = self.arm_direct_recv(conn_index, None);
            self.driver.arm_hangup_poll(conn_index);
            return;
        }

        // Plaintext path: mark established and spawn async task.
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.established = true;
        }
        self.driver.arm_hangup_poll(conn_index);
        metrics::CONNECTIONS.increment(metrics::conn::ACCEPTED);
        metrics::CONNECTIONS_ACTIVE.increment();
        self.spawn_accept_task(conn_index);
    }

    /// Arm this worker's multishot accepts, once `launch()` has listened.
    ///
    /// Cheap to call every iteration: it is a relaxed load and an early return
    /// after the first arm.
    fn arm_merged_accepts(&mut self) {
        if self.driver.merged_accept_armed
            || self.driver.merged_listeners.is_empty()
            || self
                .driver
                .shutdown_flag
                .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let live = match self.driver.merged_accept_live {
            Some(ref flag) => flag.load(std::sync::atomic::Ordering::Acquire),
            None => false,
        };
        if !live {
            return;
        }
        // Arm all or none: a partial arm would leave one listener unserved
        // with no later trigger to retry, since the flag only rises once.
        for i in 0..self.driver.merged_listeners.len() {
            let (listener_index, ref sockets) = self.driver.merged_listeners[i];
            let fd = sockets.fd(self.driver.worker_index);
            if let Err(error) = self.driver.ring.submit_accept_multi(listener_index, fd) {
                // Submission queue full is backpressure, not failure
                // (Domain Invariant 7) — leave `armed` false and retry next
                // iteration, when the queue has drained.
                let _ = error;
                return;
            }
        }
        self.driver.merged_accept_armed = true;
    }

    /// Publish this worker's live connection count for its peers to read.
    ///
    /// One relaxed store of a value the table already tracks, so a peer
    /// choosing where to place a connection is not reading a stale number.
    fn publish_load(&self) {
        if let Some(ref loads) = self.driver.worker_loads {
            let n = self.driver.connections.active_count() as u32;
            loads[self.driver.worker_index].store(n, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Where a just-accepted connection should be served. `None` means here.
    ///
    /// Tier 1 of the rebalancing design: place while the connection is still
    /// nothing but an integer. The kernel's 4-tuple hash chose this worker, and
    /// for a client opening a pool of connections that hash is uneven — at N
    /// connections over N workers roughly 1/e of workers get none. Moving the
    /// fd now costs a channel send; moving it later is impossible, because
    /// everything a live connection owns is thread-local.
    fn placement_target(&self) -> Option<usize> {
        let loads = self.driver.worker_loads.as_ref()?;
        if self.driver.peer_accept.len() != loads.len() {
            return None;
        }
        let snapshot: Vec<u32> = loads
            .iter()
            .map(|l| l.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        let accepting: Vec<bool> = match self.driver.worker_accepting {
            Some(ref flags) => flags
                .iter()
                .map(|f| f.load(std::sync::atomic::Ordering::Relaxed))
                .collect(),
            None => vec![true; snapshot.len()],
        };
        choose_placement(
            &snapshot,
            &accepting,
            self.driver.worker_index,
            self.driver.connections.active_count() as u32,
        )
    }

    /// Hand a raw accepted fd to another worker.
    ///
    /// Returns it on failure so the caller serves it here instead — dropping it
    /// would be a connection the peer silently never sees.
    fn hand_off_accepted(
        &self,
        raw_fd: std::os::fd::RawFd,
        listener: crate::ListenerId,
        peer_addr: crate::connection::PeerAddr,
        target: usize,
    ) -> Result<(), (std::os::fd::RawFd, crate::connection::PeerAddr)> {
        let Some((tx, wake)) = self.driver.peer_accept.get(target) else {
            return Err((raw_fd, peer_addr));
        };
        // SAFETY: the caller owns `raw_fd` and gives it up here; a failed send
        // returns it below.
        let conn = crate::acceptor::AcceptedConn {
            fd: unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw_fd) },
            listener,
            peer: peer_addr,
        };
        match tx.try_send(conn) {
            Ok(()) => {
                // Claim the slot on the target's behalf straight away. The
                // target only republishes once it drains, and a burst of
                // accepts all read the table before that happens — so without
                // this every worker in the burst picks the same "least loaded"
                // peer and herds onto it. The target's own publish corrects the
                // count a moment later.
                if let Some(ref loads) = self.driver.worker_loads {
                    loads[target].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                wake.wake();
                Ok(())
            }
            // Full or gone: keep it here rather than drop it.
            Err(
                crate::handoff::TrySendError::Full(conn)
                | crate::handoff::TrySendError::Disconnected(conn),
            ) => Err((std::os::fd::IntoRawFd::into_raw_fd(conn.fd), conn.peer)),
        }
    }

    /// A multishot accept produced a connection (merged accept mode).
    ///
    /// `ud`'s conn_index field carries the listener index — there is no
    /// connection yet. Multishot accept delivers no `sockaddr`, so the peer
    /// comes from `getpeername(2)` on the accepted fd.
    fn handle_accept_multi(&mut self, ud: UserData, result: i32, flags: u32) {
        let listener_index = ud.conn_index();

        if result < 0 {
            let err = -result;
            // ECANCELED and EINVAL are what shutdown produces:
            // `ListenerSockets::shut_down` took the socket out of the
            // listening state. EBADF is treated as terminal too. Anything else
            // is worth re-arming for, since losing the arm silently stops the
            // worker accepting.
            let terminal = err == libc::ECANCELED || err == libc::EBADF || err == libc::EINVAL;
            if terminal {
                self.driver.merged_accept_armed = false;
                return;
            }
        } else {
            let raw_fd = result;
            // Merged mode has no acceptor thread, so this is the only place the
            // accepted socket's options get applied. Leaving it out is how
            // `tcp_nodelay(true)` came to be silently ignored here, costing 29x
            // under TLS when Nagle met the peer's delayed ACK (#460).
            //
            // TCP only: a merged listener is never a Unix socket
            // (SO_REUSEPORT does not apply to one), so there is no is_unix case
            // to consider as there is in the acceptor.
            crate::acceptor::apply_accepted_sockopts(raw_fd, self.driver.tcp_nodelay);
            let peer = crate::backend::sockaddr::getpeername_peer_addr(raw_fd).unwrap_or(
                crate::connection::PeerAddr::Tcp(std::net::SocketAddr::from(([0, 0, 0, 0], 0))),
            );
            let listener = crate::ListenerId::from_index(listener_index);
            match self.placement_target() {
                Some(target) => {
                    if let Err((fd, peer)) = self.hand_off_accepted(raw_fd, listener, peer, target)
                    {
                        self.install_accepted(fd, listener, peer);
                    }
                }
                None => self.install_accepted(raw_fd, listener, peer),
            }
            self.publish_load();
        }

        // Without IORING_CQE_F_MORE the kernel has dropped the arm; re-arm or
        // this worker silently stops accepting.
        if !cqueue::more(flags) {
            self.driver.merged_accept_armed = false;
            self.arm_merged_accepts();
        }
    }

    /// A deferred `shutdown(SHUT_WR)` has completed.
    ///
    /// It releases the hold on the Close: `Shutdown` names its socket as the
    /// registered-file slot `Fixed(conn_index)`, so `try_finalize_close` holds
    /// the `Close` that frees the slot until this CQE lands. Without that, the
    /// `Close` could complete first, the next accept could register the slot,
    /// and the kernel could then run the FIN against *that* connection — a live
    /// peer whose next send fails with `EPIPE` (#518). A failed result is
    /// counted (`connections{op="shutdown_failed"}`) and changes nothing else:
    /// the socket refused the FIN because it is already closed, and the Close
    /// goes ahead.
    ///
    /// The generation in the payload is checked for form's sake and for the
    /// counter: because the close now waits on this flag, a stale one should be
    /// unreachable, and `shutdown_stale` existing at all would mean the gate
    /// leaked somewhere.
    fn handle_shutdown(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let idx = conn_index as usize;
        if idx >= self.driver.send_queues.len() {
            return;
        }
        if self.driver.connections.generation(conn_index) != ud.payload() {
            crate::metrics::RING.increment(crate::metrics::ring::SHUTDOWN_STALE);
            return;
        }
        if result < 0 {
            metrics::CONNECTIONS.increment(metrics::conn::SHUTDOWN_FAILED);
        }
        self.driver.send_queues[idx].shutdown_inflight = false;
        self.driver.defer_finalize_close(conn_index);
    }

    fn handle_eventfd_read(&mut self) {
        // Parked connections share this wake. Drained first: a connection
        // here has no worker at all until it is installed, where a queued
        // accept is merely waiting.
        self.drain_adopted();
        // `launch()` wakes every worker right after it listens on the merged
        // sockets, so this is where the arm actually happens — the call in
        // `run()` runs before the gate is up and is only for a worker that
        // starts late enough to find it already set.
        self.arm_merged_accepts();

        // Drain accept channel (server mode only).
        {
            loop {
                let item = match self.driver.accept_rx {
                    Some(ref rx) => rx.try_recv().ok(),
                    None => None,
                };
                let Some(crate::acceptor::AcceptedConn {
                    fd,
                    listener,
                    peer: peer_addr,
                }) = item
                else {
                    break;
                };
                let raw_fd = std::os::fd::IntoRawFd::into_raw_fd(fd);
                self.install_accepted(raw_fd, listener, peer_addr);
            }
        }
        self.publish_load();

        // Drain DNS resolve responses.
        if let Some(ref rx) = self.driver.resolve_rx {
            while let Ok(response) = rx.try_recv() {
                self.executor
                    .deliver_resolve(response.request_id, response.result);
            }
        }

        // Drain process spawn responses.
        if let Some(ref rx) = self.driver.spawn_rx {
            while let Ok(response) = rx.try_recv() {
                self.executor
                    .deliver_spawn(response.request_id, response.result);
            }
        }

        // Drain blocking responses.
        if let Some(ref rx) = self.driver.blocking_rx {
            while let Ok(response) = rx.try_recv() {
                if let Err(ref payload) = response.result {
                    self.driver
                        .panic_reporter
                        .report("spawn_blocking closure", &**payload);
                }
                self.executor
                    .deliver_blocking(response.request_id, response.result);
            }
        }

        // on_notify (synchronous). Set the executor's driver_state
        // thread-local so user code that calls `ringline::spawn()` /
        // wakers / `with_state` works from inside the handler.
        {
            let handler = &mut self.handler;
            let driver_ptr = &mut self.driver as *mut Driver;
            let executor_ptr = &mut self.executor as *mut crate::runtime::Executor;
            let mut driver_state = DriverState {
                driver: unsafe { NonNull::new_unchecked(driver_ptr) },
                executor: unsafe { NonNull::new_unchecked(executor_ptr) },
            };
            let guard = unsafe { set_driver_state_guarded(&mut driver_state) };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler.on_notify();
            }));
            if let Err(payload) = result {
                // SAFETY: the handler call has ended, so this is the only reference.
                unsafe {
                    (*driver_ptr)
                        .panic_reporter
                        .report("handler on_notify", &*payload)
                };
            }
            drop(guard);
        }

        // Re-arm eventfd read. Track whether the re-arm succeeded so the
        // event loop can retry on the next tick if the SQ was full.
        if !self.driver.shutdown_flag.load(Ordering::Relaxed) {
            self.driver.eventfd_armed = self
                .driver
                .ring
                .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr())
                .is_ok();
        }
    }

    fn handle_send(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let payload = ud.payload();
        let pool_slot = UserData::send_payload_slot(payload);

        // Slot-liveness guard: the slot was already released on a
        // pre-submission error path (no CQE was expected) — nothing to do.
        if !self.driver.send_copy_pool.in_use(pool_slot) {
            return;
        }

        // Identity guard: a Send CQE can outlive its connection slot (a close
        // submitted while this send was still in flight). The slot is still
        // in_use — owned by the orphaned send — so liveness alone would let
        // this CQE be misattributed to whatever connection now occupies the
        // reused index (resubmitting the dead connection's bytes onto the new
        // occupant's socket, draining its queue, or failing its send). The
        // payload carries the submitting connection's truncated generation;
        // on mismatch this CQE is the kernel's last reference to the slot:
        // release it and touch nothing else.
        if self.driver.connections.generation(conn_index) & 0xFFFF
            != u32::from(UserData::send_payload_gen(payload))
        {
            // The slot may still name an awaited send, and `release`
            // debug-asserts rather than drop a live id — so take it. It is
            // deliberately *not* settled: this completion belongs to the
            // connection the CQE outlived, and `Executor::remove_connection`
            // already recorded a provisional `Aborted` for that operation
            // when the connection went away. Per #381 a driver result
            // overrides that abort, which is exactly what must not happen
            // here — the result describes a dead occupant's send.
            if let Some((id, _len)) = self.driver.send_copy_pool.take_send_id(pool_slot) {
                self.executor.forget_send(id);
            }
            self.release_pool_slot(pool_slot);
            return;
        }

        // Chain path.
        if self.driver.chain_table.is_active(conn_index) {
            // A chain's SQEs are tagged `OpTag::Send` and bypass the send
            // queue, so while one is active this branch claims *every* Send
            // CQE on the connection. Sends submitted while a chain is active
            // are queued behind it, so no other send's CQE should land here;
            // if one does, its id must not be dropped on the floor: take it
            // (or `release` trips) and report this CQE's own outcome.
            let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
            self.release_pool_slot(pool_slot);
            if let Some((id, logical_len)) = settles {
                let settled = if result > 0 {
                    Ok(logical_len)
                } else {
                    Err(Self::send_error(result))
                };
                self.settle_send(id, settled);
            }
            let event = self.driver.chain_table.on_operation_cqe(conn_index, result);
            if matches!(event, ChainEvent::Complete { .. }) {
                self.fire_chain_complete(conn_index);
            }
            return;
        }

        if result > 0 {
            if self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
                .is_some()
            {
                if self.close_submitted(conn_index) {
                    let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                    self.release_pool_slot(pool_slot);
                    if let Some((id, _logical_len)) = settles {
                        self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    return;
                }
                self.wait_for_room(conn_index, ud, false);
                return;
            }
            let total = self.driver.send_copy_pool.original_len(pool_slot);
            // Take the send this slot settles before releasing it: the slot
            // is about to be recycled, and `release` debug-asserts rather
            // than let a live id go with it.
            let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            self.release_pool_slot(pool_slot);

            // Pop the next queued send (if any) into the kernel, then
            // register a deferred close for the end-of-iteration drain:
            // submit_next_queued may have just emptied the queue and
            // cleared `in_flight`, which is when a close_pending connection
            // is ready to close.
            self.driver.submit_next_queued(conn_index);
            self.driver.defer_finalize_close(conn_index);

            // Only a send's final slot carries its id, so the send
            // settles once, when its final chunk completes, with the
            // *logical* (plaintext) length its caller passed. The wire bytes
            // differ under TLS.
            if let Some((id, logical_len)) = settles {
                self.settle_send(id, Ok(logical_len));
            }
            return;
        }

        // The socket send buffer is full. The pool slot still holds the unsent
        // bytes, so don't release it, don't drain the queue and don't settle
        // the send.
        let errno = -result;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            if self.close_submitted(conn_index) {
                let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                self.release_pool_slot(pool_slot);
                if let Some((id, _logical_len)) = settles {
                    self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                return;
            }
            self.wait_for_room(conn_index, ud, true);
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
        self.release_pool_slot(pool_slot);
        self.driver.drain_conn_send_queue(conn_index);
        // A failed send ends the connection: the queue behind it is gone, so
        // a later send would reach the peer after a gap, and the reader is
        // told why.
        self.abort_connection(conn_index, Self::send_error(result));
        self.driver.defer_finalize_close(conn_index);

        if let Some((id, _logical_len)) = settles {
            self.settle_send(id, Err(Self::send_error(result)));
        }
    }

    /// Wait for room for the rest of send `ud`, after it came back short or
    /// (`eagain`) with `-EAGAIN`. Resubmitting now would return `-EAGAIN`.
    ///
    /// A `POLLOUT` poll usually ends the wait. Once the peer has half-closed, a
    /// one-shot poll completes at once with `POLLRDHUP` and no `POLLOUT`, so it
    /// cannot wait. `handle_send_pollout` then arms a multishot poll, which is
    /// edge-triggered: it reports `POLLRDHUP` once, and then `POLLOUT` when room
    /// appears. A multishot poll stays armed until the connection closes.
    ///
    /// `-EAGAIN` from a send made on a `POLLOUT` arms the multishot poll too. A
    /// socket reporting both would otherwise repeat a poll and a send forever.
    fn wait_for_room(&mut self, conn_index: u32, ud: UserData, eagain: bool) {
        let generation = self.driver.connections.generation(conn_index);
        let state = &mut self.driver.send_queues[conn_index as usize];
        state.waiting_send = Some(ud.raw());
        if !state.on_send_backstop {
            state.on_send_backstop = true;
            self.driver
                .send_backstop_list
                .push((conn_index, generation));
        }
        if std::mem::take(&mut state.pollout_seen) {
            self.resubmit_waiting_send(conn_index, true);
            return;
        }
        if state.send_poll == SendPoll::None {
            let multi = eagain && state.resubmitted_on_pollout;
            self.arm_send_poll(conn_index, multi);
        }
    }

    /// Arm the connection's `SendPollOut`, or queue it if the SQ is full.
    fn arm_send_poll(&mut self, conn_index: u32, multi: bool) {
        let generation = self.driver.connections.generation(conn_index);
        let armed = self
            .driver
            .ring
            .submit_send_pollout(conn_index, generation, multi);
        let state = &mut self.driver.send_queues[conn_index as usize];
        state.send_poll = match (armed.is_ok(), multi) {
            (true, true) => SendPoll::Multi,
            (true, false) => SendPoll::OneShot,
            (false, _) => {
                self.driver
                    .pending_send_pollout_retries
                    .push((conn_index, generation, multi));
                SendPoll::Pending
            }
        };
    }

    /// Resubmit the rest of the connection's waiting send, if it has one. With
    /// the SQ full, the send moves to the retry list of its kind.
    fn resubmit_waiting_send(&mut self, conn_index: u32, on_pollout: bool) {
        let state = &mut self.driver.send_queues[conn_index as usize];
        let Some(raw) = state.waiting_send.take() else {
            return;
        };
        state.resubmitted_on_pollout = on_pollout;
        let ud = UserData(raw);
        let generation = self.driver.connections.generation(conn_index);
        match ud.tag() {
            Some(tag @ (OpTag::Send | OpTag::TlsSend)) => {
                let pool_slot = UserData::send_payload_slot(ud.payload());
                let (ptr, remaining) = self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
                let resubmit = if tag == OpTag::TlsSend {
                    self.driver
                        .ring
                        .submit_tls_send(conn_index, generation, ptr, remaining, pool_slot)
                } else {
                    self.driver
                        .ring
                        .submit_send_copied(conn_index, generation, ptr, remaining, pool_slot)
                };
                if resubmit.is_err() {
                    self.driver
                        .pending_copy_retries
                        .push((conn_index, generation, pool_slot, 0, tag));
                }
            }
            Some(OpTag::SendMsgCoalesced) => {
                let slab_idx = ud.payload() as u16;
                let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
                if self
                    .driver
                    .ring
                    .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
                    .is_err()
                {
                    self.driver
                        .pending_coalesced_retries
                        .push((conn_index, generation, slab_idx, 0));
                }
            }
            _ => {
                let slab_idx = ud.payload() as u16;
                let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
                let resubmit = if self.driver.send_slab.plain_send(slab_idx) {
                    self.submit_slab_drain(OpTag::SendMsgZcDrain, conn_index, slab_idx)
                } else if self.driver.send_slab.plain_msg(slab_idx) {
                    self.driver
                        .ring
                        .submit_send_msg(conn_index, msg_ptr, slab_idx)
                } else {
                    self.driver
                        .ring
                        .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                };
                if resubmit.is_err() {
                    self.driver
                        .pending_zc_retries
                        .push((conn_index, generation, slab_idx, 0));
                }
            }
        }
    }

    /// Fail the send `ud` names, through the completion path it would have
    /// taken, and so with what that path does: on a connection whose close is
    /// not yet requested, the connection closes and the reader is handed the
    /// error (`abort_connection`); on one already closing, nothing is
    /// recorded; a zero-copy entry stays for its notifications.
    fn fail_waiting_send(&mut self, ud: UserData, result: i32) {
        match ud.tag() {
            Some(OpTag::Send) => self.handle_send(ud, result),
            Some(OpTag::TlsSend) => self.handle_tls_send(ud, result),
            Some(OpTag::SendMsgCoalesced) => self.handle_send_msg_coalesced(ud, result),
            _ => self.handle_send_msg_zc(ud, result, 0),
        }
    }

    /// Handle a `SendPollOut` CQE. See [`Self::wait_for_room`].
    fn handle_send_pollout(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        // The poll outlived its connection. `handle_close` dealt with the send.
        if self.driver.connections.generation(conn_index) != ud.payload() {
            return;
        }
        let close_submitted = self.close_submitted(conn_index);
        let state = &mut self.driver.send_queues[conn_index as usize];
        let multi = state.send_poll == SendPoll::Multi;
        let more = cqueue::more(flags);
        if !more {
            state.send_poll = SendPoll::None;
        }

        let error = if result < 0 {
            Some(result)
        } else if close_submitted {
            Some(-libc::ECANCELED)
        } else {
            None
        };
        if let Some(error) = error {
            // With nothing waiting, this is the cancel the `Close` came with,
            // or a poll that outlived its send.
            if let Some(raw) = state.waiting_send.take() {
                self.fail_waiting_send(UserData(raw), error);
            }
            return;
        }

        let mask = result as u32;
        let pollout = mask & libc::POLLOUT as u32 != 0;
        if state.waiting_send.is_none() {
            state.pollout_seen = pollout && state.in_flight;
            return;
        }
        // On an error or a hangup, the resubmit returns the socket's error. A
        // multishot poll's edge does not fire again, so this cannot spin.
        if pollout || (multi && mask & (libc::POLLERR | libc::POLLHUP) as u32 != 0) {
            self.resubmit_waiting_send(conn_index, true);
        } else if !more {
            self.arm_send_poll(conn_index, !multi);
        }
    }

    /// Resubmit every waiting send, once a second. A send can wait with no
    /// `POLLOUT` to end it: a multishot poll's edge can be lost, and a poll does
    /// not report a Unix peer's `SHUT_RD`, where a send fails `EPIPE`. The
    /// interval is a guess, and the retry is unmeasured.
    fn handle_send_backstop(&mut self) {
        self.driver.send_backstop_armed = false;
        std::mem::swap(
            &mut self.driver.send_backstop_list,
            &mut self.driver.send_backstop_scratch,
        );
        for idx in 0..self.driver.send_backstop_scratch.len() {
            let (conn_index, generation) = self.driver.send_backstop_scratch[idx];
            // A dead occupant's entry: `on_send_backstop` is the new occupant's.
            if self.driver.connections.generation(conn_index) != generation {
                continue;
            }
            let state = &mut self.driver.send_queues[conn_index as usize];
            let Some(raw) = state.waiting_send else {
                state.on_send_backstop = false;
                continue;
            };
            if state.close_submitted {
                state.waiting_send = None;
                state.on_send_backstop = false;
                self.fail_waiting_send(UserData(raw), -libc::ECANCELED);
                continue;
            }
            self.driver
                .send_backstop_list
                .push((conn_index, generation));
            self.resubmit_waiting_send(conn_index, false);
        }
        self.driver.send_backstop_scratch.clear();
    }

    /// True when a send-family CQE's slab entry still belongs to the live
    /// occupant of `conn_index`. False means the CQE outlived its connection
    /// slot (closed with the send in flight, index possibly reused) — the
    /// caller must release the entry's resources and touch no per-connection
    /// state. Mirrors the generation check in `handle_send`.
    fn slab_identity_ok(&self, conn_index: u32, slab_idx: u16) -> bool {
        self.driver.send_slab.conn_index(slab_idx) == conn_index
            && self.driver.send_slab.generation(slab_idx)
                == self.driver.connections.generation(conn_index)
    }

    /// True when the Close SQE for this connection's current occupant has
    /// been submitted (deferred close finalized, or force-finalized). Late
    /// send CQEs must not push new SQEs (partial resubmits, POLLOUT arms)
    /// after this point — they would race the in-flight Close. The queue is
    /// already drained by then, so the caller just releases its resources
    /// and fails the send it carries.
    fn close_submitted(&self, conn_index: u32) -> bool {
        self.driver.send_queues[conn_index as usize].close_submitted
    }

    /// Settle one awaited send.
    ///
    /// Every site that resolves an awaited send goes through here so that no
    /// handler open-codes the rule: an id is settled exactly once, is routed
    /// by id rather than by connection, and carries the *logical* length on
    /// success. `Executor::complete_send` wakes the owning task and
    /// overrides a provisional teardown `Aborted` with this result (#381).
    fn settle_send(&mut self, id: SendId, result: io::Result<u32>) {
        self.executor.complete_send(id, result);
    }

    /// The failure an awaited send reports for a terminal send CQE.
    ///
    /// `result == 0` on a stream send means no bytes reached the wire and the
    /// handler is tearing the send down. A send must never resolve with a
    /// truncated count (it would look like a short write of the caller's
    /// message), so it reports `WriteZero` — the same shape mio's flush
    /// reports for a zero-length write.
    fn send_error(result: i32) -> io::Error {
        if result == 0 {
            io::Error::new(io::ErrorKind::WriteZero, "send made no progress")
        } else {
            io::Error::from_raw_os_error(-result)
        }
    }

    /// Close `conn_index` because a send on it failed or the TLS engine
    /// rejected a received record, and report `err` to a
    /// reader parked on `with_data_result`, as a failed socket read is
    /// reported (mio's `abort_connection` is the same step). `read` is set
    /// first, so the close reads as a failure and not as the peer's close.
    ///
    /// A connection whose close is already requested is left as that close
    /// left it: the close's lead cancelled this send, or the receive that
    /// took the socket's error recorded it first.
    fn abort_connection(&mut self, conn_index: u32, err: io::Error) {
        let Some(cs) = self.driver.connections.get_mut(conn_index) else {
            return;
        };
        if cs.close_requested() {
            return;
        }
        cs.read = ReadHalf::Error;
        let generation = cs.generation;
        self.executor.fail_recv(conn_index, generation, err);
        self.driver.close_connection(conn_index);
    }

    /// Return a copy-pool slot and note that send capacity came back.
    ///
    /// Every copy-pool release in this file goes through here. The
    /// bounded-send admission FIFO parks its head until the pool can take a
    /// whole message, and `wake_capacity_if_released` at the end of the run
    /// loop is the only thing that unparks it — so a release that forgets the
    /// flag strands a parked send until some unrelated release happens to set
    /// it. The driver sets the same flag on its own teardown paths.
    fn release_pool_slot(&mut self, slot: u16) {
        self.driver.send_copy_pool.release(slot);
        self.driver.capacity_released = true;
    }

    /// Wake the send-capacity FIFO head if any copy-pool slot came back this
    /// iteration, and clear the flag. Called once, as the last thing in the
    /// run loop; see the call site for why that point.
    ///
    /// Separate from the loop body so tests can drive it directly.
    fn wake_capacity_if_released(&mut self) {
        if self.driver.capacity_released {
            self.driver.capacity_released = false;
            self.executor
                .wake_send_capacity(self.driver.send_copy_pool.free_count());
        }
    }

    /// Hand the executor the send results that no CQE will carry: the
    /// synchronous settles of `DriverCtx::send_awaited` and `send_bounded` (a
    /// message that queued no SQE) and teardown's destroyed queue entries.
    /// Mirrors mio's `drain_send_completions`. A completion handler settles
    /// its own send directly, through `settle_send`.
    fn drain_settled_sends(&mut self) {
        while let Some((id, result)) = self.driver.settled_sends.pop_front() {
            self.settle_send(id, result);
        }
    }

    /// Release the backing pool slots of a coalesced send, then the slab entry.
    ///
    /// Callers that mean to settle the run's awaited send must take it with
    /// `InFlightSendSlab::take_sends` *before* calling this:
    /// the slab release clears the entry's id silently (no tripwire, unlike
    /// the copy pool's).
    fn release_coalesced(&mut self, slab_idx: u16) {
        let mut slots = [u16::MAX; crate::buffer::send_slab::MAX_IOVECS];
        let mut n = 0;
        for &s in self.driver.send_slab.coalesced_pool_slots(slab_idx) {
            slots[n] = s;
            n += 1;
        }
        for &s in &slots[..n] {
            self.release_pool_slot(s);
        }
        self.driver.send_slab.release(slab_idx);
    }

    /// Handle completion of a coalesced copy `sendmsg` of plaintext or TLS
    /// ciphertext (OpTag::SendMsgCoalesced).
    /// Mirrors `handle_send` but the backing is a slab entry holding several
    /// pool slots; partial sends advance the iovec array via `try_advance`.
    fn handle_send_msg_coalesced(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let slab_idx = ud.payload() as u16;

        // Guard against a stale CQE for an already-released slab entry.
        if !self.driver.send_slab.in_use(slab_idx) {
            return;
        }
        // Identity: the CQE outlived its connection slot — release resources
        // only (plain sendmsg, no notification coming; no resubmit either
        // way, the connection is gone).
        if !self.slab_identity_ok(conn_index, slab_idx) {
            // The entry may still name awaited sends lifted off the run's pool
            // slots. Take them so nothing can claim them twice,
            // and settle nothing: the operation belonged to the connection
            // this CQE outlived, whose teardown already recorded the abort,
            // and a driver result would override that abort (#381) with a
            // dead occupant's outcome.
            for (id, _len) in self.driver.send_slab.take_sends(slab_idx) {
                self.executor.forget_send(id);
            }
            self.release_coalesced(slab_idx);
            return;
        }

        if result > 0 {
            // Partial send: advance the iovec array and resubmit the remainder.
            if self
                .driver
                .send_slab
                .try_advance(slab_idx, result as u32)
                .is_some()
            {
                // A run can span several sends (#628). Those whose bytes are
                // all on the wire settle now with their own length; only the
                // rest wait for, or fail with, the remainder.
                for (id, len) in self.driver.send_slab.take_sent_sends(slab_idx) {
                    self.settle_send(id, Ok(len));
                }
                if self.close_submitted(conn_index) {
                    let settles = self.driver.send_slab.take_sends(slab_idx);
                    self.release_coalesced(slab_idx);
                    for (id, _logical_len) in settles {
                        self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    return;
                }
                self.wait_for_room(conn_index, ud, false);
                return;
            }
            // Fully sent.
            let total = self.driver.send_slab.total_len(slab_idx);
            // Take the sends this entry still carries before releasing it.
            let settles = self.driver.send_slab.take_sends(slab_idx);
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            self.release_coalesced(slab_idx);

            self.driver.submit_next_queued(conn_index);
            self.driver.defer_finalize_close(conn_index);
            // The carried logical (plaintext) length, not `acked` — see
            // `handle_send`'s success path.
            for (id, logical_len) in settles {
                self.settle_send(id, Ok(logical_len));
            }
            return;
        }

        // EAGAIN/EWOULDBLOCK: socket buffer full. Keep the slab entry (and its
        // data) alive.
        let errno = -result;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            if self.close_submitted(conn_index) {
                let settles = self.driver.send_slab.take_sends(slab_idx);
                self.release_coalesced(slab_idx);
                for (id, _logical_len) in settles {
                    self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                return;
            }
            self.wait_for_room(conn_index, ud, true);
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        // Real error: release everything, drain the connection's queue, and
        // end the connection, as `handle_send` does.
        let settles = self.driver.send_slab.take_sends(slab_idx);
        self.release_coalesced(slab_idx);
        self.driver.drain_conn_send_queue(conn_index);
        self.abort_connection(conn_index, Self::send_error(result));
        self.driver.defer_finalize_close(conn_index);
        for (id, _logical_len) in settles {
            self.settle_send(id, Err(Self::send_error(result)));
        }
    }

    /// Submit a plain `send` of the first non-empty unsent iovec of slab entry
    /// `slab_idx`, tagged `tag`, after its `SendMsgZc` returned `-ENOMEM`, or
    /// to continue an entry marked `plain_send`. A plain `send` pins no memory
    /// (#642). The tag's handler takes the result as a partial write of the
    /// entry.
    fn submit_slab_drain(&mut self, tag: OpTag, conn_index: u32, slab_idx: u16) -> io::Result<()> {
        // An entry drained here has bytes left to send.
        let (ptr, len) = self
            .driver
            .send_slab
            .first_unsent(slab_idx)
            .ok_or_else(|| io::Error::other("drain of an entry with no bytes left"))?;
        let ud = UserData::encode(tag, conn_index, slab_idx as u32);
        // SAFETY: the bytes belong to the slab entry, which is released only
        // by a completion handler, so they outlive this CQE.
        unsafe {
            self.driver
                .ring
                .submit_drain_send_fixed(conn_index, ptr, len, ud)
        }
    }

    /// Settle the awaited send slab entry `slab_idx` carries, if any, with
    /// the length it carries. Call before releasing the entry, which clears
    /// the id.
    fn settle_slab_ok(&mut self, slab_idx: u16) {
        for (id, len) in self.driver.send_slab.take_sends(slab_idx) {
            self.settle_send(id, Ok(len));
        }
    }

    /// Settle the awaited send slab entry `slab_idx` carries, if any, with
    /// `err`. Call before releasing the entry, which clears the id.
    fn settle_slab_err(&mut self, slab_idx: u16, err: io::Error) {
        for (id, _len) in self.driver.send_slab.take_sends(slab_idx) {
            let copy = match err.raw_os_error() {
                Some(errno) => io::Error::from_raw_os_error(errno),
                None => io::Error::new(err.kind(), err.to_string()),
            };
            self.settle_send(id, Err(copy));
        }
    }

    /// A slab retry dropped because its connection is closing or gone: the
    /// send the entry carries fails `ECANCELED` while the connection is still
    /// the one that submitted it (`identity_ok`), as in
    /// `drain_coalesced_retries`. A dead occupant's send is not settled:
    /// teardown recorded its abort, and a driver result would override it
    /// (#381). Call before releasing the entry.
    fn settle_abandoned_retry(&mut self, slab_idx: u16, identity_ok: bool) {
        for (id, _len) in self.driver.send_slab.take_sends(slab_idx) {
            if identity_ok {
                self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
            } else {
                self.executor.forget_send(id);
            }
        }
    }

    /// Arm the receives that `forward_recv_over_cap` held back, for reads still
    /// parked on connections it no longer applies to.
    fn resume_forward_recvs(&mut self) {
        if self.driver.forward_recv_held_conns.is_empty() {
            return;
        }
        for conn_index in std::mem::take(&mut self.driver.forward_recv_held_conns) {
            let ci = conn_index as usize;
            // Its slot was reset.
            if !self.driver.forward_recv_held[ci] {
                continue;
            }
            if self.driver.forward_recv_over_cap(conn_index) {
                self.driver.forward_recv_held_conns.push(conn_index);
                continue;
            }
            self.driver.forward_recv_held[ci] = false;
            if self.executor.recv_waiters[ci] && self.arm_direct_recv(conn_index, None) {
                self.executor.wake_recv(conn_index);
            }
        }
    }

    /// Give a direct or TLS connection back what a park cancelled or held off: its
    /// hangup poll, and a wake for a reader that parked during the drain,
    /// whose receive was refused then and is armed when it polls again. A
    /// hangup the poll missed while it was cancelled is still pending on the
    /// socket, so the new poll completes at once. The wake also goes to a
    /// connection whose read half ended during the drain, so its reader
    /// resolves.
    fn rearm_direct_after_park(&mut self, conn_index: u32) {
        let Some(c) = self.driver.connections.get(conn_index) else {
            return;
        };
        if matches!(c.lifecycle, Lifecycle::Open) && !c.recv_finished() && !c.hangup_poll_armed {
            self.driver.arm_hangup_poll(conn_index);
        }
        self.executor.wake_recv(conn_index);
    }

    fn handle_send_msg_zc(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let slab_idx = ud.payload() as u16;

        if !self.driver.send_slab.in_use(slab_idx) {
            return;
        }

        // Identity: the CQE outlived its connection slot. Resource-only
        // handling, mirroring the normal completion minus all per-connection
        // state: a notification CQE decrements and releases when done; a main
        // CQE with IORING_CQE_F_MORE still has its notification in flight
        // (count it, never resubmit the partial remainder — the connection is
        // gone); otherwise no notification is coming and the entry releases now.
        if !self.slab_identity_ok(conn_index, slab_idx) {
            if cqueue::notif(flags) {
                self.driver.send_slab.dec_pending_notifs(slab_idx);
            } else {
                // Main CQE: the entry is now final for this op — a stale
                // partial is never resubmitted. Mark awaiting only here
                // (not on notif CQEs, which for a resubmitted partial can
                // precede the remainder's main CQE), matching run_shutdown.
                // Its send settles nothing: teardown recorded the abort.
                for (id, _len) in self.driver.send_slab.take_sends(slab_idx) {
                    self.executor.forget_send(id);
                }
                if cqueue::more(flags) {
                    self.driver.send_slab.inc_pending_notifs(slab_idx);
                }
                self.driver.send_slab.mark_awaiting_notifications(slab_idx);
            }
            if self.driver.send_slab.should_release(slab_idx) {
                let ps = self.driver.send_slab.release(slab_idx);
                if ps != u16::MAX {
                    self.release_pool_slot(ps);
                }
            }
            return;
        }

        // Chain path.
        if self.driver.chain_table.is_active(conn_index) {
            if cqueue::notif(flags) {
                self.driver.send_slab.dec_pending_notifs(slab_idx);
                if self.driver.send_slab.should_release(slab_idx) {
                    let ps = self.driver.send_slab.release(slab_idx);
                    if ps != u16::MAX {
                        self.release_pool_slot(ps);
                    }
                }
                let event = self.driver.chain_table.on_notif_cqe(conn_index);
                if matches!(event, ChainEvent::Complete { .. }) {
                    self.fire_chain_complete(conn_index);
                }
                return;
            }
            if cqueue::more(flags) {
                // A notification follows whenever the main CQE carries
                // IORING_CQE_F_MORE -- on error and on a zero result too
                // (`io_sendrecv_fail`, `io_sendmsg_zc`), -ECANCELED included.
                // Hold the entry until it arrives.
                self.driver.send_slab.inc_pending_notifs(slab_idx);
                self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                self.driver.chain_table.inc_zc_notif(conn_index);
            } else {
                // No F_MORE: no notification is coming; release now.
                let ps = self.driver.send_slab.release(slab_idx);
                if ps != u16::MAX {
                    self.release_pool_slot(ps);
                }
            }
            let event = self.driver.chain_table.on_operation_cqe(conn_index, result);
            if matches!(event, ChainEvent::Complete { .. }) {
                self.fire_chain_complete(conn_index);
            }
            return;
        }

        if cqueue::notif(flags) {
            self.driver.send_slab.dec_pending_notifs(slab_idx);
            if self.driver.send_slab.should_release(slab_idx) {
                let pool_slot = self.driver.send_slab.release(slab_idx);
                if pool_slot != u16::MAX {
                    self.release_pool_slot(pool_slot);
                }
            }
            return;
        }

        // Count a pending notification exactly when the kernel says one is
        // coming: IORING_CQE_F_MORE on the main CQE. It is set on error and on
        // a zero result too (`io_sendrecv_fail`, `io_sendmsg_zc`), so keying on
        // `result > 0` released the entry early, and the late notification
        // then decremented whichever send reused it (#487). Without F_MORE no
        // notification follows, and counting one would leak the entry.
        if cqueue::more(flags) {
            self.driver.send_slab.inc_pending_notifs(slab_idx);
        }

        // EAGAIN/EWOULDBLOCK: socket buffer full. Keep the entry (and its
        // guards) alive.
        if (result == -libc::EAGAIN || result == -libc::EWOULDBLOCK)
            && !self.close_submitted(conn_index)
        {
            self.wait_for_room(conn_index, ud, true);
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        // ENOMEM from a `SendMsgZc` (not from its drain): the pages the send
        // would pin do not fit under `RLIMIT_MEMLOCK`, or, for a `plain_msg`
        // entry's plain `sendmsg`, an allocation failed. Nothing was sent. The
        // entry's bytes stay valid until it is released, so send them with
        // plain `send`s, which pin nothing, through the drain; the rest of the
        // entry is sent the same way rather than retried zero-copy (#642).
        if result == -libc::ENOMEM
            && ud.tag() == Some(OpTag::SendMsgZc)
            && !self.close_submitted(conn_index)
        {
            // A plain `sendmsg` (`plain_msg`) pins nothing, so its `-ENOMEM`
            // is not the memlock refusal the counter reports.
            if !self.driver.send_slab.plain_msg(slab_idx) {
                metrics::POOL.increment(metrics::pool::SEND_ZC_ENOMEM);
            }
            self.driver.send_slab.set_plain_send(slab_idx);
            if self
                .submit_slab_drain(OpTag::SendMsgZcDrain, conn_index, slab_idx)
                .is_err()
            {
                // SQ full: retry next tick (`drain_zc_retries`), as for a partial.
                let generation = self.driver.connections.generation(conn_index);
                self.driver
                    .pending_zc_retries
                    .push((conn_index, generation, slab_idx, 0));
            }
            return;
        }

        #[allow(clippy::collapsible_if)]
        if result > 0 {
            if self
                .driver
                .send_slab
                .try_advance(slab_idx, result as u32)
                .is_some()
            {
                // Never resubmit a partial past a submitted Close: mirror the
                // completion path's notification accounting minus the queue
                // bookkeeping (the notification for the sent prefix
                // is still in flight).
                if self.close_submitted(conn_index) {
                    self.settle_slab_err(slab_idx, io::Error::from_raw_os_error(libc::ECANCELED));
                    self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                    if self.driver.send_slab.should_release(slab_idx) {
                        let ps = self.driver.send_slab.release(slab_idx);
                        if ps != u16::MAX {
                            self.release_pool_slot(ps);
                        }
                    }
                    return;
                }
                self.wait_for_room(conn_index, ud, false);
                return;
            }
        }

        // Send complete (all bytes sent) or error (result <= 0). The awaited
        // send settles now; the entry, and the guards it holds, stay until
        // the notification lands.
        let errno = -result;
        if result > 0 {
            self.settle_slab_ok(slab_idx);
        } else if self.close_submitted(conn_index)
            && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK || errno == libc::ENOMEM)
        {
            // Backpressure, or `ENOMEM` from a zero-copy send (a memlock
            // refusal) or its drain, after the Close was submitted: the send
            // is not retried (the arms above skip it), so it settles as the
            // plain, coalesced and TLS handlers settle a send the close cut
            // short.
            self.settle_slab_err(slab_idx, io::Error::from_raw_os_error(libc::ECANCELED));
        } else {
            self.settle_slab_err(slab_idx, Self::send_error(result));
        }
        self.driver.send_slab.mark_awaiting_notifications(slab_idx);

        let total_len = self.driver.send_slab.total_len(slab_idx);
        let should_release = self.driver.send_slab.should_release(slab_idx);

        if should_release {
            let pool_slot = self.driver.send_slab.release(slab_idx);
            if pool_slot != u16::MAX {
                self.release_pool_slot(pool_slot);
            }
        }

        if result >= 0 {
            metrics::BYTES.add(metrics::bytes::SENT, total_len as u64);
            self.driver.submit_next_queued(conn_index);
        } else {
            self.driver.drain_conn_send_queue(conn_index);
            self.abort_connection(conn_index, Self::send_error(result));
        }
    }

    fn handle_connect(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();

        // The payload is the generation of the connection the Connect was
        // submitted for. The connect timeout's close is committed by the
        // end-of-iteration drain without waiting for this CQE, so it can
        // arrive after the slot was freed and reused and must not touch the
        // new occupant.
        let generation = match self.driver.connections.get(conn_index) {
            Some(conn) if conn.generation == ud.payload() => conn.generation,
            _ => return,
        };

        if result < 0 {
            let errno = -result;

            if errno == libc::ECANCELED {
                let timeout_armed = self
                    .driver
                    .connections
                    .get(conn_index)
                    .map(|c| c.connect_timeout_armed)
                    .unwrap_or(false);
                if !timeout_armed {
                    let err = io::Error::from_raw_os_error(errno);
                    self.executor.wake_connect(conn_index, Err(err));
                    // Don't call remove_connection here — it would clear io_results
                    // before the owning task can read the error via ConnectFuture.
                    // handle_close (triggered by close_connection) will clean up.
                    self.driver.close_connection(conn_index);
                    return;
                }
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.connect_timeout_armed = false;
                }
                return;
            }

            if self
                .driver
                .connections
                .get(conn_index)
                .map(|c| c.connect_timeout_armed)
                .unwrap_or(false)
            {
                let timeout_ud = UserData::encode(OpTag::Timeout, conn_index, generation);
                let _ = self
                    .driver
                    .ring
                    .submit_async_cancel(timeout_ud.raw(), conn_index);
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.connect_timeout_armed = false;
                }
            }

            if let Some(ref mut tls_table) = self.driver.tls_table {
                tls_table.remove(conn_index);
            }

            let err = io::Error::from_raw_os_error(errno);
            self.executor.wake_connect(conn_index, Err(err));
            // Don't call remove_connection here — it would clear io_results
            // before the owning task can read the error via ConnectFuture.
            // handle_close (triggered by close_connection) will clean up.
            self.driver.close_connection(conn_index);
            return;
        }

        // Connect succeeded.
        let timeout_was_armed = self
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.connect_timeout_armed)
            .unwrap_or(false);
        if timeout_was_armed {
            let still_connecting = self
                .driver
                .connections
                .get(conn_index)
                .map(|c| matches!(c.lifecycle, Lifecycle::Connecting))
                .unwrap_or(false);
            if !still_connecting {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.connect_timeout_armed = false;
                }
                return;
            }
            let timeout_ud = UserData::encode(OpTag::Timeout, conn_index, generation);
            let _ = self
                .driver
                .ring
                .submit_async_cancel(timeout_ud.raw(), conn_index);
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.connect_timeout_armed = false;
            }
        }

        self.driver.arrival[conn_index as usize].clear();

        // Orphaned-future guard: if the ConnectFuture was dropped while the
        // SQE was in flight (e.g. `select!` with a timeout that won), no
        // task will pick up this connection — and we don't have an
        // `on_accept` path for outbound connects. Letting the slot go
        // "established" would leak it until the peer closes (which may be
        // never). Close it now instead.
        if !self.executor.connect_waiters[conn_index as usize] {
            self.driver.accumulators.reset(conn_index);
            if let Some(ref mut tls_table) = self.driver.tls_table {
                tls_table.remove(conn_index);
            }
            self.driver.close_connection(conn_index);
            return;
        }

        self.driver.accumulators.reset(conn_index);
        self.driver.reset_send_state(conn_index);
        // A slot is recycled by generation, so without this a new occupant
        // would inherit the previous one's park offer — and its state.
        self.driver.park_offered[conn_index as usize] = false;
        // Cleared, never re-armed here: on the handover path the fd has left
        // this worker, and on the adopt path the caller arms recv itself.
        self.driver.set_park_drain(conn_index, None);
        self.driver.park_carry.remove(&conn_index);

        // TLS client path
        if let Some(ref mut tls_table) = self.driver.tls_table
            && tls_table.get_mut(conn_index).is_some()
        {
            let flushed = crate::tls::flush_tls_output(
                tls_table,
                &mut self.driver.send_copy_pool,
                conn_index,
                self.driver.connections.generation(conn_index),
                &mut self.driver.tls_out_scratch,
            );
            if !self.driver.tls_out_scratch.is_empty() {
                let mut sends = std::mem::take(&mut self.driver.tls_out_scratch);
                self.driver.queue_built_sends(conn_index, &mut sends);
                self.driver.tls_out_scratch = sends;
            }
            if !flushed {
                let err = std::io::Error::other("send pool exhausted during TLS flush");
                self.executor.wake_connect(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                return;
            }
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.mark_connected();
            }
            if self.arm_direct_recv(conn_index, None) {
                let err = std::io::Error::other("TLS receive could not be armed");
                self.executor.wake_connect(conn_index, Err(err));
                return;
            }
            self.driver.arm_hangup_poll(conn_index);
            let generation = self.driver.connections.generation(conn_index);
            let driver = &mut self.driver;
            driver
                .handshake_deadlines
                .arm(conn_index, generation, |i, g| {
                    crate::tls::handshake_deadline::in_progress(&driver.connections, i, g)
                });
            return;
        }

        // Plaintext path
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.established = true;
            cs.mark_connected();
        }
        // Counted in with `established`; `handle_close` counts out.
        metrics::CONNECTIONS_ACTIVE.increment();
        // The connection receives directly: its receive is armed by its first
        // parked read, and its hangup poll now.
        debug_assert!(
            self.driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.recv_direct),
            "a plaintext connect is marked direct when it is submitted"
        );
        self.driver.arm_hangup_poll(conn_index);

        self.executor.wake_connect(conn_index, Ok(()));
    }

    fn handle_timeout(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();

        if result != -libc::ETIME {
            return;
        }

        let conn = match self.driver.connections.get(conn_index) {
            Some(c) => c,
            None => return,
        };

        // Generation check (payload carries it): a stale -ETIME arriving
        // after close + slot reuse must not kill the new occupant's connect.
        if conn.generation != ud.payload() || !conn.connect_timeout_armed {
            return;
        }

        if !matches!(conn.lifecycle, Lifecycle::Connecting) {
            return;
        }

        let connect_ud = UserData::encode(OpTag::Connect, conn_index, ud.payload());
        let _ = self
            .driver
            .ring
            .submit_async_cancel(connect_ud.raw(), conn_index);

        if let Some(ref mut tls_table) = self.driver.tls_table {
            tls_table.remove(conn_index);
        }

        let err = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");
        self.executor.wake_connect(conn_index, Err(err));
        // Don't call remove_connection here — handle_close will clean up.
        self.driver.close_connection(conn_index);
    }

    fn handle_close(&mut self, ud: UserData) {
        let conn_index = ud.conn_index();

        // A forced close leaves a send waiting for room, and the poll's CQE can
        // arrive after this one, when its generation no longer matches.
        if let Some(raw) = self.driver.send_queues[conn_index as usize]
            .waiting_send
            .take()
        {
            self.fail_waiting_send(UserData(raw), -libc::ECANCELED);
        }

        let was_established = self
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.established)
            .unwrap_or(false);

        self.driver.release_tls_state(conn_index);

        if was_established {
            metrics::CONNECTIONS.increment(metrics::conn::CLOSED);
            metrics::CONNECTIONS_ACTIVE.decrement();
        }

        // Remove the async task (drops the future), with the driver state
        // installed so the futures it holds clean up as inside a poll.
        crate::runtime::io::with_driver_state(
            &mut self.driver,
            &mut self.executor,
            |_, executor| {
                executor.remove_connection(conn_index);
            },
        );
        // The future just dropped may have owned a half, whose `Drop` finds
        // the close already requested. Clear the claim flags before the slot
        // is reused, or the next occupant inherits them.
        self.driver.clear_conn_claims(conn_index);
        self.driver.accumulators.release(conn_index);
        self.driver.arrival[conn_index as usize].release();
        self.driver.connections.release(conn_index);
    }

    fn handle_tls_send(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let payload = ud.payload();
        let pool_slot = UserData::send_payload_slot(payload);

        // Guard against stale CQE for an already-released pool slot, matching
        // handle_send. Without this, try_advance on a released slot would
        // wrap in release mode and resubmit a wild length.
        if !self.driver.send_copy_pool.in_use(pool_slot) {
            return;
        }
        // Identity guard, matching handle_send: a TlsSend CQE that outlived
        // its connection slot must only release the slot it owns.
        if self.driver.connections.generation(conn_index) & 0xFFFF
            != u32::from(UserData::send_payload_gen(payload))
        {
            // Take-and-discard, as in `handle_send`'s identity guard.
            if let Some((id, _len)) = self.driver.send_copy_pool.take_send_id(pool_slot) {
                self.executor.forget_send(id);
            }
            self.release_pool_slot(pool_slot);
            return;
        }

        if result > 0
            && self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
                .is_some()
        {
            if self.close_submitted(conn_index) {
                // The send the slot carries, if any, fails with
                // `ECANCELED`: the close is already submitted.
                let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                self.release_pool_slot(pool_slot);
                if let Some((id, _logical_len)) = settles {
                    self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                return;
            }
            self.wait_for_room(conn_index, ud, false);
            return;
        }
        // Socket send buffer full: keep the slot and resubmit the same chunk
        // when there is room.
        if result < 0 {
            let errno = -result;
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                if self.close_submitted(conn_index) {
                    // The send the slot carries, if any, fails with
                    // `ECANCELED`: the close is already submitted.
                    let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                    self.release_pool_slot(pool_slot);
                    if let Some((id, _logical_len)) = settles {
                        self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    return;
                }
                self.wait_for_room(conn_index, ud, true);
                metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
                return;
            }
        }

        let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
        self.release_pool_slot(pool_slot);
        // By construction no id reaches this handler: an awaited TLS send
        // carries it on the *final* ciphertext chunk, which `encrypt_to_sends` tags
        // `OpTag::Send`, so the id-carrying slot completes in `handle_send`.
        // Taking it anyway is what keeps `SendCopyPool::release`'s tripwire
        // honest if that ever changes, and settling it is what keeps the
        // caller from hanging on the `drain_conn_send_queue` path below.
        if let Some((id, logical_len)) = settles {
            let settled = if result > 0 {
                Ok(logical_len)
            } else {
                Err(Self::send_error(result))
            };
            self.settle_send(id, settled);
        }

        // Intermediate TLS chunks are serialized through the per-connection
        // send queue, so a completion must pop the next queued send and let
        // a deferred close finalize, exactly like handle_send.
        if result >= 0 {
            self.driver.submit_next_queued(conn_index);
            self.driver.defer_finalize_close(conn_index);
            return;
        }

        // On error, fail the connection so the owning task unblocks: drain
        // the queued sibling chunks (their slots are released by the drain),
        // close, and tell the reader why.
        if result < 0 {
            self.driver.drain_conn_send_queue(conn_index);
            self.abort_connection(conn_index, Self::send_error(result));
        }
    }

    fn fire_chain_complete(&mut self, conn_index: u32) {
        let chain = match self.driver.chain_table.take(conn_index) {
            Some(c) => c,
            None => return,
        };

        let failure = chain.failure();
        let failed = failure.is_some();
        if failed {
            self.driver.drain_conn_send_queue(conn_index);
        } else {
            self.driver.submit_next_queued(conn_index);
        }

        // `send_chain` attached an id; `send_chain_nowait` did not.
        if let Some(id) = chain.send_id {
            let result = match failure {
                Some(error) => Err(error),
                None => Ok(chain.bytes_sent),
            };
            self.settle_send(id, result);
        }

        // The bytes of the chain and the queue behind it are gone, and a dropped
        // `send_chain` future or a nowait chain reports that to nobody but the
        // reader. Later sends must not reach the peer after that gap.
        if let Some(err) = chain.failure() {
            self.abort_connection(conn_index, err);
        }

        // A close_connection that arrived while the chain was active deferred
        // its Close on chain_drained. The chain state was just taken, so
        // register the close for the end-of-iteration drain.
        self.driver.defer_finalize_close(conn_index);
    }

    fn handle_timer(&mut self, ud: UserData, result: i32) {
        // Timer CQE: -ETIME means the timeout expired normally.
        // -ECANCELED means it was cancelled (e.g., SleepFuture dropped).
        if result != -libc::ETIME {
            // Cancelled or error — the SleepFuture::drop already released the slot.
            return;
        }

        let payload = ud.payload();
        let (slot, generation) = TimerSlotPool::decode_payload(payload);

        if let Some(waker_id) = self.executor.timer_pool.fire(slot, generation) {
            self.executor.wake_task(waker_id);
        }
    }

    fn handle_recv_msg_udp(&mut self, ud: UserData, result: i32, flags: u32) {
        let batch_recv_at = self.driver.udp_batch_recv_at;
        /// Parse the `name` region from a multishot `recvmsg` output into a
        /// `SocketAddr`. The region is a `sockaddr_in` or `sockaddr_in6`
        /// depending on `ss_family`; we copy it into an aligned
        /// `sockaddr_storage` before decoding.
        fn parse_recvmsg_name(name: &[u8]) -> Option<std::net::SocketAddr> {
            if name.len() < std::mem::size_of::<libc::sa_family_t>() {
                return None;
            }
            let max = std::mem::size_of::<libc::sockaddr_storage>();
            let copy_len = name.len().min(max);
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    &mut storage as *mut _ as *mut u8,
                    copy_len,
                );
            }
            sockaddr_to_socket_addr(&storage, copy_len as u32)
        }

        let udp_index = ud.conn_index();
        let idx = udp_index as usize;
        let has_more = cqueue::more(flags);

        if idx >= self.driver.udp_sockets.len() {
            return;
        }

        if result <= 0 {
            let errno = -result;
            if !has_more {
                self.driver.on_udp_recv_ended(udp_index, errno);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(b) => b,
            None => {
                if !has_more {
                    self.driver.rearm_udp_recvmsg(udp_index);
                }
                return;
            }
        };
        // The bid is checked out of the UDP ring; account it against occupancy so
        // `free()` and the double-replenish tripwire stay accurate. It is
        // replenished exactly once — queued below on a parse/drop, or when
        // the consumer reads the queued datagram.
        self.driver.udp_provided_bufs[idx].on_handout();

        // SAFETY: The buffer pointer belongs to the UDP provided buffer ring
        // and remains valid until we replenish the bid below.
        let buf_len = result as u32;
        let buf = {
            let udp_bufs = &self.driver.udp_provided_bufs[idx];
            let (buf_ptr, _) = udp_bufs.get_buffer(bid);
            unsafe { std::slice::from_raw_parts(buf_ptr, buf_len as usize) }
        };

        // Parse the recvmsg header out of the kernel buffer. If parsing fails
        // (or the datagram is truncated, or the queue is full) the bid is
        // queued for return at once. Otherwise the bid travels with the queue
        // entry and is replenished when the consumer reads it — that's what
        // makes the recv path zero-copy.
        let parse_result = crate::backend::uring::abi::RecvMsgOut::parse(
            buf,
            &self.driver.udp_sockets[idx].recv_msghdr,
        );

        let mut handed_to_queue = false;
        if let Ok(msg_out) = parse_result
            && !msg_out.is_name_data_truncated()
            && !msg_out.is_payload_truncated()
            && let Some(peer) = parse_recvmsg_name(msg_out.name_data())
        {
            metrics::UDP.increment(metrics::udp::DATAGRAMS_RECEIVED);
            if idx < self.executor.udp_recv_queues.len() {
                if self.executor.udp_recv_queues[idx].len() >= self.executor.udp_recv_queue_capacity
                {
                    // The handler isn't draining fast enough (or has
                    // exited). Drop on the floor so we don't grow without
                    // bound. UDP is lossy by definition; the metric flags
                    // it for operators.
                    metrics::UDP.increment(metrics::udp::DATAGRAMS_DROPPED);
                } else {
                    let payload = msg_out.payload_data();
                    // When GRO is on, the kernel may have coalesced several
                    // datagrams into this payload; the UDP_GRO cmsg carries
                    // the per-segment size used to split them back apart at
                    // drain time. `is_control_data_truncated()` (MSG_CTRUNC)
                    // means we lost the cmsg but the payload is intact —
                    // treat it as a single datagram (segment_size 0) rather
                    // than dropping it.
                    let segment_size = if self.driver.udp_sockets[idx].gro
                        && !msg_out.is_control_data_truncated()
                    {
                        crate::backend::udp_gro::parse_segment_size(msg_out.control_data())
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    // SAFETY: `payload` is a slice borrowed from the kernel
                    // buffer at `(buf_ptr, buf_len)`. The buffer remains valid
                    // until `bid` is pushed to `udp_pending_replenish` (which
                    // happens when the consumer reads the queue entry).
                    let payload_ptr = payload.as_ptr();
                    let payload_len = payload.len() as u32;
                    self.executor.udp_recv_queues[idx].push_back(
                        crate::runtime::PendingUdpDatagram {
                            peer,
                            buf: crate::runtime::PendingUdpBuf::Kernel {
                                bid,
                                ptr: payload_ptr,
                                payload_len,
                            },
                            recv_at: batch_recv_at,
                            segment_size,
                            consumed: 0,
                        },
                    );
                    handed_to_queue = true;
                    self.executor.wake_udp_recv(udp_index);
                }
            }
        }

        if !handed_to_queue {
            self.driver.udp_pending_replenish.push((udp_index, bid));
        }

        if !has_more {
            self.driver.rearm_udp_recvmsg(udp_index);
        }
    }

    fn handle_send_msg_udp(&mut self, ud: UserData, result: i32) {
        let udp_index = ud.conn_index();
        let (slot_idx, pool_slot) =
            crate::backend::uring::driver::decode_udp_send_payload(ud.payload());
        let idx = udp_index as usize;

        self.release_pool_slot(pool_slot);

        let mut slot_returned = false;
        if idx < self.driver.udp_sockets.len() {
            let sock = &mut self.driver.udp_sockets[idx];
            if (slot_idx as usize) < sock.send_slots.len() {
                sock.send_freelist.push(slot_idx);
                slot_returned = true;
            }
        }

        // A freed slot may unblock a task awaiting `UdpSendHalf::send_ready`.
        if slot_returned {
            self.executor.wake_udp_send_ready(udp_index);
        }

        if result < 0 {
            metrics::UDP.increment(metrics::udp::SEND_ERRORS);
        }
    }

    /// Handle a CQE for a `Send` issued on a connected UDP socket (the
    /// `RecvMsgUdp` fast-path counterpart). Same bookkeeping as
    /// `handle_send_msg_udp`: release the pool slot and per-socket send
    /// slot, wake any task awaiting `send_ready`.
    fn handle_send_udp(&mut self, ud: UserData, result: i32) {
        // Send completion bookkeeping is identical to the sendmsg path —
        // only the SQE opcode differed. Delegate.
        self.handle_send_msg_udp(ud, result);
    }

    /// Handle a multishot `Recv` CQE for a connected UDP socket. The buffer
    /// contains only the payload (no `io_uring_recvmsg_out` header / sockaddr,
    /// since we used `IORING_OP_RECV` rather than `RECVMSG`). The peer is
    /// known from `UdpSocketState::connected_peer`.
    fn handle_recv_udp(&mut self, ud: UserData, result: i32, flags: u32) {
        let batch_recv_at = self.driver.udp_batch_recv_at;
        let udp_index = ud.conn_index();
        let idx = udp_index as usize;
        let has_more = cqueue::more(flags);

        if idx >= self.driver.udp_sockets.len() {
            return;
        }

        if result <= 0 {
            // Defensive: a zero-length datagram (or an error CQE on some
            // kernels) can still carry a selected buffer — failing to
            // replenish its bid shrinks the UDP ring by one per occurrence
            // until ENOBUFS (a remote peer sending empty datagrams could
            // drain the ring entirely).
            if let Some(bid) = cqueue::buffer_select(flags) {
                // Count the handout so the replenish's occupancy decrement is
                // balanced.
                self.driver.udp_provided_bufs[idx].on_handout();
                self.driver.udp_pending_replenish.push((udp_index, bid));
            }
            if !has_more {
                self.driver.on_udp_recv_ended(udp_index, -result);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(b) => b,
            None => {
                if !has_more {
                    self.driver.rearm_udp_recvmsg(udp_index);
                }
                return;
            }
        };
        // The bid is checked out of the UDP ring; account it against occupancy so
        // `free()` and the double-replenish tripwire stay accurate. It is
        // replenished exactly once — queued below on a parse/drop, or when
        // the consumer reads the queued datagram.
        self.driver.udp_provided_bufs[idx].on_handout();

        let payload_len = result as u32;
        let buf_ptr = {
            let udp_bufs = &self.driver.udp_provided_bufs[idx];
            let (p, _) = udp_bufs.get_buffer(bid);
            p
        };

        metrics::UDP.increment(metrics::udp::DATAGRAMS_RECEIVED);

        let mut handed_to_queue = false;
        if let Some(peer) = self.driver.udp_sockets[idx].connected_peer
            && idx < self.executor.udp_recv_queues.len()
        {
            if self.executor.udp_recv_queues[idx].len() >= self.executor.udp_recv_queue_capacity {
                metrics::UDP.increment(metrics::udp::DATAGRAMS_DROPPED);
            } else {
                self.executor.udp_recv_queues[idx].push_back(crate::runtime::PendingUdpDatagram {
                    peer,
                    buf: crate::runtime::PendingUdpBuf::Kernel {
                        bid,
                        ptr: buf_ptr,
                        payload_len,
                    },
                    recv_at: batch_recv_at,
                    // Connected sockets use the plain `recv` path with no
                    // msghdr/control region, so GRO never applies here.
                    segment_size: 0,
                    consumed: 0,
                });
                handed_to_queue = true;
                self.executor.wake_udp_recv(udp_index);
            }
        }

        if !handed_to_queue {
            self.driver.udp_pending_replenish.push((udp_index, bid));
        }

        if !has_more {
            self.driver.rearm_udp_recvmsg(udp_index);
        }
    }

    fn handle_nvme_cmd(&mut self, ud: UserData, result: i32) {
        let slab_idx = ud.payload() as u16;

        let nvme_cmd_slab = match self.driver.nvme_cmd_slab {
            Some(ref mut s) => s,
            None => return,
        };

        if !nvme_cmd_slab.in_use(slab_idx) {
            return;
        }

        let device_index = nvme_cmd_slab.release(slab_idx);

        // Decrement in-flight count, and finish a close that waited for it.
        if let Some(ref mut devices) = self.driver.nvme_devices
            && let Some(dev) = devices.get_mut(device_index)
        {
            dev.in_flight = dev.in_flight.saturating_sub(1);
            if dev.closing && dev.in_flight == 0 {
                let _ = self
                    .driver
                    .ring
                    .register_files_update(dev.fd_index, &[-1i32]);
                devices.release(device_index);
            }
        }

        // NVMe passthrough puts the device's status word (positive, e.g.
        // 0x281 for a media error) in cqe->res when the device fails the
        // command; 0 is success and negative is a transport errno. The word
        // travels to the future as a negative result at or below -0x1_0000,
        // past every errno.
        let result = crate::nvme::status_result(result);

        // Wake the async task waiting for this NVMe completion.
        self.executor.wake_disk_io(ud.payload(), result);
    }

    fn handle_direct_io(&mut self, ud: UserData, result: i32) {
        let slab_idx = ud.payload() as u16;

        let cmd_slab = match self.driver.direct_io_cmd_slab {
            Some(ref mut s) => s,
            None => return,
        };

        if !cmd_slab.in_use(slab_idx) {
            return;
        }

        let (file_index, _op) = cmd_slab.release(slab_idx);

        // Decrement in-flight count, and finish a close that waited for it.
        if let Some(ref mut files) = self.driver.direct_io_files
            && let Some(f) = files.get_mut(file_index)
        {
            f.in_flight = f.in_flight.saturating_sub(1);
            if f.closing && f.in_flight == 0 {
                let _ = self.driver.ring.register_files_update(f.fd_index, &[-1i32]);
                files.release(file_index);
            }
        }

        // Wake the async task waiting for this Direct I/O completion.
        self.executor.wake_disk_io(ud.payload(), result);
    }

    fn handle_fs(&mut self, ud: UserData, result: i32) {
        let slab_idx = ud.payload() as u16;
        let file_index = ud.conn_index() as u16;

        let cmd_slab = match self.driver.fs_cmd_slab {
            Some(ref mut s) => s,
            None => return,
        };

        if !cmd_slab.in_use(slab_idx) {
            return;
        }

        let op = cmd_slab.get(slab_idx).map(|e| e.op);

        // For Statx ops, convert the statx buffer to Metadata before releasing the slab.
        if op == Some(crate::fs::FsOp::Statx)
            && result >= 0
            && let Some(entry) = cmd_slab.get(slab_idx)
            && let Some(ref statx_buf) = entry.statx_buf
        {
            let metadata = crate::fs::Metadata::from_statx(statx_buf);
            // Keyed by the full disk-I/O key (StatFuture holds the same),
            // not the raw slab index.
            self.executor.fs_stat_results.insert(ud.payload(), metadata);
        }

        // An open whose `OpenFuture` was dropped: nothing holds a handle to
        // the file, so close it, free the slot and deliver nothing.
        if op == Some(crate::fs::FsOp::Open)
            && self.executor.abandoned_fs_opens.remove(&ud.payload())
        {
            if result >= 0 {
                let fd_index = self.driver.fs_fd_base + file_index as u32;
                let _ = self.driver.ring.register_files_update(fd_index, &[-1i32]);
            }
            if let Some(ref mut files) = self.driver.fs_files {
                files.release(file_index);
            }
            cmd_slab.release(slab_idx);
            return;
        }

        // For Open ops, handle success/failure of the file slot.
        if op == Some(crate::fs::FsOp::Open) && result < 0 {
            // Open failed — release the pre-allocated file slot.
            if let Some(ref mut files) = self.driver.fs_files {
                files.release(file_index);
            }
        }

        let (released_file_index, released_op) = cmd_slab.release(slab_idx);

        // Decrement in-flight count for file-bound ops.
        match released_op {
            crate::fs::FsOp::Read | crate::fs::FsOp::Write | crate::fs::FsOp::Fsync => {
                if let Some(ref mut files) = self.driver.fs_files
                    && let Some(f) = files.get_mut(released_file_index)
                {
                    f.in_flight = f.in_flight.saturating_sub(1);
                    // A close deferred by `fs_close` finishes with the last
                    // operation on the file (#859).
                    if f.closing && f.in_flight == 0 {
                        let _ = self.driver.ring.register_files_update(f.fd_index, &[-1i32]);
                        files.release(released_file_index);
                    }
                }
            }
            _ => {}
        }

        // Wake the async task waiting for this completion.
        self.executor.wake_disk_io(ud.payload(), result);
    }

    fn handle_pidfd_poll(&mut self, ud: UserData, result: i32) {
        let seq = ud.payload();
        self.executor.wake_pidfd(seq, result);
    }

    /// Spawn an async task for a newly accepted connection.
    ///
    /// The handler's `on_accept` future *constructor* (everything before
    /// the first `.await`, including any async-block initializer code) runs
    /// synchronously inside this method. `poll_ready_tasks` catches panics
    /// from the future's `poll`, but a panic during construction would
    /// otherwise tear down the worker thread along with every other
    /// connection on it. We wrap construction in `catch_unwind` and close
    /// the connection on panic instead.
    fn spawn_accept_task(&mut self, conn_index: u32) {
        let generation = self.driver.connections.generation(conn_index);
        let conn_ctx = ConnCtx::new(conn_index, generation);
        // The handler owns the read side for the connection's lifetime; record
        // the claim here, since `Connection::for_accept` cannot reach the
        // driver from outside a task poll.
        self.driver.recv_half_taken[conn_index as usize] = true;
        self.driver.send_half_taken[conn_index as usize] = true;
        let conn = crate::Connection::for_accept(conn_ctx);
        // SAFETY: `AssertUnwindSafe` is required because `self.handler` is
        // not `UnwindSafe`. A panic here closes the connection and goes to
        // `panic_reporter`, which decides under the policy whether the worker
        // keeps running.
        // An adopted connection gets `on_adopt`, not `on_accept`: it is not a
        // new connection, and the handler may have state to restore.
        let adopting = self.driver.adopt_pending.remove(&conn_index);
        let site = if adopting.is_some() {
            "handler on_adopt"
        } else {
            "handler on_accept"
        };
        let future_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match adopting {
                #[cfg(any(feature = "unstable-accept", test))]
                Some(state) => self.handler.on_adopt(conn, state),
                #[cfg(not(any(feature = "unstable-accept", test)))]
                Some(_) => unreachable!("park runs only in merged accept mode"),
                None => Box::pin(self.handler.on_accept(conn))
                    as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>,
            }));
        let future = match future_result {
            Ok(f) => f,
            Err(payload) => {
                // Handler panicked during async-block construction.
                // Close the connection and skip task setup.
                self.driver.close_connection(conn_index);
                self.driver.panic_reporter.report(site, &*payload);
                return;
            }
        };
        self.executor.owner_task[conn_index as usize] = Some(conn_index);
        self.executor.task_slab.spawn(conn_index, future);
        self.executor.ready_queue.push_back(conn_index);
    }

    /// Test-only: expose dispatch_cqe for synthetic CQE testing.
    #[cfg(test)]
    pub(crate) fn test_dispatch_cqe(&mut self, user_data_raw: u64, result: i32, flags: u32) {
        self.dispatch_cqe(user_data_raw, result, flags);
    }

    /// Test-only: submit a NOP with injected result through the real io_uring
    /// pipeline, then drain and dispatch all completions.
    ///
    /// This exercises the full submit_and_wait → drain_completions → dispatch_cqe
    /// path, unlike test_dispatch_cqe which bypasses SQE submission.
    ///
    /// Below Linux 6.10, which lacks `IORING_NOP_INJECT_RESULT`, the completion
    /// starts at `reap` instead.
    #[cfg(test)]
    pub(crate) fn inject_and_dispatch(&mut self, user_data_raw: u64, result: i32) {
        self.driver
            .ring
            .submit_nop_inject(user_data_raw, result)
            .expect("submit_nop_inject failed");
        self.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        self.drain_completions();
    }

    /// Retry ZC send resubmissions that failed on a previous tick (SQ full).
    fn drain_zc_retries(&mut self) {
        if self.driver.pending_zc_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_zc_retries,
            &mut self.driver.zc_retry_scratch,
        );
        for idx in 0..self.driver.zc_retry_scratch.len() {
            let (conn_index, generation, slab_idx, retries) = self.driver.zc_retry_scratch[idx];
            if !self.driver.send_slab.in_use(slab_idx) {
                continue; // slab was released in the meantime
            }
            // Connection closed or reused (or its Close already submitted —
            // no new SQEs may be pushed for it) — release the slab and
            // nothing else: the slot may already belong to a new connection.
            let identity_ok = self.driver.connections.get(conn_index).is_some()
                && self.driver.connections.generation(conn_index) == generation;
            if !identity_ok || self.close_submitted(conn_index) {
                self.settle_abandoned_retry(slab_idx, identity_ok);
                self.release_zc_slab(slab_idx);
                continue;
            }
            if retries >= 2 {
                // Give up: bytes of this send are already missing from the
                // stream, so fail the send and close rather than leaving
                // in_flight stuck and the connection wedged open.
                self.settle_slab_err(
                    slab_idx,
                    io::Error::other("max retries during zc send resubmit"),
                );
                self.release_zc_slab(slab_idx);
                self.driver.drain_conn_send_queue(conn_index);
                self.abort_connection(
                    conn_index,
                    io::Error::other("max retries during zc send resubmit"),
                );
                continue;
            }
            let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
            let submitted = if self.driver.send_slab.plain_send(slab_idx) {
                self.submit_slab_drain(OpTag::SendMsgZcDrain, conn_index, slab_idx)
            } else if self.driver.send_slab.plain_msg(slab_idx) {
                self.driver
                    .ring
                    .submit_send_msg(conn_index, msg_ptr, slab_idx)
            } else {
                self.driver
                    .ring
                    .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
            };
            if submitted.is_err() {
                self.driver.pending_zc_retries.push((
                    conn_index,
                    generation,
                    slab_idx,
                    retries + 1,
                ));
            }
        }
        self.driver.zc_retry_scratch.clear();
    }

    /// Release a ZC slab entry (and its paired pool slot) that will never
    /// get a completion CQE because its resubmission was abandoned.
    fn release_zc_slab(&mut self, slab_idx: u16) {
        self.driver.send_slab.mark_awaiting_notifications(slab_idx);
        if self.driver.send_slab.should_release(slab_idx) {
            let pool_slot = self.driver.send_slab.release(slab_idx);
            if pool_slot != u16::MAX {
                self.release_pool_slot(pool_slot);
            }
        }
    }

    /// Retry coalesced send resubmissions that failed (SQ was full).
    fn drain_coalesced_retries(&mut self) {
        if self.driver.pending_coalesced_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_coalesced_retries,
            &mut self.driver.coalesced_retry_scratch,
        );
        for idx in 0..self.driver.coalesced_retry_scratch.len() {
            let (conn_index, generation, slab_idx, retries) =
                self.driver.coalesced_retry_scratch[idx];
            if !self.driver.send_slab.in_use(slab_idx) {
                continue; // slab released meanwhile
            }
            // Connection closed or reused (or its Close already submitted) —
            // release the slab only. Touching the send queue here would
            // drain a *new* connection's sends.
            let identity_ok = self.driver.connections.get(conn_index).is_some()
                && self.driver.connections.generation(conn_index) == generation;
            if !identity_ok || self.close_submitted(conn_index) {
                // Take the lifted id either way — the slab release clears it
                // silently — but settle it only when the connection is still
                // the one that submitted it (the `close_submitted` reason).
                // The `!identity_ok` reason is a dead occupant's entry, whose
                // operation teardown already aborted; a driver result would
                // override that abort (#381).
                self.settle_abandoned_retry(slab_idx, identity_ok);
                self.release_coalesced(slab_idx);
                continue;
            }
            if retries >= 2 {
                // Give up: fail the send and close so the connection isn't
                // left open with a hole in its byte stream.
                let settles = self.driver.send_slab.take_sends(slab_idx);
                self.release_coalesced(slab_idx);
                self.driver.drain_conn_send_queue(conn_index);
                for (id, _logical_len) in settles {
                    self.settle_send(
                        id,
                        Err(io::Error::other(
                            "max retries during coalesced send resubmit",
                        )),
                    );
                }
                self.abort_connection(
                    conn_index,
                    io::Error::other("max retries during coalesced send resubmit"),
                );
                continue;
            }
            let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
            if self
                .driver
                .ring
                .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
                .is_err()
            {
                self.driver.pending_coalesced_retries.push((
                    conn_index,
                    generation,
                    slab_idx,
                    retries + 1,
                ));
            }
        }
        self.driver.coalesced_retry_scratch.clear();
    }

    /// Retry copy send resubmissions that failed (SQ was full).
    fn drain_copy_retries(&mut self) {
        if self.driver.pending_copy_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_copy_retries,
            &mut self.driver.copy_retry_scratch,
        );
        for idx in 0..self.driver.copy_retry_scratch.len() {
            let (conn_index, generation, pool_slot, retries, op) =
                self.driver.copy_retry_scratch[idx];
            if !self.driver.send_copy_pool.in_use(pool_slot) {
                continue;
            }
            // Connection closed or reused (or its Close already submitted) —
            // release the slot only.
            let identity_ok = self.driver.connections.get(conn_index).is_some()
                && self.driver.connections.generation(conn_index) == generation;
            if !identity_ok || self.close_submitted(conn_index) {
                // Take before releasing (`release` debug-asserts rather than
                // drop a live id), but settle only when the connection is
                // still the one that submitted this slot. The `!identity_ok`
                // reason is a dead occupant's slot: teardown already recorded
                // that operation's abort, and a driver result would override
                // it (#381) on behalf of a connection that is gone.
                let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                self.release_pool_slot(pool_slot);
                if identity_ok && let Some((id, _logical_len)) = settles {
                    self.settle_send(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                continue;
            }
            if retries >= 2 {
                // Give up: fail the send and close so the connection isn't
                // left open with a hole in its byte stream.
                let settles = self.driver.send_copy_pool.take_send_id(pool_slot);
                self.release_pool_slot(pool_slot);
                self.driver.drain_conn_send_queue(conn_index);
                if let Some((id, _logical_len)) = settles {
                    self.settle_send(
                        id,
                        Err(io::Error::other("max retries during send resubmit")),
                    );
                }
                self.abort_connection(
                    conn_index,
                    io::Error::other("max retries during send resubmit"),
                );
                continue;
            }
            let (ptr, remaining) = self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
            // Resubmit with the entry's original OpTag. Choosing by
            // tls_table membership here re-tagged the *final* chunk of a TLS
            // send (OpTag::Send, so `handle_send` settles its id) as TlsSend,
            // which leaves the send unsettled.
            let result = if matches!(op, OpTag::TlsSend) {
                self.driver
                    .ring
                    .submit_tls_send(conn_index, generation, ptr, remaining, pool_slot)
            } else {
                self.driver
                    .ring
                    .submit_send_copied(conn_index, generation, ptr, remaining, pool_slot)
            };
            if result.is_err() {
                self.driver.pending_copy_retries.push((
                    conn_index,
                    generation,
                    pool_slot,
                    retries + 1,
                    op,
                ));
            }
        }
        self.driver.copy_retry_scratch.clear();
    }

    /// Re-push queued sends whose head could not be submitted (SQ full).
    ///
    /// The entry waited at its queue head with `in_flight = true`, so the
    /// connection's stream order is intact and a requested close stays
    /// deferred behind it. Two failed attempts convert persistent starvation
    /// into a terminal connection error — release the queue, fail the send
    /// waiter, wake the reader, close — mirroring `drain_copy_retries`, so a
    /// connection is never left open with a parked send nobody will push.
    fn drain_send_retries(&mut self) {
        if self.driver.pending_send_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_send_retries,
            &mut self.driver.send_retry_scratch,
        );
        for idx in 0..self.driver.send_retry_scratch.len() {
            let (conn_index, generation, attempts) = self.driver.send_retry_scratch[idx];
            // Connection closed or reused, or its Close already submitted:
            // the close path released the queue, so there is nothing to push.
            if self.driver.connections.get(conn_index).is_none()
                || self.driver.connections.generation(conn_index) != generation
                || self.close_submitted(conn_index)
            {
                continue;
            }
            // Nothing parked any more — the queue was released, or another
            // path (a completed send chain) already pushed the head: the
            // entry is stale, and pushing now would put a second SQE on the
            // stream alongside the one in flight.
            let state = &self.driver.send_queues[conn_index as usize];
            if !state.parked || state.queue.is_empty() {
                continue;
            }
            if attempts >= 2 {
                // Give up: release the parked entry and everything behind it,
                // fail the send and close so the connection isn't left open
                // with a hole in its byte stream.
                //
                // No send is settled here because none is in hand:
                // the parked entry is still *queued*, so
                // `drain_conn_send_queue` -> `release_queued_sends` takes its
                // id off the pool slot and fails it (as `ConnectionAborted`)
                // through `Driver::settled_sends`, which the run
                // loop drains.
                self.driver.drain_conn_send_queue(conn_index);
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                continue;
            }
            // Re-parks itself on `pending_send_retries` with `attempts + 1`
            // if the push fails again; pops the head and returns true if it
            // goes through.
            self.driver
                .submit_next_queued_inner(conn_index, attempts + 1);
        }
        self.driver.send_retry_scratch.clear();
    }

    /// Retry Close submissions that failed (SQ was full). Entries are never
    /// dropped: the connection slot cannot be reused until the Close CQE
    /// runs handle_close, so giving up would leak the fd and the slot
    /// permanently. Backoff: attempt only every 4th tick.
    fn drain_close_retries(&mut self) {
        if self.driver.pending_close_retries.is_empty() {
            return;
        }
        // Backoff: attempt only every 4th tick. On the other three there is
        // nothing to do at all — the previous form drained the whole queue and
        // pushed every entry straight back unchanged, which is pure work.
        if !self.driver.tick_count.is_multiple_of(4) {
            return;
        }
        let retries = std::mem::take(&mut self.driver.pending_close_retries);
        for (conn_index, retry) in retries {
            if self.driver.submit_committed_close(conn_index).is_err() {
                self.driver
                    .pending_close_retries
                    .push((conn_index, retry.saturating_add(1)));
            }
        }
    }

    /// Push the `Shutdown` SQEs the ring refused. The write half already
    /// reads `Shutdown` and `shutdown_inflight` holds the Close, so an entry
    /// is never dropped while its connection lives; one whose slot has been
    /// released (its generation changed) is dropped, since nothing waits on
    /// the flag for a released slot and `reset_send_state` clears it at
    /// reactivation. Same backoff as `drain_close_retries`: every 4th tick.
    fn drain_shutdown_retries(&mut self) {
        if self.driver.pending_shutdown_retries.is_empty() {
            return;
        }
        if !self.driver.tick_count.is_multiple_of(4) {
            return;
        }
        let retries = std::mem::take(&mut self.driver.pending_shutdown_retries);
        for (conn_index, generation) in retries {
            if self.driver.connections.generation(conn_index) != generation {
                continue;
            }
            if self
                .driver
                .ring
                .submit_shutdown(conn_index, generation)
                .is_err()
            {
                self.driver
                    .pending_shutdown_retries
                    .push((conn_index, generation));
            }
        }
    }

    /// Arm the `SendPollOut`s the SQ had no room for. An entry is stale if its
    /// connection went, or if the wait ended without it.
    fn drain_send_pollout_retries(&mut self) {
        for (conn_index, generation, multi) in
            std::mem::take(&mut self.driver.pending_send_pollout_retries)
        {
            if self.driver.connections.generation(conn_index) != generation {
                continue;
            }
            let state = &mut self.driver.send_queues[conn_index as usize];
            if state.send_poll != SendPoll::Pending {
                continue;
            }
            if state.waiting_send.is_none() || state.close_submitted {
                state.send_poll = SendPoll::None;
                continue;
            }
            self.arm_send_poll(conn_index, multi);
        }
    }

    /// Test-only: inject multiple NOPs and dispatch them all in one batch.
    /// This tests batch CQE processing where one handler's side effects
    /// affect subsequent handlers in the same drain_completions() call.
    #[cfg(test)]
    /// Test-only: submit a linked chain of NOP injects and dispatch.
    /// The first N-1 SQEs have IO_LINK set; the last does not.
    /// From Linux 6.10 this tests `IOSQE_IO_LINK` error propagation through
    /// the kernel; below that it uses `inject`'s model of it.
    #[cfg(test)]
    pub(crate) fn inject_linked_chain_and_dispatch(&mut self, cqes: &[(u64, i32)]) {
        let last = cqes.len() - 1;
        for (i, &(user_data_raw, result)) in cqes.iter().enumerate() {
            if i < last {
                self.driver
                    .ring
                    .submit_nop_inject_linked(user_data_raw, result)
                    .expect("submit_nop_inject_linked failed");
            } else {
                self.driver
                    .ring
                    .submit_nop_inject(user_data_raw, result)
                    .expect("submit_nop_inject failed");
            }
        }
        self.driver
            .ring
            .submit_and_wait(cqes.len() as u32)
            .expect("submit_and_wait failed");
        self.drain_completions();
    }

    /// Test-only: inject multiple NOPs and dispatch them all in one batch.
    #[cfg(test)]
    pub(crate) fn inject_batch_and_dispatch(&mut self, cqes: &[(u64, i32)]) {
        for &(user_data_raw, result) in cqes {
            self.driver
                .ring
                .submit_nop_inject(user_data_raw, result)
                .expect("submit_nop_inject failed");
        }
        self.driver
            .ring
            .submit_and_wait(cqes.len() as u32)
            .expect("submit_and_wait failed");
        self.drain_completions();
    }

    /// Check close_notify deadlines on the armed set. If a connection
    /// has `close_pending` and the `close_notify_deadline` has elapsed,
    /// force-close it with `force_finalize_close`.
    ///
    /// Iterates only the indices in `driver.close_notify_armed`, not
    /// every entry in `driver.send_queues`. For non-TLS workloads the
    /// armed set is permanently empty and this method is a single
    /// `Vec::is_empty()` check; for TLS workloads the set is bounded
    /// by the number of concurrent in-flight TLS graceful shutdowns
    /// (typically 0 or single digits). A walk over every slot here cost
    /// about 25 % of worker CPU in the redis bench at 1 client × 64 B,
    /// because this runs on every iteration.
    fn check_close_notify_deadlines(&mut self) {
        if self.driver.close_notify_armed.is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        // Collect timed-out indices first to avoid borrow conflict
        // with `try_finalize_close`, which mutates `close_notify_armed`.
        let mut timed_out: Vec<u32> = Vec::new();
        for &idx in self.driver.close_notify_armed.iter() {
            let state = &self.driver.send_queues[idx as usize];
            if state.close_pending
                && let Some(deadline) = state.close_notify_deadline
                && now >= deadline
            {
                timed_out.push(idx);
            }
        }
        for idx in timed_out {
            // try_finalize_close would wait forever here — the deadline fired
            // precisely because the drain is stuck (peer stopped reading).
            self.driver.force_finalize_close(idx);
        }
    }

    /// Close every TLS connection whose handshake has not completed by its
    /// deadline (`ConfigBuilder::tls_handshake_timeout`). An outbound connect
    /// resolves `TimedOut`; an inbound connection has no task to report to.
    fn check_handshake_deadlines(&mut self) {
        if self.driver.handshake_deadlines.is_empty() {
            return;
        }
        let now = std::time::Instant::now();
        loop {
            let driver = &mut self.driver;
            let Some(conn_index) = driver.handshake_deadlines.pop_expired(now, |i, g| {
                crate::tls::handshake_deadline::in_progress(&driver.connections, i, g)
            }) else {
                return;
            };
            metrics::CONNECTIONS.increment(metrics::conn::TLS_HANDSHAKE_TIMEOUT);
            self.executor
                .wake_connect(conn_index, Err(crate::tls::handshake_deadline::timed_out()));
            self.driver.close_connection(conn_index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigBuilder;
    use crate::completion::{OpTag, UserData};
    use crate::config::Config;
    use crate::runtime::io::ConnCtx;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    /// Minimal handler for testing — does nothing.
    use std::sync::atomic::{AtomicU32, Ordering};

    struct NoopHandler;

    // Counts `on_adopt` calls, and records what state arrived with them.
    // Nothing else proves an adopted connection takes the adopt branch rather
    // than being handed to `on_accept` like a fresh one — the driver state
    // looks identical either way.
    //
    // Thread-local, not global: more than one test drains an adopt through
    // `NoopHandler`, and the harness runs them concurrently in one process. As
    // globals these raced — a second test's adopt could land between the
    // first's drain and its assertion, so the count read 2 instead of 1 and the
    // state read `None` instead of what was parked. Measured on real io_uring,
    // the two tests looped 150 times: 125 failures as globals, 0 as
    // thread-locals. Each test gets its own thread, and `on_adopt` increments
    // synchronously on the caller's, so this isolates them without a lock
    // anyone has to remember to take.
    //
    // Plain comments, not doc comments: `thread_local!` does not carry them
    // into its expansion, so `///` here is an `unused_doc_comments` error under
    // `-D warnings`.
    thread_local! {
        static ADOPTS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
        static ADOPTED_STATE: std::cell::RefCell<Option<String>> =
            const { std::cell::RefCell::new(None) };
    }

    impl AsyncEventHandler for NoopHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: crate::Connection) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn on_adopt(
            &self,
            _conn: crate::Connection,
            state: Option<crate::park::ParkState>,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + 'static>> {
            ADOPTS.with(|n| n.set(n.get() + 1));
            ADOPTED_STATE.with(|c| {
                *c.borrow_mut() = state.and_then(|s| s.take::<String>());
            });
            Box::pin(async {})
        }
        fn create_for_worker(_id: usize) -> Self {
            NoopHandler
        }
    }

    fn test_config_builder() -> ConfigBuilder {
        ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .sq_entries(32)
            .max_connections(16)
            .send_pool(16, 16384)
            .send_slab_slots(8)
            .fs(crate::fs::FsConfig {
                max_files: 2,
                max_commands_in_flight: 4,
            })
    }

    fn test_config() -> Config {
        test_config_builder().build().expect("valid config")
    }

    /// Create a test event loop. Requires Linux with io_uring support.
    fn make_test_loop() -> AsyncEventLoop<NoopHandler> {
        make_test_loop_with_config(test_config())
    }

    /// Create a test event loop from an explicit config.
    fn make_test_loop_with_config(config: Config) -> AsyncEventLoop<NoopHandler> {
        // Parallel release-mode test runs can transiently exhaust kernel memory
        // for io_uring_setup while sibling tests hold their rings — the daily
        // scheduled CI intermittently fails several of these tests at once with
        // ENOMEM (e.g. runs 31887895010, 31710717130). The pressure clears as
        // sibling tests finish, so retry briefly before failing.
        //
        // On Linux 6.14+ each ring is charged to RLIMIT_MEMLOCK, and a dropped
        // ring's charge is released asynchronously. A test that sets up loops
        // in quick succession (the proptests) can reach an 8 MiB limit before
        // earlier rings are freed; setup then fails with an `Error::RingSetup`
        // naming ENOMEM. It clears once the
        // kernel's exit work frees those rings (#589).
        let mut io_attempts = 0;
        let mut memlock_attempts = 0;
        loop {
            let shutdown = Arc::new(AtomicBool::new(false));
            let eventfd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            assert!(eventfd >= 0, "eventfd creation failed");
            let (_region_tx, region_rx) = crossbeam_channel::unbounded();
            match AsyncEventLoop::new(
                &config,
                NoopHandler,
                None,
                None,
                eventfd,
                shutdown,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                region_rx,
            ) {
                Ok(el) => return el,
                // Transient: another test binary may hold the memory or fds
                // this one needs for a moment. Retry, briefly.
                Err(crate::error::Error::Io(ref io))
                    if io_attempts < 10
                        && matches!(
                            io.raw_os_error(),
                            Some(libc::ENOMEM | libc::EAGAIN | libc::EMFILE | libc::ENFILE)
                        ) =>
                {
                    io_attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                // Rings dropped by earlier tests are still releasing their
                // memlock charge. Retry for up to 5 s. If it still fails, the
                // user's total charge (this process and others) does not fit
                // under the limit, and the arm below reports it.
                Err(ref e)
                    if memlock_attempts < 50
                        && crate::backend::uring::ring::is_memlock_enomem(e) =>
                {
                    memlock_attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                // Structural: io_uring is refused or unsupported on this host
                // (kernel.io_uring_disabled, seccomp, an old kernel, a limit).
                // Every test in this binary would fail the same way, so say it
                // once and stop the binary instead of reporting it 134 times.
                // Written straight to fd 2: libtest captures the print macros
                // and would discard the message on process exit.
                Err(
                    e @ (crate::error::Error::RingSetup(_)
                    | crate::error::Error::ResourceLimit(_)
                    | crate::error::Error::BufferRegistration(_)),
                ) => {
                    use std::io::Write;
                    use std::sync::atomic::{AtomicBool, Ordering};
                    // Tests run in parallel; several can reach this arm before
                    // the first one's exit lands. Only the first writes.
                    static REPORTED: AtomicBool = AtomicBool::new(false);
                    if !REPORTED.swap(true, Ordering::SeqCst) {
                        let msg = format!(
                            "\nringline: cannot create the test event loop on this host, \
                             aborting the test binary so this is reported once:\n  {e}\n\n"
                        );
                        let _ = std::io::stderr().write_all(msg.as_bytes());
                        std::process::exit(101);
                    }
                    // Another thread is exiting the process; block until it does
                    // rather than reporting the same failure again.
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => {
                    panic!(
                        "failed to create test event loop after {} retries: {e:?}",
                        io_attempts + memlock_attempts
                    )
                }
            }
        }
    }

    /// Simulate an accepted plaintext connection at the given index.
    /// Returns the conn_index that was allocated.
    fn accept_connection(el: &mut AsyncEventLoop<NoopHandler>) -> u32 {
        let conn_index = el.driver.connections.allocate().expect("no free slots");
        el.driver.accumulators.reset(conn_index);
        // As `install_accepted_with_pending` leaves a plaintext connection:
        // open and direct, with no receive armed. Its hangup poll is not
        // armed; tests that need it arm it.
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.lifecycle = Lifecycle::Open;
            cs.recv_direct = true;
            cs.established = true;
            // The real install records the listener; without it every test
            // connection looks outbound, which park now refuses.
            cs.listener = Some(crate::ListenerId::from_index(0));
        }
        conn_index
    }

    /// The read half is finished and nothing is closing: the peer's end
    /// requested no close (`docs/half-close-design.md`). `truncated` is a TLS
    /// FIN without the peer's close_notify.
    fn assert_half_open(el: &AsyncEventLoop<NoopHandler>, conn_index: u32, truncated: bool) {
        let cs = el
            .driver
            .connections
            .get(conn_index)
            .expect("the slot is held");
        assert_eq!(cs.read, ReadHalf::Eof { truncated });
        assert_eq!(cs.lifecycle, Lifecycle::Open);
        assert!(!cs.close_requested());
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(!state.close_pending, "the end requested a close");
        assert!(!state.close_submitted);
        assert!(!el.driver.pending_finalize_closes.contains(&conn_index));
    }

    /// The peer's FIN, read by a direct receive, finishes the read half and
    /// requests no close.
    #[test]
    fn a_fin_finishes_the_read_half_and_requests_no_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            0,
            0,
        );
        assert_half_open(&el, conn_index, false);
    }

    /// A hangup peek that finds the stream ended with nothing queued or
    /// buffered finishes the read half and requests no close.
    #[test]
    fn a_hangup_peek_that_finds_the_end_finishes_the_read_half() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.test_dispatch_cqe(
            UserData::encode(OpTag::HangupPeek, conn_index, generation).raw(),
            0,
            0,
        );
        assert_half_open(&el, conn_index, false);
    }

    /// A hangup peek that returns the socket's error still closes the
    /// connection, with the read half in error.
    #[test]
    fn a_hangup_peek_error_still_closes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.test_dispatch_cqe(
            UserData::encode(OpTag::HangupPeek, conn_index, generation).raw(),
            -libc::ECONNRESET,
            0,
        );
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert_eq!(cs.read, ReadHalf::Error);
        assert!(cs.close_requested(), "a reset closes the connection");
    }

    /// A FIN on a TLS connection without the peer's close_notify finishes the
    /// read half as a truncation and requests no close; the TLS state stays
    /// for the task's sends.
    #[test]
    fn a_tls_fin_finishes_the_read_half_as_a_truncation_and_requests_no_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            0,
            0,
        );
        assert_half_open(&el, conn_index, true);
        assert!(
            el.driver.tls_table.as_ref().unwrap().has(conn_index),
            "the TLS state stays for the task's sends"
        );
    }

    /// Deliver a FIN to a TLS connection whose handshake has not completed.
    /// `outbound` registers a connect waiter first, as a parked
    /// `connect(..).tls(..)` does.
    fn fin_before_the_tls_handshake_completes(
        el: &mut AsyncEventLoop<NoopHandler>,
        outbound: bool,
    ) -> u32 {
        let conn_index = accept_connection(el);
        // Dropped at return: the receive's completion is injected below, and
        // nothing reads the socket.
        let (_ours, _peer) = attach_socketpair(el, conn_index);
        install_handshaked_tls(el, conn_index);
        let cs = el.driver.connections.get_mut(conn_index).unwrap();
        cs.established = false;
        cs.outbound = outbound;
        if outbound {
            el.executor.connect_waiters[conn_index as usize] = true;
        }
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            0,
            0,
        );
        conn_index
    }

    /// A FIN before the TLS handshake completes closes the connection. No
    /// task holds an inbound connection until its handshake completes, so
    /// nothing else would close it and the slot would be held until the
    /// worker exits.
    #[test]
    fn a_tls_fin_before_the_handshake_completes_closes_the_connection() {
        let mut el = make_test_loop();
        let conn_index = fin_before_the_tls_handshake_completes(&mut el, false);
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert_eq!(cs.read, ReadHalf::Eof { truncated: true });
        assert!(cs.close_requested(), "no task holds it to close it");
    }

    /// The same FIN on an outbound connection resolves the connect with
    /// `UnexpectedEof` and closes the connection.
    #[test]
    fn a_tls_fin_before_the_handshake_completes_fails_the_connect() {
        let mut el = make_test_loop();
        let conn_index = fin_before_the_tls_handshake_completes(&mut el, true);
        assert!(!el.executor.connect_waiters[conn_index as usize]);
        match el.executor.io_results[conn_index as usize].take() {
            Some(crate::runtime::IoResult::Connect(Err(e))) => {
                assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            }
            _ => panic!("the connect waiter was not given an error"),
        }
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert!(cs.close_requested(), "the failed connect holds no slot");
    }

    /// The peer's close_notify, reported by the receive path, finishes the
    /// read half cleanly and requests no close.
    #[test]
    fn the_peers_close_notify_finishes_the_read_half_and_requests_no_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        install_handshaked_tls(&mut el, conn_index);
        el.apply_tls_recv_result(conn_index, crate::tls::TlsRecvResult::Closed);
        assert_half_open(&el, conn_index, false);
    }

    /// A close_notify that arrives with the client's last handshake flight
    /// completes the handshake and finishes the read half, and requests no
    /// close: the task reads what arrived, then `0`.
    #[test]
    fn a_close_notify_with_the_handshake_finishes_the_read_half_and_requests_no_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        install_handshaked_tls(&mut el, conn_index);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .established = false;
        el.apply_tls_recv_result(
            conn_index,
            crate::tls::TlsRecvResult::HandshakeJustCompleted { peer_closed: true },
        );
        assert!(
            el.driver.connections.get(conn_index).unwrap().established,
            "the handshake completed"
        );
        assert_half_open(&el, conn_index, false);
    }

    /// A hangup poll that completes while a direct receive is in flight puts
    /// the connection on the recheck list, so if that receive returns bytes
    /// the end behind them is found after they are read, without a read
    /// parking again.
    #[test]
    fn a_hangup_with_a_receive_in_flight_is_rechecked() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.recv_direct = true;
            cs.recv_direct_armed = true;
        }
        let ud = UserData::encode(OpTag::HangupPoll, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), libc::POLLRDHUP as i32, 0);
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(
            !c.hangup_peek_armed,
            "the receive in flight reports the end"
        );
        assert!(c.hangup_recheck && c.hangup_recheck_due);
        assert_eq!(el.driver.hangup_rechecks, vec![(conn_index, generation)]);
    }

    /// Register an awaited send on `conn_index` and attach it to pool slot
    /// `slot` with `len`, as `ConnCtx::send` does with its final slot.
    fn await_slot(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        slot: u16,
        len: u32,
    ) -> crate::runtime::send_completion::SendId {
        let id = el.executor.register_send(conn_index);
        el.driver.send_copy_pool.set_send_id(slot, id, len);
        id
    }

    /// Register an awaited send on `conn_index` and attach it to slab entry
    /// `slab_idx` with `len`, as `submit_batch_await` does.
    fn await_slab(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        slab_idx: u16,
        len: u32,
    ) -> crate::runtime::send_completion::SendId {
        let id = el.executor.register_send(conn_index);
        el.driver.send_slab.set_send_id(slab_idx, id, len);
        id
    }

    /// Register an awaited send on `conn_index` and attach it to the
    /// connection's active chain, as `send_chain` does.
    fn await_chain(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
    ) -> crate::runtime::send_completion::SendId {
        let id = el.executor.register_send(conn_index);
        el.driver.chain_table.set_send_id(conn_index, id);
        id
    }

    /// What the send `id` settled with, if it has: settles the driver
    /// queued during the iteration (teardown, empty sends) are drained
    /// first, as the run loop does.
    fn send_result(
        el: &mut AsyncEventLoop<NoopHandler>,
        id: crate::runtime::send_completion::SendId,
    ) -> Option<io::Result<u32>> {
        el.drain_settled_sends();
        el.executor.take_send_result(id)
    }

    // ── Park gate (tier 3, #443) ───────────────────────────────────

    use crate::backend::uring::driver::ParkBlocker;

    /// The baseline every other park test leans on: this harness can produce a
    /// connection the gate accepts. Without it a blocker test proves nothing —
    /// it would pass just as well if `park_blocker` always refused.
    #[test]
    fn a_quiescent_connection_is_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        // Offered: these cover the mechanical blockers, so the opt-in must
        // be out of the way or every one of them would report NotOffered.
        el.driver.park_offered[conn_index as usize] = true;
        assert_eq!(
            el.driver.park_blocker(conn_index),
            None,
            "a freshly accepted, idle connection is the canonical parkable case"
        );
        assert!(el.driver.is_parkable(conn_index));
    }

    #[test]
    fn an_in_flight_send_blocks_the_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        // Offered: these cover the mechanical blockers, so the opt-in must
        // be out of the way or every one of them would report NotOffered.
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.send_queues[conn_index as usize].in_flight = true;
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::Sends),
            "the SQE references this worker's pool slot (Domain Invariant 1)"
        );
    }

    #[test]
    fn a_requested_close_blocks_the_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.close_connection(conn_index);
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::Closing),
            "park must lose the race to teardown, not run alongside it"
        );
    }

    #[test]
    fn a_connection_still_handshaking_is_not_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.established = false;
        }
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::NotOpen),
            "there is no connection state worth moving until the handshake lands"
        );
    }

    // ── Park wiring, end to end within a worker (tier 3, #443) ─────

    /// The claim #469 makes and nothing tested: that the policy actually
    /// reaches the mechanism. Every other park test is either a pure policy
    /// function or a hand-driven completion handler — if `maybe_park_one`
    /// never called `begin_park` (wrong tick position, an inverted gate term,
    /// a missing precondition), all of them would still pass.
    #[test]
    fn the_policy_starts_a_real_park() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return; // pre-6.8: park is unavailable by design, nothing to test
        }
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;

        // A standing imbalance: this worker well above the other. Faked,
        // because tier 1 exists to stop one forming — which is exactly why
        // park is hard to provoke in a live server and easy to leave untested.
        let loads = std::sync::Arc::new(vec![AtomicU32::new(40), AtomicU32::new(0)]);
        el.driver.worker_loads = Some(loads.clone());
        el.driver.worker_index = 0;
        let (tx, _rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        let (_r0, w0) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (_r1, w1) = crate::wakeup::create_wake_fd().expect("wake fd");
        el.driver.peer_park = vec![(tx.clone(), w0.as_wake_fd()), (tx, w1.as_wake_fd())];

        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "precondition: nothing in flight"
        );

        el.maybe_park_one();

        let started = el.driver.park_in_flight[conn_index as usize]
            .expect("the policy must actually start a park");
        assert_eq!(started.target, 1, "onto the least loaded worker");
        assert_eq!(
            loads[1].load(Ordering::Relaxed),
            1,
            "and claim the target's slot immediately, or a burst would all \
             pick the same target from one stale snapshot"
        );
    }

    /// The balanced case, so the test above cannot pass against a policy that
    /// parks unconditionally.
    #[test]
    fn the_policy_starts_no_park_when_balanced() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;

        let loads = std::sync::Arc::new(vec![AtomicU32::new(20), AtomicU32::new(20)]);
        el.driver.worker_loads = Some(loads);
        el.driver.worker_index = 0;
        let (tx, _rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        let (_r0, w0) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (_r1, w1) = crate::wakeup::create_wake_fd().expect("wake fd");
        el.driver.peer_park = vec![(tx.clone(), w0.as_wake_fd()), (tx, w1.as_wake_fd())];

        el.maybe_park_one();

        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "a balanced fleet must not move anything"
        );
    }

    fn direct_flags(el: &AsyncEventLoop<NoopHandler>, conn_index: u32) -> (bool, bool) {
        let c = el.driver.connections.get(conn_index).unwrap();
        (c.recv_direct_armed, c.hangup_poll_armed)
    }

    /// A direct connection with a read parked and its hangup poll armed is
    /// parked by cancelling both. The install waits until both have ended,
    /// and no receive is armed in between, even when the reader polls again.
    #[test]
    fn a_direct_park_cancels_the_receive_and_the_poll_before_the_install() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        // Another connection's receive takes `direct_recvs` slot 0, so this
        // connection's slot differs from its generation.
        let other = accept_connection(&mut el);
        assert!(!el.driver.arm_direct_recv_or_close(other, None));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.arm_hangup_poll(conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert_eq!(direct_flags(&el, conn_index), (true, true), "precondition");
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.driver.park_offered[conn_index as usize] = true;

        el.driver.ring.pushed_cancels.clear();
        assert!(el.begin_park(conn_index, 1), "the park starts");
        assert_eq!(
            el.driver.ring.pushed_cancels,
            vec![
                UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
                UserData::encode(OpTag::HangupPoll, conn_index, generation).raw(),
            ],
            "the park cancels the direct receive by its slot and the hangup poll"
        );
        assert!(
            el.driver.park_drain[conn_index as usize].is_some(),
            "it drains: there was something to cancel"
        );
        el.drive_park_drains();
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "no install while the receive and the poll are armed"
        );

        // The receive ends cancelled; the reader polls again and parks.
        let recv_ud = UserData::encode(OpTag::RecvDirect, conn_index, slot);
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert_eq!(
            direct_flags(&el, conn_index),
            (false, true),
            "no receive is armed while the park is pending"
        );
        el.drive_park_drains();
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "no install while the poll is armed"
        );

        let poll_ud = UserData::encode(OpTag::HangupPoll, conn_index, generation);
        el.test_dispatch_cqe(poll_ud.raw(), -libc::ECANCELED, 0);
        el.drive_park_drains();
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_some(),
            "the install goes out once nothing is armed"
        );
        assert!(el.driver.park_drain[conn_index as usize].is_none());
    }

    /// An abandoned park of a direct connection gives it its hangup poll
    /// back, and a reader that parked during the drain can arm again.
    #[test]
    fn abandoning_a_direct_park_rearms_the_poll_and_allows_a_receive() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .set_park_drain(conn_index, Some(park_drain_for(&el, conn_index)));
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert_eq!(
            direct_flags(&el, conn_index),
            (false, false),
            "precondition"
        );

        el.abandon_park_drain(conn_index);

        assert!(el.driver.park_drain[conn_index as usize].is_none());
        let (recv, poll) = direct_flags(&el, conn_index);
        assert!(poll, "the hangup poll is armed again");
        assert!(!recv, "the abandon itself arms no receive");
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert_eq!(
            direct_flags(&el, conn_index),
            (true, true),
            "the reader's next poll arms its receive"
        );
    }

    /// A connection installed on a plaintext listener is direct, with no
    /// receive armed, and its hangup poll is armed.
    #[test]
    fn an_accepted_plaintext_connection_is_installed_direct() {
        let mut el = make_test_loop();
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let fd = std::os::fd::IntoRawFd::into_raw_fd(a);
        el.install_accepted(
            fd,
            crate::ListenerId::from_index(0),
            crate::connection::PeerAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
        );
        let conn_index = (0..64u32)
            .find(|&i| el.driver.connections.get(i).is_some_and(|c| c.established))
            .expect("installed");
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(c.recv_direct, "direct");
        assert!(!c.recv_direct_armed, "no receive armed");
        assert!(c.hangup_poll_armed, "the hangup poll is armed");
    }

    /// No park starts while a hangup peek is in flight, and a peek that
    /// finds the stream ended finishes the read half, which refuses the park
    /// too.
    #[test]
    fn a_hangup_peek_in_flight_holds_off_the_park() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_offered[conn_index as usize] = true;
        assert!(el.driver.submit_hangup_peek(conn_index));
        assert!(!el.begin_park(conn_index, 1), "no park behind a peek");
        assert!(el.driver.park_in_flight[conn_index as usize].is_none());
        let ud = UserData::encode(OpTag::HangupPeek, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert_eq!(
            cs.read,
            ReadHalf::Eof { truncated: false },
            "the peek found the end"
        );
        assert!(!cs.close_requested(), "the end requested a close");
        assert!(
            !el.begin_park(conn_index, 1),
            "a connection whose read half is finished is not parked"
        );
    }

    /// A hangup poll that completes during a park drain pushes no peek: the
    /// drain waits for nothing to be armed, and the hangup stays pending on
    /// the socket for the poll armed after the park.
    #[test]
    fn a_hangup_during_a_park_drain_pushes_no_peek() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.arm_hangup_poll(conn_index);
        el.driver
            .set_park_drain(conn_index, Some(park_drain_for(&el, conn_index)));
        let ud = UserData::encode(OpTag::HangupPoll, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), libc::POLLRDHUP as i32, 0);
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(!c.hangup_poll_armed);
        assert!(!c.hangup_peek_armed, "no peek while the park drains");
    }

    /// Abandoning a direct park wakes a reader that parked during the drain,
    /// so it arms its receive.
    #[test]
    fn abandoning_a_direct_park_wakes_the_reader() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .set_park_drain(conn_index, Some(park_drain_for(&el, conn_index)));
        el.executor.recv_waiters[conn_index as usize] = true;
        el.abandon_park_drain(conn_index);
        assert!(
            !el.executor.recv_waiters[conn_index as usize],
            "the parked reader was woken"
        );
    }

    /// A connection holding the error a hangup peek took from its socket is
    /// not parked: the adopting worker would see a clean end of stream.
    #[test]
    fn a_connection_holding_a_hangup_error_is_not_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        assert!(el.driver.park_blocker(conn_index).is_none(), "precondition");
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .hangup_error = libc::ECONNRESET;
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(crate::backend::uring::driver::ParkBlocker::Closing)
        );
    }

    /// A UDP re-arm that cannot be submitted stays listed, keeps the worker
    /// from blocking while the socket has a free buffer, and is retried.
    #[test]
    fn a_failed_udp_rearm_is_retried() {
        let mut cfg = test_config();
        cfg.udp_bind = vec!["127.0.0.1:0".parse().unwrap()];
        cfg.tick_timeout_us = 0;
        let mut el = make_test_loop_with_config(cfg);
        el.driver.ring.flush().unwrap();
        assert!(el.may_block());

        el.driver.on_udp_recv_ended(0, libc::ENOBUFS);
        el.driver.ring.force_push_failures(1);
        el.driver.return_udp_buffers();
        assert_eq!(el.driver.udp_awaiting_buffers, vec![0]);
        assert!(el.driver.udp_rearm_due());
        assert!(!el.may_block());

        el.driver.return_udp_buffers();
        assert!(el.driver.udp_awaiting_buffers.is_empty());
        assert!(el.may_block());

        // A failure with no buffer free waits for one, and the worker may block.
        for _ in 0..el.driver.udp_provided_bufs[0].ring_entries() {
            el.driver.udp_provided_bufs[0].on_handout();
        }
        el.driver.ring.force_push_failures(1);
        el.driver.rearm_udp_recvmsg(0);
        assert_eq!(el.driver.udp_awaiting_buffers, vec![0]);
        assert!(!el.driver.udp_rearm_due());
        assert!(el.may_block());

        el.driver.udp_pending_replenish.push((0, 0));
        el.driver.return_udp_buffers();
        assert!(el.driver.udp_awaiting_buffers.is_empty());
    }

    /// A queued deferred receive keeps the worker from blocking until
    /// `arm_deferred_recvs` takes it.
    #[test]
    fn a_deferred_recv_arm_keeps_the_worker_from_blocking() {
        let mut cfg = test_config();
        cfg.defer_recv_arm = true;
        cfg.tick_timeout_us = 0;
        let mut el = make_test_loop_with_config(cfg);
        el.driver.ring.flush().unwrap();
        assert!(el.may_block());

        // Slot 0 holds no connection, so the arm drops the entry.
        el.driver.deferred_recv_arms.push((0, 0, None));
        assert!(!el.may_block());
        el.arm_deferred_recvs();
        assert!(el.driver.deferred_recv_arms.is_empty());
        assert!(el.may_block());
    }

    /// A hangup poll that cannot be submitted puts the connection on the
    /// poll retry list, and the recheck submits it and drops the entry.
    #[test]
    fn a_hangup_poll_that_cannot_be_submitted_is_retried() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.ring.force_push_failures(1);
        el.driver.arm_hangup_poll(conn_index);
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(!c.hangup_poll_armed, "the push failed");
        assert!(c.hangup_poll_retry);
        assert!(!c.hangup_recheck, "a poll retry owes no peek");
        assert_eq!(
            el.driver.hangup_poll_retries,
            vec![(conn_index, generation)]
        );
        el.recheck_hangups();
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(c.hangup_poll_armed, "the recheck submitted the poll");
        assert!(!c.hangup_poll_retry);
        assert!(!c.hangup_peek_armed, "no peek is due");
        assert!(el.driver.hangup_poll_retries.is_empty(), "entry dropped");
        assert!(el.driver.hangup_rechecks.is_empty());
    }

    /// A poll retry whose push keeps failing keeps one entry on the retry
    /// list, and the entry is dropped once the poll is armed.
    #[test]
    fn a_failed_poll_retry_keeps_one_entry() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.ring.force_push_failures(4);
        el.driver.arm_hangup_poll(conn_index);
        el.recheck_hangups();
        el.recheck_hangups();
        el.recheck_hangups();
        assert_eq!(
            el.driver.hangup_poll_retries,
            vec![(conn_index, generation)]
        );
        el.recheck_hangups();
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .hangup_poll_armed
        );
        assert!(el.driver.hangup_poll_retries.is_empty());
    }

    /// A hangup poll retry waits while a park of the connection is pending:
    /// the install requires nothing to be armed.
    #[test]
    fn a_hangup_poll_retry_waits_for_a_pending_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.ring.force_push_failures(1);
        el.driver.arm_hangup_poll(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        el.recheck_hangups();
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(
            !c.hangup_poll_armed,
            "no poll while the install is in flight"
        );
        assert!(c.hangup_poll_retry, "the retry is still owed");
        assert_eq!(
            el.driver.hangup_poll_retries,
            vec![(conn_index, generation)]
        );
    }

    /// A peek that the hangup poll triggers and that cannot be submitted puts
    /// the connection on the recheck list with a peek due, and the recheck
    /// submits it.
    #[test]
    fn a_hangup_peek_that_cannot_be_submitted_is_retried() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.arm_hangup_poll(conn_index);
        el.driver.ring.force_push_failures(1);
        let ud = UserData::encode(OpTag::HangupPoll, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), libc::POLLRDHUP as i32, 0);
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(!c.hangup_peek_armed, "the push failed");
        assert!(c.hangup_recheck && c.hangup_recheck_due);
        assert_eq!(el.driver.hangup_rechecks, vec![(conn_index, generation)]);
        el.recheck_hangups();
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(c.hangup_peek_armed, "the recheck submitted the peek");
        assert!(!c.hangup_recheck_due);
    }

    /// No recheck peek is pushed while a park of the connection is pending.
    #[test]
    fn a_recheck_waits_for_a_pending_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        {
            let c = el.driver.connections.get_mut(conn_index).unwrap();
            c.hangup_recheck = true;
            c.hangup_recheck_due = true;
        }
        el.driver.hangup_rechecks.push((conn_index, generation));
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        el.recheck_hangups();
        let c = el.driver.connections.get(conn_index).unwrap();
        assert!(
            !c.hangup_peek_armed,
            "no peek while the install is in flight"
        );
        assert!(c.hangup_recheck_due, "the recheck is still owed");
    }

    /// A direct connection with nothing armed installs at once.
    #[test]
    fn a_direct_connection_with_nothing_armed_installs_at_once() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        assert!(el.begin_park(conn_index, 1));
        assert!(el.driver.park_drain[conn_index as usize].is_none());
        assert!(el.driver.park_in_flight[conn_index as usize].is_some());
    }

    fn park_drain_for(
        el: &AsyncEventLoop<NoopHandler>,
        conn_index: u32,
    ) -> crate::backend::uring::driver::ParkDrain {
        crate::backend::uring::driver::ParkDrain {
            target: 1,
            generation: el.driver.connections.generation(conn_index),
            ticks_left: PARK_DRAIN_TICKS,
            started: std::time::Instant::now(),
        }
    }

    fn poll_armed(el: &AsyncEventLoop<NoopHandler>, conn_index: u32) -> bool {
        el.driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.hangup_poll_armed)
    }

    /// An install that fails after the drain gives the connection its
    /// hangup poll back.
    #[test]
    fn a_failed_install_rearms_the_hangup_poll() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .set_park_drain(conn_index, Some(park_drain_for(&el, conn_index)));
        el.driver.park_offered[conn_index as usize] = true;
        el.drive_park_drains();
        assert!(el.driver.park_in_flight[conn_index as usize].is_some());
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::ParkInstall,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.handle_park_install(ud, -libc::EBADF);
        assert!(
            poll_armed(&el, conn_index),
            "no hangup poll after the failure"
        );
    }

    /// A park install still in flight for a slot's previous occupant does
    /// not refuse the new occupant's receive, and its stale completion
    /// leaves that receive armed.
    #[test]
    fn a_stale_install_does_not_block_the_next_occupants_receive() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = generation.wrapping_sub(1);
        // Written by hand: `clear_conn_claims` leaves no entry for a
        // previous occupant.
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation: stale,
            });
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.recv_direct_armed),
            "receive refused because of a stale park"
        );
        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, stale), probe.installed);
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.recv_direct_armed)
        );
    }

    /// A failed install for a slot's previous occupant does not arm the new
    /// occupant's hangup poll.
    #[test]
    fn a_stale_failed_install_does_not_rearm_the_next_occupant() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = generation.wrapping_sub(1);
        // Written by hand: `clear_conn_claims` leaves no entry for a
        // previous occupant.
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation: stale,
            });
        el.handle_park_install(park_install_ud(conn_index, stale), -libc::EBADF);
        assert!(
            !poll_armed(&el, conn_index),
            "armed the new occupant's hangup poll"
        );
    }

    /// An install CQE for a slot's previous occupant lands while the next
    /// occupant has its own install in flight. The next occupant's park stays
    /// in flight, and the stale fd is closed.
    #[test]
    fn a_stale_install_leaves_the_next_occupants_park_in_flight() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = generation.wrapping_sub(1);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });

        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, stale), probe.installed);
        assert!(probe.was_closed(), "the stale fd was kept");
        assert_eq!(
            el.driver.park_in_flight[conn_index as usize].map(|p| p.generation),
            Some(generation),
            "the stale install took the next occupant's park"
        );
        assert!(el.driver.park_ready.is_empty(), "and must not park");

        // A failed stale install, the same.
        el.handle_park_install(park_install_ud(conn_index, stale), -libc::ECANCELED);
        assert_eq!(
            el.driver.park_in_flight[conn_index as usize].map(|p| p.generation),
            Some(generation),
            "the stale failed install took the next occupant's park"
        );
        assert!(
            !poll_armed(&el, conn_index),
            "armed a poll while the next occupant's install is in flight"
        );
    }

    /// An install CQE for a slot's previous occupant lands while the next
    /// occupant's park is draining. The drain stays, and no poll is armed
    /// behind the cancel the drain sent.
    #[test]
    fn a_stale_install_leaves_the_next_occupants_park_drain_alone() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = generation.wrapping_sub(1);
        el.driver.set_park_drain(conn_index, test_drain(generation));

        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, stale), probe.installed);
        assert!(probe.was_closed(), "the stale fd was kept");
        assert_eq!(
            el.driver.park_drain[conn_index as usize].map(|d| d.generation),
            Some(generation),
            "the stale install abandoned the next occupant's drain"
        );
        assert!(
            !poll_armed(&el, conn_index),
            "armed a poll behind the drain's cancel"
        );
    }

    /// Releasing a slot clears the park in flight for its occupant, so the
    /// next occupant can start a park of its own. `begin_park` refuses while
    /// an entry is present, whatever generation it carries.
    #[test]
    fn a_recycled_slot_does_not_inherit_a_park_in_flight() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });

        recycle_connection(&mut el, conn_index);

        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "the next occupant inherited a park in flight"
        );
    }

    /// An install that finds the connection no longer parkable closes the
    /// installed fd and gives the connection its hangup poll back.
    #[test]
    fn a_blocked_install_rearms_the_hangup_poll() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        // Not offered: `park_blocker` refuses.
        el.driver.park_offered[conn_index as usize] = false;
        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);
        assert!(probe.was_closed(), "the installed fd was kept");
        assert!(
            poll_armed(&el, conn_index),
            "no hangup poll after the blocked install"
        );
    }

    /// Abandoning when no park is draining is a no-op, so a stray install CQE
    /// cannot re-arm a connection whose poll was never cancelled.
    #[test]
    fn abandoning_without_a_draining_park_changes_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.set_park_drain(conn_index, None);

        el.abandon_park_drain(conn_index);

        assert!(
            !poll_armed(&el, conn_index),
            "no park was draining, so nothing was owed"
        );
    }

    fn test_drain(generation: u32) -> Option<crate::backend::uring::driver::ParkDrain> {
        Some(crate::backend::uring::driver::ParkDrain {
            target: 1,
            generation,
            ticks_left: PARK_DRAIN_TICKS,
            started: std::time::Instant::now(),
        })
    }

    fn live_drains(el: &AsyncEventLoop<NoopHandler>) -> Vec<u32> {
        (0..el.driver.park_drain.len() as u32)
            .filter(|&i| el.driver.park_drain[i as usize].is_some())
            .collect()
    }

    /// Every live drain is on the pending list exactly once.
    fn assert_pending_covers_live(el: &AsyncEventLoop<NoopHandler>) {
        let pending = &el.driver.park_drain_pending;
        for i in live_drains(el) {
            assert_eq!(
                pending.iter().filter(|&&p| p == i).count(),
                1,
                "drain on connection {i} must be pending exactly once"
            );
        }
    }

    /// `park_drain_pending` is what `drive_park_drains` visits instead of
    /// scanning every slot (#514), so every drain must be on it exactly once
    /// through set, replace, clear, re-set and close.
    #[test]
    fn park_drain_pending_tracks_outstanding_drains() {
        let mut el = make_test_loop();
        assert!(el.driver.park_drain_pending.is_empty());
        let a = accept_connection(&mut el);
        let b = accept_connection(&mut el);
        let gen_a = el.driver.connections.generation(a);
        let gen_b = el.driver.connections.generation(b);

        el.driver.set_park_drain(a, test_drain(gen_a));
        el.driver.set_park_drain(a, test_drain(gen_a));
        el.driver.set_park_drain(b, test_drain(gen_b));
        assert_eq!(el.driver.park_drain_pending, vec![a, b]);

        // Cleared then set again before a drive: still one entry.
        el.driver.set_park_drain(a, None);
        el.driver.set_park_drain(a, test_drain(gen_a));
        assert_eq!(el.driver.park_drain_pending, vec![a, b]);
        assert_pending_covers_live(&el);

        el.driver.close_connection(b);
        assert_pending_covers_live(&el);
    }

    /// With nothing draining, the per-tick drive has nothing to visit; a
    /// drain left by a recycled slot is found, cleared and dropped from the
    /// list, and a cleared entry left on the list is dropped too.
    #[test]
    fn drive_park_drains_visits_only_the_pending_list() {
        let mut el = make_test_loop();
        let a = accept_connection(&mut el);
        let b = accept_connection(&mut el);

        el.drive_park_drains();
        assert!(el.driver.park_drain_pending.is_empty());
        assert!(live_drains(&el).is_empty());

        let stale = el.driver.connections.generation(a).wrapping_add(1);
        el.driver.set_park_drain(a, test_drain(stale));
        el.driver
            .set_park_drain(b, test_drain(el.driver.connections.generation(b)));
        el.driver.set_park_drain(b, None);
        assert_eq!(el.driver.park_drain_pending, vec![a, b]);

        el.drive_park_drains();
        assert!(el.driver.park_drain[a as usize].is_none());
        assert!(el.driver.park_drain_pending.is_empty());
    }

    /// Pool mode is the default and has no imbalance to repair. Park must be
    /// inert there, not merely unlikely.
    #[test]
    fn the_policy_is_inert_without_worker_loads() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        assert!(el.driver.worker_loads.is_none(), "pool mode: no load table");

        el.maybe_park_one();

        assert!(el.driver.park_in_flight[conn_index as usize].is_none());
    }

    /// An adopted connection must reach `on_adopt`, with its state. The
    /// driver state after an adopt and after a fresh accept is identical, so
    /// only the handler can tell the two apart — and nothing was asking it.
    #[test]
    fn an_adopted_connection_reaches_on_adopt_with_its_state() {
        let mut el = make_test_loop();
        ADOPTS.with(|n| n.set(0));
        ADOPTED_STATE.with(|c| *c.borrow_mut() = None);

        let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        el.driver.park_rx = Some(rx);
        let mut entry = parked_entry(0, b"");
        entry.state = Some(ParkState::new(String::from("session-42")));
        tx.try_send(entry).expect("queue");
        drop(tx);

        el.drain_adopted();

        assert_eq!(
            ADOPTS.with(|n| n.get()),
            1,
            "an adopted connection takes on_adopt, not on_accept"
        );
        assert_eq!(
            ADOPTED_STATE.with(|c| c.borrow().clone()).as_deref(),
            Some("session-42"),
            "and the handler gets back exactly what it deposited"
        );
    }

    // ── Park opt-in and carried state (tier 3, #443) ───────────────

    use crate::park::ParkState;

    /// The opt-in. Every other park test arms the offer by hand, so this is
    /// the one that proves the default is *refusal* — without it, a gate that
    /// had forgotten the check would look identical.
    #[test]
    fn a_connection_nobody_offered_is_never_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::NotOffered),
            "park is opt-in: quiescent is not enough"
        );
        el.driver.park_offered[conn_index as usize] = true;
        assert_eq!(
            el.driver.park_blocker(conn_index),
            None,
            "and the offer is the only thing that was missing"
        );
    }

    /// The property that makes `offer_for_park` a one-shot: arriving bytes
    /// mean a new request, so the offer is withdrawn. Without this a park
    /// could land mid-request and the handler would have to remember to
    /// revoke at every entry point.
    #[test]
    fn arriving_data_withdraws_the_park_offer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver
            .park_carry
            .insert(conn_index, ParkState::new(7u32));

        // Drive the real completion path: the withdrawal has to live on the
        // receive handler, not in a test-only helper.
        deliver_direct(&mut el, conn_index, b"GET x");

        assert!(
            !el.driver.park_offered[conn_index as usize],
            "new data means a new request: the offer must be withdrawn"
        );
        assert!(
            !el.driver.park_carry.contains_key(&conn_index),
            "and the state with it, or it would be carried at the wrong moment"
        );
    }

    /// #669: an offer made while the next request is buffered must not stand
    /// once the handler reads that request. The handler is mid-request then,
    /// and a park would drop its future without a reply.
    #[test]
    fn an_offer_made_with_a_request_buffered_does_not_survive_the_read() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;

        // Request 2 arrives while the handler is busy.
        el.driver.accumulators.append(conn_index, b"GET y");

        // Set a standing offer directly, so the assertions below need
        // `offer_for_park` to clear it.
        el.driver.park_offered[idx] = true;
        el.driver.park_carry.insert(conn_index, ParkState::new(0u8));

        // The handler finishes response 1 and offers, through the public
        // handle.
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        with_driver_state(&mut el, || ctx.offer_for_park(Some(ParkState::new(1u8))));

        // The handler reads request 2.
        el.driver.accumulators.consume(conn_index, 5);

        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::NotOffered),
            "the handler is mid-request; the offer must not stand"
        );
        assert!(
            !el.driver.park_carry.contains_key(&conn_index),
            "a declined offer must not leave state to ship"
        );
    }

    /// An offer made from inside a `with_data`, `with_bytes` or
    /// `try_with_data` callback is declined. `with_bytes`, and a
    /// `forward_recv_buf` of the whole accumulator, take the bytes out of the
    /// driver before the offer, so only the callback guard catches those
    /// cases; the plain `with_data` and `try_with_data` cases are also caught
    /// by `holds_unread` (#669).
    #[test]
    fn an_offer_from_inside_a_reader_callback_is_declined() {
        for reader in [
            "with_data",
            "with_data_forward",
            "with_bytes",
            "try_with_data",
            "try_with_data_forward",
        ] {
            let mut el = make_test_loop();
            let conn_index = accept_connection(&mut el);
            let generation = el.driver.connections.generation(conn_index);
            el.driver.accumulators.append(conn_index, b"GET z");

            // A standing offer that only `offer_for_park` reaching
            // `offer_park` clears.
            el.driver.park_offered[conn_index as usize] = true;
            el.driver.park_carry.insert(conn_index, ParkState::new(0u8));

            let ctx = ConnCtx::new(conn_index, generation);
            let waker = noop_waker();
            let consumed = match reader {
                "with_data" => {
                    let mut fut = std::pin::pin!(ctx.with_data(|d| {
                        ctx.offer_for_park(Some(ParkState::new(3u8)));
                        crate::runtime::io::ParseResult::Consumed(d.len())
                    }));
                    with_driver_state(&mut el, || {
                        let mut cx = std::task::Context::from_waker(&waker);
                        fut.as_mut().poll(&mut cx)
                    })
                }
                "with_data_forward" => {
                    // Forwarding the whole accumulator takes it out of the
                    // driver, so only the callback guard declines the offer.
                    let mut fut = std::pin::pin!(ctx.with_data(|d| {
                        ctx.forward_recv_buf(d).expect("forward");
                        ctx.offer_for_park(Some(ParkState::new(3u8)));
                        crate::runtime::io::ParseResult::Consumed(d.len())
                    }));
                    with_driver_state(&mut el, || {
                        let mut cx = std::task::Context::from_waker(&waker);
                        fut.as_mut().poll(&mut cx)
                    })
                }
                "with_bytes" => {
                    let mut fut = std::pin::pin!(ctx.with_bytes(|b| {
                        ctx.offer_for_park(Some(ParkState::new(3u8)));
                        crate::runtime::io::ParseResult::Consumed(b.len())
                    }));
                    with_driver_state(&mut el, || {
                        let mut cx = std::task::Context::from_waker(&waker);
                        fut.as_mut().poll(&mut cx)
                    })
                }
                _ => {
                    let forward = reader == "try_with_data_forward";
                    let r = with_driver_state(&mut el, || {
                        ctx.try_with_data(|d| {
                            if forward {
                                ctx.forward_recv_buf(d).expect("forward");
                            }
                            ctx.offer_for_park(Some(ParkState::new(3u8)));
                            crate::runtime::io::ParseResult::Consumed(d.len())
                        })
                    });
                    assert!(
                        matches!(r, Some(crate::runtime::io::ParseResult::Consumed(5))),
                        "{reader}"
                    );
                    std::task::Poll::Ready(5)
                }
            };
            assert!(
                matches!(consumed, std::task::Poll::Ready(5)),
                "{reader}: the read resolves with the request"
            );
            assert_eq!(
                el.driver.park_blocker(conn_index),
                Some(ParkBlocker::NotOffered),
                "{reader}: an offer from inside the callback must not stand"
            );
            assert!(
                !el.driver.park_carry.contains_key(&conn_index),
                "{reader}: and must not leave state to ship"
            );
        }
    }

    /// A reader callback on another connection, run from inside A's
    /// callback, restores A as the running callback when it returns. A's
    /// reader is `with_bytes`, so A's bytes are out of the driver and only the
    /// restored guard declines the offer.
    #[test]
    fn a_nested_reader_callback_restores_the_outer_connection() {
        let mut el = make_test_loop();
        let conn_a = accept_connection(&mut el);
        let conn_b = accept_connection(&mut el);
        el.driver.accumulators.append(conn_a, b"GET a");
        el.driver.accumulators.append(conn_b, b"GET b");
        // A standing offer that only `offer_for_park` reaching `offer_park`
        // clears.
        el.driver.park_offered[conn_a as usize] = true;
        el.driver.park_carry.insert(conn_a, ParkState::new(0u8));
        let ctx_a = ConnCtx::new(conn_a, el.driver.connections.generation(conn_a));
        let ctx_b = ConnCtx::new(conn_b, el.driver.connections.generation(conn_b));
        let waker = noop_waker();
        let mut fut = std::pin::pin!(ctx_a.with_bytes(|b| {
            let inner = ctx_b.try_with_data(|d| crate::runtime::io::ParseResult::Consumed(d.len()));
            assert!(inner.is_some(), "B's callback ran");
            ctx_a.offer_for_park(Some(ParkState::new(5u8)));
            crate::runtime::io::ParseResult::Consumed(b.len())
        }));
        let consumed = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(consumed, std::task::Poll::Ready(5)));
        assert!(
            !el.driver.park_offered[conn_a as usize],
            "A's callback is still running once B's returns: the offer must not stand"
        );
        assert!(!el.driver.park_carry.contains_key(&conn_a));
    }

    /// A declined offer also clears an offer and deposit already standing.
    #[test]
    fn a_declined_offer_clears_an_earlier_offer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        assert!(el.driver.offer_park(conn_index, Some(ParkState::new(4u8))));
        // Bytes reach the slot by a path that does not withdraw the offer.
        el.driver.accumulators.append(conn_index, b"GET w");
        assert!(!el.driver.offer_park(conn_index, None));
        assert!(!el.driver.park_offered[conn_index as usize]);
        assert!(!el.driver.park_carry.contains_key(&conn_index));
    }

    /// The other half of `offer_park`: at an idle point an offer made
    /// through the public handle stands and its state is deposited.
    #[test]
    fn an_offer_at_an_idle_point_stands() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        with_driver_state(&mut el, || ctx.offer_for_park(Some(ParkState::new(2u8))));
        assert!(el.driver.park_offered[conn_index as usize]);
        assert!(el.driver.park_carry.contains_key(&conn_index));
        assert_eq!(el.driver.park_blocker(conn_index), None);
    }

    /// Slots are recycled by generation. A new occupant inheriting the
    /// previous one's offer would be parked without asking — and would be
    /// handed a stranger's session state.
    #[test]
    fn a_recycled_slot_does_not_inherit_the_park_offer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.park_carry.insert(conn_index, ParkState::new(1u8));

        // Exercise the production clear, not a hand-written one: closing is
        // what a recycled slot actually goes through. The previous version of
        // this test set the flags itself and so would have passed even with
        // every clear deleted.
        el.driver.close_connection(conn_index);

        assert!(
            !el.driver.park_offered[conn_index as usize],
            "close must clear the offer"
        );
        assert!(
            !el.driver.park_carry.contains_key(&conn_index),
            "and release the deposited state rather than hold it until reuse"
        );
    }

    /// An established, quiescent TLS connection the handler offered is
    /// parkable: its session travels with it.
    #[test]
    fn a_quiescent_tls_connection_is_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        install_handshaked_tls(&mut el, conn_index);
        assert_eq!(el.driver.park_blocker(conn_index), None);
    }

    /// Plaintext the unbuffered engine stashed on the send path is unread
    /// data, so the park waits for the reader.
    #[cfg(not(feature = "tls-buffered"))]
    #[test]
    fn stashed_tls_plaintext_blocks_the_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        install_handshaked_tls(&mut el, conn_index);
        let (_, _, stash, _) = el
            .driver
            .tls_table
            .as_mut()
            .unwrap()
            .get_mut(conn_index)
            .unwrap()
            .conn
            .as_unbuffered_mut()
            .unwrap()
            .split_mut();
        stash.push_back(b"early".to_vec());
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::DataPending)
        );
    }

    /// Park a handshaked TLS connection through `handle_park_install` and
    /// return what it put on `park_ready`, and the client end of the session.
    fn park_a_tls_connection(
        el: &mut AsyncEventLoop<NoopHandler>,
    ) -> (crate::park::ParkedFd, TlsTestPeer) {
        let conn_index = accept_connection(el);
        let peer = install_handshaked_tls_with_peer(el, conn_index);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 0,
                generation,
            });
        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);
        std::mem::forget(probe); // the fd now belongs to the ParkedFd
        let parked = el.driver.park_ready.pop().expect("lifted off");
        assert!(
            !el.driver.tls_table.as_ref().unwrap().has(conn_index),
            "the session left this worker's table"
        );
        (parked, peer)
    }

    /// A park of a TLS connection with a receive in flight cancels the
    /// receive first, and sends the install only once the receive has ended,
    /// so the ciphertext buffer that moves with the session is not being
    /// written into.
    #[test]
    fn a_tls_park_waits_for_the_receive_to_end() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        let conn_index = accept_connection(&mut el);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        el.driver.park_offered[conn_index as usize] = true;
        let target = if el.driver.worker_index == 0 { 1 } else { 0 };
        assert!(el.begin_park(conn_index, target), "the park starts");
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "no install while the receive is in flight"
        );
        el.drive_park_drains();
        assert!(el.driver.park_in_flight[conn_index as usize].is_none());
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            -libc::ECANCELED,
            0,
        );
        el.drive_park_drains();
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_some(),
            "the install goes out once the receive has ended"
        );
    }

    /// Once a TLS connection's session has left with the park, a send on the
    /// parking worker is refused rather than written to the socket, which
    /// the adopting worker now owns, without encryption.
    #[test]
    fn a_send_after_a_tls_park_is_refused() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);
        let generation = el.driver.connections.generation(conn_index);
        install_handshaked_tls(&mut el, conn_index);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 0,
                generation,
            });
        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);
        std::mem::forget(probe); // the fd now belongs to the ParkedFd
        let _parked = el.driver.park_ready.pop().expect("lifted off");
        let token = crate::handler::ConnId::new(conn_index, generation);
        let sent = el.driver.make_ctx().send(token, b"SECRET-PLAINTEXT");
        assert!(sent.is_err(), "a send after the handoff is refused");
        el.driver.ring.submit_and_wait(0).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(try_recv(&peer, &mut buf), None, "nothing reached the peer");
    }

    /// An abandoned TLS park gives the connection back its hangup poll and
    /// wakes its reader, as for a direct connection, so a reader that parked
    /// during the drain arms its receive again.
    #[test]
    fn an_abandoned_tls_park_rearms_the_hangup_poll() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return;
        }
        let conn_index = accept_connection(&mut el);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        el.driver.park_offered[conn_index as usize] = true;
        let target = if el.driver.worker_index == 0 { 1 } else { 0 };
        assert!(el.begin_park(conn_index, target));
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            -libc::ECANCELED,
            0,
        );
        el.drive_park_drains();
        let generation = el.driver.connections.generation(conn_index);
        assert!(el.driver.park_in_flight[conn_index as usize].is_some());
        // The offer is withdrawn across the round trip, so the re-check
        // abandons the park.
        el.driver.park_offered[conn_index as usize] = false;
        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);
        assert!(probe.was_closed(), "the installed fd is closed");
        assert!(el.driver.park_ready.is_empty(), "nothing moved");
        let cs = el.driver.connections.get(conn_index).expect("still here");
        assert!(cs.hangup_poll_armed, "the hangup poll is armed again");
        assert!(
            el.driver.tls_table.as_ref().unwrap().has(conn_index),
            "the session stays"
        );
    }

    /// The TLS session is taken out of the parking worker's table and put in
    /// the entry for the adopting worker.
    #[test]
    fn the_tls_session_travels_with_the_park() {
        let mut el = make_test_loop();
        let (parked, _peer) = park_a_tls_connection(&mut el);
        assert!(parked.tls.is_some(), "the session travels with the fd");
    }

    /// Adopt `parked` through the park channel and return the slot it was
    /// installed in.
    fn adopt_parked(el: &mut AsyncEventLoop<NoopHandler>, parked: crate::park::ParkedFd) -> u32 {
        ADOPTS.with(|n| n.set(0));
        let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        el.driver.park_rx = Some(rx);
        tx.try_send(parked).expect("queue");
        drop(tx);
        el.drain_adopted();
        assert_eq!(ADOPTS.with(|n| n.get()), 1, "the handler is adopted");
        let max = el.driver.connections.max_slots();
        (0..max)
            .find(|&i| el.driver.tls_table.as_ref().unwrap().has(i))
            .expect("the session was installed")
    }

    /// An adopted TLS connection gets the session it had, established, with
    /// its hangup poll armed, and reaches `on_adopt`.
    #[test]
    fn an_adopted_tls_connection_is_installed_established() {
        let mut el = make_test_loop();
        let (parked, _peer) = park_a_tls_connection(&mut el);
        let adopted = adopt_parked(&mut el, parked);
        let cs = el.driver.connections.get(adopted).expect("open");
        assert!(cs.established, "no new handshake");
        assert!(!cs.recv_direct, "a TLS connection, not a plaintext one");
        assert!(
            cs.hangup_poll_armed,
            "a peer close is seen while nothing reads"
        );
    }

    /// Records the client sends after the move decrypt on the adopting side,
    /// so the session's record sequence carried over too.
    #[cfg(not(feature = "tls-buffered"))]
    #[test]
    fn an_adopted_tls_connection_keeps_its_session() {
        let mut el = make_test_loop();
        let (parked, mut peer) = park_a_tls_connection(&mut el);
        let adopted = adopt_parked(&mut el, parked);

        let mut dst = [0u8; 4096];
        let (_, n) = crate::tls::unbuffered::encrypt_chunk(&mut peer.conn, b"hello", &mut dst)
            .expect("client encrypts");
        let tls_conn = el
            .driver
            .tls_table
            .as_mut()
            .unwrap()
            .get_mut(adopted)
            .unwrap();
        let mut out = Vec::new();
        let outcome = crate::tls::unbuffered::feed(
            tls_conn,
            Some(&mut el.driver.accumulators),
            &mut out,
            &dst[..n],
            adopted,
        );
        assert!(
            !matches!(
                outcome,
                crate::tls::unbuffered::DriveOutcome::Error(_)
                    | crate::tls::unbuffered::DriveOutcome::Overflow
            ),
            "{outcome:?}"
        );
        assert_eq!(el.driver.accumulators.data(adopted), b"hello");
    }

    /// The carry round trip had no coverage at all: the deposited state was
    /// taken on one side and handed to `on_adopt` on the other, and no test
    /// followed it across. Asserts the state actually reaches the adopting
    /// worker's slot rather than being dropped somewhere in between.
    #[test]
    fn deposited_state_survives_the_park_and_reaches_the_adopt_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver
            .park_carry
            .insert(conn_index, ParkState::new(String::from("session-7")));
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 0,
                generation,
            });

        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);

        let parked = el.driver.park_ready.pop().expect("lifted off");
        let carried = parked
            .state
            .expect("the deposit travels with the connection")
            .take::<String>()
            .expect("and arrives as the type it was deposited as");
        assert_eq!(carried, "session-7");
        assert!(
            !el.driver.park_carry.contains_key(&conn_index),
            "and is moved, not copied — the old worker must not retain it"
        );
    }

    /// An outbound connection has no listener, so it was never placed by
    /// accept. Parking one used to fabricate `ListenerId(0)`; if any server
    /// TLS config existed, the adopting worker would then install a server
    /// session on an established outbound socket and wedge it.
    #[test]
    fn an_outbound_connection_is_never_parkable() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.listener = None;
        }
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::Outbound),
            "no listener means nothing for park to rebalance"
        );
    }

    /// The backstop for the withdraw rule. Unconsumed bytes mean the
    /// connection is not idle, whether or not the path that delivered them
    /// remembered to withdraw the offer — so a delivery path added later
    /// fails closed instead of parking mid-request.
    #[test]
    fn unconsumed_bytes_block_the_park_even_with_a_stale_offer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        assert_eq!(el.driver.park_blocker(conn_index), None, "precondition");

        // Data arrives by a path that forgot to withdraw.
        el.driver.accumulators.append(conn_index, b"half a request");

        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::DataPending),
            "the gate must not rely on every delivery path remembering"
        );
    }

    // ── Park handover (tier 3, #443) ───────────────────────────────

    fn parked_entry(target: usize, bytes: &[u8]) -> crate::park::ParkedFd {
        let probe = FdProbe::new();
        let fd = unsafe {
            <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(probe.installed)
        };
        std::mem::forget(probe); // the fd now belongs to the ParkedFd
        crate::park::ParkedFd {
            fd,
            listener: crate::ListenerId::from_index(0),
            peer: crate::connection::PeerAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
            pending: if bytes.is_empty() {
                Vec::new()
            } else {
                vec![bytes::Bytes::copy_from_slice(bytes)]
            },
            state: None,
            tls: None,
            target,
        }
    }

    /// A full target channel must not drop the entry. The connection has
    /// already left this worker — its slot is released and its future gone —
    /// so only the `OwnedFd` keeps the socket alive. Dropping it here hangs
    /// up on a live client because the target was momentarily busy.
    #[test]
    fn a_full_target_channel_retries_rather_than_hanging_up() {
        let mut el = make_test_loop();
        let (tx, _rx) = crate::handoff::bounded::<crate::park::ParkedFd>(1);
        let (_read, wake) = crate::wakeup::create_wake_fd().expect("wake fd");
        el.driver.peer_park = vec![(tx.clone(), wake.as_wake_fd())];

        // Fill the channel, then queue one more than it can take.
        tx.try_send(parked_entry(0, b"")).expect("first fits");
        el.driver.park_ready.push(parked_entry(0, b"carried"));

        el.drain_park_ready();

        assert_eq!(
            el.driver.park_ready.len(),
            1,
            "a busy target means retry next iteration, never drop the connection"
        );
    }

    /// A target that no longer exists is the one unrecoverable case, and it
    /// must not wedge the queue by retrying for ever.
    #[test]
    fn a_park_for_a_missing_worker_is_dropped_not_retried() {
        let mut el = make_test_loop();
        el.driver.peer_park = Vec::new();
        el.driver.park_ready.push(parked_entry(7, b""));

        el.drain_park_ready();

        assert!(
            el.driver.park_ready.is_empty(),
            "no such worker: retrying would spin for ever"
        );
    }

    #[test]
    fn a_successful_handover_clears_the_queue_and_reaches_the_target() {
        let mut el = make_test_loop();
        let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        let (_read, wake) = crate::wakeup::create_wake_fd().expect("wake fd");
        el.driver.peer_park = vec![(tx, wake.as_wake_fd())];
        el.driver.park_ready.push(parked_entry(0, b"carried"));

        el.drain_park_ready();

        assert!(el.driver.park_ready.is_empty(), "handed over");
        let got = rx.try_recv().expect("the target received it");
        let bytes: Vec<u8> = got.pending.iter().flat_map(|b| b.to_vec()).collect();
        assert_eq!(bytes, b"carried", "unconsumed bytes travel with it");
    }

    /// The adopting worker must present carried bytes to the handler before
    /// anything its own recv delivers. Seeding after `arm_recv` would put
    /// newer bytes ahead of older ones and silently reorder the stream.
    #[test]
    fn an_adopted_connection_starts_with_its_carried_bytes() {
        let mut el = make_test_loop();
        let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        el.driver.park_rx = Some(rx);
        tx.try_send(parked_entry(0, b"before-the-move"))
            .expect("queue");
        drop(tx);

        el.drain_adopted();

        // Nothing else has allocated on this loop, so the adopted connection
        // takes slot 0.
        let installed = 0u32;
        assert!(
            el.driver
                .connections
                .get(installed)
                .is_some_and(|c| c.active && c.peer_addr.is_some()),
            "the adopted connection took a slot"
        );
        assert_eq!(
            el.driver.accumulators.data(installed),
            b"before-the-move",
            "carried bytes are readable before the new recv delivers anything"
        );
    }

    // ── Park fd recovery (tier 3, #443) ────────────────────────────

    /// A pipe whose **write** end stands in for the installed fd.
    ///
    /// Counting `/proc/self/fd` cannot work here: it is process-wide, and the
    /// suite runs hundreds of tests in parallel in one process, each opening
    /// rings and sockets. The count moves under you.
    ///
    /// A pipe is local. Hand the write end to the handler; the read end then
    /// answers the only question that matters — if every write end has been
    /// closed, a non-blocking read returns EOF; if one is still open it
    /// returns `EAGAIN`. No other thread can perturb that.
    struct FdProbe {
        /// Handed to the code under test as the "installed" fd.
        installed: i32,
        read_end: i32,
    }

    impl FdProbe {
        fn new() -> Self {
            let mut fds = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
            unsafe {
                let fl = libc::fcntl(fds[0], libc::F_GETFL);
                libc::fcntl(fds[0], libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            FdProbe {
                installed: fds[1],
                read_end: fds[0],
            }
        }

        /// True once the handed-over fd has been closed.
        fn was_closed(&self) -> bool {
            let mut b = [0u8; 1];
            let n = unsafe { libc::read(self.read_end, b.as_mut_ptr() as *mut libc::c_void, 1) };
            n == 0
        }
    }

    impl Drop for FdProbe {
        fn drop(&mut self) {
            unsafe { libc::close(self.read_end) };
        }
    }

    fn park_install_ud(conn_index: u32, generation: u32) -> crate::completion::UserData {
        crate::completion::UserData::encode(
            crate::completion::OpTag::ParkInstall,
            conn_index,
            generation,
        )
    }

    #[test]
    fn a_park_install_with_no_park_outstanding_closes_the_fd() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let probe = FdProbe::new();

        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);

        assert!(
            probe.was_closed(),
            "a stray install CQE must still close the fd it carries"
        );
    }

    #[test]
    fn a_park_install_for_a_recycled_slot_closes_the_fd() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        let probe = FdProbe::new();

        // A CQE carrying a stale generation: the slot moved on.
        el.handle_park_install(
            park_install_ud(conn_index, generation.wrapping_add(1)),
            probe.installed,
        );

        assert!(probe.was_closed(), "stale generation must close it");
        assert!(el.driver.park_ready.is_empty(), "and must not park");
    }

    #[test]
    fn a_park_abandoned_because_quiesce_broke_closes_the_fd() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        // Offered, or `NotOffered` short-circuits ahead of the term this
        // test exists to exercise and it passes for the wrong reason.
        el.driver.park_offered[conn_index as usize] = true;
        // Quiesce breaks while the install is in flight.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        assert!(el.driver.park_blocker(conn_index).is_some(), "precondition");

        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);

        assert!(probe.was_closed(), "abandon must close the fd");
        assert!(el.driver.park_ready.is_empty(), "and must not park");
    }

    #[test]
    fn a_failed_park_install_leaves_no_park_outstanding() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });

        // A failed install (here ECANCELED); every negative result takes this path.
        el.handle_park_install(park_install_ud(conn_index, generation), -libc::ECANCELED);

        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "a failed park must clear its slot, or the connection can never \
             be parked again"
        );
        assert!(el.driver.park_ready.is_empty());
    }

    #[test]
    fn a_successful_park_lifts_the_connection_and_keeps_the_socket() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        // Deliberately no buffered bytes: `DataPending` refuses while
        // anything is unconsumed, so a connection that reaches a successful
        // park is idle by construction.
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 3,
                generation,
            });

        let probe = FdProbe::new();
        el.handle_park_install(park_install_ud(conn_index, generation), probe.installed);

        assert!(
            !probe.was_closed(),
            "a parked connection keeps its socket: the fd moves, it does not close"
        );
        assert_eq!(el.driver.park_ready.len(), 1, "one connection lifted off");
        let parked = &el.driver.park_ready[0];
        assert_eq!(parked.target, 3);
        assert!(
            parked.pending.is_empty(),
            "an idle connection carries no bytes; the drain is defence in \
             depth, not the normal path"
        );
        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "the in-flight slot clears on success too"
        );
    }

    /// Whether a forced close (`force_finalize_close`, as when a TLS
    /// close_notify deadline passes) of a connection with a send stuck in the
    /// kernel, with `lead` ahead of its `Close`, releases the socket. The send
    /// is a chain part, whose `MSG_WAITALL` keeps it in the kernel, or (with
    /// `chain` false) a send waiting for room, which leaves only its poll
    /// there. Either holds the socket until something ends it; the peer never
    /// reads, and sees a hang-up once the socket is shut down or released
    /// (#586).
    fn forced_close_releases_a_stuck_send(
        lead: crate::backend::uring::ring::CloseLead,
        chain: bool,
    ) -> bool {
        use std::os::fd::AsRawFd;
        let mut config = test_config();
        config.close_lead_override = Some(lead);
        let mut el = make_test_loop_with_config(config);
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (ours, peer) = attach_socketpair(&mut el, conn_index);
        // A small send buffer, so a 16 KiB send cannot complete while the
        // peer does not read. Then only the fixed slot holds our end.
        let small: libc::c_int = 4096;
        unsafe {
            libc::setsockopt(
                ours.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &small as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        drop(ours);

        if chain {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(&[7u8; 16384]).unwrap();
            let payload = UserData::send_payload(slot, generation);
            let ud = UserData::encode(OpTag::Send, conn_index, payload);
            let entry = crate::backend::uring::sqe::Sqe::chain_send(conn_index, ptr, len, ud.raw());
            unsafe { el.driver.ring.push_sqe(&entry) }.expect("push");
            el.driver.send_queues[conn_index as usize].in_flight = true;
        } else {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &[7u8; 16384]).expect("send");
        }
        el.driver.ring.submit_and_get_events().expect("submit");
        el.drain_completions();
        assert!(
            el.driver.send_queues[conn_index as usize].in_flight,
            "the send must still be outstanding"
        );

        // Request the close, then give up on the send.
        el.driver.close_connection(conn_index);
        el.driver.force_finalize_close(conn_index);
        let pending = std::mem::take(&mut el.driver.pending_finalize_closes);
        for c in pending {
            el.driver.try_finalize_close(c);
        }
        for _ in 0..10 {
            el.driver.ring.submit_and_wait(1).expect("submit the close");
            el.drain_completions();
            if el.driver.connections.get(conn_index).is_none() {
                break;
            }
        }
        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the slot was released"
        );

        let mut pfd = libc::pollfd {
            fd: peer.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        // Linux 6.1 releases a closed fixed file about 1.1 s later (`HZ` in
        // `io_rsrc_node_ref_zero`), measured on 6.1.159.
        let n = unsafe { libc::poll(&mut pfd, 1, 2500) };
        n > 0 && pfd.revents & (libc::POLLRDHUP | libc::POLLHUP) != 0
    }

    #[test]
    fn a_forced_close_led_by_a_cancel_releases_a_stuck_send() {
        assert!(forced_close_releases_a_stuck_send(
            crate::backend::uring::ring::CloseLead::CancelAll,
            true
        ));
    }

    #[test]
    fn a_forced_close_led_by_a_shutdown_releases_a_stuck_send() {
        assert!(forced_close_releases_a_stuck_send(
            crate::backend::uring::ring::CloseLead::Shutdown,
            true
        ));
    }

    /// The control: with nothing ahead of the `Close`, the stuck send holds
    /// the socket open.
    #[test]
    fn a_forced_close_led_by_nothing_leaves_a_stuck_send_holding_the_socket() {
        assert!(!forced_close_releases_a_stuck_send(
            crate::backend::uring::ring::CloseLead::Nothing,
            true
        ));
    }

    /// A waiting send leaves only its poll in the kernel, and the cancel of the
    /// poll releases the socket with nothing ahead of the `Close`.
    #[test]
    fn a_forced_close_led_by_nothing_releases_a_waiting_send() {
        assert!(forced_close_releases_a_stuck_send(
            crate::backend::uring::ring::CloseLead::Nothing,
            false
        ));
    }

    /// Committing a parked connection's close does not shut its socket down:
    /// the socket now belongs to another worker, through the installed fd.
    /// Before Linux 6.13 other closes lead with a shutdown (#581). The test
    /// forces that lead, so it checks on every kernel that the park path sets
    /// `socket_handed_off`.
    #[test]
    fn closing_a_parked_slot_leaves_the_handed_off_socket_open() {
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, IntoRawFd};

        // A shutdown lead, whatever the running kernel, so the test guards
        // the `socket_handed_off` check on every kernel.
        let mut config = test_config();
        config.close_lead_override = Some(crate::backend::uring::ring::CloseLead::Shutdown);
        let mut el = make_test_loop_with_config(config);
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // A real connection in the slot, and a second reference to its
        // socket standing in for the fd that `FIXED_FD_INSTALL` returns.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let installed = unsafe { libc::dup(server.as_raw_fd()) };
        assert!(installed >= 0);
        el.driver
            .ring
            .register_files_update(conn_index, &[server.into_raw_fd()])
            .expect("register the server end");

        el.driver.park_offered[conn_index as usize] = true;
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 3,
                generation,
            });
        el.handle_park_install(park_install_ud(conn_index, generation), installed);
        assert_eq!(
            el.driver.park_ready.len(),
            1,
            "the connection was lifted off"
        );

        // Commit the close the park requested, and let the kernel run it.
        let pending = std::mem::take(&mut el.driver.pending_finalize_closes);
        for c in pending {
            el.driver.try_finalize_close(c);
        }
        // The close can post several CQEs (a recv cancel, a shutdown); wait
        // for the `Close`.
        for _ in 0..10 {
            el.driver.ring.submit_and_wait(1).expect("submit the close");
            el.drain_completions();
            if el.driver.connections.get(conn_index).is_none() {
                break;
            }
        }
        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the slot was released"
        );

        // The client sees no FIN, and the handed-off socket still carries
        // data both ways.
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 8];
        let read = client.read(&mut buf);
        assert!(
            matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the client saw {read:?}; the handed-off socket was shut down"
        );
        client.write_all(b"ping").unwrap();
        let parked = &el.driver.park_ready[0];
        let mut handed_off = std::net::TcpStream::from(parked.fd.try_clone().unwrap());
        let mut got = [0u8; 4];
        handed_off.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        handed_off.write_all(b"pong").unwrap();
        client.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pong");
    }

    // ── Opcode probe (tier 3, #443) ────────────────────────────────

    /// The guard that makes a *negative* park probe trustworthy.
    ///
    /// `Send` is a 5.6 opcode and the crate floor is 6.1, so every kernel
    /// that can run this backend has it. If this assertion ever fails, the
    /// probe mechanism itself is broken — and a broken probe does not look
    /// broken: it reports "unsupported" for everything, silently disabling
    /// park on kernels that support it perfectly well.
    #[test]
    #[cfg(uring_engine)]
    fn the_opcode_probe_answers_for_an_opcode_every_kernel_has() {
        let el = make_test_loop();
        assert!(
            el.driver.ring.probe_supported(io_uring::opcode::Send::CODE),
            "the probe reported a 5.6 opcode unsupported on a >=6.1 kernel, \
             so the probe is broken rather than the kernel being old"
        );
    }

    /// Neither of the other two would notice the failure that actually
    /// matters: a probe that answers correctly for `Send` and is cached
    /// consistently, but reports `FixedFdInstall` unsupported on a kernel
    /// that has it. Park would be silently dead everywhere and every test
    /// would still be green.
    ///
    /// So tie the answer to the kernel actually running: at 6.8 or later the
    /// opcode exists and `supports_park()` must be true; below it, false.
    #[test]
    fn park_support_agrees_with_the_running_kernel_version() {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .expect("every Linux has /proc/sys/kernel/osrelease");
        let mut parts = release.trim().split(['.', '-', '+']);
        let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
        let has_opcode = (major, minor) >= (6, 8);

        let el = make_test_loop();
        assert_eq!(
            el.driver.ring.supports_park(),
            has_opcode,
            "kernel {}.{} (from {release:?}) should{} support FIXED_FD_INSTALL",
            major,
            minor,
            if has_opcode { "" } else { " not" }
        );
    }

    /// The stored answer must be the probed answer — catches probing or
    /// caching the wrong opcode, which no runtime behaviour would reveal
    /// until park silently never ran.
    #[test]
    #[cfg(uring_engine)]
    fn park_support_matches_a_fresh_probe_of_the_opcode() {
        let el = make_test_loop();
        assert_eq!(
            el.driver.ring.supports_park(),
            el.driver
                .ring
                .probe_supported(io_uring::opcode::FixedFdInstall::CODE),
        );
    }

    #[test]
    fn the_park_drain_of_an_idle_connection_is_empty() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        assert!(
            el.driver.take_pending_for_park(conn_index).is_empty(),
            "no received bytes means no chunks, not one empty chunk"
        );
    }

    // ── Send path tests ────────────────────────────────────────────

    #[test]
    fn handle_send_complete_releases_pool_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Allocate a pool slot (simulating send_nowait).
        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Simulate send CQE: all bytes sent.
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        // Pool slot should be released.
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released after send complete"
        );
    }

    #[test]
    fn handle_send_error_releases_pool_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Simulate send error (ECONNRESET = -104).
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released after send error"
        );
    }

    #[test]
    fn handle_send_settles_the_awaited_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let id = await_slot(&mut el, conn_index, slot, data.len() as u32);

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        assert_eq!(
            send_result(&mut el, id)
                .expect("send result not stored")
                .expect("the send succeeded"),
            data.len() as u32
        );
    }

    #[test]
    fn handle_send_multichunk_wakes_once_with_total() {
        // A logical send larger than one pool slot is split into several
        // chunks. They complete as separate CQEs when a run cannot carry them
        // (no free slab entry, or more than 32 slots); this test builds that
        // state by hand. Only the final chunk's slot carries the send's id,
        // so the send settles once, when the whole logical send has drained,
        // with its full length, not the first chunk's short count.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Chunk 0 is in flight; chunk 1 is queued behind it. Distinct sizes
        // so the total can't be mistaken for either chunk alone.
        let chunk0 = vec![b'a'; 16384];
        let chunk1 = vec![b'b'; 4096];
        let total = (chunk0.len() + chunk1.len()) as u32;
        let (slot0, _p0, _l0) = el.driver.send_copy_pool.copy_in(&chunk0).unwrap();
        let (slot1, ptr1, len1) = el.driver.send_copy_pool.copy_in(&chunk1).unwrap();
        // One logical send split across two slots: only the last carries the id.
        let id = await_slot(&mut el, conn_index, slot1, total);

        // Queue chunk 1 as a real BuiltSend behind the in-flight chunk 0.
        let ud1 = UserData::encode(OpTag::Send, conn_index, slot1 as u32);
        let entry1 =
            crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr1, len1, ud1.raw());
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(crate::handler::BuiltSend {
                entry: entry1,
                pool_slot: slot1,
                slab_idx: u16::MAX,
            });
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // Chunk 0 completes. The send must NOT settle yet.
        let ud0 = UserData::encode(OpTag::Send, conn_index, slot0 as u32);
        el.test_dispatch_cqe(ud0.raw(), chunk0.len() as i32, 0);
        assert!(
            send_result(&mut el, id).is_none(),
            "send settled on the first chunk of a multi-chunk send"
        );

        // Chunk 1 completes. The send settles once, with its whole length.
        el.test_dispatch_cqe(ud1.raw(), chunk1.len() as i32, 0);
        assert_eq!(
            send_result(&mut el, id)
                .expect("send not settled after its final chunk")
                .expect("the send succeeded"),
            total,
            "settled with a short count instead of the full logical send"
        );
    }

    /// A copied send wider than the free part of the pool must be refused
    /// before anything is copied or queued. Before the up-front reservation,
    /// the chunks that fit were queued (or pushed to the ring) and the caller
    /// got `Err` for the tail, so a retry duplicated the prefix on the wire.
    #[test]
    fn send_wider_than_free_slots_commits_nothing() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(4, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        // Hold three of the four slots so only one is free.
        let (_f1, _, _) = el.driver.send_copy_pool.copy_in(b"a").unwrap();
        let (_f2, _, _) = el.driver.send_copy_pool.copy_in(b"b").unwrap();
        let (_f3, _, _) = el.driver.send_copy_pool.copy_in(b"c").unwrap();
        assert_eq!(el.driver.send_copy_pool.free_count(), 1);

        // 100 bytes over 64-byte slots needs 2 slots; only 1 is free.
        let data = [0u8; 100];
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &data)
        };
        let err = result.expect_err("send needing 2 slots with 1 free must fail");
        assert_eq!(err.kind(), io::ErrorKind::Other);

        // Nothing was taken from the pool and nothing was queued or pushed.
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            1,
            "a refused send must not consume pool slots"
        );
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.queue.is_empty(), "a refused send must queue nothing");
        assert!(!state.in_flight, "a refused send must not push an SQE");
    }

    /// A send that needs more slots than the whole pool holds can never
    /// succeed, so it is refused up front with `InvalidInput` instead of
    /// committing the first `slot_count` chunks and failing on the rest.
    #[test]
    fn send_wider_than_the_pool_is_invalid_input() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(4, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        assert_eq!(el.driver.send_copy_pool.free_count(), 4);

        // 300 bytes over 64-byte slots needs 5 slots; the pool has 4.
        let data = [0u8; 300];
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &data)
        };
        let err = result.expect_err("send wider than the pool must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            4,
            "a refused send must not consume pool slots"
        );
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.queue.is_empty(), "a refused send must queue nothing");
        assert!(!state.in_flight, "a refused send must not push an SQE");
    }

    /// Guards the streaming rewrite: a multi-slot send that is admitted still
    /// queues one entry per chunk, in order.
    #[test]
    fn multi_chunk_send_still_queues_all_chunks_in_order() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(6, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        // Pool of 6, one slot held, a 4-slot send: the final free count then
        // tells "reservation consumed" (1 free) from "reservation still
        // outstanding" (0 free).
        let (_held, _, _) = el.driver.send_copy_pool.copy_in(b"x").unwrap();
        assert_eq!(el.driver.send_copy_pool.free_count(), 5);

        // With a send already in flight, every chunk is queued rather than
        // pushed to the ring, so the whole logical send is inspectable.
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // 200 bytes over 64-byte slots: 64 + 64 + 64 + 8 = 4 chunks.
        let data = [0u8; 200];
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &data)
        };
        result.expect("a send that fits the free pool must be admitted");

        let state = &el.driver.send_queues[conn_index as usize];
        assert_eq!(state.queue.len(), 4, "one queued entry per chunk");
        let lens: Vec<u32> = state
            .queue
            .iter()
            .map(|b| match b.entry.op {
                crate::backend::uring::sqe::Op::Send { len, .. } => len,
                op => panic!("expected a send, got {op:?}"),
            })
            .collect();
        assert_eq!(lens, vec![64, 64, 64, 8], "chunks queued in order");
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            1,
            "every reserved slot was filled and the reservation fully consumed"
        );
    }

    // ── SQ-pressure parking tests ──────────────────────────────────
    //
    // A built send whose SQE cannot be pushed (SQ still full after submit)
    // is parked at its queue head with `in_flight = true` and re-pushed by
    // `drain_send_retries`; it is never dropped. `Ring::force_push_failures`
    // stands in for the full SQ.

    /// Build a plain copied `Send` entry for `data` in a fresh pool slot, the
    /// way `DriverCtx::send` does, so tests can hand entries to the queue.
    fn built_copy_send(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        data: &[u8],
    ) -> crate::handler::BuiltSend {
        let generation = el.driver.connections.generation(conn_index);
        let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        let entry = crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw());
        crate::handler::BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
        }
    }

    /// Register one end of a socketpair as `conn_index`'s fixed file so a
    /// real `Send` SQE on `Fixed(conn_index)` completes against it. Returns
    /// both ends; the caller keeps them alive for the test's duration.
    fn attach_socketpair(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
    ) -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::AsRawFd;
        let (ours, peer) = make_socketpair();
        el.driver
            .ring
            .register_files_update(conn_index, &[ours.as_raw_fd()])
            .expect("register_files_update failed");
        (ours, peer)
    }

    /// Non-blocking read of up to `buf.len()` bytes from `fd`. Returns the
    /// byte count, or `None` on `EAGAIN`/`EWOULDBLOCK`.
    fn try_recv(fd: &std::os::fd::OwnedFd, buf: &mut [u8]) -> Option<usize> {
        use std::os::fd::AsRawFd;
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            assert!(
                matches!(err.kind(), io::ErrorKind::WouldBlock),
                "unexpected recv error: {err}"
            );
            return None;
        }
        Some(n as usize)
    }

    /// A push failure on an idle connection's first send parks the entry
    /// (previously `DriverCtx::send` returned `Err`, and for TLS the
    /// ciphertext — with rustls' sequence already advanced — was lost). The
    /// next iteration's `drain_send_retries` pushes it and the bytes reach
    /// the peer exactly once.
    #[test]
    fn first_push_failure_parks_and_completes_next_iteration() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        el.driver.ring.force_push_failures(1);
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello")
        };
        result.expect("SQ pressure must not surface as a send error");

        // Parked: still queued, in_flight held, registered for retry with
        // attempts 0, and the pool slot still owned by the queued entry.
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert_eq!(state.queue.len(), 1, "the entry must stay queued");
            assert!(state.in_flight, "a parked send holds in_flight");
        }
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)],
            "the connection must be registered for one retry"
        );
        assert_eq!(el.driver.send_copy_pool.free_count(), 7);

        // Next iteration: the retry pushes the parked entry.
        el.drain_send_retries();
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "the retry must pop the entry once its SQE is pushed"
        );
        assert!(
            el.driver.pending_send_retries.is_empty(),
            "a successful retry must not re-register"
        );
        assert!(el.driver.send_queues[conn_index as usize].in_flight);

        // Drive the send CQE through the real ring.
        el.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        el.drain_completions();
        assert!(
            !el.driver.send_queues[conn_index as usize].in_flight,
            "the send CQE must clear in_flight"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the send CQE must release the pool slot"
        );

        // The peer sees the bytes exactly once.
        let mut buf = [0u8; 16];
        assert_eq!(
            try_recv(&peer, &mut buf),
            Some(5),
            "peer must receive the send"
        );
        assert_eq!(&buf[..5], b"hello");
        assert_eq!(
            try_recv(&peer, &mut buf),
            None,
            "the parked send must not be delivered twice"
        );
    }

    /// A push failure on the queued tail of a stream must leave the whole
    /// queue intact and in order. Before parking, both failure arms released
    /// the entry *and everything behind it*: the prefix was on the wire, the
    /// tail vanished, and no waiter was ever woken.
    #[test]
    fn queued_tail_push_failure_parks_without_dropping_the_queue() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // No free slab entry, so the queued copy sends cannot coalesce
        // (#628 lets a run span sends) and the single-entry push path runs.
        el.driver.send_slab = crate::buffer::send_slab::InFlightSendSlab::new(0);
        // A send is in flight; behind it: one independent send and then the
        // two chunks of a second logical send.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let head = built_copy_send(&mut el, conn_index, b"X");
        let chunk0 = built_copy_send(&mut el, conn_index, b"AA");
        let chunk1 = built_copy_send(&mut el, conn_index, b"BBB");
        let expected_slots = [head.pool_slot, chunk0.pool_slot, chunk1.pool_slot];
        {
            let q = &mut el.driver.send_queues[conn_index as usize].queue;
            q.push_back(head);
            q.push_back(chunk0);
            q.push_back(chunk1);
        }
        assert_eq!(el.driver.send_copy_pool.free_count(), 5);

        // The in-flight send completes and the CQE path tries to push the
        // head; the SQ refuses.
        el.driver.ring.force_push_failures(1);
        assert!(
            !el.driver.submit_next_queued(conn_index),
            "a refused push must report false"
        );
        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(
                slots,
                expected_slots.to_vec(),
                "queue must be intact and in order"
            );
            assert!(state.in_flight, "a parked send holds in_flight");
        }
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            5,
            "parking must not release any pool slot"
        );
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)]
        );

        // The retry pushes the head; the two chunks behind it are untouched.
        el.drain_send_retries();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(
                slots,
                expected_slots[1..].to_vec(),
                "only the head may be popped by the retry"
            );
            assert!(state.in_flight);
        }
        assert!(el.driver.pending_send_retries.is_empty());
        assert_eq!(el.driver.send_copy_pool.free_count(), 5);
    }

    /// When the coalesced `sendmsg` for a run of chunks cannot be pushed,
    /// only the slab entry is released. `allocate_coalesced` records the pool
    /// slots in the entry but does not take ownership of them; the queued
    /// `BuiltSend`s still do, and they stay queued.
    #[test]
    fn coalesced_push_failure_releases_only_the_slab_entry() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // Three chunks of one logical send behind an in-flight send: a
        // coalescable run of three.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let c0 = built_copy_send(&mut el, conn_index, b"aa");
        let c1 = built_copy_send(&mut el, conn_index, b"bb");
        let c2 = built_copy_send(&mut el, conn_index, b"cc");
        let expected_slots = [c0.pool_slot, c1.pool_slot, c2.pool_slot];
        {
            let q = &mut el.driver.send_queues[conn_index as usize].queue;
            q.push_back(c0);
            q.push_back(c1);
            q.push_back(c2);
        }
        let slab_free = el.driver.send_slab.free_count();
        assert_eq!(el.driver.send_copy_pool.free_count(), 5);

        el.driver.ring.force_push_failures(1);
        assert!(!el.driver.submit_next_queued(conn_index));

        assert_eq!(
            el.driver.send_slab.free_count(),
            slab_free,
            "the coalesced slab entry must be released on a refused push"
        );
        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(
                slots,
                expected_slots.to_vec(),
                "the run must stay queued in order"
            );
            assert!(state.in_flight);
        }
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            5,
            "the queued entries still own their pool slots"
        );
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)]
        );

        // The retry re-coalesces the run and pushes it: the queue drains
        // into one slab entry.
        el.drain_send_retries();
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "the retry must push the whole coalesced run"
        );
        assert_eq!(
            el.driver.send_slab.free_count(),
            slab_free - 1,
            "the pushed run must hold one slab entry"
        );
        assert!(el.driver.pending_send_retries.is_empty());
    }

    /// Persistent SQ starvation is terminal for the connection, never a
    /// silent drop: after two failed retries the parked queue is released,
    /// the awaited send resolves `Err`, and the connection closes — the same
    /// shape as `drain_copy_retries`' give-up.
    #[test]
    fn send_retry_cap_fails_the_send_and_closes() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let id = el.executor.register_send(conn_index);

        // The initial push and both retries are refused.
        el.driver.ring.force_push_failures(3);
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_awaited(token, b"hello", id)
        };
        result.expect("SQ pressure must not surface as a send error");
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)]
        );

        // Retry 1 fails: re-parked with attempts 1.
        el.drain_send_retries();
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 1)],
            "a failed retry must re-park with the incremented attempt count"
        );
        assert_eq!(el.driver.send_queues[conn_index as usize].queue.len(), 1);
        assert!(send_result(&mut el, id).is_none());

        // Retry 2 fails: re-parked with attempts 2.
        el.drain_send_retries();
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 2)]
        );
        assert_eq!(el.driver.send_queues[conn_index as usize].queue.len(), 1);
        assert!(send_result(&mut el, id).is_none());

        // Retry 3 hits the cap: give up.
        el.drain_send_retries();
        assert!(el.driver.pending_send_retries.is_empty());
        assert!(
            matches!(send_result(&mut el, id), Some(Err(_))),
            "expected the send to be failed by the retry cap"
        );
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(state.queue.is_empty(), "give-up must release the queue");
            assert!(!state.in_flight, "give-up must clear in_flight");
        }
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "give-up must return the parked entry's pool slot"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "give-up must close the connection"
        );
    }

    /// A parked send satisfies `in_flight` for the close-deferral machinery:
    /// a close requested while parked waits for the parked bytes to go out,
    /// and their CQE registers it for the end-of-iteration drain, which
    /// commits it. Without this, the Close SQE would race (or truncate) the
    /// parked send.
    #[test]
    fn parked_send_defers_a_requested_close() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        el.driver.ring.force_push_failures(1);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello").expect("send must park, not fail");
        }
        assert!(el.driver.send_queues[conn_index as usize].in_flight);

        // Close while parked: deferred, not submitted.
        el.driver.close_connection(conn_index);
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(state.close_pending, "close must defer behind a parked send");
            assert!(
                !state.close_submitted,
                "Close must not be submitted while a send is parked"
            );
        }
        // Re-driving the finalize (as the loop's end-of-iteration drain does)
        // must still hold off.
        el.driver.try_finalize_close(conn_index);
        assert!(
            !el.driver.send_queues[conn_index as usize].close_submitted,
            "try_finalize_close must wait for the parked send"
        );

        // The retry pushes the parked send; the close still waits for its CQE.
        el.drain_send_retries();
        assert!(el.driver.send_queues[conn_index as usize].queue.is_empty());
        assert!(
            !el.driver.send_queues[conn_index as usize].close_submitted,
            "Close must wait for the pushed send's CQE"
        );

        // The send CQE drains the queue. The Close is owed to the
        // end-of-iteration drain, not committed inside the completion drain:
        // a task woken in the same batch has not been polled yet.
        el.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        el.drain_completions();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(!state.in_flight);
            assert!(
                state.close_pending,
                "the close stays pending until the drain"
            );
            assert!(
                !state.close_submitted,
                "the completion drain must not commit the Close"
            );
        }
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));
        el.finalize_pending_closes();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(!state.close_pending, "the drain finalizes the close");
            assert!(
                state.close_submitted,
                "the deferred Close must be submitted once the parked send drained"
            );
        }

        // And the parked bytes did reach the peer before the close.
        let mut buf = [0u8; 16];
        assert_eq!(try_recv(&peer, &mut buf), Some(5));
        assert_eq!(&buf[..5], b"hello");
    }

    /// `queue_built_sends` (the TLS ciphertext path) is infallible: a push
    /// failure on the first entry parks it and queues the rest behind it in
    /// order. Previously the first entry was released, the rest released
    /// too, and three callers discarded the `Err` — a handshake reply or
    /// close_notify vanished silently under SQ pressure.
    /// A retry entry that outlives its park must not push a second SQE.
    /// Park A with B queued behind it, let "another path" push A directly
    /// (`submit_next_queued` clears `parked`), then run the drain: B must
    /// stay queued because A is now in flight.
    #[test]
    fn stale_retry_entry_does_not_push_a_second_sqe() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        // No free slab entry, so the queued copy sends cannot coalesce
        // (#628 lets a run span sends) and the single-entry push path runs.
        el.driver.send_slab = crate::buffer::send_slab::InFlightSendSlab::new(0);
        let generation = el.driver.connections.generation(conn_index);

        let a = built_copy_send(&mut el, conn_index, b"aaa");
        let b = built_copy_send(&mut el, conn_index, b"bbb");
        let slot_b = b.pool_slot;
        el.driver.ring.force_push_failures(1);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.queue_built_sends(conn_index, vec![a, b]);
        }
        assert!(el.driver.send_queues[conn_index as usize].parked);
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)]
        );

        // Another path pushes the head first.
        assert!(el.driver.submit_next_queued(conn_index));
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(!state.parked, "a successful push clears parked");
            assert_eq!(state.queue.len(), 1);
            assert!(state.in_flight);
        }

        // The stale retry entry must be a no-op: B stays queued behind the
        // in-flight A rather than becoming a parallel SQE on the stream.
        el.drain_send_retries();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert_eq!(state.queue.len(), 1, "stale retry pushed a second SQE");
            assert_eq!(state.queue[0].pool_slot, slot_b);
            assert!(state.in_flight);
        }
        assert!(el.driver.pending_send_retries.is_empty());
    }

    #[test]
    fn queue_built_sends_parks_under_sq_pressure() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        // No free slab entry, so the queued copy sends cannot coalesce
        // (#628 lets a run span sends) and the single-entry push path runs.
        el.driver.send_slab = crate::buffer::send_slab::InFlightSendSlab::new(0);
        let generation = el.driver.connections.generation(conn_index);

        let first = built_copy_send(&mut el, conn_index, b"one");
        let second = built_copy_send(&mut el, conn_index, b"two");
        let expected_slots = [first.pool_slot, second.pool_slot];
        assert_eq!(el.driver.send_copy_pool.free_count(), 6);

        el.driver.ring.force_push_failures(1);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.queue_built_sends(conn_index, vec![first, second]);
        }

        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(
                slots,
                expected_slots.to_vec(),
                "both entries must be queued in order"
            );
            assert!(state.in_flight, "the parked head holds in_flight");
        }
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)]
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            6,
            "parking must not touch the pool"
        );

        // The retry pushes the head alone (the slab has no entry for a run);
        // the second stays queued.
        el.drain_send_retries();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(slots, expected_slots[1..].to_vec());
            assert!(state.in_flight);
        }
        assert!(el.driver.pending_send_retries.is_empty());
    }

    /// Two TLS ciphertext slots from one send go to the kernel as one
    /// `sendmsg`.
    #[test]
    fn queue_built_sends_submits_two_tls_slots_as_one_sendmsg() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let tls_send = |el: &mut AsyncEventLoop<NoopHandler>, data: &[u8]| {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(data).unwrap();
            let ud = UserData::encode(
                OpTag::TlsSend,
                conn_index,
                UserData::send_payload(slot, generation),
            );
            crate::handler::BuiltSend {
                entry: crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw()),
                pool_slot: slot,
                slab_idx: u16::MAX,
            }
        };
        let first = tls_send(&mut el, b"record one");
        let second = tls_send(&mut el, b"record two");
        {
            let mut ctx = el.driver.make_ctx();
            ctx.queue_built_sends(conn_index, vec![first, second]);
        }
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.queue.is_empty(), "both slots went out as one SQE");
        assert!(state.in_flight);
        let pushed = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(pushed.tag(), Some(OpTag::SendMsgCoalesced));
    }

    /// A multi-slot send that finds the SQ full parks its whole run, with
    /// the first attempt recorded, and the retry sends the run as one
    /// `sendmsg`.
    #[test]
    fn a_multi_slot_send_parks_its_run_when_the_sq_is_full() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        el.driver.ring.force_push_failures(1);
        el.driver
            .make_ctx()
            .send(token, &[b'p'; 150])
            .expect("send");
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert_eq!(state.queue.len(), 3, "the run stays queued");
            assert!(state.in_flight && state.parked);
        }
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)],
            "registered once, at attempt 0"
        );
        el.drain_send_retries();
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.queue.is_empty(), "the retry sent the whole run");
        assert_eq!(
            UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data).tag(),
            Some(OpTag::SendMsgCoalesced)
        );
        assert!(el.driver.pending_send_retries.is_empty());
    }

    #[test]
    fn handle_send_pipelined_independent_sends_wake_separately() {
        // Two awaited sends pipelined on one connection share the send
        // queue, and both are awaited at once. Each settles with its own
        // byte count when its own completion lands, not with a running
        // total and not with the other's.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Each is its own logical send. Different lengths, so neither can
        // pass for the other.
        let a = b"HELLO";
        let b = b"WORLD!!";
        let (slot_a, _pa, _la) = el.driver.send_copy_pool.copy_in(a).unwrap();
        let (slot_b, ptr_b, len_b) = el.driver.send_copy_pool.copy_in(b).unwrap();
        let id_a = await_slot(&mut el, conn_index, slot_a, a.len() as u32);
        let id_b = await_slot(&mut el, conn_index, slot_b, b.len() as u32);

        // Send A is in flight; send B is queued behind it.
        let ud_b = UserData::encode(OpTag::Send, conn_index, slot_b as u32);
        let entry_b =
            crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr_b, len_b, ud_b.raw());
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(crate::handler::BuiltSend {
                entry: entry_b,
                pool_slot: slot_b,
                slab_idx: u16::MAX,
            });
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // A completes: A settles with its own count; B is still pending.
        let ud_a = UserData::encode(OpTag::Send, conn_index, slot_a as u32);
        el.test_dispatch_cqe(ud_a.raw(), a.len() as i32, 0);
        assert_eq!(
            send_result(&mut el, id_a)
                .expect("send A was not settled")
                .expect("send A succeeded"),
            a.len() as u32
        );
        assert!(
            send_result(&mut el, id_b).is_none(),
            "send B settled by A's completion"
        );

        // B completes: B settles with its own count, not A + B.
        el.test_dispatch_cqe(ud_b.raw(), b.len() as i32, 0);
        assert_eq!(
            send_result(&mut el, id_b)
                .expect("send B was not settled")
                .expect("send B succeeded"),
            b.len() as u32
        );
    }

    // ── Stale-send identity tests (CQE outlives its connection slot) ──

    /// A Send CQE whose connection slot was released and reused must only
    /// release the orphaned pool slot — never touch the new occupant's
    /// state. The partial-send result is the nastiest case: misattribution
    /// would resubmit the dead connection's bytes onto the new occupant's
    /// socket.
    #[test]
    fn stale_send_cqe_for_reused_index_releases_slot_only() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);

        // A copy send in flight when the connection goes away.
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"orphaned bytes").unwrap();
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, old_gen),
        );

        // Close + reuse: generation bumps, same index preferred by allocate.
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index, "test premise: index reused");
        assert_ne!(el.driver.connections.generation(conn_index), old_gen);

        // The new occupant has its own send slot outstanding.
        let (slot2, _p2, _l2) = el.driver.send_copy_pool.copy_in(b"new occupant").unwrap();

        // Stale partial-send CQE for the old occupant.
        el.test_dispatch_cqe(ud.raw(), 3, 0);

        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "orphaned slot must be released by its stale CQE"
        );
        assert!(
            el.driver.send_copy_pool.in_use(slot2),
            "new occupant's slot must be untouched"
        );

        // Error-result variant: must not drain the new occupant's queue or
        // fail its send.
        let (slot3, _p3, _l3) = el.driver.send_copy_pool.copy_in(b"orphan two").unwrap();
        let ud3 = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot3, old_gen),
        );
        el.test_dispatch_cqe(ud3.raw(), -(libc::ECANCELED), 0);
        assert!(!el.driver.send_copy_pool.in_use(slot3));
        assert!(el.driver.send_copy_pool.in_use(slot2));
    }

    /// A ZC main+notification CQE pair that outlives its connection slot
    /// must run the notification accounting and release the slab entry,
    /// with no per-connection effects.
    #[test]
    fn stale_zc_cqe_for_reused_index_resource_only() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, old_gen, &iovecs, u16::MAX, guards, 0, 100)
            .unwrap();
        let free_before = el.driver.send_slab.free_count();

        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index);

        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        // Stale main CQE (success): notification still in flight — the entry
        // must survive until it lands. IORING_CQE_F_MORE is how the kernel
        // says a notification is coming, and a successful ZC send always
        // carries it.
        el.test_dispatch_cqe(ud.raw(), 100, 2);
        assert!(el.driver.send_slab.in_use(slab_idx));
        // Stale notification CQE: releases the entry.
        el.test_dispatch_cqe(ud.raw(), 0, 8);
        assert_eq!(
            el.driver.send_slab.free_count(),
            free_before + 1,
            "slab entry must be released after the stale notification"
        );
    }

    /// A reused connection slot must start with clean send state. The
    /// previous occupant's close can leave `in_flight`/`close_pending` set
    /// when its final send CQE outlives the slot (the identity check
    /// correctly refuses to clear another occupant's flags) — without the
    /// activation-time reset, the next occupant's first send parks forever
    /// behind a completion that will never come. (Observed as
    /// async_select_with_sleep hanging when run after any other test whose
    /// probe connection recycled index 0.)
    #[test]
    fn reused_slot_starts_with_clean_send_state() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Poison the state exactly as an orphaned deferred close leaves it.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.driver.send_queues[conn_index as usize].close_pending = true;
        el.driver.close_notify_armed.push(conn_index);

        // Slot recycles; the activation path resets send state.
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index);
        el.driver.reset_send_state(conn_index);

        let state = &el.driver.send_queues[conn_index as usize];
        assert!(!state.in_flight, "reused slot must not inherit in_flight");
        assert!(!state.close_pending);
        assert!(!el.driver.close_notify_armed.contains(&conn_index));
    }

    /// After the Close SQE is submitted (close_submitted), a late partial
    /// send CQE must release its slot and fail its send instead of
    /// resubmitting the remainder — the resubmit would race the in-flight
    /// Close (post-force-close scenario).
    #[test]
    fn partial_send_after_close_submitted_releases_instead_of_resubmitting() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // A send in flight; close is forced past it (deadline path):
        // in_flight cleared, close_pending set, finalize submits Close.
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"stuck send").unwrap();
        el.driver.send_queues[conn_index as usize].close_pending = true;
        el.driver.force_finalize_close(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_submitted,
            "finalize must mark close_submitted"
        );

        // The stuck send's partial CQE arrives pre-bump (generation still
        // matches): the slot must be released, not resubmitted.
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "slot must be released instead of resubmitted past a submitted Close"
        );
    }

    /// The guard predicate is `close_submitted`, deliberately NOT
    /// `recv_finished()`: during a deferred close's drain window
    /// (read half already finished, Close SQE not yet submitted), in-flight
    /// sends must still resubmit partials so their bytes reach the wire.
    /// This test pins the predicate: a finished read half alone must not
    /// suppress a resubmit.
    #[test]
    fn half_close_does_not_suppress_partial_resubmit() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            // The read half finished and a close requested (the task returned
            // after the peer's FIN) but not yet committed: the deferred-close
            // drain window this test exists to cover.
            cs.note_eof(false);
            cs.lifecycle = Lifecycle::Closing;
        }
        assert!(!el.driver.send_queues[conn_index as usize].close_submitted);

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"response").unwrap();
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        // Partial completion: the remainder must be resubmitted (slot stays
        // in use), not cancelled.
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "half-close must not cancel a legitimate in-progress send"
        );
    }

    /// close_connection must defer the Close SQE while a send chain's SQEs
    /// are still in the kernel, and finalize once the chain drains.
    /// A plain send issued while a chain is in flight must queue behind it.
    /// io_uring does not order independent SQEs, so pushing it directly let
    /// its bytes reach the peer interleaved with the chain's. Chain completion
    /// already drains the send queue (`fire_chain_complete`); the send path
    /// just never queued into it while only a chain was active.
    #[test]
    fn a_plain_send_queues_behind_an_active_chain() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        el.driver.chain_table.start(conn_index, 1);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"after the chain")
                .expect("a send behind a chain is accepted");
        }
        assert_eq!(
            el.driver.send_queues[conn_index as usize].queue.len(),
            1,
            "a send issued while a chain is active must wait in the queue"
        );

        // The chain completes; its completion submits what queued behind it.
        let event = el.driver.chain_table.on_operation_cqe(conn_index, 100);
        assert!(matches!(event, ChainEvent::Complete { .. }));
        el.fire_chain_complete(conn_index);
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.queue.is_empty(), "the queued send was not submitted");
        assert!(state.in_flight, "the queued send is now in flight");

        // And the next send waits behind it rather than pushing past it.
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"next").expect("accepted");
        }
        assert_eq!(
            el.driver.send_queues[conn_index as usize].queue.len(),
            1,
            "a send issued after the chain completed overtook the queued one"
        );
    }

    /// A chain issued while plain sends are queued or in flight would
    /// overtake them, and the plain queue cannot hold a linked chain, so the
    /// chain is refused with `WouldBlock` and releases what it built.
    #[test]
    fn a_chain_refuses_while_plain_sends_are_in_flight() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let free_before = el.driver.send_copy_pool.free_count();

        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_chain(token).copy(b"chained").finish()
        };
        let err = result.expect_err("a chain behind in-flight plain sends must be refused");
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(
            !el.driver.chain_table.is_active(conn_index),
            "a refused chain must not start"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before,
            "a refused chain must release the slots it built"
        );
    }

    /// Guarded memory for a chain's zero-copy part.
    struct ChainTestGuard(Box<[u8]>);

    impl crate::guard::SendGuard for ChainTestGuard {
        fn as_ptr_len(&self) -> (*const u8, u32) {
            (self.0.as_ptr(), self.0.len() as u32)
        }
        fn region(&self) -> crate::buffer::fixed::RegionId {
            crate::buffer::fixed::RegionId::UNREGISTERED
        }
    }

    /// A stale handle's chain must not be submitted on the slot's new
    /// occupant. Its SQEs would write to the new occupant's socket, and the
    /// `chain_table` entry it started would never complete, since the CQEs
    /// carry the old generation.
    #[test]
    fn a_chain_refuses_a_stale_handle() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, old_gen);

        el.driver.connections.release(conn_index);
        let reused = accept_connection(&mut el);
        assert_eq!(reused, conn_index, "test premise: index reused");
        let new_gen = el.driver.connections.generation(conn_index);
        assert_ne!(new_gen, old_gen);

        let pool_free = el.driver.send_copy_pool.free_count();
        let slab_free = el.driver.send_slab.free_count();
        let result = with_driver_state(&mut el, || {
            stale.send_chain(|chain| {
                chain
                    .copy(b"chained")
                    .parts()
                    .copy(b"head")
                    .guard(crate::guard::GuardBox::new(ChainTestGuard(
                        vec![7u8; 8192].into_boxed_slice(),
                    )))
                    .add()
                    .finish()
            })
        });
        let Err(err) = result else {
            panic!("a stale handle's chain must be refused");
        };
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert!(
            !el.driver.chain_table.is_active(conn_index),
            "a stale handle must not start a chain on the new occupant"
        );
        assert_eq!(el.driver.send_copy_pool.free_count(), pool_free);
        assert_eq!(el.driver.send_slab.free_count(), slab_free);

        // The control: the new occupant's own handle still chains.
        let current = ConnCtx::new(conn_index, new_gen);
        let result = with_driver_state(&mut el, || {
            current.send_chain(|chain| chain.copy(b"chained").finish())
        });
        assert!(result.is_ok(), "the current handle must still chain");
        assert!(el.driver.chain_table.is_active(conn_index));
    }

    /// A chain on a handle whose connection is gone and whose slot is free
    /// is refused before anything is submitted.
    #[test]
    fn a_chain_refuses_a_handle_whose_slot_is_free() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        el.driver.connections.release(conn_index);
        let free_before = el.driver.send_copy_pool.free_count();

        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_chain(token).copy(b"chained").finish()
        };
        let err = result.expect_err("a chain on a free slot must be refused");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert!(!el.driver.chain_table.is_active(conn_index));
        assert_eq!(el.driver.send_copy_pool.free_count(), free_before);
    }

    #[test]
    fn close_defers_while_chain_active() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.chain_table.start(conn_index, 1);
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "close must stay pending while the chain is active"
        );

        // The chain's operation CQE arrives and completes it; the
        // end-of-iteration drain then commits the close.
        let event = el.driver.chain_table.on_operation_cqe(conn_index, 100);
        assert!(matches!(event, ChainEvent::Complete { .. }));
        el.fire_chain_complete(conn_index);
        el.finalize_pending_closes();
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "close must finalize once the chain drains"
        );
    }

    /// A copy-only batch, chain send or chain part wider than one send-pool
    /// slot can never fit: it is refused with `InvalidInput`, as the same
    /// data beside a guard part already is, not with the retryable `Other`
    /// of an exhausted pool. Nothing is taken from the pool.
    #[test]
    fn copy_data_wider_than_a_slot_is_invalid_input_on_every_builder() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(4, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let half = [0u8; 40];
        let whole = [0u8; 100];

        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_parts(token)
                .copy(&half)
                .copy(&half)
                .submit()
                .expect_err("80 bytes do not fit a 64-byte slot")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "send_parts: {err}");

        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_chain(token)
                .copy(&whole)
                .finish()
                .expect_err("100 bytes do not fit a 64-byte slot")
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::InvalidInput,
            "send_chain copy: {err}"
        );

        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_chain(token)
                .parts()
                .copy(&half)
                .copy(&half)
                .add()
                .finish()
                .expect_err("80 bytes do not fit a 64-byte slot")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "chain part: {err}");

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            4,
            "nothing was taken"
        );
        assert!(el.driver.send_queues[conn_index as usize].queue.is_empty());
        assert!(!el.driver.chain_table.is_active(conn_index));
    }

    /// A `send_parts` batch whose parts carry no bytes queues nothing: no
    /// SQE, no pool slot, and an awaited one resolves `Ok(0)`, as a `send`
    /// of an empty buffer does. A zero-length Send SQE would complete with
    /// 0, which `handle_send` treats as a failed send and drains the queue
    /// behind it.
    #[test]
    fn a_zero_length_send_parts_batch_queues_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let free = el.driver.send_copy_pool.free_count();

        el.driver
            .make_ctx()
            .send_parts(token)
            .copy(b"")
            .submit()
            .expect("nothing to send is not an error");
        assert!(!el.driver.send_queues[idx].in_flight, "no SQE was pushed");
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free,
            "no slot was taken"
        );

        let id = el.executor.register_send(conn_index);
        el.driver
            .make_ctx()
            .send_parts(token)
            .copy(b"")
            .copy(b"")
            .submit_awaited(id)
            .expect("nothing to send is not an error");
        assert!(!el.driver.send_queues[idx].in_flight);
        assert_eq!(el.driver.send_copy_pool.free_count(), free);
        el.drain_settled_sends();
        assert_eq!(
            el.executor
                .take_send_result(id)
                .expect("settled")
                .expect("ok"),
            0,
            "the awaited batch resolves with its length"
        );
    }

    /// A `Shutdown` SQE the ring refuses is kept and pushed later, as a
    /// refused send or Close is, so the write half reads `Shutdown` from the
    /// request on and the Close waits for the FIN's completion. The old code
    /// set the write half back to `Open` and relied on the application
    /// calling `shutdown_write` again.
    #[test]
    fn a_refused_shutdown_sqe_still_requests_the_fin() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        el.driver.ring.force_push_failures(1);
        el.driver.make_ctx().shutdown_write(token);
        assert!(
            matches!(
                el.driver.connections.get(conn_index).unwrap().write,
                crate::connection::WriteHalf::Shutdown
            ),
            "the FIN is requested, not forgotten"
        );
        assert!(
            el.driver.send_queues[idx].shutdown_inflight,
            "the Close waits for the FIN"
        );
    }

    /// The refused `Shutdown` SQE is pushed on a later tick by the shutdown
    /// retry drain, on the same backoff as a refused Close.
    #[test]
    fn a_refused_shutdown_sqe_is_pushed_on_a_later_tick() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        el.driver.ring.force_push_failures(1);
        el.driver.make_ctx().shutdown_write(token);
        assert_eq!(
            el.driver.pending_shutdown_retries,
            vec![(conn_index, generation)],
            "the refused SQE is on the retry list"
        );

        el.driver.tick_count = 4;
        el.drain_shutdown_retries();
        assert!(
            el.driver.pending_shutdown_retries.is_empty(),
            "the retry pushed it"
        );
        assert!(el.driver.send_queues[idx].shutdown_inflight);
        assert!(matches!(
            el.driver.connections.get(conn_index).unwrap().write,
            crate::connection::WriteHalf::Shutdown
        ));
    }

    /// `shutdown_write` while a send chain is active defers the FIN until
    /// the chain completes. The chain's parts are linked SQEs with
    /// `MSG_WAITALL` and set neither `in_flight` nor the queue, so a
    /// Shutdown SQE pushed beside them is not ordered behind them: the FIN
    /// queues behind the bytes already in the socket buffer and the parts
    /// still waiting for room fail `EPIPE`.
    #[test]
    fn shutdown_write_defers_while_chain_active() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        el.driver.chain_table.start(conn_index, 1);
        el.driver.make_ctx().shutdown_write(token);
        assert!(
            matches!(
                el.driver.connections.get(conn_index).unwrap().write,
                crate::connection::WriteHalf::ShutdownPending
            ),
            "the FIN must wait for the chain"
        );
        assert!(
            !el.driver.send_queues[conn_index as usize].shutdown_inflight,
            "no Shutdown SQE beside the chain's linked parts"
        );

        // The chain's operation CQE completes it; the FIN goes out then.
        let event = el.driver.chain_table.on_operation_cqe(conn_index, 100);
        assert!(matches!(event, ChainEvent::Complete { .. }));
        el.fire_chain_complete(conn_index);
        assert!(
            matches!(
                el.driver.connections.get(conn_index).unwrap().write,
                crate::connection::WriteHalf::Shutdown
            ),
            "the deferred FIN is submitted once the chain drains"
        );
        assert!(el.driver.send_queues[conn_index as usize].shutdown_inflight);
    }

    /// Dropping the last half closes gracefully, with a close_notify on TLS. An
    /// unwinding handler passes `abrupt`, so the peer sees a truncated stream.
    #[test]
    fn the_last_half_sends_close_notify_unless_unwinding() {
        use crate::runtime::io::{Half, release_half};
        for abrupt in [false, true] {
            let mut el = make_test_loop();
            let conn_index = accept_connection(&mut el);
            let generation = el.driver.connections.generation(conn_index);
            let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);
            el.driver.send_half_taken[conn_index as usize] = true;
            el.driver.recv_half_taken[conn_index as usize] = true;

            release_half(&mut el.driver, conn_index, generation, Half::Send, abrupt);
            assert!(
                !el.driver
                    .connections
                    .get(conn_index)
                    .unwrap()
                    .close_requested(),
                "a half is still alive"
            );
            release_half(&mut el.driver, conn_index, generation, Half::Recv, abrupt);

            assert!(
                el.driver
                    .connections
                    .get(conn_index)
                    .unwrap()
                    .close_requested(),
                "the last half closes"
            );
            assert_eq!(
                el.driver.send_queues[conn_index as usize].in_flight, !abrupt,
                "close_notify went out unless unwinding"
            );
        }
    }

    /// `DriverCtx::close`, the fatal-encrypt close, bounds a TLS drain.
    #[test]
    fn ctx_close_arms_a_close_notify_deadline_on_tls() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);

        el.driver
            .make_ctx()
            .close(crate::handler::ConnId::new(conn_index, generation));

        assert!(
            el.driver.send_queues[conn_index as usize]
                .close_notify_deadline
                .is_some()
        );
        assert!(
            el.driver.send_queues[conn_index as usize].in_flight,
            "the close_notify went out"
        );
    }

    /// `DriverCtx::close` after a write shutdown queues no close_notify: the
    /// FIN has been issued, and `queue_tls_close_notify` applies the same
    /// rule to the application's close. The deadline is still armed.
    #[test]
    fn ctx_close_after_a_write_shutdown_queues_no_close_notify() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);
        el.driver.connections.get_mut(conn_index).unwrap().write =
            crate::connection::WriteHalf::Shutdown;

        el.driver
            .make_ctx()
            .close(crate::handler::ConnId::new(conn_index, generation));

        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.close_pending, "the close was requested");
        assert!(!state.in_flight, "no alert was queued behind the FIN");
        assert!(state.close_notify_pending.is_none());
        assert!(
            state.close_notify_deadline.is_some(),
            "the drain is still bounded"
        );
        assert!(
            !el.driver
                .tls_table
                .as_ref()
                .unwrap()
                .close_notify_sent(conn_index),
            "no alert is recorded as sent"
        );
    }

    /// The application's close arms no deadline: a TLS drain takes as long as
    /// the peer takes, as a plaintext one does.
    #[test]
    fn graceful_close_arms_no_close_notify_deadline() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);

        el.driver.close_connection_graceful(conn_index);

        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested(),
            "the close was requested"
        );
        assert!(
            el.driver.send_queues[conn_index as usize]
                .close_notify_deadline
                .is_none()
        );
    }

    /// Take every free slot of the send pool and return them, so a test can
    /// make a close find the pool exhausted and then hand slots back.
    fn exhaust_send_pool(el: &mut AsyncEventLoop<NoopHandler>) -> Vec<u16> {
        let mut held = Vec::new();
        while let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"x") {
            held.push(slot);
        }
        assert_eq!(el.driver.send_copy_pool.free_count(), 0);
        held
    }

    /// A TLS close that finds the send pool exhausted keeps the close_notify
    /// and queues it once a slot is free, when the close drain next runs,
    /// instead of dropping it and committing the Close behind a bare FIN.
    #[test]
    fn close_notify_waits_for_a_pool_slot_when_the_pool_is_exhausted_at_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);
        let mut held = exhaust_send_pool(&mut el);

        el.driver.close_connection_graceful(conn_index);
        assert!(
            !el.driver.send_queues[idx].in_flight,
            "test premise: nothing could be queued with the pool exhausted"
        );
        assert!(el.driver.send_queues[idx].close_pending);

        // A slot comes back (another connection's send completed), and the
        // end-of-iteration drain runs.
        el.driver.send_copy_pool.release(held.pop().unwrap());
        el.finalize_pending_closes();
        assert!(
            el.driver.send_queues[idx].in_flight,
            "the close_notify went out once a slot was free"
        );
        assert!(
            el.driver.send_queues[idx].close_pending && !el.driver.send_queues[idx].close_submitted,
            "the Close waits behind the alert"
        );
        assert!(
            el.driver
                .tls_table
                .as_ref()
                .unwrap()
                .close_notify_sent(conn_index),
            "the alert is recorded as sent"
        );
    }

    /// A close_notify that still finds no slot when the close drain runs is
    /// dropped, and the connection does not record it as sent: the peer gets
    /// a bare FIN and reads the stream as truncated, and the flag must say so.
    #[test]
    fn close_notify_dropped_for_lack_of_a_slot_is_not_recorded_as_sent() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let _peer = install_handshaked_tls_with_peer(&mut el, conn_index);
        let _held = exhaust_send_pool(&mut el);

        el.driver.close_connection_graceful(conn_index);
        el.finalize_pending_closes();
        assert!(
            el.driver.send_queues[idx].close_submitted,
            "the Close is committed without the alert"
        );
        assert!(!el.driver.send_queues[idx].in_flight);
        assert!(
            !el.driver
                .tls_table
                .as_ref()
                .unwrap()
                .close_notify_sent(conn_index),
            "a dropped alert is not recorded as sent"
        );
    }

    /// DriverCtx::close (the fatal-encrypt close) must defer behind an
    /// in-flight send instead of forcing in_flight=false and submitting
    /// Close directly (which orphaned the send's CQE).
    #[test]
    fn ctx_close_defers_behind_in_flight_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // A send SQE is in the kernel.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"in flight").unwrap();

        {
            let mut ctx = el.driver.make_ctx();
            ctx.close(crate::handler::ConnId::new(conn_index, generation));
        }
        assert!(el.driver.send_queues[conn_index as usize].close_pending);

        // The event loop's post-callback drain defers while in_flight.
        let pending = std::mem::take(&mut el.driver.pending_finalize_closes);
        for idx in pending {
            el.driver.try_finalize_close(idx);
        }
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "must not finalize with a send still in flight"
        );

        // The in-flight send completes; its CQE registers the close again
        // and the end-of-iteration drain commits it.
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), b"in flight".len() as i32, 0);
        el.finalize_pending_closes();
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "close must finalize after the in-flight send drains"
        );
    }

    // ── ZC send path tests ─────────────────────────────────────────

    #[test]
    fn handle_send_msg_zc_notif_releases_slab() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Allocate a slab entry.
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();
        let free_before = el.driver.send_slab.free_count();

        // Simulate successful operation CQE (result > 0, not partial).
        el.driver.send_slab.inc_pending_notifs(slab_idx);
        el.driver.send_slab.mark_awaiting_notifications(slab_idx);

        // Simulate notification CQE.
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        let notif_flags = 8u32; // IORING_CQE_F_NOTIF
        el.test_dispatch_cqe(ud.raw(), 0, notif_flags);

        assert_eq!(
            el.driver.send_slab.free_count(),
            free_before + 1,
            "slab entry not released after notification"
        );
    }

    #[test]
    fn handle_send_msg_zc_error_does_not_increment_notifs() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();

        // Simulate error CQE (result < 0).
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        // Slab should be released (not leaked waiting for notification).
        assert!(
            el.driver.send_slab.should_release(slab_idx) || !el.driver.send_slab.in_use(slab_idx),
            "slab entry leaked after ZC send error"
        );
    }

    /// Allocate a one-iovec ZC send entry for `conn_index`.
    fn alloc_zc_entry(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32) -> u16 {
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();
        slab_idx
    }

    const CQE_F_MORE: u32 = 1 << 1; // IORING_CQE_F_MORE
    const CQE_F_NOTIF: u32 = 1 << 3; // IORING_CQE_F_NOTIF

    /// The kernel posts a ZC notification whenever the main CQE carries
    /// `IORING_CQE_F_MORE` -- including on error (`io_sendrecv_fail`) and on
    /// a zero result (`io_sendmsg_zc` sets it unconditionally). The entry must
    /// stay in use until that notification arrives.
    #[test]
    fn handle_send_msg_zc_error_with_f_more_waits_for_its_notification() {
        for result in [-libc::ECONNRESET, 0] {
            let mut el = make_test_loop();
            let conn_index = accept_connection(&mut el);
            let slab_idx = alloc_zc_entry(&mut el, conn_index);
            let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);

            el.test_dispatch_cqe(ud.raw(), result, CQE_F_MORE);
            assert!(
                el.driver.send_slab.in_use(slab_idx),
                "result {result} with F_MORE: entry released before its notification"
            );

            el.test_dispatch_cqe(ud.raw(), 0, CQE_F_NOTIF);
            assert!(
                !el.driver.send_slab.in_use(slab_idx),
                "result {result}: entry not released after its notification"
            );
        }
    }

    /// The CI panic (ringline-rs/ringline#487): an entry released on an error
    /// CQE that carried F_MORE is reused by the next send, and the first
    /// send's late notification then decrements the new send's count --
    /// "notification underflow" in debug, and in release an entry released
    /// while the kernel may still hold the new send's pages.
    #[test]
    fn a_late_notification_never_reaches_a_reused_entry() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let first = alloc_zc_entry(&mut el, conn_index);
        let first_ud = UserData::encode(OpTag::SendMsgZc, conn_index, first as u32);
        el.test_dispatch_cqe(first_ud.raw(), -libc::ECONNRESET, CQE_F_MORE);

        // The next send, before the first one's notification arrives.
        let second = alloc_zc_entry(&mut el, conn_index);
        let second_ud = UserData::encode(OpTag::SendMsgZc, conn_index, second as u32);

        // The first send's notification, late.
        el.test_dispatch_cqe(first_ud.raw(), 0, CQE_F_NOTIF);

        // The second send is untouched: still in use, and its own main CQE
        // and notification complete it normally.
        assert!(
            el.driver.send_slab.in_use(second),
            "the second send's entry was released"
        );
        el.test_dispatch_cqe(second_ud.raw(), 100, CQE_F_MORE);
        assert!(el.driver.send_slab.in_use(second));
        el.test_dispatch_cqe(second_ud.raw(), 0, CQE_F_NOTIF);
        assert!(!el.driver.send_slab.in_use(second));
    }

    #[test]
    fn handle_send_msg_zc_result_zero_does_not_leak_slab() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();

        // Simulate result == 0 CQE (no bytes sent, no notification expected).
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        // Slab should be releasable (pending_notifs == 0).
        assert!(
            !el.driver.send_slab.in_use(slab_idx) || el.driver.send_slab.should_release(slab_idx),
            "slab entry leaked on result == 0"
        );
    }

    // ── Recv path tests ────────────────────────────────────────────

    /// Close `conn_index` through its `Close` CQE (which releases the slot and
    /// bumps its generation), then re-accept it. The free list is LIFO, so the
    /// released index comes straight back — the reuse a stale completion races.
    fn recycle_connection(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32) {
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the Close CQE must release the slot"
        );
        // What the real accept path does before handing a reused slot out.
        el.driver.reset_send_state(conn_index);
        let reused = accept_connection(el);
        assert_eq!(
            reused, conn_index,
            "the free list must hand the same slot back"
        );
    }

    /// Write `data` where the kernel would: into the spare capacity of the
    /// buffer held by direct-receive entry `slot`.
    fn write_direct_landing(el: &mut AsyncEventLoop<NoopHandler>, slot: usize, data: &[u8]) {
        let entry = el.driver.direct_recvs[slot].as_mut().expect("entry in use");
        let spare = match &mut entry.buf {
            crate::backend::uring::driver::DirectRecvBuf::Accumulator(b) => b.spare_capacity_mut(),
            crate::backend::uring::driver::DirectRecvBuf::Tls(_) => {
                unreachable!("a plaintext direct receive")
            }
        };
        for (d, &b) in spare.iter_mut().zip(data) {
            d.write(b);
        }
    }

    /// A direct receive holds the accumulator's buffer from arm to
    /// completion: through a close and the slot's reuse, and its completion
    /// for the closed connection does not reach the new occupant.
    #[test]
    fn a_direct_receive_outlives_its_connection_and_its_completion_is_stale() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_direct = true;
        el.driver.accumulators.append(conn_index, b"abc");
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        assert!(
            el.driver.accumulators.is_empty(conn_index),
            "buffer detached"
        );
        assert_eq!(el.driver.direct_recvs.len(), 1);
        write_direct_landing(&mut el, 0, b"XYZ");

        recycle_connection(&mut el, conn_index);
        assert!(
            el.driver.direct_recvs[0].is_some(),
            "the entry must stay until its completion, not the close"
        );

        let ud = UserData::encode(OpTag::RecvDirect, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        assert!(
            el.driver.direct_recvs[0].is_none(),
            "freed at its completion"
        );
        assert!(
            el.driver.accumulators.is_empty(conn_index),
            "a stale completion's bytes reached the next connection"
        );

        // The new occupant's own receive delivers behind its contents.
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_direct = true;
        el.driver.accumulators.append(conn_index, b"ab");
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        write_direct_landing(&mut el, 0, b"cde");
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        assert_eq!(el.driver.accumulators.data(conn_index), b"abcde");
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_direct_armed
        );
    }

    /// At `recv_accumulator_max` a direct connection closes instead of
    /// waiting with no receive armed.
    #[test]
    fn a_direct_connection_at_the_accumulator_cap_closes() {
        let config = ConfigBuilder::new()
            .recv_accumulator_max(4096)
            .recv_direct_region(1024)
            .build()
            .unwrap();
        let mut el = make_test_loop_with_config(config);
        let conn_index = accept_connection(&mut el);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_direct = true;
        el.driver.accumulators.append(conn_index, &[0u8; 4096]);
        assert!(el.driver.arm_direct_recv_or_close(conn_index, None));
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .is_none_or(|c| c.close_requested())
        );
    }

    /// A closed connection's accumulator gives its allocation back, so a
    /// slot does not keep the largest message its last connection buffered.
    #[test]
    fn close_releases_the_accumulator_allocation() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .accumulators
            .append(conn_index, &vec![0u8; 1024 * 1024]);
        assert!(el.driver.accumulators.capacity(conn_index) >= 1024 * 1024);

        recycle_connection(&mut el, conn_index);

        assert_eq!(
            el.driver.accumulators.capacity(conn_index),
            4096,
            "the default recv_accumulator_capacity"
        );
    }

    // ── Close path tests ───────────────────────────────────────────

    #[test]
    fn handle_close_releases_connection_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        assert!(el.driver.connections.get(conn_index).is_some());

        // Request the close (sets Lifecycle::Closing; the Close SQE is
        // committed by the event loop's drain, simulated by the CQE below).
        el.driver.close_connection(conn_index);

        // Simulate Close CQE.
        let ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        // Connection slot should be released.
        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "connection slot not released after Close CQE"
        );
    }

    /// #371: a close requested by the driver (read error, task exit) must
    /// not commit the Close SQE synchronously — the task gets its poll
    /// window first. The event loop's end-of-iteration drain of
    /// `pending_finalize_closes` commits it.
    #[test]
    fn close_connection_on_idle_connection_defers_finalize_to_the_drain() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.close_connection(conn_index);

        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.close_pending, "close must be pending");
        assert!(
            !state.close_submitted,
            "Close must not be committed before the drain"
        );
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));

        // A repeated request is a no-op and does not double-register.
        el.driver.close_connection(conn_index);
        assert_eq!(
            el.driver
                .pending_finalize_closes
                .iter()
                .filter(|&&i| i == conn_index)
                .count(),
            1
        );

        // The drain commits it.
        let pending = std::mem::take(&mut el.driver.pending_finalize_closes);
        for idx in pending {
            el.driver.try_finalize_close(idx);
        }
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.close_submitted, "drain must commit the Close");
        assert!(!state.close_pending);
    }

    /// The peer's FIN and the CQE of an in-flight send land in one completion
    /// batch. The FIN requests no close; the task woken by it sends its reply
    /// in the poll that follows the batch and returns once the reply is
    /// delivered, and that return closes the connection behind the reply,
    /// which reaches the peer.
    #[test]
    fn a_fin_batched_with_the_last_send_cqe_leaves_the_close_to_the_task() {
        use std::cell::Cell;
        use std::rc::Rc;

        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        // The connection's task: read to the peer's close, then reply, and
        // record how the reply went. `None` after teardown means the task
        // was dropped before it ran.
        let seen: Rc<Cell<Option<Result<(), io::ErrorKind>>>> = Rc::new(Cell::new(None));
        let record = Rc::clone(&seen);
        let ctx = ConnCtx::new(conn_index, generation);
        el.executor.task_slab.spawn(
            conn_index,
            Box::pin(async move {
                let read = ctx
                    .with_data_result(|d| crate::ParseResult::Consumed(d.len()))
                    .await;
                let sent = match read {
                    Ok(0) => match ctx.send(b"bye") {
                        Ok(fut) => fut.await.map(|_| ()),
                        Err(e) => Err(e),
                    },
                    Ok(n) => Err(io::Error::other(format!("read {n} bytes"))),
                    Err(e) => Err(e),
                };
                record.set(Some(sent.map_err(|e| e.kind())));
            }),
        );
        el.executor.ready_queue.push_back(conn_index);
        el.poll_ready_tasks();
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "the task parked on its read"
        );
        let recv_slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        let recv_ud = UserData::encode(OpTag::RecvDirect, conn_index, recv_slot);

        // A send is in the kernel when the FIN arrives, so the close waits
        // on its CQE.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();
        let send_ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        // The FIN, then the send's CQE, in one batch.
        el.inject_batch_and_dispatch(&[(recv_ud.raw(), 0), (send_ud.raw(), 4)]);
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(!state.close_pending, "the FIN requested a close");
            assert!(!state.in_flight, "the send's CQE drained the queue");
        }
        assert!(!el.driver.pending_finalize_closes.contains(&conn_index));
        assert_eq!(
            el.driver.connections.get(conn_index).unwrap().read,
            ReadHalf::Eof { truncated: false }
        );

        // The rest of the iteration: the woken task is polled and replies.
        el.executor.collect_wakeups();
        el.poll_ready_tasks();
        assert_eq!(seen.get(), None, "the reply is in flight");
        assert!(
            el.driver.send_queues[conn_index as usize].in_flight,
            "the reply was accepted and submitted"
        );
        el.finalize_pending_closes();
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "nothing closes while the task runs"
        );

        // The reply's CQE lands; the task sees its send resolve and returns,
        // which closes the connection; the drain commits the Close.
        complete_one_cqe(&mut el);
        el.executor.collect_wakeups();
        el.poll_ready_tasks();
        assert_eq!(seen.get(), Some(Ok(())), "the reply was refused");
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .is_none_or(|c| c.close_requested()),
            "the task's return closes the connection"
        );
        el.finalize_pending_closes();
        assert!(el.driver.send_queues[conn_index as usize].close_submitted);
        let mut buf = [0u8; 16];
        assert_eq!(drain_peer(&peer, &mut buf), 3);
        assert_eq!(&buf[..3], b"bye");
    }

    // ── Recv data delivery tests ───────────────────────────────────

    // ── Test helpers for driving receive futures and ring delivery ──

    /// A minimal no-op waker for driving receive futures in tests. The
    /// futures park via `recv_waiters` and are re-polled manually, so the waker
    /// is never actually invoked.
    fn noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        unsafe fn no_op(_: *const ()) {}
        unsafe fn clone_fn(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, no_op, no_op, no_op);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    /// Run `f` with the worker's `CURRENT_DRIVER` thread-local pointing at
    /// `el`'s driver/executor — the same mechanism the real event loop installs
    /// around task polls — so futures/`Drop` impls that call `with_state` /
    /// `try_with_state` observe a live driver. `f` must not touch `el` directly
    /// (it aliases the raw pointers installed here); use `with_state` inside.
    fn with_driver_state<R>(el: &mut AsyncEventLoop<NoopHandler>, f: impl FnOnce() -> R) -> R {
        let driver_ptr = &mut el.driver as *mut Driver;
        let executor_ptr = &mut el.executor as *mut crate::runtime::Executor;
        let mut ds = DriverState {
            driver: unsafe { NonNull::new_unchecked(driver_ptr) },
            executor: unsafe { NonNull::new_unchecked(executor_ptr) },
        };
        let _guard = unsafe { set_driver_state_guarded(&mut ds) };
        f()
    }

    /// Deliver `data` to `conn_index` through a direct receive: arm one into
    /// the accumulator's spare capacity, write `data` where the kernel would,
    /// and dispatch its completion.
    fn deliver_direct(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32, data: &[u8]) {
        assert!(
            !el.driver.arm_direct_recv_or_close(conn_index, None),
            "the receive was refused"
        );
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .expect("open")
            .recv_direct_slot;
        write_direct_landing(el, slot as usize, data);
        let ud = UserData::encode(OpTag::RecvDirect, conn_index, slot);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);
    }

    /// A stale handle must not read — or consume — the new occupant's bytes.
    ///
    /// `try_with_data` both hands the caller the accumulator's contents and
    /// advances it past what the closure consumed, so an ungated stale call
    /// leaks one connection's data to another and eats it. See #429.
    #[test]
    fn try_with_data_refuses_a_stale_handle() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));

        assert!(
            el.driver
                .accumulators
                .append(conn_index, b"the new occupant's bytes"),
            "append into the live occupant's accumulator"
        );

        let seen = with_driver_state(&mut el, || {
            stale.try_with_data(|data| crate::ParseResult::Consumed(data.len()))
        });
        assert!(
            seen.is_none(),
            "a stale handle must not see another connection's data"
        );
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"the new occupant's bytes",
            "and must not consume it either"
        );
    }

    /// A stale handle must not close the slot's new occupant (#535).
    ///
    /// A `ConnCtx` can outlive its connection, and the slot can be reused by
    /// then; closing by slot index alone would close the new occupant.
    #[test]
    fn close_ignores_a_stale_handle() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));

        with_driver_state(&mut el, || stale.close());
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested(),
            "a stale handle must not close the new occupant"
        );

        // The control: the current handle still closes it.
        let current = ConnCtx::new(conn_index, generation);
        with_driver_state(&mut el, || current.close());
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .is_none_or(|c| c.close_requested()),
            "the current handle must still close its own connection"
        );
    }

    /// A stale source or sink is refused with `EPIPE`, and neither slot is
    /// marked. An accepted forward marks its source, so a
    /// second forward from it gets `EBUSY` until the first is dropped.
    #[test]
    fn forward_refuses_stale_slots_and_a_running_forward() {
        let mut el = make_test_loop();
        let src = accept_connection(&mut el);
        let sink = accept_connection(&mut el);
        let src_gen = el.driver.connections.generation(src);
        let sink_gen = el.driver.connections.generation(sink);
        let source = ConnCtx::new(src, src_gen);
        let sink_ctx = ConnCtx::new(sink, sink_gen);
        let waker = noop_waker();
        let refused = |el: &mut AsyncEventLoop<NoopHandler>, from: ConnCtx, to: ConnCtx| {
            with_driver_state(el, || {
                let mark = || {
                    crate::runtime::io::with_state(|d, _| {
                        d.connections.get(src).is_some_and(|c| c.direct_forwarding)
                    })
                };
                let before = mark();
                let mut fut = Box::pin(from.forward_to(to.conn_index, to.generation, 5));
                assert_eq!(mark(), before, "a refused forward changed the mark");
                let mut cx = std::task::Context::from_waker(&waker);
                match fut.as_mut().poll(&mut cx) {
                    std::task::Poll::Ready(Err(e)) => e.raw_os_error(),
                    other => panic!("not refused: {other:?}"),
                }
            })
        };
        let marked = |el: &AsyncEventLoop<NoopHandler>, i: u32| {
            el.driver
                .connections
                .get(i)
                .is_some_and(|c| c.direct_forwarding)
        };

        let stale_source = ConnCtx::new(src, src_gen.wrapping_add(1));
        assert_eq!(refused(&mut el, stale_source, sink_ctx), Some(libc::EPIPE));
        assert!(!marked(&el, src), "a stale source marked the occupant");
        let stale_sink = ConnCtx::new(sink, sink_gen.wrapping_add(1));
        assert_eq!(refused(&mut el, source, stale_sink), Some(libc::EPIPE));
        assert!(!marked(&el, src), "a refusal marked the source");

        let first = with_driver_state(&mut el, || source.forward_to(sink, sink_gen, 5));
        assert!(marked(&el, src), "an accepted forward marks its source");
        assert_eq!(refused(&mut el, source, sink_ctx), Some(libc::EBUSY));
        assert!(
            marked(&el, src),
            "a refused forward cleared the running one's mark"
        );
        with_driver_state(&mut el, || drop(first));
        assert!(!marked(&el, src), "dropping the forward clears the mark");
    }

    /// A stale handle's `forward_recv_buf` must not detach the slot's new
    /// occupant's accumulator, which would drop its buffered bytes (#544).
    /// The current handle still forwards it.
    #[test]
    fn forward_recv_buf_refuses_a_stale_handle_on_the_accumulator() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));
        assert!(el.driver.accumulators.append(conn_index, b"buffered bytes"));
        let data = el.driver.accumulators.data(conn_index);
        let (ptr, len) = (data.as_ptr(), data.len());
        // SAFETY: the accumulator is not touched between here and the calls
        // below, so the slice stays valid.
        let view = unsafe { std::slice::from_raw_parts(ptr, len) };

        let err = with_driver_state(&mut el, || stale.forward_recv_buf(view))
            .expect_err("a stale handle must be refused");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"buffered bytes",
            "a stale handle detached the new occupant's accumulator"
        );
        assert_eq!(el.driver.forward_zc_consumed[conn_index as usize], 0);

        let current = ConnCtx::new(conn_index, generation);
        with_driver_state(&mut el, || current.forward_recv_buf(view))
            .expect("the current handle forwards its accumulator");
        assert!(el.driver.accumulators.data(conn_index).is_empty());
        assert_eq!(
            el.driver.forward_zc_consumed[conn_index as usize],
            len as u32
        );
    }

    /// Once the connection's Close is submitted, `forward_recv_buf` on the
    /// current handle is refused without committing anything: the
    /// accumulator keeps its bytes.
    #[test]
    fn forward_recv_buf_on_a_closing_connection_commits_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let current = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        assert!(el.driver.accumulators.append(conn_index, b"buffered bytes"));
        let data = el.driver.accumulators.data(conn_index);
        // SAFETY: the accumulator is not touched before the call below.
        let view = unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
        assert!(with_driver_state(&mut el, || current.forward_recv_buf(view)).is_err());
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"buffered bytes",
            "a refused forward dropped the accumulator's bytes"
        );
        assert_eq!(el.driver.forward_zc_consumed[conn_index as usize], 0);
        el.driver.send_queues[conn_index as usize].close_submitted = false;
    }

    /// When the zero-copy send slab is full, a whole-accumulator forward on
    /// the current handle fails, and the accumulator keeps its bytes.
    #[test]
    fn forward_recv_buf_with_a_full_send_slab_keeps_the_accumulator() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let current = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        // Above `send_zc_threshold`, so each forward takes a slab entry.
        let message = vec![9u8; 5000];
        let mut refused = None;
        for attempt in 0..64 {
            assert!(el.driver.accumulators.append(conn_index, &message));
            let data = el.driver.accumulators.data(conn_index);
            // SAFETY: the accumulator is not touched before the call below.
            let view = unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
            if let Err(e) = with_driver_state(&mut el, || current.forward_recv_buf(view)) {
                refused = Some((attempt, e));
                break;
            }
        }
        let (attempt, err) = refused.expect("the send slab never filled");
        assert!(attempt > 0, "the first forward was refused: {err}");
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            &message[..],
            "the refused forward dropped the accumulator's bytes ({err})"
        );
        assert_eq!(el.driver.forward_zc_consumed[conn_index as usize], 0);
    }

    /// A handle made stale by real teardown and the slot's re-accept must not
    /// detach the new occupant's accumulator (#544).
    #[test]
    fn forward_recv_buf_refuses_a_handle_made_stale_by_teardown() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));

        el.driver.close_connection(conn_index);
        let ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        let new_index = accept_connection(&mut el);
        assert_eq!(new_index, conn_index, "the test needs the slot reused");

        assert!(el.driver.accumulators.append(conn_index, b"new occupant"));
        let data = el.driver.accumulators.data(conn_index);
        // SAFETY: the accumulator is not touched before the call below.
        let view = unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
        let err = with_driver_state(&mut el, || old.forward_recv_buf(view))
            .expect_err("a stale handle must be refused");
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"new occupant",
            "the stale handle dropped the new occupant's buffered bytes"
        );
    }

    /// A handle made stale by real teardown (close, the Close CQE, release)
    /// and the slot's re-accept must not close the new occupant.
    #[test]
    fn close_ignores_a_handle_made_stale_by_teardown() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);
        let old = ConnCtx::new(conn_index, old_gen);

        el.driver.close_connection(conn_index);
        let ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert!(el.driver.connections.get(conn_index).is_none());

        let new_index = accept_connection(&mut el);
        assert_eq!(new_index, conn_index, "the test needs the slot reused");
        let new_gen = el.driver.connections.generation(conn_index);
        assert_ne!(new_gen, old_gen, "release must change the generation");

        with_driver_state(&mut el, || old.close());
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested(),
            "the stale handle closed the new occupant"
        );
        let current = ConnCtx::new(conn_index, new_gen);
        with_driver_state(&mut el, || current.close());
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested()
        );
    }

    /// A half that outlives its connection must not clear the slot's new
    /// occupant's flag: the flags are per slot, and `spawn` needs only
    /// `'static`, so a standalone task can hold a stale half.
    #[test]
    fn a_stale_half_drop_keeps_the_new_occupants_flag() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);
        let stale = crate::Connection::from_claimed(ConnCtx::new(conn_index, old_gen));

        // Recycle the slot, as teardown does.
        el.driver.clear_conn_claims(conn_index);
        el.driver.connections.release(conn_index);
        let new_index = accept_connection(&mut el);
        assert_eq!(new_index, conn_index, "the test needs the slot reused");
        assert_ne!(
            el.driver.connections.generation(conn_index),
            old_gen,
            "release must bump the generation"
        );
        el.driver.recv_half_taken[conn_index as usize] = true;
        el.driver.send_half_taken[conn_index as usize] = true;

        with_driver_state(&mut el, || drop(stale));

        assert!(el.driver.recv_half_taken[conn_index as usize]);
        assert!(el.driver.send_half_taken[conn_index as usize]);
    }

    /// A half dropped during teardown, with no driver in scope, leaves its flag
    /// set, and the flags are indexed by slot, so the recycle point clears both.
    #[test]
    fn clear_conn_claims_clears_both_flags() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.recv_half_taken[conn_index as usize] = true;
        el.driver.send_half_taken[conn_index as usize] = true;

        el.driver.clear_conn_claims(conn_index);

        assert!(!el.driver.recv_half_taken[conn_index as usize]);
        assert!(!el.driver.send_half_taken[conn_index as usize]);
    }

    fn make_socketpair() -> (std::os::fd::OwnedFd, std::os::fd::OwnedFd) {
        use std::os::fd::FromRawFd;
        let mut fds = [0 as libc::c_int; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(r, 0, "socketpair failed");
        unsafe {
            (
                std::os::fd::OwnedFd::from_raw_fd(fds[0]),
                std::os::fd::OwnedFd::from_raw_fd(fds[1]),
            )
        }
    }

    /// A connection accepted while the table is full is closed before it
    /// reaches a handler, and counted, so the drop can be told apart from a
    /// handler that never ran (#598).
    #[test]
    fn an_accept_into_a_full_table_is_closed_and_counted() {
        use std::os::fd::IntoRawFd;
        let mut el = make_test_loop();
        while el.driver.connections.allocate().is_some() {}
        let (ours, peer) = make_socketpair();
        let raw = ours.into_raw_fd();
        let before = metrics::CONNECTIONS
            .value(metrics::conn::ACCEPT_TABLE_FULL)
            .unwrap_or(0);

        el.install_accepted(
            raw,
            crate::ListenerId::from_index(0),
            crate::connection::PeerAddr::Tcp(std::net::SocketAddr::from(([127, 0, 0, 1], 9))),
        );

        let after = metrics::CONNECTIONS
            .value(metrics::conn::ACCEPT_TABLE_FULL)
            .unwrap_or(0);
        assert!(
            after > before,
            "the drop was not counted ({before} -> {after})"
        );
        // The peer reads EOF once the accepted end is closed. (Checking `raw`
        // itself could see another thread's fd reuse the number.)
        let mut peer = std::os::unix::net::UnixStream::from(peer);
        let mut b = [0u8; 1];
        assert_eq!(
            std::io::Read::read(&mut peer, &mut b).expect("read peer"),
            0,
            "the accepted fd was not closed"
        );
    }

    // ── Receive arrival log ────────────────────────────────────────

    /// Parse one `\n`-terminated line.
    fn arrival_line(d: &[u8]) -> crate::runtime::io::ParseResult {
        match d.iter().position(|&b| b == b'\n') {
            Some(i) => crate::runtime::io::ParseResult::Consumed(i + 1),
            None => crate::runtime::io::ParseResult::NeedMore,
        }
    }

    fn at(base: Instant, ms: u64) -> Instant {
        base + std::time::Duration::from_millis(ms)
    }

    /// Deliver `data` as the first completion of a batch whose time is
    /// `time`.
    fn deliver_in_batch(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        data: &[u8],
        time: Instant,
    ) {
        el.driver.recv_batch.begin_at(time);
        deliver_direct(el, conn_index, data);
    }

    /// Read one line with `with_data` and return the bytes consumed and the
    /// connection's `recv_arrival` afterwards. Panics if the read does not
    /// resolve on its first poll.
    fn read_line(
        el: &mut AsyncEventLoop<NoopHandler>,
        ctx: ConnCtx,
    ) -> (usize, Option<crate::RecvArrival>) {
        let waker = noop_waker();
        let mut fut = std::pin::pin!(ctx.with_data(arrival_line));
        with_driver_state(el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            match fut.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(n) => (n, ctx.recv_arrival()),
                std::task::Poll::Pending => panic!("the line is not complete"),
            }
        })
    }

    fn times(a: Option<crate::RecvArrival>) -> Option<(Instant, Instant)> {
        a.map(|a| (a.first(), a.last()))
    }

    /// Lines delivered in separate batches report their own batch's time;
    /// lines delivered in one batch report the same time.
    #[test]
    fn arrival_times_follow_the_batch_that_delivered_each_line() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();

        deliver_in_batch(&mut el, conn_index, b"a\n", at(base, 1));
        let (n, a) = read_line(&mut el, ctx);
        assert_eq!((n, times(a)), (2, Some((at(base, 1), at(base, 1)))));

        deliver_in_batch(&mut el, conn_index, b"b\n", at(base, 2));
        let (n, a) = read_line(&mut el, ctx);
        assert_eq!((n, times(a)), (2, Some((at(base, 2), at(base, 2)))));

        // Two completions in one batch.
        deliver_in_batch(&mut el, conn_index, b"c\n", at(base, 3));
        deliver_direct(&mut el, conn_index, b"d\n");
        let (_, a) = read_line(&mut el, ctx);
        assert_eq!(times(a), Some((at(base, 3), at(base, 3))));
        let (_, a) = read_line(&mut el, ctx);
        assert_eq!(times(a), Some((at(base, 3), at(base, 3))));
    }

    /// A line that arrives over two batches takes its first byte's time from
    /// the first and its last byte's from the second, although the read
    /// polled in between.
    #[test]
    fn a_line_spanning_two_batches_reports_both_times() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();
        let waker = noop_waker();
        let mut fut = std::pin::pin!(ctx.with_data(arrival_line));

        deliver_in_batch(&mut el, conn_index, b"hel", at(base, 1));
        let first = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(first.is_pending(), "the line is not complete yet");

        deliver_in_batch(&mut el, conn_index, b"lo\n", at(base, 2));
        let (second, a) = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            (fut.as_mut().poll(&mut cx), ctx.recv_arrival())
        });
        assert!(matches!(second, std::task::Poll::Ready(6)));
        assert_eq!(times(a), Some((at(base, 1), at(base, 2))));
    }

    /// The second of two pipelined lines starts in the first line's batch.
    #[test]
    fn a_pipelined_line_reports_the_batch_of_its_own_first_byte() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();

        deliver_in_batch(&mut el, conn_index, b"a\nbb", at(base, 1));
        deliver_in_batch(&mut el, conn_index, b"b\n", at(base, 2));
        let (_, a) = read_line(&mut el, ctx);
        assert_eq!(times(a), Some((at(base, 1), at(base, 1))));
        let (n, a) = read_line(&mut el, ctx);
        assert_eq!(n, 4);
        assert_eq!(times(a), Some((at(base, 1), at(base, 2))));
    }

    /// A record trims before it adds. With 65 unread batches, the trim due
    /// at the next completion must use the counts from before that
    /// completion; counting its bytes as delivered but not yet buffered would
    /// drop the oldest unread entry.
    #[test]
    fn a_record_trims_before_it_adds_its_bytes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();
        // 65 one-byte batches, recorded and appended as a receive completion
        // does.
        for i in 0..65u64 {
            el.driver.recv_batch.begin_at(at(base, i));
            el.driver.record_arrival(conn_index, 1);
            el.driver.accumulators.append(conn_index, b"x");
        }
        assert!(el.driver.arrival[conn_index as usize].trim_due());

        deliver_in_batch(&mut el, conn_index, b"\n", at(base, 100));
        let waker = noop_waker();
        let mut fut =
            std::pin::pin!(ctx.with_data(|_| crate::runtime::io::ParseResult::Consumed(1)));
        let a = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut cx).is_ready());
            ctx.recv_arrival()
        });
        assert_eq!(times(a), Some((at(base, 0), at(base, 0))));
    }

    /// A log whose bytes a non-reporting consumer took is trimmed by a
    /// record once it reaches the 1024-entry cap, instead of merging on
    /// every later record. 600 unread batches set the trim threshold past
    /// 512 entries; the threshold is capped at 1024.
    #[test]
    fn a_log_drained_without_readers_is_trimmed_at_the_cap() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        let base = Instant::now();
        for i in 0..600u64 {
            el.driver.recv_batch.begin_at(at(base, i));
            el.driver.record_arrival(conn_index, 1);
            el.driver.accumulators.append(conn_index, b"x");
        }
        assert_eq!(el.driver.arrival[idx].len(), 600);
        // A `ConnStream` or forward takes them without reporting.
        el.driver.accumulators.consume(conn_index, 600);
        // Later batches go straight to a consumer that holds nothing.
        for i in 600..1024u64 {
            el.driver.recv_batch.begin_at(at(base, i));
            el.driver.record_arrival(conn_index, 1);
        }
        assert_eq!(el.driver.arrival[idx].len(), 1024);
        el.driver.recv_batch.begin_at(at(base, 1024));
        el.driver.record_arrival(conn_index, 1);
        assert_eq!(
            el.driver.arrival[idx].len(),
            1,
            "the record at the cap trims every consumed entry instead of merging"
        );
    }

    /// A `with_bytes` parser that reports more than it was shown is credited
    /// with the bytes the read removed, and the next read still finds its own
    /// batch.
    #[test]
    fn a_parser_claiming_more_than_it_was_shown_reports_what_was_removed() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();
        deliver_in_batch(&mut el, conn_index, b"ab\n", at(base, 1));
        let waker = noop_waker();
        let mut fut =
            std::pin::pin!(ctx.with_bytes(|_| crate::runtime::io::ParseResult::Consumed(100)));
        let a = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            assert!(fut.as_mut().poll(&mut cx).is_ready());
            ctx.recv_arrival()
        });
        assert_eq!(times(a), Some((at(base, 1), at(base, 1))));
        deliver_in_batch(&mut el, conn_index, b"c\n", at(base, 2));
        let (_, a) = read_line(&mut el, ctx);
        assert_eq!(times(a), Some((at(base, 2), at(base, 2))));
    }

    /// Bytes a park carried are recorded on the adopting worker into a
    /// cleared log, so the slot's previous occupant leaves nothing behind
    /// and `delivered` covers what the accumulator holds.
    #[test]
    fn an_adopted_connection_records_its_carried_bytes() {
        let mut el = make_test_loop();
        // The slot the adopt will take held another connection's log.
        el.driver.recv_batch.begin_at(Instant::now());
        el.driver.record_arrival(0, 100);
        let (tx, rx) = crate::handoff::bounded::<crate::park::ParkedFd>(4);
        el.driver.park_rx = Some(rx);
        tx.try_send(parked_entry(0, b"carried\n")).expect("queue");
        drop(tx);
        let base = Instant::now();
        el.driver.recv_batch.begin_at(at(base, 1));

        el.drain_adopted();

        let installed = 0u32;
        assert_eq!(el.driver.arrival[0].delivered(), 8);
        assert_eq!(el.driver.recv_buffered(installed), 8);
        let ctx = ConnCtx::new(installed, el.driver.connections.generation(installed));
        let (_, a) = read_line(&mut el, ctx);
        assert_eq!(times(a), Some((at(base, 1), at(base, 1))));
    }

    /// A slot reused by a new connection starts with an empty log, and the
    /// old handle reads `None`, also after the new connection has read.
    #[test]
    fn a_reused_slot_starts_with_an_empty_arrival_log() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();
        // Leave an unread line behind.
        deliver_in_batch(&mut el, conn_index, b"a\nb\n", at(base, 1));
        let (_, a) = read_line(&mut el, old);
        assert!(a.is_some());

        el.driver.close_connection(conn_index);
        let ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert!(el.driver.connections.get(conn_index).is_none());

        let reused = accept_connection(&mut el);
        assert_eq!(reused, conn_index, "precondition: the slot is reused");
        let new = ConnCtx::new(reused, el.driver.connections.generation(reused));
        assert_eq!(el.driver.arrival[reused as usize].delivered(), 0);
        assert_eq!(el.driver.arrival[reused as usize].len(), 0);
        with_driver_state(&mut el, || {
            assert!(new.recv_arrival().is_none());
            assert!(old.recv_arrival().is_none());
        });

        // Once the new connection has read, the old handle still reads None.
        deliver_in_batch(&mut el, reused, b"c\n", at(base, 2));
        let (_, a) = read_line(&mut el, new);
        assert_eq!(times(a), Some((at(base, 2), at(base, 2))));
        with_driver_state(&mut el, || {
            assert!(new.recv_arrival().is_some());
            assert!(old.recv_arrival().is_none());
        });
    }

    /// Each `drain_completions` begins a batch: a record after the second
    /// drain does not extend the first drain's entry or reuse its time.
    #[test]
    fn each_completion_drain_begins_a_batch() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;
        el.drain_completions();
        el.driver.record_arrival(conn_index, 1);
        el.drain_completions();
        el.driver.record_arrival(conn_index, 1);
        assert_eq!(el.driver.arrival[idx].len(), 2);
    }

    /// A `try_with_data` that finds nothing buffered returns `None` and
    /// clears the previous call's times.
    #[test]
    fn try_with_data_on_an_empty_connection_clears_the_arrival() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        el.driver.recv_batch.begin_at(Instant::now());
        el.driver.record_arrival(conn_index, 2);
        el.driver.accumulators.append(conn_index, b"a\n");
        let (_, a) = read_line(&mut el, ctx);
        assert!(a.is_some());
        let r = with_driver_state(&mut el, || {
            ctx.try_with_data(|_| crate::runtime::io::ParseResult::Consumed(1))
        });
        assert!(r.is_none(), "nothing is buffered");
        assert!(with_driver_state(&mut el, || ctx.recv_arrival()).is_none());
    }

    /// A reader call that consumes nothing leaves `recv_arrival` at `None`.
    #[test]
    fn a_read_that_consumes_nothing_reports_none() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();
        el.driver.recv_batch.begin_at(at(base, 1));
        el.driver.record_arrival(conn_index, 4);
        el.driver.accumulators.append(conn_index, b"a\nbb");
        let (_, a) = read_line(&mut el, ctx);
        assert!(a.is_some());
        let r = with_driver_state(&mut el, || {
            ctx.try_with_data(|_| crate::runtime::io::ParseResult::NeedMore)
        });
        assert!(matches!(r, Some(crate::runtime::io::ParseResult::NeedMore)));
        assert!(with_driver_state(&mut el, || ctx.recv_arrival()).is_none());
    }

    // ── Connect tests ──────────────────────────────────────────────

    #[test]
    fn handle_connect_success_wakes_waiter() {
        let mut el = make_test_loop();

        // Allocate an outbound connection slot.
        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        // As the connect's submit leaves a plaintext connection.
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_direct = true;
        el.executor.connect_waiters[conn_index as usize] = true;

        // Simulate successful connect CQE (result == 0).
        let ud = UserData::encode(
            OpTag::Connect,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        // Connect waiter should be cleared and result stored.
        assert!(
            !el.executor.connect_waiters[conn_index as usize],
            "connect waiter not cleared"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "connect result not stored"
        );
        // Connection should be established and open, with its hangup poll
        // armed.
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.established, "connection not marked established");
        assert!(
            matches!(conn.lifecycle, Lifecycle::Open),
            "connection not Open after connect"
        );
        assert!(conn.hangup_poll_armed, "no hangup poll after connect");
    }

    #[test]
    fn handle_connect_error_wakes_waiter_and_closes() {
        let mut el = make_test_loop();

        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        el.executor.connect_waiters[conn_index as usize] = true;

        // Simulate ECONNREFUSED (errno 111).
        let ud = UserData::encode(
            OpTag::Connect,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -111, 0);

        // Connect waiter should be cleared with error result.
        assert!(
            !el.executor.connect_waiters[conn_index as usize],
            "connect waiter not cleared on error"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "connect error result not stored"
        );
        // Connection should be closing.
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed after connect error"
        );
    }

    // ── Timer tests ────────────────────────────────────────────────

    #[test]
    fn handle_timer_fires_and_wakes_task() {
        let mut el = make_test_loop();

        // Allocate a timer slot.
        let waker_id = 0u32; // conn_index 0 as waker
        let (slot, generation) = el.executor.timer_pool.allocate(waker_id).unwrap();

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);

        // Simulate timer CQE (result == -ETIME = -62).
        el.test_dispatch_cqe(ud.raw(), -62, 0);

        // Timer should be marked as fired.
        assert!(
            el.executor.timer_pool.is_fired(slot),
            "timer not marked as fired"
        );
    }

    #[test]
    fn handle_timer_stale_generation_ignored() {
        let mut el = make_test_loop();

        let (slot, generation) = el.executor.timer_pool.allocate(0).unwrap();
        // Release and reallocate to bump generation.
        el.executor.timer_pool.release(slot);
        let (_slot2, gen2) = el.executor.timer_pool.allocate(0).unwrap();
        assert_ne!(generation, gen2, "generation should have changed");

        // Dispatch with OLD generation — should be ignored.
        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);
        el.test_dispatch_cqe(ud.raw(), -62, 0);

        // Timer should NOT be fired (stale generation).
        assert!(
            !el.executor.timer_pool.is_fired(slot),
            "stale timer should not be fired"
        );
    }

    // ── TLS send tests ─────────────────────────────────────────────

    #[test]
    fn handle_tls_send_complete_releases_pool_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Simulate full TLS send completion (all bytes sent, try_advance returns None).
        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released after TLS send complete"
        );
    }

    #[test]
    fn handle_tls_send_error_closes_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        // Simulate TLS send error (result < 0).
        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        // Pool slot should be released.
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "pool slot not released after TLS send error"
        );
        // Connection should be closing.
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed after TLS send error"
        );
    }

    /// What every failed send leaves for the reader: the read half records
    /// the failure, the reader parked on `with_data_result` is handed the
    /// send's error, and the connection is closing.
    fn assert_send_error_aborted(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
        errno: i32,
    ) {
        let cs = el
            .driver
            .connections
            .get(conn_index)
            .expect("the slot stays occupied until the Close commits");
        assert!(cs.close_requested(), "the connection is closing");
        assert_eq!(
            cs.read,
            crate::connection::ReadHalf::Error,
            "the read half records the failure"
        );
        let err = el
            .executor
            .take_recv_error(conn_index, generation)
            .expect("the reader is handed the send's error");
        assert_eq!(err.raw_os_error(), Some(errno), "the send's own errno");
    }

    /// A plaintext send that fails ends the connection and tells the reader
    /// why. Left open, the connection reported a peer reset as a clean close
    /// whenever the send, not the parked receive, took the socket's error
    /// (connection-close audit F13).
    #[test]
    fn a_plaintext_send_error_aborts_the_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"reply").unwrap();
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the error path returns the slot"
        );
        assert_send_error_aborted(&mut el, conn_index, generation, libc::ECONNRESET);
    }

    #[test]
    fn a_zero_copy_send_error_aborts_the_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .unwrap();
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);

        el.test_dispatch_cqe(ud.raw(), -libc::EPIPE, 0);

        assert!(
            !el.driver.send_slab.in_use(slab_idx),
            "the error path returns the slab entry"
        );
        assert_send_error_aborted(&mut el, conn_index, generation, libc::EPIPE);
    }

    /// Two plaintext slots coalesced into one `sendmsg`: its failure ends the
    /// connection as a TLS run's does.
    #[test]
    fn a_plaintext_run_send_error_aborts_the_connection() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let plain_send = |el: &mut AsyncEventLoop<NoopHandler>, data: &[u8]| {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(data).unwrap();
            let ud = UserData::encode(
                OpTag::Send,
                conn_index,
                UserData::send_payload(slot, generation),
            );
            crate::handler::BuiltSend {
                entry: crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw()),
                pool_slot: slot,
                slab_idx: u16::MAX,
            }
        };
        let first = plain_send(&mut el, b"part one");
        let second = plain_send(&mut el, b"part two");
        {
            let mut ctx = el.driver.make_ctx();
            ctx.queue_built_sends(conn_index, vec![first, second]);
        }
        let pushed = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(
            pushed.tag(),
            Some(OpTag::SendMsgCoalesced),
            "both slots went out as one run"
        );
        let slab_idx = pushed.payload() as u16;

        el.test_dispatch_cqe(pushed.raw(), -libc::ECONNRESET, 0);

        assert!(
            !el.driver.send_slab.in_use(slab_idx),
            "the error path returns the run's entry"
        );
        assert_send_error_aborted(&mut el, conn_index, generation, libc::ECONNRESET);
    }

    /// A failed TLS chunk closed the connection before; the reader is now
    /// told why as well.
    #[test]
    fn a_tls_send_error_aborts_the_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"ciphertext").unwrap();
        let ud = UserData::encode(
            OpTag::TlsSend,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        assert_send_error_aborted(&mut el, conn_index, generation, libc::ECONNRESET);
    }

    /// A chain whose first send fails closed the connection before; the
    /// reader is now told why as well.
    #[test]
    fn a_chain_send_error_aborts_the_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        el.driver.chain_table.start(conn_index, 2);
        let ud1 = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(s1, generation),
        );
        let ud2 = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(s2, generation),
        );

        el.inject_linked_chain_and_dispatch(&[(ud1.raw(), -libc::ECONNRESET), (ud2.raw(), 0)]);

        assert!(
            !el.driver.chain_table.is_active(conn_index),
            "the chain completed"
        );
        assert_send_error_aborted(&mut el, conn_index, generation, libc::ECONNRESET);
    }

    /// A send the close's lead cancelled is not a failure of the connection:
    /// the read half stays as the requested close left it, and no error is
    /// recorded for the reader.
    #[test]
    fn a_send_error_after_a_requested_close_does_not_mark_the_read_as_an_error() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"reply").unwrap();
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.driver.close_connection(conn_index);

        el.test_dispatch_cqe(ud.raw(), -libc::ECANCELED, 0);

        let cs = el
            .driver
            .connections
            .get(conn_index)
            .expect("the slot stays occupied until the Close commits");
        assert_eq!(
            cs.read,
            crate::connection::ReadHalf::Open,
            "a requested close is not a read failure"
        );
        assert!(
            el.executor
                .take_recv_error(conn_index, generation)
                .is_none(),
            "nothing is recorded for the reader"
        );
    }

    #[test]
    fn handle_tls_send_eagain_arms_pollout() {
        // EAGAIN is ordinary socket backpressure: keep the slot (the unsent
        // ciphertext) and arm POLLOUT — do NOT tear the connection down.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -(libc::EAGAIN), 0);

        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "slot must stay alive across EAGAIN (unsent bytes)"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_some() && !conn.unwrap().close_requested(),
            "EAGAIN must not close the connection"
        );
    }

    /// The last operation the loop pushed.
    fn last_pushed_op(el: &AsyncEventLoop<NoopHandler>) -> crate::backend::uring::sqe::Op {
        el.driver
            .ring
            .last_pushed
            .as_ref()
            .expect("an SQE was pushed")
            .op
    }

    /// A slab entry's plain `send`, tagged so its completion reaches the same
    /// handler, is what a `SendMsgZc`'s `-ENOMEM` must be followed by (#642).
    fn assert_plain_drain(el: &AsyncEventLoop<NoopHandler>, conn_index: u32) {
        assert!(
            matches!(
                last_pushed_op(el),
                crate::backend::uring::sqe::Op::Send { .. }
            ),
            "the entry must continue with a plain send"
        );
        let ud = UserData(
            el.driver
                .ring
                .last_pushed
                .as_ref()
                .expect("an SQE was pushed")
                .user_data,
        );
        assert_eq!(ud.tag(), Some(OpTag::SendMsgZcDrain));
        assert_eq!(ud.conn_index(), conn_index);
        assert_eq!(ud.payload(), 0, "the drain names the same slab entry");
    }

    /// The last SQE is the connection's `POLLOUT` poll, one shot or multishot.
    fn assert_waits_on_poll(el: &AsyncEventLoop<NoopHandler>, conn_index: u32, multi: bool) {
        match last_pushed_op(el) {
            crate::backend::uring::sqe::Op::PollAdd {
                mask, multi: armed, ..
            } => {
                assert_eq!(mask, libc::POLLOUT as u32);
                assert_eq!(armed, multi);
            }
            op => panic!("expected a POLLOUT poll, got {op:?}"),
        }
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(state.waiting_send.is_some(), "the send must be waiting");
        assert!(state.in_flight, "nothing else may send meanwhile");
    }

    /// The `SendPollOut` CQE of `conn_index`.
    fn pollout_ud(el: &AsyncEventLoop<NoopHandler>, conn_index: u32) -> u64 {
        let generation = el.driver.connections.generation(conn_index);
        UserData::encode(OpTag::SendPollOut, conn_index, generation).raw()
    }

    /// A send of `data` in a pool slot, submitted on a new connection.
    fn stage_send(el: &mut AsyncEventLoop<NoopHandler>, data: &[u8]) -> (u32, u16, UserData) {
        let conn_index = accept_connection(el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let payload = UserData::send_payload(slot, generation);
        (
            conn_index,
            slot,
            UserData::encode(OpTag::Send, conn_index, payload),
        )
    }

    /// A coalesced copy send of two 4096-byte pool slots in slab entry 0,
    /// submitted on a new connection.
    fn stage_coalesced(el: &mut AsyncEventLoop<NoopHandler>) -> u32 {
        let conn_index = accept_connection(el);
        let data = [7u8; 4096];
        let mut iovecs = Vec::new();
        let mut slots = Vec::new();
        for _ in 0..2 {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(&data).unwrap();
            iovecs.push(libc::iovec {
                iov_base: ptr as *mut libc::c_void,
                iov_len: len as usize,
            });
            slots.push(slot);
        }
        let generation = el.driver.connections.generation(conn_index);
        let (idx, _) = el
            .driver
            .send_slab
            .allocate_coalesced(conn_index, generation, &iovecs, &slots, 8192, [])
            .unwrap();
        assert_eq!(idx, 0, "the send uses slab entry 0");
        el.driver.send_queues[conn_index as usize].in_flight = true;
        conn_index
    }

    #[test]
    fn coalesced_eagain_waits_for_room() {
        let mut el = make_test_loop();
        let conn_index = stage_coalesced(&mut el);

        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, false);
        assert!(el.driver.send_slab.in_use(0), "the entry stays alive");

        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        assert!(
            matches!(
                last_pushed_op(&el),
                crate::backend::uring::sqe::Op::SendMsg { .. }
            ),
            "the entry is resubmitted"
        );

        // A short result waits again, and is not resubmitted first.
        el.test_dispatch_cqe(ud.raw(), 4096, 0);
        assert_waits_on_poll(&el, conn_index, false);
        assert!(el.driver.send_slab.in_use(0));

        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(ud.raw(), 4096, 0);
        assert!(!el.driver.send_slab.in_use(0), "fully sent: entry released");
    }

    #[test]
    fn a_failed_poll_fails_the_waiting_send() {
        let mut el = make_test_loop();
        let conn_index = stage_coalesced(&mut el);
        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, false);

        let pushed_before = el.driver.ring.last_pushed.as_ref().map(|e| e.user_data);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(poll, -libc::EBADF, 0);
        assert!(!el.driver.send_slab.in_use(0), "the entry is released");
        assert_eq!(
            el.driver.ring.last_pushed.as_ref().map(|e| e.user_data),
            pushed_before,
            "nothing is resubmitted after an error"
        );
        assert!(!el.driver.send_queues[conn_index as usize].in_flight);
    }

    /// The sequence on a peer that has half-closed: the one-shot poll reports
    /// `POLLRDHUP` and no `POLLOUT`, the multishot poll waits, and a `POLLOUT`
    /// that lands while the resubmit is in the kernel answers its `-EAGAIN`.
    #[test]
    fn a_half_closed_peer_waits_on_a_multishot_poll() {
        const F_MORE: u32 = 2; // IORING_CQE_F_MORE
        let rdhup = libc::POLLRDHUP as i32;
        let out = libc::POLLOUT as i32;
        let mut el = make_test_loop();
        let (conn_index, slot, ud) = stage_send(&mut el, &[7u8; 300]);
        let poll = pollout_ud(&el, conn_index);

        el.test_dispatch_cqe(ud.raw(), 100, 0);
        assert_waits_on_poll(&el, conn_index, false);

        el.test_dispatch_cqe(poll, rdhup, 0);
        assert_waits_on_poll(&el, conn_index, true);

        // The multishot poll's own report of the FIN changes nothing.
        el.driver.ring.last_pushed = None;
        el.test_dispatch_cqe(poll, rdhup, F_MORE);
        assert!(el.driver.ring.last_pushed.is_none());

        el.test_dispatch_cqe(poll, rdhup | out, F_MORE);
        assert!(matches!(
            last_pushed_op(&el),
            crate::backend::uring::sqe::Op::Send { len: 200, .. }
        ));

        el.driver.ring.last_pushed = None;
        el.test_dispatch_cqe(poll, rdhup | out, F_MORE);
        assert!(
            el.driver.ring.last_pushed.is_none(),
            "the send is in the kernel: a second one would reorder the stream"
        );
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert!(matches!(
            last_pushed_op(&el),
            crate::backend::uring::sqe::Op::Send { len: 200, .. }
        ));

        el.driver.ring.last_pushed = None;
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert!(
            el.driver.ring.last_pushed.is_none(),
            "the multishot poll is still armed"
        );
        assert!(
            el.driver.send_queues[conn_index as usize]
                .waiting_send
                .is_some()
        );

        el.test_dispatch_cqe(poll, out, F_MORE);
        el.test_dispatch_cqe(ud.raw(), 200, 0);
        assert!(!el.driver.send_copy_pool.in_use(slot));
        assert!(!el.driver.send_queues[conn_index as usize].in_flight);
    }

    /// A `POLLOUT` followed by `-EAGAIN` moves to the multishot poll, because a
    /// one-shot poll would report the same `POLLOUT` and repeat the pair.
    #[test]
    fn eagain_after_pollout_does_not_repeat_the_poll() {
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);

        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, false);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, true);
    }

    /// A multishot poll that ends with the send still waiting is armed again,
    /// or the send would rest on the backstop alone.
    #[test]
    fn a_multishot_poll_that_ends_is_armed_again() {
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        el.test_dispatch_cqe(poll, libc::POLLRDHUP as i32, 0);
        assert_waits_on_poll(&el, conn_index, true);

        // No IORING_CQE_F_MORE.
        el.test_dispatch_cqe(poll, libc::POLLRDHUP as i32, 0);
        assert_waits_on_poll(&el, conn_index, false);
    }

    /// `POLLHUP` without `POLLOUT` on a multishot poll is a Unix peer's full
    /// shutdown. The resubmit reports `EPIPE` without waiting for the backstop.
    #[test]
    fn a_multishot_hangup_resubmits() {
        const F_MORE: u32 = 2; // IORING_CQE_F_MORE
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        el.test_dispatch_cqe(poll, libc::POLLRDHUP as i32, 0);
        el.test_dispatch_cqe(poll, (libc::POLLHUP | libc::POLLRDHUP) as i32, F_MORE);
        assert!(matches!(
            last_pushed_op(&el),
            crate::backend::uring::sqe::Op::Send { .. }
        ));
    }

    /// The `Close` of a connection with an armed poll cancels it first: a
    /// multishot poll keeps the socket open past the `Close` otherwise.
    #[test]
    fn close_cancels_an_armed_poll() {
        const F_MORE: u32 = 2; // IORING_CQE_F_MORE
        let mut el = make_test_loop();
        let (conn_index, slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(ud.raw(), 40, 0);
        el.test_dispatch_cqe(poll, libc::POLLRDHUP as i32, 0);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, F_MORE);
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.ring.pushed_cancels.is_empty(),
            "a send is in flight"
        );

        // The send's CQE registers the close; the end-of-iteration drain
        // commits it, cancelling the poll first.
        el.test_dispatch_cqe(ud.raw(), 60, 0);
        assert!(!el.driver.send_copy_pool.in_use(slot));
        el.finalize_pending_closes();
        assert_eq!(el.driver.ring.pushed_cancels, vec![poll]);
        assert_eq!(
            el.driver.send_queues[conn_index as usize].send_poll,
            SendPoll::None
        );

        // The cancelled poll's CQE finds nothing to do.
        el.test_dispatch_cqe(poll, -libc::ECANCELED, 0);
    }

    /// With no room for the cancel, the close stays committed and the retry
    /// submits both. Nothing re-drives a close left uncommitted on an idle
    /// connection, and a park needs `close_submitted` at once.
    #[test]
    fn a_failed_cancel_keeps_the_close_committed() {
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(ud.raw(), 40, 0);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, true);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 2);
        el.test_dispatch_cqe(ud.raw(), 60, 0);

        el.driver.close_connection(conn_index);
        el.driver.ring.force_push_failures(1);
        for c in std::mem::take(&mut el.driver.pending_finalize_closes) {
            el.driver.try_finalize_close(c);
        }
        assert!(el.driver.send_queues[conn_index as usize].close_submitted);
        assert_eq!(el.driver.pending_close_retries, vec![(conn_index, 0)]);
        assert!(el.driver.ring.pushed_cancels.is_empty());

        el.driver.tick_count = 4;
        el.drain_close_retries();
        assert!(el.driver.pending_close_retries.is_empty());
        assert_eq!(el.driver.ring.pushed_cancels, vec![poll]);
    }

    /// `-EAGAIN` on a send's first issue, after an earlier send's resubmit on a
    /// `POLLOUT`, is an ordinary full socket and takes the one-shot poll.
    #[test]
    fn a_finished_send_leaves_no_wait_state() {
        let mut el = make_test_loop();
        let (conn_index, slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(ud.raw(), 100, 0);
        assert!(!el.driver.send_copy_pool.in_use(slot));

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(&[7u8; 100]).unwrap();
        let generation = el.driver.connections.generation(conn_index);
        let payload = UserData::send_payload(slot, generation);
        let next = UserData::encode(OpTag::Send, conn_index, payload);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.test_dispatch_cqe(next.raw(), -libc::EAGAIN, 0);
        assert_waits_on_poll(&el, conn_index, false);
    }

    /// A forced close leaves a waiting send to the cancel of its poll. That
    /// CQE fails the send through its own completion path.
    #[test]
    fn a_forced_close_fails_the_waiting_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"blocked", 7);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let payload = UserData::send_payload(slot, generation);
        let ud = UserData::encode(OpTag::Send, conn_index, payload);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);

        el.driver.close_connection(conn_index);
        el.driver.force_finalize_close(conn_index);
        assert_eq!(el.driver.ring.pushed_cancels.len(), 1);

        let poll = UserData::encode(OpTag::SendPollOut, conn_index, generation);
        el.test_dispatch_cqe(poll.raw(), -libc::ECANCELED, 0);
        let err = el
            .executor
            .take_send_result(id)
            .expect("the send must settle")
            .expect_err("the send never finished");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        assert!(!el.driver.send_copy_pool.in_use(slot));
    }

    /// A poll's CQE can land after the `Close` CQE, which releases the slot.
    /// The `Close` handles the send, so the poll's mismatched generation
    /// cannot leak it.
    #[test]
    fn the_close_cqe_fails_a_send_still_waiting() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"blocked", 7);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let payload = UserData::send_payload(slot, generation);
        let ud = UserData::encode(OpTag::Send, conn_index, payload);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        el.driver.close_connection(conn_index);
        el.driver.force_finalize_close(conn_index);

        let close = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(close.raw(), 0, 0);
        assert!(!el.driver.send_copy_pool.in_use(slot));
        assert!(
            el.executor.take_send_result(id).is_some_and(|r| r.is_err()),
            "the send must settle with an error"
        );

        let poll = UserData::encode(OpTag::SendPollOut, conn_index, generation);
        el.test_dispatch_cqe(poll.raw(), -libc::ECANCELED, 0);
    }

    /// The backstop resubmits a waiting send and keeps the connection on its
    /// list, and takes it off when nothing waits.
    #[test]
    fn the_backstop_resubmits_a_waiting_send() {
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        el.test_dispatch_cqe(ud.raw(), 40, 0);
        assert_eq!(el.driver.send_backstop_list.len(), 1);

        el.handle_send_backstop();
        assert!(matches!(
            last_pushed_op(&el),
            crate::backend::uring::sqe::Op::Send { len: 60, .. }
        ));
        assert_eq!(el.driver.send_backstop_list.len(), 1);
        assert!(
            el.driver.send_queues[conn_index as usize]
                .waiting_send
                .is_none()
        );

        // `-EAGAIN`: the one-shot poll is still armed, so no second one.
        el.driver.ring.last_pushed = None;
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        assert!(el.driver.ring.last_pushed.is_none());
        assert_eq!(el.driver.send_backstop_list.len(), 1);

        el.handle_send_backstop();
        el.test_dispatch_cqe(ud.raw(), 60, 0);
        el.handle_send_backstop();
        assert!(el.driver.send_backstop_list.is_empty());
        assert!(!el.driver.send_queues[conn_index as usize].on_send_backstop);
    }

    /// A poll the SQ had no room for is armed by the next drain, with no limit
    /// on the wait. An entry whose wait ended without it is dropped.
    #[test]
    fn a_pending_poll_is_armed_or_dropped() {
        let mut el = make_test_loop();
        let (conn_index, _slot, ud) = stage_send(&mut el, &[7u8; 100]);
        let generation = el.driver.connections.generation(conn_index);
        let state = &mut el.driver.send_queues[conn_index as usize];
        state.waiting_send = Some(ud.raw());
        state.send_poll = SendPoll::Pending;
        el.driver
            .pending_send_pollout_retries
            .push((conn_index, generation, true));
        el.drain_send_pollout_retries();
        assert_waits_on_poll(&el, conn_index, true);
        assert_eq!(
            el.driver.send_queues[conn_index as usize].send_poll,
            SendPoll::Multi
        );

        let state = &mut el.driver.send_queues[conn_index as usize];
        state.waiting_send = None;
        state.send_poll = SendPoll::Pending;
        el.driver.ring.last_pushed = None;
        el.driver
            .pending_send_pollout_retries
            .push((conn_index, generation, false));
        el.drain_send_pollout_retries();
        assert!(el.driver.ring.last_pushed.is_none());
        assert_eq!(
            el.driver.send_queues[conn_index as usize].send_poll,
            SendPoll::None
        );
    }

    /// After the Close is submitted, a zero-copy send that comes back
    /// `-EAGAIN` or `-ENOMEM` is not retried, and its awaiter is told
    /// `ECANCELED`, as the plain, coalesced and TLS handlers tell theirs.
    #[test]
    fn a_zc_send_refused_after_the_close_is_submitted_settles_cancelled() {
        for errno in [libc::EAGAIN, libc::ENOMEM] {
            let mut el = make_test_loop();
            let conn_index = accept_connection(&mut el);
            let generation = el.driver.connections.generation(conn_index);
            let data = Box::new([7u8; 100]);
            let iovecs = [
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                },
                libc::iovec {
                    iov_base: data.as_ptr() as *mut _,
                    iov_len: 100,
                },
            ];
            let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
            let (slab_idx, _) = el
                .driver
                .send_slab
                .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
                .unwrap();
            let id = el.executor.register_send(conn_index);
            el.driver.send_slab.set_send_id(slab_idx, id, 100);
            el.driver.send_queues[conn_index as usize].in_flight = true;

            // The close waits behind the in-flight send, and is then forced
            // past it (the close_notify deadline path), which submits the
            // Close.
            el.driver.close_connection(conn_index);
            el.driver.force_finalize_close(conn_index);
            assert!(el.driver.send_queues[conn_index as usize].close_submitted);

            let zc = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
            el.test_dispatch_cqe(zc.raw(), -errno, 0);
            el.drain_settled_sends();
            let err = el
                .executor
                .take_send_result(id)
                .expect("the send settled")
                .expect_err("the send was refused");
            assert_eq!(
                err.raw_os_error(),
                Some(libc::ECANCELED),
                "errno {errno}: {err}"
            );
            assert!(
                !el.driver.send_slab.in_use(slab_idx),
                "errno {errno}: the entry was released"
            );
        }
    }

    /// A zero-copy send that gets `-EAGAIN` waits for room and keeps the entry
    /// until every notification has landed.
    #[test]
    fn zc_eagain_waits_and_holds_for_its_notifications() {
        const F_MORE: u32 = 2; // IORING_CQE_F_MORE
        const F_NOTIF: u32 = 8; // IORING_CQE_F_NOTIF
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let data = Box::new([7u8; 100]);
        let iovecs = [
            libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            },
            libc::iovec {
                iov_base: data.as_ptr() as *mut _,
                iov_len: 100,
            },
        ];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();
        assert_eq!(slab_idx, 0);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // EAGAIN, with a notification to follow.
        let zc = UserData::encode(OpTag::SendMsgZc, conn_index, 0);
        el.test_dispatch_cqe(zc.raw(), -libc::EAGAIN, F_MORE);
        assert_waits_on_poll(&el, conn_index, false);

        // A short result waits too, and the rest stays zero-copy.
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(zc.raw(), 40, 0);
        assert_waits_on_poll(&el, conn_index, false);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        assert!(matches!(
            last_pushed_op(&el),
            crate::backend::uring::sqe::Op::SendMsgZc { .. }
        ));
        assert!(el.driver.send_queues[conn_index as usize].in_flight);

        // The rest completes; the EAGAIN's notification is still owed.
        el.test_dispatch_cqe(zc.raw(), 60, 0);
        assert!(
            !el.driver.send_queues[conn_index as usize].in_flight,
            "the send is complete"
        );
        assert!(
            el.driver.send_slab.in_use(0),
            "the entry must wait for the owed notification"
        );
        el.test_dispatch_cqe(zc.raw(), 0, F_NOTIF);
        assert!(
            !el.driver.send_slab.in_use(0),
            "released after the notification"
        );
    }

    /// A zero-copy send that gets `-ENOMEM` (its pages do not fit under
    /// `RLIMIT_MEMLOCK`) sends the whole entry with plain `send`s, one iovec
    /// at a time, including a resubmission that waited on a full SQ, and
    /// keeps the entry until the notification lands (#642).
    #[test]
    fn zc_enomem_sends_the_rest_of_the_entry_plain() {
        const F_MORE: u32 = 2; // IORING_CQE_F_MORE
        const F_NOTIF: u32 = 8; // IORING_CQE_F_NOTIF
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let data = Box::new([7u8; 300]);
        let iovecs: Vec<libc::iovec> = (0..3)
            .map(|i| libc::iovec {
                iov_base: data[i * 100..].as_ptr() as *mut _,
                iov_len: 100,
            })
            .collect();
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 300)
            .unwrap();
        assert_eq!(slab_idx, 0);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let zc = UserData::encode(OpTag::SendMsgZc, conn_index, 0);
        let drain = UserData::encode(OpTag::SendMsgZcDrain, conn_index, 0);
        el.test_dispatch_cqe(zc.raw(), -libc::ENOMEM, F_MORE);
        assert_plain_drain(&el, conn_index);
        assert_eq!(
            el.driver.send_slab.first_unsent(0),
            Some((data.as_ptr(), 100))
        );

        // The first iovec is sent: the rest waits, and goes out plain.
        el.test_dispatch_cqe(drain.raw(), 100, 0);
        assert_waits_on_poll(&el, conn_index, false);
        let poll = pollout_ud(&el, conn_index);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        assert_plain_drain(&el, conn_index);

        // A short write of the second; its resubmission is a plain send. A
        // retry parked by a full SQ, injected here, is a plain send as well.
        el.test_dispatch_cqe(drain.raw(), 50, 0);
        assert_waits_on_poll(&el, conn_index, false);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        assert_plain_drain(&el, conn_index);
        el.driver.ring.last_pushed = None;
        el.driver
            .pending_zc_retries
            .push((conn_index, generation, slab_idx, 0));
        el.drain_zc_retries();
        assert_plain_drain(&el, conn_index);
        assert_eq!(
            el.driver.send_slab.first_unsent(0),
            Some((data[150..].as_ptr(), 50))
        );

        // The rest of the second, then the third after its own wait.
        el.test_dispatch_cqe(drain.raw(), 50, 0);
        assert_waits_on_poll(&el, conn_index, false);
        el.test_dispatch_cqe(poll, libc::POLLOUT as i32, 0);
        el.test_dispatch_cqe(drain.raw(), 100, 0);
        assert!(
            !el.driver.send_queues[conn_index as usize].in_flight,
            "the send is complete"
        );
        assert!(
            el.driver.send_slab.in_use(0),
            "the entry must wait for the ENOMEM's notification"
        );
        el.test_dispatch_cqe(zc.raw(), 0, F_NOTIF);
        assert!(
            !el.driver.send_slab.in_use(0),
            "released after the notification"
        );
    }

    /// `-ENOMEM` from the plain drain is a send error: only a `SendMsgZc`'s
    /// `-ENOMEM` means its pages did not fit under `RLIMIT_MEMLOCK`.
    #[test]
    fn a_drain_enomem_fails_the_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let data = Box::new([7u8; 100]);
        let iovecs = [libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .unwrap();
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let zc = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(zc.raw(), -libc::ENOMEM, 0);
        assert_plain_drain(&el, conn_index);

        el.driver.ring.last_pushed = None;
        let drain = UserData::encode(OpTag::SendMsgZcDrain, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(drain.raw(), -libc::ENOMEM, 0);
        assert!(
            el.driver.ring.last_pushed.is_none(),
            "a failed drain is not resubmitted"
        );
        assert!(
            !el.driver.send_slab.in_use(slab_idx),
            "the entry is released"
        );
    }

    /// An entry parked on a retry list has no operation in flight, so no CQE
    /// will release it; shutdown must release it itself rather than wait out
    /// its bound.
    #[test]
    fn shutdown_releases_entries_parked_on_retry_lists() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let mut parked = Vec::new();
        for list in 0..2 {
            let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
            let (slab_idx, _) = el
                .driver
                .send_slab
                .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
                .unwrap();
            let entry = (conn_index, generation, slab_idx, 0);
            match list {
                0 => el.driver.pending_coalesced_retries.push(entry),
                _ => el.driver.pending_zc_retries.push(entry),
            }
            parked.push(slab_idx);
        }

        let start = std::time::Instant::now();
        el.driver.run_shutdown();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "shutdown waited {:?} for parked entries",
            start.elapsed()
        );
        for slab_idx in parked {
            assert!(
                !el.driver.send_slab.in_use(slab_idx),
                "entry {slab_idx} not released"
            );
        }
    }

    /// A plain `Close` the ring refuses at exit is retried, as a refused
    /// cancel or a refused close of a connection holding slab entries
    /// already is; otherwise the connection never closes and exit waits out
    /// its whole 10 s bound for it.
    #[test]
    fn shutdown_retries_a_close_the_ring_refused() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        assert!(el.driver.connections.get(conn_index).is_some());

        // Step 2's first push is this connection's Close.
        el.driver.ring.force_push_failures(1);
        let start = std::time::Instant::now();
        el.driver.run_shutdown();
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "shutdown waited {:?} for a close the ring refused",
            start.elapsed()
        );
        assert_eq!(
            el.driver.connections.active_count(),
            0,
            "the refused close was retried and completed"
        );
    }

    /// The exit drain closes the fd carried by an install CQE it reaps. The
    /// fd is a second reference to the socket; the connection's Close
    /// releases the fixed file, and while that fd stays open the peer sees
    /// no FIN (#800).
    #[test]
    fn shutdown_closes_the_fd_of_an_install_it_drains() {
        let mut el = make_test_loop();
        if !el.driver.ring.supports_park() {
            return; // pre-6.8: no install can be in flight
        }
        let conn_index = accept_connection(&mut el);
        let (ours, peer) = attach_socketpair(&mut el, conn_index);
        let generation = el.driver.connections.generation(conn_index);
        el.driver
            .ring
            .submit_park_install(conn_index, generation)
            .expect("submit_park_install failed");
        el.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight {
                target: 1,
                generation,
            });
        // The install completes inline at submit. Take its CQE, check that
        // it carries an fd (a failed install would leave `ours` the last
        // reference and the assertion below true without the drain's arm),
        // and post it again for the exit drain to reap.
        el.driver.ring.flush().unwrap();
        let mut cqes = Vec::new();
        el.driver.ring.reap(&mut cqes);
        let ud = UserData::encode(OpTag::ParkInstall, conn_index, generation).raw();
        let (_, installed, _) = *cqes
            .iter()
            .find(|(u, _, _)| *u == ud)
            .expect("no ParkInstall CQE after the flush");
        assert!(installed >= 0, "the install failed: {installed}");
        el.driver.ring.submit_nop_inject(ud, installed).unwrap();

        el.driver.run_shutdown();
        assert!(el.driver.connections.get(conn_index).is_none());

        // The Close released the fixed file and `ours` is dropped here, so
        // the installed fd is the last reference to the socket. The peer
        // reads EOF once it is closed too.
        drop(ours);
        let mut buf = [0u8; 1];
        assert_eq!(
            try_recv(&peer, &mut buf),
            Some(0),
            "the peer saw no FIN: the installed fd is still open"
        );
    }

    #[test]
    fn handle_tls_send_stale_slot_ignored() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Allocate and immediately release a slot, then deliver a stale
        // TlsSend CQE for it (Close CQE processed earlier in the same batch).
        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        el.driver.send_copy_pool.release(slot);
        let free_before = el.driver.send_copy_pool.free_count();

        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before,
            "stale CQE must not double-release the slot"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_some() && !conn.unwrap().close_requested(),
            "stale TlsSend CQE must not close the connection"
        );
    }

    // ── Tick timeout test ──────────────────────────────────────────

    #[test]
    fn handle_tick_timeout_clears_armed_flag() {
        let mut el = make_test_loop();
        el.driver.tick_timeout_armed = true;

        let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
        el.test_dispatch_cqe(ud.raw(), -62, 0);

        assert!(
            !el.driver.tick_timeout_armed,
            "tick_timeout_armed not cleared"
        );
    }

    // ── UDP send error metric test ─────────────────────────────────

    #[test]
    fn handle_send_msg_udp_error_releases_pool_slot() {
        let mut el = make_test_loop();

        // Set up a UDP socket state (need at least one for the handler).
        if el.driver.udp_sockets.is_empty() {
            return; // Skip if no UDP sockets configured.
        }

        let data = b"datagram";
        let (pool_slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Pop the send slot we'll "simulate" — so the CQE pushes it back cleanly
        // (mirrors the real submit path).
        let slot_idx = el.driver.udp_sockets[0].send_freelist.pop().unwrap();

        // Simulate UDP send CQE (success).
        let udp_index = 0u32;
        let payload = crate::backend::uring::driver::encode_udp_send_payload(slot_idx, pool_slot);
        let ud = UserData::encode(OpTag::SendMsgUdp, udp_index, payload);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released after UDP send"
        );
        assert!(
            el.driver.udp_sockets[0].send_freelist.contains(&slot_idx),
            "send slot not returned to freelist after CQE"
        );
    }

    #[test]
    fn handle_send_msg_udp_wakes_send_ready_waiter() {
        let mut el = make_test_loop();

        if el.driver.udp_sockets.is_empty() {
            return;
        }

        // Register a waiter as though a task had polled UdpSendHalf::send_ready.
        el.executor.udp_send_ready_waiters[0] = Some(42);

        let data = b"wake";
        let (pool_slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let slot_idx = el.driver.udp_sockets[0].send_freelist.pop().unwrap();

        let payload = crate::backend::uring::driver::encode_udp_send_payload(slot_idx, pool_slot);
        let ud = UserData::encode(OpTag::SendMsgUdp, 0u32, payload);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        assert!(
            el.executor.udp_send_ready_waiters[0].is_none(),
            "send_ready waiter not cleared after CQE"
        );
    }

    #[test]
    fn udp_send_payload_roundtrip() {
        use crate::backend::uring::driver::{decode_udp_send_payload, encode_udp_send_payload};
        for slot_idx in [0u16, 1, 63, 255, u16::MAX] {
            for pool_slot in [0u16, 1, 511, 1023, u16::MAX] {
                let p = encode_udp_send_payload(slot_idx, pool_slot);
                assert_eq!(decode_udp_send_payload(p), (slot_idx, pool_slot));
            }
        }
    }

    // ── Partial send retry queue tests ─────────────────────────────

    #[test]
    fn handle_send_partial_queues_or_resubmits() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Allocate a pool slot with 10 bytes.
        let data = b"0123456789";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        // Mark send as in-flight.
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // Simulate partial send: only 5 of 10 bytes sent.
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), 5, 0);

        // The pool slot should still be in use (resubmitted or queued for retry).
        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "pool slot released prematurely on partial send"
        );
    }

    #[test]
    fn handle_send_error_settles_the_awaited_send_with_the_error() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let id = await_slot(&mut el, conn_index, slot, data.len() as u32);

        // Simulate send error (ECONNRESET).
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        assert_eq!(
            send_result(&mut el, id)
                .expect("send error result not stored")
                .expect_err("the send failed")
                .raw_os_error(),
            Some(libc::ECONNRESET)
        );
    }

    #[test]
    fn handle_send_msg_zc_error_settles_the_awaited_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();
        let id = await_slab(&mut el, conn_index, slab_idx, 100);

        // Simulate ZC send error (ECONNRESET).
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        assert_eq!(
            send_result(&mut el, id)
                .expect("send error result not stored")
                .expect_err("the send failed")
                .raw_os_error(),
            Some(libc::ECONNRESET)
        );
    }

    // ── DiskIoFuture Drop test ─────────────────────────────────────

    #[test]
    fn disk_io_future_drop_clears_waiter() {
        let mut el = make_test_loop();

        // Insert a disk_io_waiter entry manually.
        let seq = 42u32;
        let task_id = 0u32;
        el.executor.disk_io_waiters.insert(seq, task_id);
        assert!(el.executor.disk_io_waiters.contains_key(&seq));

        // Set up thread-local so DiskIoFuture::drop can access executor.
        let driver_ptr = &mut el.driver as *mut Driver;
        let executor_ptr = &mut el.executor as *mut Executor;

        // Safety: NonNull::new_unchecked is safe because we have valid pointers
        // from &mut el.driver and &mut el.executor above.
        let mut driver_state = DriverState {
            driver: unsafe { NonNull::new_unchecked(driver_ptr) },
            executor: unsafe { NonNull::new_unchecked(executor_ptr) },
        };
        let guard = unsafe { set_driver_state_guarded(&mut driver_state) };

        // Create and immediately drop a DiskIoFuture.
        {
            let _fut = crate::runtime::io::DiskIoFuture::new(seq);
        }

        drop(guard);

        // Waiter should be cleaned up.
        assert!(
            !el.executor.disk_io_waiters.contains_key(&seq),
            "disk_io_waiter not cleared on DiskIoFuture drop"
        );
    }

    // ── NOP error injection tests (real io_uring pipeline) ─────────
    //
    // These tests use IORING_NOP_INJECT_RESULT to send CQEs through
    // the full submit_and_wait → drain_completions → dispatch_cqe path.
    // Below Linux 6.10 `inject` queues the completion for `reap` instead.

    #[test]
    fn nop_inject_send_complete() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), data.len() as i32);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released via NOP inject path"
        );
    }

    #[test]
    fn nop_inject_send_error_releases_and_settles() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let id = await_slot(&mut el, conn_index, slot, data.len() as u32);

        // Inject ECONNRESET through real io_uring.
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), -104);

        // Pool slot released, waiter woken with error.
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "pool slot not released on injected send error"
        );
        assert_eq!(
            send_result(&mut el, id)
                .expect("send error result not stored")
                .expect_err("the send failed")
                .raw_os_error(),
            Some(libc::ECONNRESET)
        );
    }

    #[test]
    fn nop_inject_zc_send_error_no_slab_leak() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();

        // Inject ZC send error through real pipeline.
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), -104);

        // Slab should be releasable (no notification expected on error).
        assert!(
            !el.driver.send_slab.in_use(slab_idx) || el.driver.send_slab.should_release(slab_idx),
            "slab entry leaked on injected ZC error"
        );
    }

    #[test]
    fn nop_inject_timer_fires() {
        let mut el = make_test_loop();

        let waker_id = 0u32;
        let (slot, generation) = el.executor.timer_pool.allocate(waker_id).unwrap();

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);

        // Inject timer expiry through real pipeline.
        el.inject_and_dispatch(ud.raw(), -62); // -ETIME

        assert!(
            el.executor.timer_pool.is_fired(slot),
            "timer not fired via NOP inject"
        );
    }

    #[test]
    fn nop_inject_send_settles_the_awaited_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let id = await_slot(&mut el, conn_index, slot, data.len() as u32);

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), data.len() as i32);

        assert_eq!(
            send_result(&mut el, id)
                .expect("send result not stored")
                .expect("the send succeeded"),
            data.len() as u32
        );
    }

    #[test]
    fn nop_inject_zc_notif_releases_slab() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();
        let free_before = el.driver.send_slab.free_count();

        // Set up as if operation CQE already processed.
        el.driver.send_slab.inc_pending_notifs(slab_idx);
        el.driver.send_slab.mark_awaiting_notifications(slab_idx);

        // Inject notification CQE (IORING_CQE_F_NOTIF = 8).
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        // NOP inject only sets result, not flags. The notif flag is in CQE flags.
        // We can't inject CQE flags via NOP — use synthetic for this.
        // Fall back to test_dispatch_cqe for the notif path.
        el.test_dispatch_cqe(ud.raw(), 0, 8); // IORING_CQE_F_NOTIF

        assert_eq!(el.driver.send_slab.free_count(), free_before + 1);
    }

    #[test]
    fn nop_inject_zc_result_zero() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();

        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), 0);

        assert!(
            !el.driver.send_slab.in_use(slab_idx) || el.driver.send_slab.should_release(slab_idx),
        );
    }

    #[test]
    fn nop_inject_connect_success() {
        let mut el = make_test_loop();
        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_direct = true;
        el.executor.connect_waiters[conn_index as usize] = true;

        let ud = UserData::encode(
            OpTag::Connect,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), 0);

        assert!(!el.executor.connect_waiters[conn_index as usize]);
        assert!(el.executor.io_results[conn_index as usize].is_some());
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.established);
        assert!(matches!(conn.lifecycle, Lifecycle::Open));
    }

    #[test]
    fn nop_inject_connect_error() {
        let mut el = make_test_loop();
        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        el.executor.connect_waiters[conn_index as usize] = true;

        let ud = UserData::encode(
            OpTag::Connect,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), -111); // ECONNREFUSED

        assert!(!el.executor.connect_waiters[conn_index as usize]);
        assert!(el.executor.io_results[conn_index as usize].is_some());
    }

    #[test]
    fn nop_inject_timer_stale_generation() {
        let mut el = make_test_loop();
        let (slot, generation) = el.executor.timer_pool.allocate(0).unwrap();
        el.executor.timer_pool.release(slot);
        let (_slot2, _gen2) = el.executor.timer_pool.allocate(0).unwrap();

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let ud = UserData::encode(OpTag::Timer, 0, payload);
        el.inject_and_dispatch(ud.raw(), -62);

        assert!(!el.executor.timer_pool.is_fired(slot));
    }

    #[test]
    fn nop_inject_tls_send_complete() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), data.len() as i32);

        assert_eq!(el.driver.send_copy_pool.free_count(), free_before + 1);
    }

    #[test]
    fn nop_inject_tls_send_error_closes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"ciphertext";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        let ud = UserData::encode(OpTag::TlsSend, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), -104);

        assert!(!el.driver.send_copy_pool.in_use(slot));
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
    }

    #[test]
    fn nop_inject_tick_timeout() {
        let mut el = make_test_loop();
        el.driver.tick_timeout_armed = true;

        let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
        el.inject_and_dispatch(ud.raw(), -62);

        assert!(!el.driver.tick_timeout_armed);
    }

    #[test]
    fn nop_inject_close_releases_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.close_connection(conn_index);

        let ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(ud.raw(), 0);

        assert!(el.driver.connections.get(conn_index).is_none());
    }

    // ── Batch interaction tests (multi-CQE in one drain) ───────────
    //
    // These test cross-CQE interactions where one handler's side effects
    // affect subsequent handlers in the same drain_completions() call.

    #[test]
    fn batch_send_error_then_recv_on_same_conn() {
        // A send error and recv EOF arrive in the same batch for the
        // same connection. Both handlers should process without panic.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();
        let id = await_slot(&mut el, conn_index, slot, 4);

        let send_ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let recv_slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        let recv_ud = UserData::encode(OpTag::RecvDirect, conn_index, recv_slot);

        el.inject_batch_and_dispatch(&[
            (send_ud.raw(), -104), // send error
            (recv_ud.raw(), 0),    // recv EOF
        ]);

        // Both should have processed. Pool slot released, connection closing.
        assert!(!el.driver.send_copy_pool.in_use(slot));
        assert!(matches!(send_result(&mut el, id), Some(Err(_))));
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
    }

    #[test]
    fn batch_recv_eof_then_send_cqe() {
        // Recv EOF finishes the read half and requests no close, then the
        // in-flight send's CQE arrives in the same batch. The send handler
        // releases its slot on the open connection, and nothing is left for
        // the end-of-iteration drain.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        // A real socket behind the fixed file: the receive armed below stays
        // in the kernel instead of failing with `EBADF`, which would land as
        // a read error on the connection the injected EOF leaves open.
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();

        // Recv EOF + stale send in the same batch.
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let recv_slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        let recv_ud = UserData::encode(OpTag::RecvDirect, conn_index, recv_slot);
        let send_ud = UserData::encode(OpTag::Send, conn_index, slot as u32);

        el.inject_batch_and_dispatch(&[
            (recv_ud.raw(), 0), // EOF: the read half is finished
            (send_ud.raw(), 4), // the in-flight send completes (4 bytes = b"data")
        ]);

        assert!(!el.driver.send_copy_pool.in_use(slot));
        assert_half_open(&el, conn_index, false);
    }

    #[test]
    fn batch_two_sends_on_same_conn() {
        // Two send completions arrive in the same batch. The first should
        // release its pool slot and advance the queue. The second should
        // also release cleanly.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot1, _p, _l) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (slot2, _p, _l) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        let ud1 = UserData::encode(OpTag::Send, conn_index, slot1 as u32);
        let ud2 = UserData::encode(OpTag::Send, conn_index, slot2 as u32);

        el.inject_batch_and_dispatch(&[(ud1.raw(), 3), (ud2.raw(), 3)]);

        // Both pool slots should be released.
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 2,
            "both pool slots should be released"
        );
    }

    #[test]
    fn batch_multiple_connections_interleaved() {
        // CQEs for different connections arrive interleaved in one batch.
        let mut el = make_test_loop();
        let c1 = accept_connection(&mut el);
        let c2 = accept_connection(&mut el);
        el.driver.send_queues[c1 as usize].in_flight = true;
        el.driver.send_queues[c2 as usize].in_flight = true;

        let (s1, _p, _l) = el.driver.send_copy_pool.copy_in(b"hello").unwrap();
        let (s2, _p, _l) = el.driver.send_copy_pool.copy_in(b"world").unwrap();
        let id1 = await_slot(&mut el, c1, s1, 5);
        let id2 = await_slot(&mut el, c2, s2, 5);

        let ud1 = UserData::encode(OpTag::Send, c1, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, c2, s2 as u32);

        el.inject_batch_and_dispatch(&[
            (ud1.raw(), 5),    // c1 send complete
            (ud2.raw(), -104), // c2 send error
        ]);

        // c1 succeeded, c2 failed: each settled with its own result.
        assert_eq!(send_result(&mut el, id1).unwrap().unwrap(), 5);
        assert!(matches!(send_result(&mut el, id2), Some(Err(_))));
        // Both pool slots released.
        assert!(!el.driver.send_copy_pool.in_use(s1));
        assert!(!el.driver.send_copy_pool.in_use(s2));
    }

    // ── Retry drain tests ──────────────────────────────────────────
    //
    // Test the pending retry mechanism by manually populating the
    // retry queues and draining them.

    #[test]
    fn retry_drain_copy_send_releases_on_closed_connection() {
        // Queue a copy retry for a connection that has since been closed.
        // The retry drain should release the pool slot and skip.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let data = b"retry-data";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let generation = el.driver.connections.generation(conn_index);

        // Queue the retry.
        el.driver
            .pending_copy_retries
            .push((conn_index, generation, slot, 0, OpTag::Send));

        // Close the connection before the retry fires.
        el.driver.close_connection(conn_index);
        // Simulate the Close CQE to fully release the slot.
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);

        // Now drain retries — the connection is gone.
        el.drain_copy_retries();

        // Retry queue should be empty.
        assert!(el.driver.pending_copy_retries.is_empty());
        // Pool slot should be released (not leaked).
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "pool slot leaked on retry with closed connection"
        );
    }

    #[test]
    fn retry_drain_copy_send_with_reused_connection() {
        // Queue a copy retry, then close and reuse the connection slot.
        // The generation check should prevent resubmission to the new connection.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_generation = el.driver.connections.generation(conn_index);

        let data = b"retry-data";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        // Queue the retry with the old generation.
        el.driver
            .pending_copy_retries
            .push((conn_index, old_generation, slot, 0, OpTag::Send));

        // Close the connection.
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);

        // Reuse the slot with a new connection.
        let new_conn_index = accept_connection(&mut el);
        assert_eq!(
            new_conn_index, conn_index,
            "expected slot reuse for generation test"
        );
        let new_generation = el.driver.connections.generation(conn_index);
        assert_ne!(old_generation, new_generation);

        // Drain retries — should detect generation mismatch.
        el.drain_copy_retries();

        // Pool slot should be released (not resubmitted to new connection).
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "pool slot should be released on generation mismatch"
        );
        // New connection should be unaffected.
        assert!(el.driver.connections.get(new_conn_index).is_some());
    }

    #[test]
    fn retry_drain_zc_send_releases_on_closed_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            )
            .unwrap();

        // Simulate: operation CQE already incremented pending_notifs.
        el.driver.send_slab.inc_pending_notifs(slab_idx);

        // Queue the ZC retry.
        el.driver
            .pending_zc_retries
            .push((conn_index, generation, slab_idx, 0));

        // Close the connection.
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);

        // Drain retries — connection is gone.
        el.drain_zc_retries();

        assert!(el.driver.pending_zc_retries.is_empty());
        // Slab should be marked for release (awaiting_notifications set,
        // and pending_notifs is still 1 — will be released when the
        // notification CQE arrives).
        // The key assertion: no panic, no hang, retry was handled.
    }

    /// A key abandoned outside the executor (a future dropped with its
    /// connection's task) is queued, and `release_orphans` stops holding it
    /// and drops its result. Without the release the key and its result stay
    /// held for the life of the worker.
    #[test]
    fn a_key_abandoned_outside_the_executor_is_released() {
        let mut el = make_test_loop();
        let key = 0x0123_0005;
        el.executor.wait_disk_io(key, 0);
        // Its result has arrived and nothing will take it.
        el.executor.disk_io_results.insert(key, 0);

        // CURRENT_DRIVER is unset here, as during connection teardown.
        crate::fs::abandon_disk_io_key(key);
        assert!(
            crate::runtime::disk_io_key_held(key),
            "the key is queued, not yet released"
        );

        crate::fs::release_orphans(&mut el.driver, &mut el.executor);
        assert!(!crate::runtime::disk_io_key_held(key));
        assert!(!el.executor.disk_io_results.contains_key(&key));
    }

    #[test]
    fn disk_io_keys_are_unique_per_op() {
        // fs/NVMe/direct-io share the executor's completion maps; the key
        // must differ across ops even for the same slab index (three
        // independent slabs all start their free lists at 0).
        use crate::handler::DiskIoKind;
        let mut el = make_test_loop();
        let mut ctx = el.driver.make_ctx();
        let k1 = ctx.disk_io_key(DiskIoKind::Fs, 3).unwrap();
        let k2 = ctx.disk_io_key(DiskIoKind::Fs, 3).unwrap();
        assert_ne!(k1, k2, "same slab index must map to distinct keys");
        assert_eq!(k1 & 0xFFFF, 3, "low 16 bits must carry the slab index");
        assert_eq!(k2 & 0xFFFF, 3);

        // Slot 3 of each subsystem's slab, whatever the sequence: an fs
        // operation in flight never shares a key with a direct-I/O or NVMe
        // one, even when the sequence has come round to the same value.
        let fs = ctx.disk_io_key(DiskIoKind::Fs, 3).unwrap();
        for _ in 0..0x3FFF {
            ctx.disk_io_key(DiskIoKind::Fs, 0).unwrap();
        }
        let dio = ctx.disk_io_key(DiskIoKind::DirectIo, 3).unwrap();
        let nvme = ctx.disk_io_key(DiskIoKind::Nvme, 3).unwrap();
        assert_eq!(
            fs & 0x3FFF_FFFF,
            dio & 0x3FFF_FFFF,
            "the sequence came round"
        );
        assert_ne!(fs, dio, "fs and direct-I/O keys must differ");
        assert_ne!(fs, nvme, "fs and NVMe keys must differ");
        assert_ne!(dio, nvme, "direct-I/O and NVMe keys must differ");
    }

    /// An outbound slot whose Connect is in the kernel, with its timeout
    /// armed as `arm_connect_timeout` leaves it and a task waiting on the
    /// connect. The slot is used once first so its generation is not 0, the
    /// value a payload that carries no generation would match by accident.
    fn connecting_slot(el: &mut AsyncEventLoop<NoopHandler>) -> (u32, u32) {
        let first = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        el.driver.connections.release(first);
        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        assert_eq!(conn_index, first, "precondition: the slot is reused");
        let generation = el.driver.connections.generation(conn_index);
        assert_ne!(generation, 0);
        let cs = el.driver.connections.get_mut(conn_index).unwrap();
        cs.recv_direct = true;
        cs.connect_timeout_armed = true;
        el.executor.connect_waiters[conn_index as usize] = true;
        (conn_index, generation)
    }

    /// A Connect CQE whose payload is not the slot's generation belongs to
    /// an earlier occupant and changes nothing: the connect in progress keeps
    /// its waiter, its state and its flag, and nothing is cancelled.
    #[test]
    fn a_stale_connect_cqe_leaves_the_reused_slot_alone() {
        let mut el = make_test_loop();
        let (conn_index, generation) = connecting_slot(&mut el);
        let stale = UserData::encode(OpTag::Connect, conn_index, generation.wrapping_sub(1));
        for result in [0, -libc::ECANCELED, -libc::ECONNREFUSED] {
            el.test_dispatch_cqe(stale.raw(), result, 0);
            let conn = el
                .driver
                .connections
                .get(conn_index)
                .expect("a stale Connect CQE closed the occupant");
            assert!(
                matches!(conn.lifecycle, Lifecycle::Connecting),
                "result {result}: the occupant left Connecting"
            );
            assert!(conn.connect_timeout_armed);
            assert!(el.executor.connect_waiters[conn_index as usize]);
            assert!(el.executor.io_results[conn_index as usize].is_none());
            assert!(el.driver.ring.pushed_cancels.is_empty());
        }
    }

    /// A close requested while the Connect is in the kernel (here by the
    /// connect timeout) is committed by the end-of-iteration drain without
    /// waiting for the Connect's CQE. That CQE is matched to this occupant
    /// by its generation when it lands before the Close CQE, and ignored
    /// when it lands after.
    #[test]
    fn a_close_on_a_connecting_slot_commits_without_the_connect_cqe() {
        let mut el = make_test_loop();
        let (conn_index, generation) = connecting_slot(&mut el);
        let timeout = UserData::encode(OpTag::Timeout, conn_index, generation);
        el.test_dispatch_cqe(timeout.raw(), -libc::ETIME, 0);
        assert_eq!(
            el.driver.ring.pushed_cancels.len(),
            1,
            "the Connect is cancelled"
        );
        assert!(!el.executor.connect_waiters[conn_index as usize]);
        assert!(el.driver.send_queues[conn_index as usize].close_pending);

        el.finalize_pending_closes();
        assert!(el.driver.send_queues[conn_index as usize].close_submitted);

        // Before the Close CQE: the slot is still this occupant's, and the
        // CQE settles the timeout flag and nothing else.
        let connect = UserData::encode(OpTag::Connect, conn_index, generation);
        el.test_dispatch_cqe(connect.raw(), -libc::ECANCELED, 0);
        let conn = el
            .driver
            .connections
            .get(conn_index)
            .expect("the slot is freed by the Close CQE, not before");
        assert!(!conn.connect_timeout_armed);
        assert!(conn.close_requested());

        let close = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(close.raw(), 0, 0);
        assert!(el.driver.connections.get(conn_index).is_none());

        // After it: the slot is inactive and the CQE is ignored.
        el.test_dispatch_cqe(connect.raw(), -libc::ECANCELED, 0);
        assert!(el.driver.connections.get(conn_index).is_none());
    }

    /// The connect timeout cancels the Connect by the user_data the Connect
    /// was submitted with, which carries the slot's generation.
    #[test]
    fn the_connect_timeout_cancels_the_connect_by_its_generation() {
        let mut el = make_test_loop();
        let (conn_index, generation) = connecting_slot(&mut el);
        let timeout = UserData::encode(OpTag::Timeout, conn_index, generation);
        el.test_dispatch_cqe(timeout.raw(), -libc::ETIME, 0);
        let connect = UserData::encode(OpTag::Connect, conn_index, generation);
        assert_eq!(el.driver.ring.pushed_cancels, vec![connect.raw()]);
    }

    /// A Connect that completes with its timeout armed cancels the timeout
    /// by the user_data `arm_connect_timeout` gave it, which carries the
    /// slot's generation.
    #[test]
    fn a_completed_connect_cancels_its_timeout_by_its_generation() {
        let mut el = make_test_loop();
        let (conn_index, generation) = connecting_slot(&mut el);
        let connect = UserData::encode(OpTag::Connect, conn_index, generation);
        el.test_dispatch_cqe(connect.raw(), 0, 0);
        let timeout = UserData::encode(OpTag::Timeout, conn_index, generation);
        assert_eq!(el.driver.ring.pushed_cancels, vec![timeout.raw()]);
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(matches!(conn.lifecycle, Lifecycle::Open));
        assert!(!conn.connect_timeout_armed);
    }

    /// The same for a Connect that fails.
    #[test]
    fn a_failed_connect_cancels_its_timeout_by_its_generation() {
        let mut el = make_test_loop();
        let (conn_index, generation) = connecting_slot(&mut el);
        let connect = UserData::encode(OpTag::Connect, conn_index, generation);
        el.test_dispatch_cqe(connect.raw(), -libc::ECONNREFUSED, 0);
        let timeout = UserData::encode(OpTag::Timeout, conn_index, generation);
        assert_eq!(el.driver.ring.pushed_cancels, vec![timeout.raw()]);
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.close_requested());
    }

    #[test]
    fn stale_connect_timeout_ignored_on_reused_slot() {
        // A -ETIME deferred through CQ overflow can arrive after the slot
        // was closed and reused for a NEW outbound connect. The generation
        // in the payload must prevent it from killing the new connect.
        let mut el = make_test_loop();
        let conn_index = el.driver.connections.allocate_outbound().unwrap();
        let old_generation = el.driver.connections.generation(conn_index);

        // Close + reuse: new outbound connect in the same slot.
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);
        let reused = el.driver.connections.allocate_outbound().unwrap();
        assert_eq!(reused, conn_index);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.connect_timeout_armed = true;
        }

        // Stale -ETIME with the OLD generation: must be ignored.
        let ud = UserData::encode(OpTag::Timeout, conn_index, old_generation);
        el.inject_and_dispatch(ud.raw(), -62);

        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_some() && matches!(conn.unwrap().lifecycle, Lifecycle::Connecting),
            "stale connect-timeout CQE must not kill the reused slot's connect"
        );
    }

    #[test]
    fn close_retry_backoff_preserves_entry() {
        // On a backoff tick (tick_count % 4 != 0) the entry must stay
        // queued — it used to be silently dropped, leaking the fd + slot.
        let mut el = make_test_loop();
        el.driver.tick_count = 1;
        el.driver.pending_close_retries.push((7, 2));

        el.drain_close_retries();

        assert_eq!(
            el.driver.pending_close_retries,
            vec![(7, 2)],
            "backoff tick must preserve the close-retry entry unchanged"
        );
    }

    #[test]
    fn copy_retry_giveup_fails_send_and_closes() {
        // Exhausted retries must not leave the connection wedged open with
        // in_flight stuck: release the slot, fail the send, close.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let id = await_slot(&mut el, conn_index, slot, 4);

        el.driver
            .pending_copy_retries
            .push((conn_index, generation, slot, 2, OpTag::Send));
        el.drain_copy_retries();

        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "give-up must release the pool slot"
        );
        assert!(
            matches!(send_result(&mut el, id), Some(Err(_))),
            "give-up must fail the send"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "give-up must close the connection"
        );
    }

    #[test]
    fn submit_next_queued_empty_registers_deferred_close_for_the_drain() {
        // A close deferred behind an in-flight ZC send is registered for the
        // end-of-iteration drain when the queue empties, even though that
        // completion path calls nothing else on the close.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Simulate an in-flight send, then close: the Close SQE is deferred.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "close must defer while a send is in flight"
        );
        assert!(
            !el.driver.pending_finalize_closes.contains(&conn_index),
            "nothing to drain while the send is in flight"
        );

        // The send's CQE path ends in submit_next_queued with an empty
        // queue — this registers the close; the drain commits it.
        el.driver.submit_next_queued(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "the close stays pending until the drain"
        );
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));
        el.finalize_pending_closes();
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "deferred close must finalize in the drain once the queue drains"
        );
        assert!(el.driver.send_queues[conn_index as usize].close_submitted);
    }

    #[test]
    fn drain_conn_send_queue_registers_deferred_close_for_the_drain() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.driver.close_connection(conn_index);
        assert!(el.driver.send_queues[conn_index as usize].close_pending);

        el.driver.drain_conn_send_queue(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "the close stays pending until the drain"
        );
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));
        el.finalize_pending_closes();
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "deferred close must finalize in the drain once the queue is force-drained"
        );
    }

    // ── Executor wake-path regression tests ────────────────────────

    #[test]
    fn self_wake_via_channel_completes() {
        // join(rx.recv(), try_send) inside ONE task: recv registers its
        // waiter, try_send wakes it while the task is mid-poll (slot
        // `Polling`). The wake used to be dropped -> permanent deadlock.
        use crate::runtime::{channel::mpsc, join::join};
        let mut el = make_test_loop();
        let (tx, rx) = mpsc::channel::<u32>(4);
        let done = std::rc::Rc::new(std::cell::Cell::new(false));
        let done2 = done.clone();

        let idx = el
            .executor
            .standalone_slab
            .spawn(Box::pin(async move {
                let (v, _) = join(rx.recv(), async move {
                    tx.try_send(7).unwrap();
                })
                .await;
                assert_eq!(v, Some(7));
                done2.set(true);
            }))
            .unwrap();
        el.executor.ready_queue.push_back(idx | STANDALONE_BIT);

        for _ in 0..4 {
            el.poll_ready_tasks();
        }
        assert!(
            done.get(),
            "self-wake during poll was lost — task deadlocked"
        );
    }

    #[test]
    fn stored_std_waker_wakes_parked_task() {
        // A future that stashes cx.waker() and is woken later from outside
        // its own poll. The drain path used to skip the Parked->Ready
        // transition, so the wake was lost forever.
        use std::cell::RefCell;
        use std::rc::Rc;
        use std::task::{Poll, Waker};

        struct StashWaker {
            slot: Rc<RefCell<Option<Waker>>>,
            polls: u32,
        }
        impl std::future::Future for StashWaker {
            type Output = ();
            fn poll(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<()> {
                self.polls += 1;
                if self.polls == 1 {
                    *self.slot.borrow_mut() = Some(cx.waker().clone());
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }
        }

        let mut el = make_test_loop();
        let slot = Rc::new(RefCell::new(None));
        let done = std::rc::Rc::new(std::cell::Cell::new(false));
        let (slot2, done2) = (slot.clone(), done.clone());

        let idx = el
            .executor
            .standalone_slab
            .spawn(Box::pin(async move {
                StashWaker {
                    slot: slot2,
                    polls: 0,
                }
                .await;
                done2.set(true);
            }))
            .unwrap();
        el.executor.ready_queue.push_back(idx | STANDALONE_BIT);
        el.poll_ready_tasks();
        assert!(!done.get(), "future must park on first poll");

        // Wake from "outside" (e.g. another task) via the stored waker.
        slot.borrow().as_ref().unwrap().wake_by_ref();
        el.executor.collect_wakeups();
        el.poll_ready_tasks();

        assert!(done.get(), "stored-waker wake of a parked task was lost");
    }

    #[test]
    fn mpsc_two_blocked_senders_both_complete() {
        // Two producers blocked on a capacity-1 channel: the single-slot
        // send_waiter used to let the second registration overwrite the
        // first, hanging it forever.
        use crate::runtime::channel::mpsc;
        let mut el = make_test_loop();
        let (tx, rx) = mpsc::channel::<u32>(1);
        tx.try_send(0).unwrap(); // fill the queue
        let completed = std::rc::Rc::new(std::cell::Cell::new(0u32));

        for _ in 0..2 {
            let tx = tx.clone();
            let completed = completed.clone();
            let idx = el
                .executor
                .standalone_slab
                .spawn(Box::pin(async move {
                    tx.send(1).await.unwrap();
                    completed.set(completed.get() + 1);
                }))
                .unwrap();
            el.executor.ready_queue.push_back(idx | STANDALONE_BIT);
        }
        // Park both senders on the full queue.
        el.poll_ready_tasks();
        assert_eq!(completed.get(), 0);

        // Drain three values (the prefill + both sends), interleaving polls
        // so each freed slot wakes exactly one blocked sender.
        let drainer_done = std::rc::Rc::new(std::cell::Cell::new(false));
        let dd = drainer_done.clone();
        let idx = el
            .executor
            .standalone_slab
            .spawn(Box::pin(async move {
                for _ in 0..3 {
                    assert!(rx.recv().await.is_some());
                }
                dd.set(true);
            }))
            .unwrap();
        el.executor.ready_queue.push_back(idx | STANDALONE_BIT);

        for _ in 0..8 {
            el.poll_ready_tasks();
        }
        assert!(drainer_done.get(), "drainer did not finish");
        assert_eq!(
            completed.get(),
            2,
            "a blocked sender's wake was lost (single-slot send_waiter)"
        );
    }

    // ── Linked SQE chain error propagation tests ───────────────────
    //
    // Submit linked NOP chains where the first SQE fails. The kernel
    // cancels subsequent linked SQEs with ECANCELED. This tests the
    // chain error handling path end-to-end through the real kernel.

    #[test]
    fn linked_chain_copy_send_first_fails_releases_all() {
        // 3-SQE chain: first Send fails, second and third get ECANCELED.
        // All pool slots should be released, chain should complete.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Allocate 3 pool slots for the chain.
        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Register chain state: 3 SQEs, 9 total bytes.
        el.driver.chain_table.start(conn_index, 3);
        let id = await_chain(&mut el, conn_index);

        // Submit linked NOPs: first with injected error, rest linked.
        // The completions are: error CQE, ECANCELED CQE, ECANCELED CQE.
        let ud1 = UserData::encode(OpTag::Send, conn_index, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, conn_index, s2 as u32);
        let ud3 = UserData::encode(OpTag::Send, conn_index, s3 as u32);

        el.inject_linked_chain_and_dispatch(&[
            (ud1.raw(), -104), // ECONNRESET — first SQE fails
            (ud2.raw(), 0),    // kernel sets result for linked NOPs
            (ud3.raw(), 0),    // kernel sets result for linked NOPs
        ]);

        // All 3 pool slots should be released.
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 3,
            "not all pool slots released after chain error"
        );

        // Chain should be complete (no longer active).
        assert!(
            !el.driver.chain_table.is_active(conn_index),
            "chain still active after all CQEs processed"
        );

        // The awaited chain settled with an error.
        assert!(
            matches!(send_result(&mut el, id), Some(Err(_))),
            "chain result not stored"
        );
    }

    #[test]
    fn linked_chain_middle_fails_rest_canceled() {
        // 3-SQE chain: first succeeds, second fails, third ECANCELED.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        el.driver.chain_table.start(conn_index, 3);
        let id = await_chain(&mut el, conn_index);

        let ud1 = UserData::encode(OpTag::Send, conn_index, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, conn_index, s2 as u32);
        let ud3 = UserData::encode(OpTag::Send, conn_index, s3 as u32);

        el.inject_linked_chain_and_dispatch(&[
            (ud1.raw(), 3),    // first succeeds (3 bytes)
            (ud2.raw(), -104), // second fails
            (ud3.raw(), 0),    // third ECANCELED
        ]);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 3,
            "not all pool slots released"
        );
        assert!(!el.driver.chain_table.is_active(conn_index));
        assert!(matches!(send_result(&mut el, id), Some(Err(_))));
    }

    #[test]
    fn linked_chain_all_succeed() {
        // 3-SQE chain: all succeed. No errors.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        el.driver.chain_table.start(conn_index, 3);
        let id = await_chain(&mut el, conn_index);

        let ud1 = UserData::encode(OpTag::Send, conn_index, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, conn_index, s2 as u32);
        let ud3 = UserData::encode(OpTag::Send, conn_index, s3 as u32);

        el.inject_linked_chain_and_dispatch(&[(ud1.raw(), 3), (ud2.raw(), 3), (ud3.raw(), 3)]);

        assert_eq!(el.driver.send_copy_pool.free_count(), free_before + 3);
        assert!(!el.driver.chain_table.is_active(conn_index));
        assert_eq!(send_result(&mut el, id).unwrap().unwrap(), 9);
    }

    // ── Cancel injection tests ─────────────────────────────────────
    //
    // Submit a real timeout SQE, then cancel it with ASYNC_CANCEL.
    // This exercises the timer ECANCELED path through the real kernel,
    // simulating what happens when SleepFuture is dropped via select!.

    #[test]
    fn cancel_injection_timer_ecanceled() {
        let mut el = make_test_loop();

        // Allocate a timer slot and submit a real timeout (10 seconds — won't fire).
        let waker_id = 0u32;
        let (slot, generation) = el.executor.timer_pool.allocate(waker_id).unwrap();

        // Set up the timespec in the pool.
        el.executor.timer_pool.timespecs[slot as usize] =
            crate::backend::uring::abi::Timespec::new().sec(10).nsec(0);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let timer_ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr = &el.executor.timer_pool.timespecs[slot as usize]
            as *const crate::backend::uring::abi::Timespec;

        // Submit the real timeout SQE.
        el.driver
            .ring
            .submit_timeout(ts_ptr, timer_ud)
            .expect("submit_timeout failed");

        // Now cancel it — simulating SleepFuture::drop.
        el.driver
            .ring
            .submit_async_cancel(timer_ud.raw(), 0)
            .expect("submit_async_cancel failed");

        // Process CQEs: should get Timer CQE with -ECANCELED,
        // and Cancel CQE (which is a no-op in dispatch).
        el.driver
            .ring
            .submit_and_wait(2)
            .expect("submit_and_wait failed");
        el.drain_completions();

        // Timer should NOT be fired (it was cancelled, not expired).
        assert!(
            !el.executor.timer_pool.is_fired(slot),
            "cancelled timer should not be fired"
        );

        // Simulate SleepFuture::drop releasing the slot.
        el.executor.timer_pool.release(slot);

        // Verify the slot can be reallocated (proves it was returned).
        let (slot2, _gen2) = el.executor.timer_pool.allocate(0).unwrap();
        assert_eq!(slot2, slot, "released slot should be reusable");
        el.executor.timer_pool.release(slot2);
    }

    #[test]
    fn cancel_injection_timer_fires_before_cancel() {
        // Submit a very short timeout (1ns), then cancel. The timeout
        // might fire before the cancel takes effect. Both outcomes
        // should be handled without panic or leak.
        let mut el = make_test_loop();

        let waker_id = 0u32;
        let (slot, generation) = el.executor.timer_pool.allocate(waker_id).unwrap();

        // 1 nanosecond timeout — will fire almost immediately.
        el.executor.timer_pool.timespecs[slot as usize] =
            crate::backend::uring::abi::Timespec::new().sec(0).nsec(1);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let timer_ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr = &el.executor.timer_pool.timespecs[slot as usize]
            as *const crate::backend::uring::abi::Timespec;

        el.driver
            .ring
            .submit_timeout(ts_ptr, timer_ud)
            .expect("submit_timeout failed");
        el.driver
            .ring
            .submit_async_cancel(timer_ud.raw(), 0)
            .expect("submit_async_cancel failed");

        // Process all CQEs.
        el.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        // Small sleep to let both CQEs arrive.
        std::thread::sleep(std::time::Duration::from_millis(10));
        el.drain_completions();

        // Either the timer fired (-ETIME) or was cancelled (-ECANCELED).
        // In both cases: no panic, no leak.
        // If fired, the slot is marked as fired.
        // If cancelled, the slot is not fired.
        // Release the slot (simulating SleepFuture::drop).
        el.executor.timer_pool.release(slot);

        // No assertions on fired state — both outcomes are valid.
        // The key assertion: no panic during processing, and the slot
        // is cleanly released.
    }

    // ── Bounded-send settlement, teardown and identity ─────────────
    //
    // Series PR 7b (`docs/uring-bounded-send-design.md`). A bounded send
    // (`ConnCtx::send_backpressured`, series PR 9) must resolve with the
    // exact result of *its own* operation. On io_uring its id rides the
    // final pool slot — lifted onto the slab entry when the run is
    // coalesced — and every completion, give-up and teardown site takes the
    // id and settles it.
    //
    // A site that drops a settle and a site that drops the *take* fail
    // differently, on purpose: the first leaves the operation unresolved and
    // fails an assertion here; the second trips `SendCopyPool::release`'s
    // debug tripwire ("released while still carrying bounded send") and
    // panics inside the production code instead.

    /// Spawn a standalone task and park it, returning its full task id.
    ///
    /// Every bounded send in this section is owned by a standalone task, as
    /// mio's equivalents are: an entry owned by its own connection's task is
    /// *dropped* by teardown rather than resolved (`SendCompletions`'s
    /// dead-owner rule), because that task's future is already gone. Parked
    /// rather than left Ready so that waking it is a real transition.
    fn parked_standalone(executor: &mut Executor) -> u32 {
        let idx = executor
            .standalone_slab
            .spawn(Box::pin(std::future::pending::<()>()))
            .expect("free standalone slot");
        let future = executor
            .standalone_slab
            .take_ready(idx)
            .expect("a freshly spawned task is Ready");
        executor.standalone_slab.park(idx, future);
        idx | STANDALONE_BIT
    }

    /// A loop with the SQ-pressure tests' tiny 8 x 64-byte send pool, so a
    /// 100-byte message is genuinely more than one slot.
    fn bounded_test_loop() -> AsyncEventLoop<NoopHandler> {
        make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        )
    }

    /// Take an id from the capacity FIFO and mark it submitted, for the
    /// handler tests that build the pool slot (or slab entry) by hand the
    /// way the existing send tests do. `SendId` has no constructor
    /// but `enqueue`, which is how the real caller gets one too.
    fn submitted_id(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
    ) -> SendId {
        let task_id = parked_standalone(&mut el.executor);
        let id = el
            .executor
            .enqueue_send_capacity(conn_index, generation, 1, task_id);
        el.executor.mark_send_submitted(id);
        id
    }

    /// Admit one bounded send end to end, the way series PR 9's future
    /// will: park an owner, take an id, hand the message to
    /// `DriverCtx::send_bounded`, mark it submitted.
    fn admit_bounded_send(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn: crate::handler::ConnId,
        data: &[u8],
        required_slots: usize,
    ) -> SendId {
        let task_id = parked_standalone(&mut el.executor);
        let id =
            el.executor
                .enqueue_send_capacity(conn.index, conn.generation, required_slots, task_id);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send_bounded(conn, data, id).expect("admitted");
        }
        el.executor.mark_send_submitted(id);
        id
    }

    /// Submit what is in the SQ, wait for a completion, and dispatch the
    /// batch — one real CQE round-trip against the attached socketpair.
    fn complete_one_cqe(el: &mut AsyncEventLoop<NoopHandler>) {
        el.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        el.drain_completions();
    }

    /// Drain everything the peer can read right now.
    fn drain_peer(peer: &std::os::fd::OwnedFd, buf: &mut [u8]) -> usize {
        let mut got = 0;
        while got < buf.len() {
            match try_recv(peer, &mut buf[got..]) {
                Some(0) | None => break,
                Some(n) => got += n,
            }
        }
        got
    }

    /// A test loop whose slots can hold one whole worst-case TLS record, so
    /// the ciphertext bound is expressible. The 64-byte slots the other
    /// bounded tests use cannot.
    fn tls_bounded_test_loop() -> AsyncEventLoop<NoopHandler> {
        make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 16448)
                .build()
                .expect("valid config"),
        )
    }

    /// Install an already-handshaked TLS connection at `conn_index`, driven by
    /// whichever record-layer engine this build compiled in. `accept_connection`
    /// deliberately does not create one (the table has no server config), so
    /// this is the only TLS a bounded-send test sees.
    fn install_handshaked_tls(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32) {
        let _peer = install_handshaked_tls_with_peer(el, conn_index);
    }

    /// The client end of a connection installed by
    /// [`install_handshaked_tls_with_peer`], able to decrypt what the server
    /// end sends.
    struct TlsTestPeer {
        #[cfg(not(feature = "tls-buffered"))]
        conn: crate::tls::TlsConn,
        #[cfg(feature = "tls-buffered")]
        conn: crate::tls::buffered::BufferedKind,
    }

    impl TlsTestPeer {
        /// The plaintext `ciphertext` carries, or the record layer's error. A
        /// record sealed and then dropped leaves a sequence gap, which the
        /// next record reports as `bad_record_mac`.
        fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            #[cfg(not(feature = "tls-buffered"))]
            return crate::tls::unbuffered::tests::decrypt_at(&mut self.conn, ciphertext);
            #[cfg(feature = "tls-buffered")]
            return crate::tls::buffered::test_support::decrypt_at(&mut self.conn, ciphertext);
        }
    }

    /// As [`install_handshaked_tls`], keeping the client end.
    fn install_handshaked_tls_with_peer(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
    ) -> TlsTestPeer {
        let max = el.driver.connections.max_slots();
        let mut table = crate::tls::TlsTable::with_listener_configs(max, None, None, Vec::new());
        #[cfg(not(feature = "tls-buffered"))]
        let peer = {
            let (server, client) = crate::tls::unbuffered::tests::handshaked_pair();
            table.insert_for_test(conn_index, server);
            TlsTestPeer { conn: client }
        };
        #[cfg(feature = "tls-buffered")]
        let peer = {
            let (server, client) = crate::tls::buffered::test_support::handshaked();
            table.insert_for_test(
                conn_index,
                crate::tls::buffered::test_support::wrap_server(server),
            );
            TlsTestPeer { conn: client }
        };
        el.driver.tls_table = Some(table);
        // A TLS connection receives into its TLS engine's buffer, not its
        // accumulator.
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.recv_direct = false;
        }
        peer
    }

    /// A Close that completes before the TLS receive it cancelled moves the
    /// receive's buffer allocation out of the dropped TLS state into the
    /// receive's entry, which frees it when the receive completes. The
    /// receive's SQE is pushed but never submitted, so the kernel never writes
    /// into the allocation this test frees.
    #[cfg(not(feature = "tls-buffered"))]
    #[test]
    fn a_close_before_the_tls_receive_completes_moves_the_allocation() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        let slot = el
            .driver
            .connections
            .get(conn_index)
            .unwrap()
            .recv_direct_slot;
        el.test_dispatch_cqe(UserData::encode(OpTag::Close, conn_index, 0).raw(), 0, 0);
        assert!(matches!(
            &el.driver.direct_recvs[slot as usize],
            Some(crate::backend::uring::driver::DirectRecv {
                buf: crate::backend::uring::driver::DirectRecvBuf::Tls(Some(_)),
                ..
            })
        ));
        el.test_dispatch_cqe(
            UserData::encode(OpTag::RecvDirect, conn_index, slot).raw(),
            -libc::ECANCELED,
            0,
        );
        assert!(el.driver.direct_recvs[slot as usize].is_none());
    }

    /// Worker shutdown with a TLS receive in flight ends the receive in the TLS
    /// state before the Close drops it, so the Close finds none in flight.
    #[test]
    fn shutdown_ends_an_in_flight_tls_receive() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert!(!el.driver.arm_direct_recv_or_close(conn_index, None));
        el.driver.ring.flush().unwrap();
        el.driver.run_shutdown();
        assert!(el.driver.direct_recvs.iter().all(Option::is_none));
        assert!(el.driver.connections.get(conn_index).is_none());
        assert!(!el.driver.tls_table.as_ref().unwrap().has(conn_index));
    }

    /// Run `conn_index`'s queued sends through the real ring until it is idle,
    /// then return everything that reached `peer`.
    fn flush_sends_to_peer(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        peer: &std::os::fd::OwnedFd,
    ) -> Vec<u8> {
        for _ in 0..64 {
            if !el.driver.send_queues[conn_index as usize].in_flight {
                break;
            }
            el.driver
                .ring
                .submit_and_wait(1)
                .expect("submit_and_wait failed");
            el.drain_completions();
        }
        assert!(
            !el.driver.send_queues[conn_index as usize].in_flight,
            "sends did not drain"
        );
        let mut wire = Vec::new();
        let mut buf = [0u8; 65536];
        while let Some(n) = try_recv(peer, &mut buf) {
            if n == 0 {
                break;
            }
            wire.extend_from_slice(&buf[..n]);
        }
        wire
    }

    /// Take free send-pool slots until only `leave` remain; hand them back
    /// with [`release_slots`].
    fn hold_all_but(el: &mut AsyncEventLoop<NoopHandler>, leave: usize) -> Vec<u16> {
        let mut held = Vec::new();
        while el.driver.send_copy_pool.free_count() > leave {
            let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"x").unwrap();
            held.push(slot);
        }
        held
    }

    fn release_slots(el: &mut AsyncEventLoop<NoopHandler>, held: Vec<u16>) {
        for slot in held {
            el.driver.send_copy_pool.release(slot);
        }
    }

    /// A plain TLS send that the pool cannot cover must be refused *before*
    /// rustls seals a record. Encrypting first and running out partway left
    /// the sealed records' sequence numbers spent with no ciphertext on the
    /// wire, so every later record failed `bad_record_mac` at the peer —
    /// and the connection was left open to send them.
    ///
    /// One free slot holds the first record of a two-record send, which is
    /// exactly where the old path ran dry.
    #[test]
    fn plain_tls_send_refuses_before_encrypting_when_the_pool_is_short() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer_fd) = attach_socketpair(&mut el, conn_index);
        let mut peer = install_handshaked_tls_with_peer(&mut el, conn_index);

        let held = hold_all_but(&mut el, 1);
        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &[b'z'; 16448])
                .expect_err("one free slot cannot cover a two-record send")
        };
        assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
        assert_eq!(el.driver.send_copy_pool.free_count(), 1);
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested(),
            "a pre-encryption refusal is backpressure, not a dead connection"
        );

        // The refusal spent no sequence number: once the pool frees up, the
        // next record decrypts.
        release_slots(&mut el, held);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello").expect("the pool has room now");
        }
        let wire = flush_sends_to_peer(&mut el, conn_index, &peer_fd);
        assert_eq!(peer.decrypt(&wire).as_deref(), Ok(&b"hello"[..]));
    }

    /// A plain TLS send wider than the whole pool can never be admitted. It
    /// used to be discovered mid-encryption, after rustls had sealed records
    /// for it; now it is refused up front with `InvalidInput`, like the
    /// plaintext path, and the connection carries on.
    #[test]
    fn plain_tls_send_wider_than_the_pool_is_refused_up_front() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer_fd) = attach_socketpair(&mut el, conn_index);
        let mut peer = install_handshaked_tls_with_peer(&mut el, conn_index);

        // Nine records into an eight-slot pool.
        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &vec![b'z'; 9 * 16384])
                .expect_err("nine records cannot fit eight slots")
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err}");
        assert_eq!(el.driver.send_copy_pool.free_count(), 8);

        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello").expect("a small send still fits");
        }
        let wire = flush_sends_to_peer(&mut el, conn_index, &peer_fd);
        assert_eq!(peer.decrypt(&wire).as_deref(), Ok(&b"hello"[..]));
    }

    /// `send_parts` on a TLS connection gathers and encrypts through the same
    /// path, so it gets the same pre-encryption refusal.
    #[test]
    fn tls_send_parts_refuses_before_encrypting_when_the_pool_is_short() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer_fd) = attach_socketpair(&mut el, conn_index);
        let mut peer = install_handshaked_tls_with_peer(&mut el, conn_index);

        let held = hold_all_but(&mut el, 1);
        let big = [b'z'; 16448];
        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_parts(token)
                .copy(&big[..8000])
                .copy(&big[8000..])
                .submit()
                .expect_err("one free slot cannot cover a two-record send")
        };
        assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .close_requested()
        );

        release_slots(&mut el, held);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello").expect("the pool has room now");
        }
        let wire = flush_sends_to_peer(&mut el, conn_index, &peer_fd);
        assert_eq!(peer.decrypt(&wire).as_deref(), Ok(&b"hello"[..]));
    }

    /// Where no bound can be expressed (the unbuffered engine with a slot too
    /// small to hold one whole record) a plain send is attempted without one.
    /// `Config::validate` rejects such a slot for every configured rustls
    /// config, so this test installs TLS state directly, after validation. If
    /// the pool runs dry mid-encryption the records already sealed have spent
    /// their sequence numbers, so the connection is closed rather than left
    /// open to emit records the peer will reject.
    #[cfg(not(feature = "tls-buffered"))]
    #[test]
    fn plain_tls_send_that_fails_mid_encryption_closes_the_connection() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 4096)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, _peer_fd) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);
        assert_eq!(
            el.driver
                .tls_table
                .as_ref()
                .unwrap()
                .ciphertext_capacity(conn_index, 16384)
                .unwrap()
                .slots(4096),
            None,
            "the premise: this slot size has no expressible bound"
        );

        let held = hold_all_but(&mut el, 1);
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, &[b'z'; 16384])
        };
        assert!(result.is_err(), "one 4 KiB slot cannot hold 16 KiB");
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "records were sealed and dropped, so the connection must close"
        );
        // The close queues a close_notify, and it can only have got a slot if
        // the failed encryption gave back the one it took.
        assert_eq!(el.driver.send_copy_pool.free_count(), 0);
        assert!(
            el.driver.send_queues[conn_index as usize].in_flight,
            "the close_notify is on its way, in the slot the encryption returned"
        );
        release_slots(&mut el, held);
    }

    /// Departure 1, end to end on the path the series was built for: a
    /// bounded **TLS** send whose SQE cannot be pushed.
    ///
    /// This is the case #318's original design got wrong. Its fix was to
    /// return `WouldBlock` and let the future retry the whole logical send —
    /// but by then rustls has advanced its record sequence for ciphertext
    /// that never reached the wire, so the re-encrypted records carry
    /// sequence numbers the peer is not expecting and it fails the connection
    /// with `bad_record_mac`. PR 4 refined the rule: park the *built* SQE and
    /// re-push the same bytes, which re-runs no encryption at all, and if the
    /// SQ stays full past the cap, fail the operation and close the
    /// connection rather than drop it silently.
    ///
    /// What this pins is that a bounded TLS send takes that path: it never
    /// re-encrypts, the caller is told, and the connection goes down instead
    /// of emitting a record gap.
    #[test]
    fn bounded_tls_send_parks_and_then_fails_rather_than_re_encrypting() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);

        let free_before = el.driver.send_copy_pool.free_count();

        // The initial push and every retry are refused.
        el.driver.ring.force_push_failures(4);
        let id = admit_bounded_send(&mut el, token, &[b'z'; 512], 2);

        // Parked, not failed, and nothing resolved yet: the bytes are still
        // committed to this connection's stream.
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)],
            "a full SQ parks the built SQE rather than failing the send"
        );
        assert!(
            el.executor.take_send_result(id).is_none(),
            "nothing resolves while the entry is merely parked"
        );

        el.drain_send_retries();
        assert!(el.executor.take_send_result(id).is_none());
        el.drain_send_retries();
        assert!(el.executor.take_send_result(id).is_none());

        // Past the cap: the operation fails and the connection goes down.
        el.drain_send_retries();
        assert!(el.driver.pending_send_retries.is_empty());
        // The give-up path does not settle the id directly — the parked entry
        // is still queued, so `drain_conn_send_queue` -> `release_queued_sends`
        // takes it off the pool slot and fails it through the driver's
        // completion queue, which the run loop drains. Skipping this step is
        // what makes the settle look like it never happened.
        el.drain_settled_sends();
        let result = el
            .executor
            .take_send_result(id)
            .expect("the retry cap must settle the bounded send, not drop it");
        assert!(
            result.is_err(),
            "the caller learns the message did not go out"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "a TLS send that cannot reach the wire closes the connection, \
             because the records it already sealed left a gap"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before,
            "giving up returns every slot the encryption took"
        );
    }

    /// Series PR 8 on the io_uring side: a bounded TLS send is admitted
    /// against the *ciphertext* bound before `encrypt_to_sends` runs, and the
    /// encryption never beats that bound.
    #[test]
    fn bounded_tls_send_is_admitted_against_the_ciphertext_bound() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);

        // Fits in one slot as plaintext but spans two records, so plaintext
        // sizing and ciphertext sizing give different answers.
        const PLAINTEXT: usize = 16448;
        let bound = el
            .driver
            .tls_table
            .as_ref()
            .unwrap()
            .ciphertext_capacity(conn_index, PLAINTEXT)
            .expect("the connection has TLS state");
        assert_eq!(bound.records(), 3);
        assert_eq!(bound.slots(16448), Some(3));

        let free_before = el.driver.send_copy_pool.free_count();
        assert_eq!(free_before, 8);
        let _id = admit_bounded_send(
            &mut el,
            token,
            &[b'z'; PLAINTEXT],
            bound.slots(16448).unwrap(),
        );

        let used = free_before - el.driver.send_copy_pool.free_count();
        assert!(
            used > PLAINTEXT.div_ceil(16448),
            "the ciphertext genuinely costs more slots than the plaintext \
             would have reserved ({used} used)"
        );
        assert!(
            used <= 3,
            "encryption must never beat the bound it was admitted against \
             ({used} used against a bound of 3)"
        );
    }

    /// The refusal has to happen *before* rustls mutates. Once a record is
    /// sealed the sequence number is spent, so by departure 1 a shortfall
    /// discovered mid-encryption closes the connection instead of applying
    /// backpressure. With only enough free slots for the plaintext, admission
    /// must still refuse.
    #[test]
    fn bounded_tls_send_refuses_before_encrypting_when_the_bound_does_not_fit() {
        let mut el = tls_bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, _peer) = attach_socketpair(&mut el, conn_index);
        install_handshaked_tls(&mut el, conn_index);

        // Leave two free slots: enough for one slot of plaintext, short of the
        // three-slot ciphertext bound.
        let mut held = Vec::new();
        while el.driver.send_copy_pool.free_count() > 2 {
            let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"x").unwrap();
            held.push(slot);
        }

        const PLAINTEXT: usize = 16448;
        let task_id = parked_standalone(&mut el.executor);
        let id = el
            .executor
            .enqueue_send_capacity(conn_index, generation, 3, task_id);
        let err = {
            let mut ctx = el.driver.make_ctx();
            ctx.send_bounded(token, &[b'z'; PLAINTEXT], id)
                .expect_err("two free slots cannot cover a three-slot bound")
        };
        assert_eq!(err.kind(), std::io::ErrorKind::Other, "{err}");

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            2,
            "a refusal must not have encrypted anything"
        );
        assert!(
            el.driver.connections.get(conn_index).is_some(),
            "backpressure, not a closed connection"
        );

        for slot in held {
            el.driver.send_copy_pool.release(slot);
        }
    }

    /// One id, one settle: a single-slot bounded send resolves `Ok` with the
    /// length its caller passed, when its own CQE lands and not before.
    #[test]
    fn bounded_send_single_slot_settles_ok_with_the_logical_length() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let id = admit_bounded_send(&mut el, token, b"hello", 1);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            7,
            "the message took exactly one slot"
        );
        assert!(
            el.executor.take_send_result(id).is_none(),
            "nothing may resolve before the completion"
        );

        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the send CQE must settle the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            5,
            "a bounded send reports the length its caller passed"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the completion returned the slot"
        );
        let mut buf = [0u8; 16];
        assert_eq!(drain_peer(&peer, &mut buf), 5);
        assert_eq!(&buf[..5], b"hello");
    }

    /// A message wider than one pool slot goes to the kernel as one
    /// `sendmsg` over its slots, and its one completion reports the logical
    /// length and returns every slot.
    #[test]
    fn a_multi_slot_bounded_send_is_one_sendmsg_and_settles_once() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        // 100 bytes over 64-byte slots: chunks of 64 and 36.
        let payload = vec![b'm'; 100];
        let id = admit_bounded_send(&mut el, token, &payload, 2);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            6,
            "the premise of this test: the message really is two slots"
        );
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "both chunks went to the ring as one sendmsg; nothing is queued"
        );

        // The one completion carries both chunks and settles the operation.
        complete_one_cqe(&mut el);
        let result = el
            .executor
            .take_send_result(id)
            .expect("the run's completion settles the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            100,
            "the logical length, not a chunk's"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "both slots came back"
        );

        let mut buf = [0u8; 128];
        assert_eq!(drain_peer(&peer, &mut buf), 100);
    }

    /// A plain `send` wider than one pool slot also goes to the kernel as one
    /// `sendmsg`, whose completion returns every slot.
    #[test]
    fn a_multi_slot_send_is_one_sendmsg() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        // 150 bytes over 64-byte slots: chunks of 64, 64 and 22.
        let payload = vec![b'n'; 150];
        el.driver.make_ctx().send(token, &payload).expect("send");
        assert_eq!(el.driver.send_copy_pool.free_count(), 5, "three slots");
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "all three chunks went to the ring as one sendmsg"
        );

        complete_one_cqe(&mut el);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "one completion returned every slot"
        );
        let mut buf = [0u8; 256];
        assert_eq!(drain_peer(&peer, &mut buf), 150);
    }

    /// A zero-length bounded send queues no SQE, so no CQE will ever settle
    /// it: `send_bounded` settles it itself, synchronously, through
    /// `Driver::settled_sends`. This is why that queue's payload
    /// is an `io::Result` and not an `io::Error` — its defining property is
    /// the *missing completion*, not failure.
    #[test]
    fn zero_length_bounded_send_settles_ok_without_a_cqe() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        let id = admit_bounded_send(&mut el, token, b"", 0);
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty()
                && !el.driver.send_queues[conn_index as usize].in_flight,
            "an empty message produces no SQE at all"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "and takes no slot"
        );
        assert_eq!(
            el.driver.settled_sends.len(),
            1,
            "so the driver settles it itself"
        );

        el.drain_settled_sends();
        let result = el
            .executor
            .take_send_result(id)
            .expect("the synchronous settle reached the executor");
        assert_eq!(result.expect("an empty send succeeds"), 0);
    }

    /// A partial write resubmits the remainder in place; the id stays on the
    /// slot and is settled exactly once, by the completion that finishes the
    /// message and with the whole length — never the partial count.
    #[test]
    fn bounded_send_partial_write_settles_once_with_the_whole_length() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let data = [b'p'; 20];
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(&data).unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 20);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        // 8 of 20 bytes: the handler keeps the slot (and its id) and
        // resubmits the remainder.
        el.test_dispatch_cqe(ud.raw(), 8, 0);
        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "a partial write keeps its slot"
        );
        assert!(
            el.executor.take_send_result(id).is_none(),
            "a partial write must not settle the operation"
        );

        // The remaining 12 finish it.
        el.test_dispatch_cqe(ud.raw(), 12, 0);
        let result = el
            .executor
            .take_send_result(id)
            .expect("the finishing CQE settles the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            20,
            "the whole message, not the 12 bytes of the finishing CQE"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the finishing CQE returns the slot"
        );
    }

    /// A coalesced run settles the id that `submit_next_queued_inner` lifted
    /// off the run's final pool slot and onto the slab entry — with
    /// the carried logical length, not the run's wire total.
    #[test]
    fn coalesced_run_settles_the_id_lifted_onto_the_slab_entry() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let id = submitted_id(&mut el, conn_index, generation);

        // Two chunks of one logical send behind an in-flight send: a
        // coalescable run.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let c0 = built_copy_send(&mut el, conn_index, b"aa");
        let c1 = built_copy_send(&mut el, conn_index, b"bbb");
        // Deliberately neither chunk's length and not the run's 5 wire
        // bytes: under TLS the number the caller passed is a plaintext
        // length no completion handler can recompute, which is the whole
        // reason it travels with the id.
        el.driver.send_copy_pool.set_send_id(c1.pool_slot, id, 99);
        let last_slot = c1.pool_slot;
        {
            let q = &mut el.driver.send_queues[conn_index as usize].queue;
            q.push_back(c0);
            q.push_back(c1);
        }

        assert!(
            el.driver.submit_next_queued(conn_index),
            "the run must coalesce and push"
        );
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "the whole run was popped"
        );
        assert_eq!(
            el.driver.send_copy_pool.take_send_id(last_slot),
            None,
            "the id moved off the pool slot onto the slab entry"
        );

        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the coalesced CQE settles the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            99,
            "the carried logical length, not the 5 bytes on the wire"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "both slots came back with the coalesced completion"
        );
        let mut buf = [0u8; 16];
        assert_eq!(drain_peer(&peer, &mut buf), 5);
        assert_eq!(&buf[..5], b"aabbb");
    }

    /// An awaited send queued behind a send that fails is drained with the
    /// queue, and fails `ConnectionAborted`: its bytes never reach the wire.
    #[test]
    fn a_queued_awaited_send_fails_when_the_send_ahead_of_it_fails() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"ahead").unwrap();
        let ahead = await_slot(&mut el, conn_index, slot, 5);
        let behind = built_copy_send(&mut el, conn_index, b"behind");
        let queued = await_slot(&mut el, conn_index, behind.pool_slot, 6);
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(behind);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        assert_eq!(
            send_result(&mut el, ahead)
                .expect("the failed send settled")
                .expect_err("it failed")
                .raw_os_error(),
            Some(libc::ECONNRESET)
        );
        assert_eq!(
            send_result(&mut el, queued)
                .expect("the drained send settled")
                .expect_err("it never reached the wire")
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// A queued zero-copy batch carries its send on its slab entry, and a
    /// drain of the queue fails it like a copied send.
    #[test]
    fn a_queued_zero_copy_send_fails_when_the_queue_is_drained() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, msg_ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .expect("slab room");
        let id = await_slab(&mut el, conn_index, slab_idx, 100);
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        let entry = crate::backend::uring::sqe::Sqe::send_msg_zc(conn_index, msg_ptr, ud.raw());
        let state = &mut el.driver.send_queues[conn_index as usize];
        state.queue.push_back(crate::handler::BuiltSend {
            entry,
            pool_slot: u16::MAX,
            slab_idx,
        });
        state.in_flight = true;

        el.driver.drain_conn_send_queue(conn_index);

        assert_eq!(
            send_result(&mut el, id)
                .expect("the drained zero-copy send settled")
                .expect_err("it never reached the wire")
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!el.driver.send_slab.in_use(slab_idx));
    }

    /// A chain abandoned by a forced close fails the send it carries.
    #[test]
    fn a_force_closed_chain_fails_its_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.chain_table.start(conn_index, 1);
        let id = await_chain(&mut el, conn_index);

        el.driver.force_finalize_close(conn_index);

        assert_eq!(
            send_result(&mut el, id)
                .expect("the cancelled chain settled its send")
                .expect_err("the chain never completed")
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    /// A zero-copy send settles on its operation CQE, before the
    /// notification that frees its guards.
    #[test]
    fn a_zero_copy_send_settles_before_its_notification() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .expect("slab room");
        let id = await_slab(&mut el, conn_index, slab_idx, 100);
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);

        // The operation CQE, with a notification still to come.
        el.test_dispatch_cqe(ud.raw(), 100, CQE_F_MORE);
        assert_eq!(send_result(&mut el, id).unwrap().unwrap(), 100);
        assert!(
            el.driver.send_slab.in_use(slab_idx),
            "the entry waits for its notification"
        );

        el.test_dispatch_cqe(ud.raw(), 0, CQE_F_NOTIF);
        assert!(!el.driver.send_slab.in_use(slab_idx));
    }

    /// An awaited send that is refused, or submits nothing, leaves no entry
    /// in the completion table: no completion would ever free it.
    #[test]
    fn a_refused_awaited_send_leaves_no_entry() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let conn = ConnCtx::new(conn_index, generation);
        // Another send is in flight, so every chain is refused.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let huge = vec![0u8; 1 << 24];
        for _ in 0..10 {
            with_driver_state(&mut el, || {
                let refused = conn.send_chain(|chain| chain.copy(b"x").finish());
                assert_eq!(
                    refused.err().map(|e| e.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                let empty = conn.send_chain(|_chain| Ok(()));
                assert!(empty.is_ok());
                let too_big = conn.send(&huge);
                assert_eq!(
                    too_big.err().map(|e| e.kind()),
                    Some(io::ErrorKind::InvalidInput)
                );
            });
        }
        assert_eq!(el.executor.send_completions.live(), 0);
    }

    /// A send owned by its connection's own task is abandoned when the
    /// connection is torn down, and the completion that arrives after the
    /// slot is reused frees its entry without settling it.
    #[test]
    fn a_stale_completion_for_a_dropped_send_settles_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"orphaned").unwrap();
        crate::runtime::CURRENT_TASK_ID.with(|c| c.set(conn_index));
        let id = await_slot(&mut el, conn_index, slot, 8);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, old_gen),
        );

        // The future is dropped with the task (its `Drop` cancels the
        // entry), the release frees what it left, and the slot is reused.
        el.executor.cancel_send(id);
        el.executor.remove_connection(conn_index);
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index, "test premise: index reused");
        assert_eq!(
            el.executor.send_completions.live(),
            0,
            "nothing left behind"
        );

        el.test_dispatch_cqe(ud.raw(), 8, 0);

        assert_eq!(el.executor.send_completions.live(), 0);
        assert!(send_result(&mut el, id).is_none());
    }

    thread_local! {
        /// Whether the probe's `Drop` ran with the driver state installed.
        static DROPPED_IN_EXECUTOR: std::cell::Cell<Option<bool>> =
            const { std::cell::Cell::new(None) };
    }

    /// Records, when dropped, whether the executor was reachable.
    struct DropProbe;

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let inside = crate::runtime::io::try_with_state(|_, _| ()).is_some();
            DROPPED_IN_EXECUTOR.with(|c| c.set(Some(inside)));
        }
    }

    /// A connection task dropped by the Close CQE is dropped with the driver
    /// state installed, so the futures it holds clean up as they do inside a
    /// poll.
    #[test]
    fn a_connection_task_dropped_by_the_close_cqe_is_dropped_inside_the_executor() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        DROPPED_IN_EXECUTOR.with(|c| c.set(None));

        el.executor.task_slab.spawn(
            conn_index,
            Box::pin(async move {
                let _probe = DropProbe;
                std::future::pending::<()>().await;
            }),
        );
        el.executor.ready_queue.push_back(conn_index);
        el.poll_ready_tasks();
        assert!(
            DROPPED_IN_EXECUTOR.with(|c| c.get()).is_none(),
            "the task is parked with the probe alive"
        );

        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the Close CQE released the slot"
        );
        assert_eq!(
            DROPPED_IN_EXECUTOR.with(|c| c.get()),
            Some(true),
            "the task's futures see the executor when they drop"
        );
    }

    /// A zero-copy retry dropped because its connection's Close is submitted
    /// fails the send it carries with `ECANCELED`.
    #[test]
    fn a_retry_dropped_at_close_fails_its_send() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .expect("slab room");
        let id = await_slab(&mut el, conn_index, slab_idx, 100);
        el.driver.send_queues[conn_index as usize].close_submitted = true;
        el.driver
            .pending_zc_retries
            .push((conn_index, generation, slab_idx, 0));
        el.drain_zc_retries();
        assert_eq!(
            send_result(&mut el, id)
                .expect("the dropped retry settled its send")
                .expect_err("it never went out")
                .raw_os_error(),
            Some(libc::ECANCELED)
        );
    }

    /// A zero-copy send whose completion reports zero bytes fails
    /// `WriteZero`, as a copied send does.
    #[test]
    fn a_zero_byte_zero_copy_completion_settles_write_zero() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let iovecs = [libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 100,
        }];
        let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate(conn_index, generation, &iovecs, u16::MAX, guards, 0, 100)
            .expect("slab room");
        let id = await_slab(&mut el, conn_index, slab_idx, 100);
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert_eq!(
            send_result(&mut el, id)
                .expect("settled")
                .expect_err("no bytes went out")
                .kind(),
            io::ErrorKind::WriteZero
        );
    }

    /// A terminal send error settles `Err` with the errno and returns the
    /// slot.
    #[test]
    fn send_error_settles_err_and_releases_the_slot() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"doomed").unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 6);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the error CQE settles the operation")
            .expect_err("the send failed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ECONNRESET),
            "the bounded send gets the real errno"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the error path returns the slot"
        );
    }

    /// A zero-result send completion is a *failure*: a truncated count would
    /// read to the caller as a short write of its message.
    #[test]
    fn zero_length_send_completion_settles_write_zero() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"nothing went").unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 12);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), 0, 0);

        let err = el
            .executor
            .take_send_result(id)
            .expect("a zero-result CQE settles the operation")
            .expect_err("a bounded send never reports a truncated count");
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
    }

    /// The settled length is the one carried with the id, not the completing
    /// chunk's byte count. This is the shape a TLS send has: `send_awaited`
    /// and `send_bounded` attach the id to the final *ciphertext* chunk (the
    /// one `encrypt_to_sends` tags `OpTag::Send`) together with the
    /// *plaintext* length, because no handler can recompute it: the chunk
    /// itself is one TLS record.
    ///
    /// The slot here holds stand-in ciphertext, not a real record: this test
    /// module has no TLS harness (no `tls_table`, no handshake), so what is
    /// pinned is `handle_send`'s half of the rule, not `encrypt_to_sends`'s.
    #[test]
    fn a_send_settles_with_the_carried_length_not_the_wire_bytes() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let ciphertext = [b'c'; 30];
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(&ciphertext).unwrap();
        // 12 bytes of plaintext became 30 bytes on the wire.
        el.driver.send_copy_pool.set_send_id(slot, id, 12);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), 30, 0);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the operation resolved");
        assert_eq!(
            result.expect("the send succeeded"),
            12,
            "the caller's length, not the record's"
        );
    }

    /// A forced close of a connection whose `Shutdown` is in the kernel keeps
    /// `write = Shutdown`: a repeat `shutdown_write` submits no second
    /// `Shutdown`, and the Close still waits for the first one's CQE.
    #[test]
    fn a_forced_close_keeps_an_in_flight_shutdown_recorded() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        // As `shutdown_write` leaves an idle connection once its SQE is
        // accepted.
        el.driver.connections.get_mut(conn_index).unwrap().write =
            crate::connection::WriteHalf::Shutdown;
        el.driver.send_queues[conn_index as usize].shutdown_inflight = true;

        el.driver.close_connection(conn_index);
        el.driver.force_finalize_close(conn_index);
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(
            matches!(conn.write, crate::connection::WriteHalf::Shutdown),
            "the forced close dropped the record of the Shutdown in the kernel"
        );
        assert!(!el.driver.send_queues[conn_index as usize].close_submitted);

        el.driver.ring.last_pushed = None;
        {
            let mut ctx = el.driver.make_ctx();
            ctx.shutdown_write(token);
        }
        assert!(
            el.driver.ring.last_pushed.is_none(),
            "a second Shutdown was submitted"
        );
        assert!(el.driver.send_queues[conn_index as usize].shutdown_inflight);

        let ud = UserData::encode(OpTag::Shutdown, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        el.finalize_pending_closes();
        assert!(el.driver.send_queues[conn_index as usize].close_submitted);
    }

    /// A `Shutdown` CQE that reports an error (here `ENOTCONN`, the socket
    /// already closed) is counted under `shutdown_failed`, and still
    /// releases the Close it held. A successful one is not counted.
    #[test]
    fn a_failed_shutdown_is_counted_and_releases_the_close() {
        let mut el = make_test_loop();
        let first = accept_connection(&mut el);
        let second = accept_connection(&mut el);
        for &c in &[first, second] {
            let state = &mut el.driver.send_queues[c as usize];
            state.close_pending = true;
            state.shutdown_inflight = true;
        }
        let count = || {
            metrics::CONNECTIONS
                .value(metrics::conn::SHUTDOWN_FAILED)
                .unwrap_or(0)
        };

        let before = count();
        let generation = el.driver.connections.generation(first);
        el.test_dispatch_cqe(
            UserData::encode(OpTag::Shutdown, first, generation).raw(),
            0,
            0,
        );
        assert_eq!(count(), before, "a successful Shutdown was counted");

        let generation = el.driver.connections.generation(second);
        el.test_dispatch_cqe(
            UserData::encode(OpTag::Shutdown, second, generation).raw(),
            -libc::ENOTCONN,
            0,
        );
        assert!(count() > before, "the failed Shutdown was not counted");
        assert!(
            !el.driver.send_queues[second as usize].shutdown_inflight,
            "the failed Shutdown still holds the Close"
        );
        el.finalize_pending_closes();
        assert!(
            el.driver.send_queues[second as usize].close_submitted,
            "the Close was never committed"
        );
    }

    /// `shutdown_write` on a connection whose close is requested submits
    /// nothing: the Close ends the write half, as on mio.
    #[test]
    fn shutdown_write_after_a_requested_close_submits_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        el.driver.close_connection(conn_index);

        el.driver.ring.last_pushed = None;
        {
            let mut ctx = el.driver.make_ctx();
            ctx.shutdown_write(token);
        }
        assert!(
            el.driver.ring.last_pushed.is_none(),
            "a Shutdown was submitted behind a requested close"
        );
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(matches!(conn.write, crate::connection::WriteHalf::Open));
        assert!(!el.driver.send_queues[conn_index as usize].shutdown_inflight);
    }

    /// The #518 gate. `Shutdown` names its socket as the registered-file slot
    /// `Fixed(conn_index)`, so the `Close` that frees that slot for the next
    /// accept must not be submitted while the `Shutdown` is still in the kernel
    /// — otherwise the FIN can land on the slot's *next* occupant, half-closing
    /// a live connection whose next send then fails `EPIPE`.
    ///
    /// Measured before the fix at 49/400 rounds with 16 connections and 0/400
    /// with the handler's `shutdown_write()` removed, which is what identified
    /// the op.
    #[test]
    fn close_waits_for_the_shutdown_cqe_before_freeing_the_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // A deferred shutdown went out and its CQE has not landed.
        el.driver.send_queues[conn_index as usize].shutdown_inflight = true;
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "the close is requested"
        );
        assert!(
            !el.driver.send_queues[conn_index as usize].close_submitted,
            "Close must not be submitted while a Shutdown SQE names this slot"
        );
        el.driver.try_finalize_close(conn_index);
        assert!(
            !el.driver.send_queues[conn_index as usize].close_submitted,
            "re-driving the finalize must still hold off"
        );

        // The Shutdown CQE lands: the flag clears, the close is registered
        // again, and the end-of-iteration drain commits it.
        let ud = UserData::encode(OpTag::Shutdown, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert!(
            !el.driver.send_queues[conn_index as usize].shutdown_inflight,
            "its own CQE clears the flag"
        );
        el.finalize_pending_closes();
        assert!(
            el.driver.send_queues[conn_index as usize].close_submitted,
            "the Shutdown CQE re-registers the close for the drain"
        );
    }

    /// A `Shutdown` CQE whose slot has already been recycled must be rejected on
    /// its generation and counted, not allowed to clear the new occupant's flag
    /// (domain invariant 3). The gate above should make this unreachable, which
    /// is why `shutdown_stale` being nonzero is worth knowing about.
    #[test]
    fn stale_shutdown_cqe_is_rejected_on_its_generation() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        el.driver.send_queues[conn_index as usize].shutdown_inflight = true;
        let stale = UserData::encode(OpTag::Shutdown, conn_index, generation.wrapping_add(1));
        el.test_dispatch_cqe(stale.raw(), 0, 0);
        assert!(
            el.driver.send_queues[conn_index as usize].shutdown_inflight,
            "a CQE from a previous occupant must not clear this occupant's flag"
        );
    }

    /// `handle_send`'s `close_submitted` gate: a partial completion arriving
    /// after the Close SQE went out must not resubmit the remainder behind
    /// it. The slot goes back and the bounded send is cancelled rather than
    /// left waiting for a CQE that will never be asked for.
    #[test]
    fn partial_send_after_close_submitted_settles_the_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let data = [b'x'; 20];
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(&data).unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 20);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), 8, 0);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the close_submitted gate must settle the operation")
            .expect_err("the remainder was never sent");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the gate returns the slot"
        );
    }

    /// `handle_tls_send`'s `close_submitted` returns are silent — they leave
    /// `send().await` hanging, a pre-existing hole this PR does not fix —
    /// but a bounded send must not reproduce it. No id reaches this handler
    /// by construction today (the id-carrying chunk is tagged `OpTag::Send`);
    /// the settle is what keeps that from becoming a hang if it ever does.
    #[test]
    fn tls_send_close_submitted_settles_instead_of_returning_silently() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let ciphertext = [b'c'; 20];
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(&ciphertext).unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 20);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let ud = UserData::encode(
            OpTag::TlsSend,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), 8, 0);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the silent return must still settle the operation")
            .expect_err("the remainder was never sent");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the gate returns the slot"
        );
    }

    /// `drain_copy_retries`' give-up arm: persistent SQ starvation during a
    /// partial-send resubmit is terminal for the connection, and the bounded
    /// send is told so rather than waiting for a CQE nobody will ask for.
    #[test]
    fn copy_retry_cap_settles_the_bounded_send_err() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"stuck").unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 5);
        el.driver
            .pending_copy_retries
            .push((conn_index, generation, slot, 2, OpTag::Send));

        el.drain_copy_retries();

        let err = el
            .executor
            .take_send_result(id)
            .expect("the give-up arm must settle the operation")
            .expect_err("the resubmit never landed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("max retries during send resubmit"),
            "unexpected message: {err}"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "give-up returns the slot"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "give-up must close the connection"
        );
    }

    /// Queue two awaited copy sends, `aa` and `bbb`, behind an in-flight
    /// send, then let the in-flight one finish, so both go out as one
    /// coalesced `sendmsg` (#628). Returns their ids and the slab entry.
    fn two_pipelined_sends(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
    ) -> (SendId, SendId, u16) {
        let first = submitted_id(el, conn_index, generation);
        let second = submitted_id(el, conn_index, generation);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (id, data) in [(first, &b"aa"[..]), (second, b"bbb")] {
            let built = built_copy_send(el, conn_index, data);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        assert!(el.driver.submit_next_queued(conn_index));
        assert!(
            el.driver.send_queues[conn_index as usize].queue.is_empty(),
            "both sends left in one operation"
        );
        let pushed = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(pushed.tag(), Some(OpTag::SendMsgCoalesced));
        (first, second, pushed.payload() as u16)
    }

    /// Two pipelined sends coalesced into one `sendmsg` each settle with their
    /// own length, not the run's total.
    #[test]
    fn pipelined_sends_coalesce_and_each_settles_with_its_own_length() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (first, second, slab_idx) = two_pipelined_sends(&mut el, conn_index, generation);
        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        assert_eq!(el.executor.take_send_result(first).unwrap().unwrap(), 2);
        assert_eq!(el.executor.take_send_result(second).unwrap().unwrap(), 3);
        assert!(!el.driver.send_slab.in_use(slab_idx));
    }

    /// A partial write that covers the first send settles it at once; an
    /// error on the rest fails only the second.
    #[test]
    fn a_partial_write_settles_the_sends_it_covers() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (first, second, slab_idx) = two_pipelined_sends(&mut el, conn_index, generation);
        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), 2, 0);
        assert_eq!(el.executor.take_send_result(first).unwrap().unwrap(), 2);
        assert!(
            el.executor.take_send_result(second).is_none(),
            "still in flight"
        );
        el.test_dispatch_cqe(ud.raw(), -libc::EPIPE, 0);
        let err = el.executor.take_send_result(second).unwrap().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
    }

    /// Three awaited sends coalesced: a real error before any byte fails all
    /// three.
    #[test]
    fn error_fails_every_send_in_the_run() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ids: Vec<SendId> = (0..3)
            .map(|_| submitted_id(&mut el, conn_index, generation))
            .collect();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (id, data) in ids.iter().zip([&b"aa"[..], b"bbb", b"cccc"]) {
            let built = built_copy_send(&mut el, conn_index, data);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, *id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        assert!(el.driver.submit_next_queued(conn_index));
        let pushed = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(pushed.tag(), Some(OpTag::SendMsgCoalesced));
        el.test_dispatch_cqe(pushed.raw(), -libc::EPIPE, 0);
        for id in ids {
            let err = el
                .executor
                .take_send_result(id)
                .expect("settled")
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EPIPE));
        }
    }

    /// Successive partial writes, each covering one more send, then the
    /// rest: each send settles once with its own length.
    #[test]
    fn successive_partials_settle_in_order() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ids: Vec<SendId> = (0..3)
            .map(|_| submitted_id(&mut el, conn_index, generation))
            .collect();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (id, data) in ids.iter().zip([&b"aa"[..], b"bbb", b"cccc"]) {
            let built = built_copy_send(&mut el, conn_index, data);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, *id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        assert!(el.driver.submit_next_queued(conn_index));
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        // 1 byte: nothing covered.
        el.test_dispatch_cqe(ud.raw(), 1, 0);
        assert!(el.executor.take_send_result(ids[0]).is_none());
        // 3 more (total 4): first covered, second not (ends at 5).
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        assert_eq!(el.executor.take_send_result(ids[0]).unwrap().unwrap(), 2);
        assert!(el.executor.take_send_result(ids[1]).is_none());
        // 1 more (total 5): second covered exactly.
        el.test_dispatch_cqe(ud.raw(), 1, 0);
        assert_eq!(el.executor.take_send_result(ids[1]).unwrap().unwrap(), 3);
        assert!(el.executor.take_send_result(ids[2]).is_none());
        el.test_dispatch_cqe(ud.raw(), 4, 0);
        assert_eq!(el.executor.take_send_result(ids[2]).unwrap().unwrap(), 4);
        assert!(!el.driver.send_slab.in_use(ud.payload() as u16));
    }

    /// A coalesced push failure puts every lifted id back; the retry then
    /// settles each send with its own length.
    #[test]
    fn push_failure_restores_every_id() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ids: Vec<SendId> = (0..2)
            .map(|_| submitted_id(&mut el, conn_index, generation))
            .collect();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (id, data) in ids.iter().zip([&b"aa"[..], b"bbb"]) {
            let built = built_copy_send(&mut el, conn_index, data);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, *id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        el.driver.ring.force_push_failures(1);
        assert!(!el.driver.submit_next_queued(conn_index));
        el.drain_send_retries();
        assert!(el.driver.send_queues[conn_index as usize].queue.is_empty());
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(ud.tag(), Some(OpTag::SendMsgCoalesced));
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        assert_eq!(el.executor.take_send_result(ids[0]).unwrap().unwrap(), 2);
        assert_eq!(el.executor.take_send_result(ids[1]).unwrap().unwrap(), 3);
    }

    /// A slab-full fall-through puts every lifted id back on its slot, so the
    /// single-submit path settles each send.
    #[test]
    fn slab_full_restores_every_id() {
        let mut el = bounded_test_loop();
        el.driver.send_slab = crate::buffer::send_slab::InFlightSendSlab::new(0);
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ids: Vec<SendId> = (0..2)
            .map(|_| submitted_id(&mut el, conn_index, generation))
            .collect();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let mut slots = Vec::new();
        for (id, data) in ids.iter().zip([&b"aa"[..], b"bbb"]) {
            let built = built_copy_send(&mut el, conn_index, data);
            slots.push(built.pool_slot);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, *id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        assert!(el.driver.submit_next_queued(conn_index));
        // The head left alone; the second still owns its id on its slot.
        assert_eq!(
            el.driver.send_copy_pool.take_send_id(slots[1]),
            Some((ids[1], 3))
        );
        el.driver.send_copy_pool.set_send_id(slots[1], ids[1], 3);
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        el.test_dispatch_cqe(ud.raw(), 2, 0);
        assert_eq!(el.executor.take_send_result(ids[0]).unwrap().unwrap(), 2);
    }

    /// A TLS-internal ciphertext chunk that fails closes the connection
    /// (`handle_tls_send`); coalesced with a following chunk, it still does.
    #[test]
    fn coalesced_tls_chunk_error_closes_connection() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (tag, data) in [
            (OpTag::TlsSend, &b"record-1"[..]),
            (OpTag::Send, b"record-2"),
        ] {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(data).unwrap();
            let ud = UserData::encode(tag, conn_index, UserData::send_payload(slot, generation));
            let entry =
                crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw());
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(crate::handler::BuiltSend {
                    entry,
                    pool_slot: slot,
                    slab_idx: u16::MAX,
                });
        }
        assert!(el.driver.submit_next_queued(conn_index));
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(
            ud.tag(),
            Some(OpTag::SendMsgCoalesced),
            "TLS chunks coalesced"
        );
        el.test_dispatch_cqe(ud.raw(), -104, 0);
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed after a TLS ciphertext send error"
        );
    }

    /// Queue two `Send`-tagged chunks behind an in-flight send and coalesce
    /// them; returns the coalesced operation's user_data.
    fn two_send_tagged_chunks(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32) -> UserData {
        let generation = el.driver.connections.generation(conn_index);
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for data in [&b"record-1"[..], b"record-2"] {
            let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(data).unwrap();
            let ud = UserData::encode(
                OpTag::Send,
                conn_index,
                UserData::send_payload(slot, generation),
            );
            let entry =
                crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw());
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(crate::handler::BuiltSend {
                    entry,
                    pool_slot: slot,
                    slab_idx: u16::MAX,
                });
        }
        assert!(el.driver.submit_next_queued(conn_index));
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        assert_eq!(ud.tag(), Some(OpTag::SendMsgCoalesced));
        ud
    }

    /// Two single-record TLS sends: every chunk is tagged `Send`, and an
    /// error closes the connection.
    #[test]
    fn tls_connection_run_of_final_chunks_closes_on_error() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        install_handshaked_tls(&mut el, conn_index);
        let ud = two_send_tagged_chunks(&mut el, conn_index);
        el.test_dispatch_cqe(ud.raw(), -104, 0);
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
    }

    /// The same run on a plaintext connection closes too, and tells the
    /// reader why.
    #[test]
    fn plaintext_run_error_closes_and_tells_the_reader() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ud = two_send_tagged_chunks(&mut el, conn_index);
        el.test_dispatch_cqe(ud.raw(), -104, 0);
        assert_send_error_aborted(&mut el, conn_index, generation, libc::ECONNRESET);
    }

    /// With the close already submitted, a partial write settles the sends it
    /// covers and cancels every other send in the run.
    #[test]
    fn a_partial_write_after_the_close_cancels_the_rest() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let ids: Vec<SendId> = (0..3)
            .map(|_| submitted_id(&mut el, conn_index, generation))
            .collect();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        for (id, data) in ids.iter().zip([&b"aa"[..], b"bbb", b"cccc"]) {
            let built = built_copy_send(&mut el, conn_index, data);
            el.driver
                .send_copy_pool
                .set_send_id(built.pool_slot, *id, data.len() as u32);
            el.driver.send_queues[conn_index as usize]
                .queue
                .push_back(built);
        }
        assert!(el.driver.submit_next_queued(conn_index));
        let ud = UserData(el.driver.ring.last_pushed.as_ref().unwrap().user_data);
        el.driver.send_queues[conn_index as usize].close_submitted = true;
        el.test_dispatch_cqe(ud.raw(), 2, 0);
        assert_eq!(el.executor.take_send_result(ids[0]).unwrap().unwrap(), 2);
        for &id in &ids[1..] {
            let err = el
                .executor
                .take_send_result(id)
                .expect("settled")
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        }
    }

    /// With the close already submitted, `EAGAIN` cancels every send in the
    /// run.
    #[test]
    fn eagain_after_the_close_cancels_every_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (first, second, slab_idx) = two_pipelined_sends(&mut el, conn_index, generation);
        el.driver.send_queues[conn_index as usize].close_submitted = true;
        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), -libc::EAGAIN, 0);
        for id in [first, second] {
            let err = el
                .executor
                .take_send_result(id)
                .expect("settled")
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        }
    }

    /// The coalesced retry's give-up fails every send in the run.
    #[test]
    fn the_coalesced_retry_give_up_fails_every_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (first, second, slab_idx) = two_pipelined_sends(&mut el, conn_index, generation);
        el.driver
            .pending_coalesced_retries
            .push((conn_index, generation, slab_idx, 2));
        el.drain_coalesced_retries();
        for id in [first, second] {
            let err = el
                .executor
                .take_send_result(id)
                .expect("settled")
                .unwrap_err();
            assert!(err.to_string().contains("max retries"), "{err}");
        }
    }

    /// `drain_coalesced_retries`' give-up arm, on the id the slab entry
    /// carries.
    #[test]
    fn coalesced_retry_cap_settles_the_bounded_send_err() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (s0, p0, l0) = el.driver.send_copy_pool.copy_in(b"aa").unwrap();
        let (s1, p1, l1) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let iovecs = [
            libc::iovec {
                iov_base: p0 as *mut libc::c_void,
                iov_len: l0 as usize,
            },
            libc::iovec {
                iov_base: p1 as *mut libc::c_void,
                iov_len: l1 as usize,
            },
        ];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate_coalesced(
                conn_index,
                generation,
                &iovecs,
                &[s0, s1],
                l0 + l1,
                Some((id, 99, l0 + l1)),
            )
            .expect("slab room");
        el.driver
            .pending_coalesced_retries
            .push((conn_index, generation, slab_idx, 2));

        el.drain_coalesced_retries();

        let err = el
            .executor
            .take_send_result(id)
            .expect("the give-up arm must settle the operation")
            .expect_err("the resubmit never landed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string()
                .contains("max retries during coalesced send resubmit"),
            "unexpected message: {err}"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "give-up returns every slot the run held"
        );
    }

    /// `drain_send_retries`' give-up arm holds no id at all: the parked
    /// entry is still *queued*, so `drain_conn_send_queue` takes the id off
    /// its pool slot and aborts it through
    /// `Driver::settled_sends`, which the run loop drains. Both
    /// halves have to work or the caller hangs.
    #[test]
    fn send_retry_cap_aborts_the_parked_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        // The initial push and both retries are refused.
        el.driver.ring.force_push_failures(3);
        let id = admit_bounded_send(&mut el, token, b"parked", 1);
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 0)],
            "SQ pressure parks the entry instead of failing the send"
        );

        el.drain_send_retries();
        el.drain_send_retries();
        assert!(
            el.executor.take_send_result(id).is_none(),
            "a re-parked entry must not resolve"
        );

        // The cap.
        el.drain_send_retries();
        assert_eq!(
            el.driver.settled_sends.len(),
            1,
            "the destroyed queue entry is recorded for the loop to deliver"
        );
        el.drain_settled_sends();

        let err = el
            .executor
            .take_send_result(id)
            .expect("the aborted entry must be told")
            .expect_err("the message never reached the wire");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the parked entry's slot came back"
        );
    }

    /// Teardown through `drain_conn_send_queue`: a bounded send still queued
    /// when its connection's queue is destroyed is aborted, not forgotten.
    #[test]
    fn drain_conn_send_queue_aborts_a_queued_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        // A send is already in flight, so the whole message queues.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let id = admit_bounded_send(&mut el, token, b"queued", 1);
        assert_eq!(
            el.driver.send_queues[conn_index as usize].queue.len(),
            1,
            "the message is queued, never submitted — the case under test"
        );

        el.driver.drain_conn_send_queue(conn_index);

        assert_eq!(
            el.driver.settled_sends.len(),
            1,
            "the destroyed entry is recorded for the loop to deliver"
        );
        el.drain_settled_sends();
        let err = el
            .executor
            .take_send_result(id)
            .expect("the destroyed entry must be told")
            .expect_err("the message never reached the wire");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string()
                .contains("connection closed before the send reached the wire"),
            "unexpected message: {err}"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the queued entry's slot came back"
        );
    }

    /// Teardown through `force_finalize_close` — the close_notify-deadline
    /// path, which abandons the queue rather than waiting for it to drain.
    /// Its own `release_queued_sends` call site has to fail the ids too.
    #[test]
    fn force_finalize_close_aborts_a_queued_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);

        el.driver.send_queues[conn_index as usize].in_flight = true;
        let id = admit_bounded_send(&mut el, token, b"abandoned", 1);
        assert_eq!(el.driver.send_queues[conn_index as usize].queue.len(), 1);

        el.driver.force_finalize_close(conn_index);

        assert_eq!(el.driver.settled_sends.len(), 1);
        el.drain_settled_sends();
        let err = el
            .executor
            .take_send_result(id)
            .expect("the abandoned entry must be told")
            .expect_err("the message never reached the wire");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the abandoned entry's slot came back"
        );
    }

    /// A forced close that `try_finalize_close` cannot commit, because a
    /// `Shutdown` is still in the kernel, disarms its deadline: the force
    /// runs once, and the Shutdown CQE commits the Close.
    #[test]
    fn a_forced_close_blocked_on_a_shutdown_runs_once() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        {
            let state = &mut el.driver.send_queues[conn_index as usize];
            state.close_pending = true;
            state.shutdown_inflight = true;
            state.close_notify_deadline = Some(std::time::Instant::now());
        }
        el.driver.close_notify_armed.push(conn_index);

        el.check_close_notify_deadlines();
        let state = &el.driver.send_queues[conn_index as usize];
        assert!(
            state.close_pending && !state.close_submitted,
            "the Shutdown holds the Close"
        );
        assert!(
            state.close_notify_deadline.is_none(),
            "the deadline stayed armed after the force"
        );
        assert!(
            !el.driver.close_notify_armed.contains(&conn_index),
            "the connection stayed on the armed set after the force"
        );

        // The next tick runs no second force.
        el.driver.capacity_released = false;
        el.check_close_notify_deadlines();
        assert!(
            !el.driver.capacity_released,
            "a second force reported released capacity"
        );

        // The Shutdown CQE registers the connection for the end-of-iteration
        // drain, which commits the Close.
        let ud = UserData::encode(OpTag::Shutdown, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));
        for c in std::mem::take(&mut el.driver.pending_finalize_closes) {
            el.driver.try_finalize_close(c);
        }
        assert!(
            el.driver.send_queues[conn_index as usize].close_submitted,
            "the Close was never committed"
        );
    }

    /// Reactivating a slot whose queue is empty returns no slot to the pool,
    /// and reports none.
    #[test]
    fn resetting_an_empty_send_queue_releases_no_capacity() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.capacity_released = false;

        el.driver.reset_send_state(conn_index);

        assert!(
            !el.driver.capacity_released,
            "an empty queue reported released capacity"
        );
    }

    /// A forced close that abandons a queued send no caller waits on
    /// (`send_nowait`) still reports the slot it returned to the pool, or a
    /// bounded send parked on the pool waits for an unrelated release.
    #[test]
    fn a_forced_close_abandoning_an_unawaited_send_releases_capacity() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let (slot, ptr, len) = el.driver.send_copy_pool.copy_in(b"unawaited").unwrap();
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        let entry = crate::backend::uring::sqe::Sqe::stream_send(conn_index, ptr, len, ud.raw());
        {
            let state = &mut el.driver.send_queues[conn_index as usize];
            state.queue.push_back(crate::handler::BuiltSend {
                entry,
                pool_slot: slot,
                slab_idx: u16::MAX,
            });
            state.in_flight = true;
            state.close_pending = true;
        }
        el.driver.capacity_released = false;

        el.driver.force_finalize_close(conn_index);

        assert!(
            el.driver.settled_sends.is_empty(),
            "nothing awaited the send"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the slot stayed in use"
        );
        assert!(
            el.driver.capacity_released,
            "the returned slot was not reported"
        );
    }

    /// A send CQE that outlived its connection slot settles nothing: the
    /// operation belonged to the dead occupant, whose teardown already
    /// recorded a provisional abort that a driver result would override
    /// (#381) on behalf of a connection that is gone. It still releases the
    /// orphaned slot — it is the kernel's last reference — and it must not
    /// touch anything the new occupant owns.
    #[test]
    fn stale_generation_send_completion_settles_nothing() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, old_gen);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"orphaned").unwrap();
        el.driver.send_copy_pool.set_send_id(slot, id, 8);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, old_gen),
        );

        // Close + reuse: same index, new generation.
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index, "test premise: index reused");
        assert_ne!(el.driver.connections.generation(conn_index), old_gen);
        // The new occupant has a send of its own outstanding.
        let (slot2, _p2, _l2) = el.driver.send_copy_pool.copy_in(b"new occupant").unwrap();

        el.test_dispatch_cqe(ud.raw(), 8, 0);

        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the stale CQE is the last reference to the orphaned slot"
        );
        assert!(
            el.driver.send_copy_pool.in_use(slot2),
            "the new occupant's slot must be untouched"
        );
        assert!(
            el.executor.take_send_result(id).is_none(),
            "a dead occupant's completion must not settle its operation"
        );

        // Not vacuous: the entry is still present and still settleable, so
        // the stale CQE left it alone rather than removing it.
        el.executor.complete_send(id, Ok(42));
        assert_eq!(
            el.executor
                .take_send_result(id)
                .expect("the entry survived the stale CQE")
                .expect("settled by the control"),
            42,
            "the id was still live — 'settled nothing' is a real observation"
        );
    }

    /// Departure 4 of the series design, on io_uring's `poll_ready_tasks`
    /// route into `Executor::remove_connection`.
    ///
    /// A standalone task owns a bounded send on connection X. X's own task
    /// then returns `Poll::Ready`, so the poll closes and removes X while
    /// the send is still in the kernel, recording a provisional abort. The
    /// close is deferred behind the in-flight send, whose CQE lands
    /// afterwards and delivers every byte — so the owner must be told
    /// `Ok(len)`, not `ConnectionAborted`. Mirrors mio's
    /// `bounded_send_owned_by_another_task_survives_its_connection_task_returning`.
    #[test]
    fn bounded_send_owned_by_another_task_survives_its_connection_task_returning() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnId::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let id = admit_bounded_send(&mut el, token, b"delivered", 1);

        // The connection's own task runs and returns Ready.
        // `NoopHandler::on_accept` is `async {}`, so one poll completes it
        // and `poll_ready_tasks` takes the close + remove branch.
        el.spawn_accept_task(conn_index);
        el.poll_ready_tasks();
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "the returning task requested the close"
        );
        assert!(
            el.driver.send_queues[conn_index as usize].in_flight,
            "teardown ran with the send still in the kernel — the case under test"
        );

        // The send's CQE lands in the next drain and must win; that
        // iteration's drain then commits the close.
        complete_one_cqe(&mut el);
        el.finalize_pending_closes();

        let result = el
            .executor
            .take_send_result(id)
            .expect("the operation resolved");
        assert_eq!(
            result.expect("every byte reached the socket, so this is not an abort"),
            9,
            "a real driver result must overwrite the teardown's synthetic abort"
        );
        assert!(
            el.driver.send_queues[conn_index as usize].close_submitted,
            "the deferred close finalized once the send drained"
        );
        let mut buf = [0u8; 16];
        assert_eq!(drain_peer(&peer, &mut buf), 9);
        assert_eq!(&buf[..9], b"delivered");
    }

    // ── Bounded sends through the real kernel pipeline ─────────────
    //
    // The section above proves the *rules* (which site settles what) by
    // calling handlers with fabricated CQEs. These prove the *plumbing* the
    // rules ride on, which `test_dispatch_cqe` cannot touch because it hands
    // the handler a `user_data` that never left the process:
    //
    //   * the 64-bit `UserData` word survives a round trip through
    //     `io_uring`'s SQE and CQE — including `send_payload`'s truncated
    //     generation in the payload's high half;
    //   * `drain_completions` decodes that word and `dispatch_cqe` routes it
    //     to the handler the `OpTag` names, rather than to a neighbour;
    //   * the CQE's `res` field carries the result the kernel wrote, signed,
    //     unclamped;
    //   * a *batch* of completions drained together does not cross-talk —
    //     each settles its own id, with its own length, in submission order.
    //
    // `IORING_NOP_INJECT_RESULT` (Linux 6.10, modelled below it) is the
    // mechanism, as it is for the `nop_inject_*` tests above;
    // `inject_and_dispatch`,
    // `inject_batch_and_dispatch` and `inject_linked_chain_and_dispatch` are
    // the three shapes.

    /// A generation whose low bits are a real pattern rather than 0 or 1.
    ///
    /// `UserData::send_payload` packs the generation into the payload's high
    /// half; at generation 0 that half is all zeros, which a round trip that
    /// lost the high bits would reproduce by accident. 0x2A3 cannot be
    /// produced by accident.
    const PATTERNED_GENERATION: u32 = 0x2A3;

    /// Recycle `conn_index` until its generation is `target`, leaving the
    /// slot accepted again.
    ///
    /// Release is what bumps a generation, and only the connection table is
    /// touched — no `Close` SQE, no send-queue state — so this is purely a
    /// way to give the identity bits something to say.
    fn recycle_to_generation(el: &mut AsyncEventLoop<NoopHandler>, conn_index: u32, target: u32) {
        while el.driver.connections.generation(conn_index) < target {
            el.driver.connections.release(conn_index);
            assert_eq!(
                el.driver.connections.allocate(),
                Some(conn_index),
                "the released index is the only free-list head, so it must come back"
            );
        }
        assert_eq!(
            el.driver.connections.generation(conn_index),
            target,
            "generation overshot its target"
        );
        let cs = el
            .driver
            .connections
            .get_mut(conn_index)
            .expect("just allocated");
        cs.lifecycle = Lifecycle::Open;
        cs.recv_direct = true;
        cs.established = true;
    }

    /// Copy `data` into a fresh pool slot and attach a
    /// freshly admitted bounded send reporting `logical_len` — the by-hand
    /// equivalent of the last chunk `DriverCtx::send_bounded` builds, as the
    /// handler tests above assemble it. Returns the id and the slot.
    fn bounded_slot(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
        data: &[u8],
        logical_len: u32,
    ) -> (SendId, u16) {
        let id = submitted_id(el, conn_index, generation);
        let (slot, _ptr, _len) = el
            .driver
            .send_copy_pool
            .copy_in(data)
            .expect("free pool slot");
        el.driver.send_copy_pool.set_send_id(slot, id, logical_len);
        (id, slot)
    }

    /// A successful `Send` completion settles `Ok(logical_len)` and returns
    /// the slot when the completion comes back through the kernel.
    ///
    /// What the round trip adds over
    /// `bounded_send_single_slot_settles_ok_with_the_logical_length`: there
    /// the `user_data` is built by `send_bounded` and consumed by the same
    /// process a moment later, so a payload whose high half were dropped on
    /// the way out would still match on the way back in. Here the connection
    /// sits at a patterned generation, so the payload's high 16 bits carry
    /// 0x02A3 out through the SQE and must come back intact — a lost or
    /// shifted high half fails `handle_send`'s identity guard and settles
    /// nothing, which the `expect` below catches.
    #[test]
    fn nop_inject_bounded_send_ok_survives_the_kernel_round_trip() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"hello", 5);
        let payload = UserData::send_payload(slot, generation);
        assert_eq!(
            UserData::send_payload_gen(payload),
            0x02A3,
            "test premise: the payload's high half really does carry a pattern"
        );
        let ud = UserData::encode(OpTag::Send, conn_index, payload);

        el.inject_and_dispatch(ud.raw(), 5);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the CQE must have reached handle_send with its identity intact");
        assert_eq!(
            result.expect("the send succeeded"),
            5,
            "a bounded send reports the length its caller passed"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the completion returned the slot"
        );
    }

    /// A terminal `Send` error settles `Err` with the errno the *kernel*
    /// wrote into the CQE.
    ///
    /// Complements `send_error_settles_err_and_releases_the_slot`, which
    /// passes `-ECONNRESET` to the handler as a Rust argument. Here it
    /// crosses the boundary as the CQE's `res` field, so this also pins that
    /// `drain_completions` reads `res` as a signed int — a handler reached
    /// with `res` widened unsigned would see a large positive result and take
    /// the *success* path, settling `Ok` instead.
    #[test]
    fn nop_inject_bounded_send_error_carries_the_real_errno() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"doomed", 6);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.inject_and_dispatch(ud.raw(), -libc::ECONNRESET);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the error CQE settles the operation")
            .expect_err("a negative res is a failure, not a byte count");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ECONNRESET),
            "the bounded send gets the errno the kernel reported"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the error path returns the slot"
        );
    }

    /// A `Send` CQE with `res == 0` settles `Err(WriteZero)`.
    ///
    /// Complements `zero_length_send_completion_settles_write_zero`. Zero is
    /// the one result a NOP produces on its own, so this also confirms the
    /// injection really did carry the value rather than the handler seeing a
    /// default: the `WriteZero` it settles is `send_error`'s special
    /// case and nothing else in the pipeline produces that kind.
    #[test]
    fn nop_inject_bounded_send_zero_result_settles_write_zero() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"nothing went", 12);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.inject_and_dispatch(ud.raw(), 0);

        let err = el
            .executor
            .take_send_result(id)
            .expect("a zero-result CQE settles the operation")
            .expect_err("a bounded send never reports a truncated count");
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the zero-result path returns the slot"
        );
    }

    /// A partial completion resubmits the remainder, and the *resubmission*
    /// is what finishes the send: the id is settled once, with the whole
    /// logical length.
    ///
    /// This is the one test in which no `user_data` is written by the test at
    /// all after the first CQE. `handle_send` re-encodes the remainder's SQE
    /// itself (`Ring::submit_send_copied`, which rebuilds
    /// `send_payload(slot, generation)` from the live connection), the kernel
    /// really sends those bytes to the peer, and its CQE has to route back to
    /// the same slot with the id still on it. The direct-dispatch test
    /// `bounded_send_partial_write_settles_once_with_the_whole_length` pins
    /// the same rule with two fabricated CQEs and cannot observe any of that.
    #[test]
    fn nop_inject_bounded_send_partial_then_real_completion_settles_once() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let data = [b'p'; 20];
        let (id, slot) = bounded_slot(&mut el, conn_index, generation, &data, 20);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        // 8 of 20 bytes. The handler keeps the slot (and its id), polls, and
        // resubmits bytes 8..20 as a real SQE against the socketpair.
        el.inject_and_dispatch(ud.raw(), 8);
        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "a partial write keeps its slot"
        );
        assert!(
            el.executor.take_send_result(id).is_none(),
            "a partial write must not settle the operation"
        );

        // The poll, and the resubmission's own completion, from the kernel.
        complete_one_cqe(&mut el);
        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the resubmission's CQE must route back to the same slot");
        assert_eq!(
            result.expect("the send succeeded"),
            20,
            "the whole message, not the 12 bytes the resubmission carried"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the finishing CQE returns the slot"
        );

        // Only the resubmitted remainder was ever really written: the first
        // 8 bytes existed solely as an injected result.
        let mut buf = [0u8; 32];
        assert_eq!(drain_peer(&peer, &mut buf), 12);
        assert_eq!(&buf[..12], &data[8..]);
    }

    /// A `Send` CQE for a *previous* occupant of a reused connection slot
    /// settles nothing, releases the orphaned slot, and leaves the new
    /// occupant alone — and a completion for the new occupant, injected
    /// straight afterwards, does settle.
    ///
    /// This pair is the strongest argument for this whole section. The only
    /// thing separating the two CQEs is 16 bits of truncated generation in
    /// the payload's high half, so the pair proves those bits made the round
    /// trip *and* that the guard reads them: lose them and the first CQE
    /// would settle (the assert below catches it); mangle them and the second
    /// would not (its `expect` catches that). The direct-dispatch test
    /// `stale_generation_send_completion_settles_nothing` pins the same rule
    /// with fabricated CQEs, where the encoding is never exercised at all.
    #[test]
    fn nop_inject_stale_generation_send_completion_settles_nothing() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let old_gen = el.driver.connections.generation(conn_index);

        let (stale_id, stale_slot) = bounded_slot(&mut el, conn_index, old_gen, b"orphaned", 8);
        let stale_ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(stale_slot, old_gen),
        );

        // Close + reuse: same index, next generation.
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().expect("free slot");
        assert_eq!(reused, conn_index, "test premise: index reused");
        let new_gen = el.driver.connections.generation(conn_index);
        assert_eq!(new_gen, old_gen + 1);

        // The new occupant admits a bounded send of its own.
        let (fresh_id, fresh_slot) =
            bounded_slot(&mut el, conn_index, new_gen, b"new occupant", 12);
        let fresh_ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(fresh_slot, new_gen),
        );

        el.inject_and_dispatch(stale_ud.raw(), 8);

        assert!(
            el.executor.take_send_result(stale_id).is_none(),
            "a dead occupant's completion must not settle its operation"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(stale_slot),
            "the stale CQE is the kernel's last reference to the orphaned slot"
        );
        assert!(
            el.driver.send_copy_pool.in_use(fresh_slot),
            "the new occupant's slot must be untouched"
        );

        // The control: one generation later, through the same pipeline, the
        // completion is accepted. Without this the assertion above would pass
        // just as well if the round trip had destroyed the payload outright.
        el.inject_and_dispatch(fresh_ud.raw(), 12);
        let result = el
            .executor
            .take_send_result(fresh_id)
            .expect("the live occupant's completion must settle");
        assert_eq!(
            result.expect("the send succeeded"),
            12,
            "'settles nothing' above is a statement about identity, not about \
             the pipeline being broken"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(fresh_slot),
            "the live completion returned its slot too"
        );
    }

    /// A coalesced run's completion settles the id its slab entry carries,
    /// with the carried logical length.
    ///
    /// `coalesced_run_settles_the_id_lifted_onto_the_slab_entry` builds the
    /// run with `submit_next_queued` and lets a real `sendmsg` complete, so
    /// it pins the *lift* — but its `user_data` is the one the driver wrote
    /// a moment earlier. This pins the slab-backed family's word through the
    /// kernel instead: `OpTag::SendMsgCoalesced` is a tag byte in bits 63..56
    /// whose payload is a bare slab index and whose identity lives in the
    /// entry rather than the payload, and `drain_completions` — which
    /// `test_dispatch_cqe` skips entirely — is what has to decode it.
    #[test]
    fn nop_inject_coalesced_send_settles_the_carried_length() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (s0, p0, l0) = el.driver.send_copy_pool.copy_in(b"aa").unwrap();
        let (s1, p1, l1) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let iovecs = [
            libc::iovec {
                iov_base: p0 as *mut libc::c_void,
                iov_len: l0 as usize,
            },
            libc::iovec {
                iov_base: p1 as *mut libc::c_void,
                iov_len: l1 as usize,
            },
        ];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate_coalesced(
                conn_index,
                generation,
                &iovecs,
                &[s0, s1],
                l0 + l1,
                // Neither chunk's length and not the run's 5 wire bytes: the
                // carried number is the only one a handler cannot recompute.
                Some((id, 99, l0 + l1)),
            )
            .expect("slab room");

        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), (l0 + l1) as i32);

        let result = el
            .executor
            .take_send_result(id)
            .expect("the coalesced CQE settles the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            99,
            "the carried logical length, not the 5 bytes of the run"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "both backing slots came back"
        );
        assert!(
            !el.driver.send_slab.in_use(slab_idx),
            "the slab entry came back"
        );
    }

    /// A coalesced run that fails settles `Err` with the errno, and returns
    /// every slot the run held plus the slab entry.
    ///
    /// No existing test covers `handle_send_msg_coalesced`'s terminal error
    /// branch with an id at all — the closest,
    /// `coalesced_retry_cap_settles_the_bounded_send_err`, drives the retry
    /// drain, which is a different site reporting a different error. It is
    /// also a path the tripwire cannot cover: the id rides the *slab* entry,
    /// which `InFlightSendSlab::release` clears silently, unlike
    /// `SendCopyPool::release`. Drop the take here and nothing panics — the
    /// caller just never hears back. An explicit assertion is the only guard
    /// this branch has.
    #[test]
    fn nop_inject_coalesced_send_error_settles_the_real_errno() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (s0, p0, l0) = el.driver.send_copy_pool.copy_in(b"aa").unwrap();
        let (s1, p1, l1) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let iovecs = [
            libc::iovec {
                iov_base: p0 as *mut libc::c_void,
                iov_len: l0 as usize,
            },
            libc::iovec {
                iov_base: p1 as *mut libc::c_void,
                iov_len: l1 as usize,
            },
        ];
        let (slab_idx, _msg) = el
            .driver
            .send_slab
            .allocate_coalesced(
                conn_index,
                generation,
                &iovecs,
                &[s0, s1],
                l0 + l1,
                Some((id, 99, l0 + l1)),
            )
            .expect("slab room");

        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), -libc::EPIPE);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the error CQE settles the operation")
            .expect_err("the run failed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EPIPE),
            "the bounded send gets the errno the kernel reported"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the error path returns every slot the run held"
        );
        assert!(
            !el.driver.send_slab.in_use(slab_idx),
            "the slab entry came back"
        );
    }

    /// `handle_tls_send`'s `close_submitted` gate settles rather than
    /// returning silently.
    ///
    /// `tls_send_close_submitted_settles_instead_of_returning_silently` pins
    /// the rule by calling the handler directly; this pins that a real CQE
    /// tagged `OpTag::TlsSend`, carrying `send_payload`'s truncated
    /// generation, comes back out of `drain_completions` and reaches the same
    /// gate. It matters more on this path than any other in the section: both
    /// of the gate's exits are bare `return`s with no wake and no log, so a
    /// word that decoded wrong here would produce no symptom at all — the
    /// caller would simply hang. The settled id is the only observable.
    #[test]
    fn nop_inject_tls_send_close_submitted_settles_instead_of_hanging() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let ciphertext = [b'c'; 20];
        let (id, slot) = bounded_slot(&mut el, conn_index, generation, &ciphertext, 20);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let ud = UserData::encode(
            OpTag::TlsSend,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.inject_and_dispatch(ud.raw(), 8);

        let err = el
            .executor
            .take_send_result(id)
            .expect("the silent return must still settle the operation")
            .expect_err("the remainder was never sent");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the gate returns the slot"
        );
    }

    /// A failed `POLLOUT` poll settles the bounded send waiting behind it, and
    /// a poll naming an earlier occupant of the connection does nothing.
    #[test]
    fn nop_inject_send_pollout_error_settles_the_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"blocked", 7);
        let payload = UserData::send_payload(slot, generation);
        let send = UserData::encode(OpTag::Send, conn_index, payload);
        let state = &mut el.driver.send_queues[conn_index as usize];
        state.in_flight = true;
        state.waiting_send = Some(send.raw());
        state.send_poll = SendPoll::OneShot;

        let stale = UserData::encode(OpTag::SendPollOut, conn_index, generation - 1);
        el.inject_and_dispatch(stale.raw(), -libc::EBADF);
        assert!(el.driver.send_copy_pool.in_use(slot));

        let ud = UserData::encode(OpTag::SendPollOut, conn_index, generation);
        el.inject_and_dispatch(ud.raw(), -libc::EBADF);

        let err = el
            .executor
            .take_send_result(id)
            .expect("a failed POLLOUT must settle the operation")
            .expect_err("the send never resumed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EBADF),
            "the bounded send gets the poll's errno"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the failed poll returns the slot"
        );
    }

    /// Two bounded sends on two connections, both completions drained in one
    /// `drain_completions`: each settles with its own id and its own length,
    /// and neither sees the other's.
    ///
    /// Batch isolation is invisible to `test_dispatch_cqe`, which can only
    /// deliver one fabricated CQE per call and so can never produce the case
    /// where one handler's side effects run between two decodes. The two
    /// sends deliberately differ in every field that could be confused: two
    /// connection indices, two pool slots, two generations (so a swapped
    /// payload would also trip an identity guard), two wire results, and two
    /// logical lengths — none of which equals its own wire result, so a
    /// handler reporting `acked` rather than the carried length fails too.
    #[test]
    fn nop_inject_batch_two_connections_settle_their_own_bounded_sends() {
        let mut el = bounded_test_loop();

        let conn_a = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_a, PATTERNED_GENERATION);
        let gen_a = el.driver.connections.generation(conn_a);

        let conn_b = accept_connection(&mut el);
        let gen_b = el.driver.connections.generation(conn_b);
        assert_ne!(conn_a, conn_b, "two distinct connection slots");
        assert_ne!(gen_a, gen_b, "and two distinct generations");

        // Ciphertext-shaped: 30 wire bytes for 12 logical, 10 for 4.
        let (id_a, slot_a) = bounded_slot(&mut el, conn_a, gen_a, &[b'a'; 30], 12);
        let (id_b, slot_b) = bounded_slot(&mut el, conn_b, gen_b, &[b'b'; 10], 4);
        assert_ne!(slot_a, slot_b, "and two distinct pool slots");

        let ud_a = UserData::encode(OpTag::Send, conn_a, UserData::send_payload(slot_a, gen_a));
        let ud_b = UserData::encode(OpTag::Send, conn_b, UserData::send_payload(slot_b, gen_b));
        el.inject_batch_and_dispatch(&[(ud_a.raw(), 30), (ud_b.raw(), 10)]);

        let result_a = el
            .executor
            .take_send_result(id_a)
            .expect("the first completion settled its own operation");
        assert_eq!(
            result_a.expect("the send succeeded"),
            12,
            "connection A's carried length"
        );
        let result_b = el
            .executor
            .take_send_result(id_b)
            .expect("the second completion settled its own operation");
        assert_eq!(
            result_b.expect("the send succeeded"),
            4,
            "connection B's carried length — not A's, and not B's wire bytes"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "both slots came back"
        );
    }

    /// `IOSQE_IO_LINK` orders a bounded send's completion *before* its
    /// connection's `Close`: the send settles `Ok`, and the teardown that
    /// follows in the same drain leaves that result standing.
    ///
    /// The link is the point. Nothing in the suite can otherwise pin the
    /// relative order of two CQEs — `drain_completions` takes them in
    /// whatever order the kernel posted them — and this ordering is the one
    /// that decides whether the caller of a fully delivered message is told
    /// `Ok(len)` or `ConnectionAborted`. `Executor::remove_connection` runs
    /// inside `handle_close` here, so it sees the entry already `Done` and,
    /// per #381's rule, must not touch it.
    #[test]
    fn nop_inject_bounded_send_linked_before_close_settles_before_teardown() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"delivered", 9);
        // The Close SQE is already in the kernel — the state in which a send
        // CQE and a Close CQE can be in flight together.
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let send_ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_linked_chain_and_dispatch(&[(send_ud.raw(), 9), (close_ud.raw(), 0)]);

        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the Close really did run in this drain"
        );
        let result = el
            .executor
            .take_send_result(id)
            .expect("the send settled before teardown could abort it");
        assert_eq!(
            result.expect("every byte reached the socket, so this is not an abort"),
            9,
            "a completion ordered before the Close reports its own result"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the completion returned the slot"
        );
    }

    /// The same two CQEs linked the other way round: the `Close` lands first,
    /// so teardown's `ConnectionAborted` is what the caller gets, and the
    /// send CQE that follows — now a dead occupant's — must not overwrite it.
    ///
    /// The mirror of the test above, and the one that shows the ordering is
    /// really being controlled rather than assumed: the setup is identical
    /// apart from the order of the linked pair, and the outcome inverts.
    /// `Executor::remove_connection` records the provisional abort, the
    /// connection's generation moves on, and `handle_send`'s identity guard
    /// then takes the id off the slot and drops it rather than settling —
    /// #381's rule that a driver result overrides an abort deliberately does
    /// *not* apply to a result that describes a connection that is gone.
    #[test]
    fn nop_inject_close_linked_before_bounded_send_keeps_teardowns_abort() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"too late", 8);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let send_ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_linked_chain_and_dispatch(&[(close_ud.raw(), 0), (send_ud.raw(), 8)]);

        assert!(
            el.driver.connections.get(conn_index).is_none(),
            "the Close ran first and released the slot"
        );
        let err = el
            .executor
            .take_send_result(id)
            .expect("teardown resolved the operation")
            .expect_err("the send CQE arrived after its connection was gone");
        assert_eq!(
            err.kind(),
            io::ErrorKind::ConnectionAborted,
            "the teardown abort stands; the late completion must not override it"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the late CQE is still the kernel's last reference to the slot"
        );
    }

    // ── Property-based tests (proptest) ────────────────────────────
    //
    // Generate random sequences of CQE events and verify resource
    // invariants hold: no pool leaks, no slab leaks, no panics.

    mod proptest_cqe {
        use super::*;
        use proptest::prelude::*;

        /// Random CQE action on a connection with an allocated pool slot.
        #[derive(Debug, Clone)]
        enum SendAction {
            /// Send completes successfully (all bytes).
            Ok,
            /// Send fails with an error.
            Error,
            /// Send completes with 0 bytes.
            Zero,
        }

        /// Random CQE action for ZC sends.
        #[derive(Debug, Clone)]
        enum ZcAction {
            /// ZC send succeeds, notification follows.
            OkThenNotif,
            /// ZC send fails with error.
            Error,
            /// ZC send result == 0.
            Zero,
            /// ZC send fails with IORING_CQE_F_MORE, and its notification
            /// follows -- what the kernel does for a failed ZC send (#487).
            ErrorThenNotif,
        }

        /// Random recv CQE result.
        #[derive(Debug, Clone)]
        enum RecvAction {
            /// EOF (result == 0).
            Eof,
            /// Error (unknown errno).
            Error,
            /// Data.
            Data,
            /// ECANCELED.
            Ecanceled,
        }

        /// Arm a direct receive on `ci` and return its completion's user_data.
        fn armed_recv_ud(el: &mut AsyncEventLoop<NoopHandler>, ci: u32) -> UserData {
            assert!(
                !el.driver.arm_direct_recv_or_close(ci, None),
                "receive refused"
            );
            let slot = el
                .driver
                .connections
                .get(ci)
                .expect("open")
                .recv_direct_slot;
            UserData::encode(OpTag::RecvDirect, ci, slot)
        }

        fn send_action_strategy() -> impl Strategy<Value = SendAction> {
            prop_oneof![
                Just(SendAction::Ok),
                Just(SendAction::Error),
                Just(SendAction::Zero),
            ]
        }

        fn zc_action_strategy() -> impl Strategy<Value = ZcAction> {
            prop_oneof![
                Just(ZcAction::OkThenNotif),
                Just(ZcAction::Error),
                Just(ZcAction::Zero),
                Just(ZcAction::ErrorThenNotif),
            ]
        }

        fn recv_action_strategy() -> impl Strategy<Value = RecvAction> {
            prop_oneof![
                Just(RecvAction::Eof),
                Just(RecvAction::Error),
                Just(RecvAction::Data),
                Just(RecvAction::Ecanceled),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            #[test]
            fn send_sequence_no_pool_leak(actions in proptest::collection::vec(send_action_strategy(), 1..8)) {
                let mut el = make_test_loop();
                let conn_index = accept_connection(&mut el);
                el.driver.send_queues[conn_index as usize].in_flight = true;

                let initial_free = el.driver.send_copy_pool.free_count();

                for action in &actions {
                    let data = b"test";
                    let (slot, _, _) = match el.driver.send_copy_pool.copy_in(data) {
                        Some(s) => s,
                        None => break, // pool exhausted — stop sequence
                    };

                    let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
                    let result = match action {
                        SendAction::Ok => data.len() as i32,
                        SendAction::Error => -104, // ECONNRESET
                        SendAction::Zero => 0,
                    };
                    el.test_dispatch_cqe(ud.raw(), result, 0);
                }

                // All pool slots should be released (no leaks).
                prop_assert_eq!(
                    el.driver.send_copy_pool.free_count(),
                    initial_free,
                    "pool slot leak detected"
                );
            }

            #[test]
            fn zc_sequence_no_slab_leak(actions in proptest::collection::vec(zc_action_strategy(), 1..6)) {
                let mut el = make_test_loop();
                let conn_index = accept_connection(&mut el);

                let initial_slab_free = el.driver.send_slab.free_count();
                let _initial_pool_free = el.driver.send_copy_pool.free_count();

                for action in &actions {
                    let iovecs = [libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 100 }];
                    let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
                    let (slab_idx, _) = match el.driver.send_slab.allocate(
                conn_index,
                el.driver.connections.generation(conn_index),
                &iovecs,
                u16::MAX,
                guards,
                0,
                100,
            ) {
                        Some(s) => s,
                        None => break,
                    };

                    let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);

                    match action {
                        ZcAction::OkThenNotif => {
                            // Operation CQE with success; the kernel sets
                            // IORING_CQE_F_MORE (2) because a notification follows.
                            el.test_dispatch_cqe(ud.raw(), 100, 2);
                            // Notification CQE.
                            el.test_dispatch_cqe(ud.raw(), 0, 8); // IORING_CQE_F_NOTIF
                        }
                        ZcAction::Error => {
                            el.test_dispatch_cqe(ud.raw(), -104, 0);
                            // Error path: mark_awaiting + should_release.
                            // May need explicit release if should_release is true.
                            if el.driver.send_slab.in_use(slab_idx) && el.driver.send_slab.should_release(slab_idx) {
                                el.driver.send_slab.release(slab_idx);
                            }
                        }
                        ZcAction::ErrorThenNotif => {
                            el.test_dispatch_cqe(ud.raw(), -104, 2); // F_MORE
                            prop_assert!(
                                el.driver.send_slab.in_use(slab_idx),
                                "released before the notification F_MORE promised"
                            );
                            el.test_dispatch_cqe(ud.raw(), 0, 8); // IORING_CQE_F_NOTIF
                        }
                        ZcAction::Zero => {
                            el.test_dispatch_cqe(ud.raw(), 0, 0);
                            if el.driver.send_slab.in_use(slab_idx) && el.driver.send_slab.should_release(slab_idx) {
                                el.driver.send_slab.release(slab_idx);
                            }
                        }
                    }
                }

                // All slab entries should be released.
                prop_assert_eq!(
                    el.driver.send_slab.free_count(),
                    initial_slab_free,
                    "slab entry leak detected"
                );
            }

            #[test]
            fn recv_sequence_no_panic(actions in proptest::collection::vec(recv_action_strategy(), 1..10)) {
                let mut el = make_test_loop();
                let conn_index = accept_connection(&mut el);

                for action in &actions {
                    // Stop once the connection is closed or its read half is
                    // finished: nothing arms a receive after the end.
                    if el
                        .driver
                        .connections
                        .get(conn_index)
                        .is_none_or(|c| c.close_requested() || c.recv_finished())
                    {
                        break;
                    }

                    let result = match action {
                        RecvAction::Eof => 0,
                        RecvAction::Error => -99,
                        RecvAction::Data => {
                            deliver_direct(&mut el, conn_index, b"data");
                            continue;
                        }
                        RecvAction::Ecanceled => -125,
                    };
                    let ud = armed_recv_ud(&mut el, conn_index);
                    el.test_dispatch_cqe(ud.raw(), result, 0);
                }

                // No assertion needed — the property is "no panic".
                // If we get here, the sequence was handled cleanly.
            }

            /// Mixed operation sequence across multiple connections.
            /// This is the most aggressive test — it interleaves different
            /// operation types on different connections, including connection
            /// lifecycle (accept, use, close, slot reuse).
            #[test]
            fn mixed_operations_no_leak_no_panic(
                actions in proptest::collection::vec(0..10u8, 5..30)
            ) {
                let mut el = make_test_loop();
                let initial_pool_free = el.driver.send_copy_pool.free_count();
                let initial_slab_free = el.driver.send_slab.free_count();

                // Track live connections and their allocated resources.
                let mut live_conns: Vec<u32> = Vec::new();
                let mut pool_slots_in_flight: Vec<u16> = Vec::new();

                for action in actions {
                    match action {
                        // Accept a new connection (if capacity available).
                        0 if live_conns.len() < 8 => {
                            let ci = accept_connection(&mut el);
                            el.driver.send_queues[ci as usize].in_flight = false;
                            live_conns.push(ci);
                        }

                        // Send success on a random live connection.
                        1 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                let ud = UserData::encode(
                                    OpTag::Send,
                                    ci,
                                    UserData::send_payload(
                                        slot,
                                        el.driver.connections.generation(ci),
                                    ),
                                );
                                el.test_dispatch_cqe(ud.raw(), 4, 0);
                            }
                        }

                        // Send error on the oldest live connection: the error
                        // closes it, and the Close CQE follows.
                        2 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                let ud = UserData::encode(
                                    OpTag::Send,
                                    ci,
                                    UserData::send_payload(
                                        slot,
                                        el.driver.connections.generation(ci),
                                    ),
                                );
                                el.test_dispatch_cqe(ud.raw(), -104, 0);
                                let close_ud = UserData::encode(OpTag::Close, ci, 0);
                                el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                            } else {
                                live_conns.insert(0, ci); // put it back
                            }
                        }

                        // ZC send success + notification on a live connection.
                        3 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            let iovecs = [libc::iovec {
                                iov_base: std::ptr::null_mut(),
                                iov_len: 50,
                            }];
                            let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
                            if let Some((slab_idx, _)) = el.driver.send_slab.allocate(ci, el.driver.connections.generation(ci), &iovecs, u16::MAX, guards, 0, 50) {
                                let ud = UserData::encode(
                                    OpTag::SendMsgZc, ci, slab_idx as u32,
                                );
                                // Operation CQE (success).
                                el.test_dispatch_cqe(ud.raw(), 50, 0);
                                // Notification CQE.
                                el.test_dispatch_cqe(ud.raw(), 0, 8);
                            }
                        }

                        // ZC send error on the oldest live connection: the
                        // error closes it, and the Close CQE follows.
                        4 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            let iovecs = [libc::iovec {
                                iov_base: std::ptr::null_mut(),
                                iov_len: 50,
                            }];
                            let guards = [const { None }; crate::buffer::send_slab::MAX_GUARDS];
                            if let Some((slab_idx, _)) = el.driver.send_slab.allocate(ci, el.driver.connections.generation(ci), &iovecs, u16::MAX, guards, 0, 50) {
                                let ud = UserData::encode(
                                    OpTag::SendMsgZc, ci, slab_idx as u32,
                                );
                                el.test_dispatch_cqe(ud.raw(), -104, 0);
                                // No notification is pending (flags 0), so
                                // the error path released the entry.
                                prop_assert!(
                                    !el.driver.send_slab.in_use(slab_idx),
                                    "the error path releases the entry"
                                );
                                let close_ud = UserData::encode(OpTag::Close, ci, 0);
                                el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                            } else {
                                live_conns.insert(0, ci); // put it back
                            }
                        }

                        // Recv EOF finishes the read half; the task's return
                        // closes the connection.
                        5 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            let ud = armed_recv_ud(&mut el, ci);
                            el.test_dispatch_cqe(ud.raw(), 0, 0);
                            el.driver.close_connection(ci);
                            // Simulate Close CQE.
                            let close_ud = UserData::encode(OpTag::Close, ci, 0);
                            el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                        }

                        // Recv data.
                        6 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            deliver_direct(&mut el, ci, b"data");
                        }

                        // Send + Recv EOF in same batch (the cross-CQE bug pattern).
                        7 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                pool_slots_in_flight.push(slot);
                                let send_ud = UserData::encode(
                                    OpTag::Send,
                                    ci,
                                    UserData::send_payload(
                                        slot,
                                        el.driver.connections.generation(ci),
                                    ),
                                );
                                let recv_ud = armed_recv_ud(&mut el, ci);
                                // EOF first, then stale send — the bug pattern.
                                el.test_dispatch_cqe(recv_ud.raw(), 0, 0);
                                el.test_dispatch_cqe(send_ud.raw(), 4, 0);
                                // The task's return closes; then the Close CQE.
                                el.driver.close_connection(ci);
                                let close_ud = UserData::encode(OpTag::Close, ci, 0);
                                el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                            } else {
                                live_conns.insert(0, ci); // put it back
                            }
                        }

                        // Close a live connection directly.
                        8 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            el.driver.close_connection(ci);
                            let close_ud = UserData::encode(OpTag::Close, ci, 0);
                            el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                        }

                        // No-op (or action on empty conn list).
                        _ => {}
                    }
                }

                // Clean up remaining live connections.
                for ci in &live_conns {
                    el.driver.close_connection(*ci);
                    let close_ud = UserData::encode(OpTag::Close, *ci, 0);
                    el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                }

                // Invariants: no resource leaks.
                prop_assert_eq!(
                    el.driver.send_copy_pool.free_count(),
                    initial_pool_free,
                    "pool slot leak after mixed operations"
                );
                prop_assert_eq!(
                    el.driver.send_slab.free_count(),
                    initial_slab_free,
                    "slab entry leak after mixed operations"
                );
            }
        }
    }

    /// An accept completion the loop never handled carries an ordinary fd the
    /// kernel installed, and `close_ring` closes it so the peer sees the
    /// close (#780): one reaped into the batch past its cursor, and one
    /// posted to the ring and not reaped. A completion before the cursor was
    /// dispatched, and its fd is left to its owner.
    #[test]
    fn close_ring_closes_the_fds_of_unhandled_accepts() {
        use std::io::Read;
        use std::os::fd::IntoRawFd;
        use std::time::Duration;

        let mut el = make_test_loop();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("listener address");
        let connect = || std::net::TcpStream::connect(addr).expect("connect");
        let accept = || listener.accept().expect("accept").0.into_raw_fd();
        let ud = UserData::encode(OpTag::AcceptMulti, 0, 0).raw();

        let mut handled_peer = connect();
        let handled = accept();
        let mut batched_peer = connect();
        let batched = accept();
        el.driver.cqe_batch.clear();
        el.driver.cqe_batch.push((ud, handled, 0));
        el.driver.cqe_batch.push((ud, batched, 0));
        el.driver.cqe_cursor = 1;
        let mut posted_peer = connect();
        let posted = accept();
        // A NOP with this result completes in the wait, on Linux 6.10 and
        // later; before that `inject` hands it to `reap` directly and the
        // wait returns at once.
        el.driver
            .ring
            .submit_nop_inject(ud, posted)
            .expect("inject");
        el.driver.ring.submit_and_wait(1).expect("submit_and_wait");

        // Safety: the loop is leaked below, as the worker leaks it.
        unsafe { el.close_ring() };
        std::mem::forget(el);

        let mut byte = [0u8; 1];
        for (name, peer) in [("batched", &mut batched_peer), ("posted", &mut posted_peer)] {
            peer.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let read = peer.read(&mut byte);
            assert!(
                matches!(read, Ok(0)),
                "the {name} accept's fd was not closed: {read:?}"
            );
        }
        handled_peer
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("read timeout");
        assert!(
            handled_peer.read(&mut byte).is_err(),
            "the handled accept's fd was closed"
        );
        // Safety: `handled` is this test's open fd.
        unsafe {
            libc::close(handled);
        }
    }
}

#[cfg(test)]
mod placement_tests {
    use super::{HANDOFF_MARGIN, PARK_FLOOR, PARK_MARGIN, choose_park_target, choose_placement};

    #[test]
    fn keeps_the_connection_when_this_worker_is_the_quietest() {
        assert_eq!(choose_placement(&[0, 5, 5, 5], &[true; 4], 0, 0), None);
    }

    #[test]
    fn keeps_it_when_the_gap_is_under_the_margin() {
        // One ahead of the quietest is not worth a channel send and a wake —
        // but only while the quietest is actually serving something. Against an
        // *idle* worker the margin drops to 1, which
        // `one_ahead_of_an_idle_worker_does_hand_off` covers, so this case has
        // to use a non-empty minimum to exercise the margin it is named for.
        assert_eq!(choose_placement(&[3, 2, 3, 3], &[true; 4], 0, 3), None);
    }

    #[test]
    fn hands_off_once_the_margin_is_reached() {
        assert_eq!(
            choose_placement(&[HANDOFF_MARGIN, 0, 5, 5], &[true; 4], 0, HANDOFF_MARGIN),
            Some(1)
        );
    }

    #[test]
    fn hands_off_to_the_quietest_not_merely_a_quieter_one() {
        assert_eq!(choose_placement(&[9, 4, 1, 4], &[true; 4], 0, 9), Some(2));
    }

    #[test]
    fn never_hands_off_to_itself_even_when_it_is_the_minimum() {
        // The minimum is this worker, so there is nowhere better to go.
        assert_eq!(choose_placement(&[0, 3, 3, 3], &[true; 4], 0, 0), None);
    }

    #[test]
    fn a_single_worker_has_nowhere_to_hand_off_to() {
        assert_eq!(choose_placement(&[99], &[true], 0, 99), None);
    }

    #[test]
    fn never_hands_off_to_a_worker_steered_out_of_the_rotation() {
        // Worker 1 is the least loaded precisely *because* it was steered out.
        // Handing it work would undo the steering.
        assert_eq!(
            choose_placement(&[9, 0, 4, 9], &[true, false, true, true], 0, 9),
            Some(2),
            "should fall through to the quietest worker still accepting"
        );
    }

    #[test]
    fn keeps_the_connection_when_every_other_worker_is_out() {
        assert_eq!(
            choose_placement(&[9, 0, 0, 0], &[true, false, false, false], 0, 9),
            None
        );
    }

    /// Replay a whole burst through the policy and report who ends up serving.
    ///
    /// `arrivals` is the worker the kernel handed each connection to, in order.
    /// Mirrors the runtime: `mine` is the count *before* the arrival is
    /// installed, and a handoff claims the target's slot immediately (as
    /// `hand_off_accepted` does) so the next decision sees it.
    fn replay(arrivals: &[usize], workers: usize) -> Vec<usize> {
        let mut served = vec![0usize; workers];
        let mut loads = vec![0u32; workers];
        let accepting = vec![true; workers];
        for &who in arrivals {
            let mine = served[who] as u32;
            let dst = choose_placement(&loads, &accepting, who, mine).unwrap_or(who);
            served[dst] += 1;
            loads[dst] += 1;
        }
        served
    }

    // ── Park policy (tier 3, #443) ─────────────────────────────────

    /// A balanced fleet must not park. Without this, every other policy test
    /// could pass against a function that always sheds.
    #[test]
    fn a_balanced_worker_does_not_park() {
        let loads = [20, 20, 21, 20];
        let up = [true; 4];
        assert_eq!(choose_park_target(&loads, &up, 2, 21), None);
    }

    #[test]
    fn a_standing_imbalance_parks_onto_the_least_loaded() {
        let loads = [40, 8, 30, 31];
        let up = [true; 4];
        assert_eq!(choose_park_target(&loads, &up, 0, 40), Some(1));
    }

    /// Tier 1 places arrivals and costs an integer; tier 3 moves a live
    /// connection. The wider margin is what keeps the cheap mechanism in
    /// front, and what stops the two fighting over the same pair.
    #[test]
    fn a_gap_tier_one_still_covers_does_not_escalate_to_park() {
        let loads = [20, 20 - HANDOFF_MARGIN - 1, 20, 20];
        let up = [true; 4];
        assert!(
            choose_placement(&loads, &up, 0, 20).is_some(),
            "tier 1 acts"
        );
        assert_eq!(
            choose_park_target(&loads, &up, 0, 20),
            None,
            "and tier 3 stays out of it"
        );
    }

    /// The floor. Without it the last connections ping-pong: a worker at 1 is
    /// forever "above" a worker at 0 by any margin, so the pair never settles.
    #[test]
    fn a_nearly_empty_worker_does_not_park_its_last_connections() {
        let loads = [PARK_FLOOR, 0, PARK_FLOOR, PARK_FLOOR];
        let up = [true; 4];
        assert_eq!(
            choose_park_target(&loads, &up, 0, PARK_FLOOR),
            None,
            "at the floor, hold"
        );
        // One above the floor, and far enough above the target, it moves.
        let loads = [PARK_FLOOR + PARK_MARGIN, 0, 9, 9];
        assert_eq!(
            choose_park_target(&loads, &up, 0, PARK_FLOOR + PARK_MARGIN),
            Some(1)
        );
    }

    /// Parking onto a worker steered out of the rotation (tier 2) would put
    /// back exactly what steering is draining — the trap `choose_placement`
    /// already names, and it applies identically here.
    #[test]
    fn park_never_targets_a_worker_steered_out_of_the_rotation() {
        let loads = [40, 0, 30, 31];
        let up = [true, false, true, true];
        assert_eq!(
            choose_park_target(&loads, &up, 0, 40),
            Some(2),
            "the drained worker is skipped even though it is emptiest"
        );
    }

    #[test]
    fn a_worker_that_is_itself_the_least_loaded_does_not_park() {
        let loads = [5, 40, 40, 40];
        let up = [true; 4];
        assert_eq!(choose_park_target(&loads, &up, 0, 5), None);
    }

    #[test]
    fn a_pooled_client_leaves_no_worker_idle() {
        // The arrival shape the kernel's hash actually produced on the rack:
        // eight connections over eight workers, landing 2,2,1,1,1,1,0,0
        // (#456). With a flat margin of 2 the policy never fired — a worker
        // sheds on its third connection and nobody got a third — and two
        // workers stayed idle in 3 of 3 reps.
        let served = replay(&[0, 0, 1, 1, 2, 3, 4, 5], 8);
        let idle = served.iter().filter(|&&c| c == 0).count();
        assert_eq!(
            idle, 0,
            "a pooled client must not leave a worker idle; served {served:?}"
        );
    }

    #[test]
    fn the_worst_case_hash_still_spreads() {
        // Everything lands on one worker. It cannot reach even, but it must
        // not leave anyone at zero.
        let served = replay(&[0; 8], 8);
        assert_eq!(
            served.iter().filter(|&&c| c == 0).count(),
            0,
            "served {served:?}"
        );
    }

    #[test]
    fn a_busy_fleet_is_not_churned_by_the_relaxed_margin() {
        // Nobody idle, so the margin of 2 still governs: a worker one ahead of
        // the quietest keeps its connection rather than ping-ponging it.
        assert_eq!(choose_placement(&[4, 3, 5, 4], &[true; 4], 0, 4), None);
    }

    #[test]
    fn one_ahead_of_an_idle_worker_does_hand_off() {
        // The case the flat margin of 2 refused, and the whole point of the
        // change: this worker holds one, someone holds none.
        assert_eq!(choose_placement(&[1, 0, 1, 1], &[true; 4], 0, 1), Some(1));
    }

    #[test]
    fn an_empty_table_is_not_a_panic() {
        assert_eq!(choose_placement(&[], &[], 0, 0), None);
    }
}
