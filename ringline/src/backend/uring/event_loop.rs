use std::io;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::time::Instant;

use io_uring::cqueue;

use crate::backend::Driver;
use crate::backend::sockaddr_to_socket_addr;
use crate::chain::ChainEvent;
use crate::completion::{OpTag, UserData};
use crate::connection::{Lifecycle, ReadHalf, RecvArm};
use crate::metrics;
use crate::runtime::handler::AsyncEventHandler;
use crate::runtime::io::{ConnCtx, DriverState, UdpCtx, set_driver_state_guarded};
use crate::runtime::send_capacity::BoundedSendId;
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
    /// Create a new async event loop for a worker thread.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &crate::config::Config,
        handler: A,
        accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
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
        // provided buffer until the task consumes it. Capacity beyond the
        // ring size is physically unusable: the ring starves (ENOBUFS)
        // before the queue ever fills, and the drop accounting never
        // fires. Clamp so overflow is an observable drop instead of a
        // silent stall. (The mio backend copies into owned buffers and
        // keeps the full configured depth.)
        let udp_queue_capacity = config
            .udp_recv_queue_capacity
            .min(config.udp_recv_buffer.ring_size as usize);
        let executor = Executor::new(
            config.max_connections,
            config.standalone_task_capacity,
            config.timer_slots,
            config.udp_bind.len() as u32,
            udp_queue_capacity,
        );
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
            let udp_ctx = UdpCtx {
                udp_index: udp_idx as u32,
            };
            if let Some(future) = self.handler.on_udp_bind(udp_ctx)
                && let Some(idx) = self.executor.standalone_slab.spawn(future)
            {
                self.executor.ready_queue.push_back(idx | STANDALONE_BIT);
            }
        }

        // Spawn on_start task (client-only entry point).
        if let Some(future) = self.handler.on_start()
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

            // The blocking wait itself is always performed; only the timing
            // around it is gated on `loop_diag`.
            let wait_start = if loop_diag {
                Some(std::time::Instant::now())
            } else {
                None
            };
            // Don't block while tasks are already runnable (self-wakes
            // collected after the last poll pass, tasks woken from
            // on_tick): submit SQEs but return immediately so the ready
            // queue is polled now instead of after the next CQE or tick
            // timeout (indefinitely, with tick_timeout_us = 0).
            self.executor.collect_wakeups();
            // Commit buffer returns from the poll pass and revive
            // ENOBUFS-parked receivers before we block.
            self.flush_direct_echoes();
            self.flush_replenish_and_rearm();
            // Declining to block still has to reap: under DEFER_TASKRUN the
            // kernel runs task_work only on a GETEVENTS enter, and
            // `submit_and_wait(0)` carries no such flag. Going through
            // `submit_and_get_events` (same single syscall) keeps completions
            // flowing while a task is runnable — otherwise a task that stays
            // runnable without queueing SQEs (so `flush()` takes its empty-SQ
            // shortcut) starves the whole worker of completions.
            if self.executor.ready_queue.is_empty() {
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
                         tasks_1st_avg={:.2} tasks_fp_avg={:.2} parks={} fallbacks={}",
                        diag_cqes_1st as f64 / diag_iters.max(1) as f64,
                        diag_cqes_2nd as f64 / diag_iters.max(1) as f64,
                        diag_tasks_1st as f64 / diag_iters.max(1) as f64,
                        diag_tasks_fp as f64 / diag_iters.max(1) as f64,
                        self.driver.recv_park_count,
                        self.driver.recv_fallback_count,
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

            // Recv buffer replenish for TCP now happens eagerly at the end of
            // `drain_completions` (same iteration the buffers were consumed).
            // UDP replenish stays here — it is conditional on the UDP buffer
            // ring being configured and is off the burst hot path.
            if !self.driver.udp_pending_replenish.is_empty()
                && let Some(ref mut udp_bufs) = self.driver.udp_provided_bufs
            {
                udp_bufs.replenish_batch(&self.driver.udp_pending_replenish);
                self.driver.udp_pending_replenish.clear();
            }

            // Drain pending region-registry updates dispatched from
            // `ShutdownHandle::register_region` / `unregister_region`. Each
            // message is applied to this worker's ring + registry and then
            // acknowledged so the registrar can return to its caller.
            self.drain_region_control();
            // Retry send/close submissions that failed on a previous tick
            // (SQ was full). The SQ has been flushed by submit_and_wait above.
            self.drain_zc_retries();
            self.drain_coalesced_retries();
            self.drain_recv_forward_retries();
            self.drain_copy_retries();
            self.drain_send_retries();
            self.drain_close_retries();
            self.drain_send_pollout_retries();
            self.driver.tick_count += 1;

            // Check close_notify deadlines — force-close connections where
            // close_notify was sent but the close CQE never arrived.
            self.check_close_notify_deadlines();

            // Drain waker-based ready queue (from wakers fired during poll).
            self.executor.collect_wakeups();

            // Poll all ready tasks.
            let tasks_before = self.executor.ready_queue.len();
            self.poll_ready_tasks();
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
            // process send CQEs that wake no tasks (no send waiter for
            // send_nowait callers).
            let _ = self.driver.ring.flush();

            // Non-blocking drain: consume the CQEs (primarily send completions)
            // that flush()'s GETEVENTS step posted to the CQ ring.
            // For send_nowait the pool slot is freed here; wake_send is a
            // no-op (no waiter).  Draining inline collapses the two-iteration
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
            // inside the handler. Raw pointers dodge the borrow conflict
            // with `make_ctx()` (which would otherwise hold &mut self.driver).
            let handler = &mut self.handler;
            let driver_ptr = &mut self.driver as *mut Driver;
            let executor_ptr = &mut self.executor as *mut crate::runtime::Executor;
            let mut driver_state = DriverState {
                driver: unsafe { NonNull::new_unchecked(driver_ptr) },
                executor: unsafe { NonNull::new_unchecked(executor_ptr) },
            };
            let guard = unsafe { set_driver_state_guarded(&mut driver_state) };
            // Safety: driver_ptr is the only live reference to self.driver
            // until the guard is dropped below. catch_unwind keeps a panic
            // in user tick code from unwinding past the guard's scope with
            // futures observing a dangling CURRENT_DRIVER, and from killing
            // the worker.
            {
                let mut ctx = unsafe { (*driver_ptr).make_ctx() };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler.on_tick(&mut ctx);
                }));
                if result.is_err() {
                    eprintln!("ringline: handler on_tick panicked; continuing");
                }
            }
            drop(guard);

            // Rebalance after the handler's tick, not before: the tick is
            // where a handler typically finishes work and offers a connection,
            // so running first would act on last iteration's offers and always
            // be one tick stale. After the guard, because `begin_park` takes
            // `&mut self` and the guard holds a raw pointer to the driver.
            self.maybe_park_one();

            // Finalize every close requested this iteration — by
            // `close_connection` from a CQE handler or the task-exit arm, or
            // by `DriverCtx::close` from a task. Deliberately after
            // `poll_ready_tasks`, so a task woken by the peer's FIN gets its
            // poll and a send it queues drains before the Close is committed
            // (#371). try_finalize_close is guarded, so a connection with
            // sends/chains still outstanding just waits for its CQEs to
            // re-drive via note_send_finalized.
            if !self.driver.pending_finalize_closes.is_empty() {
                let mut pending = std::mem::take(&mut self.driver.pending_finalize_closes);
                for conn_index in pending.drain(..) {
                    self.driver.try_finalize_close(conn_index);
                }
                self.driver.pending_finalize_closes = pending;
            }

            // Hand the executor every bounded-send result that no CQE
            // carried. Two producers fill this queue and both of them have
            // run by now: `DriverCtx::send_bounded`, from `poll_ready_tasks`
            // and from `on_tick` (a message that queued no SQE at all), and
            // teardown, from any `drain_conn_send_queue` /
            // `force_finalize_close` / `reset_send_state` above — including
            // the `try_finalize_close` pass immediately preceding. Draining
            // once, here, is therefore the single point that covers all of
            // them, and nothing waits on it: `complete_bounded_send` wakes
            // the owner straight onto `Executor::ready_queue`, which the top
            // of the next iteration collects *before* deciding whether to
            // block, so a settled send is polled without a `submit_and_wait`
            // in between.
            self.drain_bounded_send_completions();

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
                    let result = self
                        .driver
                        .fixed_buffers
                        .set_slot(slot, &region)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
                        .and_then(|()| {
                            let iov = libc::iovec {
                                iov_base: region.ptr() as *mut _,
                                iov_len: region.len(),
                            };
                            // Safety: caller of `register_region` guarantees the
                            // region outlives the registration.
                            unsafe { self.driver.ring.register_buffers_update_one(slot, iov) }
                        });
                    let _ = ack.send(result);
                }
                RegionControlMsg::Unregister { slot, ack } => {
                    let result = self
                        .driver
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
                        });
                    let _ = ack.send(result);
                }
            }
        }
    }

    /// Poll all tasks in the ready queue (both connection and standalone tasks).
    fn poll_ready_tasks(&mut self) {
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
        // polled right now, records woken_while_polling so the poll loop
        // re-queues it after parking). A std::task::Waker does NOT — what a
        // future gets from its Context pushes onto the thread-local queue in
        // runtime/waker.rs, which only reaches executor.ready_queue via
        // collect_wakeups() once this pass has ended. So a future that wakes
        // itself through its Context (the usual "yield to the executor"
        // pattern) resumes on the NEXT event-loop iteration — after
        // submit_and_wait and drain_completions — not within this pass.
        // tests/ready_queue_fairness.rs pins that property.
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
                    let waker = standalone_waker(task_idx);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(raw_id));
                    executor.currently_polling = Some(raw_id);
                    executor.woken_while_polling = false;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        fut.as_mut().poll(&mut cx)
                    }));
                    executor.currently_polling = None;
                    match result {
                        Ok(std::task::Poll::Ready(())) => {
                            executor.standalone_slab.remove(task_idx);
                        }
                        Ok(std::task::Poll::Pending) => {
                            executor.standalone_slab.park(task_idx, fut);
                            // The task woke itself mid-poll (its slot read
                            // `Polling`, which the wake cannot transition) —
                            // re-queue now that it is parked.
                            if executor.woken_while_polling {
                                let _ = executor.wake_task(raw_id);
                            }
                        }
                        Err(_panic) => {
                            // Drop the future and free the slot. We swallow
                            // the panic to keep the worker alive — without
                            // this, a single buggy `on_udp_bind` /
                            // `on_start` future panics the whole worker
                            // thread and tears down every other connection
                            // on it.
                            drop(fut);
                            executor.standalone_slab.remove(task_idx);
                            eprintln!("ringline: standalone task panicked; dropped");
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
                    let waker = conn_waker(conn_index);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(conn_index));
                    executor.currently_polling = Some(conn_index);
                    executor.woken_while_polling = false;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        fut.as_mut().poll(&mut cx)
                    }));
                    executor.currently_polling = None;
                    match result {
                        Ok(std::task::Poll::Ready(())) => {
                            // Task completed — connection handler is done.
                            driver.close_connection(conn_index);
                            executor.remove_connection(conn_index);
                        }
                        Ok(std::task::Poll::Pending) => {
                            executor.task_slab.park(conn_index, fut);
                            // Self-wake during poll (slot read `Polling`) —
                            // re-queue now that the task is parked.
                            if executor.woken_while_polling {
                                let _ = executor.wake_task(conn_index);
                            }
                        }
                        Err(_panic) => {
                            // A panicking connection handler tears down the
                            // connection but must not take the worker
                            // thread with it.
                            drop(fut);
                            driver.close_connection(conn_index);
                            executor.remove_connection(conn_index);
                            eprintln!(
                                "ringline: connection task panicked; connection {conn_index} closed"
                            );
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

        {
            let cq = self.driver.ring.ring.completion();
            for cqe in cq {
                self.driver
                    .cqe_batch
                    .push((cqe.user_data(), cqe.result(), cqe.flags()));
            }
        }

        if let Some(interval) = self.driver.flush_interval {
            let mut last_flush = Instant::now();
            for i in 0..self.driver.cqe_batch.len() {
                let (user_data_raw, result, flags) = self.driver.cqe_batch[i];
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
                self.dispatch_cqe(user_data_raw, result, flags);
            }
        }

        // Gather the batch's direct-echo arrivals before anything is submitted,
        // so a message that spanned several recv CQEs leaves as one send.
        self.flush_direct_echoes();

        // Eagerly return consumed recv buffers to the kernel ring in the same
        // iteration they were consumed, keeping the ring fuller under burst.
        self.flush_replenish_and_rearm();
    }

    /// Flush every direct-echo connection holding staged buffers.
    ///
    /// A connection stays on the queue while its hold is non-empty — because a
    /// send is already in flight, because the gather hit `MAX_IOVECS`, or
    /// because more arrived during the flush — and drops off once it drains
    /// (including when `close_connection` drains it). That means no completion
    /// handler has to remember to re-arm the connection: the next drain's pass
    /// finds it still queued.
    fn flush_direct_echoes(&mut self) {
        if self.driver.direct_echo_pending.is_empty() {
            return;
        }
        let mut i = 0;
        while i < self.driver.direct_echo_pending.len() {
            let conn_index = self.driver.direct_echo_pending[i];
            self.driver.flush_direct_echo(conn_index);
            // Drop the entry once the hold drains, and also if the slot is no
            // longer a direct-echo connection: `recv_hold` is shared with
            // recv-forward, whose hold is the task's to drain, and a stale
            // entry left over from a closed connection must not start
            // gathering for whatever occupies the slot next.
            if !self
                .driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.direct_echo)
                || self.driver.recv_hold[conn_index as usize].is_empty()
            {
                self.driver.direct_echo_queued[conn_index as usize] = false;
                self.driver.direct_echo_pending.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    /// Commit pending provided-buffer returns to the kernel ring and re-arm
    /// any connections whose multishot recv was parked on ENOBUFS.
    ///
    /// Safe because every bid pushed to `pending_replenish` had its contents
    /// copied out (into the accumulator / recv sink / TLS state) before being
    /// pushed — dispatch has fully completed, so no handler still references
    /// these buffers. Zero-copy held buffers are tracked in
    /// `pending_recv_bufs` / `recv_hold` slots and are never in this queue.
    ///
    /// Also called from the run loop right before the blocking wait: bids
    /// released by tasks during the poll pass would otherwise sit uncommitted
    /// (and starved connections parked) until the next unrelated CQE.
    fn flush_replenish_and_rearm(&mut self) {
        // Starved connections holding a zero-copy single-buffer hold
        // (`pending_recv_bufs`) with data the parser hasn't consumed: flush
        // the hold into the accumulator so its bid can rejoin the ring.
        // This both frees a buffer (often enough to revive the multishot
        // below) and moves the partial message where the fallback path
        // expects it.
        if !self.driver.recv_starved.is_empty() {
            for i in 0..self.driver.recv_starved.len() {
                let conn_index = self.driver.recv_starved[i];
                if let Some(pending) = self.driver.pending_recv_bufs[conn_index as usize].take() {
                    let data =
                        unsafe { std::slice::from_raw_parts(pending.ptr, pending.len as usize) };
                    if !self.driver.accumulators.append(conn_index, data) {
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                    }
                    self.driver.pending_replenish.push(pending.bid);
                }
            }
        }

        // Commit returned bids up front so re-armed multishots find them.
        let replenished = if !self.driver.pending_replenish.is_empty() {
            self.driver
                .provided_bufs
                .replenish_batch(&self.driver.pending_replenish);
            self.driver.pending_replenish.clear();
            true
        } else {
            false
        };

        if self.driver.recv_starved.is_empty() {
            return;
        }

        // Arbitrate each parked connection:
        //
        // - Fallback in flight: stays parked untouched — a multishot armed
        //   alongside the outstanding one-shot could append out of order
        //   (io_uring does not order independent SQEs). The fallback's
        //   completion re-parks it and a later pass hands off.
        // - Partial message on the plaintext accumulator path: prefer a
        //   fallback recv EVEN IF buffers were replenished. Re-arming the
        //   multishot moves at most one ring's worth before parking again —
        //   with responses larger than the ring that park/re-arm churn is
        //   the pathology (per-pass throughput = ring capacity × pass
        //   rate), while a fallback moves one `fallback_chunk` (> ring
        //   capacity) per pass and never closes the TCP window. The
        //   multishot resumes once the message completes and the
        //   accumulator drains.
        // - Everything else: re-arm the multishot when buffers came back,
        //   otherwise keep waiting (nothing is half-delivered).
        let mut i = 0;
        while i < self.driver.recv_starved.len() {
            let conn_index = self.driver.recv_starved[i];
            if self.driver.recv_fallback_inflight[conn_index as usize] {
                i += 1;
                continue;
            }
            // A forwarding connection throttled by the Mode A hold cap owns its own
            // re-arm (`maybe_rearm_throttled_forward`, gated on the hold draining
            // below the cap). Leave it parked here so the two paths do not both
            // arm a multishot.
            if self.driver.forward_hold_throttled[conn_index as usize] {
                i += 1;
                continue;
            }
            let alive = self.driver.connections.get(conn_index).is_some_and(|c| {
                matches!(c.lifecycle, Lifecycle::Open) && matches!(c.recv_arm, RecvArm::Multi)
            });
            if !alive {
                self.driver.recv_starved.swap_remove(i);
                continue;
            }
            if self.fallback_eligible(conn_index)
                && self.driver.try_submit_fallback_recv(conn_index)
            {
                self.driver.recv_starved.swap_remove(i);
                continue;
            }
            // Re-arm whenever the ring can actually feed a multishot, not only
            // on a pass that just returned bids. A connection parked while the
            // ring was dry, whose bids came back in a pass that did not visit
            // it — a fallback completion re-parks it *after* the flush — would
            // otherwise sit parked against a full ring with nothing left to
            // trigger another replenish: no further recv, so no further bid
            // return, so no further pass with `replenished`. Forever.
            if replenished || self.driver.provided_bufs.free() > 0 {
                self.driver.recv_starved.swap_remove(i);
                let generation = self.driver.connections.generation(conn_index);
                if self
                    .driver
                    .ring
                    .submit_multishot_recv(conn_index, generation)
                    .is_err()
                {
                    metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
                    self.executor.wake_recv(conn_index);
                    self.driver.close_connection(conn_index);
                } else if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.recv_multishot_armed = true;
                }
                continue;
            }
            i += 1;
        }
    }

    /// Whether a parked connection may take the fallback recv path:
    /// plaintext accumulator route only (no TLS, recv sink, segmented
    /// delivery, zero-copy forward, or direct echo — those paths keep the
    /// park-until-replenish behavior) with a partial message already
    /// accumulated. The caller has already checked liveness and that no
    /// fallback is in flight.
    fn fallback_eligible(&mut self, conn_index: u32) -> bool {
        let ci = conn_index as usize;
        let is_tls = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has(conn_index));
        let is_direct_echo = self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.direct_echo);
        // Segmented delivery (`forward_to`/`forward_to_conn`, `with_segments`)
        // is defined over provided buffers: a segment is a held bid, and the
        // hold is where a reader looks. The fallback reads into a pool slot and
        // can only append to the accumulator, so on a segmented connection it
        // does not merely bypass the reader — it reorders the stream, since
        // bytes already held are earlier than the ones it appends. A forward
        // source is the worst case: it never looks at the accumulator at all,
        // so the fallback chain feeds bytes into a buffer nobody reads while
        // the forward waits for a segment that cannot arrive, forever. It is
        // reachable because a forward's own overshoot tail (bytes past `len`)
        // lands in the accumulator, which is exactly the "half-delivered
        // message" this path takes as its cue.
        let is_segmented =
            self.driver.recv_domain[ci] == crate::recv::domain::RecvDomain::Segmented;
        if is_tls
            || is_direct_echo
            || is_segmented
            || self.driver.recv_forward[ci]
            || self.executor.recv_sinks[ci].is_some()
        {
            return false;
        }
        // Only degrade when a message is half-delivered; an empty
        // accumulator means nothing is torn and the connection can simply
        // wait for replenish (holds were flushed above).
        !self.driver.accumulators.data(conn_index).is_empty()
    }

    /// Completion of a fallback one-shot recv (`OpTag::RecvFallback`).
    ///
    /// The payload carries the fallback pool slot; the recorded
    /// `(conn_index, generation)` owner is validated before any connection
    /// state is touched — slots recycle and stale CQEs are normal. The
    /// pool slot is released here and only here, so the kernel's write
    /// target stays valid for exactly the life of the operation.
    fn handle_recv_fallback(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let slot = ud.payload() as u16;

        let pool_ok = self
            .driver
            .fallback_recv_pool
            .as_ref()
            .is_some_and(|p| p.in_use(slot));
        if !pool_ok {
            return;
        }
        let (owner_conn, owner_gen) = self.driver.fallback_slot_owner[slot as usize];
        let stale = owner_conn != conn_index
            || self.driver.connections.generation(conn_index) != owner_gen
            || self.driver.connections.get(conn_index).is_none();
        if stale {
            // The connection this recv was submitted for is gone; the data
            // (if any) belongs to a closed socket. Release the slot only.
            self.driver
                .fallback_recv_pool
                .as_mut()
                .expect("checked in_use above")
                .release(slot);
            return;
        }

        self.driver.recv_fallback_inflight[conn_index as usize] = false;

        if result < 0 {
            self.driver
                .fallback_recv_pool
                .as_mut()
                .expect("checked in_use above")
                .release(slot);
            if -result == libc::ECANCELED {
                // Cancelled, connection still alive: re-park so a later
                // flush re-arms the multishot (or retries the fallback) —
                // otherwise no recv is armed and the connection hangs.
                if !self.driver.recv_starved.contains(&conn_index) {
                    self.driver.recv_starved.push(conn_index);
                }
                return;
            }
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.read = ReadHalf::Error;
            }
            self.executor
                .fail_recv(conn_index, owner_gen, io::Error::from_raw_os_error(-result));
            self.driver.close_connection(conn_index);
            return;
        }

        if result == 0 {
            // TCP FIN mid-message (fallback only runs with a partial
            // message accumulated): same truncation semantics as the
            // multishot path for plaintext connections.
            self.driver
                .fallback_recv_pool
                .as_mut()
                .expect("checked in_use above")
                .release(slot);
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.note_eof(false);
            }
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
            return;
        }

        // Withdraw before the append and before `recv_fallback_inflight`
        // clears: that flag was the only term holding the park off, so
        // delivering here would otherwise take the connection from blocked to
        // "parkable with a half-received request" in one step.
        self.withdraw_park_offer(conn_index);

        let bytes_received = result as u32;
        metrics::BYTES.add(metrics::bytes::RECEIVED, bytes_received as u64);
        metrics::BYTES.add(metrics::bytes::FALLBACK_RECEIVED, bytes_received as u64);

        let pool = self
            .driver
            .fallback_recv_pool
            .as_mut()
            .expect("checked in_use above");
        let (ptr, _) = pool.current_ptr_remaining(slot);
        let data = unsafe { std::slice::from_raw_parts(ptr, bytes_received as usize) };
        // `fallback_eligible` refuses a segmented connection, but the domain can
        // flip *while a fallback is in flight* — a handler that parses a length
        // header and then starts a forward does exactly that. These bytes are
        // the newest on the stream, so they go to the back of the hold, where
        // the segmented reader will find them; appending them to the
        // accumulator would stand them in front of the held bytes and strand
        // them besides, since a forward never reads the accumulator.
        let appended = if self.driver.recv_domain[conn_index as usize]
            == crate::recv::domain::RecvDomain::Segmented
        {
            self.driver.segment_hold[conn_index as usize].push_back(
                crate::backend::HeldRecvBuf::Owned(bytes::Bytes::copy_from_slice(data)),
            );
            true
        } else {
            self.driver.accumulators.append(conn_index, data)
        };
        self.driver
            .fallback_recv_pool
            .as_mut()
            .expect("checked in_use above")
            .release(slot);
        if !appended {
            // Streamed past recv_accumulator_max — close rather than OOM,
            // matching the multishot overflow path.
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
            return;
        }

        self.executor.wake_recv(conn_index);
        // Re-park: the multishot is still dead. The next flush either
        // re-arms it (replenish arrived) or continues the fallback chain
        // (parse still incomplete, ring still dry). If the parse completed,
        // the connection waits parked until bids return — exactly the
        // pre-fallback steady state.
        if !self.driver.recv_starved.contains(&conn_index) {
            self.driver.recv_starved.push(conn_index);
        }
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

        match tag {
            OpTag::AcceptMulti => self.handle_accept_multi(ud, result, flags),
            OpTag::ParkInstall => self.handle_park_install(ud, result),
            OpTag::RecvMulti => self.handle_recv_multi(ud, result, flags),
            OpTag::RecvFallback => self.handle_recv_fallback(ud, result),
            OpTag::Send => self.handle_send(ud, result),
            OpTag::SendMsgZc => self.handle_send_msg_zc(ud, result, flags),
            OpTag::Close => self.handle_close(ud),
            OpTag::Shutdown => {}
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
            OpTag::SendRecvBuf => self.handle_send_recv_buf(ud, result),
            OpTag::SendPollOut => self.handle_send_pollout(ud, result),
            OpTag::SendMsgCoalesced => self.handle_send_msg_coalesced(ud, result),
            OpTag::SendMsgCoalescedPollOut => self.handle_send_msg_coalesced_pollout(ud, result),
            OpTag::SendRecvBufsCoalesced => self.handle_send_recv_bufs_coalesced(ud, result),
            OpTag::SendRecvBufsCoalescedPollOut => {
                self.handle_send_recv_bufs_coalesced_pollout(ud, result)
            }
            OpTag::ForwardWrite => self.handle_forward_write(ud, result),
            OpTag::ForwardWritePollOut => self.handle_forward_write_pollout(ud, result),
            #[cfg(feature = "timestamps")]
            OpTag::RecvMsgMultiTs => self.handle_recv_msg_multi_ts(ud, result, flags),
        }
    }

    fn handle_recv_multi(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let has_more = cqueue::more(flags);

        // Identity check, before anything touches connection state. The slot
        // must still be occupied AND by the same connection this recv was armed
        // for: a multishot can outlive its fixed-file `Close` (the cancel in
        // `try_finalize_close` is best-effort and is dropped when the SQ is
        // full), so its terminal `-ECONNRESET` can land after the index has been
        // handed to a new connection. `recv_multishot_armed` cannot tell the two
        // apart — it is per-slot, and `arm_recv` sets it again for the new
        // occupant. The arm-time generation, carried whole in the payload, can.
        // See `docs/recv-multi-identity-design.md`.
        if self.driver.connections.get(conn_index).is_none()
            || self.driver.connections.generation(conn_index) != ud.payload()
        {
            // Connection already released, or the slot has been reused — but if
            // result > 0, the kernel consumed a provided buffer that must be
            // replenished. Exactly once: this early return is the only branch
            // that can see this bid.
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                self.driver.provided_bufs.on_handout();
                self.driver.pending_replenish.push(bid);
            }
            return;
        }

        if result > 0 {
            self.withdraw_park_offer(conn_index);
        }

        // A completion without `IORING_CQE_F_MORE` means the kernel terminated
        // this multishot recv. Record that the recv is no longer armed so the
        // close path knows it need not cancel it (a re-arm below sets it back).
        if !has_more && let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = false;
        }

        if result <= 0 {
            if result == 0 {
                // TCP FIN. For a TLS connection this is only a clean EOF if
                // the peer's close_notify was processed first — otherwise
                // it's a truncation (possibly an attacker-injected FIN) and
                // recv futures must surface UnexpectedEof, not clean EOF.
                let close_notify_seen = self
                    .driver
                    .tls_table
                    .as_mut()
                    .and_then(|t| t.get_mut(conn_index))
                    .map(|tc| tc.peer_sent_close_notify);
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.note_eof(close_notify_seen == Some(false));
                }
                // Wake recv waiter before closing so the owning task can
                // detect EOF (with_data will see `recv_finished()` and return 0).
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
            let errno = -result;
            if errno == libc::ENOBUFS {
                metrics::POOL.increment(metrics::pool::BUFFER_RING_EMPTY);
                // Park until buffers return to the provided ring (see
                // flush_replenish_and_rearm). Re-arming immediately
                // completed with ENOBUFS again while data was pending and
                // the ring was empty — submit_and_wait(1) never blocked and
                // the worker spun at 100% CPU until a task freed a bid.
                if !has_more && !self.driver.recv_starved.contains(&conn_index) {
                    self.driver.recv_starved.push(conn_index);
                    self.driver.recv_park_count += 1;
                    metrics::POOL.increment(metrics::pool::RECV_PARKED);
                }
            } else if errno == libc::ECANCELED {
                // A cancel terminated the multishot. Whatever was armed is gone
                // now, `IORING_CQE_F_MORE` or not: a cancel posts `-ECANCELED`
                // only for a request it actually found live, and at most one
                // multishot recv per (connection, generation) is ever live, so
                // this CQE belongs to the current arming even when the flag
                // says the request continues. Trusting the flag left the
                // connection marked armed against a multishot the kernel had
                // already killed — no data ever arrived again, and every
                // re-arm path declined because it looked armed.
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.recv_multishot_armed = false;
                }
                // If this connection was throttled by the Mode A hold cap, this
                // is the ECANCELED for that throttle-cancel: re-arm now if the
                // hold has already drained below the cap (otherwise a later
                // write completion will).
                self.maybe_rearm_throttled_forward(conn_index);
                // The cancel may also have landed on a *different* multishot
                // than the one it was aimed at: it matches by user_data, and a
                // throttled recv that terminated on its own (`!has_more`) is
                // re-armed with that same user_data as soon as the forward
                // settles — before the kernel gets to the queued cancel. The
                // connection is no longer throttled by then, so neither this
                // branch's re-arm nor the one at the end of the handler (which
                // this `return` skips) would fire, and the connection sat
                // `Open`/`Multi` with no recv armed and its bytes piling up in
                // the accumulator, forever.
                self.rearm_multishot_if_idle(conn_index);
                return;
            } else if !has_more {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.read = ReadHalf::Error;
                }
                let generation = self.driver.connections.generation(conn_index);
                self.executor.fail_recv(
                    conn_index,
                    generation,
                    io::Error::from_raw_os_error(errno),
                );
                self.driver.close_connection(conn_index);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(bid) => bid,
            None => {
                // No buffer selected despite result > 0 — should not happen.
                // Close the connection to prevent a silent hang (no recv armed).
                if !has_more {
                    self.executor.wake_recv(conn_index);
                    self.driver.close_connection(conn_index);
                }
                return;
            }
        };

        self.driver.provided_bufs.on_handout();
        let bytes_received = result as u32;
        metrics::BYTES.add(metrics::bytes::RECEIVED, bytes_received as u64);
        let (buf_ptr, _) = self.driver.provided_bufs.get_buffer(bid);
        let data = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_received as usize) };

        // NOTE: bid is NOT unconditionally pushed to pending_replenish here.
        // The zero-copy recv path defers replenishment until the task consumes
        // the data. Each branch below is responsible for either pushing the bid
        // to pending_replenish or storing it in a pending_recv_bufs slot.

        // TLS path
        let is_tls_conn = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has(conn_index));

        if is_tls_conn {
            // The ciphertext bid is replenished immediately (TLS decrypts into
            // rustls's own buffer, so the provided buffer is free at feed time);
            // TLS segments never pin the ring.
            self.driver.pending_replenish.push(bid);
            {
                // Route decrypted plaintext by recv domain. In the segmented
                // domain, each drained plaintext chunk becomes an owned segment
                // pushed to this connection's hold (copy-per-chunk — rustls owns
                // the plaintext, so TLS recv can never be zero-copy; see
                // `docs/segmented-recv-design.md`, "## TLS"). Otherwise it lands
                // in the recv accumulator (the default with_data/with_bytes path).
                let is_segmented = self.driver.recv_domain[conn_index as usize]
                    == crate::recv::domain::RecvDomain::Segmented;
                let recv_accumulator_max = self.driver.recv_accumulator_max;
                let tls_table = self.driver.tls_table.as_mut().unwrap();
                let sink = if is_segmented {
                    // Bound total outstanding held plaintext exactly as the
                    // accumulator path bounds its buffer (recv_accumulator_max):
                    // an unbounded plaintext flood must still kill the connection.
                    // TLS holds are always `Owned`, but sum defensively.
                    let hold = &mut self.driver.segment_hold[conn_index as usize];
                    let outstanding: usize = hold
                        .iter()
                        .map(|h| match h {
                            crate::backend::HeldRecvBuf::Owned(b) => b.len(),
                            crate::backend::HeldRecvBuf::Pinned { len, .. } => *len as usize,
                        })
                        .sum();
                    crate::tls::PlaintextSink::Segments {
                        hold,
                        outstanding,
                        max: recv_accumulator_max,
                    }
                } else {
                    crate::tls::PlaintextSink::Accumulator(&mut self.driver.accumulators)
                };
                let result = crate::tls::feed_tls_recv(
                    tls_table,
                    sink,
                    &mut self.driver.send_copy_pool,
                    conn_index,
                    self.driver.connections.generation(conn_index),
                    data,
                    &mut self.driver.tls_out_scratch,
                );

                // Route collected TLS output (handshake responses, alerts)
                // through the per-connection send queue — including on the
                // Error path, where an alert should still go out before the
                // close below.
                if !self.driver.tls_out_scratch.is_empty() {
                    let mut sends = std::mem::take(&mut self.driver.tls_out_scratch);
                    self.driver.queue_built_sends(conn_index, &mut sends);
                    self.driver.tls_out_scratch = sends;
                }

                match result {
                    crate::tls::TlsRecvResult::HandshakeJustCompleted => {
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
                    }
                    crate::tls::TlsRecvResult::Ok => {
                        self.executor.wake_recv(conn_index);
                    }
                    crate::tls::TlsRecvResult::Error(e) => {
                        // Wake connect waiter if handshake hasn't completed yet.
                        let established = self
                            .driver
                            .connections
                            .get(conn_index)
                            .map(|c| c.established)
                            .unwrap_or(false);
                        if !established {
                            let err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, e);
                            self.executor.wake_connect(conn_index, Err(err));
                        }
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                    }
                    crate::tls::TlsRecvResult::Closed => {
                        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                            cs.note_eof(false);
                        }
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                    }
                }
            }
        } else if self.driver.recv_domain[conn_index as usize]
            == crate::recv::domain::RecvDomain::Segmented
        {
            // Segmented delivery (Mode B/C). Consult the aggregate low-water
            // reserve on the shared per-worker recv ring (see
            // `docs/segmented-recv-design.md`, "Backpressure and ring safety").
            // `on_handout()` above already counted this bid, so `free()` reflects
            // this delivery.
            let reserve = self.driver.recv_segment_reserve;
            let free = self.driver.provided_bufs.free();
            match crate::recv::occupancy::delivery_decision(free, reserve) {
                crate::recv::occupancy::Delivery::ZeroCopyOk => {
                    // Above the reserve: hold the provided buffer in-place (bid
                    // NOT replenished, no accumulator copy) for a future segment
                    // reader. The buffer stays pinned until the reader or
                    // `close_connection` drains the hold. Backpressure is natural
                    // — unreplenished bids deplete the ring (ENOBUFS) until a
                    // reader releases them, exactly like the recv-forward hold.
                    self.driver.segment_hold[conn_index as usize].push_back(
                        crate::backend::HeldRecvBuf::Pinned {
                            bid,
                            len: bytes_received,
                        },
                    );
                }
                crate::recv::occupancy::Delivery::ForceCopy => {
                    // At/below the reserve: copy the bytes into an owned `Bytes`
                    // and replenish the bid IMMEDIATELY so the ring recovers and
                    // holders cannot deplete it. `on_handout()` counted the bid at
                    // buffer_select; this replenish balances it (net-zero pin), so
                    // the outstanding/free accounting stays consistent. INC
                    // ordering: copy before replenish, no await between.
                    let owned = bytes::Bytes::copy_from_slice(data);
                    self.driver.segment_hold[conn_index as usize]
                        .push_back(crate::backend::HeldRecvBuf::Owned(owned));
                    self.driver.pending_replenish.push(bid);
                }
            }
            // Mode A hold cap (see `docs/segmented-recv-design.md`, "Mode A"). A
            // `forward_to` connection whose held-buffer backlog reaches
            // `forward_hold_cap` (a slow/high-latency sink, or a very large
            // object) would otherwise pin much of the shared per-worker ring (and
            // grow heap when the reserve force-copies), starving other
            // connections. Throttle it: cancel its multishot recv so its TCP
            // receive window closes and the source stops sending. The recv is
            // re-armed once writes drain the hold below the cap
            // (`maybe_rearm_throttled_forward`). Applies only to forwarders
            // (`forward_recv_active`), not pure Mode B segment readers.
            let ci = conn_index as usize;
            if self.driver.forward_recv_active[ci]
                && !self.driver.forward_hold_throttled[ci]
                && self.driver.segment_hold[ci].len() >= self.driver.forward_hold_cap
            {
                self.driver.forward_hold_throttled[ci] = true;
                // Only cancel a still-armed multishot. If this CQE terminated the
                // multishot (`!has_more` cleared `recv_multishot_armed` at the top
                // of the handler), there is nothing to cancel — the re-arm gate
                // below (`!has_more`) already skips re-arming a throttled conn.
                let armed = self
                    .driver
                    .connections
                    .get(conn_index)
                    .is_some_and(|c| c.recv_multishot_armed);
                if armed {
                    // Cancel by the RecvMulti user_data (targets the request, not
                    // the fd — immune to reordering). `recv_multishot_armed` stays
                    // set until the ECANCELED CQE clears it (top of the handler),
                    // which gates re-arm so two multishots with the same user_data
                    // never overlap. The payload must reproduce the arm-time
                    // generation or the cancel matches nothing.
                    let recv_ud = UserData::encode(
                        OpTag::RecvMulti,
                        conn_index,
                        self.driver.connections.generation(conn_index),
                    );
                    let _ = self
                        .driver
                        .ring
                        .submit_async_cancel(recv_ud.raw(), conn_index);
                    metrics::POOL.increment(metrics::pool::FORWARD_THROTTLED);
                }
            }
            // A forwarder can submit its write straight from here; only a
            // Mode B/C segment reader needs its task woken to look at the hold.
            if self.driver.forward_progress[conn_index as usize].is_some() {
                self.finish_forward_if_done(conn_index);
            } else {
                self.executor.wake_recv(conn_index);
            }
        } else if self.driver.recv_forward[conn_index as usize] {
            // Zero-copy recv-forward path: hold the provided buffer in-place
            // (bid NOT replenished) for scatter-gather forwarding via
            // `forward_held`. No accumulator copy. Backpressure is natural —
            // unreplenished bids deplete the ring (ENOBUFS) until a forward
            // completes. The hold is drained on close (see close_connection).
            self.driver.recv_hold[conn_index as usize].push_back(crate::backend::PendingRecvBuf {
                bid,
                len: bytes_received,
                ptr: buf_ptr,
            });
            self.executor.wake_recv(conn_index);
        } else {
            // Direct echo fast path: submit the echo SQE directly from the CQE
            // handler, bypassing task wakeup entirely. This eliminates the
            // collect_wakeups → poll_ready_tasks roundtrip (~1 full event-loop
            // iteration of latency) on the hot single-connection echo path.
            let is_direct_echo = self
                .driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.direct_echo);

            if is_direct_echo {
                // Stage the buffer rather than submitting a Send for it now.
                // The flush pass at the end of this drain gathers everything
                // that arrived in the batch into one operation, so a message
                // spanning several recv completions echoes as one message
                // instead of one segment per completion (#397).
                self.driver.hold_direct_echo(
                    conn_index,
                    crate::backend::PendingRecvBuf {
                        bid,
                        len: bytes_received,
                        ptr: buf_ptr,
                    },
                );
                // Do NOT call wake_recv here. DirectEchoFuture only needs to
                // be woken on connection close (handled by the result <= 0 path
                // above), not on every incoming buffer.
            } else {
                // Plaintext path: route through recv sink if active, else zero-copy/accumulator.
                if let Some(sink) = &mut self.executor.recv_sinks[conn_index as usize] {
                    self.driver.pending_replenish.push(bid);
                    let remaining_cap = sink.cap - sink.pos;
                    let to_sink = data.len().min(remaining_cap);
                    if to_sink > 0 {
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                data.as_ptr(),
                                sink.ptr.add(sink.pos),
                                to_sink,
                            );
                        }
                        sink.pos += to_sink;
                    }
                    // Overflow (trailing CRLF, next commands) goes to accumulator.
                    if to_sink < data.len()
                        && !self
                            .driver
                            .accumulators
                            .append(conn_index, &data[to_sink..])
                    {
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                        return;
                    }
                } else {
                    // Zero-copy fast path: if no pending buffer AND accumulator is
                    // empty, hold the kernel buffer in-place instead of copying.
                    // NOTE: must be the non-merging `is_empty` — `data()` here
                    // would merge a held frozen remainder on every recv CQE,
                    // a full-remainder copy per chunk while a large response
                    // streams in (O(N·K)).
                    let acc_empty = self.driver.accumulators.is_empty(conn_index);
                    let slot = &mut self.driver.pending_recv_bufs[conn_index as usize];

                    if acc_empty && slot.is_none() {
                        *slot = Some(crate::backend::PendingRecvBuf {
                            bid,
                            len: bytes_received,
                            ptr: buf_ptr,
                        });
                    } else {
                        // Flush any existing pending buffer to accumulator first.
                        let mut accumulator_overflowed = false;
                        if let Some(pending) = slot.take() {
                            let pending_data = unsafe {
                                std::slice::from_raw_parts(pending.ptr, pending.len as usize)
                            };
                            if !self.driver.accumulators.append(conn_index, pending_data) {
                                accumulator_overflowed = true;
                            }
                            self.driver.pending_replenish.push(pending.bid);
                        }
                        if !accumulator_overflowed
                            && !self.driver.accumulators.append(conn_index, data)
                        {
                            accumulator_overflowed = true;
                        }
                        self.driver.pending_replenish.push(bid);
                        if accumulator_overflowed {
                            // Handler kept returning NeedMore while the peer
                            // streamed past `recv_accumulator_max`. Close the
                            // connection rather than OOM the worker.
                            self.executor.wake_recv(conn_index);
                            self.driver.close_connection(conn_index);
                            return;
                        }
                    }
                }
                self.executor.wake_recv(conn_index);
            }
        }

        if !has_more
            && !self.driver.forward_hold_throttled[conn_index as usize]
            && let Some(conn) = self.driver.connections.get(conn_index)
            && matches!(conn.lifecycle, Lifecycle::Open)
            && matches!(conn.recv_arm, RecvArm::Multi)
        {
            let generation = self.driver.connections.generation(conn_index);
            if self
                .driver
                .ring
                .submit_multishot_recv(conn_index, generation)
                .is_err()
            {
                metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
            } else if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_multishot_armed = true;
            }
        }
    }

    /// Handle a RecvMsgMulti CQE (multishot recvmsg with SO_TIMESTAMPING).
    ///
    /// The provided buffer contains an `io_uring_recvmsg_out` header followed by
    /// name (0 bytes for TCP), control data (cmsg with SCM_TIMESTAMPING), and
    /// the TCP payload.
    #[cfg(feature = "timestamps")]
    fn handle_recv_msg_multi_ts(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let has_more = cqueue::more(flags);

        // Identity check — same reasoning as `handle_recv_multi`: the slot must
        // still be occupied by the connection this recvmsg was armed for, or the
        // completion belongs to a previous occupant of a reused index.
        if self.driver.connections.get(conn_index).is_none()
            || self.driver.connections.generation(conn_index) != ud.payload()
        {
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                self.driver.provided_bufs.on_handout();
                self.driver.pending_replenish.push(bid);
            }
            return;
        }

        if result <= 0 {
            if result == 0 {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.note_eof(false);
                }
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
            let errno = -result;
            if errno == libc::ENOBUFS {
                metrics::POOL.increment(metrics::pool::BUFFER_RING_EMPTY);
                if !has_more {
                    let generation = self.driver.connections.generation(conn_index);
                    let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
                    let _ = self
                        .driver
                        .ring
                        .submit_multishot_recvmsg(conn_index, generation, msghdr_ptr);
                }
            } else if errno == libc::ECANCELED {
                return;
            } else if !has_more {
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.read = ReadHalf::Error;
                }
                let generation = self.driver.connections.generation(conn_index);
                self.executor.fail_recv(
                    conn_index,
                    generation,
                    io::Error::from_raw_os_error(errno),
                );
                self.driver.close_connection(conn_index);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(bid) => bid,
            None => {
                if !has_more {
                    self.executor.wake_recv(conn_index);
                    self.driver.close_connection(conn_index);
                }
                return;
            }
        };

        // Same rule as the multishot and fallback paths: bytes are about to be
        // delivered, so any park offer is stale (#443 tier 3).
        self.withdraw_park_offer(conn_index);

        self.driver.provided_bufs.on_handout();
        let buf_len = result as u32;
        let (buf_ptr, _) = self.driver.provided_bufs.get_buffer(bid);
        let buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len as usize) };

        self.driver.pending_replenish.push(bid);

        // Parse the io_uring_recvmsg_out header to extract control data + payload.
        let msg_out = match io_uring::types::RecvMsgOut::parse(buf, &self.driver.recvmsg_msghdr) {
            Ok(out) => out,
            Err(()) => {
                // Parse failed — treat as regular data (shouldn't happen).
                return;
            }
        };

        let payload = msg_out.payload_data();
        if payload.is_empty() {
            // EOF via recvmsg.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.note_eof(false);
            }
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
            return;
        }

        metrics::BYTES.add(metrics::bytes::RECEIVED, payload.len() as u64);

        // Extract SCM_TIMESTAMPING from control data.
        let control = msg_out.control_data();
        if let Some(ts_ns) = Self::parse_scm_timestamp(control)
            && let Some(cs) = self.driver.connections.get_mut(conn_index)
        {
            cs.recv_timestamp_ns = ts_ns;
        }

        // Route payload through accumulator (same as plaintext RecvMulti path).
        if let Some(sink) = &mut self.executor.recv_sinks[conn_index as usize] {
            let remaining_cap = sink.cap - sink.pos;
            let to_sink = payload.len().min(remaining_cap);
            if to_sink > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        sink.ptr.add(sink.pos),
                        to_sink,
                    );
                }
                sink.pos += to_sink;
            }
            if to_sink < payload.len()
                && !self
                    .driver
                    .accumulators
                    .append(conn_index, &payload[to_sink..])
            {
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
        } else if !self.driver.accumulators.append(conn_index, payload) {
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
            return;
        }
        self.executor.wake_recv(conn_index);

        if !has_more
            && let Some(conn) = self.driver.connections.get(conn_index)
            && matches!(conn.lifecycle, Lifecycle::Open)
            && matches!(conn.recv_arm, RecvArm::MsgMulti)
        {
            let generation = self.driver.connections.generation(conn_index);
            let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
            let _ = self
                .driver
                .ring
                .submit_multishot_recvmsg(conn_index, generation, msghdr_ptr);
        }
    }

    /// Parse SCM_TIMESTAMPING from cmsg control data.
    /// Returns the software RX timestamp as nanoseconds since epoch, or None.
    #[cfg(feature = "timestamps")]
    fn parse_scm_timestamp(control: &[u8]) -> Option<u64> {
        // cmsg layout: cmsghdr { cmsg_len (usize), cmsg_level (i32), cmsg_type (i32) }
        // followed by payload data, then padding to align next cmsghdr.
        let hdr_size = std::mem::size_of::<libc::cmsghdr>();
        let align = std::mem::align_of::<libc::cmsghdr>();
        let mut offset = 0usize;

        while offset + hdr_size <= control.len() {
            // Safety: read_unaligned handles the case where control is not
            // aligned to cmsghdr's alignment requirement.
            let hdr_ptr = control[offset..].as_ptr() as *const libc::cmsghdr;
            let hdr = unsafe { std::ptr::read_unaligned(hdr_ptr) };

            if hdr.cmsg_len < hdr_size {
                break;
            }

            let data_offset = offset + hdr_size;
            let data_len = hdr.cmsg_len - hdr_size;

            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SO_TIMESTAMPING {
                // Payload is 3 × struct timespec: [software, hw_transformed, hw_raw].
                // We want the software timestamp (index 0).
                let ts_size = std::mem::size_of::<libc::timespec>();
                if data_len >= ts_size && data_offset + ts_size <= control.len() {
                    let ts_ptr = control[data_offset..].as_ptr() as *const libc::timespec;
                    let ts = unsafe { std::ptr::read_unaligned(ts_ptr) };
                    if ts.tv_sec != 0 || ts.tv_nsec != 0 {
                        return Some(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64);
                    }
                }
            }

            // Advance to next cmsg (aligned).
            let next = offset + ((hdr.cmsg_len + align - 1) & !(align - 1));
            if next <= offset {
                break;
            }
            offset = next;
        }

        None
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
                Err(crossbeam_channel::TrySendError::Full(p)) => retry.push(p),
                // Target gone: nothing to retry onto.
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {}
            }
        }
        self.driver.park_ready = retry;
    }

    /// Adopt connections other workers parked onto this one.
    ///
    /// The parking worker cancelled its multishot recv before recovering the
    /// fd — linked ahead of the install, so the cancel is guaranteed to have
    /// run by the time the entry reached its channel. That is what makes it
    /// safe to arm a recv here: no other worker is still reading this socket.
    fn drain_adopted(&mut self) {
        let Some(rx) = self.driver.park_rx.clone() else {
            return;
        };
        while let Ok(parked) = rx.try_recv() {
            let crate::park::ParkedFd {
                fd,
                listener,
                peer,
                pending,
                state,
                ..
            } = parked;
            // `install_accepted_with_pending` registers the fd and closes this
            // handle, exactly as it does for a freshly accepted one.
            let raw = std::os::fd::IntoRawFd::into_raw_fd(fd);
            metrics::CONNECTIONS.increment(metrics::conn::ADOPTED);
            self.install_accepted_with_pending(raw, listener, peer, pending, Some(state));
        }
    }

    /// Withdraw a park offer because bytes arrived (tier 3, #443).
    ///
    /// Arriving bytes mean a new request has begun, so the quiescent point the
    /// handler offered at is gone. This is what makes `offer_for_park` a
    /// one-shot: the handler offers once when idle and never has to remember
    /// to revoke.
    ///
    /// **Every path that delivers bytes to a connection must call this**, and
    /// missing one is not hypothetical — the fallback and timestamped recv
    /// paths both did. `park_blocker` carries a state-based backstop
    /// (`ParkBlocker::DataPending`) for exactly that reason, so a path added
    /// later fails closed rather than parking mid-request.
    fn withdraw_park_offer(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        // Read first: the common case is no offer, and a predictable branch
        // beats two stores on every delivery.
        if self.driver.park_offered.get(idx).copied().unwrap_or(false) {
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
        let generation = self.driver.connections.generation(conn_index);

        // Cancel the armed multishot recv *ahead of* the install, linked, so
        // the kernel orders them. A recv left armed here would keep draining a
        // socket that now belongs to another worker.
        let cancel_target = self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.recv_multishot_armed)
            .then(|| {
                crate::completion::UserData::encode(
                    crate::completion::OpTag::RecvMulti,
                    conn_index,
                    generation,
                )
                .raw()
            });

        if self
            .driver
            .ring
            .submit_park_install(conn_index, generation, cancel_target)
            .is_err()
        {
            // SQ pressure is backpressure, not failure (Domain Invariant 7).
            return false;
        }
        metrics::CONNECTIONS.increment(metrics::conn::PARK_STARTED);
        self.driver.park_in_flight[conn_index as usize] =
            Some(crate::backend::uring::driver::ParkInFlight { target, generation });
        true
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
        let Some(in_flight) = self.driver.park_in_flight[conn_index as usize].take() else {
            // No park outstanding: a stray or duplicated CQE. Still close the
            // fd, or the socket reference leaks.
            if result >= 0 {
                unsafe { libc::close(result) };
            }
            return;
        };

        // A failed install, or an `ECANCELED` from the linked recv-cancel
        // failing (the recv self-terminated first). Neither is an error —
        // park is best-effort and policy can try again later.
        if result < 0 {
            return;
        }
        // SAFETY: a non-negative `FixedFdInstall` result is a fresh fd owned
        // by this process; nothing else holds it.
        let fd = {
            use std::os::fd::FromRawFd;
            unsafe { std::os::fd::OwnedFd::from_raw_fd(result) }
        };

        // The slot may have been recycled while the install was in flight.
        // Checked against the arm-time generation carried in the payload,
        // like every other completion handler (Domain Invariant 3); the copy
        // in `in_flight` is only there to carry the target.
        if self.driver.connections.generation(conn_index) != ud.payload()
            || ud.payload() != in_flight.generation
        {
            return; // `fd` drops, closing this reference.
        }
        // Quiesce can have broken across the round trip.
        if !self.driver.is_parkable(conn_index) {
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

        // Ordinary teardown. It closes the fixed-file entry and drops the
        // handler future, but does *not* FIN: `fd` above is a second
        // reference keeping the socket open. A connection with a pending
        // shutdown could not have passed the gate, so no FIN is queued.
        self.driver.close_connection(conn_index);

        metrics::CONNECTIONS.increment(metrics::conn::PARK_COMPLETED);
        self.driver.park_ready.push(crate::park::ParkedFd {
            fd,
            listener,
            peer,
            pending,
            state,
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
    /// Seeded *before* `arm_recv`, so a handler polled on this worker sees the
    /// carried bytes ahead of anything the new recv delivers. Appending after
    /// would put freshly received bytes in front of older ones and silently
    /// reorder the peer's stream.
    fn install_accepted_with_pending(
        &mut self,
        raw_fd: std::os::fd::RawFd,
        listener: crate::ListenerId,
        peer_addr: crate::connection::PeerAddr,
        pending: Vec<bytes::Bytes>,
        // `adopt` is `Some` when this install is an adopt; the inner value is
        // what the handler deposited. Recorded per connection so the TLS
        // branch's deferred spawn still finds it.
        adopt: Option<Option<crate::park::ParkState>>,
    ) {
        let conn_index = match self.driver.connections.allocate() {
            Some(idx) => idx,
            None => {
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
            self.driver.connections.release(conn_index);
            unsafe {
                libc::close(raw_fd);
            }
            return;
        }
        unsafe {
            libc::close(raw_fd);
        }

        if let Some(pending) = self.driver.pending_recv_bufs[conn_index as usize].take() {
            self.driver.pending_replenish.push(pending.bid);
        }
        self.driver.accumulators.reset(conn_index);
        self.driver.reset_segment_state(conn_index);
        self.driver.reset_send_state(conn_index);
        // A slot is recycled by generation, so without this a new occupant
        // would inherit the previous one's park offer — and its state.
        self.driver.park_offered[conn_index as usize] = false;
        self.driver.park_carry.remove(&conn_index);
        match adopt {
            Some(state) => {
                self.driver.adopt_pending.insert(conn_index, state);
            }
            None => {
                self.driver.adopt_pending.remove(&conn_index);
            }
        }
        for chunk in &pending {
            self.driver.accumulators.append(conn_index, chunk);
        }
        self.arm_recv(conn_index);

        // TLS path: defer accept until handshake completes.
        if let Some(ref mut tls_table) = self.driver.tls_table
            && tls_table.has_server_config_for(Some(listener))
        {
            if tls_table.create(conn_index, Some(listener)).is_err() {
                self.driver.close_connection(conn_index);
            }
            return;
        }

        // Plaintext path: mark established and spawn async task.
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.established = true;
        }
        metrics::CONNECTIONS.increment(metrics::conn::ACCEPTED);
        metrics::CONNECTIONS_ACTIVE.increment();
        self.spawn_accept_task(conn_index);
    }

    /// Arm this worker's multishot accepts, once `launch()` has listened.
    ///
    /// Cheap to call every iteration: it is a relaxed load and an early return
    /// after the first arm.
    fn arm_merged_accepts(&mut self) {
        if self.driver.merged_accept_armed || self.driver.merged_accept_fds.is_empty() {
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
        let fds = self.driver.merged_accept_fds.clone();
        for (listener_index, fd) in fds {
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
        match tx.try_send(crate::acceptor::AcceptedConn {
            fd: raw_fd,
            listener,
            peer: peer_addr.clone(),
        }) {
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
            Err(_) => Err((raw_fd, peer_addr)),
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
            // ECANCELED/EBADF/EINVAL are the shapes shutdown takes: the
            // listener was closed under us. Anything else is worth re-arming
            // for, since losing the arm silently stops the worker accepting.
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
            crate::acceptor::apply_accepted_sockopts(
                raw_fd,
                self.driver.tcp_nodelay,
                #[cfg(feature = "timestamps")]
                self.driver.timestamps,
            );
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
                    fd: raw_fd,
                    listener,
                    peer: peer_addr,
                }) = item
                else {
                    break;
                };
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
                self.executor
                    .deliver_blocking(response.request_id, response.result);
            }
        }

        // on_notify (synchronous). Set the executor's driver_state
        // thread-local so user code that calls `ringline::spawn()` /
        // wakers / `with_state` works from inside the handler. Raw
        // pointers dodge the borrow conflict with `make_ctx()`.
        {
            let handler = &mut self.handler;
            let driver_ptr = &mut self.driver as *mut Driver;
            let executor_ptr = &mut self.executor as *mut crate::runtime::Executor;
            let mut driver_state = DriverState {
                driver: unsafe { NonNull::new_unchecked(driver_ptr) },
                executor: unsafe { NonNull::new_unchecked(executor_ptr) },
            };
            let guard = unsafe { set_driver_state_guarded(&mut driver_state) };
            {
                let mut ctx = unsafe { (*driver_ptr).make_ctx() };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handler.on_notify(&mut ctx);
                }));
                if result.is_err() {
                    eprintln!("ringline: handler on_notify panicked; continuing");
                }
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
            // The slot may still name a bounded send, and `release`
            // debug-asserts rather than drop a live id — so take it. It is
            // deliberately *not* settled: this completion belongs to the
            // connection the CQE outlived, and `Executor::remove_connection`
            // already recorded a provisional `Aborted` for that operation
            // when the connection went away. Per #381 a driver result
            // overrides that abort, which is exactly what must not happen
            // here — the result describes a dead occupant's send.
            let _ = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            return;
        }

        // Chain path.
        if self.driver.chain_table.is_active(conn_index) {
            // A chain's SQEs are tagged `OpTag::Send` and bypass the send
            // queue, so while one is active this branch claims *every* Send
            // CQE on the connection — including one belonging to a bounded
            // send submitted alongside it. That aliasing predates this PR and
            // is not fixed here, but the id must not be dropped on the floor:
            // take it (or `release` trips) and report this CQE's own outcome.
            let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            if let Some((id, logical_len)) = bounded {
                let settled = if result > 0 {
                    Ok(logical_len)
                } else {
                    Err(Self::bounded_send_error(result))
                };
                self.settle_bounded(id, settled);
            }
            let event = self.driver.chain_table.on_operation_cqe(conn_index, result);
            if matches!(event, ChainEvent::Complete { .. }) {
                self.fire_chain_complete(conn_index);
            }
            return;
        }

        if result > 0 {
            if let Some((ptr, remaining)) = self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
            {
                if self.close_submitted(conn_index) {
                    let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                    self.release_pool_slot(pool_slot);
                    if let Some((id, _logical_len)) = bounded {
                        self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    self.executor.wake_send(
                        conn_index,
                        Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                    );
                    return;
                }
                let generation = self.driver.connections.generation(conn_index);
                if self
                    .driver
                    .ring
                    .submit_send_copied(conn_index, generation, ptr, remaining, pool_slot)
                    .is_err()
                {
                    // SQ full — queue for retry on next tick.
                    self.driver.pending_copy_retries.push((
                        conn_index,
                        generation,
                        pool_slot,
                        0,
                        OpTag::Send,
                    ));
                }
                return;
            }
            let total = self.driver.send_copy_pool.original_len(pool_slot);
            // Read the end-of-send flag before releasing the slot — and, for
            // the same reason, take the bounded send that slot settles: the
            // slot is about to be recycled, and `release` debug-asserts
            // rather than let a live id go with it.
            let end_of_send = self.driver.send_copy_pool.is_end_of_send(pool_slot);
            let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            self.release_pool_slot(pool_slot);

            // Accumulate this chunk's bytes against the logical send.
            self.driver.send_queues[conn_index as usize].acked_bytes += total;

            // Pop the next queued send (if any) into the kernel,
            // *then* check whether a deferred close should fire —
            // submit_next_queued may have just emptied the queue and
            // cleared `in_flight`, which is exactly when a
            // close_pending connection is ready to actually close.
            self.driver.submit_next_queued(conn_index);
            self.driver.note_send_finalized(conn_index);

            // A bounded send reports the *logical* (plaintext) length it was
            // handed, never `acked`: `acked` counts wire bytes, which differ
            // from the caller's length under TLS and would be exactly the
            // truncated count the design forbids. Only an end-of-send slot
            // ever carries an id, but the settle sits outside that branch so
            // that a stray one still cannot be lost.
            if let Some((id, logical_len)) = bounded {
                self.settle_bounded(id, Ok(logical_len));
            }

            // Wake the send waiter once, when this logical send's final chunk
            // completes, reporting its whole byte count. Intermediate chunks of
            // a multi-slot send only accumulate; waking on one would report a
            // short count, and pipelined independent sends share this queue so
            // waking on queue-drain would wake the wrong future.
            if end_of_send {
                let acked =
                    std::mem::take(&mut self.driver.send_queues[conn_index as usize].acked_bytes);
                self.executor.wake_send(conn_index, Ok(acked));
            }
            return;
        }

        // `EAGAIN` / `EWOULDBLOCK` from the kernel means the socket
        // send buffer is full and we'd block. The right response is to
        // wait for `POLLOUT` and resubmit the same data — the pool
        // slot still holds the unsent bytes via
        // `current_ptr_remaining`. Don't release the slot, don't drain
        // the queue, don't wake the send waiter.
        let errno = -result;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            if self.close_submitted(conn_index) {
                let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                self.release_pool_slot(pool_slot);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                self.executor.wake_send(
                    conn_index,
                    Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                );
                return;
            }
            let generation = self.driver.connections.generation(conn_index);
            if self
                .driver
                .ring
                .submit_send_pollout(conn_index, generation, pool_slot, false)
                .is_err()
            {
                // SQ full now — queue for retry on the next tick.
                self.driver
                    .pending_send_pollout_retries
                    .push((conn_index, generation, pool_slot, 0, false));
            }
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
        self.release_pool_slot(pool_slot);
        self.driver.drain_conn_send_queue(conn_index);
        self.driver.note_send_finalized(conn_index);

        let io_result = if result == 0 {
            Ok(0u32)
        } else {
            Err(io::Error::from_raw_os_error(-result))
        };
        if let Some((id, _logical_len)) = bounded {
            self.settle_bounded(id, Err(Self::bounded_send_error(result)));
        }
        self.executor.wake_send(conn_index, io_result);
    }

    /// Handle a `POLLOUT` CQE armed after a `Send` returned `-EAGAIN`.
    ///
    /// Resubmits the same send using `current_ptr_remaining(pool_slot)`,
    /// which still points at the unsent bytes inside the same pool slot
    /// we kept alive across the EAGAIN. If the resubmit also fails to
    /// land (SQ full), pushes onto `pending_copy_retries` so the next
    /// tick picks it up.
    fn handle_send_pollout(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        // Payload: pool_slot in the low 16 bits, is_tls flag in bit 16 (the
        // resubmit must keep a TLS chunk on the TlsSend completion path),
        // truncated connection generation in bits 17..31.
        let payload = ud.payload();
        let pool_slot = UserData::send_payload_slot(payload);
        let is_tls = UserData::send_pollout_is_tls(payload);

        // Liveness: released on a pre-submission error path — nothing to do.
        if !self.driver.send_copy_pool.in_use(pool_slot) {
            return;
        }
        // Identity: the connection may have been closed (and its index
        // reused) while we were waiting for POLLOUT. The slot is still owned
        // by the orphaned send — release it and touch nothing else, exactly
        // as `handle_send` does on generation mismatch.
        if self.driver.connections.generation(conn_index) & 0x7FFF
            != u32::from(UserData::send_pollout_gen(payload))
        {
            // Take-and-discard, exactly as in `handle_send`'s identity
            // guard: the id must leave the slot so `release` does not trip,
            // and it must not be settled, because teardown already aborted
            // the dead occupant's operation and a driver result would
            // override that abort (#381).
            let _ = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            return;
        }

        // Poll itself failed (e.g. fd closed unexpectedly). Treat
        // the same as a generic send failure: drop everything for
        // this connection.
        if result < 0 {
            let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            self.driver.drain_conn_send_queue(conn_index);
            self.driver.note_send_finalized(conn_index);
            if let Some((id, _logical_len)) = bounded {
                self.settle_bounded(id, Err(io::Error::from_raw_os_error(-result)));
            }
            self.executor
                .wake_send(conn_index, Err(io::Error::from_raw_os_error(-result)));
            return;
        }

        if self.close_submitted(conn_index) {
            let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            if let Some((id, _logical_len)) = bounded {
                self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
            }
            self.executor.wake_send(
                conn_index,
                Err(io::Error::from_raw_os_error(libc::ECANCELED)),
            );
            return;
        }
        let (ptr, remaining) = self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
        let generation = self.driver.connections.generation(conn_index);
        let resubmit = if is_tls {
            self.driver
                .ring
                .submit_tls_send(conn_index, generation, ptr, remaining, pool_slot)
        } else {
            self.driver
                .ring
                .submit_send_copied(conn_index, generation, ptr, remaining, pool_slot)
        };
        if resubmit.is_err() {
            // SQ full — pick up on the next tick.
            let tag = if is_tls { OpTag::TlsSend } else { OpTag::Send };
            self.driver
                .pending_copy_retries
                .push((conn_index, generation, pool_slot, 0, tag));
        }
    }

    /// True when a send-family CQE's slab entry still belongs to the live
    /// occupant of `conn_index`. False means the CQE outlived its connection
    /// slot (closed with the send in flight, index possibly reused) — the
    /// caller must release the entry's resources and touch no per-connection
    /// state. Mirrors the generation checks in `handle_send` /
    /// `handle_recv_fallback`.
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
    /// and fails the waiter.
    fn close_submitted(&self, conn_index: u32) -> bool {
        self.driver.send_queues[conn_index as usize].close_submitted
    }

    /// Settle one bounded (`ConnCtx::send_backpressured`) operation.
    ///
    /// Every site that resolves a bounded send goes through here so that no
    /// handler open-codes the rule: an id is settled exactly once, is routed
    /// by id rather than by connection, and carries the *logical* length on
    /// success. `Executor::complete_bounded_send` wakes the owning task and
    /// overrides a provisional teardown `Aborted` with this result (#381).
    fn settle_bounded(&mut self, id: BoundedSendId, result: io::Result<u32>) {
        self.executor.complete_bounded_send(id, result);
    }

    /// The failure a bounded send reports for a terminal send CQE.
    ///
    /// `result == 0` on a stream send means no bytes reached the wire and the
    /// handler is tearing the send down; `send().await` reports `Ok(0)` there,
    /// but a bounded send must never resolve with a truncated count (it would
    /// look like a short write of the caller's message), so it reports
    /// `WriteZero` — the same shape mio's flush reports for a zero-length
    /// write.
    fn bounded_send_error(result: i32) -> io::Error {
        if result == 0 {
            io::Error::new(io::ErrorKind::WriteZero, "send made no progress")
        } else {
            io::Error::from_raw_os_error(-result)
        }
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

    /// Hand the executor the bounded-send results that no CQE will carry:
    /// `DriverCtx::send_bounded`'s synchronous settles (a message that queued
    /// no SQE) and teardown's destroyed queue entries. Mirrors the first half
    /// of mio's `drain_send_completions`; the per-connection `SendFuture`
    /// wakes have no equivalent queue here, since an io_uring completion
    /// handler calls `wake_send` directly.
    fn drain_bounded_send_completions(&mut self) {
        while let Some((id, result)) = self.driver.bounded_send_completions.pop_front() {
            self.settle_bounded(id, result);
        }
    }

    /// Release the backing pool slots of a coalesced send, then the slab entry.
    ///
    /// Callers that mean to settle the run's bounded send must take it with
    /// `InFlightSendSlab::take_coalesced_bounded_send` *before* calling this:
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

    /// Handle completion of a coalesced plaintext `sendmsg` (OpTag::SendMsgCoalesced).
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
            // The entry may still name the bounded send lifted off the run's
            // end-of-send pool slot. Take it so nothing can claim it twice,
            // and settle nothing: the operation belonged to the connection
            // this CQE outlived, whose teardown already recorded the abort,
            // and a driver result would override that abort (#381) with a
            // dead occupant's outcome.
            let _ = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
            self.release_coalesced(slab_idx);
            return;
        }

        if result > 0 {
            // Partial send: advance the iovec array and resubmit the remainder.
            if let Some(msg_ptr) = self.driver.send_slab.try_advance(slab_idx, result as u32) {
                if self.close_submitted(conn_index) {
                    let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
                    self.release_coalesced(slab_idx);
                    if let Some((id, _logical_len)) = bounded {
                        self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    self.executor.wake_send(
                        conn_index,
                        Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                    );
                    return;
                }
                if self
                    .driver
                    .ring
                    .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
                    .is_err()
                {
                    let generation = self.driver.connections.generation(conn_index);
                    self.driver
                        .pending_coalesced_retries
                        .push((conn_index, generation, slab_idx, 0));
                }
                return;
            }
            // Fully sent.
            let total = self.driver.send_slab.total_len(slab_idx);
            // Read the end-of-send flag before releasing the slab entry —
            // and, for the same reason, take the bounded send it settles.
            let end_of_send = self.driver.send_slab.is_end_of_send(slab_idx);
            let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            self.release_coalesced(slab_idx);

            // Accumulate these chunks' bytes against the logical send, and wake
            // the waiter once, when the entry carrying the send's final chunk
            // completes, reporting the whole logical byte count. See
            // `ConnSendState::acked_bytes`.
            self.driver.send_queues[conn_index as usize].acked_bytes += total;
            self.driver.submit_next_queued(conn_index);
            self.driver.note_send_finalized(conn_index);
            // The carried logical (plaintext) length, not `acked` — see
            // `handle_send`'s success path.
            if let Some((id, logical_len)) = bounded {
                self.settle_bounded(id, Ok(logical_len));
            }
            if end_of_send {
                let acked =
                    std::mem::take(&mut self.driver.send_queues[conn_index as usize].acked_bytes);
                self.executor.wake_send(conn_index, Ok(acked));
            }
            return;
        }

        // EAGAIN/EWOULDBLOCK: socket buffer full — wait for POLLOUT, keep the
        // slab entry (and its data) alive, then resubmit the same sendmsg.
        let errno = -result;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            if self.close_submitted(conn_index) {
                let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
                self.release_coalesced(slab_idx);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                self.executor.wake_send(
                    conn_index,
                    Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                );
                return;
            }
            if self
                .driver
                .ring
                .submit_send_msg_coalesced_pollout(conn_index, slab_idx)
                .is_err()
            {
                let generation = self.driver.connections.generation(conn_index);
                self.driver
                    .pending_coalesced_retries
                    .push((conn_index, generation, slab_idx, 0));
            }
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        // Real error — release everything and drain the connection's queue.
        let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
        self.release_coalesced(slab_idx);
        self.driver.drain_conn_send_queue(conn_index);
        self.driver.note_send_finalized(conn_index);
        let io_result = if result == 0 {
            Ok(0u32)
        } else {
            Err(io::Error::from_raw_os_error(-result))
        };
        if let Some((id, _logical_len)) = bounded {
            self.settle_bounded(id, Err(Self::bounded_send_error(result)));
        }
        self.executor.wake_send(conn_index, io_result);
    }

    /// Handle a POLLOUT CQE armed after a coalesced send returned `-EAGAIN`.
    /// Resubmits the same sendmsg (data still intact in the slab entry).
    fn handle_send_msg_coalesced_pollout(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let slab_idx = ud.payload() as u16;

        if !self.driver.send_slab.in_use(slab_idx) {
            return;
        }
        // Identity: closed (index possibly reused) while waiting for POLLOUT.
        if !self.slab_identity_ok(conn_index, slab_idx) {
            // Take-and-discard, as in `handle_send_msg_coalesced`: the dead
            // occupant's operation was already aborted by its teardown.
            let _ = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
            self.release_coalesced(slab_idx);
            return;
        }

        if result < 0 {
            let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
            self.release_coalesced(slab_idx);
            self.driver.drain_conn_send_queue(conn_index);
            self.driver.note_send_finalized(conn_index);
            if let Some((id, _logical_len)) = bounded {
                self.settle_bounded(id, Err(io::Error::from_raw_os_error(-result)));
            }
            self.executor
                .wake_send(conn_index, Err(io::Error::from_raw_os_error(-result)));
            return;
        }

        if self.close_submitted(conn_index) {
            let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
            self.release_coalesced(slab_idx);
            if let Some((id, _logical_len)) = bounded {
                self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
            }
            self.executor.wake_send(
                conn_index,
                Err(io::Error::from_raw_os_error(libc::ECANCELED)),
            );
            return;
        }
        let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
        if self
            .driver
            .ring
            .submit_send_msg_coalesced(conn_index, msg_ptr, slab_idx)
            .is_err()
        {
            let generation = self.driver.connections.generation(conn_index);
            self.driver
                .pending_coalesced_retries
                .push((conn_index, generation, slab_idx, 0));
        }
    }

    /// Replenish the held provided-buffer bids backing a recv-forward entry and
    /// release the slab slot. The bids become available in the `ProvidedBufRing`
    /// again (resuming recv if it was ENOBUFS-stalled).
    fn release_recv_forward(&mut self, slab_idx: u16) {
        let mut bids = [u16::MAX; crate::buffer::send_slab::MAX_IOVECS];
        let mut n = 0;
        for &b in self.driver.send_slab.recv_forward_bids(slab_idx) {
            bids[n] = b;
            n += 1;
        }
        for &b in &bids[..n] {
            self.driver.pending_replenish.push(b);
        }
        self.driver.send_slab.release(slab_idx);
    }

    /// Handle completion of a zero-copy recv-forward `sendmsg`
    /// (OpTag::SendRecvBufsCoalesced). Mirrors `handle_send_msg_coalesced` but
    /// the backing is held provided buffers whose bids are replenished (not pool
    /// slots released) on completion. Partial sends advance the iovec array via
    /// `try_advance`; the bids stay held (memory valid) until full completion.
    fn handle_send_recv_bufs_coalesced(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let slab_idx = ud.payload() as u16;

        if !self.driver.send_slab.in_use(slab_idx) {
            return;
        }
        // Identity: the CQE outlived its connection slot — replenish the held
        // bids and release the entry; touch no per-connection state.
        if !self.slab_identity_ok(conn_index, slab_idx) {
            self.release_recv_forward(slab_idx);
            return;
        }

        if result > 0 {
            // Partial send: advance the iovec array and resubmit the remainder.
            // Bids are NOT replenished yet — the provided-buffer memory must stay
            // valid for the resubmitted iovecs.
            if let Some(msg_ptr) = self.driver.send_slab.try_advance(slab_idx, result as u32) {
                if self.close_submitted(conn_index) {
                    self.release_recv_forward(slab_idx);
                    self.executor.wake_send(
                        conn_index,
                        Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                    );
                    return;
                }
                if self
                    .driver
                    .ring
                    .submit_send_recv_bufs_coalesced(conn_index, msg_ptr, slab_idx)
                    .is_err()
                {
                    let generation = self.driver.connections.generation(conn_index);
                    self.driver
                        .pending_recv_forward_retries
                        .push((conn_index, generation, slab_idx, 0));
                }
                return;
            }
            // Fully sent.
            let total = self.driver.send_slab.total_len(slab_idx);
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            self.release_recv_forward(slab_idx);
            self.driver.submit_next_queued(conn_index);
            self.driver.note_send_finalized(conn_index);
            self.executor.wake_send(conn_index, Ok(total));
            return;
        }

        // EAGAIN/EWOULDBLOCK: wait for POLLOUT, keep the slab entry (and the held
        // buffers) alive, then resubmit the same sendmsg.
        let errno = -result;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            if self.close_submitted(conn_index) {
                self.release_recv_forward(slab_idx);
                self.executor.wake_send(
                    conn_index,
                    Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                );
                return;
            }
            if self
                .driver
                .ring
                .submit_send_recv_bufs_coalesced_pollout(conn_index, slab_idx)
                .is_err()
            {
                let generation = self.driver.connections.generation(conn_index);
                self.driver
                    .pending_recv_forward_retries
                    .push((conn_index, generation, slab_idx, 0));
            }
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        // Real error — replenish bids, release, and unwind the connection.
        self.release_recv_forward(slab_idx);
        self.driver.submit_next_queued(conn_index);
        self.driver.note_send_finalized(conn_index);
        let io_result = if result == 0 {
            Ok(0u32)
        } else {
            Err(io::Error::from_raw_os_error(-result))
        };
        self.executor.wake_send(conn_index, io_result);
    }

    /// Handle a POLLOUT CQE armed after a recv-forward send returned `-EAGAIN`.
    /// Resubmits the same sendmsg (held buffers still intact in the slab entry).
    fn handle_send_recv_bufs_coalesced_pollout(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let slab_idx = ud.payload() as u16;

        if !self.driver.send_slab.in_use(slab_idx) {
            return;
        }
        // Identity: closed (index possibly reused) while waiting for POLLOUT.
        if !self.slab_identity_ok(conn_index, slab_idx) {
            self.release_recv_forward(slab_idx);
            return;
        }

        if result < 0 {
            self.release_recv_forward(slab_idx);
            self.driver.submit_next_queued(conn_index);
            self.driver.note_send_finalized(conn_index);
            self.executor
                .wake_send(conn_index, Err(io::Error::from_raw_os_error(-result)));
            return;
        }

        if self.close_submitted(conn_index) {
            self.release_recv_forward(slab_idx);
            self.executor.wake_send(
                conn_index,
                Err(io::Error::from_raw_os_error(libc::ECANCELED)),
            );
            return;
        }
        let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
        if self
            .driver
            .ring
            .submit_send_recv_bufs_coalesced(conn_index, msg_ptr, slab_idx)
            .is_err()
        {
            let generation = self.driver.connections.generation(conn_index);
            self.driver
                .pending_recv_forward_retries
                .push((conn_index, generation, slab_idx, 0));
        }
    }

    /// Release the backing of the in-flight forward write, record an error for
    /// the `ForwardToFuture`, and wake it. A pinned bid returns to the ring.
    fn fail_forward_write(&mut self, conn_index: u32, errno: i32) {
        if let Some(state) = self.driver.forward_write[conn_index as usize].take() {
            // A batch holds several bids; every pinned one goes back, exactly
            // once.
            for backing in state.backings {
                if let crate::backend::HeldRecvBuf::Pinned { bid, .. } = backing {
                    self.driver.pending_replenish.push(bid);
                }
            }
        }
        // On a closing connection this is the cancelled-write's (ECANCELED) CQE:
        // the backing is now released, so continue the deferred close instead of
        // waking the doomed forward future.
        if self.driver.send_queues[conn_index as usize].close_pending {
            self.driver.try_finalize_close(conn_index);
            return;
        }
        self.driver.forward_progress[conn_index as usize] = None;
        self.driver.forward_done[conn_index as usize] = Some(Err(errno));
        self.executor.wake_recv(conn_index);
    }

    /// Resubmit the remaining bytes of the in-flight forward write (after a short
    /// write, or after a POLLOUT re-arm). The backing stays held; only the source
    /// pointer, length, and (for files) offset advance. On submit failure the
    /// forward is failed (releasing the backing).
    fn resubmit_forward_write(&mut self, conn_index: u32) {
        // A connection sink's slot may have been recycled since the forward
        // started; writing to a reused index would deliver this stream to
        // whoever owns it now.
        let stale = self.driver.forward_write[conn_index as usize]
            .as_ref()
            .is_some_and(|st| match st.target {
                crate::backend::uring::driver::SinkTarget::Conn { index, generation } => {
                    self.driver.connections.generation(index) != generation
                }
                crate::backend::uring::driver::SinkTarget::Fd { .. } => false,
            });
        if stale {
            self.fail_forward_write(conn_index, libc::EPIPE);
            return;
        }
        if let Err(e) = self.driver.resubmit_forward_writev(conn_index) {
            self.fail_forward_write(conn_index, e.raw_os_error().unwrap_or(libc::EIO));
        }
    }

    /// Re-arm a forwarding connection's multishot recv after the Mode A hold cap
    /// throttled (cancelled) it, once the held-buffer backlog has drained below
    /// `forward_hold_cap`.
    ///
    /// Called from the write-completion handler (the hold drains as writes finish)
    /// and from the ECANCELED branch (the throttle-cancel's own completion). Both
    /// converge on the same guard, so there is no deadlock: after a throttle the
    /// hold is drained one buffer per serialized write completion, and each
    /// completion re-checks this gate; the ECANCELED path covers the case where
    /// the hold already drained before the cancel completed. The `!armed` guard
    /// waits for the old multishot to fully terminate (its ECANCELED clears
    /// `recv_multishot_armed` at the top of `handle_recv_multi`) so two multishots
    /// with the same `RecvMulti` user_data never overlap.
    /// Drive a Mode A forward, and wake its task only if it finished.
    ///
    /// Every caller of `Driver::advance_forward` wants the same follow-up:
    /// record a terminal result and wake the waiting future, or do nothing
    /// because the forward is still running. Keeping that in one place is what
    /// makes "the task is woken once per forward" checkable rather than a
    /// property spread across two handlers.
    fn finish_forward_if_done(&mut self, conn_index: u32) {
        if let Some(result) = self.driver.advance_forward(conn_index) {
            self.driver.forward_done[conn_index as usize] =
                Some(result.map_err(|e| e.raw_os_error().unwrap_or(libc::EIO)));
            self.executor.wake_recv(conn_index);
        }
    }

    /// Re-arm a connection's multishot recv if it should be receiving and
    /// nothing is armed.
    ///
    /// The backstop for a cancel that outlived its target. `submit_async_cancel`
    /// matches a request by `user_data`, and a connection's multishot recv
    /// re-uses one user_data for the life of the slot (generation included), so
    /// a cancel queued against one arming can be applied by the kernel to the
    /// next one. Whoever cancelled has by then moved on, so no other path
    /// re-arms; without this the connection goes quiet for good.
    ///
    /// Deliberately does nothing for a connection that is closing, is not in
    /// multishot mode, or is throttled by the Mode A hold cap — that last one
    /// owns its own re-arm and must not have a second multishot armed under it.
    fn rearm_multishot_if_idle(&mut self, conn_index: u32) {
        if self.driver.forward_hold_throttled[conn_index as usize] {
            return;
        }
        let should_arm = self.driver.connections.get(conn_index).is_some_and(|c| {
            !c.recv_multishot_armed
                && matches!(c.lifecycle, Lifecycle::Open)
                && matches!(c.recv_arm, RecvArm::Multi)
        });
        if !should_arm {
            return;
        }
        let generation = self.driver.connections.generation(conn_index);
        if self
            .driver
            .ring
            .submit_multishot_recv(conn_index, generation)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
        } else if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = true;
        }
    }

    fn maybe_rearm_throttled_forward(&mut self, conn_index: u32) {
        let ci = conn_index as usize;
        if !self.driver.forward_hold_throttled[ci] {
            return;
        }
        // Wait for the cancelled multishot to terminate before arming a fresh one.
        let armed = self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.recv_multishot_armed);
        if armed {
            return;
        }
        // Only re-arm once the hold has drained below the cap.
        if self.driver.segment_hold[ci].len() >= self.driver.forward_hold_cap {
            return;
        }
        // Connection must still be open in multishot recv mode.
        let open = self.driver.connections.get(conn_index).is_some_and(|c| {
            matches!(c.lifecycle, Lifecycle::Open) && matches!(c.recv_arm, RecvArm::Multi)
        });
        if !open {
            self.driver.forward_hold_throttled[ci] = false;
            return;
        }
        // If the cancelled multishot happened to ENOBUFS-terminate (rather than
        // ECANCELED) it may have parked in `recv_starved`; take it back so the
        // starved-rearm path and this throttle re-arm cannot both fire.
        if let Some(pos) = self
            .driver
            .recv_starved
            .iter()
            .position(|&c| c == conn_index)
        {
            self.driver.recv_starved.swap_remove(pos);
        }
        self.driver.forward_hold_throttled[ci] = false;
        let generation = self.driver.connections.generation(conn_index);
        if self
            .driver
            .ring
            .submit_multishot_recv(conn_index, generation)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
        } else if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = true;
        }
    }

    /// Handle completion of a segmented-recv Mode A forward write
    /// (`OpTag::ForwardWrite`). The payload carries the connection generation at
    /// submit, so a stale completion (slot closed/reused — `close_connection`
    /// already released the backing) is ignored. On full completion the held bid
    /// is replenished exactly once and the `ForwardToFuture` is woken; a short
    /// write resubmits the remainder at the advanced offset; `-EAGAIN` (socket
    /// sink) arms POLLOUT.
    fn handle_forward_write(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let submit_gen = ud.payload();
        let live = self.driver.forward_write[conn_index as usize]
            .as_ref()
            .is_some_and(|s| s.generation == submit_gen);
        if !live {
            return;
        }

        // If the connection is closing, `close_connection` cancelled this write;
        // stop forwarding regardless of the result. Reclaim the backing (the CQE
        // means the kernel is done reading it) and drive the deferred close — do
        // not resubmit a short write, arm POLLOUT, or wake the doomed future.
        let closing = self.driver.send_queues[conn_index as usize].close_pending;

        if result > 0 {
            let n = result as u32;
            let reached_total = {
                let state = self.driver.forward_write[conn_index as usize]
                    .as_mut()
                    .expect("checked live above");
                state.written = state.written.saturating_add(n);
                state.written >= state.total
            };
            if !reached_total && !closing {
                // Short write — resubmit the remainder (files, or a socket send
                // the kernel did not fully retry).
                self.resubmit_forward_write(conn_index);
                return;
            }
            // Fully written (or closing — stop forwarding): release the backing
            // exactly once.
            let state = self.driver.forward_write[conn_index as usize]
                .take()
                .expect("checked live above");
            let total = state.total;
            for backing in state.backings {
                if let crate::backend::HeldRecvBuf::Pinned { bid, .. } = backing {
                    self.driver.pending_replenish.push(bid);
                }
            }
            if closing {
                // The forward write was the last thing pinning this slot; its bid
                // is now released, so continue the deferred close.
                self.driver.try_finalize_close(conn_index);
                return;
            }
            metrics::BYTES.add(metrics::bytes::SENT, total as u64);
            if let Some(p) = self.driver.forward_progress[conn_index as usize].as_mut() {
                p.forwarded = p.forwarded.saturating_add(total as u64);
            }
            // Submit the next held buffer from here rather than waking the task
            // to do it. The task is woken only when the forward ends, which is
            // what takes Mode A from one scheduler round-trip per provided
            // buffer to one per forward.
            self.finish_forward_if_done(conn_index);
            // A write completed, so the hold is draining. If the recv was
            // throttled by the hold cap and the hold is now below it (and the
            // throttle-cancel's ECANCELED has been observed), re-arm the
            // multishot so the source resumes.
            self.maybe_rearm_throttled_forward(conn_index);
            return;
        }

        let errno = -result;
        if !closing && (errno == libc::EAGAIN || errno == libc::EWOULDBLOCK) {
            // Socket sink buffer full: arm POLLOUT, then resubmit when writable.
            let target = self.driver.forward_write[conn_index as usize]
                .as_ref()
                .expect("checked live above")
                .target;
            let pud = UserData::encode(OpTag::ForwardWritePollOut, conn_index, submit_gen);
            let armed = match target {
                crate::backend::uring::driver::SinkTarget::Fd { fd, .. } => {
                    self.driver.ring.submit_forward_write_pollout(fd, pud)
                }
                crate::backend::uring::driver::SinkTarget::Conn { index, .. } => self
                    .driver
                    .ring
                    .submit_forward_write_pollout_conn(index, pud),
            };
            if armed.is_err() {
                self.fail_forward_write(conn_index, libc::EAGAIN);
            }
            metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
            return;
        }

        // Real error (or a 0-byte write, which would otherwise loop forever).
        let e = if result == 0 { libc::EIO } else { errno };
        self.fail_forward_write(conn_index, e);
    }

    /// Handle a POLLOUT CQE armed after a forward write to a socket sink returned
    /// `-EAGAIN` (`OpTag::ForwardWritePollOut`). Resubmits the remaining bytes.
    fn handle_forward_write_pollout(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let submit_gen = ud.payload();
        let live = self.driver.forward_write[conn_index as usize]
            .as_ref()
            .is_some_and(|s| s.generation == submit_gen);
        if !live {
            return;
        }
        if result < 0 {
            self.fail_forward_write(conn_index, -result);
            return;
        }
        // A closing connection cancelled its forward write; even if this POLLOUT
        // raced in writable, stop forwarding — reclaim the backing and finalize
        // the close rather than resubmitting onto a doomed connection.
        if self.driver.send_queues[conn_index as usize].close_pending {
            self.fail_forward_write(conn_index, libc::ECANCELED);
            return;
        }
        self.resubmit_forward_write(conn_index);
    }

    /// Handle completion of a send from a recv buffer (zero-copy forward).
    ///
    /// Payload encoding: `bid` in low 16 bits, `remaining_len` in high 16 bits.
    /// On partial send, resubmits from offset. On completion, replenishes the bid.
    fn handle_send_recv_buf(&mut self, ud: UserData, result: i32) {
        // No liveness/identity guard and no close_submitted guard,
        // deliberately: these sends are in_flight-tracked, so the deferred
        // close waits for this CQE, and the only in_flight-bypassing close
        // (force_finalize_close) is armed exclusively on TLS connections
        // while SendRecvBuf is plaintext-only. If a non-TLS force-close
        // path is ever added, this handler needs the same generation and
        // close_submitted checks as its siblings.
        let conn_index = ud.conn_index();
        let payload = ud.payload();
        // Payload carries only the bid. The remaining byte count is in the driver
        // field (send_recv_buf_remaining) so that buffer sizes > u16::MAX work.
        let bid = payload as u16;
        let remaining_before = self.driver.send_recv_buf_remaining[conn_index as usize];

        if result > 0 {
            let bytes_sent = result as u32;

            if bytes_sent < remaining_before {
                // Partial send — resubmit the remainder.
                let new_remaining = remaining_before - bytes_sent;
                self.driver.send_recv_buf_remaining[conn_index as usize] = new_remaining;
                let (buf_ptr, _buf_size) = self.driver.provided_bufs.get_buffer(bid);
                let original_len = self.driver.send_recv_buf_original_lens[conn_index as usize];
                let offset = original_len - new_remaining;
                let new_ptr = unsafe { buf_ptr.add(offset as usize) };
                let new_payload = bid as u32;
                let new_ud = UserData::encode(
                    crate::completion::OpTag::SendRecvBuf,
                    conn_index,
                    new_payload,
                );
                let entry = io_uring::opcode::Send::new(
                    io_uring::types::Fixed(conn_index),
                    new_ptr,
                    new_remaining,
                )
                .flags(crate::completion::STREAM_SEND_FLAGS)
                .build()
                .user_data(new_ud.raw());

                if unsafe { self.driver.ring.push_sqe(&entry) }.is_err() {
                    // SQ full — replenish and give up.
                    self.driver.pending_replenish.push(bid);
                    self.driver.submit_next_queued(conn_index);
                }
                return;
            }

            // Full send complete.
            metrics::BYTES.add(metrics::bytes::SENT, remaining_before as u64);
            self.driver.pending_replenish.push(bid);
            self.driver.submit_next_queued(conn_index);
            self.executor.wake_send(conn_index, Ok(remaining_before));
            return;
        }

        // Error or zero-length send.
        self.driver.pending_replenish.push(bid);
        self.driver.submit_next_queued(conn_index);

        let io_result = if result == 0 {
            Ok(0u32)
        } else {
            Err(io::Error::from_raw_os_error(-result))
        };
        self.executor.wake_send(conn_index, io_result);
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
        // CQE with result > 0 still has its notification in flight (count it,
        // never resubmit the partial remainder — the connection is gone);
        // otherwise no notification is coming and the entry releases now.
        if !self.slab_identity_ok(conn_index, slab_idx) {
            if cqueue::notif(flags) {
                self.driver.send_slab.dec_pending_notifs(slab_idx);
            } else {
                // Main CQE: the entry is now final for this op — a stale
                // partial is never resubmitted. Mark awaiting only here
                // (not on notif CQEs, which for a resubmitted partial can
                // precede the remainder's main CQE), matching run_shutdown.
                if result > 0 {
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
            if result == -libc::ECANCELED {
                let ps = self.driver.send_slab.release(slab_idx);
                if ps != u16::MAX {
                    self.release_pool_slot(ps);
                }
            } else if result > 0 {
                // Kernel sends a ZC notification only when result > 0.
                // result == 0 means no bytes sent — no notification will arrive.
                self.driver.send_slab.inc_pending_notifs(slab_idx);
                self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                self.driver.chain_table.inc_zc_notif(conn_index);
            } else {
                // result == 0 or result < 0 (excluding ECANCELED above):
                // release immediately — no ZC notification coming.
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

        // Only increment pending notifications for successful sends — the kernel
        // sends a ZC notification CQE only when result > 0. On error (result <= 0),
        // no notification arrives, so incrementing would permanently leak the slab slot.
        if result > 0 {
            self.driver.send_slab.inc_pending_notifs(slab_idx);
        }

        #[allow(clippy::collapsible_if)]
        if result > 0 {
            if let Some(msg_ptr) = self.driver.send_slab.try_advance(slab_idx, result as u32) {
                // Never resubmit a partial past a submitted Close: mirror the
                // completion path's notification accounting minus the queue
                // and wake bookkeeping (the notification for the sent prefix
                // is still in flight).
                if self.close_submitted(conn_index) {
                    self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                    if self.driver.send_slab.should_release(slab_idx) {
                        let ps = self.driver.send_slab.release(slab_idx);
                        if ps != u16::MAX {
                            self.release_pool_slot(ps);
                        }
                    }
                    self.executor.wake_send(
                        conn_index,
                        Err(io::Error::from_raw_os_error(libc::ECANCELED)),
                    );
                    return;
                }
                // Partial send — resubmit the remainder.
                if self
                    .driver
                    .ring
                    .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                    .is_ok()
                {
                    return;
                }
                // Resubmission failed (SQ full) — queue for retry on the
                // next event loop tick. The slab entry retains all iovec
                // state from try_advance, so we can resubmit later.
                let generation = self.driver.connections.generation(conn_index);
                self.driver
                    .pending_zc_retries
                    .push((conn_index, generation, slab_idx, 0));
                return;
            }
        }

        // Send complete (all bytes sent) or error (result <= 0).
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
        }

        let io_result = if result >= 0 {
            Ok(total_len)
        } else {
            Err(io::Error::from_raw_os_error(-result))
        };
        self.executor.wake_send(conn_index, io_result);
    }

    fn handle_connect(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();

        if self.driver.connections.get(conn_index).is_none() {
            return;
        }

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
                let timeout_ud = UserData::encode(OpTag::Timeout, conn_index, 0);
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
            let timeout_ud = UserData::encode(OpTag::Timeout, conn_index, 0);
            let _ = self
                .driver
                .ring
                .submit_async_cancel(timeout_ud.raw(), conn_index);
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.connect_timeout_armed = false;
            }
        }

        // Orphaned-future guard: if the ConnectFuture was dropped while the
        // SQE was in flight (e.g. `select!` with a timeout that won), no
        // task will pick up this connection — and we don't have an
        // `on_accept` path for outbound connects. Letting the slot go
        // "established" would leak it until the peer closes (which may be
        // never). Close it now instead.
        if !self.executor.connect_waiters[conn_index as usize] {
            if let Some(pending) = self.driver.pending_recv_bufs[conn_index as usize].take() {
                self.driver.pending_replenish.push(pending.bid);
            }
            self.driver.accumulators.reset(conn_index);
            if let Some(ref mut tls_table) = self.driver.tls_table {
                tls_table.remove(conn_index);
            }
            self.driver.close_connection(conn_index);
            return;
        }

        if let Some(pending) = self.driver.pending_recv_bufs[conn_index as usize].take() {
            self.driver.pending_replenish.push(pending.bid);
        }
        self.driver.accumulators.reset(conn_index);
        self.driver.reset_segment_state(conn_index);
        self.driver.reset_send_state(conn_index);
        // A slot is recycled by generation, so without this a new occupant
        // would inherit the previous one's park offer — and its state.
        self.driver.park_offered[conn_index as usize] = false;
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
            self.arm_recv(conn_index);
            return;
        }

        // Plaintext path
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.established = true;
            cs.mark_connected();
        }
        self.arm_recv(conn_index);

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

        let connect_ud = UserData::encode(OpTag::Connect, conn_index, 0);
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

        // Replenish any held zero-copy recv buffer.
        if let Some(pending) = self.driver.pending_recv_bufs[conn_index as usize].take() {
            self.driver.pending_replenish.push(pending.bid);
        }

        // Reclaim a bid still pinned by a live `RecvSegment` (Mode B). The future
        // is dropped just below by `remove_connection`, which drops the segment —
        // but that `Drop` runs unguarded here (`CURRENT_DRIVER == None`) and
        // no-ops, so the release is done explicitly. `close_connection`
        // deliberately did NOT reclaim this bid (a parked task could still have
        // deref'd it before this point); by now the connection is fully closing
        // and no live segment can read the buffer, so it is safe to return. If an
        // in-poll `RecvSegment::drop`/`into_owned` already released it, the slot is
        // `None` and this is a no-op (single-release via the pin slot).
        if let Some(crate::backend::HeldRecvBuf::Pinned { bid, .. }) =
            self.driver.segment_pinned[conn_index as usize].take()
        {
            self.driver.pending_replenish.push(bid);
        }

        // Drain any segmented-recv buffers still held (a Mode B reader that never
        // finished consuming them, or a Mode A forward aborted by close).
        // `close_connection` deliberately left these so a post-FIN reader could
        // consume them; by teardown no consumer remains, so reclaim each Pinned
        // bid (Owned entries just drop). Symmetric to the `segment_pinned` reclaim
        // above and the `pending_recv_bufs` reclaim.
        for held in self.driver.segment_hold[conn_index as usize]
            .drain(..)
            .collect::<Vec<_>>()
        {
            if let crate::backend::HeldRecvBuf::Pinned { bid, .. } = held {
                self.driver.pending_replenish.push(bid);
            }
        }

        let was_established = self
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.established)
            .unwrap_or(false);

        if let Some(ref mut tls_table) = self.driver.tls_table {
            tls_table.remove(conn_index);
        }

        if was_established {
            metrics::CONNECTIONS.increment(metrics::conn::CLOSED);
            metrics::CONNECTIONS_ACTIVE.decrement();
        }

        // Remove the async task (drops the future).
        self.executor.remove_connection(conn_index);
        // The future just dropped may have owned a `RecvHalf` or a
        // `SegmentReader`, whose `Drop` is a no-op here (unguarded teardown).
        // Clear their claims before the slot is reused, or the next occupant
        // inherits them.
        self.driver.clear_conn_claims(conn_index);
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
            let _ = self.driver.send_copy_pool.take_bounded_send(pool_slot);
            self.release_pool_slot(pool_slot);
            return;
        }

        if result > 0
            && let Some((ptr, remaining)) = self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
        {
            if self.close_submitted(conn_index) {
                // One of this handler's two silent returns. `send().await`
                // is left hanging here (a pre-existing hole this PR does not
                // fix), but a bounded send must not reproduce it.
                let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                self.release_pool_slot(pool_slot);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                return;
            }
            let generation = self.driver.connections.generation(conn_index);
            if self
                .driver
                .ring
                .submit_tls_send(conn_index, generation, ptr, remaining, pool_slot)
                .is_err()
            {
                // SQ full — queue for retry on next tick. Use copy retry
                // since TLS sends use SendCopyPool slots; the stored OpTag
                // keeps the resubmission on the TlsSend completion path.
                self.driver.pending_copy_retries.push((
                    conn_index,
                    generation,
                    pool_slot,
                    0,
                    OpTag::TlsSend,
                ));
            }
            return;
        }
        // Socket send buffer full: wait for POLLOUT and resubmit the same
        // chunk. Tearing the connection down here (the old behavior) turned
        // ordinary backpressure during a large TLS write into a broken
        // connection. Keep the slot; is_tls=true keeps the resubmission on
        // the TlsSend path.
        if result < 0 {
            let errno = -result;
            if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                if self.close_submitted(conn_index) {
                    // The handler's other silent return; same reasoning.
                    let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                    self.release_pool_slot(pool_slot);
                    if let Some((id, _logical_len)) = bounded {
                        self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                    return;
                }
                let generation = self.driver.connections.generation(conn_index);
                if self
                    .driver
                    .ring
                    .submit_send_pollout(conn_index, generation, pool_slot, true)
                    .is_err()
                {
                    self.driver
                        .pending_send_pollout_retries
                        .push((conn_index, generation, pool_slot, 0, true));
                }
                metrics::POOL.increment(metrics::pool::SEND_EAGAIN);
                return;
            }
        }

        let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
        self.release_pool_slot(pool_slot);
        // By construction no id reaches this handler: `send_bounded` attaches
        // it to the *final* ciphertext chunk, which `encrypt_to_sends` tags
        // `OpTag::Send`, so the id-carrying slot completes in `handle_send`.
        // Taking it anyway is what keeps `SendCopyPool::release`'s tripwire
        // honest if that ever changes, and settling it is what keeps the
        // caller from hanging on the `drain_conn_send_queue` path below.
        if let Some((id, logical_len)) = bounded {
            let settled = if result > 0 {
                Ok(logical_len)
            } else {
                Err(Self::bounded_send_error(result))
            };
            self.settle_bounded(id, settled);
        }

        // Intermediate TLS chunks are serialized through the per-connection
        // send queue, so a completion must pop the next queued send and let
        // a deferred close finalize, exactly like handle_send.
        if result >= 0 {
            self.driver.submit_next_queued(conn_index);
            self.driver.note_send_finalized(conn_index);
            return;
        }

        // On error, fail the connection so the owning task unblocks: drain
        // the queued sibling chunks (their slots are released by the drain)
        // and close.
        if result < 0 {
            self.driver.drain_conn_send_queue(conn_index);
            self.driver.close_connection(conn_index);
        }
    }

    fn fire_chain_complete(&mut self, conn_index: u32) {
        let chain = match self.driver.chain_table.take(conn_index) {
            Some(c) => c,
            None => return,
        };

        let io_result = match chain.first_error {
            Some(errno) => Err(io::Error::from_raw_os_error(-errno)),
            None => Ok(chain.bytes_sent),
        };

        if chain.first_error.is_none() {
            self.driver.submit_next_queued(conn_index);
        } else {
            self.driver.drain_conn_send_queue(conn_index);
        }

        self.executor.wake_send(conn_index, io_result);

        // A close_connection that arrived while the chain was active deferred
        // its Close on chain_drained — the chain state was just taken, so
        // re-drive the finalize.
        self.driver.note_send_finalized(conn_index);
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
            // Stale socket. If a buffer was attached, hand it back so it
            // doesn't leak out of the ring.
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                // Count the handout so the replenish's occupancy decrement is
                // balanced. `replenish_batch` only decrements when the ring is
                // Some, so guard the increment the same way.
                if let Some(r) = self.driver.udp_provided_bufs.as_mut() {
                    r.on_handout();
                }
                self.driver.udp_pending_replenish.push(bid);
            }
            return;
        }

        // udp_sockets is non-empty → udp_provided_bufs is Some.
        let udp_bgid = match self.driver.udp_provided_bufs.as_ref() {
            Some(r) => r.bgid(),
            None => return,
        };

        if result <= 0 {
            let errno = -result;
            // If the multishot was torn down, rearm so the socket stays
            // live. ECANCELED is a quiet teardown during shutdown; skip.
            if !has_more && errno != libc::ECANCELED {
                if errno == libc::ENOBUFS {
                    metrics::POOL.increment(metrics::pool::BUFFER_RING_EMPTY);
                }
                self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(b) => b,
            None => {
                if !has_more {
                    self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
                }
                return;
            }
        };
        // The bid is checked out of the UDP ring; account it against occupancy so
        // `free()` and the double-replenish tripwire stay accurate. It is
        // replenished exactly once — immediately below on a parse/drop, or when
        // the consumer reads the queued datagram.
        self.driver.udp_provided_bufs.as_mut().unwrap().on_handout();

        // SAFETY: The buffer pointer belongs to the UDP provided buffer ring
        // and remains valid until we replenish the bid below.
        let buf_len = result as u32;
        let buf = {
            let udp_bufs = self.driver.udp_provided_bufs.as_ref().unwrap();
            let (buf_ptr, _) = udp_bufs.get_buffer(bid);
            unsafe { std::slice::from_raw_parts(buf_ptr, buf_len as usize) }
        };

        // Parse the recvmsg header out of the kernel buffer. If parsing fails
        // (or the datagram is truncated, or the queue is full) the bid is
        // returned to the ring immediately. Otherwise the bid travels with the
        // queue entry and is replenished when the consumer reads it — that's
        // what makes the recv path zero-copy.
        let parse_result =
            io_uring::types::RecvMsgOut::parse(buf, &self.driver.udp_sockets[idx].recv_msghdr);

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
            self.driver.udp_pending_replenish.push(bid);
        }

        if !has_more {
            self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
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

        // A freed slot may unblock a task awaiting `UdpCtx::send_ready`.
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
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                // Count the handout so the replenish's occupancy decrement is
                // balanced. `replenish_batch` only decrements when the ring is
                // Some, so guard the increment the same way.
                if let Some(r) = self.driver.udp_provided_bufs.as_mut() {
                    r.on_handout();
                }
                self.driver.udp_pending_replenish.push(bid);
            }
            return;
        }

        let udp_bgid = match self.driver.udp_provided_bufs.as_ref() {
            Some(r) => r.bgid(),
            None => return,
        };

        if result <= 0 {
            // Defensive: a zero-length datagram (or an error CQE on some
            // kernels) can still carry a selected buffer — failing to
            // replenish its bid shrinks the UDP ring by one per occurrence
            // until ENOBUFS (a remote peer sending empty datagrams could
            // drain the ring entirely).
            if let Some(bid) = cqueue::buffer_select(flags) {
                // The ring is Some here (guarded by the `udp_bgid` match above).
                // Count the handout so the replenish's occupancy decrement is
                // balanced.
                self.driver.udp_provided_bufs.as_mut().unwrap().on_handout();
                self.driver.udp_pending_replenish.push(bid);
            }
            let errno = -result;
            if !has_more && errno != libc::ECANCELED {
                if errno == libc::ENOBUFS {
                    metrics::POOL.increment(metrics::pool::BUFFER_RING_EMPTY);
                }
                self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(b) => b,
            None => {
                if !has_more {
                    self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
                }
                return;
            }
        };
        // The bid is checked out of the UDP ring; account it against occupancy so
        // `free()` and the double-replenish tripwire stay accurate. It is
        // replenished exactly once — immediately below on a parse/drop, or when
        // the consumer reads the queued datagram.
        self.driver.udp_provided_bufs.as_mut().unwrap().on_handout();

        let payload_len = result as u32;
        let buf_ptr = {
            let udp_bufs = self.driver.udp_provided_bufs.as_ref().unwrap();
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
            self.driver.udp_pending_replenish.push(bid);
        }

        if !has_more {
            self.driver.rearm_udp_recvmsg(udp_index, udp_bgid);
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

        // Decrement in-flight count.
        if let Some(ref mut devices) = self.driver.nvme_devices
            && let Some(dev) = devices.get_mut(device_index)
        {
            dev.in_flight = dev.in_flight.saturating_sub(1);
        }

        // NVMe passthrough puts the device-level status word (positive,
        // e.g. 0x281 media error) in cqe->res on command failure; 0 is
        // success and negative is a transport errno. Treating result >= 0
        // as success returned Ok(status) for failed reads/writes — silent
        // data corruption on device errors.
        let result = if result > 0 { -libc::EIO } else { result };

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

        // Decrement in-flight count.
        if let Some(ref mut files) = self.driver.direct_io_files
            && let Some(f) = files.get_mut(file_index)
        {
            f.in_flight = f.in_flight.saturating_sub(1);
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

    /// Arm the appropriate multishot recv for a connection.
    ///
    /// When the `timestamps` feature is enabled and configured, uses
    /// `RecvMsgMulti` (multishot recvmsg) to receive cmsg ancillary data
    /// containing kernel timestamps. Otherwise, uses `RecvMulti` (plain
    /// multishot recv).
    fn arm_recv(&mut self, conn_index: u32) {
        // Carried in the completion's payload so a CQE that outlives this
        // connection is rejected instead of being applied to the next occupant
        // of the slot. Valid even for an inactive slot.
        let generation = self.driver.connections.generation(conn_index);
        #[cfg(feature = "timestamps")]
        if self.driver.timestamps {
            let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
            if self
                .driver
                .ring
                .submit_multishot_recvmsg(conn_index, generation, msghdr_ptr)
                .is_err()
            {
                metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_arm = RecvArm::MsgMulti;
            }
            return;
        }
        if self
            .driver
            .ring
            .submit_multishot_recv(conn_index, generation)
            .is_err()
        {
            metrics::RING.increment(metrics::ring::RECV_ARM_FAILURES);
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
        } else if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = true;
        }
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
        // not `UnwindSafe`. A panic here is treated like a fatal handler
        // error — the connection is closed; the worker continues serving
        // others.
        // An adopted connection gets `on_adopt`, not `on_accept`: it is not a
        // new connection, and the handler may have state to restore.
        let adopting = self.driver.adopt_pending.remove(&conn_index);
        let future_result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match adopting {
                Some(state) => self.handler.on_adopt(conn, state),
                None => Box::pin(self.handler.on_accept(conn))
                    as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static>>,
            }));
        let future = match future_result {
            Ok(f) => f,
            Err(_) => {
                // Handler panicked during async-block construction.
                // Close the connection and skip task setup. Don't propagate
                // — the worker keeps serving its other connections.
                self.driver.close_connection(conn_index);
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
    /// Requires kernel 6.6+ for IORING_NOP_INJECT_RESULT.
    #[cfg(test)]
    pub(crate) fn inject_and_dispatch(&mut self, user_data_raw: u64, result: i32) {
        self.driver
            .ring
            .submit_nop_inject(user_data_raw, result)
            .expect("submit_nop_inject failed — kernel 6.6+ required");
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
            if self.driver.connections.get(conn_index).is_none()
                || self.driver.connections.generation(conn_index) != generation
                || self.close_submitted(conn_index)
            {
                self.release_zc_slab(slab_idx);
                continue;
            }
            if retries >= 2 {
                // Give up: bytes of this send are already missing from the
                // stream, so fail the waiter and close rather than leaving
                // in_flight stuck and the connection wedged open.
                self.release_zc_slab(slab_idx);
                self.driver.drain_conn_send_queue(conn_index);
                let err = io::Error::other("max retries during zc send resubmit");
                self.executor.wake_send(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                continue;
            }
            let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
            if self
                .driver
                .ring
                .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                .is_err()
            {
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
                let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
                self.release_coalesced(slab_idx);
                if identity_ok && let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                continue;
            }
            if retries >= 2 {
                // Give up: fail the waiter and close so the connection isn't
                // left open with a hole in its byte stream.
                let bounded = self.driver.send_slab.take_coalesced_bounded_send(slab_idx);
                self.release_coalesced(slab_idx);
                self.driver.drain_conn_send_queue(conn_index);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(
                        id,
                        Err(io::Error::other(
                            "max retries during coalesced send resubmit",
                        )),
                    );
                }
                let err = io::Error::other("max retries during coalesced send resubmit");
                self.executor.wake_send(conn_index, Err(err));
                self.driver.close_connection(conn_index);
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

    /// Retry recv-forward send resubmissions that failed (SQ was full).
    fn drain_recv_forward_retries(&mut self) {
        if self.driver.pending_recv_forward_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_recv_forward_retries,
            &mut self.driver.recv_forward_retry_scratch,
        );
        for idx in 0..self.driver.recv_forward_retry_scratch.len() {
            let (conn_index, generation, slab_idx, retries) =
                self.driver.recv_forward_retry_scratch[idx];
            if !self.driver.send_slab.in_use(slab_idx) {
                continue; // slab released meanwhile
            }
            // Connection closed or reused — replenish bids and release only.
            if self.driver.connections.get(conn_index).is_none()
                || self.driver.connections.generation(conn_index) != generation
                || self.close_submitted(conn_index)
            {
                self.release_recv_forward(slab_idx);
                continue;
            }
            if retries >= 2 {
                // Give up: forwarded bytes were dropped mid-stream, so close
                // instead of forwarding the rest of the queue after the gap.
                self.release_recv_forward(slab_idx);
                self.driver.drain_conn_send_queue(conn_index);
                let err = io::Error::other("max retries during recv-forward resubmit");
                self.executor.wake_send(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                continue;
            }
            let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
            if self
                .driver
                .ring
                .submit_send_recv_bufs_coalesced(conn_index, msg_ptr, slab_idx)
                .is_err()
            {
                self.driver.pending_recv_forward_retries.push((
                    conn_index,
                    generation,
                    slab_idx,
                    retries + 1,
                ));
            }
        }
        self.driver.recv_forward_retry_scratch.clear();
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
                let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                self.release_pool_slot(pool_slot);
                if identity_ok && let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                }
                continue;
            }
            if retries >= 2 {
                // Give up: fail the waiter and close so the connection isn't
                // left open with a hole in its byte stream.
                let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                self.release_pool_slot(pool_slot);
                self.driver.drain_conn_send_queue(conn_index);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(
                        id,
                        Err(io::Error::other("max retries during send resubmit")),
                    );
                }
                let err = io::Error::other("max retries during send resubmit");
                self.executor.wake_send(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                continue;
            }
            let (ptr, remaining) = self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
            // Resubmit with the entry's original OpTag. Choosing by
            // tls_table membership here re-tagged the *final* chunk of a TLS
            // send (deliberately OpTag::Send so its CQE wakes the waiter) as
            // TlsSend, whose handler never wakes — a permanent send() hang.
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
                // fail the waiter and close so the connection isn't left open
                // with a hole in its byte stream.
                //
                // No bounded send is settled here because none is in hand:
                // the parked entry is still *queued*, so
                // `drain_conn_send_queue` -> `release_queued_sends` takes its
                // id off the pool slot and fails it (as `ConnectionAborted`)
                // through `Driver::bounded_send_completions`, which the run
                // loop drains.
                self.driver.drain_conn_send_queue(conn_index);
                let err = io::Error::other("max retries during send submit");
                self.executor.wake_send(conn_index, Err(err));
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
            if self.driver.ring.submit_close(conn_index).is_err() {
                self.driver
                    .pending_close_retries
                    .push((conn_index, retry.saturating_add(1)));
            }
        }
    }

    /// Retry POLLOUT arming that failed at EAGAIN time (SQ was full).
    /// Max 3 attempts with backoff: attempt only every 2nd tick, keeping
    /// entries queued in between.
    fn drain_send_pollout_retries(&mut self) {
        if self.driver.pending_send_pollout_retries.is_empty() {
            return;
        }
        std::mem::swap(
            &mut self.driver.pending_send_pollout_retries,
            &mut self.driver.send_pollout_retry_scratch,
        );
        let tick_mod = self.driver.tick_count % 2;
        for idx in 0..self.driver.send_pollout_retry_scratch.len() {
            let (conn_index, generation, pool_slot, retry, is_tls) =
                self.driver.send_pollout_retry_scratch[idx];
            if retry >= 3 {
                // Max retries exceeded — release pool + drain queue + close.
                // Identity first (the other branches below check it too): if
                // the connection died while the retry aged, only the slot may
                // be touched — draining/waking/closing would hit the index's
                // new occupant.
                let mut bounded = None;
                if self.driver.send_copy_pool.in_use(pool_slot) {
                    bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                    self.release_pool_slot(pool_slot);
                }
                if self.driver.connections.get(conn_index).is_none()
                    || self.driver.connections.generation(conn_index) != generation
                {
                    // A dead occupant's slot. The id was taken so `release`
                    // could not trip on it, and it is deliberately dropped
                    // here rather than settled: teardown already aborted that
                    // operation, and a driver result would override the abort
                    // (#381) for a connection that no longer exists.
                    continue;
                }
                self.driver.drain_conn_send_queue(conn_index);
                if let Some((id, _logical_len)) = bounded {
                    self.settle_bounded(
                        id,
                        Err(io::Error::other("max retries during send pollout retry")),
                    );
                }
                let err = io::Error::other("max retries during send pollout retry");
                self.executor.wake_send(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                continue;
            }
            if tick_mod != 0 {
                // Not this tick — keep the entry queued.
                self.driver
                    .pending_send_pollout_retries
                    .push((conn_index, generation, pool_slot, retry, is_tls));
                continue;
            }
            if !self.driver.send_copy_pool.in_use(pool_slot) {
                continue;
            }
            let identity_ok = self.driver.connections.get(conn_index).is_some()
                && self.driver.connections.generation(conn_index) == generation;
            if !identity_ok || self.close_submitted(conn_index) {
                if self.driver.send_copy_pool.in_use(pool_slot) {
                    // Same split as `drain_copy_retries`: settle only when
                    // the slot still belongs to the live occupant (the
                    // `close_submitted` reason); a dead occupant's id is
                    // taken and discarded.
                    let bounded = self.driver.send_copy_pool.take_bounded_send(pool_slot);
                    self.release_pool_slot(pool_slot);
                    if identity_ok && let Some((id, _logical_len)) = bounded {
                        self.settle_bounded(id, Err(io::Error::from_raw_os_error(libc::ECANCELED)));
                    }
                }
                continue;
            }
            if self
                .driver
                .ring
                .submit_send_pollout(conn_index, generation, pool_slot, is_tls)
                .is_err()
            {
                self.driver.pending_send_pollout_retries.push((
                    conn_index,
                    generation,
                    pool_slot,
                    retry + 1,
                    is_tls,
                ));
            }
        }
        self.driver.send_pollout_retry_scratch.clear();
    }

    /// Test-only: inject multiple NOPs and dispatch them all in one batch.
    /// This tests batch CQE processing where one handler's side effects
    /// affect subsequent handlers in the same drain_completions() call.
    #[cfg(test)]
    /// Test-only: submit a linked chain of NOP injects and dispatch.
    /// The first N-1 SQEs have IO_LINK set; the last does not.
    /// This tests IOSQE_IO_LINK error propagation through the kernel.
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
    /// force-close it by calling `try_finalize_close`.
    ///
    /// Iterates only the indices in `driver.close_notify_armed`, not
    /// every entry in `driver.send_queues`. For non-TLS workloads the
    /// armed set is permanently empty and this method is a single
    /// `Vec::is_empty()` check; for TLS workloads the set is bounded
    /// by the number of concurrent in-flight TLS graceful shutdowns
    /// (typically 0 or single digits).
    ///
    /// Profiling the redis bench at 1 client × 64 B (i.e. plain TCP)
    /// showed the previous O(N over all slots) walk at ~25 % of
    /// worker CPU because it ran on every event-loop iteration; the
    /// armed-set version drops that to noise.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigBuilder;
    use crate::completion::{OpTag, UserData};
    use crate::config::Config;
    use crate::runtime::io::ConnCtx;
    use crate::runtime::io::SegConsumed;
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
            .recv_buffer(16, 4096)
            // Reserve 0: the shared 16-buffer ring never hits the low-water mark
            // in these unit tests, so segmented deliveries stay zero-copy
            // (Pinned) as the existing assertions expect. Force-copy behavior is
            // covered by dedicated tests that raise the reserve explicitly.
            .recv_segment_reserve(0)
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

    /// A test config with an explicit segmented-recv low-water reserve. With the
    /// 16-buffer test ring, `reserve == 16` forces every segmented delivery to
    /// Mode C (Owned copy), while a small reserve keeps early deliveries Pinned.
    fn config_with_reserve(reserve: u32) -> Config {
        test_config_builder()
            .recv_segment_reserve(reserve)
            .build()
            .expect("valid config")
    }

    /// A test config with an explicit Mode A `forward_to` held-buffer cap (and
    /// reserve 0 so held buffers stay Pinned in the 16-buffer test ring).
    fn config_with_forward_cap(cap: usize) -> Config {
        test_config_builder()
            .recv_segment_reserve(0)
            .forward_hold_cap(cap)
            .build()
            .expect("valid config")
    }

    /// Create a test event loop. Requires Linux with io_uring support.
    fn make_test_loop() -> AsyncEventLoop<NoopHandler> {
        make_test_loop_with_config(test_config())
    }

    /// Create a test event loop from an explicit config (e.g. to exercise the
    /// segmented-recv low-water reserve, which `test_config` pins to 0).
    fn make_test_loop_with_config(config: Config) -> AsyncEventLoop<NoopHandler> {
        // Parallel release-mode test runs can transiently exhaust kernel memory
        // for io_uring_setup while sibling tests hold their rings — the daily
        // scheduled CI intermittently fails several of these tests at once with
        // ENOMEM (e.g. runs 31887895010, 31710717130). The pressure clears as
        // sibling tests finish, so retry briefly before failing.
        let mut attempts = 0;
        loop {
            let shutdown = Arc::new(AtomicBool::new(false));
            let eventfd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
            assert!(eventfd >= 0, "eventfd creation failed");
            let (_region_tx, region_rx) = crossbeam_channel::unbounded();
            match AsyncEventLoop::new(
                &config,
                NoopHandler,
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
                    if attempts < 10
                        && matches!(
                            io.raw_os_error(),
                            Some(libc::ENOMEM | libc::EAGAIN | libc::EMFILE | libc::ENFILE)
                        ) =>
                {
                    attempts += 1;
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
                    panic!("failed to create test event loop after {attempts} retries: {e:?}")
                }
            }
        }
    }

    /// Simulate an accepted plaintext connection at the given index.
    /// Returns the conn_index that was allocated.
    fn accept_connection(el: &mut AsyncEventLoop<NoopHandler>) -> u32 {
        let conn_index = el.driver.connections.allocate().expect("no free slots");
        el.driver.accumulators.reset(conn_index);
        // arm_recv needs to submit an SQE — skip in test since we inject CQEs directly.
        // Just set lifecycle = Open / recv_arm = Multi so the handlers work correctly.
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.lifecycle = Lifecycle::Open;
            cs.recv_arm = RecvArm::Multi;
            cs.established = true;
            // The real install records the listener; without it every test
            // connection looks outbound, which park now refuses.
            cs.listener = Some(crate::ListenerId::from_index(0));
        }
        conn_index
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

    #[test]
    fn a_live_segment_reader_blocks_the_park() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        // Offered: these cover the mechanical blockers, so the opt-in must
        // be out of the way or every one of them would report NotOffered.
        el.driver.park_offered[conn_index as usize] = true;
        el.driver.segment_reader_live[conn_index as usize] = true;
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::SegmentReader),
            "a reader owns delivery discipline for its lifetime: not quiescent"
        );
    }

    /// Supersedes an earlier decision, deliberately.
    ///
    /// #463 held that a pinned bid must not *block* a park, because waiting
    /// for a slow reader could make a connection permanently unparkable; the
    /// bid would be copied to owned at move time instead. That reasoning came
    /// from the close path and does not carry: a held buffer is unconsumed
    /// data, so the quiescent point the handler offered at has passed, and
    /// parking would ship state deposited before a request already in flight.
    /// Nothing becomes permanently unparkable — the handler re-offers at its
    /// next idle point.
    ///
    /// The held buffer is placed directly rather than driven through a reader:
    /// what is under test is the gate's treatment of a held bid, not the
    /// lifecycle that produces one.
    #[test]
    fn held_ring_buffers_block_the_park_as_unconsumed_data() {
        for (label, place) in [
            (
                "pinned",
                Box::new(|el: &mut AsyncEventLoop<NoopHandler>, c: u32| {
                    el.driver.segment_pinned[c as usize] =
                        Some(crate::backend::uring::driver::HeldRecvBuf::Pinned { bid: 0, len: 5 });
                }) as Box<dyn Fn(&mut AsyncEventLoop<NoopHandler>, u32)>,
            ),
            (
                "held",
                Box::new(|el: &mut AsyncEventLoop<NoopHandler>, c: u32| {
                    el.driver.segment_hold[c as usize].push_back(
                        crate::backend::uring::driver::HeldRecvBuf::Pinned { bid: 1, len: 5 },
                    );
                }),
            ),
            (
                "recv_hold",
                Box::new(|el: &mut AsyncEventLoop<NoopHandler>, c: u32| {
                    el.driver.recv_hold[c as usize].push_back(
                        crate::backend::uring::driver::PendingRecvBuf {
                            bid: 2,
                            len: 5,
                            ptr: std::ptr::null(),
                        },
                    );
                }),
            ),
        ] {
            let mut el = make_test_loop();
            let conn_index = accept_connection(&mut el);
            el.driver.park_offered[conn_index as usize] = true;
            assert_eq!(
                el.driver.park_blocker(conn_index),
                None,
                "{label}: precondition — parkable before the buffer is held"
            );
            place(&mut el, conn_index);
            assert_eq!(
                el.driver.park_blocker(conn_index),
                Some(ParkBlocker::DataPending),
                "{label}: unconsumed data means the offer is stale"
            );
        }
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
        let (tx, _rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(4);
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
        let (tx, _rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(4);
        let (_r0, w0) = crate::wakeup::create_wake_fd().expect("wake fd");
        let (_r1, w1) = crate::wakeup::create_wake_fd().expect("wake fd");
        el.driver.peer_park = vec![(tx.clone(), w0.as_wake_fd()), (tx, w1.as_wake_fd())];

        el.maybe_park_one();

        assert!(
            el.driver.park_in_flight[conn_index as usize].is_none(),
            "a balanced fleet must not move anything"
        );
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

        let (tx, rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(4);
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
        let generation = el.driver.connections.generation(conn_index);
        el.driver.park_offered[conn_index as usize] = true;
        el.driver
            .park_carry
            .insert(conn_index, ParkState::new(7u32));

        // Drive the real completion path — the withdrawal has to live on the
        // recv handler, not in a test-only helper. Same synthetic CQE shape
        // `deliver_segment` uses: F_BUFFER | F_MORE with the bid in the high
        // bits.
        let data = b"GET x";
        let bid: u16 = 0;
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr as *mut u8, data.len());
        }
        let flags = 1u32 | 2u32 | ((bid as u32) << 16);
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, flags);

        assert!(
            !el.driver.park_offered[conn_index as usize],
            "new data means a new request: the offer must be withdrawn"
        );
        assert!(
            !el.driver.park_carry.contains_key(&conn_index),
            "and the state with it, or it would be carried at the wrong moment"
        );
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

    /// TLS state does not travel yet, so parking would hand the peer an
    /// established session to a worker that knows nothing about it. Refused
    /// loudly rather than silently renegotiating.
    #[test]
    fn a_tls_connection_is_not_parkable_yet() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.park_offered[conn_index as usize] = true;
        install_handshaked_tls(&mut el, conn_index);
        assert_eq!(
            el.driver.park_blocker(conn_index),
            Some(ParkBlocker::TlsSession),
            "carrying the session is unimplemented, so park must refuse"
        );
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
        let (tx, _rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(1);
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
        let (tx, rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(4);
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
        let (tx, rx) = crossbeam_channel::bounded::<crate::park::ParkedFd>(4);
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

        // ECANCELED: the linked recv-cancel failed, so the install never ran.
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
        // park is idle by construction. Carrying leftovers was the earlier
        // design and is superseded — see
        // `held_ring_buffers_block_the_park_as_unconsumed_data`.
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

    // ── Opcode probe (tier 3, #443) ────────────────────────────────

    /// The guard that makes a *negative* park probe trustworthy.
    ///
    /// `Send` is a 5.6 opcode and the crate floor is 6.1, so every kernel
    /// that can run this backend has it. If this assertion ever fails, the
    /// probe mechanism itself is broken — and a broken probe does not look
    /// broken: it reports "unsupported" for everything, silently disabling
    /// park on kernels that support it perfectly well.
    #[test]
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
    fn park_support_matches_a_fresh_probe_of_the_opcode() {
        let el = make_test_loop();
        assert_eq!(
            el.driver.ring.supports_park(),
            el.driver
                .ring
                .probe_supported(io_uring::opcode::FixedFdInstall::CODE),
        );
    }

    // ── Park drain (tier 3, #443) ──────────────────────────────────

    /// Wire order is the property under test, and it is the one a
    /// "did the bytes survive" assertion would miss: the accumulator holds
    /// bytes that arrived before anything still held, and `segment_pinned`
    /// was popped from the front of `segment_hold`.
    #[test]
    fn the_park_drain_returns_bytes_in_wire_order() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.accumulators.append(conn_index, b"first");
        el.driver.segment_pinned[conn_index as usize] = Some(
            crate::backend::uring::driver::HeldRecvBuf::Owned(bytes::Bytes::from_static(b"second")),
        );
        el.driver.segment_hold[conn_index as usize].push_back(
            crate::backend::uring::driver::HeldRecvBuf::Owned(bytes::Bytes::from_static(b"third")),
        );
        el.driver.segment_hold[conn_index as usize].push_back(
            crate::backend::uring::driver::HeldRecvBuf::Owned(bytes::Bytes::from_static(b"fourth")),
        );

        let drained = el.driver.take_pending_for_park(conn_index);
        let joined: Vec<u8> = drained.iter().flat_map(|b| b.to_vec()).collect();
        assert_eq!(
            joined, b"firstsecondthirdfourth",
            "accumulator, then pinned, then held in FIFO order"
        );
    }

    #[test]
    fn the_park_drain_copies_pinned_bytes_and_returns_the_bid() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"payload");
        assert!(
            !el.driver.segment_hold[conn_index as usize].is_empty(),
            "precondition: the bytes are held as a bid, not already owned"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "precondition: the bid has not been returned yet"
        );

        let drained = el.driver.take_pending_for_park(conn_index);
        let joined: Vec<u8> = drained.iter().flat_map(|b| b.to_vec()).collect();
        assert_eq!(joined, b"payload", "the held bytes survive as owned copies");
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "the bid must go back to the ring, or park leaks a buffer per move"
        );
    }

    #[test]
    fn the_park_drain_leaves_every_holder_empty() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let idx = conn_index as usize;

        el.driver.accumulators.append(conn_index, b"acc");
        el.driver.segment_pinned[idx] = Some(crate::backend::uring::driver::HeldRecvBuf::Owned(
            bytes::Bytes::from_static(b"pin"),
        ));
        el.driver.segment_hold[idx].push_back(crate::backend::uring::driver::HeldRecvBuf::Owned(
            bytes::Bytes::from_static(b"held"),
        ));

        let _ = el.driver.take_pending_for_park(conn_index);

        assert!(el.driver.accumulators.is_empty(conn_index), "accumulator");
        assert!(el.driver.segment_pinned[idx].is_none(), "pin slot");
        assert!(el.driver.segment_hold[idx].is_empty(), "segment hold");
        assert!(el.driver.recv_hold[idx].is_empty(), "recv hold");
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
    fn handle_send_wakes_send_waiter() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Set up a send waiter.
        el.executor.send_waiters[conn_index as usize] = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        // Waiter should be cleared and result stored.
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "send result not stored"
        );
    }

    #[test]
    fn handle_send_multichunk_wakes_once_with_total() {
        // A logical send larger than one pool slot is split into several
        // chunks that complete as separate CQEs, but the connection has a
        // single send waiter. The waiter must be woken exactly once — when
        // the whole logical send has drained — reporting the full byte
        // count, not the first chunk's short count.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;

        // Chunk 0 is in flight; chunk 1 is queued behind it. Distinct sizes
        // so the summed total can't be mistaken for either chunk alone.
        let chunk0 = vec![b'a'; 16384];
        let chunk1 = vec![b'b'; 4096];
        let total = (chunk0.len() + chunk1.len()) as u32;
        let (slot0, _p0, _l0) = el.driver.send_copy_pool.copy_in(&chunk0).unwrap();
        let (slot1, ptr1, len1) = el.driver.send_copy_pool.copy_in(&chunk1).unwrap();
        // One logical send split across two slots: only the last is end-of-send.
        el.driver.send_copy_pool.set_end_of_send(slot0, false);
        el.driver.send_copy_pool.set_end_of_send(slot1, true);

        // Queue chunk 1 as a real BuiltSend behind the in-flight chunk 0.
        let ud1 = UserData::encode(OpTag::Send, conn_index, slot1 as u32);
        let entry1 = io_uring::opcode::Send::new(io_uring::types::Fixed(conn_index), ptr1, len1)
            .flags(crate::completion::STREAM_SEND_FLAGS)
            .build()
            .user_data(ud1.raw());
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(crate::handler::BuiltSend {
                entry: entry1,
                pool_slot: slot1,
                slab_idx: u16::MAX,
                total_len: chunk1.len() as u32,
            });
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // Chunk 0 completes. The waiter must NOT be woken yet.
        let ud0 = UserData::encode(OpTag::Send, conn_index, slot0 as u32);
        el.test_dispatch_cqe(ud0.raw(), chunk0.len() as i32, 0);
        assert!(
            el.executor.send_waiters[conn_index as usize],
            "send waiter woken on the first chunk of a multi-chunk send"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_none(),
            "send result stored before the logical send drained"
        );
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes,
            chunk0.len() as u32,
            "first chunk's bytes not accumulated"
        );

        // Chunk 1 completes and drains the queue. The waiter wakes once,
        // reporting the whole logical send, and the accumulator resets.
        el.test_dispatch_cqe(ud1.raw(), chunk1.len() as i32, 0);
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not woken after the queue drained"
        );
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Ok(n))) => assert_eq!(
                *n, total,
                "waiter woken with a short count instead of the full logical send"
            ),
            _ => panic!("expected Send(Ok(_)) result after the logical send drained"),
        }
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes, 0,
            "accumulator not reset after the logical send completed"
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
        let token = crate::handler::ConnToken::new(conn_index, generation);

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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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
    /// queues one entry per chunk, in order, with only the last chunk marked
    /// end-of-send (so the waiter is woken once with the full count).
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
        let token = crate::handler::ConnToken::new(conn_index, generation);

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
        let end_flags: Vec<bool> = state
            .queue
            .iter()
            .map(|b| el.driver.send_copy_pool.is_end_of_send(b.pool_slot))
            .collect();
        assert_eq!(
            end_flags,
            vec![false, false, false, true],
            "only the final chunk is end-of-send"
        );
        let lens: Vec<u32> = state.queue.iter().map(|b| b.total_len).collect();
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
        let entry = io_uring::opcode::Send::new(io_uring::types::Fixed(conn_index), ptr, len)
            .flags(crate::completion::STREAM_SEND_FLAGS)
            .build()
            .user_data(ud.raw());
        crate::handler::BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
            total_len: data.len() as u32,
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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

        // A send is in flight; behind it: one independent send (its own
        // logical send, so end-of-send) and then the two chunks of a second
        // logical send. The independent head keeps the coalescing run at
        // one entry, so this exercises the single-entry push path.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let head = built_copy_send(&mut el, conn_index, b"X");
        let chunk0 = built_copy_send(&mut el, conn_index, b"AA");
        let chunk1 = built_copy_send(&mut el, conn_index, b"BBB");
        el.driver
            .send_copy_pool
            .set_end_of_send(chunk0.pool_slot, false);
        el.driver
            .send_copy_pool
            .set_end_of_send(chunk1.pool_slot, true);
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
        el.driver
            .send_copy_pool
            .set_end_of_send(c0.pool_slot, false);
        el.driver
            .send_copy_pool
            .set_end_of_send(c1.pool_slot, false);
        el.driver.send_copy_pool.set_end_of_send(c2.pool_slot, true);
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
    /// the send waiter resolves `Err`, and the connection closes — the same
    /// shape as `drain_copy_retries`' give-up.
    #[test]
    fn send_retry_cap_fails_the_waiter_and_closes() {
        let mut el = make_test_loop_with_config(
            test_config_builder()
                .send_pool(8, 64)
                .build()
                .expect("valid config"),
        );
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnToken::new(conn_index, generation);
        el.executor.send_waiters[conn_index as usize] = true;
        el.executor.owner_task[conn_index as usize] = Some(conn_index);

        // The initial push and both retries are refused.
        el.driver.ring.force_push_failures(3);
        let result = {
            let mut ctx = el.driver.make_ctx();
            ctx.send(token, b"hello")
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
        assert!(el.executor.io_results[conn_index as usize].is_none());

        // Retry 2 fails: re-parked with attempts 2.
        el.drain_send_retries();
        assert_eq!(
            el.driver.pending_send_retries,
            vec![(conn_index, generation, 2)]
        );
        assert_eq!(el.driver.send_queues[conn_index as usize].queue.len(), 1);
        assert!(el.executor.io_results[conn_index as usize].is_none());

        // Retry 3 hits the cap: give up.
        el.drain_send_retries();
        assert!(el.driver.pending_send_retries.is_empty());
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Err(_))) => {}
            _ => panic!("expected the send waiter to be failed by the retry cap"),
        }
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
    /// then finalizes on their CQE. Without this, the Close SQE would race
    /// (or truncate) the parked send.
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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
        // Re-driving the finalize (as the loop's end-of-iteration drain and
        // `note_send_finalized` do) must still hold off.
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

        // The send CQE drains the queue and finalizes the deferred close.
        el.driver
            .ring
            .submit_and_wait(1)
            .expect("submit_and_wait failed");
        el.drain_completions();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            assert!(!state.in_flight);
            assert!(
                !state.close_pending,
                "the close must finalize after the CQE"
            );
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

    /// A queued recv-buffer forward owns a provided buffer, not a pool slot.
    /// Releasing the queue (give-up, force-finalize, slot reuse) must hand
    /// its bid back to the ring instead of leaking it.
    #[test]
    fn releasing_a_queued_recv_buf_forward_replenishes_its_bid() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let bid: u16 = 7;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, bid as u32);
        let entry =
            io_uring::opcode::Send::new(io_uring::types::Fixed(conn_index), std::ptr::null(), 0)
                .flags(crate::completion::STREAM_SEND_FLAGS)
                .build()
                .user_data(ud.raw());
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(crate::handler::BuiltSend {
                entry,
                pool_slot: u16::MAX,
                slab_idx: u16::MAX,
                total_len: 0,
            });
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let before = el.driver.pending_replenish.len();

        el.driver.drain_conn_send_queue(conn_index);

        assert!(el.driver.send_queues[conn_index as usize].queue.is_empty());
        assert_eq!(
            &el.driver.pending_replenish[before..],
            &[bid],
            "the queued forward's bid must be replenished on release"
        );
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

        // The retry pushes the head (each entry is its own logical send, so
        // the coalescing run stops at one); the second stays queued.
        el.drain_send_retries();
        {
            let state = &el.driver.send_queues[conn_index as usize];
            let slots: Vec<u16> = state.queue.iter().map(|b| b.pool_slot).collect();
            assert_eq!(slots, expected_slots[1..].to_vec());
            assert!(state.in_flight);
        }
        assert!(el.driver.pending_send_retries.is_empty());
    }

    #[test]
    fn handle_send_pipelined_independent_sends_wake_separately() {
        // Two independent conn.send() calls pipelined on one connection share
        // the per-connection send queue but each has its own waiter/result.
        // Unlike chunks of one logical send, each must wake with its own byte
        // count, not a running total. (Regression: joining two sends hung when
        // the fix woke once on queue-drain and conflated the two.)
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;

        // Each is its own logical send, so both slots are end-of-send (the
        // copy_in default).
        let a = b"HELLO";
        let b = b"WORLD";
        let (slot_a, _pa, _la) = el.driver.send_copy_pool.copy_in(a).unwrap();
        let (slot_b, ptr_b, len_b) = el.driver.send_copy_pool.copy_in(b).unwrap();

        // Send A is in flight; send B is queued behind it.
        let ud_b = UserData::encode(OpTag::Send, conn_index, slot_b as u32);
        let entry_b = io_uring::opcode::Send::new(io_uring::types::Fixed(conn_index), ptr_b, len_b)
            .flags(crate::completion::STREAM_SEND_FLAGS)
            .build()
            .user_data(ud_b.raw());
        el.driver.send_queues[conn_index as usize]
            .queue
            .push_back(crate::handler::BuiltSend {
                entry: entry_b,
                pool_slot: slot_b,
                slab_idx: u16::MAX,
                total_len: b.len() as u32,
            });
        el.driver.send_queues[conn_index as usize].in_flight = true;

        // A completes: its waiter wakes with A's own byte count, not accumulated.
        let ud_a = UserData::encode(OpTag::Send, conn_index, slot_a as u32);
        el.test_dispatch_cqe(ud_a.raw(), a.len() as i32, 0);
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Ok(n))) => {
                assert_eq!(*n, a.len() as u32, "send A woke with the wrong count")
            }
            _ => panic!("send A's waiter was not woken"),
        }

        // The future consumes A's result; the next send re-arms the waiter.
        el.executor.io_results[conn_index as usize] = None;
        el.executor.send_waiters[conn_index as usize] = true;

        // B completes: its waiter wakes with B's own count, not A + B.
        el.test_dispatch_cqe(ud_b.raw(), b.len() as i32, 0);
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Ok(n))) => {
                assert_eq!(*n, b.len() as u32, "send B woke with an accumulated count")
            }
            _ => panic!("send B's waiter was not woken"),
        }
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
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes, 0,
            "stale CQE must not credit bytes to the new occupant"
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
        // must survive until it lands.
        el.test_dispatch_cqe(ud.raw(), 100, 0);
        assert!(el.driver.send_slab.in_use(slab_idx));
        // Stale notification CQE: releases the entry.
        el.test_dispatch_cqe(ud.raw(), 0, 8);
        assert_eq!(
            el.driver.send_slab.free_count(),
            free_before + 1,
            "slab entry must be released after the stale notification"
        );
        assert_eq!(el.driver.send_queues[conn_index as usize].acked_bytes, 0);
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
        el.driver.send_queues[conn_index as usize].acked_bytes = 7;
        el.driver.close_notify_armed.push(conn_index);

        // Slot recycles; the activation path resets send state.
        el.driver.connections.release(conn_index);
        let reused = el.driver.connections.allocate().unwrap();
        assert_eq!(reused, conn_index);
        el.driver.reset_send_state(conn_index);

        let state = &el.driver.send_queues[conn_index as usize];
        assert!(!state.in_flight, "reused slot must not inherit in_flight");
        assert!(!state.close_pending);
        assert_eq!(state.acked_bytes, 0);
        assert!(!el.driver.close_notify_armed.contains(&conn_index));
    }

    /// After the Close SQE is submitted (close_submitted), a late partial
    /// send CQE must release its slot and fail the waiter instead of
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
            // Peer FIN with the close requested but not yet committed: the
            // deferred-close drain window this test exists to cover.
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
    #[test]
    fn close_defers_while_chain_active() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.chain_table.start(conn_index, 1, 100);
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "close must stay pending while the chain is active"
        );

        // The chain's operation CQE arrives and completes it.
        let event = el.driver.chain_table.on_operation_cqe(conn_index, 100);
        assert!(matches!(event, ChainEvent::Complete { .. }));
        el.fire_chain_complete(conn_index);
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "close must finalize once the chain drains"
        );
    }

    /// DriverCtx::close (the on_tick-context close) must defer behind an
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
            ctx.close(crate::handler::ConnToken::new(conn_index, generation));
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

        // The in-flight send completes; its CQE drives the deferred Close.
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), b"in flight".len() as i32, 0);
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

    #[test]
    fn handle_recv_multi_eof_closes_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Simulate EOF CQE (result == 0).
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        // Connection should be marked as closing.
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed after recv EOF"
        );
    }

    #[test]
    fn handle_recv_multi_stale_connection_replenishes_buffer() {
        let mut el = make_test_loop();

        // Don't allocate a connection — simulate stale CQE for conn_index 0.
        let replenish_before = el.driver.pending_replenish.len();

        // Simulate recv CQE with result > 0 and a buffer ID in flags.
        // IORING_CQE_F_BUFFER = 1 << 0, buffer ID in upper 16 bits of flags.
        let bid: u16 = 5;
        let flags = (1u32) | ((bid as u32) << 16); // CQE_F_BUFFER | bid
        let ud = UserData::encode(OpTag::RecvMulti, 0, 0);
        el.test_dispatch_cqe(ud.raw(), 100, flags);

        // Buffer should be replenished despite stale connection.
        assert_eq!(
            el.driver.pending_replenish.len(),
            replenish_before + 1,
            "buffer not replenished on stale connection CQE"
        );
        assert_eq!(el.driver.pending_replenish[0], bid);
    }

    // ── RecvMulti completion identity (generation) ─────────────────
    //
    // A multishot recv can outlive its connection: `try_finalize_close`
    // cancels it best-effort and drops the cancel when the SQ is full, so the
    // kernel's terminal completion can land after the `Close` CQE released the
    // slot and a new connection took the index. The arm-time generation in the
    // payload is what tells the two apart — `recv_multishot_armed` cannot, since
    // it is per-slot and `arm_recv` sets it again for the new occupant.
    // See `docs/recv-multi-identity-design.md`.

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
        el.driver.reset_segment_state(conn_index);
        el.driver.reset_send_state(conn_index);
        let reused = accept_connection(el);
        assert_eq!(
            reused, conn_index,
            "the free list must hand the same slot back"
        );
    }

    #[test]
    fn handle_recv_multi_stale_generation_error_does_not_touch_new_occupant() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let stale_generation = el.driver.connections.generation(conn_index);

        recycle_connection(&mut el, conn_index);
        assert_ne!(
            el.driver.connections.generation(conn_index),
            stale_generation,
            "slot reuse must bump the generation"
        );

        // The new occupant has a task parked on recv and no recorded error.
        el.executor.recv_waiters[conn_index as usize] = true;
        el.executor.recv_errors[conn_index as usize] = None;

        // The previous occupant's uncancelled multishot finally reports: a
        // terminal error completion (no `F_MORE`).
        let stale_ud = UserData::encode(OpTag::RecvMulti, conn_index, stale_generation);
        el.test_dispatch_cqe(stale_ud.raw(), -libc::ECONNRESET, 0);

        let conn = el
            .driver
            .connections
            .get(conn_index)
            .expect("the new occupant must still hold the slot");
        assert!(
            !conn.close_requested(),
            "stale completion closed the new occupant"
        );
        assert!(
            matches!(conn.read, ReadHalf::Open),
            "stale completion poisoned the new occupant's read half"
        );
        assert!(
            el.executor.recv_errors[conn_index as usize].is_none(),
            "stale completion recorded a recv error on the new occupant"
        );
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "stale completion woke the new occupant's recv waiter"
        );
    }

    #[test]
    fn handle_recv_multi_stale_generation_replenishes_buffer_once() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let stale_generation = el.driver.connections.generation(conn_index);

        recycle_connection(&mut el, conn_index);
        el.driver.pending_replenish.clear();
        let free_before = el.driver.provided_bufs.free();

        // A data-bearing completion for the dead connection: the kernel did
        // consume a provided buffer, so it must go back to the ring — but its
        // bytes must not reach the new occupant.
        let bid: u16 = 3;
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"stale".as_ptr(), buf_ptr as *mut u8, 5);
        }
        let flags = 1u32 | 2u32 | ((bid as u32) << 16); // F_BUFFER | F_MORE, bid
        let stale_ud = UserData::encode(OpTag::RecvMulti, conn_index, stale_generation);
        el.test_dispatch_cqe(stale_ud.raw(), 5, flags);

        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "the consumed provided buffer must be replenished exactly once"
        );
        assert_eq!(
            el.driver.provided_bufs.free(),
            free_before - 1,
            "the handout must be accounted exactly once"
        );
        assert!(
            el.driver.accumulators.data(conn_index).is_empty(),
            "stale bytes leaked into the new occupant's accumulator"
        );
        assert!(
            el.driver.pending_recv_bufs[conn_index as usize].is_none(),
            "stale buffer pinned in the new occupant's zero-copy slot"
        );

        // The accounting closes: replenishing restores the free count.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            free_before,
            "no leak, no double replenish"
        );
    }

    #[test]
    fn handle_recv_multi_stale_generation_leaves_armed_flag_set() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let stale_generation = el.driver.connections.generation(conn_index);

        recycle_connection(&mut el, conn_index);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        // A terminal (`!has_more`) completion at the previous generation must
        // not reach the prologue that clears `recv_multishot_armed` — otherwise
        // the close path would skip cancelling a multishot that is really armed.
        let stale_ud = UserData::encode(OpTag::RecvMulti, conn_index, stale_generation);
        el.test_dispatch_cqe(stale_ud.raw(), -libc::ECONNRESET, 0);

        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "stale completion disarmed the live occupant's multishot"
        );
    }

    #[test]
    fn handle_recv_multi_current_generation_after_reuse_is_delivered() {
        // The identity check must not over-reject: after the slot is reused, a
        // completion bearing the *current* generation is delivered normally.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_connection(&mut el, conn_index);
        let generation = el.driver.connections.generation(conn_index);
        assert_ne!(generation, 0, "the recycle must have bumped the generation");

        let bid: u16 = 0;
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), buf_ptr as *mut u8, 5);
        }
        let flags = 1u32 | 2u32 | ((bid as u32) << 16); // F_BUFFER | F_MORE, bid
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, generation);
        assert_eq!(
            ud.payload(),
            generation,
            "the RecvMulti payload carries the whole generation, untruncated"
        );
        el.test_dispatch_cqe(ud.raw(), 5, flags);

        let pending = el.driver.pending_recv_bufs[conn_index as usize]
            .expect("the live occupant's completion must be delivered");
        assert_eq!(pending.bid, bid);
        assert_eq!(pending.len, 5);
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

    /// #371: a close requested by the driver (peer FIN, read error, task
    /// exit) must not commit the Close SQE synchronously — the task gets its
    /// poll window first. The event loop's end-of-iteration drain of
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

    /// A cancel that lands after a close was requested is a no-op: the close
    /// owns the teardown (and its own recv cancel), and a read half the peer
    /// already finished must keep its `Eof { truncated }` for
    /// `eof_truncated()`. Before the state split the old `Closed` state
    /// covered both cases and `cancel` returned early.
    #[test]
    fn cancel_after_close_is_a_no_op_and_keeps_truncation() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.note_eof(true); // TLS FIN without close_notify
        }
        el.driver.close_connection(conn_index);
        let before = el.driver.pending_finalize_closes.len();
        {
            let mut ctx = el.driver.make_ctx();
            let _ = ctx.cancel(crate::handler::ConnToken::new(conn_index, generation));
        }
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert_eq!(
            cs.read,
            ReadHalf::Eof { truncated: true },
            "cancel after close must not relabel a finished read half"
        );
        assert_eq!(cs.recv_arm, RecvArm::Multi, "cancel after close is a no-op");
        assert!(cs.close_requested());
        assert_eq!(el.driver.pending_finalize_closes.len(), before);
    }

    /// Cancelling the receive (`DriverCtx::cancel`) finishes the read half
    /// but is not a close: a later `close_connection` must still tear the
    /// connection down. Before the state split, cancel set `Closed`, so the
    /// later close was a no-op and the slot leaked.
    #[test]
    fn cancel_then_close_still_requests_teardown() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        {
            let mut ctx = el.driver.make_ctx();
            let _ = ctx.cancel(crate::handler::ConnToken::new(conn_index, generation));
        }
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert!(cs.recv_finished(), "cancel finishes the read half");
        assert!(!cs.close_requested(), "cancel is not a close");

        el.driver.close_connection(conn_index);
        let cs = el.driver.connections.get(conn_index).unwrap();
        assert!(cs.close_requested(), "close after cancel must be honoured");
        assert!(el.driver.pending_finalize_closes.contains(&conn_index));
    }

    // ── Recv data delivery tests ───────────────────────────────────

    #[test]
    fn handle_recv_multi_data_appends_to_accumulator() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // The provided buffer ring has real buffers. Get a valid buffer ID.
        // We'll simulate a recv CQE that references buffer 0.
        let bid: u16 = 0;
        // IORING_CQE_F_BUFFER = 1, IORING_CQE_F_MORE = 2. bid in upper 16 bits.
        let flags = 1u32 | 2u32 | ((bid as u32) << 16);
        let bytes_received = 5i32;

        // Write test data into the buffer ring's backing memory so the
        // handler reads it into the accumulator.
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), buf_ptr as *mut u8, 5);
        }

        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), bytes_received, flags);

        // With zero-copy recv, first completion should be held in pending
        // buffer slot (not copied to accumulator). Accumulator should be empty.
        let data = el.driver.accumulators.data(conn_index);
        assert!(
            data.is_empty(),
            "data should NOT be in accumulator (zero-copy)"
        );

        let pending = el.driver.pending_recv_bufs[conn_index as usize];
        assert!(pending.is_some(), "pending recv buf should be set");
        let pending = pending.unwrap();
        assert_eq!(pending.bid, bid);
        assert_eq!(pending.len, bytes_received as u32);

        // Buffer should NOT be queued for replenish yet (deferred).
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "buffer should NOT be replenished yet (zero-copy deferred)"
        );
    }

    #[test]
    fn handle_recv_multi_handout_decrements_free_then_replenish_restores() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let entries = el.driver.provided_bufs.ring_entries();
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "all buffers free before any recv"
        );

        let bid: u16 = 0;
        let flags = 1u32 | 2u32 | ((bid as u32) << 16); // F_BUFFER | F_MORE, bid=0
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"hi".as_ptr(), buf_ptr as *mut u8, 2);
        }
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 2, flags);

        // Handout accounted: exactly one fewer free.
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries - 1,
            "recv handout must decrement free by one"
        );

        // The consume path returns the bid via replenish_batch; free is restored.
        el.driver.provided_bufs.replenish_batch(&[bid]);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "replenish must restore free (balanced accounting)"
        );
    }

    #[test]
    fn handle_recv_multi_segmented_holds_buffer_and_teardown_drains() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Opt this connection into segmented delivery.
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let entries = el.driver.provided_bufs.ring_entries();
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "all buffers free before any recv"
        );

        let bid: u16 = 0;
        let flags = 1u32 | 2u32 | ((bid as u32) << 16); // F_BUFFER | F_MORE, bid=0
        let bytes_received = 5i32;
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), buf_ptr as *mut u8, 5);
        }
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), bytes_received, flags);

        // (a) Buffer went to the segment hold, NOT the accumulator or the
        // single-buffer zero-copy slot, and is NOT queued for replenish.
        assert!(
            el.driver.accumulators.data(conn_index).is_empty(),
            "segmented recv must not append to the accumulator"
        );
        assert!(
            el.driver.pending_recv_bufs[conn_index as usize].is_none(),
            "segmented recv must not use the single-buffer zero-copy slot"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "held segment bid must NOT be replenished while held"
        );
        let hold = &el.driver.segment_hold[conn_index as usize];
        assert_eq!(hold.len(), 1, "buffer should be held in segment_hold");
        match &hold[0] {
            crate::backend::HeldRecvBuf::Pinned { bid: hbid, len } => {
                assert_eq!(*hbid, bid);
                assert_eq!(*len, bytes_received as u32);
            }
            crate::backend::HeldRecvBuf::Owned(_) => {
                panic!("above the reserve, delivery must be Pinned (zero-copy)")
            }
        }

        // (b) The held buffer is accounted against the ring's free count.
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries - 1,
            "held segment must decrement free by one"
        );

        // (c) Close does NOT drain the hold — a post-FIN reader must still be able
        // to consume the already-received bytes (see the data+FIN-loss regression
        // test). The held bid stays out of the ring.
        let generation = el.driver.connections.generation(conn_index);
        el.driver.close_connection(conn_index);
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            1,
            "close must NOT drain the segment hold (a reader may still consume it)"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "the held bid must not return to the ring at close time"
        );

        // (d) Teardown (the Close CQE → handle_close) reclaims any unconsumed held
        // buffers; committing the replenish restores the ring.
        let close_ud = UserData::encode(OpTag::Close, conn_index, generation);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert!(
            el.driver.segment_hold[conn_index as usize].is_empty(),
            "handle_close drains the unconsumed hold"
        );
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "handle_close queues the held bid for replenish"
        );
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "free must return to ring_entries after the held bid is replenished"
        );
    }

    // ── Segmented recv reader (SegmentReader / RecvSegment, Mode B2) ────

    /// A minimal no-op waker for driving `SegmentReader::next` in tests. The
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

    /// Deliver one segmented recv buffer to `conn_index` via a synthetic
    /// multishot-recv CQE (`bid`, `data`). The connection must already be in the
    /// `Segmented` domain. Mirrors the real `handle_recv_multi` hold path.
    fn deliver_segment(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        bid: u16,
        data: &[u8],
    ) {
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), buf_ptr as *mut u8, data.len());
        }
        let flags = 1u32 | 2u32 | ((bid as u32) << 16); // F_BUFFER | F_MORE
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, flags);
    }

    #[test]
    fn segment_reader_hands_out_segment_bytes_and_drop_replenishes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();

        // Opt in and deliver one buffer; it lands in the hold, not the accumulator.
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);

        // Drive the reader: next() moves the held buffer into the pin slot and
        // hands out a segment.
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected a segment from a non-empty hold"),
        };

        // (a) The segment derefs to the received bytes.
        with_driver_state(&mut el, || {
            assert_eq!(&seg[..], b"hello", "segment bytes must match received data");
            assert_eq!(seg.len(), 5);
            assert!(!seg.is_empty());
        });
        // Checked out: hold emptied into the pin slot, still one buffer outstanding.
        assert!(el.driver.segment_hold[conn_index as usize].is_empty());
        assert!(el.driver.segment_pinned[conn_index as usize].is_some());
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);

        // (b) Dropping the segment (in-poll / guarded) replenishes its bid and
        // clears the pin slot; committing the replenish restores the ring.
        with_driver_state(&mut el, || drop(seg));
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_none(),
            "drop clears pin slot"
        );
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "drop queues the bid for replenish"
        );
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "free restored after drop-replenish"
        );
    }

    #[test]
    fn segment_reader_next_parks_then_resumes_on_recv() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());

        // First poll: hold empty, connection open → parks as a recv waiter.
        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p1, std::task::Poll::Pending),
            "next parks on an empty hold"
        );
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "parked next registers a recv waiter"
        );

        // Simulate a recv arrival: the hold gets a buffer and wake_recv fires.
        deliver_segment(&mut el, conn_index, 0, b"world");
        assert!(
            !el.executor.recv_waiters[conn_index as usize],
            "wake_recv cleared the recv waiter on delivery"
        );

        // Second poll: the buffer is now held → resumes with a segment.
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected a segment after the simulated recv"),
        };
        with_driver_state(&mut el, || {
            assert_eq!(
                &seg[..],
                b"world",
                "resumed segment carries the delivered bytes"
            );
            drop(seg);
        });
    }

    /// Regression for the Mode B RecvSegment UAF: closing a connection while a
    /// `RecvSegment` is still checked out must NOT return its pinned bid to the
    /// ring. The segment's `deref` still reads that provided buffer, and a parked
    /// task can resume and read it before the `Close` CQE — recycling the bid at
    /// close time would let another connection's recv overwrite live data. The
    /// release is deferred: an in-poll drop (here) releases exactly once via the
    /// pin slot; teardown via `handle_close` is covered by the next test.
    #[test]
    fn close_while_segment_pinned_defers_bid_release() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Deliver and check out a segment so its bid sits in the pin slot.
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected a pinned segment"),
        };
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_some(),
            "segment is pinned"
        );

        // Close while the segment is still checked out: the bid must stay pinned.
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_some(),
            "close must not drain the pin slot while a live segment can read it"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "the pinned bid must not return to the ring at close time"
        );

        // The segment is still valid after close (reads its own buffer, not
        // recycled memory); dropping it in-poll then releases the bid exactly once.
        with_driver_state(&mut el, || {
            assert_eq!(
                &seg[..],
                b"hello",
                "the live segment still reads its own buffer after close"
            );
            drop(seg);
        });
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "in-poll drop after close replenishes the bid exactly once"
        );
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_none(),
            "the pin slot is cleared by the drop"
        );

        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "free returns to ring_entries — no leak, no double-replenish"
        );
    }

    /// The other Mode B UAF-fix half: when a connection is torn down (the `Close`
    /// CQE → `handle_close` → the future, and with it the segment, is dropped) the
    /// pinned bid must be reclaimed exactly once — the unguarded `RecvSegment::drop`
    /// during teardown no-ops (`CURRENT_DRIVER == None`), so `handle_close` does the
    /// release. Without it the bid would leak.
    #[test]
    fn handle_close_reclaims_pinned_segment_bid_on_teardown() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected a pinned segment"),
        };

        // Close, then let the Close CQE tear the connection down. The bid is still
        // pinned at close time; `handle_close` reclaims it.
        el.driver.close_connection(conn_index);
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "bid not returned at close time"
        );
        let close_ud = UserData::encode(OpTag::Close, conn_index, generation);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "handle_close reclaims the pinned segment bid exactly once"
        );

        // The slot is released; the now-stale segment's unguarded drop no-ops (no
        // double-replenish).
        drop(seg);
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "stale segment drop after teardown does not double-replenish"
        );
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "no leak, no double"
        );
    }

    /// Regression for the Mode B data+FIN-loss bug: a data CQE and the peer FIN can
    /// arrive in the same batch, so `close_connection` runs before the woken reader
    /// is polled. The already-received bytes must NOT be discarded — the reader must
    /// still deliver them, then report EOF.
    #[test]
    fn segment_reader_delivers_held_data_after_close_then_eof() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // A response buffer is received (held), then the peer FIN closes the conn
        // before the reader runs.
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"response");
        el.driver.close_connection(conn_index);

        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();

        // The reader still sees the held response — the data was not lost at close.
        {
            let mut fut = std::pin::pin!(reader.next());
            let seg = match with_driver_state(&mut el, || {
                let mut cx = std::task::Context::from_waker(&waker);
                fut.as_mut().poll(&mut cx)
            }) {
                std::task::Poll::Ready(Ok(Some(seg))) => seg,
                _ => panic!("expected the held response segment after close"),
            };
            with_driver_state(&mut el, || {
                assert_eq!(
                    &seg[..],
                    b"response",
                    "held response delivered after close, not lost"
                );
                drop(seg);
            });
        }

        // Next poll: hold drained + connection `Closed` → clean EOF.
        let mut fut = std::pin::pin!(reader.next());
        let eof = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            matches!(fut.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(None)))
        });
        assert!(eof, "reader reports EOF after draining the held data");
    }

    /// Medium: a second concurrent `SegmentReader` on the same connection must not
    /// overwrite the pin slot (which would orphan the first segment's bid — a ring
    /// leak). Its `next()` errors instead, consuming nothing.
    #[test]
    fn second_concurrent_segment_reader_errors_rather_than_leaking() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");

        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();

        // Reader A checks out the first segment → pins bid 0.
        let mut reader_a = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let mut fut_a = std::pin::pin!(reader_a.next());
        let seg_a = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut_a.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(s))) => s,
            _ => panic!("reader A: expected a pinned segment"),
        };
        assert!(matches!(
            el.driver.segment_pinned[conn_index as usize],
            Some(crate::backend::HeldRecvBuf::Pinned { bid: 0, .. })
        ));

        // Reader B is now refused at `segments()` rather than at its first poll:
        // the conflict is reported where it is caused, before a second reader
        // exists at all (#427 step 1). Previously this surfaced one poll later,
        // as an error from `next()`.
        // `expect_err` would require `SegmentReader: Debug`, which it is not.
        let err_b = match with_driver_state(&mut el, || conn.segments()) {
            Err(e) => e,
            Ok(_) => panic!("a second reader must be refused while A is live"),
        };
        assert_eq!(
            err_b.raw_os_error(),
            Some(libc::EBUSY),
            "a live reader refuses a second one with EBUSY"
        );
        assert!(
            matches!(
                el.driver.segment_pinned[conn_index as usize],
                Some(crate::backend::HeldRecvBuf::Pinned { bid: 0, .. })
            ),
            "reader A's bid stays pinned (not overwritten)"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            1,
            "reader B must not consume the held buffer on the error path"
        );

        // Cleanup: dropping A's segment releases bid 0 exactly once — no leak.
        with_driver_state(&mut el, || drop(seg_a));
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == 0)
                .count(),
            1,
        );
    }

    /// Medium: dropping a `SegmentReader` while the connection is still in the
    /// segmented domain (no explicit `end_segments`) auto-settles — held bytes are
    /// gathered into the accumulator and the default read path is restored — so a
    /// later ordinary read neither hangs nor loses data.
    #[test]
    fn segment_reader_drop_auto_settles_held_data() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");

        let conn = ConnCtx::new(conn_index, generation);
        // Create a reader, consume nothing, drop it — guarded (CURRENT_DRIVER set),
        // as it would be inside a real task poll.
        with_driver_state(&mut el, || {
            let reader = conn.segments().expect("segments()");
            drop(reader);
        });

        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::default(),
            "reader drop restores the default read path"
        );
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"helloworld",
            "held segments are gathered into the accumulator, in order, on drop"
        );
    }

    #[test]
    fn segment_reader_next_returns_none_at_eof() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Close the connection (recv side) with nothing held.
        el.driver.close_connection(conn_index);

        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let done = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            matches!(fut.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(None)))
        });
        assert!(
            done,
            "closed connection with an empty hold yields EOF (Ok(None))"
        );
    }

    // ── Segmented recv Mode C (into_owned / recv_owned_segment) ──────────

    #[test]
    fn recv_segment_into_owned_copies_and_replenishes_exactly_once() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Deliver and check out a segment so its bid sits in the pin slot.
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected a pinned segment"),
        };
        assert!(el.driver.segment_pinned[conn_index as usize].is_some());

        // into_owned: copies the bytes and releases the pin (take() → replenish).
        let owned = with_driver_state(&mut el, || seg.into_owned());
        assert_eq!(&owned[..], b"hello", "into_owned returns the correct bytes");

        // (a) The pin slot was taken and the bid queued for replenish — exactly once
        // (into_owned's take(), then `self` drop no-ops on the now-empty slot).
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_none(),
            "into_owned clears the pin slot"
        );
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "into_owned replenishes the bid exactly once (drop-after does not double)"
        );

        // (b) Commit the replenish, then overwrite the underlying buffer: the owned
        // Bytes must be unaffected — proving it is a real copy, not an alias.
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "free returns to ring_entries after into_owned's single replenish"
        );
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"XXXXX".as_ptr(), buf_ptr as *mut u8, 5);
        }
        assert_eq!(
            &owned[..],
            b"hello",
            "owned Bytes is a copy — still valid after the bid is replenished and reused"
        );
    }

    #[test]
    fn recv_owned_segment_copies_and_replenishes_at_delivery() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();

        // recv_owned_segment opts into segmented delivery itself.
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.recv_owned_segment()).expect("recv_owned_segment()")
        );
        // First poll opts in + parks (nothing delivered yet).
        let waker = noop_waker();
        let p0 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(p0, std::task::Poll::Pending));
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::Segmented,
            "recv_owned_segment sets the Segmented domain"
        );

        // Deliver a buffer; it lands in the hold and clears the waiter.
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"world");
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);

        // Second poll: COPY at delivery, bid replenished IMMEDIATELY (never pinned).
        let owned = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(b))) => b,
            other => panic!("expected owned bytes, got {other:?}"),
        };
        assert_eq!(&owned[..], b"world", "recv_owned_segment returns the bytes");

        // Never pinned — the copy IS the release.
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_none(),
            "recv_owned_segment must never pin a buffer"
        );
        assert!(
            el.driver.segment_hold[conn_index as usize].is_empty(),
            "the held buffer was consumed"
        );
        // Bid is queued for replenish while the caller STILL holds the owned Bytes.
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "bid replenished at delivery, before the owned Bytes is dropped"
        );
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "free already restored while the caller still holds the Bytes"
        );
        // And it is a real copy: reuse the buffer, owned Bytes is unaffected.
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        unsafe {
            std::ptr::copy_nonoverlapping(b"ZZZZZ".as_ptr(), buf_ptr as *mut u8, 5);
        }
        assert_eq!(&owned[..], b"world", "owned Bytes is a copy, not an alias");
    }

    #[test]
    fn recv_owned_segment_parks_then_resumes_on_recv() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.recv_owned_segment()).expect("recv_owned_segment()")
        );
        let waker = noop_waker();

        // First poll: hold empty, connection open → parks as a recv waiter.
        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p1, std::task::Poll::Pending),
            "parks on empty hold"
        );
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "parked recv_owned_segment registers a recv waiter"
        );

        // Simulate a recv arrival: the hold gets a buffer and wake_recv fires.
        deliver_segment(&mut el, conn_index, 0, b"again");
        assert!(
            !el.executor.recv_waiters[conn_index as usize],
            "wake_recv cleared the recv waiter on delivery"
        );

        // Second poll resumes with owned bytes.
        let owned = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(b))) => b,
            _ => panic!("expected owned bytes after the simulated recv"),
        };
        assert_eq!(&owned[..], b"again");
    }

    #[test]
    fn recv_owned_segment_returns_none_at_eof() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Close the connection (recv side) with nothing held.
        el.driver.close_connection(conn_index);

        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.recv_owned_segment()).expect("recv_owned_segment()")
        );
        let waker = noop_waker();
        let done = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            matches!(fut.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(None)))
        });
        assert!(
            done,
            "closed connection with an empty hold yields EOF (Ok(None))"
        );
    }

    /// Regression: a parked `recv_owned_segment` reader must resolve to
    /// `Ok(None)` when a peer-FIN (`result == 0`) multishot completion arrives
    /// while it is parked — matching `with_data`/`with_bytes` EOF behavior — and
    /// the provided-buffer accounting must stay balanced (no bid leak). Guards
    /// against a segmented reader hanging forever on a mid-stream peer close.
    #[test]
    fn parked_recv_owned_segment_resolves_none_on_fin_completion() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        // Model an armed multishot recv (accept_connection injects CQEs directly
        // and does not arm one).
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = true;
        }

        // Park the reader: empty hold, connection open → Pending + recv waiter.
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.recv_owned_segment()).expect("recv_owned_segment()")
        );
        let waker = noop_waker();
        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p1, std::task::Poll::Pending),
            "parks on empty hold"
        );
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "parked reader registers a recv waiter"
        );

        // Deliver a peer FIN: multishot recv completion with result == 0 and no
        // F_MORE. This must wake the parked reader and close the recv side.
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 0, 0);
        assert!(
            !el.executor.recv_waiters[conn_index as usize],
            "FIN wakes the parked segmented reader"
        );

        // Second poll now observes the closed recv side and resolves to EOF.
        let done = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            matches!(fut.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(None)))
        });
        assert!(done, "FIN while parked yields Ok(None), not a hang");

        // No held buffers were leaked: the ring's free count is fully restored.
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "provided-buffer accounting balanced after FIN + close"
        );

        // The self-terminated multishot must be marked disarmed (a FIN
        // completion carries no F_MORE), so the close path issues no needless
        // recv-cancel.
        let armed = el
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.recv_multishot_armed);
        assert!(
            armed != Some(true),
            "a FIN completion clears the armed flag"
        );
    }

    /// A *proactive* close (peer has NOT sent a FIN, so the multishot recv is
    /// still armed) must clear the armed flag as part of finalizing the close —
    /// the code path that cancels the still-armed recv so the kernel drops its
    /// socket reference and actually FINs the peer.
    #[test]
    fn proactive_close_clears_armed_recv_flag() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.recv_multishot_armed = true;
        }

        // No queued sends (accept_connection leaves the send queue empty).
        // close_connection registers the close; the event loop's
        // end-of-iteration drain finalizes it (submits the recv-cancel +
        // Close SQEs) — #371 moved that out of close_connection so the task
        // gets its poll window first. Run the drain here as the loop would.
        el.driver.close_connection(conn_index);
        assert_eq!(
            el.driver
                .connections
                .get(conn_index)
                .map(|c| c.recv_multishot_armed),
            Some(true),
            "requesting the close must not touch the armed recv before the drain"
        );
        let pending = std::mem::take(&mut el.driver.pending_finalize_closes);
        for idx in pending {
            el.driver.try_finalize_close(idx);
        }

        let armed = el
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.recv_multishot_armed);
        assert!(
            armed != Some(true),
            "finalizing a proactive close disarms (cancels) the still-armed recv"
        );
    }

    // ── Segmented recv B1 callback (with_segments / SegChain) ────────────

    /// (a) Two held buffers are presented to the callback IN ORDER; a callback
    /// that consumes everything replenishes both bids, leaves the accumulator
    /// empty, and restores the ring's free count.
    #[test]
    fn with_segments_presents_two_held_buffers_in_order_full_drain() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Two arrivals held in order.
        deliver_segment(&mut el, conn_index, 0, b"AAA");
        deliver_segment(&mut el, conn_index, 1, b"BBB");
        assert_eq!(el.driver.provided_bufs.free(), entries - 2);

        let seen: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_cb = Rc::clone(&seen);
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.with_segments(
            move |chain| {
                for s in chain.iter() {
                    seen_cb.borrow_mut().push(s.to_vec());
                }
                SegConsumed(chain.total_len()) // full drain
            }
        )));
        let waker = noop_waker();
        let n = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok(n)), got {other:?}"),
        };

        assert_eq!(n, 6, "full drain consumes all presented bytes");
        assert_eq!(
            *seen.borrow(),
            vec![b"AAA".to_vec(), b"BBB".to_vec()],
            "segments presented in arrival order"
        );
        assert!(
            el.driver.accumulators.data(conn_index).is_empty(),
            "full drain leaves the accumulator empty"
        );
        assert!(el.driver.segment_hold[conn_index as usize].is_empty());
        assert!(el.driver.pending_replenish.contains(&0));
        assert!(el.driver.pending_replenish.contains(&1));
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "both held bids replenished — free restored"
        );
    }

    /// (b) Under-drain: the callback consumes only part of the first buffer; the
    /// remainder of that buffer plus the un-reached buffer gather to the FRONT of
    /// the accumulator, in order, and both bids are replenished.
    #[test]
    fn with_segments_under_drain_gathers_remainder_to_accumulator_front() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");
        assert_eq!(el.driver.provided_bufs.free(), entries - 2);

        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.with_segments(|_chain| SegConsumed(3)))
        ); // consume "hel" only
        let waker = noop_waker();
        let n = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok(3)), got {other:?}"),
        };
        assert_eq!(n, 3);

        // Remainder "lo" + un-reached "world" now live contiguously at the front
        // of the accumulator, in order.
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"loworld",
            "under-drain remainder gathers to the accumulator front, in order"
        );
        assert!(
            el.driver.segment_hold[conn_index as usize].is_empty(),
            "hold is drained after settle"
        );
        assert!(el.driver.pending_replenish.contains(&0));
        assert!(el.driver.pending_replenish.contains(&1));
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "both bids replenished despite the gather — free restored"
        );
    }

    /// (c) Accumulator-first ordering: pre-seed the accumulator, then a held
    /// buffer arrives; the SegChain presents the accumulator bytes BEFORE the
    /// held buffer. A `SegConsumed(0)` (need-more) gathers everything and parks.
    #[test]
    fn with_segments_presents_accumulator_before_held_and_parks_on_need_more() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Pre-seed the accumulator, then hold a later-arriving buffer.
        assert!(el.driver.accumulators.append(conn_index, b"ACC"));
        deliver_segment(&mut el, conn_index, 0, b"HELD");

        let seen: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_cb = Rc::clone(&seen);
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.with_segments(
            move |chain| {
                for s in chain.iter() {
                    seen_cb.borrow_mut().push(s.to_vec());
                }
                SegConsumed(0) // need a bigger frame
            }
        )));
        let waker = noop_waker();
        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });

        assert!(
            matches!(p, std::task::Poll::Pending),
            "SegConsumed(0) parks for more data"
        );
        assert_eq!(
            *seen.borrow(),
            vec![b"ACC".to_vec(), b"HELD".to_vec()],
            "accumulator remainder presented BEFORE the held buffer"
        );
        assert!(
            el.executor.recv_waiters[conn_index as usize],
            "need-more registers a recv waiter"
        );
        // Everything gathered to the accumulator front, in order; hold empty.
        assert_eq!(el.driver.accumulators.data(conn_index), b"ACCHELD");
        assert!(el.driver.segment_hold[conn_index as usize].is_empty());
        assert!(el.driver.pending_replenish.contains(&0));
    }

    /// (d) Park on an empty hold, then resume when a buffer arrives; and EOF on a
    /// closed connection with nothing to present.
    #[test]
    fn with_segments_parks_then_resumes_and_reports_eof() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // with_segments opts into Segmented itself.
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn
            .with_segments(|chain| SegConsumed(chain.total_len()))));
        let waker = noop_waker();

        // First poll: nothing to present, connection open → parks.
        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(p1, std::task::Poll::Pending), "parks on empty");
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::Segmented,
            "with_segments sets the Segmented domain"
        );
        assert!(el.executor.recv_waiters[conn_index as usize]);

        // A buffer arrives; wake fires.
        deliver_segment(&mut el, conn_index, 0, b"data");
        assert!(!el.executor.recv_waiters[conn_index as usize]);

        // Second poll: resumes, consumes everything.
        let n = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok(4)), got {other:?}"),
        };
        assert_eq!(n, 4);
        assert!(el.driver.accumulators.data(conn_index).is_empty());

        // EOF: a fresh closed connection with nothing held yields Ok(0).
        let c2 = accept_connection(&mut el);
        let g2 = el.driver.connections.generation(c2);
        el.driver.recv_domain[c2 as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.close_connection(c2);
        let conn2 = ConnCtx::new(c2, g2);
        let mut eof = std::pin::pin!(with_driver_state(&mut el, || conn2
            .with_segments(|chain| SegConsumed(chain.total_len()))));
        let done = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            matches!(eof.as_mut().poll(&mut cx), std::task::Poll::Ready(Ok(0)))
        });
        assert!(
            done,
            "closed connection with an empty hold yields Ok(0) EOF"
        );
    }

    // ── Segmented recv low-water reserve (force-copy under ring pressure) ──

    /// (a) At/below the reserve, a segmented delivery is force-copied into an
    /// OWNED segment (correct bytes) and its bid is replenished IMMEDIATELY —
    /// holding an owned segment does not pin the ring, so `free()` recovers at
    /// delivery.
    #[test]
    fn segmented_force_copy_at_reserve_delivers_owned_and_replenishes_immediately() {
        // reserve == ring size (16): free is always <= reserve → every delivery
        // force-copies (Mode C).
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        let entries = el.driver.provided_bufs.ring_entries();
        assert_eq!(el.driver.provided_bufs.free(), entries);

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");

        // Held as an OWNED copy (not pinned), with the correct bytes.
        let hold = &el.driver.segment_hold[conn_index as usize];
        assert_eq!(hold.len(), 1, "buffer held in segment_hold");
        match &hold[0] {
            crate::backend::HeldRecvBuf::Owned(b) => {
                assert_eq!(&b[..], b"hello", "owned segment carries the received bytes")
            }
            crate::backend::HeldRecvBuf::Pinned { .. } => {
                panic!("at/below the reserve, delivery must be Owned (force-copy)")
            }
        }
        // The bid was replenished IMMEDIATELY (queued at delivery), before any
        // consumer runs — so the pinned-buffer count never grows under pressure.
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "force-copy replenishes the bid at delivery"
        );
        // Committing the queued replenish restores the full ring while the owned
        // segment is STILL held — proving the hold pins nothing.
        let to_replenish: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&to_replenish);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "holding an owned segment does not pin the ring — free recovered at delivery"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            1,
            "the owned segment is still held after its bid returned to the ring"
        );
    }

    /// (b) Above the reserve, delivery is still Pinned (zero-copy) as before — the
    /// bid is NOT replenished until consumed.
    #[test]
    fn segmented_zero_copy_when_ring_above_reserve_stays_pinned() {
        // reserve 4, ring 16: the first delivery leaves free = 15 > 4 → Pinned.
        let mut el = make_test_loop_with_config(config_with_reserve(4));
        let conn_index = accept_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        let entries = el.driver.provided_bufs.ring_entries();

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");

        let hold = &el.driver.segment_hold[conn_index as usize];
        assert_eq!(hold.len(), 1);
        match &hold[0] {
            crate::backend::HeldRecvBuf::Pinned { bid: hbid, len } => {
                assert_eq!(*hbid, bid);
                assert_eq!(*len, 5);
            }
            crate::backend::HeldRecvBuf::Owned(_) => {
                panic!("above the reserve, delivery must stay Pinned (zero-copy)")
            }
        }
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "a pinned delivery does not replenish while held"
        );
        // Pinned: the buffer is still outstanding.
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);
    }

    /// The half must actually be able to read.
    ///
    /// Regression for a self-inflicted deadlock: the `ConnCtx` segmented path
    /// refuses while a `RecvHalf` is out, and `RecvHalf::segments()` delegated
    /// straight to it — so the half, which holds that claim by construction,
    /// refused itself and every segmented read through it returned `EBUSY`.
    /// The full gate passed anyway, because nothing exercised the happy path.
    #[test]
    fn recv_half_can_actually_read_segments() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        deliver_segment(&mut el, conn_index, 0, b"hello");

        let conn = ConnCtx::new(conn_index, generation);
        let mut half = with_driver_state(&mut el, || conn.take_recv()).expect("take_recv");

        let waker = noop_waker();
        let mut reader = with_driver_state(&mut el, || half.segments())
            .expect("the half must be able to enter the segmented domain it owns");
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(s))) => s,
            std::task::Poll::Ready(Ok(None)) => panic!("half read EOF instead of the segment"),
            std::task::Poll::Ready(Err(e)) => panic!("half read errored: {e}"),
            std::task::Poll::Pending => panic!("half parked with a segment held"),
        };
        with_driver_state(&mut el, || assert_eq!(&seg[..], b"hello"));
        with_driver_state(&mut el, || drop(seg));
        drop(reader);
        with_driver_state(&mut el, || drop(half));
    }

    /// The owned-segment route through the half must work too.
    #[test]
    fn recv_half_can_actually_read_owned_segments() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        deliver_segment(&mut el, conn_index, 0, b"owned");

        let conn = ConnCtx::new(conn_index, generation);
        let mut half = with_driver_state(&mut el, || conn.take_recv()).expect("take_recv");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || half.recv_owned_segment())
                .expect("the half must be able to read owned segments")
        );
        match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(b))) => assert_eq!(&b[..], b"owned"),
            other => panic!("expected owned bytes through the half, got {other:?}"),
        }
    }

    /// `take_recv` hands out the read side exactly once, and dropping it hands
    /// the connection back.
    #[test]
    fn recv_half_is_exclusive_and_released_on_drop() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let conn = ConnCtx::new(conn_index, generation);

        let half = with_driver_state(&mut el, || conn.take_recv()).expect("first take_recv");
        assert!(el.driver.recv_half_taken[conn_index as usize]);

        match with_driver_state(&mut el, || conn.take_recv()) {
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EBUSY),
                "a second take_recv must be refused with EBUSY"
            ),
            Ok(_) => panic!("the read side was handed out twice"),
        }

        // The `ConnCtx` segmented path must defer to the half wherever the
        // signature can report it.
        match with_driver_state(&mut el, || conn.segments()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EBUSY)),
            Ok(_) => panic!("ConnCtx::segments() must not bypass a live RecvHalf"),
        }

        with_driver_state(&mut el, || drop(half));
        assert!(
            !el.driver.recv_half_taken[conn_index as usize],
            "dropping the half releases the claim"
        );
        let _again = with_driver_state(&mut el, || conn.take_recv())
            .expect("the half is available again after drop");
    }

    /// `split()` takes the read claim, so it is refused exactly like a second
    /// `take_recv`. The write half carries no claim of its own yet, so it is
    /// dropping the *read* half that makes the connection splittable again.
    #[test]
    fn split_is_refused_while_the_read_side_is_out() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let conn = ConnCtx::new(conn_index, generation);

        let (tx, rx) = with_driver_state(&mut el, || conn.split()).expect("first split");
        assert!(el.driver.recv_half_taken[conn_index as usize]);

        match with_driver_state(&mut el, || conn.split()) {
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EBUSY),
                "a second split must be refused with EBUSY"
            ),
            Ok(_) => panic!("the read side was handed out twice"),
        }

        // Dropping only the send half releases the *write* claim and leaves
        // the read claim alone — the reader is still live and still exclusive.
        //
        // The drop happens inside `with_driver_state` on purpose: both halves'
        // `Drop` go through `try_with_state`, so a half dropped with no driver
        // in scope cannot release anything. In production that is covered by
        // `clear_conn_claims` at the slot's recycle point; in a unit test there
        // is no recycle, so dropping outside the driver would strand the claim
        // and the re-split below would fail with `EBUSY`. It did, before this
        // was fixed.
        with_driver_state(&mut el, || drop(tx));
        assert!(
            el.driver.recv_half_taken[conn_index as usize],
            "dropping the send half must not release the read claim"
        );
        assert!(
            !el.driver.send_half_taken[conn_index as usize],
            "dropping the send half releases the write claim"
        );

        with_driver_state(&mut el, || drop(rx));
        assert!(!el.driver.recv_half_taken[conn_index as usize]);
        let _again = with_driver_state(&mut el, || conn.split()).expect("splittable again");
    }

    /// Taking the write side twice is refused, and dropping it hands it back.
    #[test]
    fn take_send_is_exclusive_and_released_on_drop() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let conn = ConnCtx::new(conn_index, generation);

        let tx = with_driver_state(&mut el, || conn.take_send()).expect("first take_send");
        assert!(el.driver.send_half_taken[conn_index as usize]);

        match with_driver_state(&mut el, || conn.take_send()) {
            Err(e) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EBUSY),
                "a second take_send must be refused with EBUSY"
            ),
            Ok(_) => panic!("the write side was handed out twice"),
        }

        // `split` needs both, so it is refused too — and must not strand the
        // read claim on its way out.
        match with_driver_state(&mut el, || conn.split()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EBUSY)),
            Ok(_) => panic!("split must not succeed while the write side is out"),
        }
        assert!(
            !el.driver.recv_half_taken[conn_index as usize],
            "a split refused on the write claim must release the read claim it took"
        );

        with_driver_state(&mut el, || drop(tx));
        assert!(!el.driver.send_half_taken[conn_index as usize]);
        let _again = with_driver_state(&mut el, || conn.take_send()).expect("available again");
    }

    /// A stale handle must not take the write side of the slot's new occupant.
    #[test]
    fn take_send_refuses_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));
        match with_driver_state(&mut el, || stale.take_send()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPIPE)),
            Ok(_) => panic!("a stale handle must not take the write side"),
        }
        assert!(
            !el.driver.send_half_taken[conn_index as usize],
            "a refused take_send must not leave a claim behind"
        );
    }

    /// A stale handle must not split the slot's new occupant, for the same
    /// reason it must not `take_recv` it.
    #[test]
    fn split_refuses_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));
        match with_driver_state(&mut el, || stale.split()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPIPE)),
            Ok(_) => panic!("a stale handle must not split the connection"),
        }
        assert!(
            !el.driver.recv_half_taken[conn_index as usize],
            "a refused split must not leave a claim behind"
        );
    }

    /// `end_segments()` through the half leaves the segmented domain, and the
    /// half keeps its read claim afterwards. Migrating the client crates needs
    /// this: redis/memcache call `end_segments` on the handle they hold.
    #[test]
    fn end_segments_through_the_half_restores_the_default_domain() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let conn = ConnCtx::new(conn_index, generation);

        let mut half = with_driver_state(&mut el, || conn.take_recv()).expect("take_recv");
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        with_driver_state(&mut el, || half.end_segments()).expect("end_segments through the half");
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::CopyOrConsume,
            "the half must return the connection to the default read path"
        );
        assert!(
            el.driver.recv_half_taken[conn_index as usize],
            "ending the segmented domain must not release the read claim"
        );

        // And the half is still the exclusive reader.
        match with_driver_state(&mut el, || conn.take_recv()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EBUSY)),
            Ok(_) => panic!("end_segments() must not hand the read side back"),
        }
        with_driver_state(&mut el, || drop(half));
    }

    /// A forward must refuse a sink whose write half somebody else owns.
    ///
    /// This is the "forward *or* send, not both" rule, enforced for the first
    /// time. It matters because a forward does **not** go through the sink's
    /// per-connection send queue — `resubmit_forward_writev` submits its own
    /// SQE straight to the ring — so a concurrent `send` to that socket
    /// interleaves with the forward's writes, and io_uring does not order
    /// independent SQEs (Domain Invariant 2). The result is a corrupted
    /// stream, not merely reordered messages.
    #[test]
    fn a_forward_refuses_a_sink_whose_send_half_is_out() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let src = accept_connection(&mut el);
        let sink = accept_connection(&mut el);
        let src_gen = el.driver.connections.generation(src);
        let sink_gen = el.driver.connections.generation(sink);
        el.driver.recv_domain[src as usize] = crate::recv::domain::RecvDomain::Segmented;
        deliver_segment(&mut el, src, 0, b"hello");

        let source = ConnCtx::new(src, src_gen);
        let sink_ctx = ConnCtx::new(sink, sink_gen);

        // Someone owns the sink's writes.
        let tx = with_driver_state(&mut el, || sink_ctx.take_send()).expect("take_send");

        let waker = noop_waker();
        let mut fut =
            std::pin::pin!(with_driver_state(&mut el, || source.forward_to_conn(&sink_ctx, 5)));
        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        match p {
            std::task::Poll::Ready(Err(e)) => assert_eq!(
                e.raw_os_error(),
                Some(libc::EBUSY),
                "forwarding into a sink someone else writes must be EBUSY"
            ),
            other => panic!("expected EBUSY, got {other:?}"),
        }
        assert!(
            el.driver.forward_progress[src as usize].is_none(),
            "a refused forward must not leave the source armed"
        );

        // Once the owner lets go, the same forward is allowed.
        with_driver_state(&mut el, || drop(tx));
        deliver_segment(&mut el, src, 1, b"hello");
        el.driver.recv_domain[src as usize] = crate::recv::domain::RecvDomain::Segmented;
        let mut fut2 =
            std::pin::pin!(with_driver_state(&mut el, || source.forward_to_conn(&sink_ctx, 5)));
        let p2 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut2.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p2, std::task::Poll::Pending),
            "with the write half released the forward arms, got {p2:?}"
        );
    }

    /// A stale handle must not put the slot's new occupant into the segmented
    /// domain.
    ///
    /// This is the #429 headline: `with_segments` used to flip
    /// `recv_domain[idx] = Segmented` eagerly at *call* time, with no
    /// generation check at all. The victim's own `with_data` reader never
    /// looks at `segment_hold`, so its bytes are stranded and it hangs with
    /// every health signal normal — #423, inflicted on a third party. The flip
    /// now happens on the first poll, behind the same gate every other
    /// segmented entry uses.
    #[test]
    fn with_segments_does_not_flip_a_stale_slots_domain() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));

        // Merely constructing the future must not touch the driver.
        let waker = noop_waker();
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || {
            stale.with_segments(|_chain| crate::SegConsumed(0))
        }));
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::CopyOrConsume,
            "constructing the future must not flip the domain"
        );

        // Nor must polling it.
        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p, std::task::Poll::Ready(Ok(0))),
            "a stale with_segments resolves as EOF, got {p:?}"
        );
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::CopyOrConsume,
            "the live occupant must still be on the default read path"
        );
    }

    /// A stale handle must not settle the slot's new occupant's hold.
    ///
    /// `end_segments` drains held segments into the accumulator and resets the
    /// delivery domain. Run against a recycled slot it does that to whoever
    /// owns it now — #423's shape, inflicted on a third party. See #429.
    #[test]
    fn end_segments_refuses_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));

        // The live occupant is in the segmented domain.
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        match with_driver_state(&mut el, || stale.end_segments()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPIPE)),
            Ok(()) => panic!("a stale handle must not end another connection's segmented domain"),
        }
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::Segmented,
            "the live occupant's delivery domain must be untouched"
        );
    }

    /// A stale handle must not read — or consume — the new occupant's bytes.
    ///
    /// `try_with_data` both hands the caller the accumulator's contents and
    /// advances it past what the closure consumed, so an ungated stale call
    /// leaks one connection's data to another and eats it. See #429.
    #[test]
    fn try_with_data_refuses_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
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

    /// A stale handle must not flip the new occupant into recv-forward mode:
    /// it would start holding its recv buffers for a forward nobody will issue.
    #[test]
    fn enable_recv_forward_ignores_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));

        with_driver_state(&mut el, || stale.enable_recv_forward());
        assert!(
            !el.driver.recv_forward[conn_index as usize],
            "a stale handle must not enable recv-forward on the new occupant"
        );
    }

    /// A stale handle must not take the read side of the slot's new occupant.
    #[test]
    fn take_recv_refuses_a_stale_handle() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let stale = ConnCtx::new(conn_index, generation.wrapping_add(1));
        match with_driver_state(&mut el, || stale.take_recv()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EPIPE)),
            Ok(_) => panic!("a stale handle must not take the read side"),
        }
        assert!(
            !el.driver.recv_half_taken[conn_index as usize],
            "a refused take must not leave a claim behind"
        );
    }

    /// A stale half must not steal the *new* occupant's claim.
    ///
    /// The claim is per slot and a half can outlive its connection (`spawn`
    /// needs only `'static`, not `Send`). If the slot recycles and the new
    /// occupant takes its own half, a stale half dropping afterwards must not
    /// clear that claim — doing so would permit a second `RecvHalf` on a live
    /// connection, which is the whole thing this type prevents.
    #[test]
    fn a_stale_recv_half_drop_does_not_steal_the_new_claim() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let old_gen = el.driver.connections.generation(conn_index);
        let old_conn = ConnCtx::new(conn_index, old_gen);
        let stale_half = with_driver_state(&mut el, || old_conn.take_recv()).expect("take_recv");

        // Recycle the slot, as teardown does.
        el.driver.clear_conn_claims(conn_index);
        el.driver.connections.release(conn_index);
        let new_index = accept_connection(&mut el);
        assert_eq!(new_index, conn_index, "the test needs the slot reused");
        let new_gen = el.driver.connections.generation(conn_index);
        assert_ne!(new_gen, old_gen, "release must bump the generation");

        // New occupant claims the read side.
        let new_conn = ConnCtx::new(conn_index, new_gen);
        let _new_half = with_driver_state(&mut el, || new_conn.take_recv())
            .expect("the new occupant takes its own half");
        assert!(el.driver.recv_half_taken[conn_index as usize]);

        // The stale half finally drops.
        with_driver_state(&mut el, || drop(stale_half));

        assert!(
            el.driver.recv_half_taken[conn_index as usize],
            "a stale half must not release the new occupant's claim"
        );
        match with_driver_state(&mut el, || new_conn.take_recv()) {
            Err(e) => assert_eq!(e.raw_os_error(), Some(libc::EBUSY)),
            Ok(_) => panic!("two live RecvHalfs on one connection"),
        }
    }

    /// A claim must not outlive the slot it was made on.
    ///
    /// `RecvHalf::drop` and `SegmentReader::drop` both release through
    /// `try_with_state`, which is a no-op during unguarded teardown — so a
    /// claim can survive its claimant. The flags are indexed by slot, not by
    /// generation, so without an explicit clear at the recycle point the *next*
    /// occupant inherits the claim and has its reads refused forever.
    #[test]
    fn recv_claims_do_not_survive_slot_reuse() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);

        // Simulate the claims outliving their owners, which is what an
        // unguarded teardown produces.
        el.driver.recv_half_taken[conn_index as usize] = true;
        el.driver.segment_reader_live[conn_index as usize] = true;

        el.driver.clear_conn_claims(conn_index);

        assert!(
            !el.driver.recv_half_taken[conn_index as usize],
            "a recycled slot must not inherit a recv-half claim"
        );
        assert!(
            !el.driver.segment_reader_live[conn_index as usize],
            "a recycled slot must not inherit a reader claim"
        );
    }

    /// A segmented reader must deliver bytes that are sitting in the
    /// accumulator rather than parking forever (#423).
    ///
    /// The accumulator is invisible to a segmented reader, so this state used
    /// to hang with every health signal normal. It is reachable from legal
    /// compositions — `SegmentReader::drop` settles the hold into the
    /// accumulator, and `with_segments` leaves its remainder there — so the
    /// reader adopts rather than asserting.
    ///
    /// This covers `adopt_stranded_accumulator`, which the end-to-end test
    /// cannot reach: there, entry-time adoption has already drained the
    /// accumulator.
    #[test]
    fn segmented_reader_adopts_bytes_stranded_in_the_accumulator() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        // Order matters. `segments()` adopts at entry, so stranding the bytes
        // first would leave the poll-entry path with nothing to do and test the
        // wrong thing. Install the reader first, *then* strand — which is what
        // a settle (`SegmentReader::drop`, `with_segments`) actually does.
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");

        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        assert!(
            el.driver.accumulators.append(conn_index, b"stranded"),
            "accumulator append"
        );
        assert!(
            el.driver.segment_hold[conn_index as usize].is_empty(),
            "hold must be empty so only the accumulator can satisfy this read"
        );

        use metriken::CounterGroupMetric;
        let before = crate::metrics::POOL
            .counter_value(crate::metrics::pool::SEGMENT_STRANDED_ADOPTED)
            .unwrap_or(0);
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let got = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            // `RecvSegment` has no `Debug`, so describe the outcome instead of
            // formatting it.
            std::task::Poll::Ready(Ok(None)) => {
                panic!("reader reported EOF instead of adopting the stranded bytes")
            }
            std::task::Poll::Ready(Err(e)) => panic!("reader errored: {e}"),
            std::task::Poll::Pending => {
                panic!("reader parked on stranded bytes instead of adopting them")
            }
        };
        with_driver_state(&mut el, || {
            assert_eq!(&got[..], b"stranded", "the stranded bytes, in order");
        });
        drop(got);

        assert!(
            el.driver.accumulators.is_empty(conn_index),
            "the accumulator must be drained by the adopt"
        );
        assert!(
            crate::metrics::POOL
                .counter_value(crate::metrics::pool::SEGMENT_STRANDED_ADOPTED)
                .unwrap_or(0)
                > before,
            "the adopt must be counted — it is the only way this is visible in production"
        );
    }

    /// (c1) An owned held segment consumed via the reader returns the correct
    /// bytes, never enters the pin slot, and its drop replenishes nothing (no
    /// bid) — the ring stays balanced with no double-replenish.
    #[test]
    fn owned_segment_via_reader_returns_bytes_and_drop_does_not_replenish() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        // Commit the force-copy's delivery-time replenish so the ring is full.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), entries);

        // Read the owned segment out via the lending-iterator reader.
        let conn = ConnCtx::new(conn_index, generation);
        let mut reader = with_driver_state(&mut el, || conn.segments()).expect("segments()");
        let waker = noop_waker();
        let mut fut = std::pin::pin!(reader.next());
        let seg = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(seg))) => seg,
            _ => panic!("expected an owned segment from the hold"),
        };
        with_driver_state(&mut el, || {
            assert_eq!(&seg[..], b"hello", "owned segment derefs to the bytes");
            assert_eq!(seg.len(), 5);
        });
        // Owned segments never use the pin slot.
        assert!(
            el.driver.segment_pinned[conn_index as usize].is_none(),
            "owned segment must not occupy the pin slot"
        );
        // Drop the owned segment: no bid, so nothing is replenished.
        with_driver_state(&mut el, || drop(seg));
        assert!(
            el.driver.pending_replenish.is_empty(),
            "dropping an owned segment replenishes nothing"
        );
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "ring stays balanced (no double-replenish)"
        );
    }

    /// (c2) An owned held segment consumed via `recv_owned_segment` returns the
    /// correct bytes and does not replenish a second time (the bid was already
    /// returned at delivery).
    #[test]
    fn recv_owned_segment_over_owned_hold_returns_bytes_no_double_replenish() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"world");
        // Force-copy queued the bid exactly once at delivery; do NOT commit yet so
        // we can prove the consume path does not queue it again.
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1
        );

        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.recv_owned_segment()).expect("recv_owned_segment()")
        );
        let waker = noop_waker();
        let owned = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(Some(b))) => b,
            other => panic!("expected owned bytes, got {other:?}"),
        };
        assert_eq!(&owned[..], b"world");
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "consuming an owned hold entry must not replenish its bid again"
        );
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), entries, "balanced");
    }

    /// (c3) `with_segments` over two OWNED held buffers presents them in order,
    /// full-drains, and replenishes nothing at settle (owned entries hold no bid)
    /// — the ring stays balanced.
    #[test]
    fn with_segments_owned_entries_full_drain_replenishes_nothing() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        deliver_segment(&mut el, conn_index, 0, b"AAA");
        deliver_segment(&mut el, conn_index, 1, b"BBB");
        // Both force-copied: each queued its bid at delivery. Commit them so the
        // ring is full before consuming.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        assert_eq!(r.len(), 2, "both force-copied bids queued at delivery");
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), entries);

        let seen: Rc<RefCell<Vec<Vec<u8>>>> = Rc::new(RefCell::new(Vec::new()));
        let seen_cb = Rc::clone(&seen);
        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.with_segments(
            move |chain| {
                for s in chain.iter() {
                    seen_cb.borrow_mut().push(s.to_vec());
                }
                SegConsumed(chain.total_len())
            }
        )));
        let waker = noop_waker();
        let n = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok(6)), got {other:?}"),
        };
        assert_eq!(n, 6);
        assert_eq!(
            *seen.borrow(),
            vec![b"AAA".to_vec(), b"BBB".to_vec()],
            "owned segments presented in arrival order"
        );
        assert!(el.driver.accumulators.data(conn_index).is_empty());
        assert!(el.driver.segment_hold[conn_index as usize].is_empty());
        assert!(
            el.driver.pending_replenish.is_empty(),
            "owned settle replenishes nothing (bids already returned at delivery)"
        );
        assert_eq!(el.driver.provided_bufs.free(), entries, "ring balanced");
    }

    /// (c4) `with_segments` under-drain over an OWNED held buffer copies the
    /// remainder from the owned bytes into the accumulator front, in order, and
    /// replenishes nothing.
    #[test]
    fn with_segments_owned_under_drain_gathers_remainder_from_owned_bytes() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), entries);

        let conn = ConnCtx::new(conn_index, generation);
        let mut fut = std::pin::pin!(
            with_driver_state(&mut el, || conn.with_segments(|_chain| SegConsumed(3)))
        ); // consume "hel" only
        let waker = noop_waker();
        let n = match with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        }) {
            std::task::Poll::Ready(Ok(n)) => n,
            other => panic!("expected Ready(Ok(3)), got {other:?}"),
        };
        assert_eq!(n, 3);
        assert_eq!(
            el.driver.accumulators.data(conn_index),
            b"loworld",
            "under-drain remainder gathered from the owned bytes, in order"
        );
        assert!(el.driver.segment_hold[conn_index as usize].is_empty());
        assert!(
            el.driver.pending_replenish.is_empty(),
            "owned under-drain settle replenishes nothing"
        );
        assert_eq!(el.driver.provided_bufs.free(), entries, "balanced");
    }

    /// (d) Tearing down a connection with an OWNED segment still held must not
    /// double-replenish: the owned entry carries no bid (already returned at
    /// delivery), so draining it at `handle_close` queues no replenish.
    #[test]
    fn close_with_owned_segment_held_does_not_double_replenish() {
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        // The bid was queued exactly once at delivery (force-copy).
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1
        );
        assert!(matches!(
            el.driver.segment_hold[conn_index as usize][0],
            crate::backend::HeldRecvBuf::Owned(_)
        ));

        // Close leaves the hold for a possible reader; teardown drains it. The
        // owned entry carries no bid, so neither step re-queues a replenish.
        el.driver.close_connection(conn_index);
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            1,
            "close must not drain the hold"
        );
        let close_ud = UserData::encode(OpTag::Close, conn_index, generation);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert!(
            el.driver.segment_hold[conn_index as usize].is_empty(),
            "handle_close drains the owned hold"
        );
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "teardown must NOT re-queue an owned entry's bid (no bid to return)"
        );
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "exactly one replenish — no leak, no double"
        );
    }

    // ── Segmented recv Mode A (forward_to / ForwardWrite) ────────────────

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

    fn temp_file() -> (std::fs::File, std::path::PathBuf) {
        let mut path = std::env::temp_dir();
        let uniq = format!(
            "ringline-forward-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(uniq);
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("temp file");
        (f, path)
    }

    /// A connection sink: the write goes to the sink's slot, and the forward
    /// resolves on its completion exactly as a descriptor sink does.
    #[test]
    fn forward_to_conn_writes_to_the_sink_connection() {
        let mut el = make_test_loop();
        let src = accept_connection(&mut el);
        let sink = accept_connection(&mut el);
        let src_gen = el.driver.connections.generation(src);
        let sink_gen = el.driver.connections.generation(sink);
        el.driver.recv_domain[src as usize] = crate::recv::domain::RecvDomain::Segmented;
        deliver_segment(&mut el, src, 0, b"hello");

        let source = ConnCtx::new(src, src_gen);
        let sink_ctx = ConnCtx::new(sink, sink_gen);
        let waker = noop_waker();
        let mut fut =
            std::pin::pin!(with_driver_state(&mut el, || source.forward_to_conn(&sink_ctx, 5)));

        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(p1, std::task::Poll::Pending));
        let st = el.driver.forward_write[src as usize]
            .as_ref()
            .expect("write in flight");
        assert!(
            matches!(
                st.target,
                crate::backend::uring::driver::SinkTarget::Conn { index, .. } if index == sink
            ),
            "the write must target the sink connection's slot"
        );

        let ud = UserData::encode(OpTag::ForwardWrite, src, src_gen);
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        let p2 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(p2, std::task::Poll::Ready(Ok(5))));
    }

    /// A stale sink handle must not write. Slots recycle, so a forward started
    /// against a closed-and-reused sink would deliver this stream to whoever
    /// owns that slot now — silently, and to the wrong peer.
    #[test]
    fn forward_to_conn_refuses_a_recycled_sink_slot() {
        let mut el = make_test_loop();
        let src = accept_connection(&mut el);
        let sink = accept_connection(&mut el);
        let src_gen = el.driver.connections.generation(src);
        let stale_gen = el.driver.connections.generation(sink).wrapping_add(1);
        el.driver.recv_domain[src as usize] = crate::recv::domain::RecvDomain::Segmented;
        let entries = el.driver.provided_bufs.ring_entries();
        deliver_segment(&mut el, src, 0, b"hello");

        let source = ConnCtx::new(src, src_gen);
        let stale_sink = ConnCtx::new(sink, stale_gen);
        let waker = noop_waker();
        let mut fut =
            std::pin::pin!(with_driver_state(&mut el, || source.forward_to_conn(&stale_sink, 5)));

        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        match p {
            std::task::Poll::Ready(Err(e)) => {
                assert_eq!(e.raw_os_error(), Some(libc::EPIPE), "stale sink is EPIPE")
            }
            other => panic!("expected EPIPE, got {other:?}"),
        }
        assert!(
            el.driver.forward_write[src as usize].is_none(),
            "nothing may be left in flight"
        );
        // The held buffer's bid has to come back, or a refused forward leaks a
        // provided buffer per attempt.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "the refused write must release its backing"
        );
    }

    /// (a) Forward a held buffer to a socket sink: the first poll pops the
    /// buffer, submits a write, and parks with the bid held; the write CQE
    /// releases the bid exactly once and the future resolves with the bytes
    /// forwarded, resetting the delivery domain and restoring `free()`.
    #[test]
    fn forward_to_socket_releases_bid_on_write_cqe_and_resolves() {
        use std::os::fd::AsFd;
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);

        let (sink, _peer) = make_socketpair();
        let sinkfd = crate::runtime::io::SinkFd::socket(sink.as_fd());
        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();

        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.forward_to(&sinkfd, 5)));

        // First poll: pops the held buffer, submits a write, parks.
        let p1 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p1, std::task::Poll::Pending),
            "parks on the write CQE"
        );
        assert!(
            el.driver.forward_write[conn_index as usize].is_some(),
            "one write recorded in flight"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "bid stays held while the write is in flight"
        );
        assert_eq!(el.driver.provided_bufs.free(), entries - 1);

        // Simulate the write CQE (all 5 bytes).
        let ud = UserData::encode(OpTag::ForwardWrite, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        assert!(
            el.driver.forward_write[conn_index as usize].is_none(),
            "in-flight state cleared on completion"
        );
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "the write CQE replenishes the held bid exactly once"
        );
        assert_eq!(el.driver.forward_done[conn_index as usize], Some(Ok(5)));

        // Re-poll: forwarded == len → resolves, domain reset.
        let p2 = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p2, std::task::Poll::Ready(Ok(5))),
            "resolves with bytes forwarded"
        );
        assert_eq!(
            el.driver.recv_domain[conn_index as usize],
            crate::recv::domain::RecvDomain::default(),
            "delivery domain reset after the forward"
        );
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), entries, "free restored");
    }

    /// (b) File sink: a short write resubmits the remainder at the advanced
    /// offset (`written` advances, the bid stays held), and the running file
    /// offset advances across buffers (`base_offset == bytes forwarded so far`).
    #[test]
    fn forward_to_file_short_write_resubmits_and_offset_advances() {
        use std::os::fd::AsFd;
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Two 5-byte buffers; forward all 10 bytes.
        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");
        assert_eq!(el.driver.provided_bufs.free(), entries - 2);

        let (file, path) = temp_file();
        let sinkfd = crate::runtime::io::SinkFd::file(file.as_fd()).expect("buffered file ok");
        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.forward_to(&sinkfd, 10)));

        // Poll: both held buffers go out as ONE gathered writev at offset 0.
        // (Before gathering this submitted buffer 0 alone, `total == 5`.)
        let _ = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        {
            let st = el.driver.forward_write[conn_index as usize]
                .as_ref()
                .unwrap();
            assert!(st.target.is_file());
            assert_eq!(st.base_offset, 0, "the batch writes from offset 0");
            assert_eq!(st.total, 10, "both held buffers in one write");
            assert_eq!(st.backings.len(), 2, "gathered, not one buffer per write");
            assert_eq!(st.iovecs.len(), 2, "one iovec per backing");
        }

        // Short write: 3 of 10 bytes. The remainder resubmits from *inside*
        // buffer 0, so its bid is still held and the rebuilt iovec array starts
        // mid-buffer.
        let ud = UserData::encode(OpTag::ForwardWrite, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        {
            let st = el.driver.forward_write[conn_index as usize]
                .as_ref()
                .expect("still in flight after a short write");
            assert_eq!(st.written, 3, "short write advanced `written`");
            assert_eq!(st.total, 10);
            assert_eq!(
                st.iovecs.iter().map(|v| v.iov_len).sum::<usize>(),
                7,
                "the rebuilt iovecs cover exactly the bytes still owed"
            );
        }
        assert!(
            !el.driver.pending_replenish.contains(&0),
            "bid 0 stays held across the short-write resubmit"
        );

        // A further short write that finishes buffer 0 and part of buffer 1:
        // no bid comes back yet, because the batch completes as a unit.
        el.test_dispatch_cqe(ud.raw(), 4, 0);
        assert!(
            el.driver.pending_replenish.is_empty(),
            "a batch releases its bids together, on full completion"
        );
        {
            let st = el.driver.forward_write[conn_index as usize]
                .as_ref()
                .expect("still in flight");
            assert_eq!(st.written, 7);
            assert_eq!(
                st.iovecs.len(),
                1,
                "buffer 0 is fully written, so it drops out of the iovecs"
            );
        }

        // The last 3 bytes complete the batch.
        el.test_dispatch_cqe(ud.raw(), 3, 0);
        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(
            matches!(p, std::task::Poll::Ready(Ok(10))),
            "forwarded all 10 bytes"
        );
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "both bids restored"
        );
        let _ = std::fs::remove_file(path);
    }

    /// (c) Under ring pressure the forward path force-copies at delivery (Mode C
    /// backing): the bid returns to the ring immediately, so a slow sink cannot
    /// deplete the shared ring, and the owned backing's write completion does not
    /// double-replenish.
    #[test]
    fn forward_to_owned_backing_does_not_double_replenish() {
        use std::os::fd::AsFd;
        let mut el = make_test_loop_with_config(config_with_reserve(16));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        // Below the reserve → force-copy: the bid is replenished at delivery.
        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        assert!(matches!(
            el.driver.segment_hold[conn_index as usize][0],
            crate::backend::HeldRecvBuf::Owned(_)
        ));
        // Commit the delivery-time replenish so `free()` reflects the ring is not
        // depleted by the (owned) held buffer.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "force-copy returned the bid — the forwarding conn did not deplete the ring"
        );

        let (sink, _peer) = make_socketpair();
        let sinkfd = crate::runtime::io::SinkFd::socket(sink.as_fd());
        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.forward_to(&sinkfd, 5)));

        let _ = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        // Complete the write of the owned backing.
        let ud = UserData::encode(OpTag::ForwardWrite, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        assert!(
            el.driver.pending_replenish.is_empty(),
            "owned backing carries no bid — the write CQE replenishes nothing"
        );
        let p = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(matches!(p, std::task::Poll::Ready(Ok(5))));
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "no double replenish"
        );
    }

    /// (d) Close mid-forward must NOT return the in-flight write's source bid to
    /// the ring while the kernel is still reading it (invariant #1). Regression
    /// for the CRITICAL Mode A UAF: `close_connection` cancels the write and holds
    /// the backing until the (ECANCELED) CQE lands, which releases the bid exactly
    /// once and drives the deferred close. Returning the bid at close time would
    /// let another connection's recv overwrite a buffer the kernel is still
    /// DMA-reading.
    #[test]
    fn close_mid_forward_defers_bid_release_until_write_cqe() {
        use std::os::fd::AsFd;
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;

        let bid: u16 = 0;
        deliver_segment(&mut el, conn_index, bid, b"hello");
        let (sink, _peer) = make_socketpair();
        let sinkfd = crate::runtime::io::SinkFd::socket(sink.as_fd());
        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.forward_to(&sinkfd, 5)));
        let _ = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        assert!(el.driver.forward_write[conn_index as usize].is_some());
        assert!(!el.driver.pending_replenish.contains(&bid));

        // Close while the write is in flight: the backing is STILL held (the
        // kernel is reading it) and the bid is NOT yet back in the ring.
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.forward_write[conn_index as usize].is_some(),
            "close must not drain the in-flight forward write early — the kernel \
             still owns its source buffer"
        );
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "the in-flight source bid must not return to the ring before the write CQE"
        );

        // The cancelled write's CQE (ECANCELED) lands: now the kernel is done, so
        // the bid is replenished exactly once and the deferred close proceeds.
        let ud = UserData::encode(OpTag::ForwardWrite, conn_index, generation);
        el.test_dispatch_cqe(ud.raw(), -libc::ECANCELED, 0);
        assert!(
            el.driver.forward_write[conn_index as usize].is_none(),
            "the write CQE releases the backing"
        );
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "the write CQE replenishes the in-flight bid exactly once"
        );

        // A further stale write CQE for the (now released) occupant must no-op.
        el.test_dispatch_cqe(ud.raw(), 5, 0);
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == bid)
                .count(),
            1,
            "a stale forward-write CQE does not double-replenish"
        );
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "no leak, no double"
        );
    }

    /// Mode A hold cap: mark a connection as a forwarder, arm its recv, and
    /// deliver segments. The throttle engages *exactly* at the cap (not before):
    /// below the cap the recv stays un-throttled, and reaching the cap sets the
    /// throttle flag (cancelling the multishot — `recv_multishot_armed` stays set
    /// until the ECANCELED CQE clears it, gating re-arm).
    #[test]
    fn forward_hold_cap_throttles_recv_at_cap() {
        let cap = 4;
        let mut el = make_test_loop_with_config(config_with_forward_cap(cap));
        let conn_index = accept_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        // Below the cap: no throttle, still armed.
        for bid in 0..(cap - 1) as u16 {
            deliver_segment(&mut el, conn_index, bid, b"x");
        }
        assert!(
            !el.driver.forward_hold_throttled[conn_index as usize],
            "not throttled below the cap"
        );
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "recv stays armed below the cap"
        );

        // Reaching the cap engages the throttle (cancel submitted).
        deliver_segment(&mut el, conn_index, (cap - 1) as u16, b"x");
        assert!(
            el.driver.forward_hold_throttled[conn_index as usize],
            "throttled at the cap"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            cap,
            "held exactly cap buffers"
        );
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "armed flag stays set until the cancel's ECANCELED clears it (gates re-arm)"
        );
    }

    /// Mode A hold cap: after the throttle, once the ECANCELED lands and writes
    /// drain the hold below the cap, the write-completion handler re-arms the
    /// recv — no permanent throttle / deadlock.
    #[test]
    fn forward_hold_cap_rearms_after_hold_drains_on_write() {
        use std::os::fd::AsFd;
        let cap = 2;
        let mut el = make_test_loop_with_config(config_with_forward_cap(cap));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        // Fill to the cap → throttled (cancel submitted).
        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");
        assert!(el.driver.forward_hold_throttled[conn_index as usize]);

        // ECANCELED lands: clears `recv_multishot_armed`; hold still full → stays
        // throttled (re-arm waits for the hold to drain).
        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);
        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "ECANCELED clears the armed flag"
        );
        assert!(
            el.driver.forward_hold_throttled[conn_index as usize],
            "still throttled while the hold is at the cap"
        );

        // Drive the forward: poll pops buffer 0 (hold drops to 1 < cap) and
        // submits a write.
        let (sink, _peer) = make_socketpair();
        let sinkfd = crate::runtime::io::SinkFd::socket(sink.as_fd());
        let conn = ConnCtx::new(conn_index, generation);
        let waker = noop_waker();
        // Forward a large len so the future keeps going.
        let mut fut = std::pin::pin!(with_driver_state(&mut el, || conn.forward_to(&sinkfd, 100)));
        let _ = with_driver_state(&mut el, || {
            let mut cx = std::task::Context::from_waker(&waker);
            fut.as_mut().poll(&mut cx)
        });
        // The batch takes the whole hold — before gathering this popped one
        // buffer and left one behind. What the test is about is unchanged: the
        // hold falls below the cap, and the re-arm waits for the write.
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            0,
            "the gathered write took both held buffers"
        );
        assert_eq!(
            el.driver.forward_write[conn_index as usize]
                .as_ref()
                .map(|st| st.backings.len()),
            Some(2),
            "both buffers are in the one in-flight write"
        );
        assert!(
            el.driver.forward_hold_throttled[conn_index as usize],
            "not yet re-armed — waiting for the write to complete"
        );

        // Write completes → handle_forward_write drains + re-arms (hold 0 < cap 2).
        // 10 bytes now, because the write covers both buffers.
        let fw_ud = UserData::encode(OpTag::ForwardWrite, conn_index, generation);
        el.test_dispatch_cqe(fw_ud.raw(), 10, 0);
        assert!(
            !el.driver.forward_hold_throttled[conn_index as usize],
            "re-armed after the hold drained below the cap"
        );
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "multishot re-armed"
        );
    }

    /// Mode A hold cap: if the hold drains below the cap *before* the throttle's
    /// ECANCELED completes (writes outran the cancel), the ECANCELED handler
    /// itself re-arms — the deadlock-avoidance path (no write completion is left
    /// to trigger it).
    #[test]
    fn forward_throttle_rearms_from_ecanceled_when_hold_already_drained() {
        let cap = 3;
        let mut el = make_test_loop_with_config(config_with_forward_cap(cap));
        let conn_index = accept_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        for bid in 0..cap as u16 {
            deliver_segment(&mut el, conn_index, bid, b"x");
        }
        assert!(el.driver.forward_hold_throttled[conn_index as usize]);

        // Simulate the forward future draining the hold below the cap while the
        // cancel is still in flight (pop two of three held buffers).
        el.driver.segment_hold[conn_index as usize].pop_front();
        el.driver.segment_hold[conn_index as usize].pop_front();
        assert!(el.driver.segment_hold[conn_index as usize].len() < cap);

        // ECANCELED now lands with the hold already below the cap → re-arm here.
        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);
        assert!(
            !el.driver.forward_hold_throttled[conn_index as usize],
            "ECANCELED branch re-armed since the hold had drained"
        );
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "multishot re-armed from the ECANCELED path"
        );
    }

    /// A forward that ends while its throttle-cancel is still in flight must
    /// still leave the connection reading.
    ///
    /// `settle_forward_end` used to clear `forward_hold_throttled` in that case
    /// and re-arm nothing — it cannot re-arm while the old multishot is still
    /// live, two with the same user_data must never overlap. But the ECANCELED
    /// branch's re-arm is gated on exactly that flag, and nothing else re-arms a
    /// connection that has stopped forwarding, so the connection stayed unarmed
    /// and the handler's next `with_data` parked forever. Found by the
    /// length-prefixed proxy test in `tests/echo.rs` at `forward_hold_cap(1)`,
    /// where it reproduced about one run in three.
    #[test]
    fn settle_forward_end_with_cancel_in_flight_rearms_from_ecanceled() {
        let cap = 1;
        let mut el = make_test_loop_with_config(config_with_forward_cap(cap));
        let conn_index = accept_connection(&mut el);
        let ci = conn_index as usize;
        el.driver.recv_domain[ci] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[ci] = true;
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        // One segment reaches the cap, so the recv is cancelled.
        deliver_segment(&mut el, conn_index, 0, b"x");
        assert!(el.driver.forward_hold_throttled[ci], "throttled at the cap");

        // The forward finishes first: the future drains the hold and settles,
        // all before the cancel's ECANCELED comes back.
        el.driver.segment_hold[ci].pop_front();
        assert!(el.driver.settle_forward_end(conn_index));
        assert!(
            el.driver.forward_hold_throttled[ci],
            "the flag has to survive settle, or the ECANCELED re-arm is skipped"
        );

        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);
        assert!(!el.driver.forward_hold_throttled[ci]);
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "the connection must be reading again once the forward is over"
        );
    }

    /// Arming a forward must also take the zero-copy pending recv buffer, not
    /// just the accumulator.
    ///
    /// The plaintext read path holds the most recent provided buffer in place
    /// instead of copying it, so buffered bytes can sit *behind* an empty
    /// accumulator. A forward that only drained the accumulator left them
    /// there for good — nothing on the forward path reads that slot — and the
    /// bid stayed pinned, so the provided ring lost an entry too.
    ///
    /// This is the shape the proxy test hit ~3% of the time: the backend's
    /// first echo chunk landed on the connection just before the return-leg
    /// forward was armed, and the forward then waited forever for bytes it
    /// already had.
    #[test]
    fn arming_a_forward_takes_the_pending_recv_buffer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let free_before = el.driver.provided_bufs.free();

        // A plaintext arrival with an empty accumulator is held in place
        // (`deliver_segment` is just a recv CQE; the domain is still the
        // default here, so it takes the plaintext route).
        deliver_segment(&mut el, conn_index, 0, b"early bytes");
        assert!(
            el.driver.pending_recv_bufs[conn_index as usize].is_some(),
            "the arrival should be held zero-copy, not copied"
        );
        assert!(el.driver.accumulators.is_empty(conn_index));

        let conn = ConnCtx::new(conn_index, generation);
        let sink = accept_connection(&mut el);
        let sink_ctx = ConnCtx::new(sink, el.driver.connections.generation(sink));
        let _fut = with_driver_state(&mut el, || conn.forward_to_conn(&sink_ctx, 1024));

        assert!(
            el.driver.pending_recv_bufs[conn_index as usize].is_none(),
            "the held buffer must be taken, not left where the forward cannot see it"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            1,
            "its bytes belong in the hold"
        );
        let held = match &el.driver.segment_hold[conn_index as usize][0] {
            crate::backend::HeldRecvBuf::Owned(b) => b.clone(),
            crate::backend::HeldRecvBuf::Pinned { .. } => {
                panic!("expected an owned copy of the taken buffer")
            }
        };
        assert_eq!(&held[..], b"early bytes");

        // And its bid goes back, or the ring bleeds an entry per forward.
        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(el.driver.provided_bufs.free(), free_before);
    }

    /// An ECANCELED that still carries `IORING_CQE_F_MORE` must not leave the
    /// connection believing it is armed.
    ///
    /// `-ECANCELED` is posted only for a request the cancel found live, and a
    /// connection has at most one live multishot recv per generation — so the
    /// CQE belongs to the current arming whatever the flag says. Trusting the
    /// flag left `recv_multishot_armed` set against a multishot the kernel had
    /// already killed, and every re-arm path then declined because the
    /// connection looked armed. Observed as a forward parked at 4096 of 8192
    /// bytes, flagged armed, with no data ever arriving.
    #[test]
    fn ecanceled_with_more_flag_still_rearms() {
        const IORING_CQE_F_MORE: u32 = 1 << 1;
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, IORING_CQE_F_MORE);

        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "the connection must end up armed again — by a fresh multishot, not \
             by a stale flag"
        );
    }

    /// A cancel that the kernel applies to a *later* multishot must not leave
    /// the connection unarmed.
    ///
    /// The throttle-cancel matches by `user_data`, which a connection's
    /// multishot recv re-uses for the life of the slot. If the throttled recv
    /// terminates on its own (`!has_more`) and the forward then settles and
    /// re-arms, the queued cancel lands on the *new* multishot. By then the
    /// connection is no longer throttled, so the throttle re-arm declines and
    /// the ECANCELED branch used to return before the handler's ordinary
    /// re-arm — leaving a healthy `Open`/`Multi` connection with nothing armed
    /// and its bytes accumulating unread. Found by the proxy test in
    /// `tests/echo.rs`, which hung on 22 of 25 runs at `forward_hold_cap(1)`;
    /// a stuck-state dump showed exactly this shape.
    #[test]
    fn ecanceled_for_a_superseded_multishot_rearms_the_connection() {
        let mut el = make_test_loop_with_config(config_with_forward_cap(1));
        let conn_index = accept_connection(&mut el);
        let ci = conn_index as usize;

        // The state the race leaves behind: armed cleared by the ECANCELED that
        // is about to arrive, no throttle (the forward already settled), the
        // connection otherwise healthy and expected to be reading.
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;
        assert!(!el.driver.forward_hold_throttled[ci]);

        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);

        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "an unthrottled Open/Multi connection must come back armed"
        );
        assert!(
            matches!(
                el.driver.connections.get(conn_index).unwrap().lifecycle,
                Lifecycle::Open
            ),
            "and must not have been closed"
        );
    }

    /// The same ECANCELED must NOT re-arm a connection that is closing — that
    /// cancel is `close_connection` releasing the recv's reference on the fd so
    /// the Close actually FINs, and re-arming would pin it again.
    #[test]
    fn ecanceled_during_close_does_not_rearm() {
        let mut el = make_test_loop_with_config(config_with_forward_cap(1));
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;
        el.driver.close_connection(conn_index);

        let recv_ud = UserData::encode(OpTag::RecvMulti, conn_index, generation);
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);

        assert!(
            !el.driver
                .connections
                .get(conn_index)
                .is_some_and(|c| c.recv_multishot_armed),
            "a closing connection must stay unarmed"
        );
    }

    /// Mode A hold cap: closing a connection while it is throttled drains its held
    /// bids exactly once (no leak, no double-replenish), and a later stale
    /// ECANCELED for the throttle-cancel is a no-op.
    #[test]
    fn close_while_throttled_releases_held_bids_once() {
        let cap = 2;
        let mut el = make_test_loop_with_config(config_with_forward_cap(cap));
        let conn_index = accept_connection(&mut el);
        let entries = el.driver.provided_bufs.ring_entries();
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        el.driver
            .connections
            .get_mut(conn_index)
            .unwrap()
            .recv_multishot_armed = true;

        // Fill to the cap (reserve 0 → Pinned) → throttled, two bids held.
        deliver_segment(&mut el, conn_index, 0, b"hello");
        deliver_segment(&mut el, conn_index, 1, b"world");
        assert!(el.driver.forward_hold_throttled[conn_index as usize]);
        assert_eq!(el.driver.provided_bufs.free(), entries - 2);

        // Close while throttled clears the forwarder flags but does NOT drain the
        // held bids (a reader could still consume them post-FIN); teardown reclaims
        // any it never reaches.
        let generation = el.driver.connections.generation(conn_index);
        el.driver.close_connection(conn_index);
        assert!(
            !el.driver.forward_hold_throttled[conn_index as usize],
            "throttle flag cleared on close"
        );
        assert!(
            !el.driver.forward_recv_active[conn_index as usize],
            "forwarder flag cleared on close"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            2,
            "close does not drain the held bids"
        );

        // Teardown (the Close CQE → handle_close) reclaims the held bids.
        let close_ud = UserData::encode(OpTag::Close, conn_index, generation);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == 0)
                .count(),
            1,
            "bid 0 replenished exactly once"
        );
        assert_eq!(
            el.driver
                .pending_replenish
                .iter()
                .filter(|&&b| b == 1)
                .count(),
            1,
            "bid 1 replenished exactly once"
        );

        // A stale ECANCELED for the throttle-cancel after close is a no-op — it
        // bears the pre-close generation, which the slot no longer carries.
        let recv_ud = UserData::encode(OpTag::RecvMulti, conn_index, generation);
        el.test_dispatch_cqe(recv_ud.raw(), -libc::ECANCELED, 0);

        let r: Vec<u16> = std::mem::take(&mut el.driver.pending_replenish);
        el.driver.provided_bufs.replenish_batch(&r);
        assert_eq!(
            el.driver.provided_bufs.free(),
            entries,
            "no leak, no double replenish"
        );
    }

    /// `SinkFd::file` rejects an `O_DIRECT` descriptor (unaligned provided
    /// buffers cannot be a zero-copy source).
    #[test]
    fn sink_fd_file_rejects_o_direct() {
        use std::os::fd::{AsFd, FromRawFd, OwnedFd};
        let (_f, path) = temp_file();
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let raw = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_DIRECT) };
        if raw < 0 {
            // Some filesystems (e.g. tmpfs) reject O_DIRECT open — skip.
            let _ = std::fs::remove_file(&path);
            return;
        }
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let err = crate::runtime::io::SinkFd::file(owned.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn handle_recv_multi_second_completion_flushes_to_accumulator() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let flags = 1u32 | 2u32; // IORING_CQE_F_BUFFER | IORING_CQE_F_MORE, bid=0

        // First recv: bid=0, "hello"
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(0);
        unsafe {
            std::ptr::copy_nonoverlapping(b"hello".as_ptr(), buf_ptr as *mut u8, 5);
        }
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 5, flags);

        // Second recv: bid=1, " world"
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(1);
        unsafe {
            std::ptr::copy_nonoverlapping(b" world".as_ptr(), buf_ptr as *mut u8, 6);
        }
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), 6, flags | (1u32 << 16));

        // Both buffers should be replenished (first flushed, second appended directly).
        assert!(
            el.driver.pending_replenish.contains(&0),
            "first buffer should be replenished"
        );
        assert!(
            el.driver.pending_replenish.contains(&1),
            "second buffer should be replenished"
        );

        // No pending buffer (second completion went through accumulator path).
        assert!(el.driver.pending_recv_bufs[conn_index as usize].is_none());

        // Accumulator should contain both buffers' data concatenated.
        let data = el.driver.accumulators.data(conn_index);
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn handle_recv_multi_enobufs_does_not_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // ENOBUFS = -105. has_more = false (bit 1 not set).
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -105, 0);

        // Connection should still be alive (ENOBUFS is recoverable).
        assert!(
            el.driver.connections.get(conn_index).is_some(),
            "connection closed on ENOBUFS"
        );
    }

    #[test]
    fn handle_recv_multi_unknown_error_closes_when_no_more() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Unknown error, !has_more — should close.
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -99, 0); // -99 = unknown errno

        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed on unknown recv error"
        );
    }

    #[test]
    fn handle_recv_multi_ecanceled_does_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // ECANCELED = -125.
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -125, 0);

        // Connection should still be alive.
        assert!(
            el.driver.connections.get(conn_index).is_some(),
            "connection closed on ECANCELED"
        );
    }

    // ── Fallback recv tests ────────────────────────────────────────

    /// Park a connection via an ENOBUFS multishot CQE and return its index.
    fn park_connection(el: &mut AsyncEventLoop<NoopHandler>) -> u32 {
        let conn_index = accept_connection(el);
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -libc::ENOBUFS, 0);
        assert!(el.driver.recv_starved.contains(&conn_index));
        conn_index
    }

    // ── Direct-echo gather (#397) ──────────────────────────────────

    /// Arm a connection for direct echo and stage `bids` worth of held
    /// buffers, as `handle_recv_multi` would for arrivals in one drain.
    fn stage_direct_echo(el: &mut AsyncEventLoop<NoopHandler>, bids: &[u16], len: u32) -> u32 {
        let conn_index = accept_connection(el);
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.direct_echo = true;
        }
        for &bid in bids {
            let (ptr, _) = el.driver.provided_bufs.get_buffer(bid);
            el.driver
                .hold_direct_echo(conn_index, crate::backend::PendingRecvBuf { bid, len, ptr });
        }
        conn_index
    }

    #[test]
    fn direct_echo_gathers_a_multi_buffer_message_into_one_send() {
        // The #397 regression: two recv completions carrying one message used
        // to produce two Sends, so the reply left as two segments.
        let mut el = make_test_loop();
        let conn_index = stage_direct_echo(&mut el, &[0, 1], 8192);

        el.flush_direct_echoes();

        assert!(
            el.driver.recv_hold[conn_index as usize].is_empty(),
            "both buffers should have been gathered"
        );
        assert!(
            el.driver.send_slab.in_use(0),
            "no coalesced entry allocated"
        );
        assert_eq!(
            el.driver.send_slab.recv_forward_bids(0),
            &[0, 1],
            "both bids must be owned by the one send"
        );
        assert!(el.driver.send_queues[conn_index as usize].in_flight);
        assert!(
            !el.driver.direct_echo_queued[conn_index as usize],
            "a drained connection should leave the flush queue"
        );
    }

    #[test]
    fn direct_echo_sends_a_lone_buffer_without_a_slab_entry() {
        // The common case — a message that fits one completion — must not pay
        // for an msghdr and a slab entry.
        let mut el = make_test_loop();
        let conn_index = stage_direct_echo(&mut el, &[0], 256);

        el.flush_direct_echoes();

        assert!(el.driver.recv_hold[conn_index as usize].is_empty());
        assert!(
            !el.driver.send_slab.in_use(0),
            "single buffer should take the plain Send path"
        );
        assert_eq!(el.driver.send_recv_buf_remaining[conn_index as usize], 256);
        assert_eq!(
            el.driver.send_recv_buf_original_lens[conn_index as usize],
            256
        );
    }

    #[test]
    fn direct_echo_holds_arrivals_behind_an_in_flight_send() {
        // One send in flight per connection: the rest accumulate for the next
        // gather rather than racing ahead of it.
        let mut el = make_test_loop();
        let conn_index = stage_direct_echo(&mut el, &[0, 1], 4096);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        el.flush_direct_echoes();

        assert_eq!(
            el.driver.recv_hold[conn_index as usize].len(),
            2,
            "nothing may be submitted while a send is in flight"
        );
        assert!(
            el.driver.direct_echo_queued[conn_index as usize],
            "connection must stay queued so the next flush retries it"
        );

        // The send completes and the connection is picked back up without any
        // handler having re-armed it.
        el.driver.send_queues[conn_index as usize].in_flight = false;
        el.flush_direct_echoes();
        assert!(el.driver.recv_hold[conn_index as usize].is_empty());
    }

    #[test]
    fn direct_echo_close_replenishes_staged_buffers() {
        let mut el = make_test_loop();
        let conn_index = stage_direct_echo(&mut el, &[0, 1], 1024);

        el.driver.close_connection(conn_index);

        assert!(el.driver.recv_hold[conn_index as usize].is_empty());
        assert!(el.driver.pending_replenish.contains(&0));
        assert!(el.driver.pending_replenish.contains(&1));

        // And the stale queue entry is dropped by the next pass.
        el.flush_direct_echoes();
        assert!(el.driver.direct_echo_pending.is_empty());
        assert!(!el.driver.direct_echo_queued[conn_index as usize]);
    }

    #[test]
    fn direct_echo_flush_leaves_a_recv_forward_hold_alone() {
        // `recv_hold` is shared with recv-forward, where the owning task
        // drains it. A queue entry that outlived its direct-echo connection
        // must not start gathering for whatever takes the slot next.
        let mut el = make_test_loop();
        let conn_index = stage_direct_echo(&mut el, &[0, 1], 4096);

        // The slot is now a recv-forward connection instead.
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.direct_echo = false;
        }
        el.driver.recv_forward[conn_index as usize] = true;

        el.flush_direct_echoes();

        assert_eq!(
            el.driver.recv_hold[conn_index as usize].len(),
            2,
            "the hold belongs to forward_held now"
        );
        assert!(!el.driver.send_slab.in_use(0));
        assert!(
            el.driver.direct_echo_pending.is_empty(),
            "the stale entry must still be dropped"
        );
    }

    #[test]
    fn dry_flush_submits_fallback_for_partial_message() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"$16\r\npart"));

        // No pending replenish: the ring is dry.
        assert!(el.driver.pending_replenish.is_empty());
        el.flush_replenish_and_rearm();

        assert!(
            el.driver.recv_fallback_inflight[conn_index as usize],
            "fallback not submitted"
        );
        assert!(
            !el.driver.recv_starved.contains(&conn_index),
            "connection still parked after fallback submit"
        );
        assert_eq!(el.driver.recv_fallback_count, 1);
        let pool = el.driver.fallback_recv_pool.as_ref().expect("pool built");
        assert!(pool.in_use(0), "first fallback should occupy slot 0");
    }

    #[test]
    fn dry_flush_keeps_waiting_with_empty_accumulator() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);

        el.flush_replenish_and_rearm();

        assert!(
            !el.driver.recv_fallback_inflight[conn_index as usize],
            "fallback submitted with nothing half-delivered"
        );
        // Nothing is torn, so the connection does not degrade to a fallback —
        // it goes back to an ordinary multishot, which this test's ring (never
        // drained) can feed. The park is for a dry ring, and the wake
        // condition is "the ring has buffers"; a replenish is just the usual
        // way that becomes true.
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "an untorn connection re-arms once the ring can feed it"
        );
    }

    /// A fallback already in flight when the domain flips must land in the
    /// hold, not the accumulator.
    ///
    /// `fallback_eligible` refuses a segmented connection, but a handler that
    /// reads a length header and *then* starts a forward flips the domain
    /// underneath an outstanding fallback. Those bytes are the newest on the
    /// stream; in the accumulator they would sit in front of the held bytes and
    /// be stranded besides, because a forward never reads the accumulator.
    #[test]
    fn fallback_completing_after_the_domain_flips_lands_in_the_hold() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"header tail"));
        el.flush_replenish_and_rearm();
        assert!(
            el.driver.recv_fallback_inflight[conn_index as usize],
            "the fallback is submitted while the connection is still plain"
        );

        // The handler starts a forward: domain flips, the accumulator is
        // drained into the hold (what `arm_forward_source` does).
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        let buffered = el.driver.accumulators.take_frozen(conn_index);
        el.driver.segment_hold[conn_index as usize]
            .push_front(crate::backend::HeldRecvBuf::Owned(buffered));

        let ud = UserData::encode(OpTag::RecvFallback, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 5, 0);

        assert_eq!(
            el.driver.accumulators.data(conn_index).len(),
            0,
            "nothing may be left where the forward cannot see it"
        );
        assert_eq!(
            el.driver.segment_hold[conn_index as usize].len(),
            2,
            "the late bytes join the hold, behind what was already there"
        );
    }

    /// A parked connection must come back when the ring has buffers, even if
    /// this pass returned none.
    ///
    /// The re-arm used to be gated on a replenish happening in the same pass.
    /// A connection re-parked *after* that pass — a fallback completion does
    /// exactly this — then sat against a full ring with nothing left to
    /// trigger another replenish: no recv armed, so no bid returned, so no
    /// further pass with `replenished`.
    #[test]
    fn parked_connection_rearms_against_a_full_ring_without_a_replenish() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.pending_replenish.is_empty(), "nothing to return");
        assert!(el.driver.provided_bufs.free() > 0, "the ring has buffers");

        el.flush_replenish_and_rearm();

        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "a parked connection must re-arm while the ring can feed it"
        );
        assert!(!el.driver.recv_starved.contains(&conn_index));
    }

    /// A segmented connection must never take the fallback recv.
    ///
    /// The fallback reads into a pool slot and can only append to the
    /// accumulator, while a segmented reader takes its bytes from the hold —
    /// so the fallback both bypasses the reader and reorders the stream
    /// (held bytes are earlier than anything it appends). For a `forward_to`
    /// source it is fatal: the forward never reads the accumulator, so the
    /// fallback chain feeds a buffer nobody reads while the forward waits for
    /// a segment that cannot come. The proxy test in `tests/echo.rs` hung this
    /// way on 29 of 30 runs; an in-memory trace ring showed an unbroken
    /// `fb-submit`/`fb-done` loop with the accumulator climbing.
    ///
    /// The trigger is the forward's own doing: bytes past `len` are stashed in
    /// the accumulator, which is exactly the half-delivered message this path
    /// takes as its cue to degrade.
    #[test]
    fn segmented_connection_never_takes_the_fallback_recv() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        el.driver.recv_domain[conn_index as usize] = crate::recv::domain::RecvDomain::Segmented;
        el.driver.forward_recv_active[conn_index as usize] = true;
        // The overshoot tail a forward stashes when a held buffer runs past
        // `len` — a non-empty accumulator is what makes fallback eligible.
        assert!(el.driver.accumulators.append(conn_index, b"tail past len"));

        el.flush_replenish_and_rearm();

        assert!(
            !el.driver.recv_fallback_inflight[conn_index as usize],
            "a segmented connection must not take the fallback recv"
        );
        assert_eq!(el.driver.recv_fallback_count, 0);
        assert!(
            el.driver
                .connections
                .get(conn_index)
                .unwrap()
                .recv_multishot_armed,
            "it takes an ordinary multishot instead — segments need provided buffers"
        );
    }

    #[test]
    fn partial_message_prefers_fallback_over_rearm() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));

        // Buffers came back — but re-arming a connection with a partial
        // message would only move one ring's worth before parking again
        // (the churn cycle). The fallback must win the arbitration.
        el.driver.provided_bufs.on_handout(); // a replenished bid was handed out first
        el.driver.pending_replenish.push(0);
        el.flush_replenish_and_rearm();

        assert!(
            el.driver.recv_fallback_inflight[conn_index as usize],
            "partial-message connection must take the fallback path"
        );
        assert!(el.driver.recv_starved.is_empty());
    }

    #[test]
    fn empty_accumulator_rearms_multishot_on_replenish() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);

        el.driver.provided_bufs.on_handout(); // a replenished bid was handed out first
        el.driver.pending_replenish.push(0);
        el.flush_replenish_and_rearm();

        assert!(
            !el.driver.recv_fallback_inflight[conn_index as usize],
            "nothing half-delivered — multishot re-arm expected"
        );
        assert!(el.driver.recv_starved.is_empty());
    }

    #[test]
    fn replenish_does_not_rearm_while_fallback_inflight() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));
        el.flush_replenish_and_rearm();
        assert!(el.driver.recv_fallback_inflight[conn_index as usize]);
        // Fallback submission takes the connection out of the park queue;
        // its completion re-parks it.
        assert!(!el.driver.recv_starved.contains(&conn_index));

        // A stale multishot ENOBUFS CQE re-parks the connection while the
        // fallback is still in flight. When buffers come back, the
        // replenish pass must NOT arm a multishot alongside the
        // outstanding one-shot — the connection stays parked until the
        // fallback CQE hands off.
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.test_dispatch_cqe(ud.raw(), -libc::ENOBUFS, 0);
        assert!(el.driver.recv_starved.contains(&conn_index));

        el.driver.provided_bufs.on_handout(); // a replenished bid was handed out first
        el.driver.pending_replenish.push(0);
        el.flush_replenish_and_rearm();

        assert!(
            el.driver.recv_starved.contains(&conn_index),
            "fallback-inflight connection must stay parked until its CQE"
        );
        assert!(el.driver.recv_fallback_inflight[conn_index as usize]);
    }

    #[test]
    fn dry_flush_moves_held_buffer_to_accumulator_and_revives() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);

        // Simulate a zero-copy held buffer with unconsumed partial data.
        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(3);
        unsafe { std::ptr::copy_nonoverlapping(b"held".as_ptr(), buf_ptr as *mut u8, 4) };
        el.driver.provided_bufs.on_handout(); // bid 3 was handed out before being held
        el.driver.pending_recv_bufs[conn_index as usize] = Some(crate::backend::PendingRecvBuf {
            bid: 3,
            len: 4,
            ptr: buf_ptr,
        });

        el.flush_replenish_and_rearm();

        assert_eq!(el.driver.accumulators.data(conn_index), b"held");
        assert!(
            el.driver.pending_recv_bufs[conn_index as usize].is_none(),
            "hold not flushed"
        );
        // The flushed hold is a partial message — the fallback continues
        // draining it (its bid went back to the ring for other conns).
        assert!(el.driver.recv_fallback_inflight[conn_index as usize]);
        assert!(el.driver.recv_starved.is_empty());
    }

    #[test]
    fn fallback_completion_appends_wakes_and_reparks() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part-"));
        el.flush_replenish_and_rearm();
        assert!(el.driver.recv_fallback_inflight[conn_index as usize]);

        // Write payload into the pool slot the way the kernel would.
        // (`alloc_raw` leaves `remaining` at 0 — only the base pointer is
        // meaningful here, matching what the recv SQE was built from.)
        let pool = el.driver.fallback_recv_pool.as_mut().expect("pool built");
        let slot: u16 = 0;
        assert!(pool.in_use(slot));
        let (ptr, _) = pool.current_ptr_remaining(slot);
        unsafe { std::ptr::copy_nonoverlapping(b"chunk".as_ptr(), ptr as *mut u8, 5) };

        let ud = UserData::encode(OpTag::RecvFallback, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), 5, 0);

        assert_eq!(el.driver.accumulators.data(conn_index), b"part-chunk");
        assert!(
            !el.driver.recv_fallback_inflight[conn_index as usize],
            "inflight flag not cleared"
        );
        assert!(
            !el.driver.fallback_recv_pool.as_ref().unwrap().in_use(slot),
            "pool slot not released"
        );
        assert!(
            el.driver.recv_starved.contains(&conn_index),
            "connection not re-parked after fallback completion"
        );
        assert!(el.driver.connections.get(conn_index).is_some());
    }

    #[test]
    fn fallback_completion_eof_closes_connection() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));
        el.flush_replenish_and_rearm();

        let ud = UserData::encode(OpTag::RecvFallback, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        assert!(
            !el.driver.fallback_recv_pool.as_ref().unwrap().in_use(0),
            "pool slot not released on EOF"
        );
        let closed = el
            .driver
            .connections
            .get(conn_index)
            .is_none_or(|c| c.close_requested());
        assert!(closed, "FIN mid-message must close the connection");
    }

    #[test]
    fn fallback_completion_error_closes_connection() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));
        el.flush_replenish_and_rearm();

        let ud = UserData::encode(OpTag::RecvFallback, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        assert!(!el.driver.fallback_recv_pool.as_ref().unwrap().in_use(0));
        let closed = el
            .driver
            .connections
            .get(conn_index)
            .is_none_or(|c| c.close_requested());
        assert!(closed);
    }

    #[test]
    fn fallback_completion_ecanceled_reparks_alive_connection() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));
        el.flush_replenish_and_rearm();

        let ud = UserData::encode(OpTag::RecvFallback, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -libc::ECANCELED, 0);

        assert!(!el.driver.fallback_recv_pool.as_ref().unwrap().in_use(0));
        assert!(!el.driver.recv_fallback_inflight[conn_index as usize]);
        assert!(
            el.driver.recv_starved.contains(&conn_index),
            "cancelled fallback must re-park, not strand the connection"
        );
    }

    #[test]
    fn stale_fallback_completion_releases_slot_only() {
        let mut el = make_test_loop();
        let conn_index = park_connection(&mut el);
        assert!(el.driver.accumulators.append(conn_index, b"part"));
        el.flush_replenish_and_rearm();
        assert!(el.driver.recv_fallback_inflight[conn_index as usize]);

        // Close and release the slot; the generation bumps on release.
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.test_dispatch_cqe(close_ud.raw(), 0, 0);
        assert!(el.driver.connections.get(conn_index).is_none());

        // Reuse the slot for a new occupant.
        let new_index = accept_connection(&mut el);
        assert_eq!(new_index, conn_index, "test expects slot reuse");
        assert!(
            !el.driver.recv_fallback_inflight[new_index as usize],
            "close must clear the inflight flag for the next occupant"
        );

        // The stale fallback CQE for the old occupant arrives now.
        let ud = UserData::encode(OpTag::RecvFallback, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 5, 0);

        assert!(
            !el.driver.fallback_recv_pool.as_ref().unwrap().in_use(0),
            "stale CQE must release the pool slot"
        );
        assert!(
            el.driver.accumulators.data(new_index).is_empty(),
            "stale CQE must not append into the new occupant's accumulator"
        );
        assert!(el.driver.connections.get(new_index).is_some());
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
        el.executor.connect_waiters[conn_index as usize] = true;

        // Simulate successful connect CQE (result == 0).
        let ud = UserData::encode(OpTag::Connect, conn_index, 0);
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
        // Connection should be established, open, with a multishot recv armed.
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.established, "connection not marked established");
        assert!(
            matches!(conn.lifecycle, Lifecycle::Open) && matches!(conn.recv_arm, RecvArm::Multi),
            "connection not Open / recv_arm not Multi after connect"
        );
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
        let ud = UserData::encode(OpTag::Connect, conn_index, 0);
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

        // Register a waiter as though a task had polled UdpCtx::send_ready.
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
    fn handle_send_error_wakes_send_waiter_with_error() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Set up send waiter.
        el.executor.send_waiters[conn_index as usize] = true;
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        // Simulate send error (ECONNRESET).
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        // Send waiter should be cleared.
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared on error"
        );
        // Result should be stored (so SendFuture can retrieve it).
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "send error result not stored"
        );
    }

    #[test]
    fn handle_send_msg_zc_error_wakes_send_waiter() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Set up send waiter.
        el.executor.send_waiters[conn_index as usize] = true;

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

        // Simulate ZC send error (ECONNRESET).
        let ud = UserData::encode(OpTag::SendMsgZc, conn_index, slab_idx as u32);
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        // Send waiter should be cleared.
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared on ZC error"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "ZC send error result not stored"
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
            let _fut = crate::runtime::io::DiskIoFuture { seq };
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
    // Requires kernel 6.6+.

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
    fn nop_inject_send_error_releases_and_wakes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        // Inject ECONNRESET through real io_uring.
        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), -104);

        // Pool slot released, waiter woken with error.
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "pool slot not released on injected send error"
        );
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared on injected error"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "error result not stored"
        );
    }

    #[test]
    fn nop_inject_recv_eof_closes_connection() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), 0);

        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "connection not closed on injected recv EOF"
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
    fn nop_inject_send_wakes_waiter() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let data = b"hello";
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();

        let ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        el.inject_and_dispatch(ud.raw(), data.len() as i32);

        assert!(!el.executor.send_waiters[conn_index as usize]);
        assert!(el.executor.io_results[conn_index as usize].is_some());
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
    fn nop_inject_recv_enobufs() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // ENOBUFS = -105.
        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), -105);

        assert!(
            el.driver.connections.get(conn_index).is_some(),
            "connection closed on ENOBUFS"
        );
    }

    #[test]
    fn nop_inject_recv_unknown_error_closes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), -99);

        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
    }

    #[test]
    fn nop_inject_recv_ecanceled() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        el.inject_and_dispatch(ud.raw(), -125); // ECANCELED

        assert!(el.driver.connections.get(conn_index).is_some());
    }

    #[test]
    fn nop_inject_connect_success() {
        let mut el = make_test_loop();
        let conn_index = el
            .driver
            .connections
            .allocate_outbound()
            .expect("no free slots");
        el.executor.connect_waiters[conn_index as usize] = true;

        let ud = UserData::encode(OpTag::Connect, conn_index, 0);
        el.inject_and_dispatch(ud.raw(), 0);

        assert!(!el.executor.connect_waiters[conn_index as usize]);
        assert!(el.executor.io_results[conn_index as usize].is_some());
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.established);
        assert!(
            matches!(conn.lifecycle, Lifecycle::Open) && matches!(conn.recv_arm, RecvArm::Multi)
        );
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

        let ud = UserData::encode(OpTag::Connect, conn_index, 0);
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
        el.executor.send_waiters[conn_index as usize] = true;
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();

        let send_ud = UserData::encode(OpTag::Send, conn_index, slot as u32);
        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );

        el.inject_batch_and_dispatch(&[
            (send_ud.raw(), -104), // send error
            (recv_ud.raw(), 0),    // recv EOF
        ]);

        // Both should have processed. Pool slot released, connection closing.
        assert!(!el.driver.send_copy_pool.in_use(slot));
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
    }

    #[test]
    fn batch_recv_eof_then_stale_send_cqe() {
        // Recv EOF closes the connection (sets Lifecycle::Closing, submits
        // Close SQE), then a stale send CQE arrives for the same
        // conn_index in the same batch. The send handler should not
        // panic on the closing connection.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();

        // Recv EOF + stale send in the same batch.
        // The EOF handler calls close_connection internally.
        let recv_ud = UserData::encode(
            OpTag::RecvMulti,
            conn_index,
            el.driver.connections.generation(conn_index),
        );
        let send_ud = UserData::encode(OpTag::Send, conn_index, slot as u32);

        el.inject_batch_and_dispatch(&[
            (recv_ud.raw(), 0), // EOF → close_connection
            (send_ud.raw(), 4), // stale send "completes" (4 bytes = b"data")
        ]);

        // Connection should be closing. Pool slot should be released
        // cleanly (no panic).
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || conn.unwrap().close_requested());
        assert!(!el.driver.send_copy_pool.in_use(slot));
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
        el.executor.send_waiters[c1 as usize] = true;
        el.executor.send_waiters[c2 as usize] = true;
        el.driver.send_queues[c1 as usize].in_flight = true;
        el.driver.send_queues[c2 as usize].in_flight = true;

        let (s1, _p, _l) = el.driver.send_copy_pool.copy_in(b"hello").unwrap();
        let (s2, _p, _l) = el.driver.send_copy_pool.copy_in(b"world").unwrap();

        let ud1 = UserData::encode(OpTag::Send, c1, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, c2, s2 as u32);

        el.inject_batch_and_dispatch(&[
            (ud1.raw(), 5),    // c1 send complete
            (ud2.raw(), -104), // c2 send error
        ]);

        // c1: success result stored.
        assert!(el.executor.io_results[c1 as usize].is_some());
        // c2: error result stored.
        assert!(el.executor.io_results[c2 as usize].is_some());
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

    #[test]
    fn disk_io_keys_are_unique_per_op() {
        // fs/NVMe/direct-io share the executor's completion maps; the key
        // must differ across ops even for the same slab index (three
        // independent slabs all start their free lists at 0).
        let mut el = make_test_loop();
        let mut ctx = el.driver.make_ctx();
        let k1 = ctx.disk_io_key(3);
        let k2 = ctx.disk_io_key(3);
        assert_ne!(k1, k2, "same slab index must map to distinct keys");
        assert_eq!(k1 & 0xFFFF, 3, "low 16 bits must carry the slab index");
        assert_eq!(k2 & 0xFFFF, 3);
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
    fn pollout_retry_backoff_preserves_entry() {
        // Same as above for the POLLOUT retry queue (every 2nd tick).
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();

        el.driver.tick_count = 1;
        el.driver
            .pending_send_pollout_retries
            .push((conn_index, generation, slot, 1, false));

        el.drain_send_pollout_retries();

        assert_eq!(
            el.driver.pending_send_pollout_retries,
            vec![(conn_index, generation, slot, 1, false)],
            "backoff tick must preserve the pollout-retry entry unchanged"
        );
    }

    #[test]
    fn copy_retry_giveup_fails_send_and_closes() {
        // Exhausted retries must not leave the connection wedged open with
        // in_flight stuck: release the slot, wake the waiter, close.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();
        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.executor.send_waiters[conn_index as usize] = true;

        el.driver
            .pending_copy_retries
            .push((conn_index, generation, slot, 2, OpTag::Send));
        el.drain_copy_retries();

        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "give-up must release the pool slot"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "give-up must wake the send waiter with a result"
        );
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || conn.unwrap().close_requested(),
            "give-up must close the connection"
        );
    }

    #[test]
    fn submit_next_queued_empty_finalizes_deferred_close() {
        // A close deferred behind an in-flight ZC/recv-forward send must
        // finalize when the queue empties, even though those completion
        // paths never call note_send_finalized.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Simulate an in-flight send, then close: the Close SQE is deferred.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.driver.close_connection(conn_index);
        assert!(
            el.driver.send_queues[conn_index as usize].close_pending,
            "close must defer while a send is in flight"
        );

        // The send's CQE path ends in submit_next_queued with an empty
        // queue — this must fire the deferred close.
        el.driver.submit_next_queued(conn_index);
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "deferred close must finalize once the queue drains"
        );
    }

    #[test]
    fn drain_conn_send_queue_finalizes_deferred_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.driver.send_queues[conn_index as usize].in_flight = true;
        el.driver.close_connection(conn_index);
        assert!(el.driver.send_queues[conn_index as usize].close_pending);

        el.driver.drain_conn_send_queue(conn_index);
        assert!(
            !el.driver.send_queues[conn_index as usize].close_pending,
            "deferred close must finalize when the queue is force-drained"
        );
    }

    // ── Executor wake-path regression tests ────────────────────────

    #[test]
    fn self_wake_via_channel_completes() {
        // join(rx.recv(), try_send) inside ONE task: recv registers its
        // waiter, try_send wakes it while the task is mid-poll (slot
        // Empty). The wake used to be dropped -> permanent deadlock.
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
        el.executor.send_waiters[conn_index as usize] = true;

        // Allocate 3 pool slots for the chain.
        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Register chain state: 3 SQEs, 9 total bytes.
        el.driver.chain_table.start(conn_index, 3, 9);

        // Submit linked NOPs: first with injected error, rest linked.
        // The kernel will deliver: error CQE, ECANCELED CQE, ECANCELED CQE.
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

        // Send waiter should have been woken with an error.
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "chain result not stored"
        );
    }

    #[test]
    fn linked_chain_middle_fails_rest_canceled() {
        // 3-SQE chain: first succeeds, second fails, third ECANCELED.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;

        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        el.driver.chain_table.start(conn_index, 3, 9);

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
        assert!(!el.executor.send_waiters[conn_index as usize]);
    }

    #[test]
    fn linked_chain_all_succeed() {
        // 3-SQE chain: all succeed. No errors.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.executor.send_waiters[conn_index as usize] = true;

        let (s1, _, _) = el.driver.send_copy_pool.copy_in(b"aaa").unwrap();
        let (s2, _, _) = el.driver.send_copy_pool.copy_in(b"bbb").unwrap();
        let (s3, _, _) = el.driver.send_copy_pool.copy_in(b"ccc").unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        el.driver.chain_table.start(conn_index, 3, 9);

        let ud1 = UserData::encode(OpTag::Send, conn_index, s1 as u32);
        let ud2 = UserData::encode(OpTag::Send, conn_index, s2 as u32);
        let ud3 = UserData::encode(OpTag::Send, conn_index, s3 as u32);

        el.inject_linked_chain_and_dispatch(&[(ud1.raw(), 3), (ud2.raw(), 3), (ud3.raw(), 3)]);

        assert_eq!(el.driver.send_copy_pool.free_count(), free_before + 3);
        assert!(!el.driver.chain_table.is_active(conn_index));
        assert!(!el.executor.send_waiters[conn_index as usize]);
        assert!(el.executor.io_results[conn_index as usize].is_some());
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
            io_uring::types::Timespec::new().sec(10).nsec(0);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let timer_ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr =
            &el.executor.timer_pool.timespecs[slot as usize] as *const io_uring::types::Timespec;

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
            io_uring::types::Timespec::new().sec(0).nsec(1);

        let payload = TimerSlotPool::encode_payload(slot, generation);
        let timer_ud = UserData::encode(OpTag::Timer, 0, payload);
        let ts_ptr =
            &el.executor.timer_pool.timespecs[slot as usize] as *const io_uring::types::Timespec;

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

    // ── SendRecvBuf (zero-copy forward) tests ──────────────────────

    #[test]
    fn handle_send_recv_buf_full_send_replenishes_and_wakes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Set up a send waiter.
        el.executor.send_waiters[conn_index as usize] = true;

        // Simulate a forward_recv_buf send: bid=3, data_len=100.
        let bid: u16 = 3;
        let data_len: u32 = 100;
        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // Full send: all 100 bytes sent.
        el.test_dispatch_cqe(ud.raw(), 100, 0);

        // Buffer should be replenished.
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished after full send"
        );
        // Send waiter should be woken with Ok(100).
        assert!(
            !el.executor.send_waiters[conn_index as usize],
            "send waiter not cleared"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "send result not stored"
        );
    }

    #[test]
    fn handle_send_recv_buf_error_replenishes_buffer() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        el.executor.send_waiters[conn_index as usize] = true;

        let bid: u16 = 5;
        let data_len: u32 = 200;
        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // Simulate ECONNRESET.
        el.test_dispatch_cqe(ud.raw(), -104, 0);

        // Buffer should be replenished even on error.
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished after send error"
        );
        assert!(
            el.executor.io_results[conn_index as usize].is_some(),
            "error result not stored"
        );
    }

    #[test]
    fn handle_send_recv_buf_partial_send_computes_correct_offset() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Configure: buffer_size = 4096, but data is only 100 bytes.
        // This is the common case — TCP segments are smaller than buffer capacity.
        let bid: u16 = 0;
        let data_len: u32 = 100;

        // Write recognizable data into the provided buffer.
        let (buf_ptr, buf_size) = el.driver.provided_bufs.get_buffer(bid);
        assert!(
            buf_size > data_len,
            "test requires buffer_size > data_len to exercise the bug"
        );
        let test_data: Vec<u8> = (0..data_len as u8).collect();
        unsafe {
            std::ptr::copy_nonoverlapping(
                test_data.as_ptr(),
                buf_ptr as *mut u8,
                data_len as usize,
            );
        }

        // Set up original length tracking (mirrors forward_recv_buf).
        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // Partial send: only 60 of 100 bytes sent.
        el.test_dispatch_cqe(ud.raw(), 60, 0);

        // Buffer should NOT be replenished yet (still in-flight).
        assert!(
            !el.driver.pending_replenish.contains(&bid),
            "buffer replenished prematurely on partial send"
        );

        // The retry SQE should have been pushed to the ring. The handler updated
        // send_recv_buf_remaining to 40; the retry CQE just needs bid in the payload.
        assert_eq!(
            el.driver.send_recv_buf_remaining[conn_index as usize], 40,
            "remaining not updated after partial send"
        );
        let new_ud = UserData::encode(OpTag::SendRecvBuf, conn_index, bid as u32);

        // Complete the retry — all 40 remaining bytes sent.
        el.test_dispatch_cqe(new_ud.raw(), 40, 0);

        // Now the buffer should be replenished.
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished after retry completed"
        );
    }

    #[test]
    fn handle_send_recv_buf_double_partial_send_offset() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // Data is 100 bytes in a 4096-byte buffer.
        let bid: u16 = 2;
        let data_len: u32 = 100;

        let (buf_ptr, _) = el.driver.provided_bufs.get_buffer(bid);
        // Fill with pattern so we can verify offset correctness.
        let test_data: Vec<u8> = (0u8..100).collect();
        unsafe {
            std::ptr::copy_nonoverlapping(test_data.as_ptr(), buf_ptr as *mut u8, 100);
        }

        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // First partial: 30 of 100 bytes sent. Remaining = 70. Offset should be 30.
        el.test_dispatch_cqe(ud.raw(), 30, 0);
        assert!(!el.driver.pending_replenish.contains(&bid));
        assert_eq!(el.driver.send_recv_buf_remaining[conn_index as usize], 70);

        // Second partial: 20 of 70 bytes sent. Remaining = 50. Offset should be 50.
        let ud2 = UserData::encode(OpTag::SendRecvBuf, conn_index, bid as u32);
        el.test_dispatch_cqe(ud2.raw(), 20, 0);
        assert!(!el.driver.pending_replenish.contains(&bid));
        assert_eq!(el.driver.send_recv_buf_remaining[conn_index as usize], 50);

        // Final: 50 of 50 bytes sent. Should complete.
        let ud3 = UserData::encode(OpTag::SendRecvBuf, conn_index, bid as u32);
        el.test_dispatch_cqe(ud3.raw(), 50, 0);
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished after final partial send"
        );
    }

    #[test]
    fn handle_send_recv_buf_partial_send_pointer_correctness() {
        // Verify the fix: on partial send, the resubmitted SQE pointer must be
        // buf_ptr + (original_len - new_remaining), NOT buf_ptr + (buf_size - new_remaining).
        //
        // We can't inspect the SQE directly, but we can verify the logic by checking
        // that handle_send_recv_buf computes the offset from original_len rather than buf_size.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let bid: u16 = 1;
        let data_len: u32 = 50;
        let (_, _buf_size) = el.driver.provided_bufs.get_buffer(bid);

        // The bug: offset = buf_size - new_remaining = 4096 - 25 = 4071 (WRONG)
        // The fix: offset = original_len - new_remaining = 50 - 25 = 25 (CORRECT)
        // With buf_size=4096 and data_len=50, the wrong offset points way past the data.

        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // Partial send: 25 of 50 bytes.
        el.test_dispatch_cqe(ud.raw(), 25, 0);

        // If the offset was computed correctly (25, not 4071), the resubmitted SQE
        // will have a valid pointer within the data. With the bug, the pointer
        // would be past the buffer entirely (buf_ptr + 4071 vs buf_ptr + 25).
        // Since we successfully pushed the SQE without crashing or panicking,
        // and buf_size (4096) > buggy offset (4071), the SQE was "valid" but pointed
        // to garbage. The fix ensures correct data is referenced.
        //
        // The real verification is that the resubmitted send completes successfully.
        // Simulate that by completing the retry.
        assert_eq!(el.driver.send_recv_buf_remaining[conn_index as usize], 25);
        let retry_ud = UserData::encode(OpTag::SendRecvBuf, conn_index, bid as u32);
        el.test_dispatch_cqe(retry_ud.raw(), 25, 0);

        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished after partial send retry"
        );
        // Verify the original_len was preserved correctly across retries.
        assert_eq!(
            el.driver.send_recv_buf_original_lens[conn_index as usize], data_len,
            "original_len should be preserved across partial send retries"
        );
    }

    #[test]
    fn handle_send_recv_buf_zero_result_replenishes() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let bid: u16 = 7;
        let data_len: u32 = 50;
        el.driver.send_recv_buf_original_lens[conn_index as usize] = data_len;
        el.driver.send_recv_buf_remaining[conn_index as usize] = data_len;
        let payload = bid as u32;
        let ud = UserData::encode(OpTag::SendRecvBuf, conn_index, payload);

        // Result == 0 (zero-length send).
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not replenished on zero-length send"
        );
    }

    // ── Bounded-send settlement, teardown and identity ─────────────
    //
    // Series PR 7b (`docs/uring-bounded-send-design.md`). A bounded send
    // (`ConnCtx::send_backpressured`, series PR 9) must resolve with the
    // exact result of *its own* operation. On io_uring its id rides the
    // end-of-send pool slot — lifted onto the slab entry when the run is
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
    /// *dropped* by teardown rather than resolved (`SendCapacityQueue`'s
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
    /// way the existing send tests do. `BoundedSendId` has no constructor
    /// but `enqueue`, which is how the real caller gets one too.
    fn submitted_id(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
    ) -> BoundedSendId {
        let task_id = parked_standalone(&mut el.executor);
        let id = el
            .executor
            .enqueue_send_capacity(conn_index, generation, 1, task_id);
        el.executor.mark_bounded_send_submitted(id);
        id
    }

    /// Admit one bounded send end to end, the way series PR 9's future
    /// will: park an owner, take an id, hand the message to
    /// `DriverCtx::send_bounded`, mark it submitted.
    fn admit_bounded_send(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn: crate::handler::ConnToken,
        data: &[u8],
        required_slots: usize,
    ) -> BoundedSendId {
        let task_id = parked_standalone(&mut el.executor);
        let id =
            el.executor
                .enqueue_send_capacity(conn.index, conn.generation, required_slots, task_id);
        {
            let mut ctx = el.driver.make_ctx();
            ctx.send_bounded(conn, data, id).expect("admitted");
        }
        el.executor.mark_bounded_send_submitted(id);
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
        let max = el.driver.connections.max_slots();
        let mut table = crate::tls::TlsTable::with_listener_configs(max, None, None, Vec::new());
        #[cfg(feature = "tls-unbuffered")]
        table.insert_for_test(
            conn_index,
            crate::tls::unbuffered::tests::handshaked_server(),
        );
        #[cfg(not(feature = "tls-unbuffered"))]
        {
            let (server, _peer) = crate::tls::buffered::test_support::handshaked();
            table.insert_for_test(
                conn_index,
                crate::tls::buffered::test_support::wrap_server(server),
            );
        }
        el.driver.tls_table = Some(table);
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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
            el.executor.take_bounded_send_result(id).is_none(),
            "nothing resolves while the entry is merely parked"
        );

        el.drain_send_retries();
        assert!(el.executor.take_bounded_send_result(id).is_none());
        el.drain_send_retries();
        assert!(el.executor.take_bounded_send_result(id).is_none());

        // Past the cap: the operation fails and the connection goes down.
        el.drain_send_retries();
        assert!(el.driver.pending_send_retries.is_empty());
        // The give-up path does not settle the id directly — the parked entry
        // is still queued, so `drain_conn_send_queue` -> `release_queued_sends`
        // takes it off the pool slot and fails it through the driver's
        // completion queue, which the run loop drains. Skipping this step is
        // what makes the settle look like it never happened.
        el.drain_bounded_send_completions();
        let result = el
            .executor
            .take_bounded_send_result(id)
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let id = admit_bounded_send(&mut el, token, b"hello", 1);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            7,
            "the message took exactly one slot"
        );
        assert!(
            el.executor.take_bounded_send_result(id).is_none(),
            "nothing may resolve before the completion"
        );

        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_bounded_send_result(id)
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

    /// A message wider than one pool slot completes as several CQEs, but the
    /// id rides only the end-of-send chunk: the intermediate completion
    /// settles nothing, and the final one reports the *logical* length — not
    /// the 36 bytes its own chunk carried.
    #[test]
    fn bounded_send_multi_slot_settles_only_on_the_final_chunk() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnToken::new(conn_index, generation);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        // 100 bytes over 64-byte slots: chunks of 64 and 36.
        let payload = vec![b'm'; 100];
        let id = admit_bounded_send(&mut el, token, &payload, 2);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            6,
            "the premise of this test: the message really is two slots"
        );
        assert_eq!(
            el.driver.send_queues[conn_index as usize].queue.len(),
            1,
            "the first chunk went to the ring, the second queued behind it"
        );

        // The first chunk completes.
        complete_one_cqe(&mut el);
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes, 64,
            "the first chunk's completion really did run"
        );
        assert!(
            el.executor.take_bounded_send_result(id).is_none(),
            "an intermediate chunk carries no id and must settle nothing"
        );

        // The end-of-send chunk completes.
        complete_one_cqe(&mut el);
        let result = el
            .executor
            .take_bounded_send_result(id)
            .expect("the end-of-send chunk settles the operation");
        assert_eq!(
            result.expect("the send succeeded"),
            100,
            "the logical length, not the 36-byte final chunk"
        );
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "both slots came back"
        );

        let mut buf = [0u8; 128];
        assert_eq!(drain_peer(&peer, &mut buf), 100);
    }

    /// A zero-length bounded send queues no SQE, so no CQE will ever settle
    /// it: `send_bounded` settles it itself, synchronously, through
    /// `Driver::bounded_send_completions`. This is why that queue's payload
    /// is an `io::Result` and not an `io::Error` — its defining property is
    /// the *missing completion*, not failure.
    #[test]
    fn zero_length_bounded_send_settles_ok_without_a_cqe() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnToken::new(conn_index, generation);

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
            el.driver.bounded_send_completions.len(),
            1,
            "so the driver settles it itself"
        );

        el.drain_bounded_send_completions();
        let result = el
            .executor
            .take_bounded_send_result(id)
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
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 20);
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
            el.executor.take_bounded_send_result(id).is_none(),
            "a partial write must not settle the operation"
        );

        // The remaining 12 finish it.
        el.test_dispatch_cqe(ud.raw(), 12, 0);
        let result = el
            .executor
            .take_bounded_send_result(id)
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
    /// off the run's end-of-send pool slot and onto the slab entry — with
    /// the carried logical length, not the run's wire total.
    #[test]
    fn coalesced_run_settles_the_id_lifted_onto_the_slab_entry() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let (_ours, peer) = attach_socketpair(&mut el, conn_index);

        let id = submitted_id(&mut el, conn_index, generation);

        // Two chunks of one logical send behind an in-flight send: a
        // coalescable run that stops at the end-of-send chunk.
        el.driver.send_queues[conn_index as usize].in_flight = true;
        let c0 = built_copy_send(&mut el, conn_index, b"aa");
        let c1 = built_copy_send(&mut el, conn_index, b"bbb");
        el.driver
            .send_copy_pool
            .set_end_of_send(c0.pool_slot, false);
        el.driver.send_copy_pool.set_end_of_send(c1.pool_slot, true);
        // Deliberately neither chunk's length and not the run's 5 wire
        // bytes: under TLS the number the caller passed is a plaintext
        // length no completion handler can recompute, which is the whole
        // reason it travels with the id.
        el.driver
            .send_copy_pool
            .set_bounded_send(c1.pool_slot, id, 99);
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
            el.driver.send_copy_pool.take_bounded_send(last_slot),
            None,
            "the id moved off the pool slot onto the slab entry"
        );

        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_bounded_send_result(id)
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

    /// A terminal send error settles `Err` with the errno and returns the
    /// slot.
    #[test]
    fn send_error_settles_err_and_releases_the_slot() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"doomed").unwrap();
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 6);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), -libc::ECONNRESET, 0);

        let err = el
            .executor
            .take_bounded_send_result(id)
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

    /// A zero-result send completion is a *failure* for a bounded send even
    /// though `send().await` reports `Ok(0)` for it: a truncated count would
    /// read to the caller as a short write of its message.
    #[test]
    fn zero_length_send_completion_settles_write_zero() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.executor.send_waiters[conn_index as usize] = true;

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"nothing went").unwrap();
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 12);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), 0, 0);

        let err = el
            .executor
            .take_bounded_send_result(id)
            .expect("a zero-result CQE settles the operation")
            .expect_err("a bounded send never reports a truncated count");
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        // The two really do diverge: the plain send waiter still gets Ok(0).
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Ok(n))) => assert_eq!(
                *n, 0,
                "send().await's contract for a zero-result CQE is unchanged"
            ),
            _ => panic!("expected the send waiter to be woken with Send(Ok(0))"),
        }
    }

    /// The settled length is the one carried with the id, not the completing
    /// chunk's byte count. This is the shape a bounded TLS send has:
    /// `send_bounded` attaches the id to the final *ciphertext* chunk (the
    /// one `encrypt_to_sends` tags `OpTag::Send`) together with the
    /// *plaintext* length, because no handler can recompute it —
    /// `handle_send` accumulates wire bytes and the chunk itself is one TLS
    /// record.
    ///
    /// The slot here holds stand-in ciphertext, not a real record: this test
    /// module has no TLS harness (no `tls_table`, no handshake), so what is
    /// pinned is `handle_send`'s half of the rule, not `encrypt_to_sends`'s.
    #[test]
    fn send_settles_the_carried_length_while_the_waiter_sees_the_wire_bytes() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        el.executor.send_waiters[conn_index as usize] = true;

        let id = submitted_id(&mut el, conn_index, generation);
        let ciphertext = [b'c'; 30];
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(&ciphertext).unwrap();
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        // 12 bytes of plaintext became 30 bytes on the wire.
        el.driver.send_copy_pool.set_bounded_send(slot, id, 12);
        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );

        el.test_dispatch_cqe(ud.raw(), 30, 0);

        let result = el
            .executor
            .take_bounded_send_result(id)
            .expect("the operation resolved");
        assert_eq!(
            result.expect("the send succeeded"),
            12,
            "the caller's length, not the record's"
        );
        match &el.executor.io_results[conn_index as usize] {
            Some(crate::runtime::IoResult::Send(Ok(n))) => assert_eq!(
                *n, 30,
                "send().await is still woken with the wire bytes — the two \
                 numbers diverge, which is why the logical one is carried"
            ),
            _ => panic!("expected the send waiter to be woken with Send(Ok(30))"),
        }
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
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 20);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let ud = UserData::encode(
            OpTag::Send,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), 8, 0);

        let err = el
            .executor
            .take_bounded_send_result(id)
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
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 20);
        el.driver.send_queues[conn_index as usize].close_submitted = true;

        let ud = UserData::encode(
            OpTag::TlsSend,
            conn_index,
            UserData::send_payload(slot, generation),
        );
        el.test_dispatch_cqe(ud.raw(), 8, 0);

        let err = el
            .executor
            .take_bounded_send_result(id)
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
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 5);
        el.driver
            .pending_copy_retries
            .push((conn_index, generation, slot, 2, OpTag::Send));

        el.drain_copy_retries();

        let err = el
            .executor
            .take_bounded_send_result(id)
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
        el.driver.send_copy_pool.set_end_of_send(s0, false);
        el.driver.send_copy_pool.set_end_of_send(s1, true);
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
                true,
                Some((id, 99)),
            )
            .expect("slab room");
        el.driver
            .pending_coalesced_retries
            .push((conn_index, generation, slab_idx, 2));

        el.drain_coalesced_retries();

        let err = el
            .executor
            .take_bounded_send_result(id)
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

    /// `drain_send_pollout_retries`' give-up arm, on the id the parked pool
    /// slot carries.
    #[test]
    fn send_pollout_retry_cap_settles_the_bounded_send_err() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);

        let id = submitted_id(&mut el, conn_index, generation);
        let (slot, _p, _l) = el.driver.send_copy_pool.copy_in(b"blocked").unwrap();
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 7);
        el.driver
            .pending_send_pollout_retries
            .push((conn_index, generation, slot, 3, false));

        el.drain_send_pollout_retries();

        let err = el
            .executor
            .take_bounded_send_result(id)
            .expect("the give-up arm must settle the operation")
            .expect_err("POLLOUT never armed");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string()
                .contains("max retries during send pollout retry"),
            "unexpected message: {err}"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "give-up returns the slot"
        );
    }

    /// `drain_send_retries`' give-up arm holds no id at all: the parked
    /// entry is still *queued*, so `drain_conn_send_queue` takes the id off
    /// its pool slot and aborts it through
    /// `Driver::bounded_send_completions`, which the run loop drains. Both
    /// halves have to work or the caller hangs.
    #[test]
    fn send_retry_cap_aborts_the_parked_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        let generation = el.driver.connections.generation(conn_index);
        let token = crate::handler::ConnToken::new(conn_index, generation);

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
            el.executor.take_bounded_send_result(id).is_none(),
            "a re-parked entry must not resolve"
        );

        // The cap.
        el.drain_send_retries();
        assert_eq!(
            el.driver.bounded_send_completions.len(),
            1,
            "the destroyed queue entry is recorded for the loop to deliver"
        );
        el.drain_bounded_send_completions();

        let err = el
            .executor
            .take_bounded_send_result(id)
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
        let token = crate::handler::ConnToken::new(conn_index, generation);

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
            el.driver.bounded_send_completions.len(),
            1,
            "the destroyed entry is recorded for the loop to deliver"
        );
        el.drain_bounded_send_completions();
        let err = el
            .executor
            .take_bounded_send_result(id)
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
        let token = crate::handler::ConnToken::new(conn_index, generation);

        el.driver.send_queues[conn_index as usize].in_flight = true;
        let id = admit_bounded_send(&mut el, token, b"abandoned", 1);
        assert_eq!(el.driver.send_queues[conn_index as usize].queue.len(), 1);

        el.driver.force_finalize_close(conn_index);

        assert_eq!(el.driver.bounded_send_completions.len(), 1);
        el.drain_bounded_send_completions();
        let err = el
            .executor
            .take_bounded_send_result(id)
            .expect("the abandoned entry must be told")
            .expect_err("the message never reached the wire");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            8,
            "the abandoned entry's slot came back"
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
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver.send_copy_pool.set_bounded_send(slot, id, 8);
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
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes, 0,
            "no bytes credited to the new occupant"
        );
        assert!(
            el.executor.take_bounded_send_result(id).is_none(),
            "a dead occupant's completion must not settle its operation"
        );

        // Not vacuous: the entry is still present and still settleable, so
        // the stale CQE left it alone rather than removing it.
        el.executor.complete_bounded_send(id, Ok(42));
        assert_eq!(
            el.executor
                .take_bounded_send_result(id)
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
        let token = crate::handler::ConnToken::new(conn_index, generation);
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

        // The send's CQE lands in the next drain and must win.
        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_bounded_send_result(id)
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
    //     generation in the payload's high half, and `send_pollout_payload`'s
    //     15-bit variant with its `is_tls` bit wedged between;
    //   * `drain_completions` decodes that word and `dispatch_cqe` routes it
    //     to the handler the `OpTag` names, rather than to a neighbour;
    //   * the CQE's `res` field carries the result the kernel wrote, signed,
    //     unclamped;
    //   * a *batch* of completions drained together does not cross-talk —
    //     each settles its own id, with its own length, in submission order.
    //
    // `IORING_NOP_INJECT_RESULT` (kernel 6.6+) is the mechanism, as it is for
    // the `nop_inject_*` tests above; `inject_and_dispatch`,
    // `inject_batch_and_dispatch` and `inject_linked_chain_and_dispatch` are
    // the three shapes.

    /// A generation whose low bits are a real pattern rather than 0 or 1.
    ///
    /// `UserData::send_payload` packs the generation into the payload's high
    /// half; at generation 0 that half is all zeros, which a round trip that
    /// lost the high bits would reproduce by accident. 0x2A3 cannot be
    /// produced by accident, and it stays inside `send_pollout_payload`'s
    /// narrower 15-bit field too.
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
        cs.recv_arm = RecvArm::Multi;
        cs.established = true;
    }

    /// Copy `data` into a fresh pool slot, mark it end-of-send and attach a
    /// freshly admitted bounded send reporting `logical_len` — the by-hand
    /// equivalent of the last chunk `DriverCtx::send_bounded` builds, as the
    /// handler tests above assemble it. Returns the id and the slot.
    fn bounded_slot(
        el: &mut AsyncEventLoop<NoopHandler>,
        conn_index: u32,
        generation: u32,
        data: &[u8],
        logical_len: u32,
    ) -> (BoundedSendId, u16) {
        let id = submitted_id(el, conn_index, generation);
        let (slot, _ptr, _len) = el
            .driver
            .send_copy_pool
            .copy_in(data)
            .expect("free pool slot");
        el.driver.send_copy_pool.set_end_of_send(slot, true);
        el.driver
            .send_copy_pool
            .set_bounded_send(slot, id, logical_len);
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
            .take_bounded_send_result(id)
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
            .take_bounded_send_result(id)
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
    /// default: the `WriteZero` it settles is `bounded_send_error`'s special
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
            .take_bounded_send_result(id)
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

        // 8 of 20 bytes. The handler keeps the slot (and its id) and
        // resubmits bytes 8..20 as a real SQE against the socketpair.
        el.inject_and_dispatch(ud.raw(), 8);
        assert!(
            el.driver.send_copy_pool.in_use(slot),
            "a partial write keeps its slot"
        );
        assert!(
            el.executor.take_bounded_send_result(id).is_none(),
            "a partial write must not settle the operation"
        );

        // The resubmission's own completion, from the kernel.
        complete_one_cqe(&mut el);

        let result = el
            .executor
            .take_bounded_send_result(id)
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
            el.executor.take_bounded_send_result(stale_id).is_none(),
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
        assert_eq!(
            el.driver.send_queues[conn_index as usize].acked_bytes, 0,
            "no bytes credited to the new occupant"
        );

        // The control: one generation later, through the same pipeline, the
        // completion is accepted. Without this the assertion above would pass
        // just as well if the round trip had destroyed the payload outright.
        el.inject_and_dispatch(fresh_ud.raw(), 12);
        let result = el
            .executor
            .take_bounded_send_result(fresh_id)
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
        el.driver.send_copy_pool.set_end_of_send(s0, false);
        el.driver.send_copy_pool.set_end_of_send(s1, true);
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
                true,
                // Neither chunk's length and not the run's 5 wire bytes: the
                // carried number is the only one a handler cannot recompute.
                Some((id, 99)),
            )
            .expect("slab room");

        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), (l0 + l1) as i32);

        let result = el
            .executor
            .take_bounded_send_result(id)
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
        el.driver.send_copy_pool.set_end_of_send(s0, false);
        el.driver.send_copy_pool.set_end_of_send(s1, true);
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
                true,
                Some((id, 99)),
            )
            .expect("slab room");

        let ud = UserData::encode(OpTag::SendMsgCoalesced, conn_index, slab_idx as u32);
        el.inject_and_dispatch(ud.raw(), -libc::EPIPE);

        let err = el
            .executor
            .take_bounded_send_result(id)
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
            .take_bounded_send_result(id)
            .expect("the silent return must still settle the operation")
            .expect_err("the remainder was never sent");
        assert_eq!(err.raw_os_error(), Some(libc::ECANCELED));
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the gate returns the slot"
        );
    }

    /// A failed `POLLOUT` re-arm settles the bounded send waiting on the
    /// parked slot.
    ///
    /// The third and last payload encoding: `send_pollout_payload` packs the
    /// slot in the low 16 bits, `is_tls` in bit 16 and only *15* generation
    /// bits above it, so it is a different bit layout from `send_payload`
    /// with a different mask on the way back out. Nothing else in the suite
    /// puts that layout through the kernel with an id attached —
    /// `send_pollout_retry_cap_settles_the_bounded_send_err` drives the retry
    /// drain, which never encodes a payload at all.
    #[test]
    fn nop_inject_send_pollout_error_settles_the_bounded_send() {
        let mut el = bounded_test_loop();
        let conn_index = accept_connection(&mut el);
        recycle_to_generation(&mut el, conn_index, PATTERNED_GENERATION);
        let generation = el.driver.connections.generation(conn_index);

        let (id, slot) = bounded_slot(&mut el, conn_index, generation, b"blocked", 7);
        let payload = UserData::send_pollout_payload(slot, false, generation);
        assert_eq!(
            UserData::send_pollout_gen(payload),
            0x02A3,
            "test premise: the 15-bit generation field really does carry a pattern"
        );
        assert!(
            !UserData::send_pollout_is_tls(payload),
            "test premise: the flag between slot and generation is clear"
        );
        let ud = UserData::encode(OpTag::SendPollOut, conn_index, payload);

        el.inject_and_dispatch(ud.raw(), -libc::EBADF);

        let err = el
            .executor
            .take_bounded_send_result(id)
            .expect("a failed POLLOUT must settle the operation")
            .expect_err("the send never resumed");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EBADF),
            "the bounded send gets the poll's errno"
        );
        assert!(
            !el.driver.send_copy_pool.in_use(slot),
            "the failed re-arm returns the slot"
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
            .take_bounded_send_result(id_a)
            .expect("the first completion settled its own operation");
        assert_eq!(
            result_a.expect("the send succeeded"),
            12,
            "connection A's carried length"
        );
        let result_b = el
            .executor
            .take_bounded_send_result(id_b)
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
            .take_bounded_send_result(id)
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
            .take_bounded_send_result(id)
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
        }

        /// Random recv CQE result.
        #[derive(Debug, Clone)]
        enum RecvAction {
            /// EOF (result == 0).
            Eof,
            /// Error (unknown errno).
            Error,
            /// ENOBUFS — buffer ring exhausted.
            Enobufs,
            /// ECANCELED.
            Ecanceled,
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
            ]
        }

        fn recv_action_strategy() -> impl Strategy<Value = RecvAction> {
            prop_oneof![
                Just(RecvAction::Eof),
                Just(RecvAction::Error),
                Just(RecvAction::Enobufs),
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
                            // Operation CQE with success.
                            el.test_dispatch_cqe(ud.raw(), 100, 0);
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
                    // Skip if connection already closed.
                    if el
                        .driver
                        .connections
                        .get(conn_index)
                        .is_none_or(|c| c.close_requested())
                    {
                        break;
                    }

                    let ud = UserData::encode(OpTag::RecvMulti, conn_index, el.driver.connections.generation(conn_index));
                    let result = match action {
                        RecvAction::Eof => 0,
                        RecvAction::Error => -99,
                        RecvAction::Enobufs => -105,
                        RecvAction::Ecanceled => -125,
                    };
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

                        // Send error on a random live connection.
                        2 if !live_conns.is_empty() => {
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
                                el.test_dispatch_cqe(ud.raw(), -104, 0);
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

                        // ZC send error on a live connection.
                        4 if !live_conns.is_empty() => {
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
                                el.test_dispatch_cqe(ud.raw(), -104, 0);
                                // Release if should_release.
                                if el.driver.send_slab.in_use(slab_idx)
                                    && el.driver.send_slab.should_release(slab_idx)
                                {
                                    el.driver.send_slab.release(slab_idx);
                                }
                            }
                        }

                        // Recv EOF — closes the connection.
                        5 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            let ud = UserData::encode(OpTag::RecvMulti, ci, el.driver.connections.generation(ci));
                            el.test_dispatch_cqe(ud.raw(), 0, 0);
                            // Simulate Close CQE.
                            let close_ud = UserData::encode(OpTag::Close, ci, 0);
                            el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                        }

                        // Recv error.
                        6 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            let ud = UserData::encode(OpTag::RecvMulti, ci, el.driver.connections.generation(ci));
                            el.test_dispatch_cqe(ud.raw(), -105, 0); // ENOBUFS
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
                                let recv_ud = UserData::encode(OpTag::RecvMulti, ci, el.driver.connections.generation(ci));
                                // EOF first, then stale send — the bug pattern.
                                el.test_dispatch_cqe(recv_ud.raw(), 0, 0);
                                el.test_dispatch_cqe(send_ud.raw(), 4, 0);
                                // Close CQE.
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
