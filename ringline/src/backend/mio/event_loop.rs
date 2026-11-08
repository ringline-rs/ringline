//! Mio backend event loop — readiness-based I/O dispatch.

use std::io;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Context;
use std::time::{Duration, Instant};

use crate::backend::Driver;
use crate::config::Config;
use crate::connection::{Lifecycle, ReadHalf};
use crate::metrics;
use crate::runtime::handler::AsyncEventHandler;
use crate::runtime::io::{ConnCtx, DriverState, UdpSocket, set_driver_state_guarded};
use crate::runtime::task::Park;
use crate::runtime::waker::{STANDALONE_BIT, conn_waker, standalone_waker};
use crate::runtime::{CURRENT_TASK_ID, Executor};

use super::driver::WAKE_TOKEN;

/// Mio-based event loop (one per worker thread).
pub(crate) struct AsyncEventLoop<A: AsyncEventHandler> {
    driver: Driver,
    handler: A,
    executor: Executor,
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

    /// The mio backend has nothing in the kernel to wait for; the connections
    /// still open are counted out before the event loop is dropped.
    pub(crate) fn drain_after_failure(&mut self) {
        self.driver.count_out_open_connections();
    }

    /// The mio backend has no ring.
    ///
    /// # Safety
    /// No requirement; the signature matches the io_uring backend.
    pub(crate) unsafe fn close_ring(&mut self) {}

    /// The first task panic recorded under `TaskPanicPolicy::Shutdown`.
    pub(crate) fn take_task_panic(&mut self) -> Option<crate::JoinError> {
        self.driver.panic_reporter.take()
    }

    /// Create a new mio event loop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &Config,
        handler: A,
        accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
        eventfd: RawFd,
        wake_fd: crate::wakeup::WakeFd,
        shutdown_flag: Arc<AtomicBool>,
        resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
        resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
        resolver: Option<Arc<crate::resolver::ResolverPool>>,
        spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
        spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
        spawner: Option<Arc<crate::spawner::SpawnerPool>>,
        blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
        blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
        blocking_pool: Option<Arc<crate::blocking::BlockingPool>>,
    ) -> io::Result<Self> {
        // Create per-worker disk I/O pool and channels if configured.
        // Each worker gets its own pool instance (lightweight — just thread
        // handles) and its own channel pair. This avoids changing the
        // launch_inner / worker_fn signature.
        let (disk_io_rx, disk_io_tx, disk_io_pool) = if config.disk_io_threads > 0
            && (config.direct_io.is_some() || config.fs.is_some())
        {
            let pool = Arc::new(crate::disk_io_pool::DiskIoPool::start(
                config.disk_io_threads,
                // `None` only in unit tests, which hold their own `WakeHandle`.
                config
                    .wake_keep_alive
                    .clone()
                    .unwrap_or_else(|| Arc::from(Vec::new())),
            ));
            let (tx, rx) = crossbeam_channel::unbounded::<crate::disk_io_pool::DiskIoResponse>();
            (Some(rx), Some(tx), Some(pool))
        } else {
            (None, None, None)
        };

        let driver = Driver::new(
            config,
            accept_rx,
            eventfd,
            wake_fd,
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
            disk_io_rx,
            disk_io_tx,
            disk_io_pool,
        )?;

        let executor = Executor::new(
            config.max_connections,
            config.standalone_task_capacity,
            crate::runtime::TIMER_SLOTS,
            config.udp_bind.len() as u32,
            config.udp_recv_queue_capacity,
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
    /// `run()` can still return an error after the listener becomes live.
    pub(crate) fn prepare_run(&mut self) -> Result<(), crate::error::Error> {
        // Register the wake pipe read-end with mio Poll.
        self.driver.poll.registry().register(
            &mut mio::unix::SourceFd(&self.driver.wake_pipe_fd),
            WAKE_TOKEN,
            mio::Interest::READABLE,
        )?;

        Ok(())
    }

    /// Run the mio event loop until shutdown.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
        // Spawn UDP handler tasks for each bound UDP socket.
        for udp_index in 0..self.driver.udp_sockets.len() {
            let udp_socket = UdpSocket::new(udp_index as u32);
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

        // Recv buffer for reading from sockets.
        let mut recv_buf = vec![0u8; 8192];

        loop {
            // 1. Fire expired timers.
            self.fire_expired_timers();

            // 2. Compute poll timeout from nearest timer deadline. Don't
            // block at all while tasks are already runnable (woken after the
            // iteration's last poll of ready tasks: self-wakes it collected,
            // tasks woken from on_tick or by step 8's teardown)
            // or while a writable connection has sends queued: a send
            // queued by a task re-polled after the last flush would
            // otherwise wait out the timeout. A connection whose socket is
            // full stays queued too, but waits for its writable event.
            // First release what futures dropped by `drain_pending_closes`
            // queued, so an idle worker does not hold it until its next
            // event, and a released timer no longer sets the timeout.
            crate::fs::release_orphans(&mut self.driver, &mut self.executor);
            self.executor.collect_wakeups();
            let flushable = self
                .driver
                .sends_dirty
                .iter()
                .any(|&i| self.driver.writable[i as usize]);
            let timeout = if self.executor.ready_queue.is_empty() && !flushable {
                self.compute_poll_timeout()
            } else {
                Duration::ZERO
            };

            // 3. Poll for I/O events.
            match self
                .driver
                .poll
                .poll(&mut self.driver.events, Some(timeout))
            {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(crate::error::Error::Io(e)),
            }
            #[cfg(test)]
            if let Some(fault) = &self.driver.test_fault {
                fault.check()?;
            }

            // The readable sockets handled below are one batch: the reads
            // among them share one arrival time, read by the first.
            self.driver.recv_batch.begin();

            // 4. Handle events.
            // Collect events into a temporary vec to avoid borrow conflict
            // (self.driver.events borrows driver, but handlers need &mut driver).
            let mut event_list: Vec<(mio::Token, bool, bool, bool)> =
                Vec::with_capacity(self.driver.events.iter().count());
            for event in self.driver.events.iter() {
                let is_err = event.is_error()
                    || event.is_read_closed()
                    || event.is_write_closed()
                    || event.is_priority();
                event_list.push((
                    event.token(),
                    event.is_readable(),
                    event.is_writable(),
                    is_err,
                ));
            }

            for (token, readable, writable, is_err) in event_list {
                match token {
                    WAKE_TOKEN => {
                        if readable {
                            self.drain_wake_pipe();
                        }
                    }
                    tok if tok.0 >= self.driver.udp_token_base
                        && tok.0 < self.driver.udp_token_base + self.driver.udp_sockets.len() =>
                    {
                        if readable {
                            let udp_index = (tok.0 - self.driver.udp_token_base) as u32;
                            self.handle_udp_readable(udp_index);
                        }
                    }
                    tok => {
                        let conn_index = (tok.0 - 1) as u32;
                        let connecting = self
                            .driver
                            .connections
                            .get(conn_index)
                            .is_some_and(|cs| matches!(cs.lifecycle, Lifecycle::Connecting));
                        if connecting {
                            // Writable (or error — handle_writable reads
                            // SO_ERROR) resolves the connect FIRST. Handling
                            // readable first let a server-speaks-first
                            // greeting land in the accumulator only to race
                            // connect bookkeeping, and a FIN in the same
                            // batch marked the conn Closed so the Connecting
                            // check failed and wake_connect never fired —
                            // connect().await hung forever (edge-triggered
                            // mio never re-delivers).
                            if writable || is_err {
                                self.handle_writable(conn_index);
                            }
                            if readable {
                                self.handle_readable(conn_index, &mut recv_buf, !is_err);
                            }
                            continue;
                        }
                        if readable {
                            self.handle_readable(conn_index, &mut recv_buf, !is_err);
                        }
                        if writable {
                            self.handle_writable(conn_index);
                        }
                    }
                }
            }

            // 5. Drain cross-thread channels unconditionally (not just on wake
            //    events). On macOS/kqueue, SourceFd edge-triggered semantics can
            //    miss pipe writes that arrive between reregister and poll. The
            //    try_recv calls are cheap — O(1) when empty.
            self.drain_channels();

            // 6. Collect wakeups and poll ready tasks.
            self.executor.collect_wakeups();
            self.poll_ready_tasks();
            // Release what futures dropped outside the executor left behind:
            // timer slots, spawns, pidfd waits, connects, blocking and resolve
            // entries, abandoned operations' results, abandoned opens' files,
            // and abandoned reads' and writes' buffers. Futures dropped by
            // `drain_pending_closes` below are released before the next
            // poll for I/O events.
            crate::fs::release_orphans(&mut self.driver, &mut self.executor);

            // 6a. Flush pending sends queued during task polling, then
            // deliver the completions that flushing produced (completions
            // are recorded when bytes reach the socket, so flush must run
            // first or every awaited send waits an extra iteration).
            self.flush_all_pending_sends();
            self.drain_send_completions();

            // 6a-bis. A forwarding source that stopped reading because its
            // sink was backed up gets no further readable event from
            // edge-triggered epoll (interest is registered once and never
            // toggled), so the loop has to come back to it deliberately once
            // the flush above drained the sink.
            //
            // This alternates rather than running once: the resumed read
            // queues more on the sink, and nothing else will wake the loop for
            // bytes we queued ourselves. It ends when every waiting source is
            // either drained to EWOULDBLOCK (nothing left to resume) or blocked
            // again on a sink the flush could not empty.
            while self.drain_forward_resumes(&mut recv_buf) {
                self.flush_all_pending_sends();
                self.drain_send_completions();
            }

            // 6b. Finish teardown of connections closed during this
            // iteration: executor cleanup (parked futures, waiter flags)
            // before the slot is released for reuse.
            self.finalize_closes();

            // 7. on_tick callback (synchronous). Set the executor's
            // driver_state thread-local so user code that calls
            // `ringline::spawn()` / wakers / `with_state` works from
            // inside the handler.
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
            }

            self.report_drop_panics();

            // 8. Flush any sends queued by on_tick, deliver their
            // completions, and finish any closes it triggered.
            self.flush_all_pending_sends();
            self.drain_send_completions();
            self.finalize_closes();

            // 8a. One send-capacity wake per iteration. A copy-pool permit
            // can come back at many points above — `handle_writable`'s
            // flush (4), either `flush_all_pending_sends` (6a, 8), a
            // `clear_pending_sends` from an accept-time slot reuse (4), a
            // write error, a task's own send (6), or `finish_close` inside
            // either `drain_pending_closes` (6b, 8) — and each of those sets
            // `capacity_released` rather than touching the executor.
            //
            // This is the single point that covers all of them, including
            // both `drain_send_completions` call sites: it is the last
            // thing in the iteration, so `free_count()` is the final figure
            // and no release can slip past it into the blocking `poll` at
            // the top of the next iteration. Waking from inside
            // `drain_send_completions` instead would fire twice per
            // iteration and would still leave step 8's teardown releases
            // unsignalled until the next iteration's step 6a — which only
            // runs after a `poll` that may block indefinitely.
            //
            // Nothing is lost by waking late: the iteration's last poll of
            // ready tasks (step 6, or `finalize_closes` at 6b and 8 when a
            // close was pending) has already run, so the head woken here is
            // polled in the next iteration, and step 2 sees a non-empty ready
            // queue and polls with a zero timeout.
            self.wake_capacity_if_released();

            // 9. Check shutdown.
            if self.driver.shutdown_local || self.driver.shutdown_flag.load(Ordering::Relaxed) {
                self.driver.count_out_open_connections();
                return Ok(());
            }
        }
    }

    /// Drain the wake pipe and re-register for the next event.
    fn drain_wake_pipe(&mut self) {
        let mut drain_buf = [0u8; 256];
        loop {
            let result = unsafe {
                libc::read(
                    self.driver.wake_pipe_fd,
                    drain_buf.as_mut_ptr() as *mut libc::c_void,
                    drain_buf.len(),
                )
            };
            if result <= 0 {
                break;
            }
        }
        // Re-register so we get notified again (kqueue consumes the registration).
        let _ = self.driver.poll.registry().reregister(
            &mut mio::unix::SourceFd(&self.driver.wake_pipe_fd),
            WAKE_TOKEN,
            mio::Interest::READABLE,
        );
    }

    /// Drain all cross-thread channels: accept, resolve, spawn, blocking.
    ///
    /// Called unconditionally on every event loop iteration (not just on wake
    /// pipe events) to avoid missed wakeups on macOS/kqueue.
    fn drain_channels(&mut self) {
        // Drain accept channel (server mode).
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

            let conn_index = match self.driver.connections.allocate() {
                Some(idx) => idx,
                None => {
                    metrics::CONNECTIONS.increment(metrics::conn::ACCEPT_TABLE_FULL);
                    unsafe {
                        libc::close(raw_fd);
                    }
                    continue;
                }
            };

            // Set peer address.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.peer_addr = Some(peer_addr);
                cs.listener = Some(listener);
            }

            // Convert raw fd to mio TcpStream.
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd) };
            std_stream.set_nonblocking(true).ok();
            if self.driver.tcp_nodelay {
                std_stream.set_nodelay(true).ok();
            }
            let mut mio_stream = mio::net::TcpStream::from_std(std_stream);

            // READABLE *and* WRITABLE, registered once and never modified
            // afterwards. mio's epoll is edge-triggered, so a socket that is
            // already writable fires one edge and then stays quiet — it does
            // not spin. The outbound path (`handler.rs`) has always registered
            // both; matching it here is what lets the per-send `epoll_ctl`
            // toggling go away (ringline-rs/ringline#395).
            let mio_token = mio::Token(conn_index as usize + 1);
            if self
                .driver
                .poll
                .registry()
                .register(
                    &mut mio_stream,
                    mio_token,
                    crate::backend::mio::driver::STREAM_INTEREST,
                )
                .is_err()
            {
                metrics::CONNECTIONS.increment(metrics::conn::ACCEPT_REGISTER_FAILED);
                self.driver.connections.release(conn_index);
                continue;
            }

            let idx = conn_index as usize;
            self.driver.tcp_streams[idx] = Some(mio_stream);
            self.driver.accumulators.reset(conn_index);
            self.driver.arrival[idx].clear();
            // Defensive: a freshly allocated slot should have an empty send
            // queue, but if anything survived, its awaited sends must be
            // failed and its permits returned rather than dropped.
            self.driver.clear_pending_sends(idx, || {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "connection slot reused by a new accept",
                )
            });
            self.driver.writable[idx] = false;

            // TLS path: defer accept until handshake completes in handle_readable.
            if let Some(ref mut tls_table) = self.driver.tls_table
                && tls_table.has_server_config_for(Some(listener))
            {
                if tls_table.create(conn_index, Some(listener)).is_err() {
                    self.driver.close_connection(conn_index);
                }
                continue;
            }

            // Plaintext path: mark connection as established and spawn accept task.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.established = true;
            }

            metrics::CONNECTIONS.increment(metrics::conn::ACCEPTED);
            metrics::CONNECTIONS_ACTIVE.increment();

            // Spawn async accept task.
            self.spawn_accept_task(conn_index);
        }

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

        // Drain disk I/O responses.
        if let Some(ref rx) = self.driver.disk_io_rx {
            while let Ok(response) = rx.try_recv() {
                // The operation is done: its key may be handed out again.
                self.driver.disk_io_in_flight.remove(&response.seq);
                // Handle fs_open completions: install fd or release slot.
                if let Some(file_index) = self.driver.pending_fs_opens.remove(&response.seq) {
                    if self.executor.abandoned_fs_opens.remove(&response.seq) {
                        // Nothing holds a handle to this file: drop the fd, if
                        // the open succeeded, and free the slot.
                        drop(response.opened);
                        if let Some(ref mut files) = self.driver.fs_files {
                            files.release(file_index);
                        }
                        continue;
                    }
                    if let Some(opened) = response.opened {
                        // Success: the fd moves into `fs_fds`. It closes when
                        // `fs_close` and every operation queued on it have
                        // dropped their holds, or when the worker exits.
                        self.driver.fs_fds[file_index as usize] = Some(std::sync::Arc::new(opened));
                        // Convert to success (0) for the OpenFuture.
                        self.executor.wake_disk_io(response.seq, 0);
                    } else {
                        // Failure — release the pre-allocated file slot.
                        if let Some(ref mut files) = self.driver.fs_files {
                            files.release(file_index);
                        }
                        self.executor.wake_disk_io(response.seq, response.result);
                    }
                    continue;
                }

                // If the response carries metadata (stat), store it.
                if let Some(metadata) = response.metadata {
                    self.executor.fs_stat_results.insert(response.seq, metadata);
                }
                self.executor.wake_disk_io(response.seq, response.result);
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
    }

    /// Route bytes just read from a forwarding source to its sink.
    ///
    /// Returns false only when the socket must not be read again this pass —
    /// an accumulator overflow, which closes the connection. A forward that
    /// *ends* here (sink gone, or `len` reached) returns true with
    /// `forward_conn` cleared: the read loop keeps going on the ordinary path,
    /// because edge-triggered epoll will not re-notify us about bytes already
    /// sitting in the socket behind the forward's last one.
    fn forward_bytes(&mut self, conn_index: u32, data: &[u8]) -> bool {
        let idx = conn_index as usize;
        let remaining = match self.driver.forward_conn[idx].as_ref() {
            Some(st) => st.len.saturating_sub(st.forwarded),
            None => return true,
        };
        // Bytes past `len` are not ours to forward: they belong to whoever
        // reads this connection next, so they go to the accumulator — the same
        // place the io_uring path settles its carried-over tail.
        let take = (data.len() as u64).min(remaining) as usize;
        let (fwd, rest) = data.split_at(take);

        if !fwd.is_empty() && !self.driver.forward_push(conn_index, fwd) {
            // Sink gone or its slot recycled. The source itself is still
            // healthy, so the remaining bytes go to the accumulator and the
            // handler decides what to do with the EPIPE.
            self.driver.finish_forward(conn_index, Err(libc::EPIPE));
            self.executor.wake_recv(conn_index);
            return self.append_or_close(conn_index, data);
        }

        let done = self.driver.forward_conn[idx]
            .as_ref()
            .is_some_and(|st| st.forwarded >= st.len);
        if done {
            let forwarded = self.driver.forward_conn[idx]
                .as_ref()
                .map_or(0, |st| st.forwarded);
            self.driver.finish_forward(conn_index, Ok(forwarded));
            self.executor.wake_recv(conn_index);
        }
        if rest.is_empty() {
            return true;
        }
        self.append_or_close(conn_index, rest)
    }

    /// Append to the accumulator, or close the connection if that would run
    /// past `recv_accumulator_max`. Returns false when the connection was
    /// closed — the bytes are already off the socket, so the stream cannot
    /// continue coherently.
    fn append_or_close(&mut self, conn_index: u32, data: &[u8]) -> bool {
        if self.driver.accumulators.append(conn_index, data) {
            self.executor.wake_recv(conn_index);
            return true;
        }
        self.abort_connection(conn_index, crate::accumulator::recv_cap_exceeded());
        false
    }

    /// Close `conn_index` because the runtime cannot go on with it — a write
    /// failed, or a receive ran past `recv_accumulator_max` — and report
    /// `err` to a reader parked on `with_data_result`, as a failed socket
    /// read is reported. `read` is set first, so the close reads as a
    /// failure and not as the peer's close.
    fn abort_connection(&mut self, conn_index: u32, err: io::Error) {
        let generation = self.driver.connections.generation(conn_index);
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.read = ReadHalf::Error;
        }
        self.executor.fail_recv(conn_index, generation, err);
        self.driver.close_connection(conn_index);
    }

    /// Resume sources whose sink queue has drained below the cap.
    ///
    /// The counterpart to the `break` in the read loop. Returns true if any
    /// source was actually re-read, which is the caller's signal that the sink
    /// may now have newly queued bytes to flush.
    fn drain_forward_resumes(&mut self, recv_buf: &mut [u8]) -> bool {
        if self.driver.forward_resume.is_empty() {
            return false;
        }
        let queued = std::mem::take(&mut self.driver.forward_resume);
        let mut still_blocked = Vec::new();
        let mut ready = Vec::new();
        for source in queued {
            let i = source as usize;
            if self.driver.forward_conn[i].is_none() {
                self.driver.forward_resume_flag[i] = false;
                continue;
            }
            if self.driver.forward_sink_full(source) {
                // Still backed up: stays queued, flag stays set.
                still_blocked.push(source);
                continue;
            }
            self.driver.forward_resume_flag[i] = false;
            ready.push(source);
        }
        self.driver.forward_resume = still_blocked;
        let progressed = !ready.is_empty();
        // These reads run after tasks, so they are a batch of their own.
        if progressed {
            self.driver.recv_batch.begin();
        }
        for source in ready {
            // A TLS source's plaintext is already decrypted into the
            // accumulator, so it has to be moved on before another read is
            // attempted — a read that may well return EWOULDBLOCK.
            if self.driver.forward_conn[source as usize].is_some()
                && self.driver.forward_take_accumulated(source).is_some()
            {
                self.executor.wake_recv(source);
            }
            self.handle_readable(source, recv_buf, false);
        }
        progressed
    }

    /// Settle a running forward short at EOF: the requested length is not
    /// coming, and a truncated forward resolves `Ok` with what it moved (the
    /// io_uring path resolves the same way).
    fn finish_forward_at_eof(&mut self, conn_index: u32) {
        if let Some(st) = self.driver.forward_conn[conn_index as usize].as_ref() {
            let forwarded = st.forwarded;
            self.driver.finish_forward(conn_index, Ok(forwarded));
            self.executor.wake_recv(conn_index);
        }
    }

    /// Handle a connection becoming readable: read data into accumulator.
    ///
    /// The reads run on until `WouldBlock` or `0`, except that with
    /// `stop_at_short_read`, on a TCP connection on Linux, a read that leaves
    /// `recv_buf` unfilled ends them, which saves the read that would return
    /// `EAGAIN`. A caller passes it only for a readiness event that does not
    /// report the read side closed or urgent data. On a registration that is
    /// edge-triggered, a FIN or urgent mark that arrives later raises its own
    /// event, and one already here is on this event: a read stops short at an
    /// urgent mark with bytes behind it, and has to run on to `0` to see a FIN.
    ///
    /// A Unix stream read also stops short with bytes behind it, at a message
    /// carrying fds, and raises no event for them, so it reads to `WouldBlock`.
    /// So does any other platform: kqueue has no urgent data event, and mio's
    /// poll selector re-arms only on `WouldBlock`.
    fn handle_readable(&mut self, conn_index: u32, recv_buf: &mut [u8], stop_at_short_read: bool) {
        let idx = conn_index as usize;

        // Check the connection is still active.
        if self.driver.tcp_streams[idx].is_none() {
            return;
        }

        // The receive side is finished; the stream is only still registered
        // because queued sends are draining (see `drain_pending_closes`).
        // Nothing to read.
        if self
            .driver
            .connections
            .get(conn_index)
            .is_some_and(|c| c.recv_finished())
        {
            return;
        }

        // Check if this is a TLS connection.
        let is_tls = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has(conn_index));

        if is_tls {
            // TLS path: read ciphertext, decrypt, put plaintext in accumulator.
            loop {
                // Take the stream out temporarily to avoid borrow conflicts
                // (feed_tls_recv_mio needs &mut tls_table, &mut accumulators,
                // &mut stream — all fields of driver).
                let mut stream = match self.driver.tcp_streams[idx].take() {
                    Some(s) => s,
                    None => return,
                };

                let n = match stream.read(recv_buf) {
                    Ok(0) => {
                        self.driver.tcp_streams[idx] = Some(stream);
                        // EOF. A FIN without the peer's close_notify is a
                        // truncation, not a clean TLS shutdown.
                        let close_notify_seen = self
                            .driver
                            .tls_table
                            .as_mut()
                            .and_then(|t| t.get_mut(conn_index))
                            .map(|tc| tc.peer_sent_close_notify)
                            .unwrap_or(true);
                        self.finish_forward_at_eof(conn_index);
                        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                            cs.note_eof(!close_notify_seen);
                        }
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                        break;
                    }
                    Ok(n) => {
                        metrics::BYTES.add(metrics::bytes::RECEIVED, n as u64);
                        n
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        self.driver.tcp_streams[idx] = Some(stream);
                        break;
                    }
                    Err(error) => {
                        self.driver.tcp_streams[idx] = Some(stream);
                        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                            cs.read = ReadHalf::Error;
                        }
                        let generation = self.driver.connections.generation(conn_index);
                        self.executor.fail_recv(conn_index, generation, error);
                        self.driver.close_connection(conn_index);
                        break;
                    }
                };

                // The feed's plaintext is recorded as the growth of
                // `recv_buffered`, before the `Ok` arm moves any of it to a
                // forward.
                let buffered_before_feed = self.driver.arrival_feed_start(conn_index);
                let tls_table = self.driver.tls_table.as_mut().unwrap();
                let result = crate::tls::feed_tls_recv_mio(
                    tls_table,
                    &mut self.driver.accumulators,
                    &mut self.driver.pending_sends[idx],
                    conn_index,
                    &recv_buf[..n],
                );
                self.driver
                    .arrival_feed_end(conn_index, buffered_before_feed);

                // Put the stream back.
                self.driver.tcp_streams[idx] = Some(stream);

                // feed_tls_recv_mio pushes handshake/ciphertext output into
                // pending_sends directly (not via DriverCtx), so uphold the
                // dirty invariant here or the flush pass never visits it.
                if !self.driver.pending_sends[idx].is_empty() {
                    self.driver.mark_send_dirty(idx);
                }

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
                            // Counted in with `established`; `finish_close`
                            // counts out.
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
                        // does: the task reads what arrived, then EOF. No
                        // forward exists yet: no task holds the connection.
                        if peer_closed {
                            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                                cs.note_eof(false);
                            }
                            self.driver.close_connection(conn_index);
                            break;
                        }
                    }
                    crate::tls::TlsRecvResult::Ok => {
                        self.executor.wake_recv(conn_index);
                        // A TLS source forwards from the accumulator, which is
                        // where rustls just wrote the plaintext — there is no
                        // socket read to intercept the way the plaintext path
                        // does. Stop pulling ciphertext while the sink is
                        // backed up, exactly as the plaintext path stops
                        // reading.
                        if self.driver.forward_conn[idx].is_some() {
                            self.driver.forward_take_accumulated(conn_index);
                            if self.driver.forward_conn[idx].is_some()
                                && self.driver.forward_sink_full(conn_index)
                            {
                                self.driver.mark_forward_resume(conn_index);
                                break;
                            }
                        }
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
                        break;
                    }
                    crate::tls::TlsRecvResult::Closed => {
                        self.finish_forward_at_eof(conn_index);
                        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                            cs.note_eof(false);
                        }
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                        break;
                    }
                }
            }
            return;
        }

        // Plaintext path.
        let stop_at_short_read =
            stop_at_short_read
                && cfg!(any(target_os = "linux", target_os = "android"))
                && !self.driver.connections.get(conn_index).is_some_and(|c| {
                    matches!(c.peer_addr, Some(crate::connection::PeerAddr::Unix(_)))
                });
        loop {
            let stream = match self.driver.tcp_streams[idx].as_mut() {
                Some(s) => s,
                None => return,
            };

            match stream.read(recv_buf) {
                Ok(0) => {
                    self.finish_forward_at_eof(conn_index);
                    // EOF. Wake any recv waiter so it sees `0`, then request
                    // teardown; finalize waits for queued sends to drain.
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.note_eof(false);
                    }
                    self.executor.wake_recv(conn_index);
                    self.driver.close_connection(conn_index);
                    break;
                }
                Ok(n) => {
                    metrics::BYTES.add(metrics::bytes::RECEIVED, n as u64);
                    self.driver.record_arrival(conn_index, n);
                    // A forward owns this connection's bytes: they go to the
                    // sink's send queue, not to the accumulator.
                    if self.driver.forward_conn[idx].is_some() {
                        if !self.forward_bytes(conn_index, &recv_buf[..n]) {
                            break;
                        }
                        // Stop draining if the sink is backed up. Edge-triggered
                        // epoll will not re-notify, so the source is queued for
                        // an explicit resume when the sink drains.
                        if self.driver.forward_conn[idx].is_some()
                            && self.driver.forward_sink_full(conn_index)
                        {
                            self.driver.mark_forward_resume(conn_index);
                            break;
                        }
                    } else {
                        let appended = self.driver.accumulators.append(conn_index, &recv_buf[..n]);
                        if !appended {
                            // Streamed past recv_accumulator_max. The bytes were
                            // already read off the socket, so the stream cannot
                            // continue coherently — close rather than OOM, as
                            // the uring and mio-TLS overflow paths do (the TLS
                            // one through a record-layer error, with no error
                            // recorded for the reader).
                            self.abort_connection(
                                conn_index,
                                crate::accumulator::recv_cap_exceeded(),
                            );
                            break;
                        }
                        self.executor.wake_recv(conn_index);
                    }
                    if stop_at_short_read && n < recv_buf.len() {
                        break;
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(error) => {
                    // Read error — keep the exact error for
                    // `with_data_result` (`with_data` still sees EOF), then
                    // request teardown.
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.read = ReadHalf::Error;
                    }
                    let generation = self.driver.connections.generation(conn_index);
                    self.executor.fail_recv(conn_index, generation, error);
                    self.driver.close_connection(conn_index);
                    break;
                }
            }
        }
    }

    /// Handle a connection becoming writable: detect connect completion or flush pending sends.
    fn handle_writable(&mut self, conn_index: u32) {
        let idx = conn_index as usize;

        // Check if this is a connecting socket completing its connect.
        if let Some(cs) = self.driver.connections.get_mut(conn_index)
            && matches!(cs.lifecycle, Lifecycle::Connecting)
        {
            // Connect completed — check SO_ERROR for connect failure.
            // Clear any connect timeout.
            if self.driver.connect_deadlines[idx].take().is_some() {
                self.driver.connect_pending -= 1;
            }

            let result = if let Some(ref stream) = self.driver.tcp_streams[idx] {
                match stream.take_error() {
                    Ok(Some(e)) => Err(e), // connect failed (ECONNREFUSED, etc.)
                    Ok(None) => Ok(()),    // connect succeeded
                    Err(e) => Err(e),      // getsockopt itself failed
                }
            } else {
                Err(io::Error::other("stream missing"))
            };

            if result.is_ok() {
                cs.mark_connected();

                // No `ConnectFuture` is waiting: it was dropped while the
                // connect was in flight, so no task will use the connection.
                // Close it, plain or TLS, rather than leave it established
                // with no owner.
                if !self.executor.connect_waiters[idx] {
                    self.driver.close_connection(conn_index);
                    return;
                }

                // Re-arm interest exactly once, here, when the outbound
                // connection becomes established.
                //
                // This is load-bearing and was found by deleting it: mio
                // registers the stream while the connect is still in flight,
                // and with edge-triggered epoll the readiness that matters
                // arrives around establishment. Without a MOD at this point
                // the first readable edge can be missed and the connection
                // never delivers its response — every outbound echo test
                // fails, which is how this came back.
                //
                // Once per connection is not the cost #395 is about: that was
                // two `epoll_ctl(MOD)` on *every operation*, from toggling
                // WRITABLE around each deferred send.
                if let Some(stream) = self.driver.tcp_streams[idx].as_mut() {
                    let _ = self.driver.poll.registry().reregister(
                        stream,
                        mio::Token(idx + 1),
                        crate::backend::mio::driver::STREAM_INTEREST,
                    );
                }

                // Set TCP_NODELAY if configured.
                if self.driver.tcp_nodelay
                    && let Some(ref stream) = self.driver.tcp_streams[idx]
                {
                    let _ = stream.set_nodelay(true);
                }

                // TLS client path: flush ClientHello, don't wake connect waiter
                // yet — wait for the TLS handshake to complete in handle_readable.
                if let Some(ref mut tls_table) = self.driver.tls_table
                    && tls_table.has(conn_index)
                {
                    crate::tls::flush_tls_output_mio_queued(
                        tls_table,
                        &mut self.driver.pending_sends[idx],
                        conn_index,
                    );
                    if !self.driver.pending_sends[idx].is_empty() {
                        self.driver.mark_send_dirty(idx);
                    }
                    let _ = self.driver.flush_sends(conn_index);
                    return;
                }

                cs.established = true;
                metrics::CONNECTIONS_ACTIVE.increment();
            }

            match result {
                Err(e) => {
                    // Connect failed — clean up the connection.
                    self.executor.wake_connect(conn_index, Err(e));
                    self.driver.close_connection(conn_index);
                }
                Ok(()) => {
                    self.executor.wake_connect(conn_index, Ok(()));
                }
            }
            return;
        }

        // Normal writable — mark writable and flush sends.
        self.driver.writable[idx] = true;
        if let Err(e) = self.driver.flush_sends(conn_index) {
            self.fail_connection_on_send_error(conn_index, e);
        }
    }

    /// A hard write error (EPIPE/ECONNRESET/peer-closed) during a flush:
    /// fail the awaiting sender, wake the recv side so the owning task
    /// observes the close, and tear the connection down. Previously the
    /// error was swallowed — the queue was retried every loop iteration
    /// forever while send().await had already reported success.
    fn fail_connection_on_send_error(&mut self, conn_index: u32, e: io::Error) {
        // Every queued awaited send fails with the same error the write
        // produced (cloned per id — `io::Error` is not `Clone`), and every
        // bounded one gives its copy-pool permit back.
        self.driver.clear_pending_sends(conn_index as usize, || {
            crate::backend::mio::driver::clone_io_error(&e)
        });
        // The reader learns of the write error too: the connection is going
        // away because of it, not because the peer closed.
        self.abort_connection(conn_index, e);
    }

    /// Handle a UDP socket becoming readable: drain datagrams into the
    /// executor's recv queue and wake the waiting task.
    fn handle_udp_readable(&mut self, udp_index: u32) {
        // GRO is Linux-only; elsewhere `udp_gro` is inert and we always take
        // the plain `recv_from` path below.
        #[cfg(target_os = "linux")]
        if self.driver.udp_gro {
            self.handle_udp_readable_gro(udp_index);
            return;
        }
        let idx = udp_index as usize;
        let socket = &self.driver.udp_sockets[idx];
        let mut buf = [0u8; 65536];

        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    metrics::UDP.increment(metrics::udp::DATAGRAMS_RECEIVED);
                    if self.executor.udp_recv_queues[idx].len()
                        >= self.executor.udp_recv_queue_capacity
                    {
                        // Drop on the floor — see io_uring backend for
                        // rationale.
                        metrics::UDP.increment(metrics::udp::DATAGRAMS_DROPPED);
                    } else {
                        let data = buf[..n].to_vec();
                        self.executor.udp_recv_queues[idx].push_back(
                            crate::runtime::PendingUdpDatagram {
                                peer,
                                buf: crate::runtime::PendingUdpBuf::Owned(data),
                                recv_at: std::time::Instant::now(),
                                segment_size: 0,
                                consumed: 0,
                            },
                        );
                        self.executor.wake_udp_recv(udp_index);
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                // A connected socket reports an ICMP port-unreachable once,
                // on the next recv, ahead of any datagram queued behind it.
                // Stopping here would leave that datagram unread until
                // another one arrives.
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => continue,
                Err(_) => break,
            }
        }
    }

    /// GRO variant of [`handle_udp_readable`]: `recvmsg` with a control
    /// buffer so the kernel can report the `UDP_GRO` segment size. The
    /// coalesced payload is stored whole; the shared drain path splits it.
    #[cfg(target_os = "linux")]
    fn handle_udp_readable_gro(&mut self, udp_index: u32) {
        use std::os::fd::AsRawFd;
        let idx = udp_index as usize;
        let fd = self.driver.udp_sockets[idx].as_raw_fd();
        // Hold a full coalesced datagram (~64 KiB) plus headroom.
        let mut buf = [0u8; 1 << 16];
        let mut control = [0u8; crate::backend::udp_gro::UDP_GRO_CMSG_LEN];

        loop {
            let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = control.len() as _;

            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n < 0 {
                // A connected socket reports an ICMP port-unreachable once;
                // read on to the datagrams behind it.
                if io::Error::last_os_error().raw_os_error() == Some(libc::ECONNREFUSED) {
                    continue;
                }
                // EWOULDBLOCK / EAGAIN ends the drain; other errors too.
                break;
            }
            let n = n as usize;
            let peer = match crate::backend::sockaddr_to_socket_addr(&name, msg.msg_namelen) {
                Some(p) => p,
                None => continue,
            };
            metrics::UDP.increment(metrics::udp::DATAGRAMS_RECEIVED);
            if self.executor.udp_recv_queues[idx].len() >= self.executor.udp_recv_queue_capacity {
                metrics::UDP.increment(metrics::udp::DATAGRAMS_DROPPED);
                continue;
            }
            // MSG_CTRUNC means we lost the cmsg but the payload is intact —
            // treat it as a single datagram rather than dropping it.
            let segment_size = if msg.msg_flags & libc::MSG_CTRUNC == 0 && msg.msg_controllen > 0 {
                // `msg_controllen` is `size_t` on Linux (cast redundant) but
                // `socklen_t` (u32) on macOS (cast required) — allow the
                // platform-conditional cast so both clippy jobs pass.
                #[allow(clippy::unnecessary_cast)]
                let clen = msg.msg_controllen as usize;
                crate::backend::udp_gro::parse_segment_size(&control[..clen]).unwrap_or(0)
            } else {
                0
            };
            let data = buf[..n].to_vec();
            self.executor.udp_recv_queues[idx].push_back(crate::runtime::PendingUdpDatagram {
                peer,
                buf: crate::runtime::PendingUdpBuf::Owned(data),
                recv_at: std::time::Instant::now(),
                segment_size,
                consumed: 0,
            });
            self.executor.wake_udp_recv(udp_index);
        }
    }

    /// Flush pending sends for connections with buffered data. Visits only
    /// the dirty list (marked on queue) instead of scanning every slot;
    /// connections whose queue survives the flush attempt are re-marked.
    fn flush_all_pending_sends(&mut self) {
        let dirty = std::mem::take(&mut self.driver.sends_dirty);
        for conn_index in dirty {
            let idx = conn_index as usize;
            self.driver.sends_dirty_flag[idx] = false;
            if self.driver.pending_sends[idx].is_empty() {
                continue;
            }
            // Interest is registered once at accept/connect as
            // READABLE|WRITABLE and never modified, so there is nothing to arm
            // here. If we already know the socket is writable, flush now.
            if self.driver.writable[idx]
                && let Err(e) = self.driver.flush_sends(conn_index)
            {
                self.fail_connection_on_send_error(conn_index, e);
                continue;
            }
            if !self.driver.pending_sends[idx].is_empty() && !self.driver.sends_dirty_flag[idx] {
                self.driver.sends_dirty_flag[idx] = true;
                self.driver.sends_dirty.push(conn_index);
            }
        }
    }

    /// Steps 6b and 8: when a close is pending, poll the ready tasks, then
    /// drain the pending closes.
    ///
    /// A close requested before step 6 — a peer FIN or a read error seen in
    /// step 4 — gives its task the step-6 poll before the teardown below
    /// (#371). A close requested after that poll — by the flush in 6a or 8
    /// (a write error, `fail_connection_on_send_error`), or by a FIN or read
    /// error the forward-resume reads of 6a-bis saw — comes too late for it,
    /// and `drain_send_completions` polls only when it delivered a settled
    /// send, which a connection with only unawaited sends queued never has.
    /// So the task it woke is polled here, before `drain_pending_closes`
    /// drops it.
    ///
    /// The poll takes the whole ready queue, not only that task: tasks the
    /// step-6 pass's own `collect_wakeups` queued (one that woke itself
    /// through its `Waker`) and, at step 8, tasks `on_tick` spawned or woke
    /// through the executor are polled here too (a wake through a `Waker`
    /// from `on_tick` reaches the thread-local queue and is collected at step
    /// 2). Only in an iteration with a close pending: with none, this step
    /// polls nothing, and those tasks are polled by `drain_send_completions`
    /// if it delivers a settled send, otherwise in the next iteration.
    fn finalize_closes(&mut self) {
        if !self.driver.pending_closes.is_empty() && !self.executor.ready_queue.is_empty() {
            self.poll_ready_tasks();
        }
        self.drain_pending_closes();
    }

    /// Finish teardown for connections whose close was requested, once
    /// their queued sends have drained.
    ///
    /// An entry whose `pending_sends` is still non-empty (and whose stream
    /// is still registered) is retained for a later pass: the task stays
    /// alive so its awaited sends can complete, `flush_all_pending_sends`
    /// registers writable interest for it, and the writable event brings
    /// the loop back here. A write error clears `pending_sends`
    /// (`fail_connection_on_send_error`), which ends the deferral.
    ///
    /// The deferral is unbounded, as on io_uring for plaintext; mio has no
    /// equivalent of io_uring's TLS `close_notify_deadline`, so a TLS peer
    /// that half-closes and stops reading holds its slot until the write
    /// errors.
    ///
    /// Executor cleanup runs first — the slot must not be released (and
    /// reusable) while a stale parked future, waiter flags, or a recv-sink
    /// raw pointer still reference it.
    fn drain_pending_closes(&mut self) {
        let mut i = 0;
        while i < self.driver.pending_closes.len() {
            let conn_index = self.driver.pending_closes[i];
            let idx = conn_index as usize;
            debug_assert!(
                self.driver.send_queues[idx].close_pending,
                "pending_closes entry {conn_index} without close_pending"
            );
            let sends_drained =
                self.driver.pending_sends[idx].is_empty() || self.driver.tcp_streams[idx].is_none();
            if !sends_drained {
                self.driver.mark_send_dirty(idx);
                i += 1;
                continue;
            }
            self.driver.pending_closes.swap_remove(i);

            // A forward feeding this connection cannot make progress once the
            // sink is gone, and the source gets no further readable event if
            // its peer goes quiet — so fail it here rather than leave the
            // future parked forever.
            if let Some(source) = self.driver.forward_feeder[idx].take() {
                self.driver.finish_forward(source, Err(libc::EPIPE));
                self.executor.wake_recv(source);
            }
            // This connection's own forward, if it is a source. The awaiting
            // task usually lives at *another* index — a proxy's inbound task
            // owns the upstream connection — so the result is recorded rather
            // than dropped; `remove_connection` re-wakes that owner below, and
            // the future reads the count before checking the generation.
            // A new forward on a reused slot clears the slot's stale result.
            if let Some(st) = self.driver.forward_conn[idx].take() {
                self.driver.forward_feeder[st.sink_index as usize] = None;
                self.driver.forward_done[idx] = Some(Ok(st.forwarded));
            }
            self.driver.forward_resume_flag[idx] = false;

            self.executor.remove_connection(conn_index);
            self.driver.finish_close(conn_index);
        }
    }

    /// Wake the send-capacity FIFO head if any copy-pool permit came back
    /// this iteration, and clear the flag. Called once, as the last thing in
    /// the run loop; see the call site for why that point and not inside
    /// [`drain_send_completions`](Self::drain_send_completions).
    ///
    /// Separate from the loop body so the tests can drive it directly.
    fn wake_capacity_if_released(&mut self) {
        if self.driver.capacity_released {
            self.driver.capacity_released = false;
            self.executor
                .wake_send_capacity(self.driver.send_copy_pool.free_count());
        }
    }

    /// Drain the driver's settled sends and re-poll the tasks they woke.
    ///
    /// `Driver::settled_sends` is keyed by id rather than by connection;
    /// `Executor::complete_send` routes each result to the operation that
    /// produced it. Draining here keeps the results ahead of
    /// `drain_pending_closes`, so a send whose last byte reached the socket
    /// is recorded `Ok` before `Executor::remove_connection` would resolve
    /// it as `ConnectionAborted`.
    ///
    /// Returned copy-pool permits are *not* signalled here: the driver sets
    /// `capacity_released` wherever a permit goes back, and the run loop
    /// issues one `wake_send_capacity` per iteration (see step 8a).
    fn drain_send_completions(&mut self) {
        loop {
            let mut delivered = false;
            while let Some((id, result)) = self.driver.settled_sends.pop_front() {
                self.executor.complete_send(id, result);
                delivered = true;
            }
            if !delivered {
                break;
            }
            // Re-poll tasks woken by the completions so they can consume
            // the results and potentially submit more sends.
            self.executor.collect_wakeups();
            self.poll_ready_tasks();
        }
    }

    /// Fire all expired timers and push the associated tasks to the ready queue.
    fn fire_expired_timers(&mut self) {
        let now = Instant::now();
        // Heap-driven expiry: O(log n) per fired timer instead of a full
        // pool scan per loop iteration.
        while let Some((slot, generation)) = self.executor.timer_pool.pop_expired(now) {
            if let Some(waker_id) = self.executor.timer_pool.fire(slot, generation) {
                self.executor.wake_task(waker_id);
            }
        }

        // Check for timed-out connect operations. `connect_pending` counts
        // armed deadlines so the common no-outbound-connects case skips the
        // scan entirely.
        if self.driver.connect_pending > 0 {
            let mut timed_out: Vec<u32> = Vec::new();
            for (idx, deadline) in self.driver.connect_deadlines.iter().enumerate() {
                if let Some(dl) = deadline
                    && now >= *dl
                {
                    timed_out.push(idx as u32);
                }
            }
            for conn_index in timed_out {
                self.driver.connect_deadlines[conn_index as usize] = None;
                self.driver.connect_pending -= 1;
                let err = io::Error::new(io::ErrorKind::TimedOut, "connect timed out");
                self.executor.wake_connect(conn_index, Err(err));
                self.driver.close_connection(conn_index);
            }
        }
    }

    /// Compute the poll timeout from the nearest timer deadline (heap
    /// peek — no pool scan).
    fn compute_poll_timeout(&mut self) -> Duration {
        let default = Duration::from_millis(10); // default tick interval
        match self.executor.timer_pool.next_deadline() {
            Some(deadline) => deadline
                .saturating_duration_since(Instant::now())
                .min(default),
            None => default,
        }
    }

    /// Spawn an async task for a newly accepted connection.
    fn spawn_accept_task(&mut self, conn_index: u32) {
        let generation = self.driver.connections.generation(conn_index);
        let conn_ctx = ConnCtx::new(conn_index, generation);
        // The handler owns the read side for the connection's lifetime; record
        // the claim here, since `Connection::for_accept` cannot reach the
        // driver from outside a task poll.
        self.driver.recv_half_taken[conn_index as usize] = true;
        self.driver.send_half_taken[conn_index as usize] = true;
        let conn = crate::Connection::for_accept(conn_ctx);
        let future = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Box::pin(self.handler.on_accept(conn))
        })) {
            Ok(future) => future,
            Err(payload) => {
                // The handler panicked building the connection's future:
                // close the connection and skip task setup.
                self.driver.close_connection(conn_index);
                self.driver
                    .panic_reporter
                    .report("handler on_accept", &*payload);
                return;
            }
        };
        self.executor.owner_task[conn_index as usize] = Some(conn_index);
        self.executor.task_slab.spawn(conn_index, future);
        self.executor.ready_queue.push_back(conn_index);
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

        // Safety: We have valid mutable references to self.driver and self.executor
        // that outlive this method. Creating NonNull from &mut is safe.
        let mut driver_state = DriverState {
            driver: unsafe { NonNull::new_unchecked(driver) },
            executor: unsafe { NonNull::new_unchecked(executor) },
        };
        let driver_state_guard = unsafe { set_driver_state_guarded(&mut driver_state) };

        // Safety: we have exclusive access to driver/executor via self, and
        // only access them through these raw pointers until the guard drops.
        let driver = unsafe { &mut *driver };
        let executor = unsafe { &mut *executor };

        // Per-batch dedup: same strategy as the io_uring backend.
        // See that backend's poll_ready_tasks for the full safety argument,
        // including the initial_len boundary that prevents lost wakeups when
        // the internal wake path re-queues a task mid-pass, and why a
        // Context-driven self-wake is not polled again within the same pass.

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
                            driver.close_connection(conn_index);
                            executor.remove_connection(conn_index);
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
                            let dropped = crate::task_panic::drop_caught(fut);
                            driver.close_connection(conn_index);
                            executor.remove_connection(conn_index);
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

        // Reset dedup bits for the initial-batch entries only.
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
}

#[cfg(test)]
mod tests {
    //! Event-loop tests for the bounded-send path.
    //!
    //! The driver-level bounded-send tests live in
    //! `backend/mio/driver.rs`. The ones here need an `Executor` as well —
    //! the two orders in which a completion and a teardown can reach it
    //! (the close route and the returning-task route), and the capacity
    //! wake the loop issues once per iteration — so they build a whole
    //! `AsyncEventLoop` and call the run-loop steps directly. The
    //! connection scaffolding (`attach_conn`, `token`) is shared with the
    //! driver tests.

    use super::*;
    use crate::backend::mio::driver::tests::{attach_conn, token};
    use crate::config::ConfigBuilder;

    use std::future::Future;
    use std::io::Read;

    /// A handler that does nothing: these tests never accept a connection
    /// through the loop, they attach one directly.
    struct NoopHandler;

    impl AsyncEventHandler for NoopHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: crate::Connection) -> impl Future<Output = ()> + 'static {
            async move {}
        }

        fn create_for_worker(_worker_id: usize) -> Self {
            NoopHandler
        }
    }

    /// Single-worker config with the driver tests' tiny 4 x 64-byte send
    /// pool, and no filesystem subsystem so no disk-I/O threads start.
    fn test_config() -> Config {
        ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(4, 64)
            .no_fs()
            .build()
            .expect("valid test config")
    }

    /// Build an event loop with no acceptor and no optional subsystems.
    ///
    /// `prepare_run` is deliberately not called (it only registers the wake
    /// pipe, which nothing here polls). As in `driver::tests::test_driver`,
    /// the returned `WakeHandle` must stay bound for the loop's lifetime.
    fn test_loop(config: &Config) -> (AsyncEventLoop<NoopHandler>, crate::wakeup::WakeHandle) {
        test_loop_with_accept(config, None)
    }

    /// A sleep dropped on a worker other than the one that allocated its
    /// timer slot releases nothing. The slot is in the first worker's pool;
    /// releasing it into the second's would put a live slot on that pool's
    /// free list.
    #[test]
    fn a_sleep_dropped_on_another_worker_releases_nothing() {
        let config = test_config();
        let (mut first, _first_wake) = test_loop(&config);
        let sleep = {
            let mut state = DriverState {
                driver: NonNull::from(&mut first.driver),
                executor: NonNull::from(&mut first.executor),
            };
            let _guard = unsafe { set_driver_state_guarded(&mut state) };
            crate::runtime::io::try_sleep(Duration::from_secs(60)).expect("a free timer slot")
        };
        // Registering the second worker makes it this thread's worker.
        let (mut second, _second_wake) = test_loop(&config);
        let first_generations = first.executor.timer_pool.generations.clone();
        let second_generations = second.executor.timer_pool.generations.clone();
        {
            let mut state = DriverState {
                driver: NonNull::from(&mut second.driver),
                executor: NonNull::from(&mut second.executor),
            };
            let _guard = unsafe { set_driver_state_guarded(&mut state) };
            drop(sleep);
        }
        crate::fs::release_orphans(&mut second.driver, &mut second.executor);
        assert_eq!(second.executor.timer_pool.generations, second_generations);
        assert_eq!(first.executor.timer_pool.generations, first_generations);
    }

    /// Run `f` with `el`'s driver and executor as this thread's driver state,
    /// as a task poll does.
    fn in_poll<R>(el: &mut AsyncEventLoop<NoopHandler>, f: impl FnOnce() -> R) -> R {
        let mut state = DriverState {
            driver: NonNull::from(&mut el.driver),
            executor: NonNull::from(&mut el.executor),
        };
        let _guard = unsafe { set_driver_state_guarded(&mut state) };
        f()
    }

    /// Give `el` a resolver pool of `threads` threads. Its answers go to a
    /// channel nothing drains, so a request stays pending until its future
    /// goes. The pool's threads hold `wake` open while they can still write
    /// to it.
    fn give_resolver(
        el: &mut AsyncEventLoop<NoopHandler>,
        threads: usize,
        wake: &crate::wakeup::WakeHandle,
    ) -> crossbeam_channel::Receiver<crate::resolver::ResolveResponse> {
        let (tx, rx) = crossbeam_channel::unbounded();
        el.driver.resolve_tx = Some(tx);
        el.driver.resolver = Some(Arc::new(crate::resolver::ResolverPool::start(
            threads,
            Arc::from(vec![wake.clone()]),
        )));
        rx
    }

    /// The same for the blocking pool.
    fn give_blocking_pool(
        el: &mut AsyncEventLoop<NoopHandler>,
        threads: usize,
        wake: &crate::wakeup::WakeHandle,
    ) -> crossbeam_channel::Receiver<crate::blocking::BlockingResponse> {
        let (tx, rx) = crossbeam_channel::unbounded();
        el.driver.blocking_tx = Some(tx);
        el.driver.blocking_pool = Some(Arc::new(crate::blocking::BlockingPool::start(
            threads,
            Arc::from(vec![wake.clone()]),
        )));
        rx
    }

    /// A resolve future dropped before its result arrives removes its
    /// `pending_resolves` entry: at once inside a task poll, and through the
    /// orphan queue outside one. A request the pool cannot take leaves no
    /// entry either (#582).
    #[test]
    fn a_dropped_resolve_future_leaves_no_entry() {
        let config = test_config();
        let (mut el, wake) = test_loop(&config);

        // A pool with no threads cannot take the request.
        let _answers = give_resolver(&mut el, 0, &wake);
        assert!(in_poll(&mut el, || crate::runtime::io::resolve("127.0.0.1", 80)).is_err());
        assert!(el.executor.pending_resolves.is_empty());

        let _answers = give_resolver(&mut el, 1, &wake);
        let start = |el: &mut AsyncEventLoop<NoopHandler>| {
            in_poll(el, || {
                crate::runtime::io::resolve("127.0.0.1", 80).expect("resolve")
            })
        };

        // Dropped inside a task poll.
        let resolving = start(&mut el);
        assert_eq!(el.executor.pending_resolves.len(), 1);
        in_poll(&mut el, || drop(resolving));
        assert!(el.executor.pending_resolves.is_empty());

        // Dropped outside one, as at connection teardown.
        let resolving = start(&mut el);
        drop(resolving);
        assert_eq!(
            el.executor.pending_resolves.len(),
            1,
            "outside a poll the release waits for the event loop"
        );
        crate::fs::release_orphans(&mut el.driver, &mut el.executor);
        assert!(el.executor.pending_resolves.is_empty());
    }

    /// A `spawn_blocking` request the pool cannot take leaves no entry
    /// (#582).
    #[test]
    fn a_failed_blocking_request_leaves_no_entry() {
        let config = test_config();
        let (mut el, wake) = test_loop(&config);
        let _results = give_blocking_pool(&mut el, 0, &wake);
        assert!(in_poll(&mut el, || crate::runtime::io::spawn_blocking(|| ())).is_err());
        assert!(el.executor.pending_blocking.is_empty());
    }

    /// A resolve future or blocking handle dropped on a worker other than
    /// the one that created it releases nothing. Request ids start at 0 on
    /// every worker, so a release there would remove that worker's own,
    /// unrelated request (#582).
    #[test]
    fn a_handle_dropped_on_another_worker_releases_nothing() {
        let config = test_config();
        let (mut first, first_wake) = test_loop(&config);
        let _a = give_resolver(&mut first, 1, &first_wake);
        let _b = give_blocking_pool(&mut first, 1, &first_wake);
        let resolving = in_poll(&mut first, || {
            crate::runtime::io::resolve("127.0.0.1", 80).expect("resolve")
        });
        let blocking = in_poll(&mut first, || {
            crate::runtime::io::spawn_blocking(|| ()).expect("spawn_blocking")
        });

        // Registering the second worker makes it this thread's worker. Its
        // own requests get the same ids as the first worker's.
        let (mut second, second_wake) = test_loop(&config);
        let _c = give_resolver(&mut second, 1, &second_wake);
        let _d = give_blocking_pool(&mut second, 1, &second_wake);
        let _own_resolving = in_poll(&mut second, || {
            crate::runtime::io::resolve("127.0.0.1", 80).expect("resolve")
        });
        let _own_blocking = in_poll(&mut second, || {
            crate::runtime::io::spawn_blocking(|| ()).expect("spawn_blocking")
        });

        in_poll(&mut second, || {
            drop(resolving);
            drop(blocking);
        });
        crate::fs::release_orphans(&mut second.driver, &mut second.executor);
        assert_eq!(second.executor.pending_resolves.len(), 1);
        assert_eq!(second.executor.pending_blocking.len(), 1);
        assert_eq!(first.executor.pending_resolves.len(), 1);
        assert_eq!(first.executor.pending_blocking.len(), 1);
    }

    /// [`test_loop`] with an acceptor channel, for the tests that drive
    /// `drain_channels`' accept path.
    fn test_loop_with_accept(
        config: &Config,
        accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
    ) -> (AsyncEventLoop<NoopHandler>, crate::wakeup::WakeHandle) {
        let (read_fd, handle) = crate::wakeup::create_wake_fd().expect("wake fd");
        let event_loop = AsyncEventLoop::new(
            config,
            NoopHandler,
            accept_rx,
            read_fd,
            handle.as_wake_fd(),
            Arc::new(AtomicBool::new(false)),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("build mio event loop");
        (event_loop, handle)
    }

    /// A key whose operation is still in the disk-I/O pool is not handed
    /// out again when the sequence comes round, even with no future holding
    /// it (a dropped future gives its key up while its operation runs).
    #[test]
    fn a_key_whose_pool_operation_is_running_is_not_reissued() {
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(4, 64)
            .disk_io_threads(1)
            .build()
            .expect("valid test config");
        let (mut el, _wake) = test_loop(&config);
        let dir =
            std::env::temp_dir().join(format!("ringline-mio-inflight-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (open_seq, stat_seq) = {
            let mut ctx = el.driver.make_ctx();
            // Blocks the pool's only thread until a writer opens the FIFO.
            let (_, _, open_seq) = ctx
                .fs_open(&fifo, crate::fs::OpenFlags::READ, 0)
                .expect("submit open");
            // Stand in for the u32 sequence coming round to it.
            *ctx.next_disk_io_seq = open_seq;
            let stat_seq = ctx.fs_stat(&dir).expect("submit stat");
            (open_seq, stat_seq)
        };
        // Release the pool thread before the loop, and the pool, drop.
        let writer = std::fs::OpenOptions::new().write(true).open(&fifo);
        drop(writer);
        drop(el);
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(
            stat_seq, open_seq,
            "the key of an operation still in the pool was handed out again"
        );
    }

    /// A parked standalone task, so that waking it is observable (a task
    /// that is already Ready is not re-queued).
    fn parked_standalone(executor: &mut Executor) -> u32 {
        let idx = executor
            .standalone_slab
            .spawn(Box::pin(std::future::pending::<()>()))
            .expect("free standalone slot");
        park(executor, idx | STANDALONE_BIT);
        idx | STANDALONE_BIT
    }

    /// Return a Ready standalone task to Parked.
    fn park(executor: &mut Executor, task_id: u32) {
        let idx = task_id & !STANDALONE_BIT;
        let future = executor
            .standalone_slab
            .take_ready(idx)
            .expect("task is Ready");
        executor.standalone_slab.park(idx, future);
    }

    /// Departure 4 of the series design, on the `drain_pending_closes`
    /// route: a close requested while the send is still queued is finalized
    /// at step 6b, *after* step 6a's flush and completion delivery, so the
    /// send resolves `Ok` even though the connection is torn down in the
    /// same iteration. Here the ordering alone is what saves the result.
    ///
    /// This covers only that route.
    /// `Executor::remove_connection` has two other callers, both in
    /// `poll_ready_tasks`, whose step-6 pass runs *before* the flush; see
    /// `bounded_send_owned_by_another_task_survives_its_connection_task_returning`.
    #[test]
    fn bounded_completion_is_delivered_before_teardown() {
        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, mut client) = attach_conn(&mut event_loop.driver);
        let conn = token(&event_loop.driver, conn_index);

        // The submitting future is on a standalone task: one owned by the
        // connection's own task is dropped by teardown before it could ever
        // read a result (`SendCompletions::remove_connection`).
        let task_id = parked_standalone(&mut event_loop.executor);
        let payload = vec![b'z'; 200];
        let id = event_loop
            .executor
            .enqueue_send_capacity(conn_index, conn.generation, 4, task_id);
        event_loop
            .driver
            .make_ctx()
            .send_bounded(conn, &payload, id)
            .expect("admitted");
        event_loop.executor.mark_send_submitted(id);

        // Close requested while the send is still queued.
        event_loop.driver.close_connection(conn_index);

        // One iteration's tail, in the run loop's order (steps 6a and 6b).
        event_loop.flush_all_pending_sends();
        event_loop.drain_send_completions();
        event_loop.drain_pending_closes();

        let result = event_loop
            .executor
            .take_send_result(id)
            .expect("the operation resolved");
        assert_eq!(
            result.expect("the bytes reached the socket, so this is not ConnectionAborted"),
            200,
            "a real completion must beat the teardown's synthetic abort"
        );
        assert!(
            event_loop.driver.tcp_streams[conn_index as usize].is_none(),
            "the teardown did run in the same iteration"
        );
        assert_eq!(
            event_loop.driver.send_copy_pool.free_count(),
            4,
            "the permit came back with the completion"
        );

        let mut buf = vec![0u8; 200];
        client
            .read_exact(&mut buf)
            .expect("the peer got the whole message");
    }

    /// The `poll_ready_tasks` route into `Executor::remove_connection`:
    /// teardown runs at step 6, *before* step 6a's flush, so ordering
    /// cannot save the result and the provisional-abort rule has to.
    ///
    /// A standalone task owns a bounded send on connection X. X's own task
    /// then returns `Poll::Ready`, so `poll_ready_tasks` closes and removes
    /// X while the send is still queued; the flush that follows in the same
    /// iteration writes every byte to the socket. The owner must be told
    /// `Ok(len)`, not `ConnectionAborted`: the message was delivered.
    ///
    /// Before the fix (teardown recording `Done(Err(ConnectionAborted))`,
    /// which `complete` then discarded as a second result) this failed with
    /// `Custom { kind: ConnectionAborted, error: "connection closed" }`.
    #[test]
    fn bounded_send_owned_by_another_task_survives_its_connection_task_returning() {
        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, mut client) = attach_conn(&mut event_loop.driver);
        let conn = token(&event_loop.driver, conn_index);

        // Owner: a standalone task, which outlives the connection.
        let task_id = parked_standalone(&mut event_loop.executor);
        let payload = vec![b'q'; 200];
        let id = event_loop
            .executor
            .enqueue_send_capacity(conn_index, conn.generation, 4, task_id);
        event_loop
            .driver
            .make_ctx()
            .send_bounded(conn, &payload, id)
            .expect("admitted");
        event_loop.executor.mark_send_submitted(id);

        // Step 6: the connection's own task runs and returns Ready.
        // `NoopHandler::on_accept` is `async move {}`, so the first poll
        // completes it and `poll_ready_tasks` takes the
        // close_connection + remove_connection branch.
        event_loop.spawn_accept_task(conn_index);
        event_loop.poll_ready_tasks();
        assert!(
            event_loop.driver.send_queues[conn_index as usize].close_pending,
            "the returning task requested the close"
        );
        assert!(
            !event_loop.driver.pending_sends[conn_index as usize].is_empty(),
            "teardown ran with the send still queued — the case under test"
        );

        // Steps 6a and 6b: flush, deliver completions, finalize the close.
        event_loop.flush_all_pending_sends();
        event_loop.drain_send_completions();
        event_loop.drain_pending_closes();

        let result = event_loop
            .executor
            .take_send_result(id)
            .expect("the operation resolved");
        assert_eq!(
            result.expect("every byte reached the socket, so this is not an abort"),
            200,
            "a real driver result must overwrite the teardown's synthetic abort"
        );
        assert!(
            event_loop.driver.tcp_streams[conn_index as usize].is_none(),
            "the teardown did finish in the same iteration"
        );
        assert_eq!(
            event_loop.driver.send_copy_pool.free_count(),
            4,
            "the permit came back with the completion"
        );

        let mut buf = vec![0u8; 200];
        client
            .read_exact(&mut buf)
            .expect("the peer got the whole message");
        assert!(buf.iter().all(|&b| b == b'q'));
    }

    /// Permits returning during an iteration wake the capacity head exactly
    /// once, at the end of the iteration — not once per released permit.
    ///
    /// "Once" is counted at the source (`Executor::send_capacity_wakes`),
    /// not inferred from `ready_queue.len()`: `wake_task` pushes only on a
    /// Parked → Ready transition, so a second wake of the same head in the
    /// same iteration would leave the queue length at 1 too. The last block
    /// shows the counter does move when a wake really is issued.
    #[test]
    fn capacity_head_is_woken_once_per_iteration_when_permits_return() {
        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, _client) = attach_conn(&mut event_loop.driver);
        let conn = token(&event_loop.driver, conn_index);

        // A waiter for three slots sits at the head of the FIFO. Two
        // one-slot sends are in flight behind it, so only two slots are
        // free: the head cannot be admitted until they complete.
        let head_task = parked_standalone(&mut event_loop.executor);
        let head =
            event_loop
                .executor
                .enqueue_send_capacity(conn_index, conn.generation, 3, head_task);
        for _ in 0..2 {
            let task = parked_standalone(&mut event_loop.executor);
            let id =
                event_loop
                    .executor
                    .enqueue_send_capacity(conn_index, conn.generation, 1, task);
            event_loop
                .driver
                .make_ctx()
                .send_bounded(conn, b"sixty-odd bytes is one slot", id)
                .expect("admitted");
            event_loop.executor.mark_send_submitted(id);
        }
        assert_eq!(event_loop.driver.send_copy_pool.free_count(), 2);
        assert!(
            !event_loop.executor.send_capacity_turn(head, 2),
            "the head needs three slots"
        );
        assert!(event_loop.executor.ready_queue.is_empty());

        // Both sends reach the socket in one flush: two permits come back.
        event_loop.flush_all_pending_sends();
        assert_eq!(event_loop.driver.send_copy_pool.free_count(), 4);
        assert!(
            event_loop.driver.capacity_released,
            "the driver records the release instead of waking"
        );
        assert!(
            event_loop.executor.ready_queue.is_empty(),
            "the driver must not touch the executor itself"
        );

        event_loop.wake_capacity_if_released();

        assert_eq!(
            event_loop.executor.send_capacity_wakes, 1,
            "two released permits, one wake"
        );
        assert_eq!(
            event_loop.executor.ready_queue.len(),
            1,
            "and that wake reached the head"
        );
        assert_eq!(event_loop.executor.ready_queue[0], head_task);
        assert!(
            event_loop.executor.send_capacity_turn(head, 4),
            "the head can now be admitted"
        );
        assert!(
            !event_loop.driver.capacity_released,
            "the flag is consumed by the wake"
        );

        // Nothing was released since, so a further call wakes nobody —
        // re-park the head first, so a second wake would be visible.
        park(&mut event_loop.executor, head_task);
        event_loop.executor.ready_queue.clear();
        event_loop.wake_capacity_if_released();
        assert_eq!(
            event_loop.executor.send_capacity_wakes, 1,
            "the head is woken once per iteration, not once per call"
        );
        assert!(event_loop.executor.ready_queue.is_empty());

        // The counter is what the assertions above rest on, so show it can
        // move: a permit released in the *next* iteration wakes the head
        // again.
        event_loop.driver.capacity_released = true;
        event_loop.wake_capacity_if_released();
        assert_eq!(
            event_loop.executor.send_capacity_wakes, 2,
            "a genuine second release does wake the head again"
        );
        assert_eq!(event_loop.executor.ready_queue, vec![head_task]);
    }

    /// A connected socket pair; the server end is handed over as a raw fd
    /// (as the acceptor thread does), the client end returned so the test
    /// keeps the connection alive.
    fn accepted_socket() -> (RawFd, std::net::TcpStream, std::net::SocketAddr) {
        use std::os::fd::IntoRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(addr).expect("connect to the listener");
        let (server, peer) = listener.accept().expect("accept the connection");
        server
            .set_nonblocking(true)
            .expect("nonblocking server end");
        (server.into_raw_fd(), client, peer)
    }

    /// A connection accepted while the table is full is closed before it
    /// reaches a handler, and counted (#598).
    #[test]
    fn an_accept_into_a_full_table_is_closed_and_counted() {
        use std::io::Read;
        let config = test_config();
        let (accept_tx, accept_rx) = crossbeam_channel::unbounded();
        let (mut event_loop, _wake) = test_loop_with_accept(&config, Some(accept_rx));
        while event_loop.driver.connections.allocate().is_some() {}
        let (fd, mut client, peer) = accepted_socket();
        let before = metrics::CONNECTIONS
            .value(metrics::conn::ACCEPT_TABLE_FULL)
            .unwrap_or(0);

        accept_tx
            .send(crate::acceptor::AcceptedConn {
                fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
                listener: crate::ListenerId::from_index(0),
                peer: crate::connection::PeerAddr::Tcp(peer),
            })
            .expect("send");
        event_loop.drain_channels();

        let after = metrics::CONNECTIONS
            .value(metrics::conn::ACCEPT_TABLE_FULL)
            .unwrap_or(0);
        assert!(
            after > before,
            "the drop was not counted ({before} -> {after})"
        );
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let mut b = [0u8; 1];
        assert_eq!(
            client.read(&mut b).expect("read"),
            0,
            "the accepted fd was not closed"
        );
    }

    /// The accept-time slot-reuse clear in `drain_channels` disposes of
    /// whatever the previous occupant left queued: permit back, id failed.
    ///
    /// One of four permit-disposal sites; a bare `pending_sends[idx].clear()`
    /// here strands the id and trips `SlotReservation`'s drop assert.
    #[test]
    fn accept_time_slot_reuse_fails_a_stale_bounded_send() {
        let config = test_config();
        let (accept_tx, accept_rx) = crossbeam_channel::unbounded();
        let (mut event_loop, _wake) = test_loop_with_accept(&config, Some(accept_rx));
        let (conn_index, _client) = attach_conn(&mut event_loop.driver);
        let conn = token(&event_loop.driver, conn_index);

        let task_id = parked_standalone(&mut event_loop.executor);
        let id = event_loop
            .executor
            .enqueue_send_capacity(conn_index, conn.generation, 1, task_id);
        event_loop
            .driver
            .make_ctx()
            .send_bounded(conn, b"stranded", id)
            .expect("admitted");
        event_loop.executor.mark_send_submitted(id);
        assert_eq!(event_loop.driver.send_copy_pool.free_count(), 3);

        // Free the slot with its send queue still populated — the state the
        // defensive clear exists for. No production path gets here today,
        // which is exactly why nothing else would notice it regressing.
        event_loop.driver.tcp_streams[conn_index as usize] = None;
        event_loop.driver.connections.release(conn_index);

        let (server_fd, _peer, peer_addr) = accepted_socket();
        accept_tx
            .send(crate::acceptor::AcceptedConn {
                // SAFETY: `accepted_socket` gave up ownership of `server_fd`.
                fd: unsafe { std::os::fd::FromRawFd::from_raw_fd(server_fd) },
                listener: crate::ListenerId::from_index(0),
                peer: crate::connection::PeerAddr::Tcp(peer_addr),
            })
            .expect("queue the accept");
        event_loop.drain_channels();
        assert!(
            event_loop.driver.tcp_streams[conn_index as usize].is_some(),
            "the free list is LIFO, so the accept reused the same slot"
        );
        assert!(
            event_loop.driver.pending_sends[conn_index as usize].is_empty(),
            "the stale entry went"
        );
        assert_eq!(
            event_loop.driver.send_copy_pool.free_count(),
            4,
            "its permit came back to the pool"
        );

        event_loop.drain_send_completions();
        let err = event_loop
            .executor
            .take_send_result(id)
            .expect("the stranded id must be told")
            .expect_err("the send never went");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string().contains("reused by a new accept"),
            "unexpected message: {err}"
        );
    }

    /// A write error fans out to every queued bounded id with the real
    /// errno, not a synthetic abort — through the event loop's own
    /// `fail_connection_on_send_error`, which is the third of the four
    /// permit-disposal sites. Driving the helper rather than re-implementing
    /// its body is the point: a bare `pending_sends[idx].clear()` there must
    /// fail this test.
    #[test]
    fn write_error_fails_queued_bounded_sends_with_the_real_error() {
        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, client) = attach_conn(&mut event_loop.driver);
        let idx = conn_index as usize;
        let conn = token(&event_loop.driver, conn_index);

        // Abort the peer: SO_LINGER 0 makes the close an RST.
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&client),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt: {}", io::Error::last_os_error());
        drop(client);

        // The RST is asynchronous: the first write after it may still
        // succeed, so write until one fails.
        let mut write_err = None;
        for _ in 0..500 {
            event_loop
                .driver
                .make_ctx()
                .send(conn, b"x")
                .expect("queued");
            match event_loop.driver.flush_sends(conn_index) {
                Ok(_) => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => {
                    write_err = Some(e);
                    break;
                }
            }
        }
        let write_err = write_err.expect("writing to an aborted peer must fail");
        assert!(
            write_err.raw_os_error().is_some(),
            "the fan-out has an errno to preserve: {write_err:?}"
        );
        // Which errno the probe saw is not the property under test and is not
        // stable across platforms: Linux reports ECONNRESET for the first
        // write after the reset and EPIPE for every later one, macOS reports
        // ECONNRESET throughout. What must hold is that whatever the *failing
        // flush* returned reaches every queued id verbatim, rather than the
        // synthetic `ConnectionAborted` that teardown would otherwise supply
        // (that one carries no errno, which is what distinguishes it).

        // Two bounded sends queued against the dead socket.
        let mut ids = Vec::new();
        for payload in [&b"a"[..], &b"b"[..]] {
            let task_id = parked_standalone(&mut event_loop.executor);
            let id =
                event_loop
                    .executor
                    .enqueue_send_capacity(conn_index, conn.generation, 1, task_id);
            event_loop
                .driver
                .make_ctx()
                .send_bounded(conn, payload, id)
                .expect("admission does not touch the socket");
            event_loop.executor.mark_send_submitted(id);
            ids.push(id);
        }

        // The flush pass hits the write error and routes it through
        // `fail_connection_on_send_error`.
        event_loop.flush_all_pending_sends();
        assert!(
            event_loop.driver.pending_sends[idx].is_empty(),
            "the failed connection's queue is discarded"
        );
        assert_eq!(
            event_loop.driver.send_copy_pool.free_count(),
            4,
            "a failed connection still returns its permits"
        );
        assert!(
            event_loop.driver.send_queues[idx].close_pending,
            "a hard write error closes the connection"
        );

        event_loop.drain_send_completions();
        let mut seen: Option<(Option<i32>, io::ErrorKind)> = None;
        for id in ids {
            let err = event_loop
                .executor
                .take_send_result(id)
                .unwrap_or_else(|| panic!("{id:?} was never told"))
                .expect_err("the write failed");
            assert!(
                err.raw_os_error().is_some(),
                "{id:?} got a synthetic error, not the real write failure: {err:?}"
            );
            // Every id was failed by one write, so they must agree.
            match seen {
                None => seen = Some((err.raw_os_error(), err.kind())),
                Some(first) => assert_eq!(
                    (err.raw_os_error(), err.kind()),
                    first,
                    "{id:?} disagrees with its queue-mate about the write error"
                ),
            }
        }
    }

    // ── Receive arrival log ────────────────────────────────────────

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// Wait until the server side of `conn_index` holds at least `n` unread
    /// bytes. On macOS, loopback bytes are not always readable when the
    /// client's `write_all` returns.
    fn wait_for_bytes(el: &AsyncEventLoop<NoopHandler>, conn_index: u32, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut peek = vec![0u8; n];
        loop {
            let stream = el.driver.tcp_streams[conn_index as usize]
                .as_ref()
                .expect("the connection has a stream");
            match stream.peek(&mut peek) {
                Ok(got) if got >= n => return,
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("peek: {e}"),
            }
            assert!(Instant::now() < deadline, "the written bytes never arrived");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// Write `data` from the client and read it in a batch whose time is
    /// `time`. The socket must hold no unread bytes before the write.
    fn read_in_batch(
        el: &mut AsyncEventLoop<NoopHandler>,
        client: &mut std::net::TcpStream,
        conn_index: u32,
        data: &[u8],
        time: Instant,
    ) {
        use std::io::Write;
        client.write_all(data).expect("client write");
        wait_for_bytes(el, conn_index, data.len());
        el.driver.recv_batch.begin_at(time);
        let mut buf = vec![0u8; 4096];
        el.handle_readable(conn_index, &mut buf, false);
    }

    /// Read one `\n`-terminated line with `with_data` and return the
    /// connection's `recv_arrival` afterwards.
    fn read_line(el: &mut AsyncEventLoop<NoopHandler>, ctx: ConnCtx) -> Option<(Instant, Instant)> {
        let waker = std::task::Waker::noop();
        let mut fut = std::pin::pin!(ctx.with_data(|d| match d.iter().position(|&b| b == b'\n') {
            Some(i) => crate::ParseResult::Consumed(i + 1),
            None => crate::ParseResult::NeedMore,
        }));
        in_poll(el, || {
            let mut cx = std::task::Context::from_waker(waker);
            assert!(
                fut.as_mut().poll(&mut cx).is_ready(),
                "the line is complete"
            );
            ctx.recv_arrival().map(|a| (a.first(), a.last()))
        })
    }

    /// Each read records its bytes at its batch's time, and a pipelined
    /// line reports the batch of its own first byte.
    #[test]
    fn reads_report_the_batch_that_read_each_byte() {
        let config = test_config();
        let (mut el, _wake) = test_loop(&config);
        let (conn_index, mut client) = attach_conn(&mut el.driver);
        let ctx = ConnCtx::new(conn_index, el.driver.connections.generation(conn_index));
        let base = Instant::now();

        read_in_batch(&mut el, &mut client, conn_index, b"a\n", at(base, 1));
        assert_eq!(read_line(&mut el, ctx), Some((at(base, 1), at(base, 1))));

        read_in_batch(&mut el, &mut client, conn_index, b"b\nc", at(base, 2));
        read_in_batch(&mut el, &mut client, conn_index, b"c\n", at(base, 3));
        assert_eq!(read_line(&mut el, ctx), Some((at(base, 2), at(base, 2))));
        assert_eq!(read_line(&mut el, ctx), Some((at(base, 2), at(base, 3))));
    }

    /// `finish_close` empties the slot's arrival log.
    #[test]
    fn a_closed_slot_releases_its_arrival_log() {
        let config = test_config();
        let (mut el, _wake) = test_loop(&config);
        let (conn_index, mut client) = attach_conn(&mut el.driver);
        read_in_batch(&mut el, &mut client, conn_index, b"a\nb", Instant::now());
        assert_eq!(el.driver.arrival[conn_index as usize].delivered(), 3);
        el.driver.finish_close(conn_index);
        assert_eq!(el.driver.arrival[conn_index as usize].delivered(), 0);
        assert_eq!(el.driver.arrival[conn_index as usize].len(), 0);
    }

    /// An accepted connection starts with an empty log, whatever the slot's
    /// log held.
    #[test]
    fn an_accepted_slot_starts_with_an_empty_arrival_log() {
        let config = test_config();
        let (accept_tx, accept_rx) = crossbeam_channel::unbounded();
        let (mut el, _wake) = test_loop_with_accept(&config, Some(accept_rx));
        el.driver.recv_batch.begin();
        el.driver.record_arrival(0, 100);
        let (fd, _client, peer) = accepted_socket();
        accept_tx
            .send(crate::acceptor::AcceptedConn {
                fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
                listener: crate::ListenerId::from_index(0),
                peer: crate::connection::PeerAddr::Tcp(peer),
            })
            .expect("send");
        el.drain_channels();
        assert!(
            el.driver.connections.get(0).is_some(),
            "precondition: slot 0"
        );
        assert_eq!(el.driver.arrival[0].delivered(), 0);
    }

    /// A forward source re-read by `drain_forward_resumes` is read in a batch
    /// of its own, not in the batch of the reads before the tasks ran.
    #[test]
    fn a_forward_resume_begins_a_batch() {
        use std::io::Write;
        let config = test_config();
        let (mut el, _wake) = test_loop(&config);
        let (source, mut client) = attach_conn(&mut el.driver);
        let (sink, _sink_client) = attach_conn(&mut el.driver);
        el.driver.forward_conn[source as usize] =
            Some(crate::backend::mio::driver::MioForwardState {
                sink_index: sink,
                sink_generation: el.driver.connections.generation(sink),
                len: 1 << 20,
                forwarded: 0,
            });
        // A read in the loop's batch, before the tasks ran.
        el.driver.recv_batch.begin_at(Instant::now());
        el.driver.record_arrival(source, 1);
        client.write_all(b"x").expect("client write");
        wait_for_bytes(&el, source, 1);
        el.driver.mark_forward_resume(source);
        let mut buf = vec![0u8; 4096];
        assert!(el.drain_forward_resumes(&mut buf));
        assert_eq!(el.driver.arrival[source as usize].delivered(), 2);
        assert_eq!(el.driver.arrival[source as usize].len(), 2);
    }

    /// A task woken by a write error that the flush pass found is polled
    /// before `drain_pending_closes` drops it: the poll window a close
    /// promises (#371) holds on this path too. With only unawaited sends
    /// queued, `drain_send_completions` delivers nothing and so polls
    /// nothing, so the finalize step has to poll the woken task itself.
    #[test]
    fn a_task_woken_by_a_flush_write_error_is_polled_before_its_close_finalizes() {
        use std::cell::Cell;
        use std::rc::Rc;

        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, client) = attach_conn(&mut event_loop.driver);
        let idx = conn_index as usize;
        let conn = token(&event_loop.driver, conn_index);

        // The connection's task: park on a read and record what it resolves
        // to. `None` after teardown means the task was dropped unpolled.
        let seen: Rc<Cell<Option<Result<usize, io::ErrorKind>>>> = Rc::new(Cell::new(None));
        let record = Rc::clone(&seen);
        let ctx = ConnCtx::new(conn_index, conn.generation);
        event_loop.executor.task_slab.spawn(
            conn_index,
            Box::pin(async move {
                let result = ctx
                    .with_data_result(|d| crate::ParseResult::Consumed(d.len()))
                    .await;
                record.set(Some(result.map_err(|e| e.kind())));
            }),
        );
        event_loop.executor.ready_queue.push_back(conn_index);
        event_loop.poll_ready_tasks();
        assert!(
            event_loop.executor.recv_waiters[idx],
            "the task parked on its read"
        );

        // Abort the peer: SO_LINGER 0 makes the close an RST.
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&client),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt: {}", io::Error::last_os_error());
        drop(client);

        // Step 6a: queue an unawaited send and flush, until the flush finds
        // the write error (the RST is asynchronous, so the first write after
        // it may still succeed). `flush_all_pending_sends` routes the error
        // through `fail_connection_on_send_error`, which requests the close
        // and wakes the parked task.
        let mut closed = false;
        for _ in 0..500 {
            event_loop
                .driver
                .make_ctx()
                .send(conn, b"x")
                .expect("queued");
            event_loop.driver.writable[idx] = true;
            event_loop.flush_all_pending_sends();
            if event_loop.driver.send_queues[idx].close_pending {
                closed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(closed, "writing to an aborted peer must fail");
        assert!(
            event_loop.executor.ready_queue.contains(&conn_index),
            "the write error woke the task"
        );

        // Steps 6a and 6b as the loop runs them.
        event_loop.drain_send_completions();
        event_loop.finalize_closes();

        // The task was polled, and `fail_connection_on_send_error` recorded
        // the write error for it. Which errno is not stable across platforms
        // (Linux: `ECONNRESET` then `EPIPE`; macOS: `ECONNRESET`).
        match seen.get() {
            Some(Err(io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset)) => {}
            other => panic!("the task must be polled and see the write error, got {other:?}"),
        }
        assert!(
            !event_loop.executor.task_slab.has_task(conn_index),
            "the close finalized"
        );
    }
}
