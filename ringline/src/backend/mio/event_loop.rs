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
use crate::runtime::io::{ConnCtx, DriverState, UdpCtx, set_driver_state_guarded};
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
            config.timer_slots,
            config.udp_bind.len() as u32,
            config.udp_recv_queue_capacity,
        );

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
            let udp_ctx = UdpCtx {
                udp_index: udp_index as u32,
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

        // Recv buffer for reading from sockets.
        let mut recv_buf = vec![0u8; 8192];

        loop {
            // 1. Fire expired timers.
            self.fire_expired_timers();

            // 2. Compute poll timeout from nearest timer deadline. Don't
            // block at all while tasks are already runnable (self-wakes
            // collected after the last poll pass, tasks woken from on_tick).
            self.executor.collect_wakeups();
            let timeout = if self.executor.ready_queue.is_empty() {
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

            // 4. Handle events.
            // Collect events into a temporary vec to avoid borrow conflict
            // (self.driver.events borrows driver, but handlers need &mut driver).
            let mut event_list: Vec<(mio::Token, bool, bool, bool)> =
                Vec::with_capacity(self.driver.events.iter().count());
            for event in self.driver.events.iter() {
                let is_err = event.is_error() || event.is_read_closed() || event.is_write_closed();
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
                                self.handle_readable(conn_index, &mut recv_buf);
                            }
                            continue;
                        }
                        if readable {
                            self.handle_readable(conn_index, &mut recv_buf);
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
            // iteration: executor cleanup (parked futures, waiter flags,
            // recv sinks) before the slot is released for reuse.
            self.drain_pending_closes();

            // 7. on_tick callback (synchronous). Set the executor's
            // driver_state thread-local so user code that calls
            // `ringline::spawn()` / wakers / `with_state` works from
            // inside the handler. Raw pointers dodge the borrow conflict
            // with `make_ctx()`.
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
                        handler.on_tick(&mut ctx);
                    }));
                    if result.is_err() {
                        eprintln!("ringline: handler on_tick panicked; continuing");
                    }
                }
                drop(guard);
            }

            // 8. Flush any sends queued by on_tick, deliver their
            // completions, and finish any closes it triggered.
            self.flush_all_pending_sends();
            self.drain_send_completions();
            self.drain_pending_closes();

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
            // Nothing is lost by waking late: `poll_ready_tasks` (6) has
            // already run, so a task woken anywhere from 6a onwards is
            // polled in the next iteration either way, and step 2 sees a
            // non-empty ready queue and polls with a zero timeout.
            self.wake_capacity_if_released();

            // 9. Check shutdown.
            if self.driver.shutdown_local || self.driver.shutdown_flag.load(Ordering::Relaxed) {
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
                fd: raw_fd,
                listener,
                peer: peer_addr,
            }) = item
            else {
                break;
            };

            let conn_index = match self.driver.connections.allocate() {
                Some(idx) => idx,
                None => {
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
                    mio::Interest::READABLE | mio::Interest::WRITABLE,
                )
                .is_err()
            {
                self.driver.connections.release(conn_index);
                continue;
            }

            let idx = conn_index as usize;
            self.driver.tcp_streams[idx] = Some(mio_stream);
            self.driver.accumulators.reset(conn_index);
            // Defensive: a freshly allocated slot should have an empty send
            // queue, but if anything survived, its bounded entries must be
            // failed and their permits returned rather than dropped.
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
                self.executor
                    .deliver_blocking(response.request_id, response.result);
            }
        }

        // Drain disk I/O responses.
        if let Some(ref rx) = self.driver.disk_io_rx {
            while let Ok(response) = rx.try_recv() {
                // Handle fs_open completions: install fd or release slot.
                if let Some(file_index) = self.driver.pending_fs_opens.remove(&response.seq) {
                    if response.result >= 0 {
                        // Success — result is the fd.
                        let fd = response.result;
                        self.driver.fs_fds[file_index as usize] = Some(fd as std::os::fd::RawFd);
                        if let Some(ref mut files) = self.driver.fs_files
                            && let Some(f) = files.get_mut(file_index)
                        {
                            f.fd_index = fd as u32;
                        }
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
        self.executor.wake_recv(conn_index);
        self.driver.close_connection(conn_index);
        false
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
        for source in ready {
            // A TLS source's plaintext is already decrypted into the
            // accumulator, so it has to be moved on before another read is
            // attempted — a read that may well return EWOULDBLOCK.
            if self.driver.forward_conn[source as usize].is_some()
                && self.driver.forward_take_accumulated(source).is_some()
            {
                self.executor.wake_recv(source);
            }
            self.handle_readable(source, recv_buf);
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
    fn handle_readable(&mut self, conn_index: u32, recv_buf: &mut [u8]) {
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

                let tls_table = self.driver.tls_table.as_mut().unwrap();
                let result = crate::tls::feed_tls_recv_mio(
                    tls_table,
                    &mut self.driver.accumulators,
                    &mut self.driver.pending_sends[idx],
                    conn_index,
                    &recv_buf[..n],
                );

                // Put the stream back.
                self.driver.tcp_streams[idx] = Some(stream);

                // feed_tls_recv_mio pushes handshake/ciphertext output into
                // pending_sends directly (not via DriverCtx), so uphold the
                // dirty invariant here or the flush pass never visits it.
                if !self.driver.pending_sends[idx].is_empty() {
                    self.driver.mark_send_dirty(idx);
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
                    // A forward owns this connection's bytes: they go to the
                    // sink's send queue, not to the accumulator or a recv sink.
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
                        continue;
                    }
                    // Check if the connection has a recv sink (direct-to-buffer).
                    let sink = &mut self.executor.recv_sinks[idx];
                    let appended = if let Some(recv_sink) = sink {
                        let remaining = recv_sink.cap - recv_sink.pos;
                        let to_copy = n.min(remaining);
                        if to_copy > 0 {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    recv_buf.as_ptr(),
                                    recv_sink.ptr.add(recv_sink.pos),
                                    to_copy,
                                );
                            }
                            recv_sink.pos += to_copy;
                        }
                        // If there's overflow beyond the sink, put it in accumulator.
                        if n > to_copy {
                            self.driver
                                .accumulators
                                .append(conn_index, &recv_buf[to_copy..n])
                        } else {
                            true
                        }
                    } else {
                        self.driver.accumulators.append(conn_index, &recv_buf[..n])
                    };
                    if !appended {
                        // Streamed past recv_accumulator_max. The bytes were
                        // already read off the socket, so the stream cannot
                        // continue coherently — close rather than OOM,
                        // matching the uring and mio-TLS overflow paths.
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
                        break;
                    }
                    self.executor.wake_recv(conn_index);
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
                        mio::Interest::READABLE | mio::Interest::WRITABLE,
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
        // Every queued bounded send fails with the same error the write
        // produced (cloned per id — `io::Error` is not `Clone`), and gives
        // its copy-pool permit back.
        self.driver.clear_pending_sends(conn_index as usize, || {
            crate::backend::mio::driver::clone_io_error(&e)
        });
        self.executor.wake_send(conn_index, Err(e));
        self.executor.wake_recv(conn_index);
        self.driver.close_connection(conn_index);
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
    /// errors. `close_notify_timeout_ms` is inert on mio.
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

    /// Drain the driver's send completions and re-poll the tasks they woke.
    ///
    /// Two queues, in this order: the worker-wide bounded-send queue
    /// (`Driver::bounded_send_completions`, routed by id through
    /// `Executor::complete_bounded_send`), then the per-connection
    /// `send_completions` queues, calling wake_send for each so that each
    /// SendFuture resolves. The per-connection pass visits only connections
    /// marked dirty at completion-push time; a connection with results left
    /// over (single waiter slot, or no waiter yet) is re-marked for the next
    /// pass.
    ///
    /// Returned copy-pool permits are *not* signalled here: the driver sets
    /// `capacity_released` wherever a permit goes back, and the run loop
    /// issues one `wake_send_capacity` per iteration (see step 8a).
    fn drain_send_completions(&mut self) {
        loop {
            let mut delivered = false;
            // Bounded (`send_backpressured`) completions first. They are
            // keyed by id rather than by connection, so they bypass the
            // dirty-list entirely; the executor's FIFO routes each result
            // to the exact operation that produced it. Draining them here
            // (rather than after the per-connection pass) keeps them ahead
            // of `drain_pending_closes`, so a bounded send whose last byte
            // reached the socket is recorded `Ok` before
            // `Executor::remove_connection` would resolve it as
            // `ConnectionAborted`.
            while let Some((id, result)) = self.driver.bounded_send_completions.pop_front() {
                self.executor.complete_bounded_send(id, result);
                delivered = true;
            }
            let dirty = std::mem::take(&mut self.driver.completions_dirty);
            for conn_index in dirty {
                let idx = conn_index as usize;
                self.driver.completions_dirty_flag[idx] = false;
                if let Some(bytes) = self.driver.send_completions[idx].pop_front()
                    && self.executor.send_waiters[idx]
                {
                    self.executor.wake_send(conn_index, Ok(bytes));
                    delivered = true;
                }
                if !self.driver.send_completions[idx].is_empty()
                    && !self.driver.completions_dirty_flag[idx]
                {
                    self.driver.completions_dirty_flag[idx] = true;
                    self.driver.completions_dirty.push(conn_index);
                }
            }
            if !delivered {
                break;
            }
            // Re-poll tasks woken by the completions so they can consume
            // the results and potentially re-register waiters.
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
        let future = Box::pin(self.handler.on_accept(conn));
        self.executor.owner_task[conn_index as usize] = Some(conn_index);
        self.executor.task_slab.spawn(conn_index, future);
        self.executor.ready_queue.push_back(conn_index);
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
        // Context-driven self-wake instead resumes on the next iteration.

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
                            // Self-wake during poll (slot read `Polling`) —
                            // re-queue now that the task is parked.
                            if executor.woken_while_polling {
                                let _ = executor.wake_task(raw_id);
                            }
                        }
                        Err(_panic) => {
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
    /// `poll_ready_tasks` — which runs *before* the flush; see
    /// `bounded_send_owned_by_another_task_survives_its_connection_task_returning`.
    #[test]
    fn bounded_completion_is_delivered_before_teardown() {
        let config = test_config();
        let (mut event_loop, _wake) = test_loop(&config);
        let (conn_index, mut client) = attach_conn(&mut event_loop.driver);
        let conn = token(&event_loop.driver, conn_index);

        // The submitting future is on a standalone task: one owned by the
        // connection's own task is dropped by teardown before it could ever
        // read a result (`SendCapacityQueue::remove_connection`).
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
        event_loop.executor.mark_bounded_send_submitted(id);

        // Close requested while the send is still queued.
        event_loop.driver.close_connection(conn_index);

        // One iteration's tail, in the run loop's order (steps 6a and 6b).
        event_loop.flush_all_pending_sends();
        event_loop.drain_send_completions();
        event_loop.drain_pending_closes();

        let result = event_loop
            .executor
            .take_bounded_send_result(id)
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
        event_loop.executor.mark_bounded_send_submitted(id);

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
            .take_bounded_send_result(id)
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
            event_loop.executor.mark_bounded_send_submitted(id);
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
        event_loop.executor.mark_bounded_send_submitted(id);
        assert_eq!(event_loop.driver.send_copy_pool.free_count(), 3);

        // Free the slot with its send queue still populated — the state the
        // defensive clear exists for. No production path gets here today,
        // which is exactly why nothing else would notice it regressing.
        event_loop.driver.tcp_streams[conn_index as usize] = None;
        event_loop.driver.connections.release(conn_index);

        let (server_fd, _peer, peer_addr) = accepted_socket();
        accept_tx
            .send(crate::acceptor::AcceptedConn {
                fd: server_fd,
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
            .take_bounded_send_result(id)
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
            event_loop.executor.mark_bounded_send_submitted(id);
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
                .take_bounded_send_result(id)
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
}
