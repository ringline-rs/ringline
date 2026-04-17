//! Mio backend event loop — readiness-based I/O dispatch.

use std::io;
use std::io::Read;
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Context;
use std::time::{Duration, Instant};

use crate::backend::Driver;
use crate::config::Config;
use crate::connection::RecvMode;
use crate::metrics;
use crate::runtime::handler::AsyncEventHandler;
use crate::runtime::io::{ConnCtx, DriverState, clear_driver_state, set_driver_state};
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
        accept_rx: Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
        eventfd: RawFd,
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
        )?;

        let executor = Executor::new(
            config.max_connections,
            config.standalone_task_capacity,
            config.timer_slots,
            config.udp_bind.len() as u32,
        );

        Ok(AsyncEventLoop {
            driver,
            handler,
            executor,
        })
    }

    /// Run the mio event loop until shutdown.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
        // Register the wake pipe read-end with mio Poll.
        self.driver.poll.registry().register(
            &mut mio::unix::SourceFd(&self.driver.wake_pipe_fd),
            WAKE_TOKEN,
            mio::Interest::READABLE,
        )?;

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

            // 2. Compute poll timeout from nearest timer deadline.
            let timeout = self.compute_poll_timeout();

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
            let mut event_list: Vec<(mio::Token, bool, bool)> =
                Vec::with_capacity(self.driver.events.iter().count());
            for event in self.driver.events.iter() {
                event_list.push((event.token(), event.is_readable(), event.is_writable()));
            }

            for (token, readable, writable) in event_list {
                match token {
                    WAKE_TOKEN => {
                        if readable {
                            self.drain_wake_pipe();
                        }
                    }
                    tok => {
                        let conn_index = (tok.0 - 1) as u32;
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

            // 6a. Deliver buffered send completions and re-poll until drained.
            self.drain_send_completions();

            // 6b. Flush pending sends that were queued during task polling.
            self.flush_all_pending_sends();

            // 7. on_tick callback (synchronous).
            {
                let mut ctx = self.driver.make_ctx();
                self.handler.on_tick(&mut ctx);
            }

            // 8. Deliver send completions and flush any sends queued by on_tick.
            self.drain_send_completions();
            self.flush_all_pending_sends();

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
            let Some((raw_fd, peer_addr)) = item else {
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
                cs.peer_addr = Some(crate::connection::PeerAddr::Tcp(peer_addr));
            }

            // Convert raw fd to mio TcpStream.
            let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw_fd) };
            std_stream.set_nonblocking(true).ok();
            if self.driver.tcp_nodelay {
                std_stream.set_nodelay(true).ok();
            }
            let mut mio_stream = mio::net::TcpStream::from_std(std_stream);

            // Register with poll for READABLE interest.
            let mio_token = mio::Token(conn_index as usize + 1);
            if self
                .driver
                .poll
                .registry()
                .register(&mut mio_stream, mio_token, mio::Interest::READABLE)
                .is_err()
            {
                self.driver.connections.release(conn_index);
                continue;
            }

            let idx = conn_index as usize;
            self.driver.tcp_streams[idx] = Some(mio_stream);
            self.driver.accumulators.reset(conn_index);
            self.driver.pending_sends[idx].clear();
            self.driver.writable[idx] = false;

            // Mark connection as established.
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.established = true;
            }

            metrics::CONNECTIONS_ACCEPTED.increment();
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

        // on_notify (synchronous).
        {
            let mut ctx = self.driver.make_ctx();
            self.handler.on_notify(&mut ctx);
        }
    }

    /// Handle a connection becoming readable: read data into accumulator.
    fn handle_readable(&mut self, conn_index: u32, recv_buf: &mut [u8]) {
        let idx = conn_index as usize;

        // Check the connection is still active.
        if self.driver.tcp_streams[idx].is_none() {
            return;
        }

        loop {
            let stream = match self.driver.tcp_streams[idx].as_mut() {
                Some(s) => s,
                None => return,
            };

            match stream.read(recv_buf) {
                Ok(0) => {
                    // EOF — mark connection as recv-closed.
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.recv_mode = RecvMode::Closed;
                    }
                    // Wake any task waiting for recv so it sees EOF.
                    self.executor.wake_recv(conn_index);
                    break;
                }
                Ok(n) => {
                    // Check if the connection has a recv sink (direct-to-buffer).
                    let sink = &mut self.executor.recv_sinks[idx];
                    if let Some(recv_sink) = sink {
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
                                .append(conn_index, &recv_buf[to_copy..n]);
                        }
                    } else {
                        self.driver.accumulators.append(conn_index, &recv_buf[..n]);
                    }
                    self.executor.wake_recv(conn_index);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(_) => {
                    // Read error — mark as closed.
                    if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                        cs.recv_mode = RecvMode::Closed;
                    }
                    self.executor.wake_recv(conn_index);
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
            && matches!(cs.recv_mode, RecvMode::Connecting)
        {
            // Connect completed — check for errors via peer_addr().
            let result = if let Some(ref stream) = self.driver.tcp_streams[idx] {
                match stream.peer_addr() {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e),
                }
            } else {
                Err(io::Error::other("stream missing"))
            };

            if result.is_ok() {
                cs.recv_mode = RecvMode::Multi;
                cs.established = true;

                // Set TCP_NODELAY if configured.
                if self.driver.tcp_nodelay
                    && let Some(ref stream) = self.driver.tcp_streams[idx]
                {
                    let _ = stream.set_nodelay(true);
                }

                // Reset accumulator for the new connection.
                self.driver.accumulators.reset(conn_index);

                metrics::CONNECTIONS_ACTIVE.increment();
            }

            let io_result = match result {
                Ok(()) => Ok(()),
                Err(e) => Err(e),
            };
            self.executor.wake_connect(conn_index, io_result);
            return;
        }

        // Normal writable — mark writable and flush sends.
        self.driver.writable[idx] = true;
        self.driver.flush_sends(conn_index);
    }

    /// Flush pending sends for all connections that have buffered data.
    fn flush_all_pending_sends(&mut self) {
        let max = self.driver.pending_sends.len();
        for idx in 0..max {
            if !self.driver.pending_sends[idx].is_empty() {
                // Register writable interest so mio tells us when we can write.
                self.driver.register_writable(idx as u32);
                // If we already know the socket is writable, try flushing now.
                if self.driver.writable[idx] {
                    self.driver.flush_sends(idx as u32);
                }
            }
        }
    }

    /// Drain per-connection send completion queues, calling wake_send for
    /// each and re-polling tasks so that each SendFuture resolves.
    fn drain_send_completions(&mut self) {
        loop {
            let mut delivered = false;
            let max = self.driver.send_completions.len();
            for idx in 0..max {
                if let Some(bytes) = self.driver.send_completions[idx].pop_front()
                    && self.executor.send_waiters[idx]
                {
                    self.executor.wake_send(idx as u32, Ok(bytes));
                    delivered = true;
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
        // Collect timer slots that should fire to avoid borrow conflict.
        let mut to_fire: Vec<(u32, u16)> = Vec::new();
        let pool = &self.executor.timer_pool;
        for slot in 0..pool.deadlines.len() {
            if let Some(deadline) = pool.deadlines[slot]
                && now >= deadline
                && !pool.fired[slot]
            {
                let generation = pool.generations[slot];
                to_fire.push((slot as u32, generation));
            }
        }
        for (slot, generation) in to_fire {
            if let Some(waker_id) = self.executor.timer_pool.fire(slot, generation) {
                self.executor.wake_task(waker_id);
            }
        }
    }

    /// Compute the poll timeout from the nearest timer deadline.
    fn compute_poll_timeout(&self) -> Duration {
        let now = Instant::now();
        let mut min_duration = Duration::from_millis(10); // default tick interval

        let pool = &self.executor.timer_pool;
        for slot in 0..pool.deadlines.len() {
            if let Some(deadline) = pool.deadlines[slot]
                && !pool.fired[slot]
            {
                let remaining = deadline.saturating_duration_since(now);
                if remaining < min_duration {
                    min_duration = remaining;
                }
            }
        }

        min_duration
    }

    /// Spawn an async task for a newly accepted connection.
    fn spawn_accept_task(&mut self, conn_index: u32) {
        let generation = self.driver.connections.generation(conn_index);
        let conn_ctx = ConnCtx::new(conn_index, generation);
        let future = Box::pin(self.handler.on_accept(conn_ctx));
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

        let mut driver_state = DriverState { driver, executor };
        set_driver_state(&mut driver_state);

        // Safety: we have exclusive access to driver/executor via self, and
        // only access them through these raw pointers until clear_driver_state.
        let driver = unsafe { &mut *driver };
        let executor = unsafe { &mut *executor };

        let mut i = 0;
        while i < executor.ready_queue.len() {
            let raw_id = executor.ready_queue[i];
            i += 1;

            if raw_id & STANDALONE_BIT != 0 {
                // Standalone task.
                let task_idx = raw_id & !STANDALONE_BIT;
                if let Some(mut fut) = executor.standalone_slab.take_ready(task_idx) {
                    let waker = standalone_waker(task_idx);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(raw_id));
                    match fut.as_mut().poll(&mut cx) {
                        std::task::Poll::Ready(()) => {
                            executor.standalone_slab.remove(task_idx);
                        }
                        std::task::Poll::Pending => {
                            executor.standalone_slab.park(task_idx, fut);
                        }
                    }
                }
            } else {
                // Connection task.
                let conn_index = raw_id;
                if let Some(mut fut) = executor.task_slab.take_ready(conn_index) {
                    let waker = conn_waker(conn_index);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(conn_index));
                    match fut.as_mut().poll(&mut cx) {
                        std::task::Poll::Ready(()) => {
                            // Task completed — connection handler is done.
                            driver.close_connection(conn_index);
                            executor.remove_connection(conn_index);
                        }
                        std::task::Poll::Pending => {
                            executor.task_slab.park(conn_index, fut);
                        }
                    }
                }
            }
        }

        clear_driver_state();

        // Clear processed entries.
        executor.ready_queue.clear();

        // Drain any wakeups that happened during polling.
        executor.collect_wakeups();
    }
}
