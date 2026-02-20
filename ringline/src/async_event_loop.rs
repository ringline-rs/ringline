use std::io;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::time::Instant;

use io_uring::cqueue;

use crate::chain::ChainEvent;
use crate::completion::{OpTag, UserData};
use crate::connection::RecvMode;
use crate::driver::Driver;
use crate::driver::sockaddr_to_socket_addr;
use crate::metrics;
use crate::runtime::handler::AsyncEventHandler;
use crate::runtime::io::{ConnCtx, DriverState, UdpCtx, clear_driver_state, set_driver_state};
use crate::runtime::waker::{STANDALONE_BIT, conn_waker, standalone_waker};
use crate::runtime::{CURRENT_TASK_ID, Executor, TimerSlotPool};

/// Async event loop that reuses `Driver` infrastructure with an `Executor`
/// for polling connection futures instead of push-based callbacks.
pub(crate) struct AsyncEventLoop<A: AsyncEventHandler> {
    driver: Driver,
    handler: A,
    executor: Executor,
}

impl<A: AsyncEventHandler> AsyncEventLoop<A> {
    /// Create a new async event loop for a worker thread.
    pub(crate) fn new(
        config: &crate::config::Config,
        handler: A,
        accept_rx: Option<crossbeam_channel::Receiver<(std::os::fd::RawFd, std::net::SocketAddr)>>,
        eventfd: std::os::fd::RawFd,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self, crate::error::Error> {
        let driver = Driver::new(config, accept_rx, eventfd, shutdown_flag)?;
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

    /// Run the async event loop. Blocks the current thread.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
        // Always arm eventfd read — needed for shutdown wakeup even in client-only mode.
        self.driver
            .ring
            .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr())?;

        // Kick the eventfd so the first submit_and_wait(1) returns immediately.
        let kick: u64 = 1;
        unsafe {
            libc::write(
                self.driver.eventfd,
                &kick as *const u64 as *const libc::c_void,
                8,
            );
        }

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

        loop {
            // Arm a tick timeout before blocking.
            if !self.driver.tick_timeout_armed
                && let Some(ref ts) = self.driver.tick_timeout_ts
            {
                let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
                let _ = self
                    .driver
                    .ring
                    .submit_tick_timeout(ts as *const _, ud.raw());
                self.driver.tick_timeout_armed = true;
            }

            self.driver.ring.submit_and_wait(1)?;

            self.drain_completions();

            // Check for shutdown after processing completions.
            if self.driver.shutdown_local || self.driver.shutdown_flag.load(Ordering::Relaxed) {
                self.driver.run_shutdown();
                return Ok(());
            }

            // Batch replenish recv buffers.
            if !self.driver.pending_replenish.is_empty() {
                self.driver
                    .provided_bufs
                    .replenish_batch(&self.driver.pending_replenish);
                self.driver.pending_replenish.clear();
            }

            // Drain waker-based ready queue (from wakers fired during poll).
            self.executor.collect_wakeups();

            // Poll all ready tasks.
            self.poll_ready_tasks();

            // on_tick callback (synchronous).
            let mut ctx = self.driver.make_ctx();
            self.handler.on_tick(&mut ctx);
        }
    }

    /// Poll all tasks in the ready queue (both connection and standalone tasks).
    fn poll_ready_tasks(&mut self) {
        // Set thread-local driver pointer once for the entire batch.
        let mut driver_state = DriverState {
            driver: &mut self.driver as *mut Driver,
            executor: &mut self.executor as *mut Executor,
        };
        set_driver_state(&mut driver_state);

        let mut i = 0;
        while i < self.executor.ready_queue.len() {
            let raw_id = self.executor.ready_queue[i];
            i += 1;

            if raw_id & STANDALONE_BIT != 0 {
                // Standalone task.
                let task_idx = raw_id & !STANDALONE_BIT;
                if let Some(mut fut) = self.executor.standalone_slab.take_ready(task_idx) {
                    let waker = standalone_waker(task_idx);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(raw_id));
                    match fut.as_mut().poll(&mut cx) {
                        std::task::Poll::Ready(()) => {
                            // Standalone task completed — just remove it.
                            self.executor.standalone_slab.remove(task_idx);
                        }
                        std::task::Poll::Pending => {
                            self.executor.standalone_slab.park(task_idx, fut);
                        }
                    }
                }
            } else {
                // Connection task.
                let conn_index = raw_id;
                if let Some(mut fut) = self.executor.task_slab.take_ready(conn_index) {
                    let waker = conn_waker(conn_index);
                    let mut cx = Context::from_waker(&waker);

                    CURRENT_TASK_ID.with(|c| c.set(conn_index));
                    match fut.as_mut().poll(&mut cx) {
                        std::task::Poll::Ready(()) => {
                            // Task completed — connection handler is done.
                            self.driver.close_connection(conn_index);
                            self.executor.remove_connection(conn_index);
                        }
                        std::task::Poll::Pending => {
                            self.executor.task_slab.park(conn_index, fut);
                        }
                    }
                }
            }
        }

        clear_driver_state();

        // Clear processed entries.
        self.executor.ready_queue.clear();

        // Drain any wakeups that happened during polling.
        self.executor.collect_wakeups();
    }

    fn drain_completions(&mut self) {
        self.driver.cqe_batch.clear();

        {
            let cq = self.driver.ring.ring.completion();
            for cqe in cq {
                self.driver.cqe_batch.push((
                    cqe.user_data(),
                    cqe.result(),
                    cqe.flags(),
                    *cqe.big_cqe(),
                ));
            }
        }

        if let Some(interval) = self.driver.flush_interval {
            let mut last_flush = Instant::now();
            for i in 0..self.driver.cqe_batch.len() {
                let (user_data_raw, result, flags, _big_cqe) = self.driver.cqe_batch[i];
                self.dispatch_cqe(user_data_raw, result, flags);
                // Check the clock every 16 CQEs to amortise Instant::now() cost.
                if (i & 0xF) == 0xF {
                    let now = Instant::now();
                    if now.duration_since(last_flush) >= interval {
                        let _ = self.driver.ring.flush();
                        last_flush = now;
                    }
                }
            }
        } else {
            for i in 0..self.driver.cqe_batch.len() {
                let (user_data_raw, result, flags, _big_cqe) = self.driver.cqe_batch[i];
                self.dispatch_cqe(user_data_raw, result, flags);
            }
        }
    }

    fn dispatch_cqe(&mut self, user_data_raw: u64, result: i32, flags: u32) {
        metrics::CQE_PROCESSED.increment();
        let ud = UserData(user_data_raw);
        let tag = match ud.tag() {
            Some(t) => t,
            None => return,
        };

        match tag {
            OpTag::RecvMulti => self.handle_recv_multi(ud, result, flags),
            OpTag::Send => self.handle_send(ud, result),
            OpTag::SendMsgZc => self.handle_send_msg_zc(ud, result, flags),
            OpTag::Close => self.handle_close(ud),
            OpTag::Shutdown => {}
            OpTag::EventFdRead => self.handle_eventfd_read(),
            #[cfg(feature = "tls")]
            OpTag::TlsSend => self.handle_tls_send(ud, result),
            OpTag::Connect => self.handle_connect(ud, result),
            OpTag::Timeout => self.handle_timeout(ud, result),
            OpTag::Cancel => {}
            OpTag::TickTimeout => {
                self.driver.tick_timeout_armed = false;
            }
            OpTag::Timer => self.handle_timer(ud, result),
            OpTag::RecvMsgUdp => self.handle_recv_msg_udp(ud, result),
            OpTag::SendMsgUdp => self.handle_send_msg_udp(ud, result),
            OpTag::NvmeCmd => self.handle_nvme_cmd(ud, result),
            OpTag::DirectIo => self.handle_direct_io(ud, result),
        }
    }

    fn handle_recv_multi(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let has_more = cqueue::more(flags);

        if self.driver.connections.get(conn_index).is_none() {
            return;
        }

        if result <= 0 {
            if result == 0 {
                // Wake recv waiter before closing so the owning task can
                // detect EOF (with_data will see RecvMode::Closed and return 0).
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
            let errno = -result;
            if errno == libc::ENOBUFS {
                metrics::BUFFER_RING_EMPTY.increment();
                if !has_more {
                    let _ = self.driver.ring.submit_multishot_recv(conn_index);
                }
            } else if errno == libc::ECANCELED {
                return;
            } else if !has_more {
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
            }
            return;
        }

        let bid = match cqueue::buffer_select(flags) {
            Some(bid) => bid,
            None => return,
        };

        let bytes_received = result as u32;
        metrics::BYTES_RECEIVED.add(bytes_received as u64);
        let (buf_ptr, _) = self.driver.provided_bufs.get_buffer(bid);
        let data = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_received as usize) };

        self.driver.pending_replenish.push(bid);

        // TLS path
        #[cfg(feature = "tls")]
        let is_tls_conn = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has(conn_index));
        #[cfg(not(feature = "tls"))]
        let is_tls_conn = false;

        if is_tls_conn {
            #[cfg(feature = "tls")]
            {
                let tls_table = self.driver.tls_table.as_mut().unwrap();
                let result = crate::tls::feed_tls_recv(
                    tls_table,
                    &mut self.driver.accumulators,
                    &mut self.driver.ring,
                    &mut self.driver.send_copy_pool,
                    &mut self.driver.tls_scratch,
                    conn_index,
                    data,
                );

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
                            metrics::CONNECTIONS_ACCEPTED.increment();
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
                    crate::tls::TlsRecvResult::Error(_) | crate::tls::TlsRecvResult::Closed => {
                        self.driver.close_connection(conn_index);
                        self.executor.remove_connection(conn_index);
                    }
                }
            }
        } else {
            // Plaintext path: route through recv sink if active, else accumulator.
            if let Some(sink) = &mut self.executor.recv_sinks[conn_index as usize] {
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
                if to_sink < data.len() {
                    self.driver
                        .accumulators
                        .append(conn_index, &data[to_sink..]);
                }
            } else {
                self.driver.accumulators.append(conn_index, data);
            }
            self.executor.wake_recv(conn_index);
        }

        if !has_more
            && let Some(conn) = self.driver.connections.get(conn_index)
            && matches!(conn.recv_mode, RecvMode::Multi)
        {
            let _ = self.driver.ring.submit_multishot_recv(conn_index);
        }
    }

    fn handle_eventfd_read(&mut self) {
        // Drain accept channel (server mode only).
        {
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

                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.peer_addr = Some(peer_addr);
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
                    continue;
                }
                unsafe {
                    libc::close(raw_fd);
                }

                self.driver.accumulators.reset(conn_index);
                let _ = self.driver.ring.submit_multishot_recv(conn_index);

                // TLS path: defer accept until handshake completes.
                #[cfg(feature = "tls")]
                if let Some(ref mut tls_table) = self.driver.tls_table
                    && tls_table.has_server_config()
                {
                    tls_table.create(conn_index);
                    continue;
                }

                // Plaintext path: mark established and spawn async task.
                if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                    cs.established = true;
                }
                metrics::CONNECTIONS_ACCEPTED.increment();
                metrics::CONNECTIONS_ACTIVE.increment();
                self.spawn_accept_task(conn_index);
            }
        }

        // on_notify (synchronous).
        {
            let mut ctx = self.driver.make_ctx();
            self.handler.on_notify(&mut ctx);
        }

        // Re-arm eventfd read.
        if !self.driver.shutdown_flag.load(Ordering::Relaxed) {
            let _ = self
                .driver
                .ring
                .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr());
        }
    }

    fn handle_send(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let pool_slot = ud.payload() as u16;

        // Chain path.
        if self.driver.chain_table.is_active(conn_index) {
            self.driver.send_copy_pool.release(pool_slot);
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
                let _ = self
                    .driver
                    .ring
                    .submit_send_copied(conn_index, ptr, remaining, pool_slot);
                return;
            }
            let total = self.driver.send_copy_pool.original_len(pool_slot);
            metrics::BYTES_SENT.add(total as u64);
            self.driver.send_copy_pool.release(pool_slot);

            self.driver.submit_next_queued(conn_index);

            // Wake the send waiter.
            self.executor.wake_send(conn_index, Ok(total));
            return;
        }

        self.driver.send_copy_pool.release(pool_slot);
        self.driver.drain_conn_send_queue(conn_index);

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

        // Chain path.
        if self.driver.chain_table.is_active(conn_index) {
            if cqueue::notif(flags) {
                self.driver.send_slab.dec_pending_notifs(slab_idx);
                if self.driver.send_slab.should_release(slab_idx) {
                    let ps = self.driver.send_slab.release(slab_idx);
                    if ps != u16::MAX {
                        self.driver.send_copy_pool.release(ps);
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
                    self.driver.send_copy_pool.release(ps);
                }
            } else if result >= 0 {
                self.driver.send_slab.inc_pending_notifs(slab_idx);
                self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                self.driver.chain_table.inc_zc_notif(conn_index);
            } else {
                let ps = self.driver.send_slab.release(slab_idx);
                if ps != u16::MAX {
                    self.driver.send_copy_pool.release(ps);
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
                    self.driver.send_copy_pool.release(pool_slot);
                }
            }
            return;
        }

        self.driver.send_slab.inc_pending_notifs(slab_idx);

        if result > 0
            && let Some(msg_ptr) = self.driver.send_slab.try_advance(slab_idx, result as u32)
            && self
                .driver
                .ring
                .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                .is_ok()
        {
            return;
        }

        self.driver.send_slab.mark_awaiting_notifications(slab_idx);

        let total_len = self.driver.send_slab.total_len(slab_idx);
        let should_release = self.driver.send_slab.should_release(slab_idx);

        if should_release {
            let pool_slot = self.driver.send_slab.release(slab_idx);
            if pool_slot != u16::MAX {
                self.driver.send_copy_pool.release(pool_slot);
            }
        }

        if result >= 0 {
            metrics::BYTES_SENT.add(total_len as u64);
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

            #[cfg(feature = "tls")]
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
                .map(|c| matches!(c.recv_mode, RecvMode::Connecting))
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

        self.driver.accumulators.reset(conn_index);

        // TLS client path
        #[cfg(feature = "tls")]
        if let Some(ref mut tls_table) = self.driver.tls_table
            && tls_table.get_mut(conn_index).is_some()
        {
            crate::tls::flush_tls_output(
                tls_table,
                &mut self.driver.ring,
                &mut self.driver.send_copy_pool,
                conn_index,
            );
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_mode = RecvMode::Multi;
            }
            let _ = self.driver.ring.submit_multishot_recv(conn_index);
            return;
        }

        // Plaintext path
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.recv_mode = RecvMode::Multi;
            cs.established = true;
        }
        let _ = self.driver.ring.submit_multishot_recv(conn_index);

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

        if !matches!(conn.recv_mode, RecvMode::Connecting) {
            return;
        }

        let connect_ud = UserData::encode(OpTag::Connect, conn_index, 0);
        let _ = self
            .driver
            .ring
            .submit_async_cancel(connect_ud.raw(), conn_index);

        #[cfg(feature = "tls")]
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

        let was_established = self
            .driver
            .connections
            .get(conn_index)
            .map(|c| c.established)
            .unwrap_or(false);

        #[cfg(feature = "tls")]
        if let Some(ref mut tls_table) = self.driver.tls_table {
            tls_table.remove(conn_index);
        }

        if was_established {
            metrics::CONNECTIONS_CLOSED.increment();
            metrics::CONNECTIONS_ACTIVE.decrement();
        }

        // Remove the async task (drops the future).
        self.executor.remove_connection(conn_index);
        self.driver.connections.release(conn_index);
    }

    #[cfg(feature = "tls")]
    fn handle_tls_send(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let pool_slot = ud.payload() as u16;

        if result > 0
            && let Some((ptr, remaining)) = self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
        {
            let _ = self
                .driver
                .ring
                .submit_tls_send(conn_index, ptr, remaining, pool_slot);
            return;
        }
        self.driver.send_copy_pool.release(pool_slot);
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

    fn handle_recv_msg_udp(&mut self, ud: UserData, result: i32) {
        let udp_index = ud.conn_index();
        let idx = udp_index as usize;

        if idx >= self.driver.udp_sockets.len() {
            return;
        }

        if result <= 0 {
            self.driver.resubmit_udp_recvmsg(udp_index);
            return;
        }

        let bytes = result as usize;
        let peer = sockaddr_to_socket_addr(
            &self.driver.udp_sockets[idx].recv_addr,
            self.driver.udp_sockets[idx].recv_msghdr.msg_namelen,
        );

        // Copy datagram to avoid borrow conflict.
        let data = self.driver.udp_sockets[idx].recv_buf[..bytes].to_vec();

        // Resubmit recvmsg before waking task.
        self.driver.resubmit_udp_recvmsg(udp_index);

        if let Some(peer) = peer {
            metrics::UDP_DATAGRAMS_RECEIVED.increment();
            // Push to the async recv queue and wake waiting task.
            if idx < self.executor.udp_recv_queues.len() {
                self.executor.udp_recv_queues[idx].push_back((data, peer));
                self.executor.wake_udp_recv(udp_index);
            }
        }
    }

    fn handle_send_msg_udp(&mut self, ud: UserData, result: i32) {
        let udp_index = ud.conn_index();
        let pool_slot = ud.payload() as u16;
        let idx = udp_index as usize;

        self.driver.send_copy_pool.release(pool_slot);

        if idx < self.driver.udp_sockets.len() {
            self.driver.udp_sockets[idx].send_in_flight = false;
        }

        let _ = result;
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

        // Wake the async task waiting for this NVMe completion.
        self.executor.wake_disk_io(slab_idx as u32, result);
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
        self.executor.wake_disk_io(slab_idx as u32, result);
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
}
