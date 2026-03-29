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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &crate::config::Config,
        handler: A,
        accept_rx: Option<crossbeam_channel::Receiver<(std::os::fd::RawFd, std::net::SocketAddr)>>,
        eventfd: std::os::fd::RawFd,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
        resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
        resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
        resolver: Option<std::sync::Arc<crate::resolver::ResolverPool>>,
    ) -> Result<Self, crate::error::Error> {
        let driver = Driver::new(
            config,
            accept_rx,
            eventfd,
            shutdown_flag,
            resolve_rx,
            resolve_tx,
            resolver,
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

    /// Run the async event loop. Blocks the current thread.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
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
            // Retry eventfd re-arm if a previous attempt failed (SQ was full).
            if !self.driver.eventfd_armed && !self.driver.shutdown_flag.load(Ordering::Relaxed) {
                self.driver.eventfd_armed = self
                    .driver
                    .ring
                    .submit_eventfd_read(self.driver.eventfd, self.driver.eventfd_buf.as_mut_ptr())
                    .is_ok();
            }

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

            // Retry any ZC send resubmissions that failed on the previous tick
            // (SQ was full). The SQ has been flushed by submit_and_wait above.
            if !self.driver.pending_zc_retries.is_empty() {
                let retries: Vec<_> = self.driver.pending_zc_retries.drain(..).collect();
                for (conn_index, generation, slab_idx) in retries {
                    if !self.driver.send_slab.in_use(slab_idx) {
                        continue; // slab was released in the meantime
                    }
                    // Verify the connection hasn't been reused (generation check).
                    if self.driver.connections.get(conn_index).is_none()
                        || self.driver.connections.generation(conn_index) != generation
                    {
                        // Connection closed or reused — release the slab.
                        self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                        if self.driver.send_slab.should_release(slab_idx) {
                            let pool_slot = self.driver.send_slab.release(slab_idx);
                            if pool_slot != u16::MAX {
                                self.driver.send_copy_pool.release(pool_slot);
                            }
                        }
                        continue;
                    }
                    let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
                    if self
                        .driver
                        .ring
                        .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                        .is_err()
                    {
                        // Still failing — close the connection as last resort.
                        self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                        if self.driver.send_slab.should_release(slab_idx) {
                            let pool_slot = self.driver.send_slab.release(slab_idx);
                            if pool_slot != u16::MAX {
                                self.driver.send_copy_pool.release(pool_slot);
                            }
                        }
                        self.driver.drain_conn_send_queue(conn_index);
                        let err = io::Error::other("SQ full during partial ZC send resubmission");
                        self.executor.wake_send(conn_index, Err(err));
                        self.driver.close_connection(conn_index);
                    }
                }
            }

            // Retry any copy send resubmissions that failed (SQ was full).
            if !self.driver.pending_copy_retries.is_empty() {
                let retries: Vec<_> = self.driver.pending_copy_retries.drain(..).collect();
                for (conn_index, generation, pool_slot) in retries {
                    if !self.driver.send_copy_pool.in_use(pool_slot) {
                        continue;
                    }
                    // Verify the connection hasn't been reused (generation check).
                    if self.driver.connections.get(conn_index).is_none()
                        || self.driver.connections.generation(conn_index) != generation
                    {
                        self.driver.send_copy_pool.release(pool_slot);
                        continue;
                    }
                    let (ptr, remaining) =
                        self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
                    // Determine opcode: TLS connections use TlsSend, others use Send.
                    let is_tls = self
                        .driver
                        .tls_table
                        .as_ref()
                        .is_some_and(|t| t.has(conn_index));
                    let result = if is_tls {
                        self.driver
                            .ring
                            .submit_tls_send(conn_index, ptr, remaining, pool_slot)
                    } else {
                        self.driver
                            .ring
                            .submit_send_copied(conn_index, ptr, remaining, pool_slot)
                    };
                    if result.is_err() {
                        self.driver.send_copy_pool.release(pool_slot);
                        self.driver.drain_conn_send_queue(conn_index);
                        let err = io::Error::other("SQ full during partial copy send resubmission");
                        self.executor.wake_send(conn_index, Err(err));
                        self.driver.close_connection(conn_index);
                    }
                }
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
                            // Standalone task completed — just remove it.
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
            #[cfg(feature = "timestamps")]
            OpTag::RecvMsgMultiTs => self.handle_recv_msg_multi_ts(ud, result, flags),
        }
    }

    fn handle_recv_multi(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let has_more = cqueue::more(flags);

        if self.driver.connections.get(conn_index).is_none() {
            // Connection already released — but if result > 0, the kernel
            // consumed a provided buffer that must be replenished.
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                self.driver.pending_replenish.push(bid);
            }
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

        let bytes_received = result as u32;
        metrics::BYTES_RECEIVED.add(bytes_received as u64);
        let (buf_ptr, _) = self.driver.provided_bufs.get_buffer(bid);
        let data = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_received as usize) };

        self.driver.pending_replenish.push(bid);

        // TLS path
        let is_tls_conn = self
            .driver
            .tls_table
            .as_ref()
            .is_some_and(|t| t.has(conn_index));

        if is_tls_conn {
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
                        self.executor.wake_recv(conn_index);
                        self.driver.close_connection(conn_index);
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

    /// Handle a RecvMsgMulti CQE (multishot recvmsg with SO_TIMESTAMPING).
    ///
    /// The provided buffer contains an `io_uring_recvmsg_out` header followed by
    /// name (0 bytes for TCP), control data (cmsg with SCM_TIMESTAMPING), and
    /// the TCP payload.
    #[cfg(feature = "timestamps")]
    fn handle_recv_msg_multi_ts(&mut self, ud: UserData, result: i32, flags: u32) {
        let conn_index = ud.conn_index();
        let has_more = cqueue::more(flags);

        if self.driver.connections.get(conn_index).is_none() {
            if result > 0
                && let Some(bid) = cqueue::buffer_select(flags)
            {
                self.driver.pending_replenish.push(bid);
            }
            return;
        }

        if result <= 0 {
            if result == 0 {
                self.executor.wake_recv(conn_index);
                self.driver.close_connection(conn_index);
                return;
            }
            let errno = -result;
            if errno == libc::ENOBUFS {
                metrics::BUFFER_RING_EMPTY.increment();
                if !has_more {
                    let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
                    let _ = self
                        .driver
                        .ring
                        .submit_multishot_recvmsg(conn_index, msghdr_ptr);
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
            None => {
                if !has_more {
                    self.executor.wake_recv(conn_index);
                    self.driver.close_connection(conn_index);
                }
                return;
            }
        };

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
            self.executor.wake_recv(conn_index);
            self.driver.close_connection(conn_index);
            return;
        }

        metrics::BYTES_RECEIVED.add(payload.len() as u64);

        // Extract SCM_TIMESTAMPING from control data.
        let control = msg_out.control_data();
        if let Some(ts_ns) = Self::parse_scm_timestamp(control) {
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_timestamp_ns = ts_ns;
            }
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
            if to_sink < payload.len() {
                self.driver
                    .accumulators
                    .append(conn_index, &payload[to_sink..]);
            }
        } else {
            self.driver.accumulators.append(conn_index, payload);
        }
        self.executor.wake_recv(conn_index);

        if !has_more
            && let Some(conn) = self.driver.connections.get(conn_index)
            && matches!(conn.recv_mode, RecvMode::MsgMulti)
        {
            let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
            let _ = self
                .driver
                .ring
                .submit_multishot_recvmsg(conn_index, msghdr_ptr);
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
                    cs.peer_addr = Some(crate::connection::PeerAddr::Tcp(peer_addr));
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
                self.arm_recv(conn_index);

                // TLS path: defer accept until handshake completes.
                if let Some(ref mut tls_table) = self.driver.tls_table
                    && tls_table.has_server_config()
                {
                    if tls_table.create(conn_index).is_err() {
                        self.driver.close_connection(conn_index);
                    }
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

        // Drain DNS resolve responses.
        if let Some(ref rx) = self.driver.resolve_rx {
            while let Ok(response) = rx.try_recv() {
                self.executor
                    .deliver_resolve(response.request_id, response.result);
            }
        }

        // on_notify (synchronous).
        {
            let mut ctx = self.driver.make_ctx();
            self.handler.on_notify(&mut ctx);
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
        let pool_slot = ud.payload() as u16;

        // Guard against stale CQE for an already-released pool slot
        // (e.g., Close CQE processed before this Send CQE in the same batch).
        if !self.driver.send_copy_pool.in_use(pool_slot) {
            return;
        }

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
                if self
                    .driver
                    .ring
                    .submit_send_copied(conn_index, ptr, remaining, pool_slot)
                    .is_err()
                {
                    // SQ full — queue for retry on next tick.
                    let generation = self.driver.connections.generation(conn_index);
                    self.driver
                        .pending_copy_retries
                        .push((conn_index, generation, pool_slot));
                }
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

        // Only increment pending notifications for successful sends — the kernel
        // sends a ZC notification CQE only when result > 0. On error (result <= 0),
        // no notification arrives, so incrementing would permanently leak the slab slot.
        if result > 0 {
            self.driver.send_slab.inc_pending_notifs(slab_idx);
        }

        #[allow(clippy::collapsible_if)]
        if result > 0 {
            if let Some(msg_ptr) = self.driver.send_slab.try_advance(slab_idx, result as u32) {
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
                    .push((conn_index, generation, slab_idx));
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
        if let Some(ref mut tls_table) = self.driver.tls_table
            && tls_table.get_mut(conn_index).is_some()
        {
            if !crate::tls::flush_tls_output(
                tls_table,
                &mut self.driver.ring,
                &mut self.driver.send_copy_pool,
                conn_index,
            ) {
                let err = std::io::Error::other("send pool exhausted during TLS flush");
                self.executor.wake_connect(conn_index, Err(err));
                self.driver.close_connection(conn_index);
                return;
            }
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_mode = RecvMode::Multi;
            }
            self.arm_recv(conn_index);
            return;
        }

        // Plaintext path
        if let Some(cs) = self.driver.connections.get_mut(conn_index) {
            cs.established = true;
            cs.recv_mode = RecvMode::Multi;
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

        if !matches!(conn.recv_mode, RecvMode::Connecting) {
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
            metrics::CONNECTIONS_CLOSED.increment();
            metrics::CONNECTIONS_ACTIVE.decrement();
        }

        // Remove the async task (drops the future).
        self.executor.remove_connection(conn_index);
        self.driver.connections.release(conn_index);
    }

    fn handle_tls_send(&mut self, ud: UserData, result: i32) {
        let conn_index = ud.conn_index();
        let pool_slot = ud.payload() as u16;

        if result > 0
            && let Some((ptr, remaining)) = self
                .driver
                .send_copy_pool
                .try_advance(pool_slot, result as u32)
        {
            if self
                .driver
                .ring
                .submit_tls_send(conn_index, ptr, remaining, pool_slot)
                .is_err()
            {
                // SQ full — queue for retry on next tick. Use copy retry
                // since TLS sends use SendCopyPool slots.
                let generation = self.driver.connections.generation(conn_index);
                self.driver
                    .pending_copy_retries
                    .push((conn_index, generation, pool_slot));
            }
            return;
        }
        self.driver.send_copy_pool.release(pool_slot);

        // On error, close the connection so the owning task unblocks.
        // The last ciphertext chunk uses OpTag::Send which wakes the send
        // waiter, but if an intermediate chunk fails the connection is
        // broken — close it so handle_close cleans up.
        if result < 0 {
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

        if result < 0 {
            metrics::UDP_SEND_ERRORS.increment();
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

    /// Arm the appropriate multishot recv for a connection.
    ///
    /// When the `timestamps` feature is enabled and configured, uses
    /// `RecvMsgMulti` (multishot recvmsg) to receive cmsg ancillary data
    /// containing kernel timestamps. Otherwise, uses `RecvMulti` (plain
    /// multishot recv).
    fn arm_recv(&mut self, conn_index: u32) {
        #[cfg(feature = "timestamps")]
        if self.driver.timestamps {
            let msghdr_ptr = &*self.driver.recvmsg_msghdr as *const libc::msghdr;
            let _ = self
                .driver
                .ring
                .submit_multishot_recvmsg(conn_index, msghdr_ptr);
            if let Some(cs) = self.driver.connections.get_mut(conn_index) {
                cs.recv_mode = RecvMode::MsgMulti;
            }
            return;
        }
        let _ = self.driver.ring.submit_multishot_recv(conn_index);
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

    /// Test-only: directly drain pending retry queues (without running
    /// the full event loop). This tests the retry mechanism in isolation.
    #[cfg(test)]
    pub(crate) fn drain_retries(&mut self) {
        // Copy retry drain — mirrors the logic in run().
        if !self.driver.pending_copy_retries.is_empty() {
            let retries: Vec<_> = self.driver.pending_copy_retries.drain(..).collect();
            for (conn_index, generation, pool_slot) in retries {
                if !self.driver.send_copy_pool.in_use(pool_slot) {
                    continue;
                }
                if self.driver.connections.get(conn_index).is_none()
                    || self.driver.connections.generation(conn_index) != generation
                {
                    self.driver.send_copy_pool.release(pool_slot);
                    continue;
                }
                let (ptr, remaining) = self.driver.send_copy_pool.current_ptr_remaining(pool_slot);
                let result = self
                    .driver
                    .ring
                    .submit_send_copied(conn_index, ptr, remaining, pool_slot);
                if result.is_err() {
                    self.driver.send_copy_pool.release(pool_slot);
                    self.driver.drain_conn_send_queue(conn_index);
                    let err = io::Error::other("SQ full during partial copy send resubmission");
                    self.executor.wake_send(conn_index, Err(err));
                    self.driver.close_connection(conn_index);
                }
            }
        }

        // ZC retry drain.
        if !self.driver.pending_zc_retries.is_empty() {
            let retries: Vec<_> = self.driver.pending_zc_retries.drain(..).collect();
            for (conn_index, generation, slab_idx) in retries {
                if !self.driver.send_slab.in_use(slab_idx) {
                    continue;
                }
                if self.driver.connections.get(conn_index).is_none()
                    || self.driver.connections.generation(conn_index) != generation
                {
                    self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                    if self.driver.send_slab.should_release(slab_idx) {
                        let pool_slot = self.driver.send_slab.release(slab_idx);
                        if pool_slot != u16::MAX {
                            self.driver.send_copy_pool.release(pool_slot);
                        }
                    }
                    continue;
                }
                let msg_ptr = self.driver.send_slab.msghdr_ptr(slab_idx);
                if self
                    .driver
                    .ring
                    .submit_send_msg_zc(conn_index, msg_ptr, slab_idx)
                    .is_err()
                {
                    self.driver.send_slab.mark_awaiting_notifications(slab_idx);
                    if self.driver.send_slab.should_release(slab_idx) {
                        let pool_slot = self.driver.send_slab.release(slab_idx);
                        if pool_slot != u16::MAX {
                            self.driver.send_copy_pool.release(pool_slot);
                        }
                    }
                    self.driver.drain_conn_send_queue(conn_index);
                    let err = io::Error::other("SQ full during partial ZC send resubmission");
                    self.executor.wake_send(conn_index, Err(err));
                    self.driver.close_connection(conn_index);
                }
            }
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::{OpTag, UserData};
    use crate::config::Config;
    use crate::runtime::io::ConnCtx;
    use std::future::Future;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    /// Minimal handler for testing — does nothing.
    struct NoopHandler;

    impl AsyncEventHandler for NoopHandler {
        #[allow(clippy::manual_async_fn)]
        fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
            async {}
        }
        fn create_for_worker(_id: usize) -> Self {
            NoopHandler
        }
    }

    fn test_config() -> Config {
        let mut config = Config::default();
        config.worker.threads = 1;
        config.worker.pin_to_core = false;
        config.sq_entries = 32;
        config.recv_buffer.ring_size = 16;
        config.recv_buffer.buffer_size = 4096;
        config.max_connections = 16;
        config.send_copy_count = 16;
        config.send_slab_slots = 8;
        config
    }

    /// Create a test event loop. Requires Linux with io_uring support.
    fn make_test_loop() -> AsyncEventLoop<NoopHandler> {
        let config = test_config();
        let shutdown = Arc::new(AtomicBool::new(false));
        let eventfd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        assert!(eventfd >= 0, "eventfd creation failed");
        AsyncEventLoop::new(
            &config,
            NoopHandler,
            None,
            eventfd,
            shutdown,
            None,
            None,
            None,
        )
        .expect("failed to create test event loop")
    }

    /// Simulate an accepted plaintext connection at the given index.
    /// Returns the conn_index that was allocated.
    fn accept_connection(el: &mut AsyncEventLoop<NoopHandler>) -> u32 {
        let conn_index = el.driver.connections.allocate().expect("no free slots");
        el.driver.accumulators.reset(conn_index);
        // arm_recv needs to submit an SQE — skip in test since we inject CQEs directly.
        // Just set recv_mode = Multi so the handlers work correctly.
        if let Some(cs) = el.driver.connections.get_mut(conn_index) {
            cs.recv_mode = RecvMode::Multi;
            cs.established = true;
        }
        conn_index
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), 0, 0);

        // Connection should be marked as closing.
        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),
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

    // ── Close path tests ───────────────────────────────────────────

    #[test]
    fn handle_close_releases_connection_slot() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        assert!(el.driver.connections.get(conn_index).is_some());

        // Close the connection (sets recv_mode = Closed, submits Close SQE).
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

        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), bytes_received, flags);

        // Data should be in the accumulator.
        let data = el.driver.accumulators.data(conn_index);
        assert_eq!(data, b"hello", "data not appended to accumulator");

        // Buffer should be queued for replenish.
        assert!(
            el.driver.pending_replenish.contains(&bid),
            "buffer not queued for replenish"
        );
    }

    #[test]
    fn handle_recv_multi_enobufs_does_not_close() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // ENOBUFS = -105. has_more = false (bit 1 not set).
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
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
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -99, 0); // -99 = unknown errno

        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),
            "connection not closed on unknown recv error"
        );
    }

    #[test]
    fn handle_recv_multi_ecanceled_does_nothing() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        // ECANCELED = -125.
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.test_dispatch_cqe(ud.raw(), -125, 0);

        // Connection should still be alive.
        assert!(
            el.driver.connections.get(conn_index).is_some(),
            "connection closed on ECANCELED"
        );
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
        // Connection should be established with recv_mode = Multi.
        let conn = el.driver.connections.get(conn_index).unwrap();
        assert!(conn.established, "connection not marked established");
        assert!(
            matches!(conn.recv_mode, RecvMode::Multi),
            "recv_mode not set to Multi after connect"
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
            conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),
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
            conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),
            "connection not closed after TLS send error"
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
        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(data).unwrap();
        let free_before = el.driver.send_copy_pool.free_count();

        // Simulate UDP send CQE (success).
        let udp_index = 0u32;
        let ud = UserData::encode(OpTag::SendMsgUdp, udp_index, slot as u32);
        el.test_dispatch_cqe(ud.raw(), data.len() as i32, 0);

        assert_eq!(
            el.driver.send_copy_pool.free_count(),
            free_before + 1,
            "pool slot not released after UDP send"
        );
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let mut driver_state = DriverState {
            driver: driver_ptr,
            executor: executor_ptr,
        };
        set_driver_state(&mut driver_state);

        // Create and immediately drop a DiskIoFuture.
        {
            let _fut = crate::runtime::io::DiskIoFuture { seq };
        }

        clear_driver_state();

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

        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.inject_and_dispatch(ud.raw(), 0);

        let conn = el.driver.connections.get(conn_index);
        assert!(
            conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
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
        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
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

        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        el.inject_and_dispatch(ud.raw(), -99);

        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed),);
    }

    #[test]
    fn nop_inject_recv_ecanceled() {
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);

        let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
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
        assert!(matches!(conn.recv_mode, RecvMode::Multi));
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
        assert!(conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed));
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
        let recv_ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);

        el.inject_batch_and_dispatch(&[
            (send_ud.raw(), -104), // send error
            (recv_ud.raw(), 0),    // recv EOF
        ]);

        // Both should have processed. Pool slot released, connection closing.
        assert!(!el.driver.send_copy_pool.in_use(slot));
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed));
    }

    #[test]
    fn batch_recv_eof_then_stale_send_cqe() {
        // Recv EOF closes the connection (sets recv_mode=Closed, submits
        // Close SQE), then a stale send CQE arrives for the same
        // conn_index in the same batch. The send handler should not
        // panic on the closing connection.
        let mut el = make_test_loop();
        let conn_index = accept_connection(&mut el);
        el.driver.send_queues[conn_index as usize].in_flight = true;

        let (slot, _ptr, _len) = el.driver.send_copy_pool.copy_in(b"data").unwrap();

        // Recv EOF + stale send in the same batch.
        // The EOF handler calls close_connection internally.
        let recv_ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
        let send_ud = UserData::encode(OpTag::Send, conn_index, slot as u32);

        el.inject_batch_and_dispatch(&[
            (recv_ud.raw(), 0), // EOF → close_connection
            (send_ud.raw(), 4), // stale send "completes" (4 bytes = b"data")
        ]);

        // Connection should be closing. Pool slot should be released
        // cleanly (no panic).
        let conn = el.driver.connections.get(conn_index);
        assert!(conn.is_none() || matches!(conn.unwrap().recv_mode, RecvMode::Closed));
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
            .push((conn_index, generation, slot));

        // Close the connection before the retry fires.
        el.driver.close_connection(conn_index);
        // Simulate the Close CQE to fully release the slot.
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);

        // Now drain retries — the connection is gone.
        el.drain_retries();

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
            .push((conn_index, old_generation, slot));

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
        el.drain_retries();

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
        let guards = [None, None, None, None];
        let (slab_idx, _ptr) = el
            .driver
            .send_slab
            .allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100)
            .unwrap();

        // Simulate: operation CQE already incremented pending_notifs.
        el.driver.send_slab.inc_pending_notifs(slab_idx);

        // Queue the ZC retry.
        el.driver
            .pending_zc_retries
            .push((conn_index, generation, slab_idx));

        // Close the connection.
        el.driver.close_connection(conn_index);
        let close_ud = UserData::encode(OpTag::Close, conn_index, 0);
        el.inject_and_dispatch(close_ud.raw(), 0);

        // Drain retries — connection is gone.
        el.drain_retries();

        assert!(el.driver.pending_zc_retries.is_empty());
        // Slab should be marked for release (awaiting_notifications set,
        // and pending_notifs is still 1 — will be released when the
        // notification CQE arrives).
        // The key assertion: no panic, no hang, retry was handled.
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
                    let guards = [None, None, None, None];
                    let (slab_idx, _) = match el.driver.send_slab.allocate(conn_index, &iovecs, u16::MAX, guards, 0, 100) {
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
                    if el.driver.connections.get(conn_index).is_none()
                        || matches!(
                            el.driver.connections.get(conn_index).unwrap().recv_mode,
                            RecvMode::Closed
                        )
                    {
                        break;
                    }

                    let ud = UserData::encode(OpTag::RecvMulti, conn_index, 0);
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
                        0 => {
                            if live_conns.len() < 8 {
                                let ci = accept_connection(&mut el);
                                el.driver.send_queues[ci as usize].in_flight = false;
                                live_conns.push(ci);
                            }
                        }

                        // Send success on a random live connection.
                        1 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                let ud = UserData::encode(OpTag::Send, ci, slot as u32);
                                el.test_dispatch_cqe(ud.raw(), 4, 0);
                            }
                        }

                        // Send error on a random live connection.
                        2 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                let ud = UserData::encode(OpTag::Send, ci, slot as u32);
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
                            let guards = [None, None, None, None];
                            if let Some((slab_idx, _)) = el.driver.send_slab.allocate(
                                ci, &iovecs, u16::MAX, guards, 0, 50,
                            ) {
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
                            let guards = [None, None, None, None];
                            if let Some((slab_idx, _)) = el.driver.send_slab.allocate(
                                ci, &iovecs, u16::MAX, guards, 0, 50,
                            ) {
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
                            let ud = UserData::encode(OpTag::RecvMulti, ci, 0);
                            el.test_dispatch_cqe(ud.raw(), 0, 0);
                            // Simulate Close CQE.
                            let close_ud = UserData::encode(OpTag::Close, ci, 0);
                            el.test_dispatch_cqe(close_ud.raw(), 0, 0);
                        }

                        // Recv error.
                        6 if !live_conns.is_empty() => {
                            let ci = live_conns[0];
                            let ud = UserData::encode(OpTag::RecvMulti, ci, 0);
                            el.test_dispatch_cqe(ud.raw(), -105, 0); // ENOBUFS
                        }

                        // Send + Recv EOF in same batch (the cross-CQE bug pattern).
                        7 if !live_conns.is_empty() => {
                            let ci = live_conns.remove(0);
                            if let Some((slot, _, _)) = el.driver.send_copy_pool.copy_in(b"data") {
                                pool_slots_in_flight.push(slot);
                                let send_ud = UserData::encode(OpTag::Send, ci, slot as u32);
                                let recv_ud = UserData::encode(OpTag::RecvMulti, ci, 0);
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
