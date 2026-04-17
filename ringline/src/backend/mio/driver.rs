//! Mio backend driver — owns per-worker I/O state.

use std::collections::VecDeque;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::accumulator::AccumulatorTable;
use crate::buffer::send_copy::SendCopyPool;
use crate::config::Config;
use crate::connection::{ConnectionTable, RecvMode};
use crate::handler::{ConnSendState, DriverCtx};

/// mio token 0 is reserved for the wake pipe.
pub(crate) const WAKE_TOKEN: mio::Token = mio::Token(0);

/// Per-connection pending send: `(data, offset)` for partial writes.
pub(crate) type PendingSend = (Vec<u8>, usize);

/// Per-worker mio driver state.
pub(crate) struct Driver {
    pub(crate) connections: ConnectionTable,
    pub(crate) accumulators: AccumulatorTable,
    pub(crate) send_copy_pool: SendCopyPool,
    pub(crate) send_queues: Vec<ConnSendState>,
    pub(crate) accept_rx: Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
    pub(crate) wake_handle: crate::wakeup::WakeHandle,
    pub(crate) shutdown_flag: Arc<AtomicBool>,
    pub(crate) shutdown_local: bool,
    pub(crate) tls_table: Option<crate::tls::TlsTable>,
    pub(crate) connect_addrs: Vec<libc::sockaddr_storage>,
    /// Per-connection mio tokens -> connection index mapping.
    pub(crate) poll: mio::Poll,
    pub(crate) events: mio::Events,
    /// Resolver response channels.
    pub(crate) resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
    pub(crate) resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
    pub(crate) resolver: Option<Arc<crate::resolver::ResolverPool>>,
    /// Spawner response channels.
    pub(crate) spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
    pub(crate) spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
    pub(crate) spawner: Option<Arc<crate::spawner::SpawnerPool>>,
    /// Blocking pool channels.
    pub(crate) blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
    pub(crate) blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
    pub(crate) blocking_pool: Option<Arc<crate::blocking::BlockingPool>>,

    // ── mio-specific state ───────────────────────────────────────────
    /// Per-connection mio TcpStream storage.
    pub(crate) tcp_streams: Vec<Option<mio::net::TcpStream>>,
    /// Per-connection pending send buffers: `VecDeque<(data, offset)>`.
    /// Populated by DriverCtx::send(), drained by the event loop on writable.
    pub(crate) pending_sends: Vec<VecDeque<PendingSend>>,
    /// Per-connection writable flag (most recent readiness from mio).
    pub(crate) writable: Vec<bool>,
    /// Scratch buffer for TLS plaintext decryption (one per worker thread).
    pub(crate) tls_scratch: Vec<u8>,
    /// Raw fd of the wake pipe read end — registered with mio as WAKE_TOKEN.
    pub(crate) wake_pipe_fd: RawFd,
    /// Whether to set TCP_NODELAY on accepted connections.
    pub(crate) tcp_nodelay: bool,
    /// Per-connection queue of awaitable-send byte counts.
    /// `DriverCtx::send_await()` pushes len here; the event loop drains
    /// these and calls `Executor::wake_send()` for each.
    pub(crate) send_completions: Vec<VecDeque<u32>>,
}

impl Driver {
    /// Create a new mio-backed driver.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &Config,
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
        let max_conn = config.max_connections as usize;
        let poll = mio::Poll::new()?;
        let events = mio::Events::with_capacity(1024);

        let tls_table = {
            let server_config = config.tls.as_ref().map(|t| t.server_config.clone());
            let client_config = config.tls_client.as_ref().map(|t| t.client_config.clone());
            if server_config.is_some() || client_config.is_some() {
                Some(crate::tls::TlsTable::new(
                    config.max_connections,
                    server_config,
                    client_config,
                ))
            } else {
                None
            }
        };

        Ok(Driver {
            connections: ConnectionTable::new(config.max_connections),
            accumulators: AccumulatorTable::new(
                config.max_connections,
                config.recv_buffer.buffer_size as usize,
            ),
            send_copy_pool: SendCopyPool::new(config.send_copy_count, config.send_copy_slot_size),
            send_queues: (0..max_conn).map(|_| ConnSendState::new()).collect(),
            accept_rx,
            wake_handle: crate::wakeup::WakeHandle::from_raw_fd(eventfd),
            shutdown_flag,
            shutdown_local: false,
            tls_table,
            connect_addrs: vec![unsafe { std::mem::zeroed() }; max_conn],
            poll,
            events,
            resolve_rx,
            resolve_tx,
            resolver,
            spawn_rx,
            spawn_tx,
            spawner,
            blocking_rx,
            blocking_tx,
            blocking_pool,
            tcp_streams: (0..max_conn).map(|_| None).collect(),
            pending_sends: (0..max_conn).map(|_| VecDeque::new()).collect(),
            writable: vec![false; max_conn],
            tls_scratch: vec![0u8; 16384],
            wake_pipe_fd: eventfd,
            tcp_nodelay: config.tcp_nodelay,
            send_completions: (0..max_conn).map(|_| VecDeque::new()).collect(),
        })
    }

    /// Create a `DriverCtx` borrow for issuing operations.
    pub(crate) fn make_ctx(&mut self) -> DriverCtx<'_> {
        let tls_ptr = self
            .tls_table
            .as_mut()
            .map(|t| t as *mut _)
            .unwrap_or(std::ptr::null_mut());

        DriverCtx {
            connections: &mut self.connections,
            send_copy_pool: &mut self.send_copy_pool,
            tls_table: tls_ptr,
            shutdown_requested: &mut self.shutdown_local,
            connect_addrs: &mut self.connect_addrs,
            tcp_nodelay: self.tcp_nodelay,
            #[cfg(feature = "timestamps")]
            timestamps: false,
            #[cfg(feature = "timestamps")]
            recvmsg_msghdr: std::ptr::null(),
            send_queues: &mut self.send_queues,
            pending_sends: &mut self.pending_sends,
            tcp_streams: &mut self.tcp_streams,
            poll: &mut self.poll,
            writable: &mut self.writable,
            send_completions: &mut self.send_completions,
        }
    }

    /// Close and clean up a connection.
    pub(crate) fn close_connection(&mut self, conn_index: u32) {
        let idx = conn_index as usize;

        // Check that the connection is active and not already closing.
        if let Some(conn) = self.connections.get_mut(conn_index) {
            if matches!(conn.recv_mode, RecvMode::Closed) {
                return; // already closing
            }
            conn.recv_mode = RecvMode::Closed;
        } else {
            return;
        }

        // Flush any pending send data before closing. Temporarily switch to
        // blocking mode so write_all doesn't fail with WouldBlock.
        if let Some(ref mut stream) = self.tcp_streams[idx] {
            use std::io::Write;
            use std::os::fd::AsRawFd;
            let fd = stream.as_raw_fd();
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            }
            for (data, offset) in self.pending_sends[idx].drain(..) {
                let _ = stream.write_all(&data[offset..]);
            }
            let _ = stream.flush();

            // Send TLS close_notify if this is a TLS connection.
            if let Some(ref mut tls_table) = self.tls_table
                && tls_table.has(conn_index)
            {
                if let Some(tls_conn) = tls_table.get_mut(conn_index) {
                    tls_conn.conn.send_close_notify();
                }
                crate::tls::flush_tls_output_mio(tls_table, stream, conn_index);
                tls_table.remove(conn_index);
            }
        }

        // Deregister from poll and drop the TcpStream.
        if let Some(mut stream) = self.tcp_streams[idx].take() {
            let _ = self.poll.registry().deregister(&mut stream);
            // stream is dropped here, closing the fd
        }

        // Clear pending sends (already drained above, but reset state).
        self.pending_sends[idx].clear();
        self.writable[idx] = false;
        self.send_completions[idx].clear();

        // Clear send queue.
        self.send_queues[idx].queue.clear();
        self.send_queues[idx].in_flight = false;

        // Release the connection slot.
        if self.connections.get(conn_index).is_some() {
            self.connections.release(conn_index);
        }

        crate::metrics::CONNECTIONS_CLOSED.increment();
        crate::metrics::CONNECTIONS_ACTIVE.decrement();
    }

    /// Flush pending sends for a connection. Called by the event loop when
    /// the connection becomes writable.
    ///
    /// Returns `(all_flushed, bytes_written)`: `all_flushed` is true if all
    /// pending data was flushed (or there was nothing to flush), false if we
    /// got WouldBlock mid-flush. `bytes_written` is the total bytes written
    /// in this call.
    pub(crate) fn flush_sends(&mut self, conn_index: u32) -> (bool, u32) {
        let idx = conn_index as usize;
        let stream = match self.tcp_streams[idx].as_mut() {
            Some(s) => s,
            None => return (true, 0),
        };

        let mut total_written: u32 = 0;
        while let Some((data, offset)) = self.pending_sends[idx].front_mut() {
            match stream.write(&data[*offset..]) {
                Ok(0) => {
                    // Connection closed by peer during write.
                    return (true, total_written);
                }
                Ok(n) => {
                    total_written += n as u32;
                    *offset += n;
                    if *offset >= data.len() {
                        // This send is complete.
                        self.pending_sends[idx].pop_front();
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.writable[idx] = false;
                    return (false, total_written);
                }
                Err(_) => {
                    // Write error — connection will be closed.
                    return (true, total_written);
                }
            }
        }

        // All sends flushed. Switch back to read-only interest.
        if let Some(stream) = self.tcp_streams[idx].as_mut() {
            let _ = self.poll.registry().reregister(
                stream,
                mio::Token(idx + 1),
                mio::Interest::READABLE,
            );
        }
        (true, total_written)
    }

    /// Register writable interest for a connection (because we have
    /// pending send data).
    pub(crate) fn register_writable(&mut self, conn_index: u32) {
        let idx = conn_index as usize;
        if let Some(stream) = self.tcp_streams[idx].as_mut() {
            let _ = self.poll.registry().reregister(
                stream,
                mio::Token(idx + 1),
                mio::Interest::READABLE | mio::Interest::WRITABLE,
            );
        }
    }
}
