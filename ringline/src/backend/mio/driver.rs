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
use crate::disk_io_pool::DiskIoPool;
use crate::handler::{ConnSendState, DriverCtx};

use mio::Interest;

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
    /// Per-connection connect timeout deadline (None if no timeout or not connecting).
    pub(crate) connect_deadlines: Vec<Option<std::time::Instant>>,
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
    /// Bound UDP sockets (one per `config.udp_bind` address).
    pub(crate) udp_sockets: Vec<mio::net::UdpSocket>,
    /// First mio token used for UDP sockets. UDP socket `i` has token
    /// `udp_token_base + i`. Tokens below this are WAKE_TOKEN (0) and
    /// TCP connections (1..=max_connections).
    pub(crate) udp_token_base: usize,

    // ── Disk I/O pool state ─────────���───────────────────────────────
    /// Disk I/O response channel (worker-local receive end).
    pub(crate) disk_io_rx: Option<crossbeam_channel::Receiver<crate::disk_io_pool::DiskIoResponse>>,
    /// Disk I/O response channel (worker-local send end, passed into requests).
    pub(crate) disk_io_tx: Option<crossbeam_channel::Sender<crate::disk_io_pool::DiskIoResponse>>,
    /// Shared disk I/O pool.
    pub(crate) disk_io_pool: Option<Arc<DiskIoPool>>,
    /// Monotonic sequence counter for disk I/O requests.
    pub(crate) next_disk_io_seq: u32,

    // ── Direct I/O file management ──────────��───────────────────────
    /// Direct I/O file table (allocates file slots, tracks raw fds).
    pub(crate) direct_io_files: Option<crate::direct_io::DirectIoFileTable>,
    /// Raw fds for direct I/O files, indexed by file slot.
    pub(crate) direct_io_fds: Vec<Option<RawFd>>,

    // ── Filesystem file management ──────────────────────────────────
    /// Filesystem file table (allocates file slots, tracks raw fds).
    pub(crate) fs_files: Option<crate::fs::FsFileTable>,
    /// Raw fds for filesystem files, indexed by file slot.
    pub(crate) fs_fds: Vec<Option<RawFd>>,
    /// Pending fs_open requests: maps seq → file_index. On completion, the
    /// result (fd) is stored in `fs_fds[file_index]`. On failure, the file
    /// slot is released.
    pub(crate) pending_fs_opens: std::collections::HashMap<u32, u16>,
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
        disk_io_rx: Option<crossbeam_channel::Receiver<crate::disk_io_pool::DiskIoResponse>>,
        disk_io_tx: Option<crossbeam_channel::Sender<crate::disk_io_pool::DiskIoResponse>>,
        disk_io_pool: Option<Arc<DiskIoPool>>,
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

        // UDP token range starts after WAKE_TOKEN (0) and TCP connections
        // (1..=max_connections).
        let udp_token_base = max_conn + 2;

        // Bind UDP sockets and register with mio poll.
        let mut udp_sockets = Vec::with_capacity(config.udp_bind.len());
        for (i, addr) in config.udp_bind.iter().enumerate() {
            let std_socket = std::net::UdpSocket::bind(addr)
                .map_err(|e| io::Error::new(e.kind(), format!("UDP bind {addr}: {e}")))?;
            std_socket.set_nonblocking(true)?;
            let mut mio_socket = mio::net::UdpSocket::from_std(std_socket);
            poll.registry().register(
                &mut mio_socket,
                mio::Token(udp_token_base + i),
                Interest::READABLE,
            )?;
            udp_sockets.push(mio_socket);
        }

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
            connect_deadlines: vec![None; max_conn],
            tls_scratch: vec![0u8; 16384],
            wake_pipe_fd: eventfd,
            tcp_nodelay: config.tcp_nodelay,
            send_completions: (0..max_conn).map(|_| VecDeque::new()).collect(),
            udp_sockets,
            udp_token_base,
            disk_io_rx,
            disk_io_tx,
            disk_io_pool,
            next_disk_io_seq: 0,
            direct_io_files: config
                .direct_io
                .as_ref()
                .map(|dio| crate::direct_io::DirectIoFileTable::new(dio.max_files)),
            direct_io_fds: config
                .direct_io
                .as_ref()
                .map(|dio| vec![None; dio.max_files as usize])
                .unwrap_or_default(),
            fs_files: config
                .fs
                .as_ref()
                .map(|fs| crate::fs::FsFileTable::new(fs.max_files)),
            fs_fds: config
                .fs
                .as_ref()
                .map(|fs| vec![None; fs.max_files as usize])
                .unwrap_or_default(),
            pending_fs_opens: std::collections::HashMap::new(),
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
            connect_deadlines: &mut self.connect_deadlines,
            disk_io_pool: &self.disk_io_pool,
            disk_io_tx: &self.disk_io_tx,
            wake_handle: self.wake_handle,
            next_disk_io_seq: &mut self.next_disk_io_seq,
            direct_io_files: &mut self.direct_io_files,
            direct_io_fds: &mut self.direct_io_fds,
            fs_files: &mut self.fs_files,
            fs_fds: &mut self.fs_fds,
            pending_fs_opens: &mut self.pending_fs_opens,
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
        self.connect_deadlines[idx] = None;
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
