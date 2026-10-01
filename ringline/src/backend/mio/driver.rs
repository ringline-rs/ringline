//! Mio backend driver — owns per-worker I/O state.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::accumulator::AccumulatorTable;
use crate::buffer::send_copy::{SendCopyPool, SlotReservation};
use crate::config::Config;
use crate::connection::{ConnectionTable, Lifecycle, WriteHalf};
use crate::disk_io_pool::DiskIoPool;
use crate::handler::{ConnSendState, DriverCtx};
use crate::runtime::send_capacity::BoundedSendId;

use mio::Interest;

/// mio token 0 is reserved for the wake pipe.
pub(crate) const WAKE_TOKEN: mio::Token = mio::Token(0);

/// Per-connection pending send: the bytes plus how far into them the socket
/// has got, so a partial `writev` can resume where it stopped.
///
/// `notify_len` is `Some(len)` for awaitable sends: the completion
/// (wake_send) is delivered only when the entry has fully reached the
/// socket — completing at queue time reported success for bytes that were
/// never written and swallowed write errors entirely.
///
/// `bounded` marks a `send_backpressured` entry: its [`BoundedSendId`]
/// routes the exact result of *this* operation back to the future that
/// submitted it, and the [`SlotReservation`] is the copy-pool permit that
/// admitted it. The permit is held unfilled for the entry's whole life and
/// released when the entry completes or is discarded — never dropped
/// (`SlotReservation`'s `Drop` debug-asserts that).
pub(crate) struct PendingSend {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
    pub(crate) notify_len: Option<u32>,
    pub(crate) bounded: Option<(BoundedSendId, SlotReservation)>,
}

impl PendingSend {
    /// A fire-and-forget send: nothing is woken when it reaches the socket.
    pub(crate) fn plain(data: Vec<u8>) -> Self {
        Self {
            data,
            offset: 0,
            notify_len: None,
            bounded: None,
        }
    }

    /// A bounded (`send_backpressured`) send holding its admission permit.
    ///
    /// Built by `DriverCtx::send_bounded`; the permit is released (and `id`
    /// completed) by [`Driver::flush_sends`] or
    /// [`Driver::clear_pending_sends`], never by dropping the entry.
    pub(crate) fn bounded(data: Vec<u8>, id: BoundedSendId, permit: SlotReservation) -> Self {
        Self {
            data,
            offset: 0,
            notify_len: None,
            bounded: Some((id, permit)),
        }
    }
}

/// An in-flight `forward_to_conn` on the mio backend, indexed by source.
///
/// mio has no provided-buffer ring to hold, so unlike the io_uring Mode A
/// state this carries no backing — the bytes are copied into a queued send on
/// the sink as they are read, and all that survives between reads is where
/// they are going and how many are left.
pub(crate) struct MioForwardState {
    pub(crate) sink_index: u32,
    /// Sink generation at the start. Slots recycle; a forward that kept
    /// writing to a reused index would deliver this stream to another peer.
    pub(crate) sink_generation: u32,
    /// Bytes the caller asked to forward.
    pub(crate) len: u64,
    /// Bytes queued on the sink so far.
    pub(crate) forwarded: u64,
}

/// Clone an `io::Error` well enough to hand the same failure to several
/// waiters. `io::Error` is not `Clone`, and a bounded-send fan-out has to
/// give every discarded id an equivalent error: the OS errno is preserved
/// where there is one (so `raw_os_error()`/`kind()` match the original),
/// otherwise the kind and message are.
pub(crate) fn clone_io_error(e: &io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(code) => io::Error::from_raw_os_error(code),
        None => io::Error::new(e.kind(), e.to_string()),
    }
}

/// Discard every entry in one connection's send queue, releasing each
/// bounded entry's copy-pool permit and failing its id with `err()`.
///
/// The field-wise form of [`Driver::clear_pending_sends`], so callers that
/// hold a `DriverCtx` (or a live borrow of another `Driver` field) can use
/// it too. A `PendingSend` must never be dropped any other way: its
/// [`SlotReservation`] cannot release itself and debug-asserts on drop.
pub(crate) fn clear_pending_sends_into(
    queue: &mut VecDeque<PendingSend>,
    pool: &mut SendCopyPool,
    completions: &mut VecDeque<(BoundedSendId, io::Result<u32>)>,
    capacity_released: &mut bool,
    err: impl Fn() -> io::Error,
) {
    while let Some(entry) = queue.pop_front() {
        if let Some((id, permit)) = entry.bounded {
            pool.release_reservation(permit);
            *capacity_released = true;
            completions.push_back((id, Err(err())));
        }
    }
}

/// Per-worker mio driver state.
pub(crate) struct Driver {
    pub(crate) connections: ConnectionTable,
    pub(crate) accumulators: AccumulatorTable,
    pub(crate) send_copy_pool: SendCopyPool,
    pub(crate) send_queues: Vec<ConnSendState>,
    pub(crate) accept_rx: Option<crossbeam_channel::Receiver<crate::acceptor::AcceptedConn>>,
    pub(crate) wake_handle: crate::wakeup::WakeFd,
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
    /// Connection indices with non-empty `pending_sends`, so the per-loop
    /// flush pass touches only dirty connections instead of scanning all
    /// slots. Invariant: `pending_sends[i]` non-empty ⇒ `sends_dirty_flag[i]`
    /// set (and `i` present in `sends_dirty`).
    pub(crate) sends_dirty: Vec<u32>,
    pub(crate) sends_dirty_flag: Vec<bool>,
    /// Same shape for `send_completions`.
    pub(crate) completions_dirty: Vec<u32>,
    pub(crate) completions_dirty_flag: Vec<bool>,
    /// Number of connections with an armed connect deadline — lets the
    /// per-loop timeout sweep skip the scan entirely in the common case.
    pub(crate) connect_pending: u32,
    /// Per-connection writable flag (most recent readiness from mio).
    pub(crate) writable: Vec<bool>,
    /// Per-connection connect timeout deadline (None if no timeout or not connecting).
    pub(crate) connect_deadlines: Vec<Option<std::time::Instant>>,
    /// Raw fd of the wake pipe read end — registered with mio as WAKE_TOKEN.
    pub(crate) wake_pipe_fd: RawFd,
    /// Whether to set TCP_NODELAY on accepted connections.
    pub(crate) tcp_nodelay: bool,
    /// Connections whose teardown has been requested (`close_pending`),
    /// awaiting executor cleanup and slot release by the event loop's
    /// `drain_pending_closes`. An entry stays here until its
    /// `pending_sends` have drained (or its stream is gone), so a response
    /// queued after the peer's FIN is still delivered (io_uring's
    /// `try_finalize_close` defers the same way for sends already queued at
    /// the FIN; see #371 for the post-EOF send it does not yet cover). Deferring the release also
    /// (a) lets `Executor::remove_connection` run first (stale parked
    /// futures, waiter flags, and recv sinks used to survive into the
    /// slot's next occupant — a use-after-free via the recv-sink raw
    /// pointer), and (b) closes the reuse window between a task closing a
    /// connection and its own post-poll cleanup.
    pub(crate) pending_closes: Vec<u32>,
    /// Per-connection `forward_to_conn` state, indexed by the **source**.
    pub(crate) forward_conn: Vec<Option<MioForwardState>>,
    /// Terminal result of a forward, set once by the event loop and consumed
    /// by the future: `Ok(bytes forwarded)` or `Err(errno)`.
    pub(crate) forward_done: Vec<Option<Result<u64, i32>>>,
    /// Reverse index, sink → source, so a sink's teardown can fail the forward
    /// that feeds it instead of leaving its future parked forever.
    pub(crate) forward_feeder: Vec<Option<u32>>,
    /// Sources that stopped reading because their sink hit `forward_hold_cap`
    /// and must be re-read once it drains. Edge-triggered epoll will not
    /// re-notify a socket we chose not to drain, so the loop keeps the list.
    pub(crate) forward_resume: Vec<u32>,
    /// Membership flag for `forward_resume` (no duplicate entries).
    pub(crate) forward_resume_flag: Vec<bool>,
    /// Per connection index: is a [`RecvHalf`](crate::RecvHalf) currently out?
    ///
    /// The mio backend has no segmented recv domain, so unlike the io_uring
    /// driver there is no companion `segment_reader_live` — this is the whole
    /// recv claim here.
    pub(crate) recv_half_taken: Vec<bool>,
    /// Per connection index: is a [`SendHalf`](crate::SendHalf) currently out?
    /// The write-side twin of `recv_half_taken`; see the io_uring driver.
    pub(crate) send_half_taken: Vec<bool>,
    /// Queued sends allowed on a sink before its source stops reading. Shares
    /// `Config::forward_hold_cap` with the io_uring hold cap: same intent —
    /// bound one slow forward — applied to the queue mio actually has.
    pub(crate) forward_hold_cap: usize,
    /// Per-connection queue of awaitable-send byte counts.
    /// `DriverCtx::send_await()` pushes len here; the event loop drains
    /// these and calls `Executor::wake_send()` for each.
    pub(crate) send_completions: Vec<VecDeque<u32>>,
    /// Results of bounded (`send_backpressured`) sends, in completion order
    /// and keyed by the id the submitting future holds. Not per-connection:
    /// a [`BoundedSendId`] is unique on the worker, and the consumer
    /// (`Executor::complete_bounded_send`) looks entries up by id.
    ///
    /// Produced here by [`Driver::flush_sends`] (`Ok(len)` when the entry's
    /// last byte reaches the socket) and [`Driver::clear_pending_sends`]
    /// (`Err` when the entry is discarded); drained by the event loop's
    /// `drain_send_completions`. The driver never touches the `Executor`
    /// itself.
    pub(crate) bounded_send_completions: VecDeque<(BoundedSendId, io::Result<u32>)>,
    /// Set whenever a copy-pool permit goes back to the pool, so the event
    /// loop can call `Executor::wake_send_capacity` once per iteration
    /// instead of once per released permit. The event loop clears it.
    pub(crate) capacity_released: bool,
    /// Bound UDP sockets (one per `config.udp_bind` address).
    pub(crate) udp_sockets: Vec<mio::net::UdpSocket>,
    /// Whether UDP GRO was requested; when set, the readable handler uses
    /// `recvmsg` with a control buffer to read the `UDP_GRO` segment size.
    /// Only consulted on Linux (GRO is a Linux feature).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) udp_gro: bool,
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
            let listener_configs: Vec<_> = config
                .listener_tls
                .iter()
                .map(|slot| slot.as_ref().map(|t| t.server_config.clone()))
                .collect();
            // Any per-listener config counts — see the io_uring driver.
            if server_config.is_some()
                || client_config.is_some()
                || listener_configs.iter().any(|c| c.is_some())
            {
                Some(crate::tls::TlsTable::with_listener_configs(
                    config.max_connections,
                    server_config,
                    client_config,
                    listener_configs,
                ))
            } else {
                None
            }
        };

        // UDP token range starts after WAKE_TOKEN (0) and TCP connections
        // (1..=max_connections).
        let udp_token_base = max_conn + 2;

        // Bind UDP sockets and register with mio poll.
        //
        // We can't use `std::net::UdpSocket::bind` here because it binds
        // before we get a chance to set `SO_REUSEPORT`, which the io_uring
        // backend already enables and which is required for multi-worker
        // setups (each worker creates its own socket bound to the same
        // address).
        let mut udp_sockets = Vec::with_capacity(config.udp_bind.len());
        for (i, addr) in config.udp_bind.iter().enumerate() {
            let std_socket = bind_udp_with_reuseport(*addr, config.udp_gro)
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
            accumulators: AccumulatorTable::new_with_max(
                config.max_connections,
                config.recv_buffer.buffer_size as usize,
                config.recv_accumulator_max,
            ),
            send_copy_pool: {
                let mut pool =
                    SendCopyPool::new(config.send_copy_count, config.send_copy_slot_size);
                // Built on the pinned worker thread, so the pages stay local to
                // it. mio has no provided recv ring; the send pool is the only
                // pre-allocated buffer memory here.
                if config.prefault_buffers {
                    pool.prefault();
                }
                pool
            },
            send_queues: (0..max_conn).map(|_| ConnSendState::new()).collect(),
            accept_rx,
            // The pipe's WRITE end: handed to worker-pool threads (disk I/O,
            // resolver, spawner) so their completion wakes actually reach
            // this worker. `eventfd` is the READ end (polled by the loop) —
            // it used to be wrapped here, making every pool wake an EBADF
            // no-op observed only at the poll timeout (~10 ms).
            wake_handle: wake_fd,
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
            pending_closes: Vec::new(),
            pending_sends: (0..max_conn).map(|_| VecDeque::new()).collect(),
            sends_dirty: Vec::new(),
            sends_dirty_flag: vec![false; max_conn],
            completions_dirty: Vec::new(),
            completions_dirty_flag: vec![false; max_conn],
            connect_pending: 0,
            writable: vec![false; max_conn],
            connect_deadlines: vec![None; max_conn],
            wake_pipe_fd: eventfd,
            tcp_nodelay: config.tcp_nodelay,
            forward_conn: (0..max_conn).map(|_| None).collect(),
            forward_done: vec![None; max_conn],
            forward_feeder: vec![None; max_conn],
            forward_resume: Vec::new(),
            forward_resume_flag: vec![false; max_conn],
            recv_half_taken: vec![false; max_conn],
            send_half_taken: vec![false; max_conn],
            forward_hold_cap: config.forward_hold_cap,
            send_completions: (0..max_conn).map(|_| VecDeque::new()).collect(),
            bounded_send_completions: VecDeque::new(),
            capacity_released: false,
            udp_sockets,
            udp_gro: config.udp_gro,
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
            send_queues: &mut self.send_queues,
            pending_sends: &mut self.pending_sends,
            sends_dirty: &mut self.sends_dirty,
            sends_dirty_flag: &mut self.sends_dirty_flag,
            completions_dirty: &mut self.completions_dirty,
            completions_dirty_flag: &mut self.completions_dirty_flag,
            connect_pending: &mut self.connect_pending,
            pending_closes: &mut self.pending_closes,
            tcp_streams: &mut self.tcp_streams,
            poll: &mut self.poll,
            writable: &mut self.writable,
            send_completions: &mut self.send_completions,
            bounded_send_completions: &mut self.bounded_send_completions,
            capacity_released: &mut self.capacity_released,
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

    /// Request teardown of a connection. The only place (with the
    /// `DriverCtx` close) that sets `Lifecycle::Closing` on this backend —
    /// see the invariant on `Lifecycle::Closing`.
    ///
    /// Teardown itself (socket, buffers, executor state, slot release)
    /// happens in the event loop's `drain_pending_closes`, which has
    /// Executor access and defers until `pending_sends` has drained.
    /// Marking `Closing` here makes the call idempotent.
    /// Drop any recv-side exclusivity claims held against `conn_index`.
    ///
    /// Called at the slot's recycle point. Named to match
    /// `uring::driver::Driver::clear_conn_claims`, which additionally clears
    /// `segment_reader_live` — mio has no segmented domain, so there is only
    /// the one flag here.
    pub(crate) fn clear_conn_claims(&mut self, conn_index: u32) {
        if let Some(taken) = self.recv_half_taken.get_mut(conn_index as usize) {
            *taken = false;
        }
        if let Some(taken) = self.send_half_taken.get_mut(conn_index as usize) {
            *taken = false;
        }
    }

    pub(crate) fn close_connection(&mut self, conn_index: u32) {
        let idx = conn_index as usize;

        if let Some(conn) = self.connections.get_mut(conn_index) {
            if conn.close_requested() {
                return; // already closing
            }
            conn.lifecycle = Lifecycle::Closing;
        } else {
            return;
        }
        self.send_queues[idx].close_pending = true;
        self.pending_closes.push(conn_index);
    }

    /// Tear down a closed connection's driver-side state: best-effort
    /// nonblocking flush of pending sends, TLS close_notify, socket
    /// deregistration, buffer cleanup, and slot release. Called by the
    /// event loop after `Executor::remove_connection`.
    ///
    /// The flush is a single nonblocking attempt — the previous behavior
    /// flipped the fd to blocking and `write_all`'d, which let one
    /// zero-window peer stall the entire worker indefinitely.
    pub(crate) fn finish_close(&mut self, conn_index: u32) {
        let idx = conn_index as usize;

        let _ = self.flush_sends(conn_index);

        if let Some(ref mut stream) = self.tcp_streams[idx] {
            use std::io::Write;
            // Send TLS close_notify if this is a TLS connection
            // (best-effort, nonblocking).
            if let Some(ref mut tls_table) = self.tls_table
                && tls_table.has(conn_index)
            {
                // close_notify generation is engine-specific: the buffered
                // engine queues the alert on the rustls connection here (see
                // `crate::tls::buffered::BufferedKind::send_close_notify`),
                // while the unbuffered one encrypts it inside
                // `flush_tls_output_mio_direct` via
                // `WriteTraffic::queue_close_notify`. Both are best-effort --
                // the socket is going away.
                #[cfg(not(feature = "tls-unbuffered"))]
                if let Some(tls_conn) = tls_table.get_mut(conn_index)
                    && let Some(buffered) = tls_conn.conn.as_buffered_mut()
                {
                    buffered.send_close_notify();
                }
                crate::tls::flush_tls_output_mio_direct(tls_table, stream, conn_index);
                tls_table.remove(conn_index);
            }
            let _ = stream.flush();
        }

        // Deregister from poll and drop the TcpStream.
        if let Some(mut stream) = self.tcp_streams[idx].take() {
            let _ = self.poll.registry().deregister(&mut stream);
            // stream is dropped here, closing the fd
        }

        let was_established = self
            .connections
            .get(conn_index)
            .map(|c| c.established)
            .unwrap_or(false);

        self.clear_pending_sends(idx, || {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed before the send reached the socket",
            )
        });
        self.writable[idx] = false;
        if self.connect_deadlines[idx].take().is_some() {
            self.connect_pending -= 1;
        }
        self.send_completions[idx].clear();
        self.accumulators.reset(conn_index);

        self.send_queues[idx].queue.clear();
        self.send_queues[idx].in_flight = false;
        self.send_queues[idx].close_pending = false;

        // A future dropped during teardown may have owned a `RecvHalf` whose
        // `Drop` could not run (no driver in scope). Clear the claim before the
        // slot is reused, or its next occupant inherits it and can never take
        // its own read side.
        self.clear_conn_claims(conn_index);

        if self.connections.get(conn_index).is_some() {
            self.connections.release(conn_index);
        }

        crate::metrics::CONNECTIONS.increment(crate::metrics::conn::CLOSED);
        // Only decrement the active gauge for connections that were counted
        // into it — failed connects and TLS-handshake failures never
        // incremented, so unconditional decrement underflowed the gauge.
        if was_established {
            crate::metrics::CONNECTIONS_ACTIVE.decrement();
        }
    }

    /// Drop every queued send for `idx`, failing each bounded entry's id
    /// with `err()` and returning its copy-pool permit.
    ///
    /// The only sanctioned way to discard a `PendingSend`: a plain
    /// `pending_sends[idx].clear()` would drop a live [`SlotReservation`]
    /// (debug-assert) and strand the `send_backpressured` future that owns
    /// the entry's id. `err` is a closure because `io::Error` is not
    /// `Clone` and one call may have to fail several ids — see
    /// [`clone_io_error`].
    ///
    /// Callers pass `ConnectionAborted` at the teardown and slot-reuse
    /// sites and the real write error at
    /// `EventLoop::fail_connection_on_send_error`.
    pub(crate) fn clear_pending_sends(&mut self, idx: usize, err: impl Fn() -> io::Error) {
        clear_pending_sends_into(
            &mut self.pending_sends[idx],
            &mut self.send_copy_pool,
            &mut self.bounded_send_completions,
            &mut self.capacity_released,
            err,
        );
    }

    /// Queue forwarded bytes on the sink. Returns false if the sink is gone or
    /// its slot was recycled, which fails the forward.
    pub(crate) fn forward_push(&mut self, source: u32, data: &[u8]) -> bool {
        let Some(st) = self.forward_conn[source as usize].as_ref() else {
            return false;
        };
        let (sink, sink_gen) = (st.sink_index, st.sink_generation);
        if self.connections.generation(sink) != sink_gen
            || self.tcp_streams[sink as usize].is_none()
        {
            return false;
        }
        self.pending_sends[sink as usize].push_back(PendingSend::plain(data.to_vec()));
        self.mark_send_dirty(sink as usize);
        if let Some(st) = self.forward_conn[source as usize].as_mut() {
            st.forwarded += data.len() as u64;
        }
        true
    }

    /// Move what the accumulator is holding into a running forward, up to its
    /// remaining length, and settle the forward if that satisfies it.
    ///
    /// Two callers need this. A forward starts after the handler parsed a
    /// length header, so the body bytes that arrived with the header are
    /// already in the accumulator and are the front of the forward. And a TLS
    /// source has no other route: `feed_tls_recv_mio` decrypts into the
    /// accumulator, so forwarded plaintext is collected from there rather than
    /// from the socket read.
    ///
    /// Returns the settled result if the forward ended here, so the caller can
    /// wake the waiting task.
    pub(crate) fn forward_take_accumulated(&mut self, source: u32) -> Option<Result<u64, i32>> {
        let st = self.forward_conn[source as usize].as_ref()?;
        let remaining = st.len.saturating_sub(st.forwarded) as usize;
        let available = self.accumulators.data(source).len().min(remaining);
        if available > 0 {
            let head = self.accumulators.data(source)[..available].to_vec();
            self.accumulators.consume(source, available);
            if !self.forward_push(source, &head) {
                self.finish_forward(source, Err(libc::EPIPE));
                return Some(Err(libc::EPIPE));
            }
        }
        if available >= remaining {
            let forwarded = self.forward_conn[source as usize]
                .as_ref()
                .map_or(0, |st| st.forwarded);
            self.finish_forward(source, Ok(forwarded));
            return Some(Ok(forwarded));
        }
        None
    }

    /// Whether the sink's queue has reached the cap that stops the source
    /// reading. Without this a slow sink grows the queue without bound: mio
    /// cannot decline to read the way a depleted provided ring does.
    pub(crate) fn forward_sink_full(&self, source: u32) -> bool {
        self.forward_conn[source as usize]
            .as_ref()
            .is_some_and(|st| {
                self.pending_sends[st.sink_index as usize].len() >= self.forward_hold_cap
            })
    }

    /// Mark a source to be re-read once its sink drains. Edge-triggered epoll
    /// will not tell us again, so the loop has to come back on its own.
    pub(crate) fn mark_forward_resume(&mut self, source: u32) {
        let i = source as usize;
        if !self.forward_resume_flag[i] {
            self.forward_resume_flag[i] = true;
            self.forward_resume.push(source);
        }
    }

    /// Settle a forward and leave the result for the waiting future.
    pub(crate) fn finish_forward(&mut self, source: u32, result: Result<u64, i32>) {
        let i = source as usize;
        if let Some(st) = self.forward_conn[i].take() {
            self.forward_feeder[st.sink_index as usize] = None;
        }
        self.forward_done[i] = Some(result);
    }

    /// Record `idx` in the dirty-sends list so the event loop's flush pass
    /// visits it. Invariant: non-empty `pending_sends[idx]` ⇒ flag set.
    /// Every push into `pending_sends` — including the TLS paths that push
    /// from the event loop — and every partial flush must uphold this, or
    /// the queue stalls until an unrelated writable event arrives.
    pub(crate) fn mark_send_dirty(&mut self, idx: usize) {
        if !self.sends_dirty_flag[idx] {
            self.sends_dirty_flag[idx] = true;
            self.sends_dirty.push(idx as u32);
        }
    }

    /// Flush pending sends for a connection. Called by the event loop when
    /// the connection becomes writable.
    ///
    /// Returns `Ok((all_flushed, bytes_written))`: `all_flushed` is true if
    /// all pending data was flushed (or there was nothing to flush), false
    /// if we got WouldBlock mid-flush. A hard write error is returned as
    /// `Err` — the caller must fail the connection (the previous code
    /// swallowed it, kept the queue, and retried the failing writev every
    /// loop iteration forever while awaited sends reported success).
    ///
    /// Awaitable entries (`notify_len` set) push their completion when the
    /// entry's last byte reaches the socket.
    pub(crate) fn flush_sends(&mut self, conn_index: u32) -> io::Result<(bool, u32)> {
        use std::os::fd::AsRawFd;

        let idx = conn_index as usize;
        let stream = match self.tcp_streams[idx].as_mut() {
            Some(s) => s,
            None => return Ok((true, 0)),
        };

        let mut total_written: u32 = 0;

        // Use writev() to coalesce multiple pending sends into a single
        // syscall, reducing TCP segment count under pipelining.
        while !self.pending_sends[idx].is_empty() {
            let mut iovecs: Vec<libc::iovec> =
                Vec::with_capacity(self.pending_sends[idx].len().min(1024));
            for entry in self.pending_sends[idx].iter() {
                if iovecs.len() >= 1024 {
                    break;
                }
                let remaining = &entry.data[entry.offset..];
                if !remaining.is_empty() {
                    iovecs.push(libc::iovec {
                        iov_base: remaining.as_ptr() as *mut libc::c_void,
                        iov_len: remaining.len(),
                    });
                }
            }

            if iovecs.is_empty() {
                // Every queued entry has nothing left to write (only a
                // zero-length entry can get here; `send_bounded` never
                // queues one). Discard them through the permit-aware path
                // so a bounded entry cannot leak its reservation.
                clear_pending_sends_into(
                    &mut self.pending_sends[idx],
                    &mut self.send_copy_pool,
                    &mut self.bounded_send_completions,
                    &mut self.capacity_released,
                    || {
                        io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "queued send discarded with no bytes left to write",
                        )
                    },
                );
                break;
            }

            let fd = stream.as_raw_fd();
            let result = unsafe { libc::writev(fd, iovecs.as_ptr(), iovecs.len() as i32) };

            if result < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    self.writable[idx] = false;
                    // Queue survives this flush — keep the dirty invariant.
                    self.mark_send_dirty(idx);
                    return Ok((false, total_written));
                }
                return Err(err);
            }
            if result == 0 {
                // Connection closed by peer.
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "peer closed during send flush",
                ));
            }

            // Advance through the pending sends by the number of bytes written.
            crate::metrics::BYTES.add(crate::metrics::bytes::SENT, result as u64);
            let mut remaining = result as usize;
            total_written += result as u32;
            while remaining > 0 {
                if let Some(entry) = self.pending_sends[idx].front_mut() {
                    let avail = entry.data.len() - entry.offset;
                    if remaining >= avail {
                        remaining -= avail;
                        // Take both completions out of the entry before it
                        // is popped: the bounded permit must go back to the
                        // pool here, never by dropping the entry.
                        let notify = entry.notify_len.take();
                        let bounded = entry.bounded.take();
                        let written = entry.data.len() as u32;
                        if let Some(len) = notify {
                            self.send_completions[idx].push_back(len);
                            if !self.completions_dirty_flag[idx] {
                                self.completions_dirty_flag[idx] = true;
                                self.completions_dirty.push(idx as u32);
                            }
                        }
                        if let Some((id, permit)) = bounded {
                            self.send_copy_pool.release_reservation(permit);
                            self.capacity_released = true;
                            self.bounded_send_completions.push_back((id, Ok(written)));
                        }
                        self.pending_sends[idx].pop_front();
                    } else {
                        entry.offset += remaining;
                        remaining = 0;
                    }
                } else {
                    break;
                }
            }
        }

        // All sends flushed. A deferred half-close goes out only now, after
        // the final byte reached the socket.
        if let Some(cs) = self.connections.get_mut(conn_index)
            && matches!(cs.write, WriteHalf::ShutdownPending)
        {
            cs.write = WriteHalf::Shutdown;
            if let Some(stream) = self.tcp_streams[idx].as_mut() {
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        }

        // All sends flushed. Switch back to read-only interest — unless the
        // receive side is already closed (peer FIN, read error, or a
        // requested close), in which case re-adding READABLE would just
        // No re-arm here any more. Interest is registered once, as
        // READABLE|WRITABLE, and never modified: dropping WRITABLE after each
        // drain and re-adding it on the next send cost two `epoll_ctl(MOD)`
        // per operation, because an echo workload makes that queue transition
        // on every single request (#395).
        //
        // It also removes the hazard this code used to work around: it was a
        // `reregister` that re-reported EOF on a half-closed socket and span
        // the loop at 100% CPU. Not re-registering cannot re-report anything.
        Ok((true, total_written))
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Hand back the copy-pool permits of any bounded sends still
        // queued. Worker shutdown drops the driver with whatever is in
        // `pending_sends`; a `PendingSend`'s `SlotReservation` cannot
        // release itself and debug-asserts if it is dropped unfilled, so
        // this is the last of the disposal paths (the others are
        // `clear_pending_sends` and the completion in `flush_sends`). No
        // completion is pushed: the executor is going away with the driver.
        let pool = &mut self.send_copy_pool;
        for queue in self.pending_sends.iter_mut() {
            for entry in queue.drain(..) {
                if let Some((_id, permit)) = entry.bounded {
                    pool.release_reservation(permit);
                }
            }
        }

        // Close the wake pipe's read end. The write end is held by
        // `WakeHandle` clones that may live longer than the worker; it is
        // closed when the last `WakeHandle` clone drops.
        unsafe {
            libc::close(self.wake_pipe_fd);
        }
    }
}

/// Create and bind a UDP socket with `SO_REUSEPORT` enabled, returning a
/// `std::net::UdpSocket`.
///
/// `std::net::UdpSocket::bind` binds before any setsockopt can run, so it
/// can't be used here — multi-worker setups bind every worker to the same
/// port and need `SO_REUSEPORT` set before bind.
fn bind_udp_with_reuseport(addr: SocketAddr, udp_gro: bool) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::FromRawFd;

    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // `SOCK_CLOEXEC` is Linux-only; on macOS/BSD we set FD_CLOEXEC via fcntl
    // after the socket is created, mirroring the pattern in `acceptor.rs`.
    #[cfg(target_os = "linux")]
    let sock_type = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let sock_type = libc::SOCK_DGRAM;
    let fd = unsafe { libc::socket(domain, sock_type, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
        if fd_flags < 0 || libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
    }

    // SO_REUSEPORT lets every worker bind the same port. A zero port reaches
    // a worker only when each worker should get its own port, and with the
    // option set the free-port search can return a port another
    // SO_REUSEPORT socket already holds, so it is left off then.
    if addr.port() != 0 {
        let optval: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }

    // Enable UDP GRO (opt-in → hard-fail, mirroring the io_uring backend).
    // GRO is Linux-only; on other platforms `udp_gro` is a no-op.
    #[cfg(target_os = "linux")]
    if udp_gro {
        let on: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_UDP,
                crate::backend::udp_gro::UDP_GRO,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = udp_gro;

    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let addr_len = crate::backend::socket_addr_to_sockaddr(addr, &mut storage);
    let rc = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
}

#[cfg(test)]
pub(crate) mod tests {
    //! Driver-level tests for the mio backend.
    //!
    //! There is no mio event-loop test harness: these build a real `Driver`
    //! around a real loopback socket pair and drive its methods directly
    //! (`make_ctx()` for the `DriverCtx` entry points, `flush_sends` for the
    //! write side). The three helpers below are the shared scaffolding —
    //! `test_config` / `test_driver` / `attach_conn` — and are meant to be
    //! reused by every test added here. `attach_conn` and `token` are
    //! `pub(crate)` as well: the bounded-send tests that also need an
    //! `Executor` live in `backend/mio/event_loop.rs` and attach their
    //! connection the same way.

    use super::*;
    use crate::config::ConfigBuilder;
    use crate::handler::ConnToken;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    /// A minimal single-worker config for driver tests.
    ///
    /// Mirrors `backend/uring/event_loop.rs`'s `test_config_builder` minus the
    /// io_uring-only knobs. The send pool is deliberately tiny — 4 slots of
    /// 64 bytes — so tests can exhaust it and observe slot accounting with
    /// small payloads.
    fn test_config() -> Config {
        ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(4, 64)
            .build()
            .expect("valid test config")
    }

    /// Build a `Driver` with no acceptor, resolver, spawner, blocking or
    /// disk-I/O plumbing — every optional subsystem is `None`.
    ///
    /// The returned `WakeHandle` owns the write end of the wake pipe and
    /// **must be bound for the lifetime of the driver**
    /// (`let (mut driver, _wake) = test_driver(&config);`); dropping it closes
    /// the fd the driver still holds. The read end is intentionally left
    /// dangling: it is a per-test fd leak that the process exit reclaims,
    /// which is simpler than handing tests a second guard to keep alive.
    fn test_driver(config: &Config) -> (Driver, crate::wakeup::WakeHandle) {
        let (read_fd, handle) = crate::wakeup::create_wake_fd().expect("wake fd");
        let driver = Driver::new(
            config,
            None,
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
            None,
            None,
            None,
        )
        .expect("build mio driver");
        (driver, handle)
    }

    /// Attach a real, connected socket to a fresh connection slot, mirroring
    /// the plaintext half of `event_loop.rs`'s accept path: allocate the slot,
    /// register the accepted stream with the poll, reset the accumulator, and
    /// mark the connection `Open` / established / writable.
    ///
    /// Returns the connection index and the *client* end of the pair, so a
    /// test can read back whatever the driver wrote. The client end is
    /// blocking with a 5 s read timeout: a read that the driver never
    /// satisfies fails the test instead of hanging it.
    ///
    /// The listener is dropped before returning — an already accepted
    /// connection is unaffected by closing the listening socket, so nothing
    /// needs to keep the port bound.
    pub(crate) fn attach_conn(driver: &mut Driver) -> (u32, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let client = std::net::TcpStream::connect(addr).expect("connect to the listener");
        let (server, _peer) = listener.accept().expect("accept the connection");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("client read timeout");
        server
            .set_nonblocking(true)
            .expect("nonblocking accepted side");

        let conn_index = driver
            .connections
            .allocate()
            .expect("no free connection slots");
        let idx = conn_index as usize;

        let mut stream = mio::net::TcpStream::from_std(server);
        driver
            .poll
            .registry()
            .register(&mut stream, mio::Token(idx + 1), Interest::READABLE)
            .expect("register the accepted stream");
        driver.tcp_streams[idx] = Some(stream);
        driver.accumulators.reset(conn_index);
        driver.clear_pending_sends(idx, || {
            io::Error::new(io::ErrorKind::ConnectionAborted, "slot reused")
        });
        driver.writable[idx] = true;
        if let Some(cs) = driver.connections.get_mut(conn_index) {
            cs.lifecycle = Lifecycle::Open;
            cs.established = true;
        }

        (conn_index, client)
    }

    /// The token for an attached connection, for the `DriverCtx` entry points.
    pub(crate) fn token(driver: &Driver, conn_index: u32) -> ConnToken {
        ConnToken::new(conn_index, driver.connections.generation(conn_index))
    }

    /// Smoke test for the scaffolding itself: a plain send queues on the
    /// connection, `flush_sends` writes it all, and the peer reads the bytes.
    #[test]
    fn test_driver_builds_and_flushes_a_plain_send() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, mut client) = attach_conn(&mut driver);
        let idx = conn_index as usize;

        let conn = token(&driver, conn_index);
        driver
            .make_ctx()
            .send(conn, b"hello")
            .expect("queue a plain send");
        assert_eq!(
            driver.pending_sends[idx].len(),
            1,
            "mio sends are queued, never written inline"
        );

        let (all_flushed, written) = driver.flush_sends(conn_index).expect("flush");
        assert!(
            all_flushed,
            "the whole queue should have reached the socket"
        );
        assert_eq!(written, 5);
        assert!(driver.pending_sends[idx].is_empty());

        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).expect("read the flushed bytes");
        assert_eq!(&buf, b"hello");
    }

    /// Mint `n` distinct [`BoundedSendId`]s.
    ///
    /// Ids are only constructible through the executor's FIFO, and the
    /// driver never looks inside one — it carries the id from `send_bounded`
    /// to the completion queue. A throwaway queue is therefore enough here;
    /// the two event-loop tests that need the executor to route the result
    /// mint theirs from a real `Executor`.
    pub(crate) fn bounded_ids(n: usize) -> Vec<BoundedSendId> {
        let mut queue = crate::runtime::send_capacity::SendCapacityQueue::new();
        (0..n).map(|i| queue.enqueue(0, 0, 1, i as u32)).collect()
    }

    /// Set `SO_SNDBUF`/`SO_RCVBUF` on a raw fd.
    fn set_socket_buf(fd: RawFd, option: libc::c_int, bytes: libc::c_int) {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                &bytes as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt: {}", io::Error::last_os_error());
    }

    /// Drain and return the bounded completions the driver has queued.
    fn take_completions(driver: &mut Driver) -> Vec<(BoundedSendId, io::Result<u32>)> {
        driver.bounded_send_completions.drain(..).collect()
    }

    /// An already-handshaked `TlsConn` driven by whichever record-layer engine
    /// this build compiled in. Admission maths is only worth testing against
    /// records the engine under test actually produced, and the two engines
    /// size slots differently — the buffered one straddles them, the
    /// unbuffered one cannot.
    fn handshaked_tls_conn() -> crate::tls::TlsConn {
        #[cfg(feature = "tls-unbuffered")]
        {
            crate::tls::unbuffered::tests::handshaked_pair().0
        }
        #[cfg(not(feature = "tls-unbuffered"))]
        {
            let (server, _peer) = crate::tls::buffered::test_support::handshaked();
            crate::tls::buffered::test_support::wrap_server(server)
        }
    }

    /// The whole point of series PR 8: a bounded TLS send is admitted against
    /// the *ciphertext* bound, not the plaintext length. Getting this wrong is
    /// asymmetric — too large only delays the caller, too small lets rustls
    /// advance its record sequence and then run out of pool, which by
    /// departure 1 closes the connection.
    #[test]
    fn send_bounded_admits_a_tls_send_against_the_ciphertext_bound() {
        // Slots big enough to hold a whole worst-case record, so the bound is
        // expressible; the default 64-byte test slot is not.
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(8, 16448)
            .build()
            .expect("valid test config");
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        // A real, already-handshaked rustls session — the admission maths is
        // only worth testing against records rustls actually produced.
        let mut table = crate::tls::TlsTable::with_listener_configs(
            config.max_connections,
            None,
            None,
            Vec::new(),
        );
        table.insert_for_test(conn_index, handshaked_tls_conn());
        // One byte-slot's worth of plaintext, chosen so the two sizings give
        // different answers: it fits in ONE slot as plaintext but spans two
        // records, so the ciphertext cannot. Sizing the permit by
        // `data.len()` would admit this send against one slot and then need
        // two — the under-admission this PR exists to prevent.
        const PLAINTEXT: usize = 16448;
        assert_eq!(PLAINTEXT.div_ceil(16448), 1, "one slot as plaintext");

        let bound = table
            .ciphertext_capacity(conn_index, PLAINTEXT)
            .expect("the connection has TLS state");
        driver.tls_table = Some(table);

        // Two records for the plaintext plus the unconditional slack record.
        assert_eq!(bound.records(), 3);
        assert_eq!(bound.slots(16448), Some(3));

        assert_eq!(driver.send_copy_pool.free_count(), 8);
        driver
            .make_ctx()
            .send_bounded(conn, &[b'z'; PLAINTEXT], id)
            .expect("the pool can admit the bound");

        assert_eq!(
            driver.send_copy_pool.free_count(),
            6,
            "admitted against the three-slot ciphertext bound, then shrunk to \
             the two the records actually cost"
        );

        let entry = &driver.pending_sends[idx][0];
        assert!(
            entry.data.len() > PLAINTEXT,
            "the queued bytes are ciphertext, not the plaintext"
        );
        assert!(
            entry.data.len() <= bound.bytes(),
            "the bound must cover what rustls produced"
        );
        assert_eq!(entry.bounded.as_ref().map(|(qid, _)| *qid), Some(id));
        assert_eq!(
            entry.bounded.as_ref().map(|(_, p)| p.remaining()),
            Some(2),
            "the permit left on the entry is the shrunk one"
        );
    }

    /// The contract series PR 9's FIFO depends on: if `bounded_send_slots`
    /// says N, then `send_bounded` must succeed with exactly N slots free.
    /// The FIFO releases a waiter the moment `free_count() >= required_slots`,
    /// so N free slots is the designed operating point, not a margin.
    ///
    /// This is a **smoke check, not a proof**, and the distinction matters.
    /// The failure it guards against — the future enqueueing one number while
    /// the backend reserves another — is prevented structurally: both go
    /// through `bounded_send_slots`, so an inconsistent pair cannot be
    /// expressed. Verified by mutation: shrinking that function's result by
    /// one leaves this test green, because it shrinks *both* callers at once
    /// and the bound's slack record absorbs the difference. A test cannot
    /// catch a disagreement the type system has made impossible; what this
    /// does catch is someone reintroducing a second, separate computation.
    #[test]
    fn the_admitted_slot_count_is_enough_to_actually_send() {
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(8, 16448)
            .build()
            .expect("valid test config");
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        let mut table = crate::tls::TlsTable::with_listener_configs(
            config.max_connections,
            None,
            None,
            Vec::new(),
        );
        table.insert_for_test(conn_index, handshaked_tls_conn());
        driver.tls_table = Some(table);

        const PLAINTEXT: usize = 16448;
        let needed = crate::handler::bounded_send_slots(
            &driver.send_copy_pool,
            driver.tls_table.as_mut().unwrap() as *mut _,
            conn_index,
            PLAINTEXT,
        )
        .expect("the default slot size can bound this");

        // Starve the pool down to exactly what was admitted.
        let mut held = Vec::new();
        while driver.send_copy_pool.free_count() > needed {
            let (slot, _p, _l) = driver.send_copy_pool.copy_in(b"x").unwrap();
            held.push(slot);
        }
        assert_eq!(driver.send_copy_pool.free_count(), needed);

        driver
            .make_ctx()
            .send_bounded(conn, &[b'z'; PLAINTEXT], id)
            .expect("admitted at N free slots, so it must send at N free slots");

        for slot in held {
            driver.send_copy_pool.release(slot);
        }
    }

    /// A slot too small for the ciphertext bound refuses the send outright
    /// rather than admitting it against a smaller number. Which refusal you
    /// get depends on the engine, and both are correct: the buffered engine
    /// straddles slots, so a 64-byte slot is merely expensive (513 of them) and
    /// the pool-size refusal fires; the unbuffered engine cannot straddle, so
    /// no bound is expressible at all and the slot-size refusal fires. What
    /// must never happen in either build is a send admitted against a bound
    /// that is too small.
    #[test]
    fn send_bounded_refuses_a_tls_send_a_64_byte_slot_cannot_bound() {
        let config = test_config(); // 64-byte slots
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        let mut table = crate::tls::TlsTable::with_listener_configs(
            config.max_connections,
            None,
            None,
            Vec::new(),
        );
        table.insert_for_test(conn_index, handshaked_tls_conn());
        driver.tls_table = Some(table);

        let err = driver
            .make_ctx()
            .send_bounded(conn, &[b'z'; 100], id)
            .expect_err("a 64-byte slot cannot bound a TLS send");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        // Either way the message has to name the knob the operator can change.
        let msg = err.to_string();
        #[cfg(feature = "tls-unbuffered")]
        assert!(
            msg.contains("send_copy_slot_size"),
            "no bound is expressible, so the refusal names the slot size: {msg}"
        );
        #[cfg(not(feature = "tls-unbuffered"))]
        assert!(
            msg.contains("send-pool slots") && msg.contains("Config::send_pool"),
            "the bound is expressible but exceeds the pool: {msg}"
        );
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "a refusal reserves nothing"
        );
        assert!(driver.bounded_send_completions.is_empty());
    }

    /// Admission is the reservation: `send_bounded` takes its copy-pool
    /// permit up front, queues the bytes, and writes nothing.
    #[test]
    fn send_bounded_reserves_a_permit_and_queues_without_writing() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, mut client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        assert_eq!(driver.send_copy_pool.free_count(), 4);
        // 200 bytes over 64-byte slots needs all four.
        let payload = vec![b'a'; 200];
        driver
            .make_ctx()
            .send_bounded(conn, &payload, id)
            .expect("the pool can admit the whole message");

        assert_eq!(
            driver.send_copy_pool.free_count(),
            0,
            "the permit is held from admission until the last byte reaches the socket"
        );
        assert_eq!(driver.pending_sends[idx].len(), 1);
        let entry = &driver.pending_sends[idx][0];
        assert_eq!(entry.data.len(), 200);
        assert_eq!(entry.offset, 0);
        assert!(
            entry.notify_len.is_none(),
            "a bounded entry routes by id, not through the send() completion queue"
        );
        assert_eq!(
            entry.bounded.as_ref().map(|(qid, _)| *qid),
            Some(id),
            "the entry carries its id and permit"
        );
        assert!(
            driver.bounded_send_completions.is_empty(),
            "queueing completes nothing"
        );
        assert!(
            !driver.capacity_released,
            "no permit came back, so the capacity head must not be woken"
        );

        // Nothing was written: the peer sees no bytes at all.
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("short read timeout");
        let mut buf = [0u8; 1];
        let err = client
            .read(&mut buf)
            .expect_err("send_bounded must not write synchronously");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "expected an empty socket, got {err:?}"
        );
    }

    /// The completion and the permit are produced together, by the flush
    /// that puts the entry's last byte on the socket.
    #[test]
    fn flush_completes_bounded_entry_and_releases_permit() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, mut client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        let payload = vec![b'a'; 200];
        driver
            .make_ctx()
            .send_bounded(conn, &payload, id)
            .expect("admitted");

        let (all_flushed, written) = driver.flush_sends(conn_index).expect("flush");
        assert!(all_flushed);
        assert_eq!(written, 200);
        assert!(driver.pending_sends[idx].is_empty());
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "the permit goes back when the message is on the socket"
        );
        assert!(
            driver.capacity_released,
            "the event loop must be told capacity came back"
        );

        let completions = take_completions(&mut driver);
        assert_eq!(
            completions.len(),
            1,
            "exactly one completion per bounded id"
        );
        assert_eq!(completions[0].0, id);
        assert_eq!(
            *completions[0].1.as_ref().expect("a flushed send succeeds"),
            200
        );

        let mut buf = vec![0u8; 200];
        client.read_exact(&mut buf).expect("read the whole message");
        assert!(buf.iter().all(|&b| b == b'a'));
    }

    /// A message split across flushes keeps its id and its permit until the
    /// final byte, then completes exactly once.
    #[test]
    fn partial_write_keeps_permit_and_id() {
        // `test_config`'s four 64-byte slots cap a bounded send at 256
        // bytes, which no socket buffer is small enough to split, so this
        // test builds its own pool: 1 MiB over four 512 KiB slots reserves
        // two slots and cannot fit in any plausible socket buffer, shrunk or
        // not. The drain below is single-threaded and reads only bytes it
        // already knows were written, so nothing here depends on the host's
        // scheduling or on what a kernel does with `SO_SNDBUF` — two earlier
        // shapes did, and disagreed between macOS and a Linux CI guest: a
        // reader-thread race that never drained 2 MiB, then a 64 KiB payload
        // that Linux swallowed whole in the first flush.
        const PAYLOAD: usize = 1024 * 1024;
        let config = ConfigBuilder::new()
            .workers(1)
            .pin_to_core(false)
            .max_connections(16)
            .send_pool(4, 512 * 1024)
            .build()
            .expect("valid test config");
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        set_socket_buf(
            driver.tcp_streams[idx]
                .as_ref()
                .expect("attached stream")
                .as_raw_fd(),
            libc::SO_SNDBUF,
            4096,
        );
        // Explicitly sizing the peer's receive buffer also disables its
        // autotuning, so the window cannot grow to swallow the message.
        set_socket_buf(client.as_raw_fd(), libc::SO_RCVBUF, 4096);

        let payload = vec![b'p'; PAYLOAD];
        driver
            .make_ctx()
            .send_bounded(conn, &payload, id)
            .expect("admitted");
        let reserved_free = driver.send_copy_pool.free_count();
        assert_eq!(
            reserved_free, 2,
            "1 MiB reserves two of the four 512 KiB slots"
        );

        let (all_flushed, written) = driver
            .flush_sends(conn_index)
            .expect("a short write is not an error");
        assert!(
            !all_flushed,
            "no socket buffer takes a 1 MiB message in one writev"
        );
        assert!(
            (written as usize) < PAYLOAD,
            "expected a short write, got {written} of {PAYLOAD}"
        );
        assert_eq!(driver.pending_sends[idx].len(), 1, "the entry survives");
        assert_eq!(driver.pending_sends[idx][0].offset, written as usize);
        assert_eq!(
            driver.pending_sends[idx][0]
                .bounded
                .as_ref()
                .map(|(qid, _)| *qid),
            Some(id),
            "id and permit stay with the unfinished entry"
        );
        assert_eq!(
            driver.send_copy_pool.free_count(),
            reserved_free,
            "the permit is not released mid-message"
        );
        assert!(
            driver.bounded_send_completions.is_empty(),
            "no completion before the last byte"
        );

        // Drain and flush alternately on this one thread. Each read asks for
        // exactly the bytes the driver has already reported writing, so it
        // can never block on bytes that are not there, and no sleep or
        // timeout is involved: the loop is bounded by the socket buffer, not
        // by the clock.
        let mut client = client;
        let mut sink: Vec<u8> = Vec::with_capacity(PAYLOAD);
        let mut buf = vec![0u8; 64 * 1024];
        let mut written_total = written as usize;
        let mut drained = 0usize;
        let mut finished = false;

        for _ in 0..10_000 {
            while drained < written_total {
                let want = (written_total - drained).min(buf.len());
                client
                    .read_exact(&mut buf[..want])
                    .expect("the peer reads bytes the driver already wrote");
                sink.extend_from_slice(&buf[..want]);
                drained += want;
            }
            if finished {
                break;
            }
            let (done, w) = driver.flush_sends(conn_index).expect("flush");
            written_total += w as usize;
            // Drain once more before leaving, so `sink` holds every byte.
            finished = done;
        }
        assert!(finished, "the message never drained to the peer");
        assert_eq!(
            written_total, PAYLOAD,
            "every byte was written exactly once"
        );
        assert_eq!(sink.len(), PAYLOAD, "the peer received the whole message");
        assert!(
            sink.iter().all(|&b| b == b'p'),
            "the peer received the message intact"
        );

        let completions = take_completions(&mut driver);
        assert_eq!(
            completions.len(),
            1,
            "a message split across flushes still completes exactly once"
        );
        assert_eq!(completions[0].0, id);
        assert_eq!(
            *completions[0].1.as_ref().expect("the send succeeded") as usize,
            PAYLOAD,
            "the completion reports the whole message, not the last chunk"
        );
        assert_eq!(driver.send_copy_pool.free_count(), 4, "permit returned");

        // Closing the socket ends the reader's `read_to_end`.
        driver.tcp_streams[idx] = None;
    }

    /// A refused admission reserves nothing, queues nothing, and produces no
    /// completion — the caller owns the failure.
    #[test]
    fn send_bounded_refuses_without_side_effects() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let ids = bounded_ids(3);

        // 129 bytes = three 64-byte slots, leaving one free.
        driver
            .make_ctx()
            .send_bounded(conn, &[b'h'; 129], ids[0])
            .expect("admitted");
        assert_eq!(driver.send_copy_pool.free_count(), 1);

        // Needs two slots; only one is free.
        let err = driver
            .make_ctx()
            .send_bounded(conn, &[b'x'; 65], ids[1])
            .expect_err("the pool cannot admit the whole message");
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(
            err.to_string().contains("send copy pool exhausted"),
            "unexpected message: {err}"
        );
        assert_eq!(driver.pending_sends[idx].len(), 1, "nothing was queued");
        assert_eq!(
            driver.send_copy_pool.free_count(),
            1,
            "a refusal must not consume capacity"
        );
        assert!(
            driver.bounded_send_completions.is_empty(),
            "a refused id never completes"
        );

        // Larger than the whole pool: a different, permanent failure.
        let err = driver
            .make_ctx()
            .send_bounded(conn, &[b'y'; 257], ids[2])
            .expect_err("no pool occupancy could ever admit this");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string().contains("raise Config::send_pool"),
            "unexpected message: {err}"
        );
        assert_eq!(driver.pending_sends[idx].len(), 1);
        assert_eq!(driver.send_copy_pool.free_count(), 1);
        assert!(driver.bounded_send_completions.is_empty());
    }

    /// Discarding a send queue fails every bounded id in it, in queue order,
    /// and returns every permit.
    #[test]
    fn clear_pending_sends_fans_out_and_releases() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let ids = bounded_ids(2);

        driver
            .make_ctx()
            .send_bounded(conn, b"first", ids[0])
            .expect("admitted");
        driver.make_ctx().send(conn, b"plain").expect("queued");
        driver
            .make_ctx()
            .send_bounded(conn, b"second", ids[1])
            .expect("admitted");
        assert_eq!(driver.pending_sends[idx].len(), 3);
        assert_eq!(
            driver.send_copy_pool.free_count(),
            2,
            "one slot per bounded entry"
        );
        assert!(!driver.capacity_released);

        driver.clear_pending_sends(idx, || {
            io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")
        });

        assert!(driver.pending_sends[idx].is_empty());
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "both permits came back"
        );
        assert!(driver.capacity_released);

        let completions = take_completions(&mut driver);
        assert_eq!(
            completions.len(),
            2,
            "one completion per bounded entry; the plain entry has nobody to tell"
        );
        assert_eq!(
            completions.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            ids,
            "completions follow queue order"
        );
        for (id, result) in &completions {
            let err = result.as_ref().expect_err("a discarded send fails");
            assert_eq!(
                err.kind(),
                io::ErrorKind::ConnectionAborted,
                "wrong kind for {id:?}"
            );
        }
    }

    /// `finish_close` disposes of whatever is still queued when the socket
    /// is already gone — the one way teardown reaches its clear with a
    /// non-empty queue (`drain_pending_closes` finalizes on
    /// `pending_sends.is_empty() || tcp_streams[idx].is_none()`).
    ///
    /// One of the permit-disposal sites; a bare `pending_sends[idx].clear()`
    /// here strands the id and trips `SlotReservation`'s drop assert.
    #[test]
    fn finish_close_fails_a_send_left_queued_by_a_gone_socket() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        driver
            .make_ctx()
            .send_bounded(conn, b"never sent", id)
            .expect("admitted");
        assert_eq!(driver.send_copy_pool.free_count(), 3);
        driver.capacity_released = false;

        // The stream is gone, so `finish_close`'s opening flush writes
        // nothing and the entry survives to the clear.
        driver.tcp_streams[idx] = None;
        driver.close_connection(conn_index);
        driver.finish_close(conn_index);

        assert!(driver.pending_sends[idx].is_empty());
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "teardown returns the permit"
        );
        assert!(driver.capacity_released);
        let completions = take_completions(&mut driver);
        assert_eq!(completions.len(), 1, "the stranded id must be told");
        assert_eq!(completions[0].0, id);
        let err = completions[0].1.as_ref().expect_err("the send never went");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string()
                .contains("closed before the send reached the socket"),
            "unexpected message: {err}"
        );
    }

    /// The connect-time slot-reuse clear (`DriverCtx::connect`) disposes of
    /// whatever the previous occupant left queued: permit back, id failed.
    ///
    /// One of four permit-disposal sites; a bare `pending_sends[idx].clear()`
    /// here strands the id and trips `SlotReservation`'s drop assert.
    #[test]
    fn connect_time_slot_reuse_fails_a_stale_bounded_send() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let conn = token(&driver, conn_index);
        let id = bounded_ids(1)[0];

        driver
            .make_ctx()
            .send_bounded(conn, b"stranded", id)
            .expect("admitted");
        assert_eq!(driver.send_copy_pool.free_count(), 3);
        driver.capacity_released = false;

        // Free the slot with its send queue still populated — the state the
        // defensive clear exists for. No production path gets here today,
        // which is exactly why nothing else would notice it regressing.
        driver.tcp_streams[idx] = None;
        driver.connections.release(conn_index);

        // Nobody has to accept: mio's connect is nonblocking.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let reused = driver.make_ctx().connect(addr).expect("connect");
        assert_eq!(
            reused.index, conn_index,
            "the free list is LIFO, so this is the same slot"
        );

        assert!(driver.pending_sends[idx].is_empty(), "the stale entry went");
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "its permit came back to the pool"
        );
        assert!(driver.capacity_released, "the capacity head must be woken");
        let completions = take_completions(&mut driver);
        assert_eq!(completions.len(), 1, "the stranded id must be told");
        assert_eq!(completions[0].0, id);
        let err = completions[0].1.as_ref().expect_err("the send never went");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string().contains("reused by a new connect"),
            "unexpected message: {err}"
        );
    }

    /// `flush_sends`' empty-iovec bail-out disposes of what it discards.
    ///
    /// Only a zero-length entry reaches that branch and `send_bounded`
    /// settles those itself, so the entry is built by hand — permit
    /// included, exactly as `send_bounded` would hold it. One of four
    /// permit-disposal sites.
    #[test]
    fn empty_iovec_bailout_fails_the_bounded_entry_it_discards() {
        let config = test_config();
        let (mut driver, _wake) = test_driver(&config);
        let (conn_index, _client) = attach_conn(&mut driver);
        let idx = conn_index as usize;
        let id = bounded_ids(1)[0];

        let permit = driver
            .send_copy_pool
            .reserve_slots(1)
            .expect("a free slot to promise");
        driver.pending_sends[idx].push_back(PendingSend::bounded(Vec::new(), id, permit));
        assert_eq!(driver.send_copy_pool.free_count(), 3);

        let (all_flushed, written) = driver.flush_sends(conn_index).expect("flush");
        assert!(all_flushed, "nothing is left to write");
        assert_eq!(written, 0);

        assert!(driver.pending_sends[idx].is_empty());
        assert_eq!(
            driver.send_copy_pool.free_count(),
            4,
            "the discarded entry's permit came back"
        );
        assert!(driver.capacity_released);
        let completions = take_completions(&mut driver);
        assert_eq!(completions.len(), 1, "the discarded id must be told");
        assert_eq!(completions[0].0, id);
        let err = completions[0].1.as_ref().expect_err("discarded, not sent");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(
            err.to_string().contains("no bytes left to write"),
            "unexpected message: {err}"
        );
    }
}
