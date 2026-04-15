//! Mio backend driver — owns per-worker I/O state.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::accumulator::AccumulatorTable;
use crate::buffer::send_copy::SendCopyPool;
use crate::config::Config;
use crate::connection::ConnectionTable;
use crate::handler::{ConnSendState, DriverCtx};

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
    /// Per-connection mio tokens → connection index mapping.
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
            let server_config = config.tls.as_ref().and_then(|t| t.server_config.clone());
            let client_config = config.tls.as_ref().and_then(|t| t.client_config.clone());
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
                config.recv_buffer.buf_size,
            ),
            send_copy_pool: SendCopyPool::new(
                config.send_copy_pool_slots,
                config.send_copy_slot_size,
            ),
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
            fixed_buffers: todo!("mio DriverCtx not yet implemented"),
            send_copy_pool: &mut self.send_copy_pool,
            tls_table: tls_ptr,
            shutdown_requested: &mut self.shutdown_local,
            connect_addrs: &mut self.connect_addrs,
            tcp_nodelay: false,
            #[cfg(feature = "timestamps")]
            timestamps: false,
            #[cfg(feature = "timestamps")]
            recvmsg_msghdr: std::ptr::null(),
            chain_table: todo!("mio DriverCtx not yet implemented"),
            max_chain_length: 0,
            send_queues: &mut self.send_queues,
        }
    }

    /// Close and clean up a connection.
    pub(crate) fn close_connection(&mut self, _conn_index: u32) {
        // TODO: deregister from poll, clean up connection state
    }
}
