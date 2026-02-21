use std::collections::VecDeque;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use io_uring::cqueue;

use crate::accumulator::AccumulatorTable;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::buffer::provided::ProvidedBufRing;
use crate::buffer::send_copy::SendCopyPool;
use crate::buffer::send_slab::InFlightSendSlab;
use crate::chain::SendChainTable;
use crate::completion::{OpTag, UserData};
use crate::config::Config;
use crate::connection::{ConnectionTable, RecvMode};
use crate::handler::{BuiltSend, ConnSendState, DriverCtx};
use crate::ring::Ring;

/// Per-worker UDP socket state.
#[allow(dead_code)]
pub(crate) struct UdpSocketState {
    /// Fixed file table index for this socket.
    pub fd_index: u32,
    /// Bound address.
    pub local_addr: SocketAddr,
    // ── Recv state (heap-allocated for stable addresses) ──
    pub recv_buf: Box<[u8]>,
    pub recv_addr: Box<libc::sockaddr_storage>,
    pub recv_iov: Box<libc::iovec>,
    pub recv_msghdr: Box<libc::msghdr>,
    // ── Send state ──
    pub send_addr: Box<libc::sockaddr_storage>,
    pub send_iov: Box<libc::iovec>,
    pub send_msghdr: Box<libc::msghdr>,
    pub send_in_flight: bool,
    pub send_pool_slot: u16,
}

impl UdpSocketState {
    /// Reset msg_namelen before re-submitting recvmsg.
    pub fn reset_recv_namelen(&mut self) {
        self.recv_msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    }
}

/// Convert a libc sockaddr_storage to a std SocketAddr.
pub(crate) fn sockaddr_to_socket_addr(
    addr: &libc::sockaddr_storage,
    len: u32,
) -> Option<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    match addr.ss_family as libc::c_int {
        libc::AF_INET if len >= std::mem::size_of::<libc::sockaddr_in>() as u32 => {
            let sa = unsafe { &*(addr as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            let port = u16::from_be(sa.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if len >= std::mem::size_of::<libc::sockaddr_in6>() as u32 => {
            let sa = unsafe { &*(addr as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
            let port = u16::from_be(sa.sin6_port);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sa.sin6_flowinfo,
                sa.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Write a SocketAddr into a sockaddr_storage, return the address length.
pub(crate) fn socket_addr_to_sockaddr(
    addr: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> u32 {
    // Zero the storage to avoid uninitialised padding bytes.
    unsafe {
        std::ptr::write_bytes(
            storage as *mut _ as *mut u8,
            0,
            std::mem::size_of::<libc::sockaddr_storage>(),
        );
    }
    match addr {
        SocketAddr::V4(v4) => {
            let sa = storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = v4.port().to_be();
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            std::mem::size_of::<libc::sockaddr_in>() as u32
        }
        SocketAddr::V6(v6) => {
            let sa = storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sa).sin6_port = v6.port().to_be();
                (*sa).sin6_flowinfo = v6.flowinfo();
                (*sa).sin6_addr.s6_addr = v6.ip().octets();
                (*sa).sin6_scope_id = v6.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as u32
        }
    }
}

/// I/O driver encapsulating all infrastructure state (ring, buffers, connections).
///
/// `AsyncEventLoop` is composed of a `Driver` + handler + executor.
pub(crate) struct Driver {
    pub(crate) ring: Ring,
    pub(crate) connections: ConnectionTable,
    pub(crate) fixed_buffers: FixedBufferRegistry,
    pub(crate) provided_bufs: ProvidedBufRing,
    pub(crate) send_copy_pool: SendCopyPool,
    pub(crate) send_slab: InFlightSendSlab,
    pub(crate) accumulators: AccumulatorTable,
    pub(crate) pending_replenish: Vec<u16>,
    pub(crate) accept_rx: Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
    pub(crate) eventfd: RawFd,
    pub(crate) eventfd_buf: [u8; 8],
    /// Deadline-based flush interval. None = disabled (SQPOLL or explicit 0).
    pub(crate) flush_interval: Option<Duration>,
    pub(crate) shutdown_flag: Arc<AtomicBool>,
    pub(crate) shutdown_local: bool,
    #[cfg(feature = "tls")]
    pub(crate) tls_table: Option<crate::tls::TlsTable>,
    #[cfg(feature = "tls")]
    pub(crate) tls_scratch: Vec<u8>,
    /// Pre-allocated sockaddr storage for outbound connect SQEs.
    pub(crate) connect_addrs: Vec<libc::sockaddr_storage>,
    /// Pre-allocated timespec storage for connect timeouts.
    pub(crate) connect_timespecs: Vec<io_uring::types::Timespec>,
    /// Pre-allocated batch buffer for draining CQEs.
    /// Tuple: (user_data, result, flags, big_cqe). The big_cqe field
    /// contains the extra 16 bytes from Entry32 CQEs (used by NVMe passthrough).
    pub(crate) cqe_batch: Vec<(u64, i32, u32, [u64; 2])>,
    /// Whether to set TCP_NODELAY on connections.
    pub(crate) tcp_nodelay: bool,
    /// Whether SO_TIMESTAMPING is enabled for connections.
    #[cfg(feature = "timestamps")]
    pub(crate) timestamps: bool,
    /// Pinned msghdr template for RecvMsgMulti with SO_TIMESTAMPING.
    /// Used as the SQE template and for parsing CQE buffers via RecvMsgOut.
    #[cfg(feature = "timestamps")]
    pub(crate) recvmsg_msghdr: Box<libc::msghdr>,
    /// Per-connection send chain tracking for IOSQE_IO_LINK chains.
    pub(crate) chain_table: SendChainTable,
    /// Maximum SQEs per chain (0 = disabled).
    pub(crate) max_chain_length: u16,
    /// Per-connection send queues for serializing sends (one in-flight at a time).
    pub(crate) send_queues: Vec<ConnSendState>,
    /// Tick timeout duration. When set, a timeout SQE ensures the event loop
    /// wakes periodically even when no I/O completions are pending.
    pub(crate) tick_timeout_ts: Option<io_uring::types::Timespec>,
    /// Whether a tick timeout SQE is currently in-flight.
    pub(crate) tick_timeout_armed: bool,
    /// Per-worker UDP socket state.
    pub(crate) udp_sockets: Vec<UdpSocketState>,
    /// NVMe device tracking table. `None` when NVMe is not configured.
    pub(crate) nvme_devices: Option<crate::nvme::NvmeDeviceTable>,
    /// NVMe command slab for tracking in-flight commands. `None` when NVMe is not configured.
    pub(crate) nvme_cmd_slab: Option<crate::nvme::NvmeCmdSlab>,
    /// Base offset in the fixed file table for NVMe device fds.
    /// NVMe devices are registered at `nvme_fd_base + device_index`.
    pub(crate) nvme_fd_base: u32,
    /// Direct I/O file tracking table. `None` when direct I/O is not configured.
    pub(crate) direct_io_files: Option<crate::direct_io::DirectIoFileTable>,
    /// Direct I/O command slab for tracking in-flight commands. `None` when not configured.
    pub(crate) direct_io_cmd_slab: Option<crate::direct_io::DirectIoCmdSlab>,
    /// Base offset in the fixed file table for direct I/O file fds.
    pub(crate) direct_io_fd_base: u32,
}

impl Driver {
    /// Create a new driver for a worker thread.
    pub(crate) fn new(
        config: &Config,
        accept_rx: Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
        eventfd: RawFd,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<Self, crate::error::Error> {
        config.validate()?;
        let ring = Ring::setup(config)?;

        let fixed_buffers = FixedBufferRegistry::new(&config.registered_regions);

        let provided_bufs = ProvidedBufRing::new(
            config.recv_buffer.bgid,
            config.recv_buffer.ring_size,
            config.recv_buffer.buffer_size,
        )?;

        let udp_count = config.udp_bind.len() as u32;
        let nvme_max = config
            .nvme
            .as_ref()
            .map(|n| n.max_devices as u32)
            .unwrap_or(0);
        let direct_io_max = config
            .direct_io
            .as_ref()
            .map(|d| d.max_files as u32)
            .unwrap_or(0);

        // Register resources with the kernel
        ring.register_buffers(&fixed_buffers)?;
        ring.register_files_sparse(config.max_connections + udp_count + nvme_max + direct_io_max)?;
        ring.register_buf_ring(&provided_bufs)?;

        let connections = ConnectionTable::new(config.max_connections);
        let send_copy_pool = SendCopyPool::new(config.send_copy_count, config.send_copy_slot_size);
        let send_slab = InFlightSendSlab::new(config.send_slab_slots);
        let accumulators =
            AccumulatorTable::new(config.max_connections, config.recv_accumulator_capacity);

        // Deadline flush: disabled when SQPOLL (kernel polls SQ) or interval is 0.
        let flush_interval = if config.sqpoll || config.flush_interval_us == 0 {
            None
        } else {
            Some(Duration::from_micros(config.flush_interval_us))
        };

        #[cfg(feature = "tls")]
        let tls_table = {
            let has_server = config.tls.is_some();
            let has_client = config.tls_client.is_some();
            if has_server || has_client {
                Some(crate::tls::TlsTable::new(
                    config.max_connections,
                    config.tls.as_ref().map(|tc| tc.server_config.clone()),
                    config
                        .tls_client
                        .as_ref()
                        .map(|tc| tc.client_config.clone()),
                ))
            } else {
                None
            }
        };
        #[cfg(feature = "tls")]
        let tls_scratch = vec![0u8; 16384];

        let mut connect_addrs = Vec::with_capacity(config.max_connections as usize);
        connect_addrs.resize(config.max_connections as usize, unsafe {
            std::mem::zeroed()
        });

        let mut connect_timespecs = Vec::with_capacity(config.max_connections as usize);
        connect_timespecs.resize(
            config.max_connections as usize,
            io_uring::types::Timespec::new(),
        );

        let mut send_queues = Vec::with_capacity(config.max_connections as usize);
        for _ in 0..config.max_connections {
            send_queues.push(ConnSendState::new());
        }

        // Set up UDP sockets.
        let mut udp_sockets = Vec::with_capacity(config.udp_bind.len());
        for (udp_idx, bind_addr) in config.udp_bind.iter().enumerate() {
            let fd_index = config.max_connections + udp_idx as u32;
            let state = Self::setup_udp_socket(&ring, *bind_addr, fd_index)?;
            udp_sockets.push(state);
        }

        let mut driver = Driver {
            ring,
            connections,
            fixed_buffers,
            provided_bufs,
            send_copy_pool,
            send_slab,
            accumulators,
            pending_replenish: Vec::with_capacity(config.recv_buffer.ring_size as usize),
            accept_rx,
            eventfd,
            eventfd_buf: [0u8; 8],
            flush_interval,
            shutdown_flag,
            shutdown_local: false,
            #[cfg(feature = "tls")]
            tls_table,
            #[cfg(feature = "tls")]
            tls_scratch,
            connect_addrs,
            connect_timespecs,
            cqe_batch: Vec::with_capacity(config.sq_entries as usize * 4),
            tcp_nodelay: config.tcp_nodelay,
            #[cfg(feature = "timestamps")]
            timestamps: config.timestamps,
            #[cfg(feature = "timestamps")]
            recvmsg_msghdr: {
                let mut hdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
                // TCP: no source address needed.
                hdr.msg_namelen = 0;
                // Room for SCM_TIMESTAMPING cmsg: cmsghdr(16) + 3×timespec(48) = 64 bytes.
                hdr.msg_controllen = 64;
                hdr
            },
            chain_table: SendChainTable::new(config.max_connections),
            max_chain_length: config.max_chain_length,
            send_queues,
            tick_timeout_ts: if config.tick_timeout_us > 0 {
                Some(
                    io_uring::types::Timespec::new()
                        .sec(config.tick_timeout_us / 1_000_000)
                        .nsec((config.tick_timeout_us % 1_000_000) as u32 * 1000),
                )
            } else {
                None
            },
            tick_timeout_armed: false,
            udp_sockets,
            nvme_devices: config
                .nvme
                .as_ref()
                .map(|n| crate::nvme::NvmeDeviceTable::new(n.max_devices)),
            nvme_cmd_slab: config
                .nvme
                .as_ref()
                .map(|n| crate::nvme::NvmeCmdSlab::new(n.max_commands_in_flight)),
            nvme_fd_base: config.max_connections + udp_count,
            direct_io_files: config
                .direct_io
                .as_ref()
                .map(|d| crate::direct_io::DirectIoFileTable::new(d.max_files)),
            direct_io_cmd_slab: config
                .direct_io
                .as_ref()
                .map(|d| crate::direct_io::DirectIoCmdSlab::new(d.max_commands_in_flight)),
            direct_io_fd_base: config.max_connections + udp_count + nvme_max,
        };

        // Submit initial recvmsg for each UDP socket.
        for udp_idx in 0..driver.udp_sockets.len() {
            let ud = UserData::encode(OpTag::RecvMsgUdp, udp_idx as u32, 0);
            let msghdr_ptr = &mut *driver.udp_sockets[udp_idx].recv_msghdr as *mut libc::msghdr;
            let fd_index = driver.udp_sockets[udp_idx].fd_index;
            let _ = driver.ring.submit_recvmsg(fd_index, msghdr_ptr, ud);
        }

        Ok(driver)
    }

    /// Construct a [`DriverCtx`] by borrowing driver fields.
    ///
    /// Borrows `self` mutably, so callers cannot access individual driver
    /// fields while the returned `DriverCtx` is live. For cases requiring
    /// simultaneous access to specific fields (e.g., accumulators + ctx),
    /// construct `DriverCtx` inline with explicit field borrows.
    pub(crate) fn make_ctx(&mut self) -> DriverCtx<'_> {
        DriverCtx {
            ring: &mut self.ring,
            connections: &mut self.connections,
            fixed_buffers: &mut self.fixed_buffers,
            send_copy_pool: &mut self.send_copy_pool,
            send_slab: &mut self.send_slab,
            #[cfg(feature = "tls")]
            tls_table: match self.tls_table {
                Some(ref mut t) => t as *mut crate::tls::TlsTable,
                None => std::ptr::null_mut(),
            },
            shutdown_requested: &mut self.shutdown_local,
            connect_addrs: &mut self.connect_addrs,
            tcp_nodelay: self.tcp_nodelay,
            #[cfg(feature = "timestamps")]
            timestamps: self.timestamps,
            #[cfg(feature = "timestamps")]
            recvmsg_msghdr: &*self.recvmsg_msghdr as *const libc::msghdr,
            connect_timespecs: &mut self.connect_timespecs,
            chain_table: &mut self.chain_table,
            max_chain_length: self.max_chain_length,
            send_queues: &mut self.send_queues,
            udp_sockets: &mut self.udp_sockets,
            nvme_devices: &mut self.nvme_devices,
            nvme_cmd_slab: &mut self.nvme_cmd_slab,
            nvme_fd_base: self.nvme_fd_base,
            direct_io_files: &mut self.direct_io_files,
            direct_io_cmd_slab: &mut self.direct_io_cmd_slab,
            direct_io_fd_base: self.direct_io_fd_base,
        }
    }

    pub(crate) fn close_connection(&mut self, conn_index: u32) {
        if let Some(conn) = self.connections.get_mut(conn_index) {
            if matches!(conn.recv_mode, RecvMode::Closed) {
                return; // already closing — avoid double Close SQE
            }
            conn.recv_mode = RecvMode::Closed;
        } else {
            return;
        }
        // Cancel any active chain — per-SQE resources released as CQEs arrive.
        self.chain_table.cancel(conn_index);
        // Drain queued sends and release resources.
        self.drain_conn_send_queue(conn_index);
        let _ = self.ring.submit_close(conn_index);
    }

    /// Pop the next queued send for a connection and submit it to the ring.
    /// Returns true if a send was submitted, false if the queue was empty
    /// (in which case in_flight is set to false).
    pub(crate) fn submit_next_queued(&mut self, conn_index: u32) -> bool {
        let state = &mut self.send_queues[conn_index as usize];
        match state.queue.pop_front() {
            Some(built) => {
                let pool_slot = built.pool_slot;
                let slab_idx = built.slab_idx;
                match unsafe { self.ring.push_sqe(built.entry) } {
                    Ok(()) => true,
                    Err(_) => {
                        // SQ full — release this entry and drain remaining queue.
                        Self::release_built_resources(
                            &mut self.send_slab,
                            &mut self.send_copy_pool,
                            pool_slot,
                            slab_idx,
                        );
                        Self::release_queued_sends(
                            &mut state.queue,
                            &mut self.send_slab,
                            &mut self.send_copy_pool,
                        );
                        state.in_flight = false;
                        false
                    }
                }
            }
            None => {
                state.in_flight = false;
                false
            }
        }
    }

    /// Drain and release all queued sends for a connection.
    pub(crate) fn drain_conn_send_queue(&mut self, conn_index: u32) {
        let state = &mut self.send_queues[conn_index as usize];
        Self::release_queued_sends(
            &mut state.queue,
            &mut self.send_slab,
            &mut self.send_copy_pool,
        );
        state.in_flight = false;
    }

    /// Release all entries from a send queue.
    pub(crate) fn release_queued_sends(
        queue: &mut VecDeque<BuiltSend>,
        send_slab: &mut InFlightSendSlab,
        send_copy_pool: &mut SendCopyPool,
    ) {
        for built in queue.drain(..) {
            Self::release_built_resources(
                send_slab,
                send_copy_pool,
                built.pool_slot,
                built.slab_idx,
            );
        }
    }

    /// Release pool slot and/or slab entry for a single BuiltSend.
    pub(crate) fn release_built_resources(
        send_slab: &mut InFlightSendSlab,
        send_copy_pool: &mut SendCopyPool,
        pool_slot: u16,
        slab_idx: u16,
    ) {
        if slab_idx != u16::MAX {
            let ps = send_slab.release(slab_idx);
            if ps != u16::MAX {
                send_copy_pool.release(ps);
            }
        } else if pool_slot != u16::MAX {
            send_copy_pool.release(pool_slot);
        }
    }

    /// Create a UDP socket, bind with SO_REUSEPORT, register in fixed file table.
    fn setup_udp_socket(
        ring: &Ring,
        bind_addr: SocketAddr,
        fd_index: u32,
    ) -> Result<UdpSocketState, crate::error::Error> {
        let domain = if bind_addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };

        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
        if fd < 0 {
            return Err(crate::error::Error::Io(std::io::Error::last_os_error()));
        }

        // Set SO_REUSEPORT for multi-worker binding.
        let optval: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }

        // Bind.
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let addr_len = socket_addr_to_sockaddr(bind_addr, &mut storage);
        let ret =
            unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, addr_len) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(crate::error::Error::Io(err));
        }

        // Register in the fixed file table, then close the original fd.
        ring.register_files_update(fd_index, &[fd])?;
        unsafe {
            libc::close(fd);
        }

        // Allocate recv state.
        let recv_buf = vec![0u8; 65536].into_boxed_slice();
        let mut recv_addr: Box<libc::sockaddr_storage> = Box::new(unsafe { std::mem::zeroed() });
        let mut recv_iov = Box::new(libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
        let mut recv_msghdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });

        // Set up pointers (stable because everything is boxed).
        recv_iov.iov_base = recv_buf.as_ptr() as *mut libc::c_void;
        recv_iov.iov_len = recv_buf.len();
        recv_msghdr.msg_name = &mut *recv_addr as *mut _ as *mut libc::c_void;
        recv_msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        recv_msghdr.msg_iov = &mut *recv_iov as *mut libc::iovec;
        recv_msghdr.msg_iovlen = 1;

        // Allocate send state.
        let mut send_addr: Box<libc::sockaddr_storage> = Box::new(unsafe { std::mem::zeroed() });
        let mut send_iov = Box::new(libc::iovec {
            iov_base: std::ptr::null_mut(),
            iov_len: 0,
        });
        let mut send_msghdr: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });

        send_msghdr.msg_name = &mut *send_addr as *mut _ as *mut libc::c_void;
        send_msghdr.msg_iov = &mut *send_iov as *mut libc::iovec;
        send_msghdr.msg_iovlen = 1;

        Ok(UdpSocketState {
            fd_index,
            local_addr: bind_addr,
            recv_buf,
            recv_addr,
            recv_iov,
            recv_msghdr,
            send_addr,
            send_iov,
            send_msghdr,
            send_in_flight: false,
            send_pool_slot: u16::MAX,
        })
    }

    /// Send a UDP datagram via the copy pool.
    pub(crate) fn udp_send_to(
        &mut self,
        udp_index: u32,
        peer: SocketAddr,
        data: &[u8],
    ) -> Result<(), crate::error::UdpSendError> {
        let idx = udp_index as usize;
        if idx >= self.udp_sockets.len() {
            return Err(crate::error::UdpSendError::Io(std::io::Error::other(
                "invalid UDP socket index",
            )));
        }
        if self.udp_sockets[idx].send_in_flight {
            return Err(crate::error::UdpSendError::SendInFlight);
        }

        // Copy data to the send pool.
        let (pool_slot, ptr, len) = self
            .send_copy_pool
            .copy_in(data)
            .ok_or(crate::error::UdpSendError::PoolExhausted)?;

        // Set up destination address.
        let addr_len = socket_addr_to_sockaddr(peer, &mut self.udp_sockets[idx].send_addr);

        // Set up iovec.
        self.udp_sockets[idx].send_iov.iov_base = ptr as *mut libc::c_void;
        self.udp_sockets[idx].send_iov.iov_len = len as usize;

        // Update msghdr.
        self.udp_sockets[idx].send_msghdr.msg_namelen = addr_len;

        let fd_index = self.udp_sockets[idx].fd_index;
        let msghdr_ptr = &*self.udp_sockets[idx].send_msghdr as *const libc::msghdr;
        let ud = UserData::encode(OpTag::SendMsgUdp, udp_index, pool_slot as u32);

        match self.ring.submit_sendmsg(fd_index, msghdr_ptr, ud) {
            Ok(()) => {
                crate::metrics::UDP_DATAGRAMS_SENT.increment();
                self.udp_sockets[idx].send_in_flight = true;
                self.udp_sockets[idx].send_pool_slot = pool_slot;
                Ok(())
            }
            Err(_) => {
                self.send_copy_pool.release(pool_slot);
                Err(crate::error::UdpSendError::SubmissionQueueFull)
            }
        }
    }

    /// Re-submit recvmsg for a UDP socket after processing a datagram.
    pub(crate) fn resubmit_udp_recvmsg(&mut self, udp_index: u32) {
        let idx = udp_index as usize;
        if idx >= self.udp_sockets.len() {
            return;
        }
        self.udp_sockets[idx].reset_recv_namelen();
        let ud = UserData::encode(OpTag::RecvMsgUdp, udp_index, 0);
        let msghdr_ptr = &mut *self.udp_sockets[idx].recv_msghdr as *mut libc::msghdr;
        let fd_index = self.udp_sockets[idx].fd_index;
        let _ = self.ring.submit_recvmsg(fd_index, msghdr_ptr, ud);
    }

    /// Shutdown: close all connections, drain remaining CQEs, close eventfd.
    pub(crate) fn run_shutdown(&mut self) {
        // 1. Close all active connections and drain their send queues.
        let max = self.connections.max_slots();
        for i in 0..max {
            if self.connections.get(i).is_some() {
                self.drain_conn_send_queue(i);
                let _ = self.ring.submit_close(i);
            }
        }

        // 2. Submit + drain loop until all connections are closed.
        //    Arm a timeout SQE each iteration so submit_and_wait(1) never blocks
        //    indefinitely (the tick timeout from the main loop is not armed here).
        let shutdown_ts = io_uring::types::Timespec::new().nsec(100_000_000); // 100ms
        for _ in 0..100 {
            if self.connections.active_count() == 0 {
                break;
            }
            let ud = UserData::encode(OpTag::TickTimeout, 0, 0);
            let _ = self.ring.submit_tick_timeout(&shutdown_ts, ud.raw());
            if self.ring.submit_and_wait(1).is_err() {
                break;
            }

            self.cqe_batch.clear();
            {
                let cq = self.ring.ring.completion();
                for cqe in cq {
                    self.cqe_batch.push((
                        cqe.user_data(),
                        cqe.result(),
                        cqe.flags(),
                        *cqe.big_cqe(),
                    ));
                }
            }

            for i in 0..self.cqe_batch.len() {
                let (user_data_raw, _result, flags, _big_cqe) = self.cqe_batch[i];
                let ud = UserData(user_data_raw);
                let tag = match ud.tag() {
                    Some(t) => t,
                    None => continue,
                };

                match tag {
                    OpTag::Send => {
                        let pool_slot = ud.payload() as u16;
                        self.send_copy_pool.release(pool_slot);
                    }
                    OpTag::SendMsgZc => {
                        let slab_idx = ud.payload() as u16;
                        if !self.send_slab.in_use(slab_idx) {
                            continue;
                        }
                        if cqueue::notif(flags) {
                            self.send_slab.dec_pending_notifs(slab_idx);
                            if self.send_slab.should_release(slab_idx) {
                                let pool_slot = self.send_slab.release(slab_idx);
                                if pool_slot != u16::MAX {
                                    self.send_copy_pool.release(pool_slot);
                                }
                            }
                        } else {
                            self.send_slab.inc_pending_notifs(slab_idx);
                            self.send_slab.mark_awaiting_notifications(slab_idx);
                            if self.send_slab.should_release(slab_idx) {
                                let pool_slot = self.send_slab.release(slab_idx);
                                if pool_slot != u16::MAX {
                                    self.send_copy_pool.release(pool_slot);
                                }
                            }
                        }
                    }
                    OpTag::Close => {
                        let conn_index = ud.conn_index();
                        #[cfg(feature = "tls")]
                        if let Some(ref mut tls_table) = self.tls_table {
                            tls_table.remove(conn_index);
                        }
                        self.connections.release(conn_index);
                    }
                    #[cfg(feature = "tls")]
                    OpTag::TlsSend => {
                        let pool_slot = ud.payload() as u16;
                        self.send_copy_pool.release(pool_slot);
                    }
                    _ => {}
                }
            }
        }

        // 3. Close the eventfd.
        unsafe {
            libc::close(self.eventfd);
        }
    }
}
