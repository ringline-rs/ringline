use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;

use crate::buffer::send_copy::SendCopyPool;
use crate::buffer::send_slab::{InFlightSendSlab, MAX_GUARDS, MAX_IOVECS};
use crate::guard::GuardBox;

/// Per-connection send queue state.
///
/// Ensures at most one send SQE is in-flight per connection at a time.
/// When a send is already in-flight, subsequent sends are queued and
/// submitted immediately inside the CQE completion handler — before
/// `on_send_complete`, before returning to the event loop.
pub(crate) struct ConnSendState {
    pub in_flight: bool,
    pub queue: VecDeque<BuiltSend>,
}

impl ConnSendState {
    pub fn new() -> Self {
        ConnSendState {
            in_flight: false,
            queue: VecDeque::new(),
        }
    }
}

/// Opaque connection token handed to the handler.
/// Encodes the connection index and generation for stale detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnToken {
    pub(crate) index: u32,
    pub(crate) generation: u32,
}

impl ConnToken {
    pub(crate) fn new(index: u32, generation: u32) -> Self {
        ConnToken { index, generation }
    }

    /// Returns the connection slot index. Useful for indexing into per-connection arrays.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

/// Opaque handle for a UDP socket.
///
/// Each worker that binds a UDP address gets its own socket (via `SO_REUSEPORT`).
/// The token identifies a specific UDP socket within a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpToken(pub(crate) u32);

impl UdpToken {
    /// Returns the UDP socket index within this worker.
    pub fn index(&self) -> usize {
        self.0 as usize
    }
}

/// The context provided to handler callbacks for issuing operations.
///
/// This is a short-lived borrow into the driver's internal state.
pub struct DriverCtx<'a> {
    pub(crate) ring: &'a mut crate::ring::Ring,
    pub(crate) connections: &'a mut crate::connection::ConnectionTable,
    pub(crate) fixed_buffers: &'a mut crate::buffer::fixed::FixedBufferRegistry,
    pub(crate) send_copy_pool: &'a mut SendCopyPool,
    pub(crate) send_slab: &'a mut InFlightSendSlab,
    // SAFETY: Raw pointer for borrow splitting with the connection table.
    // Sound because: (1) single-threaded — DriverCtx is only created and used
    // on the worker thread that owns the Driver; (2) the pointer is derived
    // from `&mut Driver` which is live for the entire duration of any DriverCtx
    // borrow; (3) no mutable alias exists while DriverCtx holds this pointer
    // since DriverCtx borrows the other Driver fields mutably via split borrows.
    // Null when plaintext (TLS feature disabled or no TLS config).
    pub(crate) tls_table: *mut crate::tls::TlsTable,
    pub(crate) shutdown_requested: &'a mut bool,
    /// Pre-allocated sockaddr storage for outbound connect SQEs.
    pub(crate) connect_addrs: &'a mut Vec<libc::sockaddr_storage>,
    /// Whether to set TCP_NODELAY on outbound connections.
    pub(crate) tcp_nodelay: bool,
    /// Whether SO_TIMESTAMPING is enabled.
    #[cfg(feature = "timestamps")]
    pub(crate) timestamps: bool,
    /// Pointer to the per-worker RecvMsgMulti msghdr template.
    #[cfg(feature = "timestamps")]
    #[allow(dead_code)]
    pub(crate) recvmsg_msghdr: *const libc::msghdr,
    /// Pre-allocated timespec storage for connect timeouts.
    pub(crate) connect_timespecs: &'a mut Vec<io_uring::types::Timespec>,
    /// Per-connection send chain tracking.
    pub(crate) chain_table: &'a mut crate::chain::SendChainTable,
    /// Maximum SQEs per chain (0 = disabled).
    pub(crate) max_chain_length: u16,
    /// Per-connection send queues for serializing sends.
    pub(crate) send_queues: &'a mut Vec<ConnSendState>,
    /// Per-worker UDP socket state.
    pub(crate) udp_sockets: &'a mut Vec<crate::driver::UdpSocketState>,
    /// NVMe device table. `None` when NVMe is not configured.
    pub(crate) nvme_devices: &'a mut Option<crate::nvme::NvmeDeviceTable>,
    /// NVMe command slab. `None` when NVMe is not configured.
    pub(crate) nvme_cmd_slab: &'a mut Option<crate::nvme::NvmeCmdSlab>,
    /// Base offset in the fixed file table for NVMe device fds.
    pub(crate) nvme_fd_base: u32,
    /// Direct I/O file table. `None` when direct I/O is not configured.
    pub(crate) direct_io_files: &'a mut Option<crate::direct_io::DirectIoFileTable>,
    /// Direct I/O command slab. `None` when direct I/O is not configured.
    pub(crate) direct_io_cmd_slab: &'a mut Option<crate::direct_io::DirectIoCmdSlab>,
    /// Base offset in the fixed file table for direct I/O file fds.
    pub(crate) direct_io_fd_base: u32,
}

impl<'a> DriverCtx<'a> {
    /// Request shutdown of this worker's event loop.
    /// The worker will stop after the current iteration completes.
    pub fn request_shutdown(&mut self) {
        *self.shutdown_requested = true;
    }

    /// Get the peer address for a connection.
    pub fn peer_addr(&self, conn: ConnToken) -> Option<SocketAddr> {
        let cs = self.connections.get(conn.index)?;
        if cs.generation != conn.generation {
            return None;
        }
        cs.peer_addr
    }

    /// Check if a connection is outbound (initiated via connect/connect_tls).
    pub fn is_outbound(&self, conn: ConnToken) -> bool {
        self.connections
            .get(conn.index)
            .map(|cs| cs.generation == conn.generation && cs.outbound)
            .unwrap_or(false)
    }

    /// Get TLS session information for a connection.
    pub fn tls_info(&self, conn: ConnToken) -> Option<crate::tls::TlsInfo> {
        let cs = self.connections.get(conn.index)?;
        if cs.generation != conn.generation {
            return None;
        }
        if self.tls_table.is_null() {
            return None;
        }
        let tls_table = unsafe { &*self.tls_table };
        tls_table.get_info(conn.index)
    }

    /// Regular (copying) send — copies data into library-owned pool before SQE submission.
    pub fn send(&mut self, conn: ConnToken, data: &[u8]) -> io::Result<()> {
        let conn_state = self
            .connections
            .get(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }

        if !self.tls_table.is_null() {
            let tls_table = unsafe { &mut *self.tls_table };
            if tls_table.get_mut(conn.index).is_some() {
                return crate::tls::encrypt_and_send(
                    tls_table,
                    self.ring,
                    self.send_copy_pool,
                    conn.index,
                    data,
                );
            }
        }

        let (slot, ptr, len) = self
            .send_copy_pool
            .copy_in(data)
            .ok_or_else(|| io::Error::other("send copy pool exhausted"))?;

        let user_data = crate::completion::UserData::encode(
            crate::completion::OpTag::Send,
            conn.index,
            slot as u32,
        );
        let entry = io_uring::opcode::Send::new(io_uring::types::Fixed(conn.index), ptr, len)
            .build()
            .user_data(user_data.raw());

        let built = BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
            total_len: data.len() as u32,
        };

        self.submit_or_queue(conn.index, built)
    }

    /// Submit a built send SQE or queue it if a send is already in-flight.
    pub(crate) fn submit_or_queue(&mut self, conn_index: u32, built: BuiltSend) -> io::Result<()> {
        let state = &mut self.send_queues[conn_index as usize];
        if state.in_flight {
            state.queue.push_back(built);
            Ok(())
        } else {
            match unsafe { self.ring.push_sqe(built.entry) } {
                Ok(()) => {
                    state.in_flight = true;
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }

    /// Returns the maximum number of SQEs per IO_LINK chain.
    /// 0 means chaining is disabled.
    pub fn max_chain_length(&self) -> u16 {
        self.max_chain_length
    }

    /// Begin building an IO_LINK send chain for a connection.
    ///
    /// Multiple sends (copy-only or scatter-gather) are collected and submitted
    /// as a linked SQE chain. The kernel executes them sequentially, and a single
    /// `on_send_complete` fires when the entire chain is done.
    ///
    /// Returns a [`SendChainBuilder`]. Call `.copy()`, `.parts()...add()` to
    /// add SQEs, then `.finish()` to submit.
    pub fn send_chain(&mut self, conn: ConnToken) -> SendChainBuilder<'_, 'a> {
        SendChainBuilder {
            ctx: self,
            conn,
            built: Vec::new(),
            total_bytes: 0,
            error: None,
            finished: false,
        }
    }

    /// Begin building a scatter-gather send with mixed copy + zero-copy guard parts.
    pub fn send_parts(&mut self, conn: ConnToken) -> SendBuilder<'_, 'a> {
        SendBuilder {
            ctx: self,
            conn,
            parts: [PartSlot::Empty; MAX_IOVECS],
            part_count: 0,
            copy_slices: [(std::ptr::null(), 0); MAX_IOVECS],
            copy_count: 0,
            total_copy_len: 0,
            guards: [None, None, None, None],
            guard_count: 0,
            total_len: 0,
            error: None,
        }
    }

    /// Close a connection.
    pub fn close(&mut self, conn: ConnToken) {
        if let Some(conn_state) = self.connections.get_mut(conn.index) {
            if conn_state.generation != conn.generation {
                return;
            }
            conn_state.recv_mode = crate::connection::RecvMode::Closed;

            // Drain the send queue and release all queued resources.
            let state = &mut self.send_queues[conn.index as usize];
            for built in state.queue.drain(..) {
                if built.slab_idx != u16::MAX {
                    let pool_slot = self.send_slab.release(built.slab_idx);
                    if pool_slot != u16::MAX {
                        self.send_copy_pool.release(pool_slot);
                    }
                } else if built.pool_slot != u16::MAX {
                    self.send_copy_pool.release(built.pool_slot);
                }
            }
            state.in_flight = false;

            // Graceful TLS shutdown: send close_notify before closing.
            if !self.tls_table.is_null() {
                let tls_table = unsafe { &mut *self.tls_table };
                tls_table.send_close_notify(conn.index, self.ring, self.send_copy_pool);
            }

            let _ = self.ring.submit_close(conn.index);
        }
    }

    /// Shutdown the write side of a connection.
    pub fn shutdown_write(&mut self, conn: ConnToken) {
        if let Some(conn_state) = self.connections.get(conn.index) {
            if conn_state.generation != conn.generation {
                return;
            }
            let _ = self.ring.submit_shutdown(conn.index);
        }
    }

    /// Send a UDP datagram to the given peer address.
    ///
    /// Copies `data` into the send pool and submits a `sendmsg` SQE. Only one
    /// send can be in-flight per UDP socket at a time.
    pub fn send_to(
        &mut self,
        socket: UdpToken,
        peer: SocketAddr,
        data: &[u8],
    ) -> Result<(), crate::error::UdpSendError> {
        let idx = socket.0 as usize;
        if idx >= self.udp_sockets.len() {
            return Err(crate::error::UdpSendError::Io(io::Error::other(
                "invalid UDP socket index",
            )));
        }
        if self.udp_sockets[idx].send_in_flight {
            return Err(crate::error::UdpSendError::SendInFlight);
        }

        let (pool_slot, ptr, len) = self
            .send_copy_pool
            .copy_in(data)
            .ok_or(crate::error::UdpSendError::PoolExhausted)?;

        // Set up destination address.
        let addr_len =
            crate::driver::socket_addr_to_sockaddr(peer, &mut self.udp_sockets[idx].send_addr);

        // Set up iovec.
        self.udp_sockets[idx].send_iov.iov_base = ptr as *mut libc::c_void;
        self.udp_sockets[idx].send_iov.iov_len = len as usize;

        // Update msghdr.
        self.udp_sockets[idx].send_msghdr.msg_namelen = addr_len;

        let fd_index = self.udp_sockets[idx].fd_index;
        let msghdr_ptr = &*self.udp_sockets[idx].send_msghdr as *const libc::msghdr;
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::SendMsgUdp,
            socket.0,
            pool_slot as u32,
        );

        match self.ring.submit_sendmsg(fd_index, msghdr_ptr, ud) {
            Ok(()) => {
                crate::metrics::UDP_DATAGRAMS_SENT.increment();
                self.udp_sockets[idx].send_in_flight = true;
                self.udp_sockets[idx].send_pool_slot = pool_slot;
                Ok(())
            }
            Err(_e) => {
                self.send_copy_pool.release(pool_slot);
                Err(crate::error::UdpSendError::SubmissionQueueFull)
            }
        }
    }

    /// Initiate an outbound TCP connection. Returns immediately with a `ConnToken`.
    /// The `on_connect` callback fires when the TCP handshake completes (or fails).
    pub fn connect(&mut self, addr: SocketAddr) -> Result<ConnToken, crate::error::Error> {
        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or(crate::error::Error::ConnectionLimitReached)?;
        let generation = self.connections.generation(conn_index);

        // Store peer address.
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(addr);
        }

        // Create socket.
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw_fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw_fd < 0 {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }

        // Set TCP_NODELAY if configured.
        if self.tcp_nodelay {
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Set SO_TIMESTAMPING for kernel-level RX timestamps.
        #[cfg(feature = "timestamps")]
        if self.timestamps {
            let flags: libc::c_int = (libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_RX_SOFTWARE)
                as libc::c_int;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    libc::SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Register in the direct file table, then close the original fd.
        if let Err(e) = self.ring.register_files_update(conn_index, &[raw_fd]) {
            unsafe {
                libc::close(raw_fd);
            }
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }
        unsafe {
            libc::close(raw_fd);
        }

        // Fill sockaddr_storage for the connect SQE.
        let addrlen = crate::driver::socket_addr_to_sockaddr(
            addr,
            &mut self.connect_addrs[conn_index as usize],
        );

        // Submit the async connect.
        if let Err(e) = self.ring.submit_connect(
            conn_index,
            &self.connect_addrs[conn_index as usize] as *const _ as *const libc::sockaddr,
            addrlen,
        ) {
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        Ok(ConnToken::new(conn_index, generation))
    }

    /// Initiate an outbound TCP connection with a timeout.
    /// If the connection is not established within `timeout_ms`, `on_connect` fires
    /// with `Err(TimedOut)`.
    pub fn connect_with_timeout(
        &mut self,
        addr: SocketAddr,
        timeout_ms: u64,
    ) -> Result<ConnToken, crate::error::Error> {
        let token = self.connect(addr)?;
        self.arm_connect_timeout(token.index, timeout_ms);
        Ok(token)
    }

    /// Initiate an outbound TLS connection. Returns immediately with a `ConnToken`.
    /// The `on_connect` callback fires when both TCP + TLS handshakes complete (or fail).
    pub fn connect_tls(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<ConnToken, crate::error::Error> {
        if self.tls_table.is_null() {
            return Err(crate::error::Error::RingSetup(
                "TLS not configured".to_string(),
            ));
        }
        let tls_table = unsafe { &mut *self.tls_table };
        if !tls_table.has_client_config() {
            return Err(crate::error::Error::RingSetup(
                "TLS client config not set".to_string(),
            ));
        }

        let conn_index = self
            .connections
            .allocate_outbound()
            .ok_or(crate::error::Error::ConnectionLimitReached)?;
        let generation = self.connections.generation(conn_index);

        // Store peer address.
        if let Some(cs) = self.connections.get_mut(conn_index) {
            cs.peer_addr = Some(addr);
        }

        // Create socket.
        let domain = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let raw_fd = unsafe {
            libc::socket(
                domain,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw_fd < 0 {
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(io::Error::last_os_error()));
        }

        // Set TCP_NODELAY if configured.
        if self.tcp_nodelay {
            let optval: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::IPPROTO_TCP,
                    libc::TCP_NODELAY,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Set SO_TIMESTAMPING for kernel-level RX timestamps.
        #[cfg(feature = "timestamps")]
        if self.timestamps {
            let flags: libc::c_int = (libc::SOF_TIMESTAMPING_SOFTWARE
                | libc::SOF_TIMESTAMPING_RX_SOFTWARE)
                as libc::c_int;
            unsafe {
                libc::setsockopt(
                    raw_fd,
                    libc::SOL_SOCKET,
                    libc::SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        // Register in the direct file table, then close the original fd.
        if let Err(e) = self.ring.register_files_update(conn_index, &[raw_fd]) {
            unsafe {
                libc::close(raw_fd);
            }
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }
        unsafe {
            libc::close(raw_fd);
        }

        // Create TLS client state (buffers ClientHello internally).
        let sni = rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|e| {
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            crate::error::Error::RingSetup(format!("invalid server name: {e}"))
        })?;
        tls_table.create_client(conn_index, sni);

        // Fill sockaddr_storage for the connect SQE.
        let addrlen = crate::driver::socket_addr_to_sockaddr(
            addr,
            &mut self.connect_addrs[conn_index as usize],
        );

        // Submit the async connect.
        if let Err(e) = self.ring.submit_connect(
            conn_index,
            &self.connect_addrs[conn_index as usize] as *const _ as *const libc::sockaddr,
            addrlen,
        ) {
            tls_table.remove(conn_index);
            let _ = self.ring.register_files_update(conn_index, &[-1]);
            self.connections.release(conn_index);
            return Err(crate::error::Error::Io(e));
        }

        Ok(ConnToken::new(conn_index, generation))
    }

    /// Initiate an outbound TLS connection with a timeout.
    pub fn connect_tls_with_timeout(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
        timeout_ms: u64,
    ) -> Result<ConnToken, crate::error::Error> {
        let token = self.connect_tls(addr, server_name)?;
        self.arm_connect_timeout(token.index, timeout_ms);
        Ok(token)
    }

    /// Cancel pending operations on a connection.
    pub fn cancel(&mut self, conn: ConnToken) -> io::Result<()> {
        let cs = self
            .connections
            .get_mut(conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if cs.generation != conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }

        // Determine target op to cancel.
        let target_tag = match cs.recv_mode {
            crate::connection::RecvMode::Connecting => crate::completion::OpTag::Connect,
            crate::connection::RecvMode::Multi => crate::completion::OpTag::RecvMulti,
            #[cfg(feature = "timestamps")]
            crate::connection::RecvMode::MsgMulti => crate::completion::OpTag::RecvMsgMultiTs,
            crate::connection::RecvMode::Closed => {
                return Ok(()); // nothing to cancel
            }
        };

        // If cancelling a connect with an armed timeout, also cancel the timeout
        // so the Connect ECANCELED CQE is handled as user-initiated (not timeout-initiated).
        if matches!(target_tag, crate::completion::OpTag::Connect) && cs.connect_timeout_armed {
            cs.connect_timeout_armed = false;
            let timeout_ud = crate::completion::UserData::encode(
                crate::completion::OpTag::Timeout,
                conn.index,
                0,
            );
            let _ = self.ring.submit_async_cancel(timeout_ud.raw(), conn.index);
        }

        cs.recv_mode = crate::connection::RecvMode::Closed;

        let target_ud = crate::completion::UserData::encode(target_tag, conn.index, 0);
        self.ring.submit_async_cancel(target_ud.raw(), conn.index)?;
        Ok(())
    }

    // ── NVMe passthrough methods ──────────────────────────────────────────

    /// Open an NVMe device for passthrough I/O.
    ///
    /// `path` must be an NVMe-generic character device (e.g., `/dev/ng0n1`).
    /// `nsid` is the NVMe namespace ID (usually 1).
    ///
    /// The device fd is registered in the io_uring fixed file table. Returns
    /// an [`NvmeDevice`](crate::nvme::NvmeDevice) handle for subsequent operations.
    pub fn open_nvme_device(
        &mut self,
        path: &str,
        nsid: u32,
    ) -> io::Result<crate::nvme::NvmeDevice> {
        let devices = self
            .nvme_devices
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;

        let index = devices
            .allocate()
            .ok_or_else(|| io::Error::other("NVMe device table full"))?;

        // Open the NVMe-generic character device.
        let c_path =
            std::ffi::CString::new(path).map_err(|_| io::Error::other("invalid device path"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        if fd < 0 {
            devices.release(index);
            return Err(io::Error::last_os_error());
        }

        // Register in the fixed file table.
        let fd_index = self.nvme_fd_base + index as u32;
        if self.ring.register_files_update(fd_index, &[fd]).is_err() {
            devices.release(index);
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::other("failed to register NVMe fd"));
        }
        unsafe {
            libc::close(fd);
        }

        // Store device state.
        if let Some(dev) = devices.get_mut(index) {
            dev.fd_index = fd_index;
            dev.nsid = nsid;
        }

        let generation = devices.get(index).map(|d| d.generation).unwrap_or(0);
        Ok(crate::nvme::NvmeDevice { index, generation })
    }

    /// Submit an NVMe read command.
    ///
    /// Reads `num_blocks` logical blocks starting at `lba` into the buffer
    /// at `buf_addr` with length `buf_len`.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    ///
    /// # Safety
    ///
    /// `buf_addr` must point to a valid, aligned buffer of at least `buf_len`
    /// bytes that remains valid and exclusively accessible until the
    /// corresponding CQE completes.
    pub fn nvme_read(
        &mut self,
        device: crate::nvme::NvmeDevice,
        lba: u64,
        num_blocks: u16,
        buf_addr: u64,
        buf_len: u32,
    ) -> io::Result<u32> {
        let (fd_index, nsid) = self.validate_nvme_device(device)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab
            .allocate(device.index)
            .ok_or_else(|| io::Error::other("NVMe command slab exhausted"))?;

        let cmd = crate::nvme::NvmeUringCmd::read(nsid, lba, num_blocks, buf_addr, buf_len);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            slab_idx as u32,
        );

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an NVMe write command.
    ///
    /// Writes `num_blocks` logical blocks starting at `lba` from the buffer
    /// at `buf_addr` with length `buf_len`.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    ///
    /// # Safety
    ///
    /// `buf_addr` must point to a valid, aligned buffer of at least `buf_len`
    /// bytes that remains valid and exclusively accessible until the
    /// corresponding CQE completes.
    pub fn nvme_write(
        &mut self,
        device: crate::nvme::NvmeDevice,
        lba: u64,
        num_blocks: u16,
        buf_addr: u64,
        buf_len: u32,
    ) -> io::Result<u32> {
        let (fd_index, nsid) = self.validate_nvme_device(device)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab
            .allocate(device.index)
            .ok_or_else(|| io::Error::other("NVMe command slab exhausted"))?;

        let cmd = crate::nvme::NvmeUringCmd::write(nsid, lba, num_blocks, buf_addr, buf_len);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            slab_idx as u32,
        );

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an NVMe flush command.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    pub fn nvme_flush(&mut self, device: crate::nvme::NvmeDevice) -> io::Result<u32> {
        let (fd_index, nsid) = self.validate_nvme_device(device)?;

        let slab = self
            .nvme_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let slab_idx = slab
            .allocate(device.index)
            .ok_or_else(|| io::Error::other("NVMe command slab exhausted"))?;

        let cmd = crate::nvme::NvmeUringCmd::flush(nsid);
        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::NvmeCmd,
            device.index as u32,
            slab_idx as u32,
        );

        match unsafe { self.ring.submit_nvme_cmd(fd_index, &cmd, ud) } {
            Ok(()) => {
                if let Some(devices) = self.nvme_devices.as_mut()
                    && let Some(dev) = devices.get_mut(device.index)
                {
                    dev.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.nvme_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Close an NVMe device.
    pub fn close_nvme_device(&mut self, device: crate::nvme::NvmeDevice) -> io::Result<()> {
        let (fd_index, _nsid) = self.validate_nvme_device(device)?;

        // Unregister from the fixed file table.
        let _ = self.ring.register_files_update(fd_index, &[-1i32]);

        if let Some(devices) = self.nvme_devices.as_mut() {
            devices.release(device.index);
        }

        Ok(())
    }

    /// Validate an NVMe device handle and return (fd_index, nsid).
    fn validate_nvme_device(&self, device: crate::nvme::NvmeDevice) -> io::Result<(u32, u32)> {
        let devices = self
            .nvme_devices
            .as_ref()
            .ok_or_else(|| io::Error::other("NVMe not configured"))?;
        let dev = devices
            .get(device.index)
            .ok_or_else(|| io::Error::other("invalid NVMe device handle"))?;
        if dev.generation != device.generation {
            return Err(io::Error::other("stale NVMe device handle"));
        }
        Ok((dev.fd_index, dev.nsid))
    }

    // ── Direct I/O methods ────────────────────────────────────────────────

    /// Open a file for direct I/O (O_DIRECT).
    ///
    /// `path` can be any file or block device path. The file is opened with
    /// `O_RDWR | O_DIRECT`. The fd is registered in the io_uring fixed file table.
    ///
    /// Returns a [`DirectIoFile`](crate::direct_io::DirectIoFile) handle for
    /// subsequent operations.
    pub fn open_direct_io_file(
        &mut self,
        path: &str,
    ) -> io::Result<crate::direct_io::DirectIoFile> {
        let files = self
            .direct_io_files
            .as_mut()
            .ok_or_else(|| io::Error::other("direct I/O not configured"))?;

        let index = files
            .allocate()
            .ok_or_else(|| io::Error::other("direct I/O file table full"))?;

        // Open with O_DIRECT | O_RDWR.
        let c_path =
            std::ffi::CString::new(path).map_err(|_| io::Error::other("invalid file path"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_DIRECT) };
        if fd < 0 {
            files.release(index);
            return Err(io::Error::last_os_error());
        }

        // Register in the fixed file table.
        let fd_index = self.direct_io_fd_base + index as u32;
        if self.ring.register_files_update(fd_index, &[fd]).is_err() {
            files.release(index);
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::other("failed to register direct I/O fd"));
        }
        unsafe {
            libc::close(fd);
        }

        // Store file state.
        if let Some(f) = files.get_mut(index) {
            f.fd_index = fd_index;
        }

        let generation = files.get(index).map(|f| f.generation).unwrap_or(0);
        Ok(crate::direct_io::DirectIoFile { index, generation })
    }

    /// Submit a direct I/O read.
    ///
    /// Reads `len` bytes from `offset` into the buffer at `buf`.
    /// The buffer must be aligned to the logical block size and remain valid
    /// until the direct I/O completion fires.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    ///
    /// # Safety
    /// `buf` must point to valid, aligned memory of at least `len` bytes
    /// that remains valid until the completion callback fires.
    pub unsafe fn direct_io_read(
        &mut self,
        file: crate::direct_io::DirectIoFile,
        offset: u64,
        buf: *mut u8,
        len: u32,
    ) -> io::Result<u32> {
        let fd_index = self.validate_direct_io_file(file)?;

        let slab = self
            .direct_io_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("direct I/O not configured"))?;
        let slab_idx = slab
            .allocate(file.index, crate::direct_io::DirectIoOp::Read)
            .ok_or_else(|| io::Error::other("direct I/O command slab exhausted"))?;

        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::DirectIo,
            file.index as u32,
            slab_idx as u32,
        );

        match unsafe { self.ring.submit_direct_read(fd_index, buf, len, offset, ud) } {
            Ok(()) => {
                if let Some(files) = self.direct_io_files.as_mut()
                    && let Some(f) = files.get_mut(file.index)
                {
                    f.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.direct_io_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit a direct I/O write.
    ///
    /// Writes `len` bytes from the buffer at `buf` to `offset`.
    /// The buffer must be aligned to the logical block size and remain valid
    /// until the direct I/O completion fires.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    ///
    /// # Safety
    /// `buf` must point to valid, aligned memory of at least `len` bytes
    /// that remains valid until the completion callback fires.
    pub unsafe fn direct_io_write(
        &mut self,
        file: crate::direct_io::DirectIoFile,
        offset: u64,
        buf: *const u8,
        len: u32,
    ) -> io::Result<u32> {
        let fd_index = self.validate_direct_io_file(file)?;

        let slab = self
            .direct_io_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("direct I/O not configured"))?;
        let slab_idx = slab
            .allocate(file.index, crate::direct_io::DirectIoOp::Write)
            .ok_or_else(|| io::Error::other("direct I/O command slab exhausted"))?;

        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::DirectIo,
            file.index as u32,
            slab_idx as u32,
        );

        match unsafe {
            self.ring
                .submit_direct_write(fd_index, buf, len, offset, ud)
        } {
            Ok(()) => {
                if let Some(files) = self.direct_io_files.as_mut()
                    && let Some(f) = files.get_mut(file.index)
                {
                    f.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.direct_io_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Submit an fsync for a direct I/O file.
    ///
    /// Returns the command slab index (sequence number) for correlation.
    pub fn direct_io_fsync(&mut self, file: crate::direct_io::DirectIoFile) -> io::Result<u32> {
        let fd_index = self.validate_direct_io_file(file)?;

        let slab = self
            .direct_io_cmd_slab
            .as_mut()
            .ok_or_else(|| io::Error::other("direct I/O not configured"))?;
        let slab_idx = slab
            .allocate(file.index, crate::direct_io::DirectIoOp::Fsync)
            .ok_or_else(|| io::Error::other("direct I/O command slab exhausted"))?;

        let ud = crate::completion::UserData::encode(
            crate::completion::OpTag::DirectIo,
            file.index as u32,
            slab_idx as u32,
        );

        match self.ring.submit_direct_fsync(fd_index, ud) {
            Ok(()) => {
                if let Some(files) = self.direct_io_files.as_mut()
                    && let Some(f) = files.get_mut(file.index)
                {
                    f.in_flight += 1;
                }
                Ok(slab_idx as u32)
            }
            Err(e) => {
                if let Some(slab) = self.direct_io_cmd_slab.as_mut() {
                    slab.release(slab_idx);
                }
                Err(e)
            }
        }
    }

    /// Close a direct I/O file.
    pub fn close_direct_io_file(&mut self, file: crate::direct_io::DirectIoFile) -> io::Result<()> {
        let fd_index = self.validate_direct_io_file(file)?;

        // Unregister from the fixed file table.
        let _ = self.ring.register_files_update(fd_index, &[-1i32]);

        if let Some(files) = self.direct_io_files.as_mut() {
            files.release(file.index);
        }

        Ok(())
    }

    /// Validate a direct I/O file handle and return the fd_index.
    fn validate_direct_io_file(&self, file: crate::direct_io::DirectIoFile) -> io::Result<u32> {
        let files = self
            .direct_io_files
            .as_ref()
            .ok_or_else(|| io::Error::other("direct I/O not configured"))?;
        let f = files
            .get(file.index)
            .ok_or_else(|| io::Error::other("invalid direct I/O file handle"))?;
        if f.generation != file.generation {
            return Err(io::Error::other("stale direct I/O file handle"));
        }
        Ok(f.fd_index)
    }

    /// Arm a connect timeout for the given connection index.
    fn arm_connect_timeout(&mut self, conn_index: u32, timeout_ms: u64) {
        let ts = &mut self.connect_timespecs[conn_index as usize];
        *ts = io_uring::types::Timespec::new()
            .sec(timeout_ms / 1000)
            .nsec((timeout_ms % 1000) as u32 * 1_000_000);

        let ud =
            crate::completion::UserData::encode(crate::completion::OpTag::Timeout, conn_index, 0);
        if self.ring.submit_timeout(ts as *const _, ud).is_ok()
            && let Some(cs) = self.connections.get_mut(conn_index)
        {
            cs.connect_timeout_armed = true;
        }
    }
}

/// A prepared SQE with its associated resources, ready for submission.
pub(crate) struct BuiltSend {
    pub entry: io_uring::squeue::Entry,
    /// SendCopyPool slot index. u16::MAX if none.
    pub pool_slot: u16,
    /// InFlightSendSlab index. u16::MAX if none (only for SendMsgZc).
    pub slab_idx: u16,
    /// Total bytes this SQE will send.
    pub total_len: u32,
}

/// A pre-classified part for `AsyncSendBuilder::submit_batch`.
///
/// Used to build mixed scatter-gather sends in the async API without the
/// lifetime constraints of the closure-based `AsyncSendBuilder::build`.
pub enum SendPart<'a> {
    /// Data to be copied into the send pool on submit.
    Copy(&'a [u8]),
    /// Zero-copy guard — ownership is transferred to the kernel on submit.
    Guard(GuardBox),
}

/// Part type in a scatter-gather send.
#[derive(Clone, Copy)]
enum PartSlot {
    Empty,
    Copy { slice_idx: u8 },
    Guard { guard_idx: u8 },
}

/// Builder for scatter-gather sends with mixed copy + zero-copy guard parts.
pub struct SendBuilder<'b, 'a> {
    ctx: &'b mut DriverCtx<'a>,
    conn: ConnToken,
    parts: [PartSlot; MAX_IOVECS],
    part_count: u8,
    copy_slices: [(*const u8, usize); MAX_IOVECS],
    copy_count: u8,
    total_copy_len: usize,
    guards: [Option<GuardBox>; MAX_GUARDS],
    guard_count: u8,
    total_len: u32,
    error: Option<io::Error>,
}

impl<'b, 'a> SendBuilder<'b, 'a> {
    /// Add a copy part. The data will be copied into the send pool on `submit()`.
    /// The data reference must outlive the builder (guaranteed by the `'b` lifetime).
    pub fn copy(mut self, data: &'b [u8]) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 8)",
            ));
            return self;
        }
        let idx = self.copy_count;
        self.copy_slices[idx as usize] = (data.as_ptr(), data.len());
        self.copy_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Copy { slice_idx: idx };
        self.part_count += 1;
        self.total_len += data.len() as u32;
        self.total_copy_len += data.len();
        self
    }

    /// Add a zero-copy guard part. The guard keeps the memory alive until the kernel
    /// releases it via the ZC notification.
    pub fn guard(mut self, guard: GuardBox) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 8)",
            ));
            return self;
        }
        if self.guard_count as usize >= MAX_GUARDS {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many guards (max 4)",
            ));
            return self;
        }
        let (_, len) = guard.as_ptr_len();
        let gidx = self.guard_count;
        self.guards[gidx as usize] = Some(guard);
        self.guard_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Guard { guard_idx: gidx };
        self.part_count += 1;
        self.total_len += len;
        self
    }

    /// Submit the scatter-gather send.
    pub fn submit(mut self) -> io::Result<()> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }

        if self.part_count == 0 {
            return Ok(());
        }

        // Validate connection + generation.
        let conn_state = self
            .ctx
            .connections
            .get(self.conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != self.conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }

        // TLS path: gather all data, encrypt, copy-send. Drop guards immediately.
        if !self.ctx.tls_table.is_null() {
            let tls_table = unsafe { &mut *self.ctx.tls_table };
            if tls_table.get_mut(self.conn.index).is_some() {
                return self.submit_tls(tls_table);
            }
        }

        // No guards: gather all copy parts into one pool slot, submit as regular Send.
        if self.guard_count == 0 {
            return self.submit_copy_only();
        }

        // With guards: build iovecs mixing copy pool subranges and guard pointers.
        self.submit_with_guards()
    }

    /// TLS fallback: gather all data into a contiguous buffer, encrypt, copy-send.
    fn submit_tls(mut self, tls_table: &mut crate::tls::TlsTable) -> io::Result<()> {
        let mut plaintext = Vec::with_capacity(self.total_len as usize);
        for i in 0..self.part_count as usize {
            match self.parts[i] {
                PartSlot::Copy { slice_idx } => {
                    let (ptr, len) = self.copy_slices[slice_idx as usize];
                    let data = unsafe { std::slice::from_raw_parts(ptr, len) };
                    plaintext.extend_from_slice(data);
                }
                PartSlot::Guard { guard_idx } => {
                    if let Some(ref g) = self.guards[guard_idx as usize] {
                        let (ptr, len) = g.as_ptr_len();
                        let data = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
                        plaintext.extend_from_slice(data);
                    }
                }
                PartSlot::Empty => {}
            }
        }
        // Drop guards — TLS encrypted copy-send doesn't need ZC
        for g in self.guards.iter_mut() {
            *g = None;
        }
        crate::tls::encrypt_and_send(
            tls_table,
            self.ctx.ring,
            self.ctx.send_copy_pool,
            self.conn.index,
            &plaintext,
        )
    }

    /// Copy-only path: gather all copy parts into one pool slot, return built SQE.
    fn build_copy_only(&mut self) -> io::Result<BuiltSend> {
        let (slot, ptr, len) = unsafe {
            self.ctx.send_copy_pool.copy_in_gather(
                &self.copy_slices[..self.copy_count as usize],
                self.total_copy_len,
            )
        }
        .ok_or_else(|| io::Error::other("send copy pool exhausted"))?;

        let user_data = crate::completion::UserData::encode(
            crate::completion::OpTag::Send,
            self.conn.index,
            slot as u32,
        );
        let entry = io_uring::opcode::Send::new(io_uring::types::Fixed(self.conn.index), ptr, len)
            .build()
            .user_data(user_data.raw());

        Ok(BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
            total_len: self.total_len,
        })
    }

    /// Mixed copy+guard path: allocate pool slot + slab entry, return built SQE.
    #[allow(clippy::needless_range_loop)]
    fn build_with_guards(&mut self) -> io::Result<BuiltSend> {
        let slot_size = self.ctx.send_copy_pool.slot_size() as usize;
        if self.total_copy_len > slot_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "total copy data exceeds send pool slot size",
            ));
        }

        if self.total_copy_len > 0 {
            let (slot, pool_ptr, _pool_len) = unsafe {
                self.ctx.send_copy_pool.copy_in_gather(
                    &self.copy_slices[..self.copy_count as usize],
                    self.total_copy_len,
                )
            }
            .ok_or_else(|| io::Error::other("send copy pool exhausted"))?;

            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            let mut copy_offset: usize = 0;
            for i in 0..self.part_count as usize {
                match self.parts[i] {
                    PartSlot::Copy { slice_idx } => {
                        let (_src_ptr, src_len) = self.copy_slices[slice_idx as usize];
                        iovecs[i] = libc::iovec {
                            iov_base: pool_ptr.wrapping_add(copy_offset) as *mut _,
                            iov_len: src_len,
                        };
                        copy_offset += src_len;
                    }
                    PartSlot::Guard { guard_idx } => {
                        let g = self.guards[guard_idx as usize].as_ref().unwrap();
                        let (gptr, glen) = g.as_ptr_len();
                        let region = g.region();
                        if region != crate::buffer::fixed::RegionId::UNREGISTERED {
                            self.ctx
                                .fixed_buffers
                                .validate_region_ptr(region, gptr, glen)
                                .map_err(|e| {
                                    self.ctx.send_copy_pool.release(slot);
                                    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                                })?;
                        }
                        iovecs[i] = libc::iovec {
                            iov_base: gptr as *mut _,
                            iov_len: glen as usize,
                        };
                    }
                    PartSlot::Empty => {}
                }
            }

            // Take guards out of self (moved into slab).
            let guards = std::mem::take(&mut self.guards);
            let iov_slice = &iovecs[..self.part_count as usize];
            let total_len = self.total_len;
            let (slab_idx, msg_ptr) = self
                .ctx
                .send_slab
                .allocate(
                    self.conn.index,
                    iov_slice,
                    slot,
                    guards,
                    self.guard_count,
                    total_len,
                )
                .ok_or_else(|| {
                    self.ctx.send_copy_pool.release(slot);
                    io::Error::other("send slab exhausted")
                })?;

            let user_data = crate::completion::UserData::encode(
                crate::completion::OpTag::SendMsgZc,
                self.conn.index,
                slab_idx as u32,
            );
            let entry =
                io_uring::opcode::SendMsgZc::new(io_uring::types::Fixed(self.conn.index), msg_ptr)
                    .build()
                    .user_data(user_data.raw());

            Ok(BuiltSend {
                entry,
                pool_slot: slot,
                slab_idx,
                total_len,
            })
        } else {
            // No copy data, only guards.
            let mut iovecs = [libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: 0,
            }; MAX_IOVECS];
            for i in 0..self.part_count as usize {
                if let PartSlot::Guard { guard_idx } = self.parts[i] {
                    let g = self.guards[guard_idx as usize].as_ref().unwrap();
                    let (gptr, glen) = g.as_ptr_len();
                    let region = g.region();
                    if region != crate::buffer::fixed::RegionId::UNREGISTERED {
                        self.ctx
                            .fixed_buffers
                            .validate_region_ptr(region, gptr, glen)
                            .map_err(|e| {
                                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
                            })?;
                    }
                    iovecs[i] = libc::iovec {
                        iov_base: gptr as *mut _,
                        iov_len: glen as usize,
                    };
                }
            }

            let guards = std::mem::take(&mut self.guards);
            let iov_slice = &iovecs[..self.part_count as usize];
            let total_len = self.total_len;
            let (slab_idx, msg_ptr) = self
                .ctx
                .send_slab
                .allocate(
                    self.conn.index,
                    iov_slice,
                    u16::MAX,
                    guards,
                    self.guard_count,
                    total_len,
                )
                .ok_or_else(|| io::Error::other("send slab exhausted"))?;

            let user_data = crate::completion::UserData::encode(
                crate::completion::OpTag::SendMsgZc,
                self.conn.index,
                slab_idx as u32,
            );
            let entry =
                io_uring::opcode::SendMsgZc::new(io_uring::types::Fixed(self.conn.index), msg_ptr)
                    .build()
                    .user_data(user_data.raw());

            Ok(BuiltSend {
                entry,
                pool_slot: u16::MAX,
                slab_idx,
                total_len,
            })
        }
    }

    /// Build the SQE entry without pushing to the ring.
    /// Used by SendChainBuilder to collect multiple SQEs.
    #[allow(dead_code)]
    pub(crate) fn build_entry(mut self) -> io::Result<BuiltSend> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        if self.part_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty send builder",
            ));
        }

        // Validate connection + generation.
        let conn_state = self
            .ctx
            .connections
            .get(self.conn.index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "invalid connection"))?;
        if conn_state.generation != self.conn.generation {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stale connection",
            ));
        }

        if self.guard_count == 0 {
            self.build_copy_only()
        } else {
            self.build_with_guards()
        }
    }

    /// Copy-only path: gather all copy parts, submit or queue.
    fn submit_copy_only(mut self) -> io::Result<()> {
        let built = self.build_copy_only()?;
        self.ctx.submit_or_queue(self.conn.index, built)
    }

    /// Mixed copy+guard path: submit or queue.
    fn submit_with_guards(mut self) -> io::Result<()> {
        let built = self.build_with_guards()?;
        self.ctx.submit_or_queue(self.conn.index, built)
    }
}

/// Builder for submitting multiple SQEs as a linked IO_LINK chain.
///
/// Collects send operations (copy-only or scatter-gather) and submits them
/// as an atomic chain. The kernel executes linked SQEs sequentially. If any
/// SQE fails, subsequent linked SQEs are cancelled with -ECANCELED.
///
/// Created via [`DriverCtx::send_chain`].
pub struct SendChainBuilder<'b, 'a> {
    ctx: &'b mut DriverCtx<'a>,
    conn: ConnToken,
    built: Vec<BuiltSend>,
    total_bytes: u32,
    error: Option<io::Error>,
    finished: bool,
}

impl<'b, 'a> SendChainBuilder<'b, 'a> {
    /// Add a copy-only send to the chain.
    pub fn copy(mut self, data: &[u8]) -> Self {
        if self.error.is_some() {
            return self;
        }
        if self.built.len() >= self.ctx.max_chain_length as usize {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chain exceeds max_chain_length",
            ));
            return self;
        }

        let (slot, ptr, len) = match self.ctx.send_copy_pool.copy_in(data) {
            Some(v) => v,
            None => {
                self.error = Some(io::Error::other("send copy pool exhausted"));
                return self;
            }
        };

        let user_data = crate::completion::UserData::encode(
            crate::completion::OpTag::Send,
            self.conn.index,
            slot as u32,
        );
        let entry = io_uring::opcode::Send::new(io_uring::types::Fixed(self.conn.index), ptr, len)
            .build()
            .user_data(user_data.raw());

        self.total_bytes += data.len() as u32;
        self.built.push(BuiltSend {
            entry,
            pool_slot: slot,
            slab_idx: u16::MAX,
            total_len: data.len() as u32,
        });
        self
    }

    /// Begin a scatter-gather send within the chain.
    /// Returns a [`ChainPartsBuilder`] that collects copy + guard parts
    /// for a single SendMsgZc SQE.
    pub fn parts(self) -> ChainPartsBuilder<'b, 'a> {
        ChainPartsBuilder {
            chain: self,
            parts: [PartSlot::Empty; MAX_IOVECS],
            part_count: 0,
            copy_slices: [(std::ptr::null(), 0); MAX_IOVECS],
            copy_count: 0,
            total_copy_len: 0,
            guards: [None, None, None, None],
            guard_count: 0,
            total_len: 0,
        }
    }

    /// Finalize and submit the chain.
    ///
    /// All SQEs are linked with IO_LINK except the last. Registers chain
    /// state in the SendChainTable for CQE tracking.
    pub fn finish(mut self) -> io::Result<()> {
        self.finished = true;

        if let Some(e) = self.error.take() {
            self.release_all();
            return Err(e);
        }

        let count = self.built.len();
        if count == 0 {
            return Ok(());
        }

        let total_bytes = self.total_bytes;
        let conn_index = self.conn.index;

        if count == 1 {
            // Single SQE — no IO_LINK needed, but register chain state for
            // consistent CQE handling.
            let built = self.built.pop().unwrap();
            self.ctx.chain_table.start(conn_index, 1, total_bytes);
            unsafe {
                self.ctx.ring.push_sqe(built.entry)?;
            }
        } else {
            // Multiple SQEs — push as linked chain.
            let mut entries: Vec<io_uring::squeue::Entry> =
                self.built.drain(..).map(|b| b.entry).collect();
            self.ctx
                .chain_table
                .start(conn_index, count as u16, total_bytes);
            unsafe {
                self.ctx.ring.push_sqe_chain(&mut entries)?;
            }
        }

        Ok(())
    }

    /// Release all allocated resources (pool slots and slab entries).
    fn release_all(&mut self) {
        for built in self.built.drain(..) {
            if built.slab_idx != u16::MAX {
                let pool_slot = self.ctx.send_slab.release(built.slab_idx);
                if pool_slot != u16::MAX {
                    self.ctx.send_copy_pool.release(pool_slot);
                }
            } else if built.pool_slot != u16::MAX {
                self.ctx.send_copy_pool.release(built.pool_slot);
            }
        }
    }
}

impl Drop for SendChainBuilder<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            self.release_all();
        }
    }
}

/// Sub-builder for a scatter-gather SQE within a [`SendChainBuilder`] chain.
///
/// Created via [`SendChainBuilder::parts`]. Call `.copy()` and `.guard()`
/// to add parts, then `.add()` to finalize and return to the chain builder.
pub struct ChainPartsBuilder<'b, 'a> {
    chain: SendChainBuilder<'b, 'a>,
    parts: [PartSlot; MAX_IOVECS],
    part_count: u8,
    copy_slices: [(*const u8, usize); MAX_IOVECS],
    copy_count: u8,
    total_copy_len: usize,
    guards: [Option<GuardBox>; MAX_GUARDS],
    guard_count: u8,
    total_len: u32,
}

impl<'b, 'a> ChainPartsBuilder<'b, 'a> {
    /// Add a copy part to this scatter-gather SQE.
    pub fn copy(mut self, data: &[u8]) -> Self {
        if self.chain.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.chain.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 8)",
            ));
            return self;
        }
        let idx = self.copy_count;
        self.copy_slices[idx as usize] = (data.as_ptr(), data.len());
        self.copy_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Copy { slice_idx: idx };
        self.part_count += 1;
        self.total_len += data.len() as u32;
        self.total_copy_len += data.len();
        self
    }

    /// Add a zero-copy guard part to this scatter-gather SQE.
    pub fn guard(mut self, guard: GuardBox) -> Self {
        if self.chain.error.is_some() {
            return self;
        }
        if self.part_count as usize >= MAX_IOVECS {
            self.chain.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many send parts (max 8)",
            ));
            return self;
        }
        if self.guard_count as usize >= MAX_GUARDS {
            self.chain.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many guards (max 4)",
            ));
            return self;
        }
        let (_, len) = guard.as_ptr_len();
        let gidx = self.guard_count;
        self.guards[gidx as usize] = Some(guard);
        self.guard_count += 1;
        self.parts[self.part_count as usize] = PartSlot::Guard { guard_idx: gidx };
        self.part_count += 1;
        self.total_len += len;
        self
    }

    /// Finalize this scatter-gather SQE and add it to the chain.
    /// Returns the chain builder for further chaining.
    #[allow(clippy::needless_range_loop)]
    pub fn add(mut self) -> SendChainBuilder<'b, 'a> {
        if self.chain.error.is_some() || self.part_count == 0 {
            return self.chain;
        }

        if self.chain.built.len() >= self.chain.ctx.max_chain_length as usize {
            self.chain.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chain exceeds max_chain_length",
            ));
            return self.chain;
        }

        // Build the SQE using a temporary SendBuilder on the chain's context.
        let conn_index = self.chain.conn.index;

        let built = if self.guard_count == 0 {
            // Copy-only: gather into pool slot.
            let result = unsafe {
                self.chain.ctx.send_copy_pool.copy_in_gather(
                    &self.copy_slices[..self.copy_count as usize],
                    self.total_copy_len,
                )
            };
            match result {
                Some((slot, ptr, len)) => {
                    let user_data = crate::completion::UserData::encode(
                        crate::completion::OpTag::Send,
                        conn_index,
                        slot as u32,
                    );
                    let entry =
                        io_uring::opcode::Send::new(io_uring::types::Fixed(conn_index), ptr, len)
                            .build()
                            .user_data(user_data.raw());

                    BuiltSend {
                        entry,
                        pool_slot: slot,
                        slab_idx: u16::MAX,
                        total_len: self.total_len,
                    }
                }
                None => {
                    self.chain.error = Some(io::Error::other("send copy pool exhausted"));
                    return self.chain;
                }
            }
        } else {
            // With guards: allocate pool slot (if copy data) + slab entry.
            let slot_size = self.chain.ctx.send_copy_pool.slot_size() as usize;
            if self.total_copy_len > slot_size {
                self.chain.error = Some(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "total copy data exceeds send pool slot size",
                ));
                return self.chain;
            }

            if self.total_copy_len > 0 {
                let result = unsafe {
                    self.chain.ctx.send_copy_pool.copy_in_gather(
                        &self.copy_slices[..self.copy_count as usize],
                        self.total_copy_len,
                    )
                };
                match result {
                    Some((slot, pool_ptr, _)) => {
                        // Build iovecs with copy parts pointing into pool slot.
                        let mut iovecs = [libc::iovec {
                            iov_base: std::ptr::null_mut(),
                            iov_len: 0,
                        }; MAX_IOVECS];
                        let mut copy_offset: usize = 0;
                        for i in 0..self.part_count as usize {
                            match self.parts[i] {
                                PartSlot::Copy { slice_idx } => {
                                    let (_, src_len) = self.copy_slices[slice_idx as usize];
                                    iovecs[i] = libc::iovec {
                                        iov_base: pool_ptr.wrapping_add(copy_offset) as *mut _,
                                        iov_len: src_len,
                                    };
                                    copy_offset += src_len;
                                }
                                PartSlot::Guard { guard_idx } => {
                                    let g = self.guards[guard_idx as usize].as_ref().unwrap();
                                    let (gptr, glen) = g.as_ptr_len();
                                    iovecs[i] = libc::iovec {
                                        iov_base: gptr as *mut _,
                                        iov_len: glen as usize,
                                    };
                                }
                                PartSlot::Empty => {}
                            }
                        }

                        let iov_slice = &iovecs[..self.part_count as usize];
                        let total_len = self.total_len;
                        let guards = std::mem::take(&mut self.guards);
                        match self.chain.ctx.send_slab.allocate(
                            conn_index,
                            iov_slice,
                            slot,
                            guards,
                            self.guard_count,
                            total_len,
                        ) {
                            Some((slab_idx, msg_ptr)) => {
                                let user_data = crate::completion::UserData::encode(
                                    crate::completion::OpTag::SendMsgZc,
                                    conn_index,
                                    slab_idx as u32,
                                );
                                let entry = io_uring::opcode::SendMsgZc::new(
                                    io_uring::types::Fixed(conn_index),
                                    msg_ptr,
                                )
                                .build()
                                .user_data(user_data.raw());

                                BuiltSend {
                                    entry,
                                    pool_slot: slot,
                                    slab_idx,
                                    total_len,
                                }
                            }
                            None => {
                                self.chain.ctx.send_copy_pool.release(slot);
                                self.chain.error = Some(io::Error::other("send slab exhausted"));
                                return self.chain;
                            }
                        }
                    }
                    None => {
                        self.chain.error = Some(io::Error::other("send copy pool exhausted"));
                        return self.chain;
                    }
                }
            } else {
                // Guards only, no copy data.
                let mut iovecs = [libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                }; MAX_IOVECS];
                for i in 0..self.part_count as usize {
                    if let PartSlot::Guard { guard_idx } = self.parts[i] {
                        let g = self.guards[guard_idx as usize].as_ref().unwrap();
                        let (gptr, glen) = g.as_ptr_len();
                        iovecs[i] = libc::iovec {
                            iov_base: gptr as *mut _,
                            iov_len: glen as usize,
                        };
                    }
                }

                let iov_slice = &iovecs[..self.part_count as usize];
                let total_len = self.total_len;
                let guards = std::mem::take(&mut self.guards);
                match self.chain.ctx.send_slab.allocate(
                    conn_index,
                    iov_slice,
                    u16::MAX,
                    guards,
                    self.guard_count,
                    total_len,
                ) {
                    Some((slab_idx, msg_ptr)) => {
                        let user_data = crate::completion::UserData::encode(
                            crate::completion::OpTag::SendMsgZc,
                            conn_index,
                            slab_idx as u32,
                        );
                        let entry = io_uring::opcode::SendMsgZc::new(
                            io_uring::types::Fixed(conn_index),
                            msg_ptr,
                        )
                        .build()
                        .user_data(user_data.raw());

                        BuiltSend {
                            entry,
                            pool_slot: u16::MAX,
                            slab_idx,
                            total_len,
                        }
                    }
                    None => {
                        self.chain.error = Some(io::Error::other("send slab exhausted"));
                        return self.chain;
                    }
                }
            }
        };

        self.chain.total_bytes += built.total_len;
        self.chain.built.push(built);
        self.chain
    }
}
