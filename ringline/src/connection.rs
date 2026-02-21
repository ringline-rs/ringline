/// Recv mode for a connection.
#[derive(Debug)]
pub enum RecvMode {
    /// Multishot recv armed with provided buffer ring.
    Multi,
    /// Multishot recvmsg armed with provided buffer ring (with cmsg for timestamps).
    #[cfg(feature = "timestamps")]
    MsgMulti,
    /// Connection is closing, no recv armed.
    Closed,
    /// Outbound connect SQE in-flight, no recv armed yet.
    Connecting,
}

/// Per-connection state tracked by the driver.
pub struct ConnectionState {
    /// Current recv mode.
    pub recv_mode: RecvMode,
    /// Whether the connection is active.
    pub active: bool,
    /// Generation counter to detect stale ConnTokens.
    pub generation: u32,
    /// Whether this is an outbound (connect) connection.
    pub outbound: bool,
    /// Whether the connection has been fully established (TCP+TLS handshake done).
    /// `on_close` is only fired when `established == true`.
    pub established: bool,
    /// Peer address (set on accept or connect).
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Whether a connect timeout SQE is armed for this connection.
    pub connect_timeout_armed: bool,
    /// Most recent kernel RX timestamp (nanoseconds since epoch, CLOCK_REALTIME).
    /// Set when a `RecvMsgMulti` completion delivers a `SCM_TIMESTAMPING` cmsg.
    #[cfg(feature = "timestamps")]
    pub recv_timestamp_ns: u64,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    pub fn new() -> Self {
        ConnectionState {
            recv_mode: RecvMode::Closed,
            active: false,
            generation: 0,
            outbound: false,
            established: false,
            peer_addr: None,
            connect_timeout_armed: false,
            #[cfg(feature = "timestamps")]
            recv_timestamp_ns: 0,
        }
    }

    pub fn activate(&mut self) {
        self.active = true;
        self.recv_mode = RecvMode::Multi;
    }

    /// Activate as an outbound (connect) connection.
    pub fn activate_outbound(&mut self) {
        self.active = true;
        self.outbound = true;
        self.established = false;
        self.recv_mode = RecvMode::Connecting;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
        self.recv_mode = RecvMode::Closed;
        self.outbound = false;
        self.established = false;
        self.peer_addr = None;
        self.connect_timeout_armed = false;
        #[cfg(feature = "timestamps")]
        {
            self.recv_timestamp_ns = 0;
        }
        self.generation = self.generation.wrapping_add(1);
    }
}

/// Manages connection slots with a free list for O(1) allocation.
pub struct ConnectionTable {
    slots: Vec<ConnectionState>,
    free_list: Vec<u32>,
}

impl ConnectionTable {
    pub fn new(max_connections: u32) -> Self {
        let mut slots = Vec::with_capacity(max_connections as usize);
        for _ in 0..max_connections {
            slots.push(ConnectionState::new());
        }
        // Free list: indices in reverse order so pop gives lowest first.
        let free_list: Vec<u32> = (0..max_connections).rev().collect();
        ConnectionTable { slots, free_list }
    }

    /// Allocate a connection slot. Returns the slot index.
    pub fn allocate(&mut self) -> Option<u32> {
        let idx = self.free_list.pop()?;
        self.slots[idx as usize].activate();
        Some(idx)
    }

    /// Allocate a connection slot for an outbound connection. Returns the slot index.
    pub fn allocate_outbound(&mut self) -> Option<u32> {
        let idx = self.free_list.pop()?;
        self.slots[idx as usize].activate_outbound();
        Some(idx)
    }

    /// Release a connection slot back to the free list.
    pub fn release(&mut self, idx: u32) {
        if (idx as usize) < self.slots.len() {
            if !self.slots[idx as usize].active {
                return; // Already released — avoid double-push to free list
            }
            self.slots[idx as usize].deactivate();
            self.free_list.push(idx);
        }
    }

    /// Get a reference to a connection's state.
    pub fn get(&self, idx: u32) -> Option<&ConnectionState> {
        self.slots.get(idx as usize).filter(|s| s.active)
    }

    /// Get a mutable reference to a connection's state.
    pub fn get_mut(&mut self, idx: u32) -> Option<&mut ConnectionState> {
        self.slots.get_mut(idx as usize).filter(|s| s.active)
    }

    /// Get a mutable reference without checking active status (for internal use).
    #[allow(dead_code)]
    pub fn get_mut_unchecked(&mut self, idx: u32) -> &mut ConnectionState {
        &mut self.slots[idx as usize]
    }

    /// Number of active connections.
    pub fn active_count(&self) -> usize {
        self.slots.len().saturating_sub(self.free_list.len())
    }

    /// Total number of connection slots (max_connections).
    pub fn max_slots(&self) -> u32 {
        self.slots.len() as u32
    }

    /// Get the generation for a slot (valid even if inactive).
    pub fn generation(&self, idx: u32) -> u32 {
        self.slots[idx as usize].generation
    }
}
