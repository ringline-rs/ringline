//! Connection pool for HTTP clients.
//!
//! Fixed-size pool with round-robin dispatch and lazy reconnection.
//! Follows the `ringline-momento/src/pool.rs` pattern.

use std::net::SocketAddr;

use crate::client::HttpClient;
use crate::error::HttpError;

/// Configuration for an HTTP connection pool.
pub struct PoolConfig {
    /// Server address to connect to.
    pub addr: SocketAddr,
    /// Host name (for TLS SNI and Host header).
    pub host: String,
    /// Number of connections in the pool.
    pub pool_size: usize,
    /// Protocol to use.
    pub protocol: Protocol,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub connect_timeout_ms: u64,
}

/// Which HTTP protocol to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP/2 over TLS.
    H2,
    /// HTTP/1.1 over TLS.
    H1,
    /// HTTP/1.1 over plaintext TCP.
    H1Plain,
}

enum Slot {
    Connected(Box<HttpClient>),
    Disconnected,
}

/// A fixed-size HTTP connection pool with round-robin dispatch.
pub struct Pool {
    addr: SocketAddr,
    host: String,
    protocol: Protocol,
    slots: Vec<Slot>,
    next: usize,
    connect_timeout_ms: u64,
}

impl Pool {
    /// Create a new pool. All slots start disconnected.
    pub fn new(config: PoolConfig) -> Self {
        let mut slots = Vec::with_capacity(config.pool_size);
        for _ in 0..config.pool_size {
            slots.push(Slot::Disconnected);
        }
        Pool {
            addr: config.addr,
            host: config.host,
            protocol: config.protocol,
            slots,
            next: 0,
            connect_timeout_ms: config.connect_timeout_ms,
        }
    }

    /// Eagerly connect all slots.
    pub async fn connect_all(&mut self) -> Result<(), HttpError> {
        for i in 0..self.slots.len() {
            let client = self.do_connect().await?;
            self.slots[i] = Slot::Connected(Box::new(client));
        }
        Ok(())
    }

    /// Get a client bound to the next healthy connection.
    ///
    /// Advances the round-robin cursor. Disconnected slots are lazily
    /// reconnected. Returns [`HttpError::AllConnectionsFailed`] if all
    /// slots fail.
    pub async fn client(&mut self) -> Result<&mut HttpClient, HttpError> {
        let size = self.slots.len();
        for _ in 0..size {
            let idx = self.next;
            self.next = (self.next + 1) % size;

            match &self.slots[idx] {
                Slot::Connected(_) => {
                    if let Slot::Connected(client) = &mut self.slots[idx] {
                        return Ok(client);
                    }
                    unreachable!();
                }
                Slot::Disconnected => {
                    if let Ok(client) = self.do_connect().await {
                        self.slots[idx] = Slot::Connected(Box::new(client));
                        if let Slot::Connected(client) = &mut self.slots[idx] {
                            return Ok(client);
                        }
                        unreachable!();
                    }
                }
            }
        }
        Err(HttpError::AllConnectionsFailed)
    }

    /// Mark a slot as disconnected by index.
    pub fn mark_disconnected(&mut self, idx: usize) {
        if idx < self.slots.len() {
            self.slots[idx] = Slot::Disconnected;
        }
    }

    /// Close all connections.
    pub fn close_all(&mut self) {
        for slot in &mut self.slots {
            *slot = Slot::Disconnected;
        }
    }

    /// Number of currently connected slots.
    pub fn connected_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, Slot::Connected(_)))
            .count()
    }

    /// Total number of slots in the pool.
    pub fn pool_size(&self) -> usize {
        self.slots.len()
    }

    async fn do_connect(&self) -> Result<HttpClient, HttpError> {
        match self.protocol {
            Protocol::H2 => {
                if self.connect_timeout_ms > 0 {
                    HttpClient::connect_h2_with_timeout(
                        self.addr,
                        &self.host,
                        self.connect_timeout_ms,
                    )
                    .await
                } else {
                    HttpClient::connect_h2(self.addr, &self.host).await
                }
            }
            Protocol::H1 => HttpClient::connect_h1(self.addr, &self.host).await,
            Protocol::H1Plain => HttpClient::connect_h1_plain(self.addr, &self.host).await,
        }
    }
}
