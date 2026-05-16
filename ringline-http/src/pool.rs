//! Connection pool for HTTP clients.
//!
//! Fixed-size pool with round-robin dispatch and lazy reconnection.
//! Follows the `ringline-momento/src/pool.rs` pattern.

use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

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
    ///
    /// The returned [`PooledClient`] derefs to `&mut HttpClient` and, on
    /// drop, recycles its slot if the peer signalled close
    /// ([`HttpClient::peer_will_close`]). The next call to `client()`
    /// will lazily reconnect that slot.
    pub async fn client(&mut self) -> Result<PooledClient<'_>, HttpError> {
        let size = self.slots.len();
        for _ in 0..size {
            let idx = self.next;
            self.next = (self.next + 1) % size;

            match &self.slots[idx] {
                Slot::Connected(_) => {
                    return Ok(PooledClient { pool: self, idx });
                }
                Slot::Disconnected => {
                    if let Ok(client) = self.do_connect().await {
                        self.slots[idx] = Slot::Connected(Box::new(client));
                        return Ok(PooledClient { pool: self, idx });
                    }
                }
            }
        }
        Err(HttpError::AllConnectionsFailed)
    }

    /// Mark a slot as disconnected by index, closing the underlying connection.
    pub fn mark_disconnected(&mut self, idx: usize) {
        if idx < self.slots.len() {
            if let Slot::Connected(client) = &self.slots[idx] {
                client.close();
            }
            self.slots[idx] = Slot::Disconnected;
        }
    }

    /// Close all connections.
    pub fn close_all(&mut self) {
        for slot in &mut self.slots {
            if let Slot::Connected(client) = slot {
                client.close();
            }
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

/// A pool-owned handle to an [`HttpClient`].
///
/// Borrows the pool exclusively while alive; derefs to `&mut HttpClient`.
/// On drop, the guard inspects [`HttpClient::peer_will_close`] and
/// recycles its slot (closes the underlying connection and marks the
/// slot for lazy reconnect) when the peer has signalled close — avoiding
/// the request-smuggling-class hazard of sending a fresh request on a
/// connection the server is about to close.
pub struct PooledClient<'a> {
    pool: &'a mut Pool,
    idx: usize,
}

impl PooledClient<'_> {
    /// Index of the underlying slot in the pool. Useful for callers that
    /// want to explicitly recycle (e.g., on an application-level error
    /// the guard's `peer_will_close` check would not catch).
    pub fn slot(&self) -> usize {
        self.idx
    }
}

impl Deref for PooledClient<'_> {
    type Target = HttpClient;

    fn deref(&self) -> &HttpClient {
        match &self.pool.slots[self.idx] {
            Slot::Connected(client) => client,
            // `client()` only constructs `PooledClient` for a Connected
            // slot, and we hold &mut Pool exclusively for the guard's
            // lifetime, so the slot cannot transition under us.
            Slot::Disconnected => unreachable!("PooledClient over Disconnected slot"),
        }
    }
}

impl DerefMut for PooledClient<'_> {
    fn deref_mut(&mut self) -> &mut HttpClient {
        match &mut self.pool.slots[self.idx] {
            Slot::Connected(client) => client,
            Slot::Disconnected => unreachable!("PooledClient over Disconnected slot"),
        }
    }
}

impl Drop for PooledClient<'_> {
    fn drop(&mut self) {
        let should_recycle = match &self.pool.slots[self.idx] {
            Slot::Connected(client) => client.peer_will_close(),
            Slot::Disconnected => false,
        };
        if should_recycle {
            self.pool.mark_disconnected(self.idx);
        }
    }
}
