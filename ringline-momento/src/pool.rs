//! Connection pool for ringline-momento.
//!
//! `Pool` manages a fixed set of backend connections with round-robin dispatch
//! and lazy reconnection. Each connection is automatically authenticated on
//! (re)connect. It is single-threaded (no Arc, no Mutex) — designed for use
//! within a single ringline async worker.
//!
//! # Usage
//!
//! ```no_run
//! # use ringline_momento::{Pool, PoolConfig, Credential};
//! # async fn example() -> Result<(), ringline_momento::Error> {
//! let credential = Credential::from_env()?;
//! let config = PoolConfig {
//!     credential,
//!     pool_size: 4,
//!     connect_timeout_ms: 0,
//! };
//! let mut pool = Pool::new(config);
//! pool.connect_all().await?;
//! let mut client = pool.client().await?;
//! client.set("my-cache", b"key", b"value", 60_000).await?;
//! # Ok(())
//! # }
//! ```

use ringline::ConnCtx;

use crate::{Client, Credential, Error};

/// Configuration for a connection pool.
pub struct PoolConfig {
    /// Momento credential (contains endpoint + auth token).
    pub credential: Credential,
    /// Number of connections in the pool.
    pub pool_size: usize,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub connect_timeout_ms: u64,
}

enum Slot {
    Connected(Client),
    Disconnected,
}

/// A fixed-size connection pool with round-robin dispatch.
///
/// All slots start disconnected. Call [`connect_all()`](Pool::connect_all) for
/// eager startup, or let [`client()`](Pool::client) lazily reconnect on demand.
pub struct Pool {
    credential: Credential,
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
            credential: config.credential,
            slots,
            next: 0,
            connect_timeout_ms: config.connect_timeout_ms,
        }
    }

    /// Eagerly connect all slots. Returns an error if any connection fails.
    pub async fn connect_all(&mut self) -> Result<(), Error> {
        for i in 0..self.slots.len() {
            let client = self.do_connect().await?;
            self.slots[i] = Slot::Connected(client);
        }
        Ok(())
    }

    /// Get a [`Client`] bound to the next healthy connection.
    ///
    /// Advances the round-robin cursor and returns a client for a connected
    /// slot. Disconnected slots are lazily reconnected. If all slots fail,
    /// returns [`Error::AllConnectionsFailed`].
    pub async fn client(&mut self) -> Result<&mut Client, Error> {
        let size = self.slots.len();
        for _ in 0..size {
            let idx = self.next;
            self.next = (self.next + 1) % size;

            match &self.slots[idx] {
                Slot::Connected(_) => {
                    // Return a mutable reference to the existing client
                    if let Slot::Connected(client) = &mut self.slots[idx] {
                        return Ok(client);
                    }
                    unreachable!();
                }
                Slot::Disconnected => {
                    if let Ok(client) = self.do_connect().await {
                        self.slots[idx] = Slot::Connected(client);
                        if let Slot::Connected(client) = &mut self.slots[idx] {
                            return Ok(client);
                        }
                        unreachable!();
                    }
                }
            }
        }
        Err(Error::AllConnectionsFailed)
    }

    /// Mark a connection as dead after a `ConnectionClosed` error.
    pub fn mark_disconnected(&mut self, conn: ConnCtx) {
        let token = conn.token();
        for slot in &mut self.slots {
            if let Slot::Connected(client) = slot
                && client.conn().token() == token
            {
                client.conn().close();
                *slot = Slot::Disconnected;
                return;
            }
        }
    }

    /// Close all connections and reset slots to disconnected.
    pub fn close_all(&mut self) {
        for slot in &mut self.slots {
            if let Slot::Connected(client) = slot {
                client.conn().close();
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

    async fn do_connect(&self) -> Result<Client, Error> {
        if self.connect_timeout_ms > 0 {
            Client::connect_with_timeout(&self.credential, self.connect_timeout_ms).await
        } else {
            Client::connect(&self.credential).await
        }
    }
}
