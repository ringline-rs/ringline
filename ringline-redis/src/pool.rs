//! Connection pool for ringline-redis.
//!
//! `Pool` manages a fixed set of backend connections with round-robin dispatch
//! and lazy reconnection. It is single-threaded (no Arc, no Mutex) — designed
//! for use within a single ringline async worker.
//!
//! # Usage
//!
//! ```no_run
//! # use std::net::SocketAddr;
//! # use ringline_redis::{Pool, PoolConfig};
//! # async fn example() -> Result<(), ringline_redis::Error> {
//! let config = PoolConfig {
//!     addr: "127.0.0.1:6379".parse().unwrap(),
//!     pool_size: 4,
//!     connect_timeout_ms: 0,
//!     tls_server_name: None,
//!     password: None,
//!     username: None,
//! };
//! let mut pool = Pool::new(config);
//! pool.connect_all().await?;
//! pool.client().await?.set("k", "v").await?;
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;

use ringline::ConnCtx;

use crate::{Client, Error, Pipeline};

/// Configuration for a connection pool.
pub struct PoolConfig {
    /// Backend address to connect to.
    pub addr: SocketAddr,
    /// Number of connections in the pool.
    pub pool_size: usize,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub connect_timeout_ms: u64,
    /// TLS server name (SNI) for outbound connections. `None` means plain TCP.
    pub tls_server_name: Option<String>,
    /// Password for AUTH after connect. `None` skips authentication.
    pub password: Option<String>,
    /// Username for ACL-based AUTH (Redis 6.0+). Only used when `password` is set.
    pub username: Option<String>,
}

enum Slot {
    Connected(ConnCtx),
    Disconnected,
}

/// A fixed-size connection pool with round-robin dispatch.
///
/// All slots start disconnected. Call [`connect_all()`](Pool::connect_all) for
/// eager startup, or let [`client()`](Pool::client) lazily reconnect on demand.
pub struct Pool {
    addr: SocketAddr,
    slots: Vec<Slot>,
    next: usize,
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
    password: Option<String>,
    username: Option<String>,
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
            slots,
            next: 0,
            connect_timeout_ms: config.connect_timeout_ms,
            tls_server_name: config.tls_server_name,
            password: config.password,
            username: config.username,
        }
    }

    /// Eagerly connect all slots. Returns an error if any connection fails.
    pub async fn connect_all(&mut self) -> Result<(), Error> {
        for i in 0..self.slots.len() {
            let conn = self.do_connect().await?;
            self.slots[i] = Slot::Connected(conn);
        }
        Ok(())
    }

    /// Get a [`Client`] bound to the next healthy connection.
    ///
    /// Advances the round-robin cursor and returns a client for a connected
    /// slot. Disconnected slots are lazily reconnected. If all slots fail,
    /// returns [`Error::AllConnectionsFailed`].
    pub async fn client(&mut self) -> Result<Client, Error> {
        let size = self.slots.len();
        for _ in 0..size {
            let idx = self.next;
            self.next = (self.next + 1) % size;

            match &self.slots[idx] {
                Slot::Connected(conn) => return Ok(Client::new(*conn)),
                Slot::Disconnected => {
                    if let Ok(conn) = self.do_connect().await {
                        self.slots[idx] = Slot::Connected(conn);
                        return Ok(Client::new(conn));
                    }
                }
            }
        }
        Err(Error::AllConnectionsFailed)
    }

    /// Get a [`Pipeline`] on the next healthy connection.
    pub async fn pipeline(&mut self) -> Result<Pipeline, Error> {
        let client = self.client().await?;
        Ok(client.pipeline())
    }

    /// Mark a connection as dead after a `ConnectionClosed` error.
    ///
    /// Matches by [`ConnCtx::token()`] and sets the slot to disconnected.
    /// The next [`client()`](Pool::client) call will lazily reconnect.
    pub fn mark_disconnected(&mut self, client: Client) {
        let token = client.conn().token();
        for slot in &mut self.slots {
            if let Slot::Connected(conn) = slot
                && conn.token() == token
            {
                conn.close();
                *slot = Slot::Disconnected;
                return;
            }
        }
    }

    /// Close all connections and reset slots to disconnected.
    pub fn close_all(&mut self) {
        for slot in &mut self.slots {
            if let Slot::Connected(conn) = slot {
                conn.close();
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

    async fn do_connect(&self) -> Result<ConnCtx, Error> {
        let conn = if let Some(sni) = &self.tls_server_name {
            let fut = if self.connect_timeout_ms > 0 {
                ringline::connect_tls_with_timeout(self.addr, sni, self.connect_timeout_ms)?
            } else {
                ringline::connect_tls(self.addr, sni)?
            };
            fut.await?
        } else {
            let fut = if self.connect_timeout_ms > 0 {
                ringline::connect_with_timeout(self.addr, self.connect_timeout_ms)?
            } else {
                ringline::connect(self.addr)?
            };
            fut.await?
        };

        Client::new(conn)
            .maybe_auth(self.password.as_deref(), self.username.as_deref())
            .await?;

        Ok(conn)
    }
}
