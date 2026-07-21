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

#[cfg(has_io_uring)]
use crate::ValueStream;
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
    /// The ephemeral [`Client`] backing a live streaming [`get_stream`](Pool::get_stream).
    ///
    /// A [`ValueStream`] borrows `&mut Client`, so the client it borrows must
    /// outlive the stream and live at a stable address — it is parked here for
    /// the stream's lifetime (the returned stream borrows `&mut self` through
    /// this field, blocking all other pool use until it is dropped).
    #[cfg(has_io_uring)]
    stream_client: Option<Client>,
    /// Index of the slot whose connection is/was lent to a streaming
    /// `get_stream`, pending a health re-check on the next checkout. See
    /// [`reconcile_stream_slot`](Pool::reconcile_stream_slot).
    #[cfg(has_io_uring)]
    stream_slot: Option<usize>,
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
            #[cfg(has_io_uring)]
            stream_client: None,
            #[cfg(has_io_uring)]
            stream_slot: None,
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
        self.reconcile_stream_slot();
        let (_idx, conn) = self.checkout().await?;
        Ok(Client::new(conn))
    }

    /// Select the next healthy slot (round-robin, lazily reconnecting a
    /// disconnected one) and return its index plus connection handle.
    ///
    /// Shared by [`client`](Pool::client) and
    /// [`get_stream`](Pool::get_stream); the latter needs the slot index to
    /// re-check the connection's health after the stream ends.
    async fn checkout(&mut self) -> Result<(usize, ConnCtx), Error> {
        let size = self.slots.len();
        for _ in 0..size {
            let idx = self.next;
            self.next = (self.next + 1) % size;

            match &self.slots[idx] {
                Slot::Connected(conn) => return Ok((idx, *conn)),
                Slot::Disconnected => {
                    if let Ok(conn) = self.do_connect().await {
                        self.slots[idx] = Slot::Connected(conn);
                        return Ok((idx, conn));
                    }
                }
            }
        }
        Err(Error::AllConnectionsFailed)
    }

    /// Re-check the health of a slot that was lent to a streaming
    /// [`get_stream`](Pool::get_stream) and evict it if the stream poisoned it.
    ///
    /// A [`ValueStream`] dropped mid-value calls `close()` on its connection
    /// (poison), which flips the slot's `recv_mode` to `Closed` synchronously —
    /// so [`ConnCtx::is_alive`](ringline::ConnCtx::is_alive) reports it dead on
    /// the very next turn, before the Close CQE has even bumped the generation.
    /// A cleanly drained stream (`collect`/`discard`/`next_segment`-to-end, or a
    /// nil reply) restores the default read path and leaves the connection
    /// alive.
    ///
    /// Called at the top of every checkout path so a poisoned connection is
    /// marked [`Disconnected`](Slot::Disconnected) — forcing a reconnect on its
    /// next use — and is **never handed back out desynced**. On a healthy stream
    /// the slot stays `Connected` and is reused with no reconnect.
    #[cfg(has_io_uring)]
    fn reconcile_stream_slot(&mut self) {
        let Some(idx) = self.stream_slot.take() else {
            return;
        };
        // Drop the parked streaming client (its `ConnCtx` is a cheap `Copy`; the
        // underlying connection lives in the driver, untouched by this).
        self.stream_client = None;
        if let Slot::Connected(conn) = &self.slots[idx]
            && !conn.is_alive()
        {
            // Poisoned by an undrained-stream drop — evict so the next checkout
            // reconnects rather than reusing a closed/desynced connection. The
            // stream's own `close()` already tore the connection down; do not
            // close again here.
            self.slots[idx] = Slot::Disconnected;
        }
    }

    #[cfg(not(has_io_uring))]
    #[inline]
    fn reconcile_stream_slot(&mut self) {}

    /// Get a [`Pipeline`] on the next healthy connection.
    pub async fn pipeline(&mut self) -> Result<Pipeline, Error> {
        let client = self.client().await?;
        Ok(client.pipeline())
    }

    /// Streaming GET on the next healthy pooled connection (io_uring only).
    ///
    /// Like [`Client::get_stream`], but routed onto a pooled connection. The
    /// returned [`ValueStream`] borrows `&mut self`, so the pool is held
    /// **exclusively** for the stream's whole lifetime — no other pool operation
    /// can run concurrently (a compile error), which is what keeps the streamed
    /// connection from being handed to a second caller mid-read.
    ///
    /// Returns `Ok(None)` for a missing key.
    ///
    /// # Poison eviction (why this is sound to pool)
    ///
    /// Dropping the [`ValueStream`] before its value is fully drained poisons
    /// the underlying connection (`close()`), exactly as on a single-connection
    /// [`Client`]. Because the borrow ties the stream to `&mut self`, the pool
    /// re-checks that connection's health on the **next** checkout
    /// ([`reconcile_stream_slot`](Pool::reconcile_stream_slot)): a poisoned
    /// connection is evicted and lazily reconnected, so a desynced connection is
    /// never returned to the pool for reuse. A fully drained stream
    /// (`collect`/`discard`/`next_segment`-to-end) leaves the connection healthy
    /// and it is reused with no reconnect.
    ///
    /// # Scope
    ///
    /// v1 offers pooled streaming on [`Pool`] only. `ShardedClient` streaming is
    /// a documented follow-up (the same borrow/eviction shape, per shard);
    /// `ClusterClient` streaming stays out of scope — a MOVED/ASK redirect
    /// requires re-issuing the read on another node mid-stream, which the
    /// length-bounded single-connection stream cannot express.
    #[cfg(has_io_uring)]
    pub async fn get_stream(
        &mut self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<ValueStream<'_>>, Error> {
        self.reconcile_stream_slot();
        let (idx, conn) = self.checkout().await?;
        // Park an ephemeral client at a stable address so the returned
        // `ValueStream` (which borrows `&mut Client`) can borrow through it for
        // its whole lifetime; record the slot so the next checkout can re-check
        // this connection's health and evict it if the stream poisoned it.
        self.stream_slot = Some(idx);
        self.stream_client = Some(Client::new(conn));
        let client = self.stream_client.as_mut().expect("just set");
        client.get_stream(key).await
    }

    /// Mark a connection as dead after a `ConnectionClosed` error.
    ///
    /// Matches by [`ConnCtx::token()`] and sets the slot to disconnected.
    /// The next [`client()`](Pool::client) call will lazily reconnect.
    pub fn mark_disconnected(&mut self, conn: ConnCtx) {
        let token = conn.token();
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
