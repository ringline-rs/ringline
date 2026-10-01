//! Connection pool for ringline-ping.
//!
//! `Pool` manages a fixed set of backend connections with round-robin dispatch
//! and lazy reconnection. It is single-threaded (no Arc, no Mutex) — designed
//! for use within a single ringline async worker.
//!
//! # Usage
//!
//! ```no_run
//! # use std::net::SocketAddr;
//! # use ringline_ping::{Pool, PoolConfig};
//! # async fn example() -> Result<(), ringline_ping::Error> {
//! let config = PoolConfig::new("127.0.0.1:6379".parse().unwrap(), 4);
//! let pool = Pool::new(config);
//! pool.connect_all().await?;
//! pool.client().await?.ping().await?;
//! # Ok(())
//! # }
//! ```

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::Rc;

use ringline::ConnCtx;

use crate::{Client, Error};

/// Configuration for a connection pool.
pub struct PoolConfig {
    /// Backend address to connect to.
    pub(crate) addr: SocketAddr,
    /// Number of connections in the pool.
    pub(crate) pool_size: usize,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub(crate) connect_timeout_ms: u64,
    /// TLS server name (SNI) for outbound connections. `None` means plain TCP.
    /// Requires a client configuration from `ConfigBuilder::tls_client`.
    pub(crate) tls_server_name: Option<String>,
}

impl PoolConfig {
    /// Create a pool config for `pool_size` connections to `addr`.
    /// Defaults: no connect timeout, plain TCP (no TLS).
    pub fn new(addr: SocketAddr, pool_size: usize) -> Self {
        Self {
            addr,
            pool_size,
            connect_timeout_ms: 0,
            tls_server_name: None,
        }
    }

    /// Set the connect timeout in milliseconds. `0` (the default) disables it.
    pub fn connect_timeout_ms(mut self, ms: u64) -> Self {
        self.connect_timeout_ms = ms;
        self
    }

    /// Set the TLS server name (SNI) for outbound connections; enables TLS.
    pub fn tls_server_name(mut self, name: impl Into<String>) -> Self {
        self.tls_server_name = Some(name.into());
        self
    }
}

enum Slot {
    /// Idle in the pool. Each slot owns its client, so a connection is split
    /// once, when it is opened, rather than on every checkout (#528).
    ///
    /// Boxed so the enum stays pointer-sized and the client has a stable
    /// address.
    Connected(Box<Client>),
    /// Checked out, or reserved while a connect for this slot is in flight.
    ///
    /// A [`PooledClient`] holds the client and returns it here when dropped.
    /// The reservation uses the same state so a second caller does not connect
    /// a slot that is already being connected.
    Lent,
    Disconnected,
}

/// Slot table shared between the pool and the clients checked out of it.
///
/// Held by the pool and by each checked-out client through an `Rc`, so a
/// checked-out client does not borrow the pool. Single-threaded: the connection
/// halves are `!Send`.
struct Shared {
    slots: RefCell<Vec<Slot>>,
    next: Cell<usize>,
}

/// Holds a slot reserved as [`Lent`](Slot::Lent) across a connect.
///
/// Releases the slot back to [`Disconnected`](Slot::Disconnected) when dropped
/// unless disarmed, so a `client()` or `connect_all()` future that is cancelled
/// mid-connect — by [`timeout`](ringline::timeout), or by its task being
/// dropped at teardown — does not leave the slot reserved forever. Restoring
/// only on the error path would make cancellation permanently shrink the pool.
struct Reservation<'a> {
    shared: &'a Shared,
    idx: usize,
    armed: bool,
}

impl Reservation<'_> {
    /// Keep the reservation: the caller is storing something in the slot.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // `try_borrow_mut` for the same reason as `PooledClient::drop`: a panic
        // in `Drop` while unwinding would abort.
        if let Ok(mut slots) = self.shared.slots.try_borrow_mut() {
            slots[self.idx] = Slot::Disconnected;
        }
    }
}

/// A client checked out of a [`Pool`].
///
/// Derefs to [`Client`]. On drop the client returns to its slot if the
/// connection is still alive; if it is not, the slot is marked disconnected and
/// reconnects on its next checkout.
///
/// To evict a connection the pool should stop reusing — after a protocol error,
/// where the socket is still open but the response stream no longer matches
/// the requests sent — call
/// [`Client::close`] on it before dropping the guard.
///
/// A guard that is never dropped leaves its slot checked out permanently, and
/// the pool has one fewer connection to hand out.
///
/// If the guard is dropped outside the executor, for example when its task is
/// dropped at connection teardown, the slot is marked disconnected and the
/// connection is not closed.
pub struct PooledClient {
    client: Option<Box<Client>>,
    idx: usize,
    shared: Rc<Shared>,
}

impl std::ops::Deref for PooledClient {
    type Target = Client;
    fn deref(&self) -> &Client {
        self.client.as_ref().expect("client is taken only in Drop")
    }
}

impl std::ops::DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut Client {
        self.client.as_mut().expect("client is taken only in Drop")
    }
}

impl Drop for PooledClient {
    fn drop(&mut self) {
        let Some(mut client) = self.client.take() else {
            return;
        };
        // Dropping a `Client` releases the connection's claim but does not
        // close the socket, so any path that does not return the client to a
        // slot must close it or the socket and driver slot leak.
        //
        // `is_alive()` gates each close below. It is false once the connection
        // is closing or its slot has been released, and outside the executor;
        // `close` does nothing in each of those cases, so the gate only skips
        // a redundant call.

        let alive = client.is_alive();

        // The pool is gone and this is the last handle on the table, so there
        // is nobody to hand the client back to.
        if Rc::strong_count(&self.shared) == 1 {
            if alive {
                client.close();
            }
            return;
        }

        // `try_borrow_mut` rather than `borrow_mut`: no current path drops a
        // guard while the table is borrowed, so the failure arm is unreachable,
        // but a panic in `Drop` while unwinding would abort.
        match self.shared.slots.try_borrow_mut() {
            Ok(mut slots) => {
                slots[self.idx] = if alive {
                    Slot::Connected(client)
                } else {
                    Slot::Disconnected
                };
            }
            Err(_) => {
                if alive {
                    client.close();
                }
            }
        }
    }
}

/// A fixed-size connection pool with round-robin dispatch.
///
/// All slots start disconnected. Call [`connect_all()`](Pool::connect_all) for
/// eager startup, or let [`client()`](Pool::client) lazily reconnect on demand.
pub struct Pool {
    addr: SocketAddr,
    shared: Rc<Shared>,
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
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
            shared: Rc::new(Shared {
                slots: RefCell::new(slots),
                next: Cell::new(0),
            }),
            connect_timeout_ms: config.connect_timeout_ms,
            tls_server_name: config.tls_server_name,
        }
    }

    /// Connect every slot that is disconnected.
    ///
    /// Slots that are connected or checked out are left as they are, so this
    /// can be called again, or while clients are checked out. Returns the
    /// first connect error; slots connected before it stay connected.
    pub async fn connect_all(&self) -> Result<(), Error> {
        for i in 0..self.len() {
            // Reserve before awaiting, for the reason `client()` does: the
            // check would otherwise be stale by the time of the write, and a
            // concurrent checkout could connect the same slot. The loser's
            // client would then be displaced and dropped, and dropping a
            // `Client` does not close its connection, so the socket and the
            // driver slot would leak.
            {
                let mut slots = self.shared.slots.borrow_mut();
                if !matches!(slots[i], Slot::Disconnected) {
                    continue;
                }
                slots[i] = Slot::Lent;
            }
            let mut reservation = Reservation {
                shared: &self.shared,
                idx: i,
                armed: true,
            };
            // On `Err` or cancellation the reservation releases the slot.
            let client = self.do_connect().await?;
            reservation.disarm();
            self.shared.slots.borrow_mut()[i] = Slot::Connected(Box::new(client));
        }
        Ok(())
    }

    /// Number of slots, connected or not.
    fn len(&self) -> usize {
        self.shared.slots.borrow().len()
    }

    /// Get a [`Client`] bound to the next healthy connection.
    ///
    /// Advances the round-robin cursor and returns a guard for a connected
    /// slot. Disconnected slots are reconnected on demand; slots already
    /// checked out are skipped. Returns [`Error::PoolExhausted`] if every slot
    /// is checked out, and [`Error::AllConnectionsFailed`] if no slot could be
    /// connected.
    ///
    /// The client is moved out of its slot and the slot is marked lent, so the
    /// returned [`PooledClient`] does not borrow the pool and several may be
    /// held at once.
    pub async fn client(&self) -> Result<PooledClient, Error> {
        let size = self.len();
        if size == 0 {
            return Err(Error::PoolExhausted);
        }
        // The cursor is read once, and the scan steps from that snapshot. A
        // concurrent caller advances the cursor across this task's `await`, so
        // re-reading it each iteration can move this scan past a slot it has
        // not visited yet and revisit another, which can report
        // `AllConnectionsFailed` while a usable slot exists. Stepping from a
        // snapshot visits every index exactly once.
        let start = self.shared.next.get();
        self.shared.next.set((start + 1) % size);
        // Distinguishes "every slot is checked out" from "every connect failed".
        let mut attempted = false;
        for step in 0..size {
            let idx = (start + step) % size;

            // One match decides all three cases, and `mem::replace` performs
            // the reservation: the slot is `Lent` from here until either the
            // guard returns it or the `Reservation` releases it. Reserving
            // before the await is what stops a concurrent caller connecting
            // the same slot and having its client displaced and dropped —
            // dropping a `Client` does not close its connection.
            enum Next {
                Ready(Box<Client>),
                Connect,
                Skip,
            }
            let next = {
                let mut slots = self.shared.slots.borrow_mut();
                match std::mem::replace(&mut slots[idx], Slot::Lent) {
                    Slot::Connected(client) => Next::Ready(client),
                    // Already out: put it back and move on.
                    Slot::Lent => {
                        slots[idx] = Slot::Lent;
                        Next::Skip
                    }
                    // Left reserved by the replace above.
                    Slot::Disconnected => Next::Connect,
                }
            };
            let client = match next {
                Next::Ready(client) => client,
                Next::Skip => continue,
                Next::Connect => {
                    let mut reservation = Reservation {
                        shared: &self.shared,
                        idx,
                        armed: true,
                    };
                    // On failure or cancellation the reservation releases it.
                    match self.do_connect().await {
                        Ok(client) => {
                            reservation.disarm();
                            Box::new(client)
                        }
                        Err(_) => {
                            attempted = true;
                            continue;
                        }
                    }
                }
            };
            return Ok(PooledClient {
                client: Some(client),
                idx,
                shared: Rc::clone(&self.shared),
            });
        }
        if attempted {
            Err(Error::AllConnectionsFailed)
        } else {
            Err(Error::PoolExhausted)
        }
    }

    /// Mark a connection as dead after a `ConnectionClosed` error.
    ///
    /// Matches by [`ConnCtx::token()`] and sets the slot to disconnected.
    /// A connection that is currently checked out is not matched; call
    /// [`Client::close`] on its guard instead.
    /// The next [`client()`](Pool::client) call will lazily reconnect.
    pub fn mark_disconnected(&self, conn: ConnCtx) {
        let token = conn.token();
        for slot in self.shared.slots.borrow_mut().iter_mut() {
            if let Slot::Connected(conn) = slot
                && conn.token() == token
            {
                conn.close();
                *slot = Slot::Disconnected;
                return;
            }
        }
    }

    /// Close all idle connections and reset their slots to disconnected.
    ///
    /// A connection currently checked out is not closed here: its
    /// [`PooledClient`] owns it, and dropping that returns it to a slot this
    /// call has already reset. Drop the checked-out clients first if the intent
    /// is to close every connection.
    pub fn close_all(&self) {
        for slot in self.shared.slots.borrow_mut().iter_mut() {
            // `is_alive()` for the reason given in `PooledClient::drop`.
            if let Slot::Connected(conn) = slot
                && conn.is_alive()
            {
                conn.close();
            }
            *slot = Slot::Disconnected;
        }
    }

    /// Number of slots holding an idle connection. Does not count connections
    /// currently checked out; see [`lent_count`](Pool::lent_count).
    pub fn connected_count(&self) -> usize {
        self.shared
            .slots
            .borrow()
            .iter()
            .filter(|s| matches!(s, Slot::Connected(_)))
            .count()
    }

    /// Number of connections currently checked out.
    pub fn lent_count(&self) -> usize {
        self.shared
            .slots
            .borrow()
            .iter()
            .filter(|s| matches!(s, Slot::Lent))
            .count()
    }

    /// Total number of slots in the pool, connected or not.
    pub fn pool_size(&self) -> usize {
        self.len()
    }

    async fn do_connect(&self) -> Result<Client, Error> {
        // TLS and the timeout are set on the builder (#528).
        let mut connect = ringline::connect(self.addr);
        if let Some(sni) = &self.tls_server_name {
            connect = connect.tls(sni.as_str());
        }
        if self.connect_timeout_ms > 0 {
            connect = connect.timeout(std::time::Duration::from_millis(self.connect_timeout_ms));
        }
        let conn = connect.await?;
        Ok(Client::new(conn))
    }
}
