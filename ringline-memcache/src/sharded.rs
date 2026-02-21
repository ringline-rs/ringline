//! Ketama-sharded client for ringline-memcache.
//!
//! Routes commands to independent Memcache instances using consistent hashing
//! (ketama). Each server has a pool of connections with round-robin dispatch
//! and lazy reconnection.
//!
//! # Example
//!
//! ```no_run
//! use ringline_memcache::{ShardedClient, ShardedConfig};
//!
//! async fn example() -> Result<(), ringline_memcache::Error> {
//!     let config = ShardedConfig {
//!         servers: vec![
//!             "127.0.0.1:11211".parse().unwrap(),
//!             "127.0.0.1:11212".parse().unwrap(),
//!         ],
//!         pool_size: 2,
//!         connect_timeout_ms: 1000,
//!         tls_server_name: None,
//!     };
//!     let mut sharded = ShardedClient::new(config);
//!     sharded.connect_all().await?;
//!     sharded.set("hello", "world").await?;
//!     let val = sharded.get("hello").await?;
//!     assert_eq!(val.unwrap().data.as_ref(), b"world");
//!     sharded.close_all();
//!     Ok(())
//! }
//! ```

use std::net::SocketAddr;

use bytes::Bytes;
use protocol_memcache::Response as McResponse;

use crate::{Client, Error, GetValue, Value, check_error, encode_add, encode_request, encode_set};
use protocol_memcache::Request as McRequest;

/// Configuration for a ketama-sharded client.
pub struct ShardedConfig {
    /// List of independent Memcache server addresses.
    pub servers: Vec<SocketAddr>,
    /// Number of connections per server (default: 1).
    pub pool_size: usize,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub connect_timeout_ms: u64,
    /// TLS server name (SNI) for outbound connections. `None` means plain TCP.
    pub tls_server_name: Option<String>,
}

enum ShardConn {
    Connected(Client),
    Disconnected,
}

struct Shard {
    addr: SocketAddr,
    conns: Vec<ShardConn>,
    next: usize,
}

/// A ketama-sharded Memcache client.
///
/// Commands are routed to independent Memcache instances using consistent
/// hashing. Each server has a pool of connections with round-robin
/// dispatch and lazy reconnection.
pub struct ShardedClient {
    shards: Vec<Shard>,
    ring: ketama::Ring,
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
}

impl ShardedClient {
    /// Create a new sharded client. All connections start disconnected.
    pub fn new(config: ShardedConfig) -> Self {
        let pool_size = config.pool_size.max(1);

        let server_ids: Vec<String> = config.servers.iter().map(|a| a.to_string()).collect();
        let ring = ketama::Ring::build(&server_ids.iter().map(|s| s.as_str()).collect::<Vec<_>>());

        let shards = config
            .servers
            .iter()
            .map(|&addr| {
                let mut conns = Vec::with_capacity(pool_size);
                for _ in 0..pool_size {
                    conns.push(ShardConn::Disconnected);
                }
                Shard {
                    addr,
                    conns,
                    next: 0,
                }
            })
            .collect();

        Self {
            shards,
            ring,
            connect_timeout_ms: config.connect_timeout_ms,
            tls_server_name: config.tls_server_name,
        }
    }

    /// Eagerly connect all connections on all shards.
    pub async fn connect_all(&mut self) -> Result<(), Error> {
        let opts = self.connect_opts();
        for shard in &mut self.shards {
            for conn in &mut shard.conns {
                let client = do_connect(shard.addr, &opts).await?;
                *conn = ShardConn::Connected(client);
            }
        }
        Ok(())
    }

    /// Close all connections on all shards.
    pub fn close_all(&mut self) {
        for shard in &mut self.shards {
            for conn in &mut shard.conns {
                if let ShardConn::Connected(client) = conn {
                    client.conn().close();
                }
                *conn = ShardConn::Disconnected;
            }
        }
    }

    /// Number of shards (servers).
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn connect_opts(&self) -> ConnectOpts {
        ConnectOpts {
            connect_timeout_ms: self.connect_timeout_ms,
            tls_server_name: self.tls_server_name.clone(),
        }
    }

    /// Get a [`Client`] for a specific shard by index (for node-level commands).
    pub async fn shard_client(&mut self, index: usize) -> Result<Client, Error> {
        let opts = self.connect_opts();
        let shard = &mut self.shards[index];
        get_client(shard, &opts).await
    }

    // -- Core routing --------------------------------------------------------

    /// Route an encoded command to the shard owning `key`.
    async fn route_command(&mut self, key: &[u8], encoded: &[u8]) -> Result<McResponse, Error> {
        let opts = self.connect_opts();
        let shard_idx = self.ring.route(key);
        let shard = &mut self.shards[shard_idx];
        let size = shard.conns.len();

        for attempt in 0..size {
            let idx = (shard.next + attempt) % size;
            let client = match &shard.conns[idx] {
                ShardConn::Connected(c) => *c,
                ShardConn::Disconnected => match do_connect(shard.addr, &opts).await {
                    Ok(c) => {
                        shard.conns[idx] = ShardConn::Connected(c);
                        c
                    }
                    Err(_) => continue,
                },
            };

            client.conn().send(encoded)?;
            match client.read_response().await {
                Ok(response) => {
                    shard.next = (idx + 1) % size;
                    check_error(&response)?;
                    return Ok(response);
                }
                Err(Error::ConnectionClosed) => {
                    shard.conns[idx] = ShardConn::Disconnected;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Err(Error::AllConnectionsFailed)
    }

    /// Verify all keys route to the same shard. Returns the common shard index.
    fn require_same_shard(&self, keys: &[&[u8]]) -> Result<usize, Error> {
        let first = self.ring.route(keys[0]);
        for key in &keys[1..] {
            if self.ring.route(key) != first {
                return Err(Error::Memcache(
                    "keys in request don't route to the same shard".into(),
                ));
            }
        }
        Ok(first)
    }

    // -- Commands ------------------------------------------------------------

    /// Get the value of a key. Returns `None` on cache miss.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&protocol_memcache::Request::get(key));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Values(mut values) => {
                if values.is_empty() {
                    Ok(None)
                } else {
                    let v = values.swap_remove(0);
                    Ok(Some(Value {
                        data: Bytes::from(v.data),
                        flags: v.flags,
                    }))
                }
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get values for multiple keys. All keys must route to the same shard.
    /// Returns only hits, each with its key and CAS token.
    pub async fn gets(&mut self, keys: &[&[u8]]) -> Result<Vec<GetValue>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.require_same_shard(keys)?;
        let encoded = encode_request(&McRequest::gets(keys));
        let response = self.route_command(keys[0], &encoded).await?;
        match response {
            McResponse::Values(values) => Ok(values
                .into_iter()
                .map(|v| GetValue {
                    key: Bytes::from(v.key),
                    data: Bytes::from(v.data),
                    flags: v.flags,
                    cas: v.cas,
                })
                .collect()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Set a key-value pair with default flags (0) and no expiration.
    pub async fn set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        self.set_with_options(key, value, 0, 0).await
    }

    /// Set a key-value pair with custom flags and expiration time.
    pub async fn set_with_options(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_set(key, value, flags, exptime);
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Store a key only if it does not already exist (ADD command).
    /// Returns `true` if stored, `false` if the key already exists.
    pub async fn add(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_add(key, value);
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Store a key only if it already exists (REPLACE command).
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn replace(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::Replace {
            key,
            value,
            flags: 0,
            exptime: 0,
        });
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment a numeric value by delta. Returns the new value after incrementing.
    /// Returns `None` if the key does not exist.
    pub async fn incr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::incr(key, delta));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Decrement a numeric value by delta. Returns the new value after decrementing.
    /// Returns `None` if the key does not exist.
    pub async fn decr(&mut self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::decr(key, delta));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Append data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn append(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::append(key, value));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Prepend data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn prepend(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::prepend(key, value));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Compare-and-swap: store the value only if the CAS token matches.
    /// Returns `Ok(true)` if stored, `Ok(false)` if the CAS token didn't match (EXISTS),
    /// or `Err` if the key was not found or another error occurred.
    pub async fn cas(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        cas_unique: u64,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::cas(key, value, cas_unique));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::Exists => Ok(false),
            McResponse::NotFound => Err(Error::Memcache("NOT_FOUND".into())),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns `true` if deleted, `false` if not found.
    pub async fn delete(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::delete(key));
        let response = self.route_command(key, &encoded).await?;
        match response {
            McResponse::Deleted => Ok(true),
            McResponse::NotFound => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Flush all items on all shards.
    pub async fn flush_all(&mut self) -> Result<(), Error> {
        let opts = self.connect_opts();
        for shard in &mut self.shards {
            let client = get_client(shard, &opts).await?;
            client.flush_all().await?;
        }
        Ok(())
    }

    /// Get the version string from any connected shard.
    pub async fn version(&mut self) -> Result<String, Error> {
        let opts = self.connect_opts();
        for shard in &mut self.shards {
            if let Ok(client) = get_client(shard, &opts).await {
                return client.version().await;
            }
        }
        Err(Error::AllConnectionsFailed)
    }
}

/// Connection options cloned from config to avoid borrow conflicts.
#[derive(Clone)]
struct ConnectOpts {
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
}

/// Get a client from a shard, lazily reconnecting if needed.
async fn get_client(shard: &mut Shard, opts: &ConnectOpts) -> Result<Client, Error> {
    let size = shard.conns.len();
    for _ in 0..size {
        let idx = shard.next;
        shard.next = (shard.next + 1) % size;

        match &shard.conns[idx] {
            ShardConn::Connected(c) => return Ok(*c),
            ShardConn::Disconnected => {
                if let Ok(client) = do_connect(shard.addr, opts).await {
                    shard.conns[idx] = ShardConn::Connected(client);
                    return Ok(client);
                }
            }
        }
    }
    Err(Error::AllConnectionsFailed)
}

async fn do_connect(addr: SocketAddr, opts: &ConnectOpts) -> Result<Client, Error> {
    let conn = if let Some(ref sni) = opts.tls_server_name {
        let fut = if opts.connect_timeout_ms > 0 {
            ringline::connect_tls_with_timeout(addr, sni, opts.connect_timeout_ms)?
        } else {
            ringline::connect_tls(addr, sni)?
        };
        fut.await?
    } else {
        let fut = if opts.connect_timeout_ms > 0 {
            ringline::connect_with_timeout(addr, opts.connect_timeout_ms)?
        } else {
            ringline::connect(addr)?
        };
        fut.await?
    };

    Ok(Client::new(conn))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_server_always_routes_to_zero() {
        let config = ShardedConfig {
            servers: vec!["127.0.0.1:11211".parse().unwrap()],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);
        assert_eq!(client.ring.route(b"any-key"), 0);
        assert_eq!(client.ring.route(b"another-key"), 0);
        assert_eq!(client.ring.route(b""), 0);
    }

    #[test]
    fn test_deterministic_routing() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:11211".parse().unwrap(),
                "127.0.0.1:11212".parse().unwrap(),
                "127.0.0.1:11213".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);

        let a = client.ring.route(b"test-key");
        let b = client.ring.route(b"test-key");
        assert_eq!(a, b);

        let c = client.ring.route(b"other-key");
        let d = client.ring.route(b"other-key");
        assert_eq!(c, d);
    }

    #[test]
    fn test_config_defaults() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:11211".parse().unwrap(),
                "127.0.0.1:11212".parse().unwrap(),
            ],
            pool_size: 4,
            connect_timeout_ms: 500,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);
        assert_eq!(client.shard_count(), 2);
        assert_eq!(client.ring.node_count(), 2);
        assert_eq!(client.shards[0].conns.len(), 4);
        assert_eq!(client.shards[1].conns.len(), 4);
    }

    #[test]
    fn test_pool_size_minimum() {
        let config = ShardedConfig {
            servers: vec!["127.0.0.1:11211".parse().unwrap()],
            pool_size: 0,
            connect_timeout_ms: 0,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);
        assert_eq!(client.shards[0].conns.len(), 1);
    }

    #[test]
    fn test_require_same_shard_matching() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:11211".parse().unwrap(),
                "127.0.0.1:11212".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);
        let keys: &[&[u8]] = &[b"same-key", b"same-key"];
        assert!(client.require_same_shard(keys).is_ok());
    }

    #[test]
    fn test_require_same_shard_single_key() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:11211".parse().unwrap(),
                "127.0.0.1:11212".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
        };
        let client = ShardedClient::new(config);
        let keys: &[&[u8]] = &[b"anykey"];
        assert!(client.require_same_shard(keys).is_ok());
    }
}
