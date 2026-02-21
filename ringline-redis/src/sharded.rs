//! Ketama-sharded client for ringline-redis.
//!
//! Routes commands to independent Redis instances using consistent hashing
//! (ketama). Unlike [`ClusterClient`](crate::ClusterClient), which relies on
//! server-side slot management, `ShardedClient` performs client-side sharding
//! across standalone Redis servers.
//!
//! # Example
//!
//! ```no_run
//! use ringline_redis::{ShardedClient, ShardedConfig};
//!
//! async fn example() -> Result<(), ringline_redis::Error> {
//!     let config = ShardedConfig {
//!         servers: vec![
//!             "127.0.0.1:6379".parse().unwrap(),
//!             "127.0.0.1:6380".parse().unwrap(),
//!         ],
//!         pool_size: 2,
//!         connect_timeout_ms: 1000,
//!         tls_server_name: None,
//!         password: None,
//!         username: None,
//!     };
//!     let mut sharded = ShardedClient::new(config);
//!     sharded.connect_all().await?;
//!     sharded.set("hello", "world").await?;
//!     let val = sharded.get("hello").await?;
//!     assert_eq!(val.as_deref(), Some(&b"world"[..]));
//!     sharded.close_all();
//!     Ok(())
//! }
//! ```

use std::net::SocketAddr;

use bytes::Bytes;
use resp_proto::{Request, Value};

use crate::{Client, Error, parse_bytes_array};

/// Configuration for a ketama-sharded client.
pub struct ShardedConfig {
    /// List of independent Redis server addresses.
    pub servers: Vec<SocketAddr>,
    /// Number of connections per server (default: 1).
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

enum ShardConn {
    Connected(Client),
    Disconnected,
}

struct Shard {
    addr: SocketAddr,
    conns: Vec<ShardConn>,
    next: usize,
}

/// A ketama-sharded Redis client.
///
/// Commands are routed to independent Redis instances using consistent
/// hashing. Each server has a pool of connections with round-robin
/// dispatch and lazy reconnection.
pub struct ShardedClient {
    shards: Vec<Shard>,
    ring: ketama::Ring,
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
    password: Option<String>,
    username: Option<String>,
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
            password: config.password,
            username: config.username,
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
            password: self.password.clone(),
            username: self.username.clone(),
        }
    }

    /// Get a [`Client`] for a specific shard by index (for node-level commands).
    pub async fn shard_client(&mut self, index: usize) -> Result<Client, Error> {
        let opts = self.connect_opts();
        let shard = &mut self.shards[index];
        get_client(shard, &opts).await
    }

    // ── Core routing ────────────────────────────────────────────────────

    /// Route an encoded command to the shard owning `key`.
    async fn route_command(&mut self, key: &[u8], encoded: &[u8]) -> Result<Value, Error> {
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
            match client.read_value().await {
                Ok(value) => {
                    // Advance round-robin past the connection we used.
                    shard.next = (idx + 1) % size;

                    if let Value::Error(ref msg) = value {
                        return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
                    }
                    return Ok(value);
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

    /// Route and expect +OK.
    async fn route_ok(&mut self, key: &[u8], encoded: &[u8]) -> Result<(), Error> {
        let value = self.route_command(key, encoded).await?;
        match value {
            Value::SimpleString(_) => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Route and expect an integer.
    async fn route_int(&mut self, key: &[u8], encoded: &[u8]) -> Result<i64, Error> {
        let value = self.route_command(key, encoded).await?;
        match value {
            Value::Integer(n) => Ok(n),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Route and expect a bulk string or null.
    async fn route_bulk(&mut self, key: &[u8], encoded: &[u8]) -> Result<Option<Bytes>, Error> {
        let value = self.route_command(key, encoded).await?;
        match value {
            Value::BulkString(data) => Ok(Some(data)),
            Value::Null => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    // ── Multi-key shard validation ──────────────────────────────────────

    /// Verify all keys route to the same shard. Returns the common shard index.
    fn require_same_shard(&self, keys: &[&[u8]]) -> Result<usize, Error> {
        let first = self.ring.route(keys[0]);
        for key in &keys[1..] {
            if self.ring.route(key) != first {
                return Err(Error::Redis(
                    "keys in request don't route to the same shard".into(),
                ));
            }
        }
        Ok(first)
    }

    // ── String commands ─────────────────────────────────────────────────

    /// Get the value of a key.
    pub async fn get(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.route_bulk(key, &Client::encode_request(&Request::get(key)))
            .await
    }

    /// Set a key-value pair.
    pub async fn set(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = Client::encode_set_request(&Request::set(key, value));
        let resp = self.route_command(key, &encoded).await?;
        match resp {
            Value::SimpleString(_) | Value::Null => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Set a key-value pair with TTL in seconds.
    pub async fn set_ex(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        ttl_secs: u64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = Client::encode_set_request(&Request::set(key, value).ex(ttl_secs));
        self.route_ok(key, &encoded).await
    }

    /// Set a key-value pair with TTL in milliseconds.
    pub async fn set_px(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        ttl_ms: u64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = Client::encode_set_request(&Request::set(key, value).px(ttl_ms));
        self.route_ok(key, &encoded).await
    }

    /// Set a key only if it does not already exist. Returns true if the key was set.
    pub async fn set_nx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = Client::encode_set_request(&Request::set(key, value).nx());
        let resp = self.route_command(key, &encoded).await?;
        match resp {
            Value::SimpleString(_) => Ok(true),
            Value::Null => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns the number of keys deleted.
    pub async fn del(&mut self, key: impl AsRef<[u8]>) -> Result<u64, Error> {
        let key = key.as_ref();
        self.route_int(key, &Client::encode_request(&Request::del(key)))
            .await
            .map(|n| n as u64)
    }

    /// Get values for multiple keys. All keys must route to the same shard.
    pub async fn mget(&mut self, keys: &[&[u8]]) -> Result<Vec<Option<Bytes>>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.require_same_shard(keys)?;
        let encoded = Client::encode_request(&Request::mget(keys));
        let value = self.route_command(keys[0], &encoded).await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::BulkString(data) => result.push(Some(data)),
                        Value::Null => result.push(None),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment the integer value of a key by 1.
    pub async fn incr(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"INCR").arg(key)),
        )
        .await
    }

    /// Decrement the integer value of a key by 1.
    pub async fn decr(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"DECR").arg(key)),
        )
        .await
    }

    /// Increment the integer value of a key by a given amount.
    pub async fn incrby(&mut self, key: impl AsRef<[u8]>, delta: i64) -> Result<i64, Error> {
        let key = key.as_ref();
        let delta_str = delta.to_string();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"INCRBY").arg(key).arg(delta_str.as_bytes())),
        )
        .await
    }

    /// Decrement the integer value of a key by a given amount.
    pub async fn decrby(&mut self, key: impl AsRef<[u8]>, delta: i64) -> Result<i64, Error> {
        let key = key.as_ref();
        let delta_str = delta.to_string();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"DECRBY").arg(key).arg(delta_str.as_bytes())),
        )
        .await
    }

    /// Append a value to a key. Returns the length of the string after the append.
    pub async fn append(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"APPEND").arg(key).arg(value)),
        )
        .await
    }

    // ── Key commands ────────────────────────────────────────────────────

    /// Check if a key exists.
    pub async fn exists(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"EXISTS").arg(key)),
        )
        .await
        .map(|n| n > 0)
    }

    /// Set a timeout on a key in seconds.
    pub async fn expire(&mut self, key: impl AsRef<[u8]>, seconds: u64) -> Result<bool, Error> {
        let key = key.as_ref();
        let secs_str = seconds.to_string();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"EXPIRE").arg(key).arg(secs_str.as_bytes())),
        )
        .await
        .map(|n| n == 1)
    }

    /// Get the TTL of a key in seconds.
    pub async fn ttl(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(key, &Client::encode_request(&Request::cmd(b"TTL").arg(key)))
            .await
    }

    /// Get the TTL of a key in milliseconds.
    pub async fn pttl(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"PTTL").arg(key)),
        )
        .await
    }

    /// Remove the existing timeout on a key.
    pub async fn persist(&mut self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"PERSIST").arg(key)),
        )
        .await
        .map(|n| n == 1)
    }

    /// Get the type of a key.
    pub async fn key_type(&mut self, key: impl AsRef<[u8]>) -> Result<String, Error> {
        let key = key.as_ref();
        let value = self
            .route_command(
                key,
                &Client::encode_request(&Request::cmd(b"TYPE").arg(key)),
            )
            .await?;
        match value {
            Value::SimpleString(data) => Ok(String::from_utf8_lossy(&data).into_owned()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Rename a key. Both keys must route to the same shard.
    pub async fn rename(
        &mut self,
        key: impl AsRef<[u8]>,
        new_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let new_key = new_key.as_ref();
        self.require_same_shard(&[key, new_key])?;
        self.route_ok(
            key,
            &Client::encode_request(&Request::cmd(b"RENAME").arg(key).arg(new_key)),
        )
        .await
    }

    /// Delete keys without blocking. Returns the number of keys removed.
    pub async fn unlink(&mut self, key: impl AsRef<[u8]>) -> Result<u64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"UNLINK").arg(key)),
        )
        .await
        .map(|n| n as u64)
    }

    // ── Hash commands ───────────────────────────────────────────────────

    /// Set a field in a hash. Returns true if the field is new.
    pub async fn hset(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let value = value.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"HSET").arg(key).arg(field).arg(value)),
        )
        .await
        .map(|n| n > 0)
    }

    /// Get the value of a hash field.
    pub async fn hget(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
    ) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        self.route_bulk(
            key,
            &Client::encode_request(&Request::cmd(b"HGET").arg(key).arg(field)),
        )
        .await
    }

    /// Get all fields and values in a hash.
    pub async fn hgetall(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<(Bytes, Bytes)>, Error> {
        let key = key.as_ref();
        let value = self
            .route_command(
                key,
                &Client::encode_request(&Request::cmd(b"HGETALL").arg(key)),
            )
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len() / 2);
                let mut iter = arr.into_iter();
                while let Some(field) = iter.next() {
                    let val = iter.next().ok_or(Error::UnexpectedResponse)?;
                    match (field, val) {
                        (Value::BulkString(f), Value::BulkString(v)) => {
                            result.push((f, v));
                        }
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get values for multiple hash fields.
    pub async fn hmget(
        &mut self,
        key: impl AsRef<[u8]>,
        fields: &[&[u8]],
    ) -> Result<Vec<Option<Bytes>>, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"HMGET").arg(key);
        for field in fields {
            req = req.arg(field);
        }
        let value = self
            .route_command(key, &Client::encode_request(&req))
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::BulkString(data) => result.push(Some(data)),
                        Value::Null => result.push(None),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete fields from a hash. Returns the number of fields removed.
    pub async fn hdel(&mut self, key: impl AsRef<[u8]>, fields: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"HDEL").arg(key);
        for field in fields {
            req = req.arg(field);
        }
        self.route_int(key, &Client::encode_request(&req)).await
    }

    /// Check if a field exists in a hash.
    pub async fn hexists(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"HEXISTS").arg(key).arg(field)),
        )
        .await
        .map(|n| n == 1)
    }

    /// Get the number of fields in a hash.
    pub async fn hlen(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"HLEN").arg(key)),
        )
        .await
    }

    /// Get all field names in a hash.
    pub async fn hkeys(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .route_command(
                key,
                &Client::encode_request(&Request::cmd(b"HKEYS").arg(key)),
            )
            .await?;
        parse_bytes_array(value)
    }

    /// Get all values in a hash.
    pub async fn hvals(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .route_command(
                key,
                &Client::encode_request(&Request::cmd(b"HVALS").arg(key)),
            )
            .await?;
        parse_bytes_array(value)
    }

    /// Increment the integer value of a hash field.
    pub async fn hincrby(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        delta: i64,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let delta_str = delta.to_string();
        self.route_int(
            key,
            &Client::encode_request(
                &Request::cmd(b"HINCRBY")
                    .arg(key)
                    .arg(field)
                    .arg(delta_str.as_bytes()),
            ),
        )
        .await
    }

    /// Set a hash field only if it does not exist.
    pub async fn hsetnx(
        &mut self,
        key: impl AsRef<[u8]>,
        field: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let field = field.as_ref();
        let value = value.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"HSETNX").arg(key).arg(field).arg(value)),
        )
        .await
        .map(|n| n == 1)
    }

    // ── List commands ───────────────────────────────────────────────────

    /// Push values to the head of a list. Returns the list length.
    pub async fn lpush(&mut self, key: impl AsRef<[u8]>, values: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"LPUSH").arg(key);
        for v in values {
            req = req.arg(v);
        }
        self.route_int(key, &Client::encode_request(&req)).await
    }

    /// Push values to the tail of a list. Returns the list length.
    pub async fn rpush(&mut self, key: impl AsRef<[u8]>, values: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"RPUSH").arg(key);
        for v in values {
            req = req.arg(v);
        }
        self.route_int(key, &Client::encode_request(&req)).await
    }

    /// Remove and return the first element of a list.
    pub async fn lpop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.route_bulk(
            key,
            &Client::encode_request(&Request::cmd(b"LPOP").arg(key)),
        )
        .await
    }

    /// Remove and return the last element of a list.
    pub async fn rpop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.route_bulk(
            key,
            &Client::encode_request(&Request::cmd(b"RPOP").arg(key)),
        )
        .await
    }

    /// Get the length of a list.
    pub async fn llen(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"LLEN").arg(key)),
        )
        .await
    }

    /// Get an element from a list by index.
    pub async fn lindex(
        &mut self,
        key: impl AsRef<[u8]>,
        index: i64,
    ) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        let idx_str = index.to_string();
        self.route_bulk(
            key,
            &Client::encode_request(&Request::cmd(b"LINDEX").arg(key).arg(idx_str.as_bytes())),
        )
        .await
    }

    /// Get a range of elements from a list.
    pub async fn lrange(
        &mut self,
        key: impl AsRef<[u8]>,
        start: i64,
        stop: i64,
    ) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let start_str = start.to_string();
        let stop_str = stop.to_string();
        let value = self
            .route_command(
                key,
                &Client::encode_request(
                    &Request::cmd(b"LRANGE")
                        .arg(key)
                        .arg(start_str.as_bytes())
                        .arg(stop_str.as_bytes()),
                ),
            )
            .await?;
        parse_bytes_array(value)
    }

    /// Trim a list to a specified range.
    pub async fn ltrim(
        &mut self,
        key: impl AsRef<[u8]>,
        start: i64,
        stop: i64,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let start_str = start.to_string();
        let stop_str = stop.to_string();
        self.route_ok(
            key,
            &Client::encode_request(
                &Request::cmd(b"LTRIM")
                    .arg(key)
                    .arg(start_str.as_bytes())
                    .arg(stop_str.as_bytes()),
            ),
        )
        .await
    }

    /// Set the value of an element by index.
    pub async fn lset(
        &mut self,
        key: impl AsRef<[u8]>,
        index: i64,
        value: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let idx_str = index.to_string();
        self.route_ok(
            key,
            &Client::encode_request(
                &Request::cmd(b"LSET")
                    .arg(key)
                    .arg(idx_str.as_bytes())
                    .arg(value),
            ),
        )
        .await
    }

    /// Push a value to the head of a list only if the list exists.
    pub async fn lpushx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"LPUSHX").arg(key).arg(value)),
        )
        .await
    }

    /// Push a value to the tail of a list only if the list exists.
    pub async fn rpushx(
        &mut self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<i64, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"RPUSHX").arg(key).arg(value)),
        )
        .await
    }

    // ── Set commands ────────────────────────────────────────────────────

    /// Add members to a set. Returns the number of members added.
    pub async fn sadd(&mut self, key: impl AsRef<[u8]>, members: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SADD").arg(key);
        for m in members {
            req = req.arg(m);
        }
        self.route_int(key, &Client::encode_request(&req)).await
    }

    /// Remove members from a set. Returns the number of members removed.
    pub async fn srem(&mut self, key: impl AsRef<[u8]>, members: &[&[u8]]) -> Result<i64, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SREM").arg(key);
        for m in members {
            req = req.arg(m);
        }
        self.route_int(key, &Client::encode_request(&req)).await
    }

    /// Get all members of a set.
    pub async fn smembers(&mut self, key: impl AsRef<[u8]>) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let value = self
            .route_command(
                key,
                &Client::encode_request(&Request::cmd(b"SMEMBERS").arg(key)),
            )
            .await?;
        parse_bytes_array(value)
    }

    /// Get the number of members in a set.
    pub async fn scard(&mut self, key: impl AsRef<[u8]>) -> Result<i64, Error> {
        let key = key.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"SCARD").arg(key)),
        )
        .await
    }

    /// Check if a member exists in a set.
    pub async fn sismember(
        &mut self,
        key: impl AsRef<[u8]>,
        member: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let member = member.as_ref();
        self.route_int(
            key,
            &Client::encode_request(&Request::cmd(b"SISMEMBER").arg(key).arg(member)),
        )
        .await
        .map(|n| n == 1)
    }

    /// Check if multiple members exist in a set.
    pub async fn smismember(
        &mut self,
        key: impl AsRef<[u8]>,
        members: &[&[u8]],
    ) -> Result<Vec<bool>, Error> {
        let key = key.as_ref();
        let mut req = Request::cmd(b"SMISMEMBER").arg(key);
        for m in members {
            req = req.arg(m);
        }
        let value = self
            .route_command(key, &Client::encode_request(&req))
            .await?;
        match value {
            Value::Array(arr) => {
                let mut result = Vec::with_capacity(arr.len());
                for v in arr {
                    match v {
                        Value::Integer(n) => result.push(n == 1),
                        _ => return Err(Error::UnexpectedResponse),
                    }
                }
                Ok(result)
            }
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Remove and return a random member from a set.
    pub async fn spop(&mut self, key: impl AsRef<[u8]>) -> Result<Option<Bytes>, Error> {
        let key = key.as_ref();
        self.route_bulk(
            key,
            &Client::encode_request(&Request::cmd(b"SPOP").arg(key)),
        )
        .await
    }

    /// Get random members from a set.
    pub async fn srandmember(
        &mut self,
        key: impl AsRef<[u8]>,
        count: i64,
    ) -> Result<Vec<Bytes>, Error> {
        let key = key.as_ref();
        let count_str = count.to_string();
        let value = self
            .route_command(
                key,
                &Client::encode_request(
                    &Request::cmd(b"SRANDMEMBER")
                        .arg(key)
                        .arg(count_str.as_bytes()),
                ),
            )
            .await?;
        parse_bytes_array(value)
    }

    // ── Server commands ─────────────────────────────────────────────────

    /// Ping any connected shard.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let ping_cmd = Client::encode_request(&Request::ping());
        for shard in &mut self.shards {
            if let Some(client) = get_connected_client(shard) {
                client.conn().send(&ping_cmd)?;
                let value = client.read_value().await?;
                if let Value::Error(ref msg) = value {
                    return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
                }
                return match value {
                    Value::SimpleString(_) => Ok(()),
                    _ => Err(Error::UnexpectedResponse),
                };
            }
        }
        Err(Error::AllConnectionsFailed)
    }

    // ── Custom command routing ──────────────────────────────────────────

    /// Execute a custom command routed by key. Returns the raw RESP Value.
    pub async fn cmd_routed(
        &mut self,
        key: impl AsRef<[u8]>,
        request: &Request<'_>,
    ) -> Result<Value, Error> {
        let key = key.as_ref();
        self.route_command(key, &Client::encode_request(request))
            .await
    }
}

/// Connection options cloned from config to avoid borrow conflicts.
#[derive(Clone)]
struct ConnectOpts {
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
    password: Option<String>,
    username: Option<String>,
}

/// Get the first connected client from a shard without reconnecting.
fn get_connected_client(shard: &Shard) -> Option<Client> {
    for conn in &shard.conns {
        if let ShardConn::Connected(client) = conn {
            return Some(*client);
        }
    }
    None
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

    let client = Client::new(conn);
    client
        .maybe_auth(opts.password.as_deref(), opts.username.as_deref())
        .await?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_server_always_routes_to_zero() {
        let config = ShardedConfig {
            servers: vec!["127.0.0.1:6379".parse().unwrap()],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
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
                "127.0.0.1:6379".parse().unwrap(),
                "127.0.0.1:6380".parse().unwrap(),
                "127.0.0.1:6381".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
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
                "127.0.0.1:6379".parse().unwrap(),
                "127.0.0.1:6380".parse().unwrap(),
            ],
            pool_size: 4,
            connect_timeout_ms: 500,
            tls_server_name: None,
            password: None,
            username: None,
        };
        let client = ShardedClient::new(config);
        assert_eq!(client.shard_count(), 2);
        assert_eq!(client.ring.node_count(), 2);
        // Each shard should have pool_size connections.
        assert_eq!(client.shards[0].conns.len(), 4);
        assert_eq!(client.shards[1].conns.len(), 4);
    }

    #[test]
    fn test_pool_size_minimum() {
        let config = ShardedConfig {
            servers: vec!["127.0.0.1:6379".parse().unwrap()],
            pool_size: 0,
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
        };
        let client = ShardedClient::new(config);
        // pool_size of 0 should be clamped to 1.
        assert_eq!(client.shards[0].conns.len(), 1);
    }

    #[test]
    fn test_require_same_shard_matching() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:6379".parse().unwrap(),
                "127.0.0.1:6380".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
        };
        let client = ShardedClient::new(config);

        // Same key always routes to same shard.
        let keys: &[&[u8]] = &[b"same-key", b"same-key"];
        assert!(client.require_same_shard(keys).is_ok());
    }

    #[test]
    fn test_require_same_shard_single_key() {
        let config = ShardedConfig {
            servers: vec![
                "127.0.0.1:6379".parse().unwrap(),
                "127.0.0.1:6380".parse().unwrap(),
            ],
            pool_size: 1,
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
        };
        let client = ShardedClient::new(config);
        let keys: &[&[u8]] = &[b"anykey"];
        assert!(client.require_same_shard(keys).is_ok());
    }
}
