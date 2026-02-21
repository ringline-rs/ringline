//! Redis Cluster client for ringline-redis.
//!
//! Routes commands to the correct cluster node based on hash slot,
//! handles MOVED/ASK redirects transparently, and refreshes the
//! cluster topology when slots move.
//!
//! # Example
//!
//! ```no_run
//! use ringline_redis::{ClusterClient, ClusterConfig};
//!
//! async fn example() -> Result<(), ringline_redis::Error> {
//!     let config = ClusterConfig {
//!         seeds: vec!["127.0.0.1:7000".parse().unwrap()],
//!         connect_timeout_ms: 1000,
//!         tls_server_name: None,
//!         password: None,
//!         username: None,
//!     };
//!     let mut cluster = ClusterClient::new(config);
//!     cluster.connect().await?;
//!     cluster.set("hello", "world").await?;
//!     let val = cluster.get("hello").await?;
//!     assert_eq!(val.as_deref(), Some(&b"world"[..]));
//!     cluster.close_all();
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use resp_proto::{RedirectKind, Request, SlotMap, Value, hash_slot, parse_redirect};

use crate::{Client, Error, parse_bytes_array};

/// Maximum number of MOVED/ASK redirect hops before giving up.
const MAX_REDIRECTS: usize = 5;

/// Configuration for a cluster client.
#[derive(Clone)]
pub struct ClusterConfig {
    /// Initial seed nodes to discover the cluster topology.
    pub seeds: Vec<SocketAddr>,
    /// Connect timeout in milliseconds. 0 means no timeout.
    pub connect_timeout_ms: u64,
    /// TLS server name (SNI) for outbound connections. `None` means plain TCP.
    pub tls_server_name: Option<String>,
    /// Password for AUTH after connect. `None` skips authentication.
    pub password: Option<String>,
    /// Username for ACL-based AUTH (Redis 6.0+). Only used when `password` is set.
    pub username: Option<String>,
}

enum NodeState {
    Connected(Client),
    Disconnected,
}

/// A Redis Cluster client that routes commands by hash slot.
///
/// Commands are routed to the correct primary node using the cluster
/// slot map. MOVED and ASK redirects are handled transparently with
/// automatic topology refresh.
pub struct ClusterClient {
    /// Map from "host:port" → node state.
    nodes: HashMap<String, NodeState>,
    slot_map: SlotMap,
    seeds: Vec<SocketAddr>,
    connect_timeout_ms: u64,
    tls_server_name: Option<String>,
    password: Option<String>,
    username: Option<String>,
}

impl ClusterClient {
    /// Create a new cluster client. Call [`connect()`](Self::connect) to
    /// discover the topology and connect to cluster primaries.
    pub fn new(config: ClusterConfig) -> Self {
        // Build an empty SlotMap from an empty array.
        let empty = Value::Array(vec![]);
        let slot_map = SlotMap::from_cluster_slots(&empty).unwrap();

        Self {
            nodes: HashMap::new(),
            slot_map,
            seeds: config.seeds,
            connect_timeout_ms: config.connect_timeout_ms,
            tls_server_name: config.tls_server_name,
            password: config.password,
            username: config.username,
        }
    }

    /// Discover the cluster topology and connect to all primary nodes.
    pub async fn connect(&mut self) -> Result<(), Error> {
        self.refresh_topology().await
    }

    /// Close all node connections.
    pub fn close_all(&mut self) {
        for (_, state) in self.nodes.drain() {
            if let NodeState::Connected(client) = state {
                client.conn().close();
            }
        }
    }

    // ── Topology ────────────────────────────────────────────────────────

    /// Query CLUSTER SLOTS from any reachable node and rebuild the slot map.
    async fn refresh_topology(&mut self) -> Result<(), Error> {
        let cluster_slots_cmd = Client::encode_request(&Request::cmd(b"CLUSTER").arg(b"SLOTS"));

        // Try existing connected nodes first.
        let connected_addrs: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|(addr, state)| {
                if matches!(state, NodeState::Connected(_)) {
                    Some(addr.clone())
                } else {
                    None
                }
            })
            .collect();

        let mut slots_value = None;

        for addr in &connected_addrs {
            if let Some(NodeState::Connected(client)) = self.nodes.get(addr) {
                client.conn().send(&cluster_slots_cmd)?;
                match client.read_value().await {
                    Ok(value) => {
                        slots_value = Some(value);
                        break;
                    }
                    Err(_) => {
                        // Mark as disconnected and try next.
                        if let Some(state) = self.nodes.get_mut(addr) {
                            if let NodeState::Connected(client) = state {
                                client.conn().close();
                            }
                            *state = NodeState::Disconnected;
                        }
                    }
                }
            }
        }

        // Fall back to seeds if no existing node responded.
        if slots_value.is_none() {
            for &seed_addr in &self.seeds {
                match self.do_connect(seed_addr).await {
                    Ok(client) => {
                        client.conn().send(&cluster_slots_cmd)?;
                        match client.read_value().await {
                            Ok(value) => {
                                let key = seed_addr.to_string();
                                self.nodes.insert(key, NodeState::Connected(client));
                                slots_value = Some(value);
                                break;
                            }
                            Err(_) => {
                                client.conn().close();
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
        }

        let value = slots_value.ok_or(Error::AllConnectionsFailed)?;
        let new_map = SlotMap::from_cluster_slots(&value)
            .ok_or_else(|| Error::Redis("invalid CLUSTER SLOTS response".into()))?;

        // Collect addresses of primaries in the new map.
        let mut new_primaries: HashMap<String, ()> = HashMap::new();
        for range in new_map.ranges() {
            new_primaries.insert(range.primary.address.clone(), ());
        }

        // Close nodes that are no longer primaries.
        self.nodes.retain(|addr, state| {
            if new_primaries.contains_key(addr) {
                true
            } else {
                if let NodeState::Connected(client) = state {
                    client.conn().close();
                }
                false
            }
        });

        // Connect to new primaries we don't have yet.
        for addr_str in new_primaries.keys() {
            if !self.nodes.contains_key(addr_str) {
                let parsed: SocketAddr = match addr_str.parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                match self.do_connect(parsed).await {
                    Ok(client) => {
                        self.nodes
                            .insert(addr_str.clone(), NodeState::Connected(client));
                    }
                    Err(_) => {
                        self.nodes.insert(addr_str.clone(), NodeState::Disconnected);
                    }
                }
            }
        }

        self.slot_map = new_map;
        Ok(())
    }

    /// Get or reconnect a client for the given "host:port" address.
    async fn client_for_addr(&mut self, addr: &str) -> Result<Client, Error> {
        // Check if already connected.
        if let Some(NodeState::Connected(client)) = self.nodes.get(addr) {
            return Ok(*client);
        }

        // Parse and reconnect.
        let parsed: SocketAddr = addr
            .parse()
            .map_err(|e: std::net::AddrParseError| Error::Redis(e.to_string()))?;
        let client = self.do_connect(parsed).await?;
        self.nodes
            .insert(addr.to_string(), NodeState::Connected(client));
        Ok(client)
    }

    async fn do_connect(&self, addr: SocketAddr) -> Result<Client, Error> {
        let conn = if let Some(sni) = &self.tls_server_name {
            let fut = if self.connect_timeout_ms > 0 {
                ringline::connect_tls_with_timeout(addr, sni, self.connect_timeout_ms)?
            } else {
                ringline::connect_tls(addr, sni)?
            };
            fut.await?
        } else {
            let fut = if self.connect_timeout_ms > 0 {
                ringline::connect_with_timeout(addr, self.connect_timeout_ms)?
            } else {
                ringline::connect(addr)?
            };
            fut.await?
        };

        let client = Client::new(conn);
        client
            .maybe_auth(self.password.as_deref(), self.username.as_deref())
            .await?;
        Ok(client)
    }

    /// Mark a node as disconnected (e.g. after ConnectionClosed).
    fn mark_disconnected(&mut self, addr: &str) {
        if let Some(state) = self.nodes.get_mut(addr) {
            if let NodeState::Connected(client) = state {
                client.conn().close();
            }
            *state = NodeState::Disconnected;
        }
    }

    // ── Core routing ────────────────────────────────────────────────────

    /// Route an encoded command to the node owning `key`, handling redirects.
    async fn route_command(&mut self, key: &[u8], encoded: &[u8]) -> Result<Value, Error> {
        let slot = hash_slot(key);

        // Determine initial target node.
        let initial_addr = self
            .slot_map
            .lookup(slot)
            .map(|r| r.primary.address.clone())
            .ok_or_else(|| Error::Redis(format!("no node for slot {slot}")))?;

        let mut target_addr = initial_addr;
        let mut retried_after_refresh = false;

        for _ in 0..MAX_REDIRECTS {
            let client = match self.client_for_addr(&target_addr).await {
                Ok(c) => c,
                Err(Error::ConnectionClosed | Error::Io(_)) => {
                    if !retried_after_refresh {
                        retried_after_refresh = true;
                        self.mark_disconnected(&target_addr);
                        self.refresh_topology().await?;
                        // Re-lookup after refresh.
                        target_addr = self
                            .slot_map
                            .lookup(slot)
                            .map(|r| r.primary.address.clone())
                            .ok_or_else(|| Error::Redis(format!("no node for slot {slot}")))?;
                        continue;
                    }
                    return Err(Error::AllConnectionsFailed);
                }
                Err(e) => return Err(e),
            };

            client.conn().send(encoded)?;
            let value = match client.read_value().await {
                Ok(v) => v,
                Err(Error::ConnectionClosed) => {
                    if !retried_after_refresh {
                        retried_after_refresh = true;
                        self.mark_disconnected(&target_addr);
                        self.refresh_topology().await?;
                        target_addr = self
                            .slot_map
                            .lookup(slot)
                            .map(|r| r.primary.address.clone())
                            .ok_or_else(|| Error::Redis(format!("no node for slot {slot}")))?;
                        continue;
                    }
                    return Err(Error::ConnectionClosed);
                }
                Err(e) => return Err(e),
            };

            // Check for redirects.
            if let Some(redirect) = parse_redirect(&value) {
                match redirect.kind {
                    RedirectKind::Moved => {
                        // Topology changed — refresh and retry.
                        self.refresh_topology().await?;
                        target_addr = self
                            .slot_map
                            .lookup(slot)
                            .map(|r| r.primary.address.clone())
                            .ok_or_else(|| Error::Redis(format!("no node for slot {slot}")))?;
                        continue;
                    }
                    RedirectKind::Ask => {
                        // One-time redirect: send ASKING then retry on target.
                        let ask_addr = redirect.address;
                        let ask_client = self.client_for_addr(&ask_addr).await?;
                        let asking_cmd = Client::encode_request(&Request::cmd(b"ASKING"));
                        ask_client.conn().send(&asking_cmd)?;
                        // Read and discard the ASKING response.
                        let _ = ask_client.read_value().await?;
                        // Send the actual command.
                        ask_client.conn().send(encoded)?;
                        let ask_value = ask_client.read_value().await?;
                        // Check the ASK target's response for errors.
                        if let Value::Error(ref msg) = ask_value {
                            return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
                        }
                        return Ok(ask_value);
                    }
                }
            }

            // Non-redirect error.
            if let Value::Error(ref msg) = value {
                return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
            }

            return Ok(value);
        }

        Err(Error::TooManyRedirects)
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

    // ── Helpers for multi-key slot validation ───────────────────────────

    /// Verify all keys hash to the same slot. Returns the common slot.
    fn require_same_slot(keys: &[&[u8]]) -> Result<u16, Error> {
        let first_slot = hash_slot(keys[0]);
        for key in &keys[1..] {
            if hash_slot(key) != first_slot {
                return Err(Error::Redis(
                    "CROSSSLOT Keys in request don't hash to the same slot".into(),
                ));
            }
        }
        Ok(first_slot)
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

    /// Get values for multiple keys. All keys must hash to the same slot.
    pub async fn mget(&mut self, keys: &[&[u8]]) -> Result<Vec<Option<Bytes>>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        Self::require_same_slot(keys)?;
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

    /// Rename a key. Both keys must hash to the same slot.
    pub async fn rename(
        &mut self,
        key: impl AsRef<[u8]>,
        new_key: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let new_key = new_key.as_ref();
        Self::require_same_slot(&[key, new_key])?;
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

    /// Ping any connected node.
    pub async fn ping(&mut self) -> Result<(), Error> {
        let ping_cmd = Client::encode_request(&Request::ping());
        // Find any connected node to ping.
        let addr = self
            .nodes
            .iter()
            .find_map(|(addr, state)| {
                if matches!(state, NodeState::Connected(_)) {
                    Some(addr.clone())
                } else {
                    None
                }
            })
            .ok_or(Error::AllConnectionsFailed)?;

        let client = self.client_for_addr(&addr).await?;
        client.conn().send(&ping_cmd)?;
        let value = client.read_value().await?;
        if let Value::Error(ref msg) = value {
            return Err(Error::Redis(String::from_utf8_lossy(msg).into_owned()));
        }
        match value {
            Value::SimpleString(_) => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
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

    /// Route pre-encoded RESP command bytes to the node owning `key`.
    ///
    /// This skips Request construction and encoding -- use when you already
    /// have the raw RESP wire bytes (e.g. proxying from a client).
    pub async fn route_raw(&mut self, key: &[u8], encoded: &[u8]) -> Result<Value, Error> {
        self.route_command(key, encoded).await
    }

    /// Get a [`Client`] for a specific node address (for node-level commands
    /// like CONFIG, CLUSTER INFO, etc.).
    pub async fn node_client(&mut self, addr: &str) -> Result<Client, Error> {
        self.client_for_addr(addr).await
    }
}

#[cfg(test)]
mod tests {
    use resp_proto::hash_slot;

    use super::*;

    #[test]
    fn test_require_same_slot_matching() {
        // Keys with same hash tag should pass.
        let keys: &[&[u8]] = &[b"{user}.name", b"{user}.email", b"{user}.age"];
        assert!(ClusterClient::require_same_slot(keys).is_ok());
    }

    #[test]
    fn test_require_same_slot_mismatch() {
        // Keys with different hash tags should fail.
        let keys: &[&[u8]] = &[b"{a}.key", b"{b}.key"];
        let err = ClusterClient::require_same_slot(keys).unwrap_err();
        assert!(matches!(err, Error::Redis(msg) if msg.contains("CROSSSLOT")));
    }

    #[test]
    fn test_require_same_slot_single_key() {
        let keys: &[&[u8]] = &[b"anykey"];
        assert!(ClusterClient::require_same_slot(keys).is_ok());
    }

    #[test]
    fn test_cluster_config_defaults() {
        let config = ClusterConfig {
            seeds: vec!["127.0.0.1:7000".parse().unwrap()],
            connect_timeout_ms: 0,
            tls_server_name: None,
            password: None,
            username: None,
        };
        let client = ClusterClient::new(config);
        assert!(client.slot_map.is_empty());
        assert!(client.nodes.is_empty());
    }

    #[test]
    fn test_hash_slot_routing_consistency() {
        // Verify that hash_slot is consistent for routing.
        let slot1 = hash_slot(b"mykey");
        let slot2 = hash_slot(b"mykey");
        assert_eq!(slot1, slot2);
        assert!(slot1 < 16384);
    }
}
