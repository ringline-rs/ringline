//! ringline-native Memcache client for use inside the ringline async runtime.
//!
//! This client wraps a [`ringline::ConnCtx`] and provides typed Memcache command
//! methods that use `with_data()` + `Response::parse()` for incremental
//! parsing. It is designed for single-threaded, single-connection use within
//! ringline's `AsyncEventHandler::on_start()` or connection tasks.
//!
//! All key and value parameters accept `impl AsRef<[u8]>`, so you can pass
//! `&str`, `String`, `&[u8]`, `Vec<u8>`, `Bytes`, etc.
//!
//! # Example
//!
//! ```no_run
//! use ringline::ConnCtx;
//! use ringline_memcache::Client;
//!
//! async fn example(conn: ConnCtx) -> Result<(), ringline_memcache::Error> {
//!     let client = Client::new(conn);
//!     client.set("hello", "world").await?;
//!     let val = client.get("hello").await?;
//!     assert_eq!(val.unwrap().data.as_ref(), b"world");
//!     Ok(())
//! }
//! ```

pub mod pool;
pub mod sharded;
pub use pool::{Pool, PoolConfig};
pub use sharded::{ShardedClient, ShardedConfig};

use std::io;

use bytes::Bytes;
use protocol_memcache::{Request as McRequest, Response as McResponse};
use ringline::{ConnCtx, ParseResult};

// -- Error -------------------------------------------------------------------

/// Errors returned by the ringline Memcache client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The connection was closed before a response was received.
    #[error("connection closed")]
    ConnectionClosed,

    /// The server returned an error response (ERROR, CLIENT_ERROR, SERVER_ERROR).
    #[error("memcache error: {0}")]
    Memcache(String),

    /// The response type did not match the expected type for the command.
    #[error("unexpected response")]
    UnexpectedResponse,

    /// Memcache protocol parse error.
    #[error("protocol error: {0}")]
    Protocol(#[from] protocol_memcache::ParseError),

    /// I/O error during send.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// All connections in the pool are down and reconnection failed.
    #[error("all connections failed")]
    AllConnectionsFailed,
}

// -- Value types -------------------------------------------------------------

/// A value returned from a single-key GET command.
#[derive(Debug, Clone)]
pub struct Value {
    /// The cached data.
    pub data: Bytes,
    /// Flags stored with the item.
    pub flags: u32,
}

/// A value returned from a multi-key GET command, including the key.
#[derive(Debug, Clone)]
pub struct GetValue {
    /// The key for this value.
    pub key: Bytes,
    /// The cached data.
    pub data: Bytes,
    /// Flags stored with the item.
    pub flags: u32,
    /// CAS unique token (present when the server returns it via `gets`).
    pub cas: Option<u64>,
}

// -- Client ------------------------------------------------------------------

/// A ringline-native Memcache client wrapping a single connection.
///
/// `Client` is `Copy` because `ConnCtx` is `Copy`. There is no pooling,
/// sharding, or channel overhead — commands go directly over the connection.
#[derive(Clone, Copy)]
pub struct Client {
    conn: ConnCtx,
}

impl Client {
    /// Create a new client wrapping an established connection.
    pub fn new(conn: ConnCtx) -> Self {
        Self { conn }
    }

    /// Returns the underlying connection context.
    pub fn conn(&self) -> ConnCtx {
        self.conn
    }

    /// Read and parse a single Memcache response from the connection.
    pub(crate) async fn read_response(&self) -> Result<McResponse, Error> {
        let mut result: Option<Result<McResponse, Error>> = None;
        let n = self
            .conn
            .with_data(|data| match McResponse::parse(data) {
                Ok((response, consumed)) => {
                    result = Some(Ok(response));
                    ParseResult::Consumed(consumed)
                }
                Err(e) if e.is_incomplete() => ParseResult::Consumed(0),
                Err(e) => {
                    result = Some(Err(Error::Protocol(e)));
                    ParseResult::Consumed(0)
                }
            })
            .await;
        if n == 0 {
            return result.unwrap_or(Err(Error::ConnectionClosed));
        }
        result.unwrap()
    }

    /// Send an encoded command and read the response, converting error
    /// responses into `Error::Memcache`.
    async fn execute(&self, encoded: &[u8]) -> Result<McResponse, Error> {
        self.conn.send(encoded)?;
        let response = self.read_response().await?;
        check_error(&response)?;
        Ok(response)
    }

    // -- Commands -------------------------------------------------------------

    /// Get the value of a key. Returns `None` on cache miss.
    pub async fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Value>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::get(key));
        let response = self.execute(&encoded).await?;
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

    /// Get values for multiple keys. Returns only hits, each with its key and CAS token.
    pub async fn gets(&self, keys: &[&[u8]]) -> Result<Vec<GetValue>, Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let encoded = encode_request(&McRequest::gets(keys));
        let response = self.execute(&encoded).await?;
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
    pub async fn set(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<(), Error> {
        self.set_with_options(key, value, 0, 0).await
    }

    /// Set a key-value pair with custom flags and expiration time.
    pub async fn set_with_options(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        flags: u32,
        exptime: u32,
    ) -> Result<(), Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_set(key, value, flags, exptime);
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Store a key only if it does not already exist (ADD command).
    /// Returns `true` if stored, `false` if the key already exists.
    pub async fn add(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_add(key, value);
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Store a key only if it already exists (REPLACE command).
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn replace(
        &self,
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
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Increment a numeric value by delta. Returns the new value after incrementing.
    /// Returns `None` if the key does not exist.
    pub async fn incr(&self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::incr(key, delta));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Decrement a numeric value by delta. Returns the new value after decrementing.
    /// Returns `None` if the key does not exist.
    pub async fn decr(&self, key: impl AsRef<[u8]>, delta: u64) -> Result<Option<u64>, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::decr(key, delta));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Numeric(val) => Ok(Some(val)),
            McResponse::NotFound => Ok(None),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Append data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn append(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::append(key, value));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::NotStored => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Prepend data to an existing item's value.
    /// Returns `true` if stored, `false` if the key does not exist.
    pub async fn prepend(
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::prepend(key, value));
        let response = self.execute(&encoded).await?;
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
        &self,
        key: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        cas_unique: u64,
    ) -> Result<bool, Error> {
        let key = key.as_ref();
        let value = value.as_ref();
        let encoded = encode_request(&McRequest::cas(key, value, cas_unique));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Stored => Ok(true),
            McResponse::Exists => Ok(false),
            McResponse::NotFound => Err(Error::Memcache("NOT_FOUND".into())),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Delete a key. Returns `true` if deleted, `false` if not found.
    pub async fn delete(&self, key: impl AsRef<[u8]>) -> Result<bool, Error> {
        let key = key.as_ref();
        let encoded = encode_request(&McRequest::delete(key));
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Deleted => Ok(true),
            McResponse::NotFound => Ok(false),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Flush all items from the cache.
    pub async fn flush_all(&self) -> Result<(), Error> {
        let encoded = encode_request(&McRequest::flush_all());
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse),
        }
    }

    /// Get the server version string.
    pub async fn version(&self) -> Result<String, Error> {
        let encoded = encode_request(&McRequest::version());
        let response = self.execute(&encoded).await?;
        match response {
            McResponse::Version(v) => Ok(String::from_utf8_lossy(&v).into_owned()),
            _ => Err(Error::UnexpectedResponse),
        }
    }
}

// -- Encoding helpers --------------------------------------------------------

/// Encode a `McRequest` into a `Vec<u8>`.
pub(crate) fn encode_request(req: &McRequest<'_>) -> Vec<u8> {
    let size = match req {
        McRequest::Get { key } => 6 + key.len(),
        McRequest::Gets { keys } => 6 + keys.iter().map(|k| 1 + k.len()).sum::<usize>(),
        McRequest::Set { key, value, .. } | McRequest::Add { key, value, .. } => {
            41 + key.len() + value.len()
        }
        McRequest::Replace { key, value, .. } => 45 + key.len() + value.len(),
        McRequest::Incr { key, .. } | McRequest::Decr { key, .. } => 27 + key.len(),
        McRequest::Append { key, value } => 44 + key.len() + value.len(),
        McRequest::Prepend { key, value } => 45 + key.len() + value.len(),
        McRequest::Cas { key, value, .. } => 61 + key.len() + value.len(),
        McRequest::Delete { key } => 9 + key.len(),
        McRequest::FlushAll => 11,
        McRequest::Version => 9,
        McRequest::Quit => 6,
    };
    let mut buf = vec![0u8; size];
    let len = req.encode(&mut buf);
    buf.truncate(len);
    buf
}

/// Encode a SET command into a `Vec<u8>`.
pub(crate) fn encode_set(key: &[u8], value: &[u8], flags: u32, exptime: u32) -> Vec<u8> {
    encode_request(&McRequest::Set {
        key,
        value,
        flags,
        exptime,
    })
}

/// Encode an ADD command into a `Vec<u8>`.
pub(crate) fn encode_add(key: &[u8], value: &[u8]) -> Vec<u8> {
    encode_request(&McRequest::Add {
        key,
        value,
        flags: 0,
        exptime: 0,
    })
}

/// Check a response for error variants and return an appropriate `Error`.
pub(crate) fn check_error(response: &McResponse) -> Result<(), Error> {
    match response {
        McResponse::Error => Err(Error::Memcache("ERROR".into())),
        McResponse::ClientError(msg) => Err(Error::Memcache(format!(
            "CLIENT_ERROR {}",
            String::from_utf8_lossy(msg)
        ))),
        McResponse::ServerError(msg) => Err(Error::Memcache(format!(
            "SERVER_ERROR {}",
            String::from_utf8_lossy(msg)
        ))),
        _ => Ok(()),
    }
}
