//! Bidirectional Memcache protocol implementation.
//!
//! This crate provides complete Memcache protocol support for both client
//! and server implementations. Both ASCII and binary protocols are supported.
//!
//! # Features
//!
//! - `ascii` (default): ASCII text protocol support
//! - `binary`: Binary protocol support
//! - `full`: Both ASCII and binary protocols
//!
//! # ASCII Protocol
//!
//! The ASCII protocol is text-based and human-readable. It's easier to debug
//! but has more parsing overhead.
//!
//! ## Example - Client Side
//!
//! ```
//! use protocol_memcache::{Request, Response};
//!
//! // Encode a GET command
//! let mut buf = vec![0u8; 1024];
//! let len = Request::get(b"mykey").encode(&mut buf);
//!
//! // Parse the response
//! let response_data = b"VALUE mykey 0 5\r\nhello\r\nEND\r\n";
//! let (response, consumed) = Response::parse(response_data).unwrap();
//! ```
//!
//! ## Example - Server Side
//!
//! ```
//! use protocol_memcache::{Command, Response};
//!
//! // Parse an incoming command
//! let request_data = b"get mykey\r\n";
//! let (cmd, consumed) = Command::parse(request_data).unwrap();
//!
//! // Encode a response
//! let mut buf = vec![0u8; 1024];
//! let len = Response::stored().encode(&mut buf);
//! ```
//!
//! # Binary Protocol
//!
//! The binary protocol uses fixed 24-byte headers and is more efficient for
//! high-throughput scenarios. Enable with the `binary` feature.
//!
//! ```ignore
//! use protocol_memcache::binary::{BinaryRequest, BinaryResponse, Opcode};
//!
//! // Encode a GET request
//! let mut buf = [0u8; 256];
//! let len = BinaryRequest::encode_get(&mut buf, b"mykey", 1);
//! ```

#[cfg(feature = "ascii")]
mod command;
mod error;
#[cfg(feature = "ascii")]
mod request;
#[cfg(feature = "ascii")]
mod response;
#[cfg(feature = "ascii")]
mod streaming;

#[cfg(feature = "binary")]
pub mod binary;

#[cfg(feature = "ascii")]
pub use command::{
    Command, DEFAULT_MAX_KEY_LEN, DEFAULT_MAX_KEYS, DEFAULT_MAX_VALUE_LEN, ParseOptions,
};
pub use error::ParseError;
#[cfg(feature = "ascii")]
pub use request::{AddRequest, ReplaceRequest, Request};
#[cfg(feature = "ascii")]
pub use response::{Response, Value};
#[cfg(feature = "ascii")]
pub use streaming::{ParseProgress, STREAMING_THRESHOLD, SetHeader, complete_set, parse_streaming};
