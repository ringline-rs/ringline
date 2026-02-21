//! Bidirectional RESP2/RESP3 protocol implementation.
//!
//! This crate provides complete RESP (Redis Serialization Protocol) support for both
//! client and server implementations, supporting both RESP2 and RESP3 protocols.
//!
//! - **Values**: Parse and encode RESP values (strings, integers, arrays, etc.)
//! - **Requests**: Encode commands (client) and parse commands (server)
//! - **Responses**: Encode responses (server) and parse responses (client)
//!
//! # Features
//!
//! - `resp3` - Enables RESP3 protocol support with additional types:
//!   - Boolean (`#t`/`#f`)
//!   - Double (`,3.14159`)
//!   - BigNumber (`(12345678901234567890`)
//!   - BulkError (`!<len>\r\n<error>`)
//!   - VerbatimString (`=<len>\r\ntxt:<data>`)
//!   - Map (`%<len>\r\n<key><val>...`)
//!   - Set (`~<len>\r\n<elem>...`)
//!   - Push (`><len>\r\n<elem>...`)
//!   - Attribute (`|<len>\r\n<attrs>...<value>`)
//!   - Null (`_\r\n`)
//!
//! # Example - Client Side
//!
//! ```
//! use protocol_resp::{Request, Value};
//!
//! // Encode a GET command
//! let mut buf = vec![0u8; 1024];
//! let len = Request::get(b"mykey").encode(&mut buf);
//!
//! // Parse the response
//! let response_data = b"+OK\r\n";
//! let (value, consumed) = Value::parse(response_data).unwrap();
//! ```
//!
//! # Example - Server Side
//!
//! ```
//! use protocol_resp::{Command, Value};
//!
//! // Parse an incoming command
//! let request_data = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
//! let (cmd, consumed) = Command::parse(request_data).unwrap();
//!
//! // Encode a response
//! let mut buf = vec![0u8; 1024];
//! let len = Value::bulk_string(b"myvalue").encode(&mut buf);
//! ```

pub mod cluster;
mod command;
mod error;
mod request;
pub mod streaming;
mod value;

pub use cluster::{
    NodeInfo, Redirect, RedirectKind, SLOT_COUNT, SlotMap, SlotRange, crc16, hash_slot,
    parse_redirect,
};
pub use command::Command;
pub use error::ParseError;
pub use request::{Request, SetRequest};
pub use streaming::{ParseProgress, STREAMING_THRESHOLD, SetHeader, complete_set, parse_streaming};
pub use value::{
    DEFAULT_MAX_BULK_STRING_LEN, DEFAULT_MAX_COLLECTION_ELEMENTS, DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_KEY_LEN, DEFAULT_MAX_TOTAL_ITEMS, ParseOptions, Value,
};
