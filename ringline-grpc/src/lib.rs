//! Sans-IO gRPC client framing layer.
//!
//! This crate provides a pure sans-IO gRPC client framing layer built on top
//! of `ringline-h2`. It has no protobuf dependency -- the caller provides raw
//! `&[u8]` message bodies and handles serialization externally.
//!
//! # Architecture
//!
//! ```text
//!   TCP + TLS bytes
//!        |
//!   +----v-----------+
//!   | ringline-h2    |  HTTP/2 framing + HPACK
//!   +----+-----------+
//!        |
//!   +----v-----------+
//!   | ringline-grpc  |  gRPC message framing + status codes
//!   | GrpcConnection |  GrpcEvent: Response, Message, Status, etc.
//!   +----------------+
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use ringline_grpc::{GrpcConnection, GrpcEvent, Settings};
//!
//! let mut grpc = GrpcConnection::new(Settings::client_default());
//!
//! // Send the connection preface to the transport.
//! let preface = grpc.take_pending_send();
//! transport_send(&preface);
//!
//! // Send a unary request (codec-agnostic: caller provides raw bytes).
//! let stream_id = grpc.send_unary("my.Service", "MyMethod", &request_bytes, &[])?;
//! transport_send(&grpc.take_pending_send());
//!
//! // Feed received bytes and drain events.
//! grpc.recv(&received_data)?;
//! while let Some(event) = grpc.poll_event() {
//!     match event {
//!         GrpcEvent::Message { stream_id, data } => { /* decoded message */ }
//!         GrpcEvent::Status { stream_id, status, message, .. } => { /* done */ }
//!         _ => {}
//!     }
//! }
//! ```

pub mod connection;
pub mod error;
pub mod message;

pub use connection::{GrpcConnection, GrpcEvent};
pub use error::{GrpcError, GrpcStatus};
pub use ringline_h2::{HeaderField, Settings};
