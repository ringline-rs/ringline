//! Async HTTP client for the ringline io_uring runtime.
//!
//! Provides HTTP/2 and HTTP/1.1 client connections built on top of the sans-IO
//! `ringline-h2` framing layer and the ringline async runtime. The crate
//! bridges the gap between the sans-IO state machines and the `ConnCtx` I/O
//! primitives.
//!
//! # Architecture
//!
//! `H2AsyncConn` wraps an `H2Connection` (sans-IO) with a pump loop that
//! continuously transfers bytes between `ConnCtx` and the H2 state machine.
//! This follows the same pattern as `ringline-momento`: fire requests
//! synchronously, then pump until responses arrive.
//!
//! `H1Conn` provides simple HTTP/1.1 request-response over a `ConnCtx`,
//! with header parsing and chunked transfer decoding.
//!
//! `HttpClient` is the top-level API wrapping either protocol with a
//! reqwest-style builder interface.
//!
//! # Example
//!
//! ```rust,ignore
//! use ringline_http::HttpClient;
//!
//! async fn example() -> Result<(), ringline_http::HttpError> {
//!     let mut client = HttpClient::connect_h2(addr, "example.com").await?;
//!
//!     let resp = client.get("/api/data")
//!         .header("authorization", "Bearer tok")
//!         .send()
//!         .await?;
//!
//!     assert_eq!(resp.status(), 200);
//!     let body = resp.bytes();
//!     Ok(())
//! }
//! ```
//!
//! # Multiplexed API
//!
//! ```rust,ignore
//! use ringline_http::H2AsyncConn;
//!
//! async fn example() -> Result<(), ringline_http::HttpError> {
//!     let mut h2 = H2AsyncConn::connect(addr, "example.com").await?;
//!
//!     let s1 = h2.fire_request("GET", "/a", "example.com", &[], None)?;
//!     let s2 = h2.fire_request("GET", "/b", "example.com", &[], None)?;
//!
//!     let (stream_id, resp) = h2.recv().await?;
//!     let (stream_id, resp) = h2.recv().await?;
//!     Ok(())
//! }
//! ```
//!
//! # Copy Semantics
//!
//! | Path | Copies | Notes |
//! |------|--------|-------|
//! | **H2 recv headers** | 1 | `with_data` feeds `h2.recv()` which copies into `recv_buf`. Headers decoded from owned `Vec<u8>`. |
//! | **H2 recv body** | 1 | `h2.recv()` copies into `recv_buf`. `H2Event::Data` contains `Vec<u8>`. |
//! | **H2 send** | 2 | Headers encoded into `h2.send_buf`, then `send_nowait()` copies to pool. |
//! | **H1 recv** | 1 | `with_data` provides borrowed slice, headers parsed in-place, body copied out. |
//! | **H1 send** | 1 | Serialize to `Vec<u8>`, `send_nowait()` copies to pool. |

pub mod body;
pub mod client;
pub mod error;
pub mod h1_conn;
pub mod h2_conn;
pub mod pool;
pub mod request;
pub mod response;

pub use client::HttpClient;
pub use error::HttpError;
pub use h1_conn::H1Conn;
pub use h2_conn::H2AsyncConn;
pub use pool::{Pool, PoolConfig, Protocol};
pub use request::RequestBuilder;
pub use response::Response;
