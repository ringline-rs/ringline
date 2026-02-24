//! Top-level HTTP client with protocol dispatch.

use std::net::SocketAddr;

use crate::error::HttpError;
use crate::h1_conn::H1Conn;
use crate::h2_conn::H2AsyncConn;
use crate::request::RequestBuilder;
use crate::response::Response;

enum ConnectionInner {
    H2(Box<H2AsyncConn>),
    H1(H1Conn),
}

/// HTTP client supporting both HTTP/2 and HTTP/1.1 connections.
///
/// # Example
///
/// ```rust,ignore
/// let mut client = HttpClient::connect_h2(addr, "example.com").await?;
/// let resp = client.get("/api/data").header("authorization", "Bearer tok").send().await?;
/// assert_eq!(resp.status(), 200);
/// ```
pub struct HttpClient {
    inner: ConnectionInner,
    host: String,
}

impl HttpClient {
    /// Connect using HTTP/2 over TLS.
    pub async fn connect_h2(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let h2 = H2AsyncConn::connect(addr, host).await?;
        Ok(Self {
            inner: ConnectionInner::H2(Box::new(h2)),
            host: host.to_string(),
        })
    }

    /// Connect using HTTP/2 over TLS with a timeout (milliseconds).
    pub async fn connect_h2_with_timeout(
        addr: SocketAddr,
        host: &str,
        timeout_ms: u64,
    ) -> Result<Self, HttpError> {
        let h2 = H2AsyncConn::connect_with_timeout(addr, host, timeout_ms).await?;
        Ok(Self {
            inner: ConnectionInner::H2(Box::new(h2)),
            host: host.to_string(),
        })
    }

    /// Connect using HTTP/1.1 over TLS.
    pub async fn connect_h1(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let h1 = H1Conn::connect_tls(addr, host).await?;
        Ok(Self {
            inner: ConnectionInner::H1(h1),
            host: host.to_string(),
        })
    }

    /// Connect using HTTP/1.1 over plaintext TCP.
    pub async fn connect_h1_plain(addr: SocketAddr, host: &str) -> Result<Self, HttpError> {
        let h1 = H1Conn::connect_plain(addr, host).await?;
        Ok(Self {
            inner: ConnectionInner::H1(h1),
            host: host.to_string(),
        })
    }

    /// Build a GET request.
    pub fn get(&mut self, path: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "GET", path)
    }

    /// Build a POST request.
    pub fn post(&mut self, path: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "POST", path)
    }

    /// Build a PUT request.
    pub fn put(&mut self, path: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "PUT", path)
    }

    /// Build a DELETE request.
    pub fn delete(&mut self, path: &str) -> RequestBuilder<'_> {
        RequestBuilder::new(self, "DELETE", path)
    }

    /// Send a request with the given method, path, headers, and optional body.
    pub(crate) async fn send_request(
        &mut self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        match &mut self.inner {
            ConnectionInner::H2(h2) => {
                h2.send_request(method, path, &self.host, extra_headers, body)
                    .await
            }
            ConnectionInner::H1(h1) => h1.send_request(method, path, extra_headers, body).await,
        }
    }
}
