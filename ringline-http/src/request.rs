//! Request builder for ergonomic HTTP request construction.

use crate::body::Body;
use crate::client::HttpClient;
use crate::error::HttpError;
use crate::response::Response;

/// Builder for an HTTP request.
pub struct RequestBuilder<'a> {
    client: &'a mut HttpClient,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Body,
}

impl<'a> RequestBuilder<'a> {
    pub(crate) fn new(client: &'a mut HttpClient, method: &str, path: &str) -> Self {
        Self {
            client,
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Body::Empty,
        }
    }

    /// Add a header to the request.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Send the request and return the response.
    pub async fn send(self) -> Result<Response, HttpError> {
        let extra: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        let body_bytes = match &self.body {
            Body::Empty => None,
            Body::Bytes(b) => Some(b.as_ref()),
        };

        self.client
            .send_request(&self.method, &self.path, &extra, body_bytes)
            .await
    }
}
