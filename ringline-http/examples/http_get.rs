#![allow(clippy::manual_async_fn)]

//! Demonstrates HTTP/2 and HTTP/1.1 GET requests using ringline-http.
//!
//! Fetches a URL over HTTPS and prints the response status and body size.
//! Defaults to https://www.example.com/ if no URL is given.
//!
//!   cargo run -p ringline-http --example http_get
//!   cargo run -p ringline-http --example http_get -- https://httpbin.org/get

use std::future::Future;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder, TlsClientConfig};

#[derive(Debug)]
struct Target {
    addr: std::net::SocketAddr,
    host: String,
    path: String,
}

static TARGET: OnceLock<Target> = OnceLock::new();

struct HttpHandler;

impl AsyncEventHandler for HttpHandler {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async move {
            let target = TARGET.get().unwrap();

            // Try HTTP/2 first, fall back to HTTP/1.1.
            eprintln!("connecting to {} (HTTP/2)...", target.host);
            let result = async {
                let mut client =
                    ringline_http::HttpClient::connect_h2(target.addr, &target.host).await?;

                let resp = client
                    .get(&target.path)
                    .header("user-agent", "ringline-http/example")
                    .send()
                    .await?;

                Ok::<_, ringline_http::HttpError>(resp)
            }
            .await;

            match result {
                Ok(resp) => {
                    eprintln!("HTTP/2 {} — {} bytes", resp.status(), resp.body().len());
                }
                Err(e) => {
                    eprintln!("error: {e}");
                }
            }

            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        HttpHandler
    }
}

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://www.example.com/".to_string());

    // Parse URL minimally (scheme://host[:port][/path]).
    let without_scheme = url
        .strip_prefix("https://")
        .expect("only https:// URLs supported");
    let (host_port, path) = without_scheme
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((without_scheme, "/".to_string()));
    let host = host_port.split(':').next().unwrap().to_string();
    let port: u16 = host_port
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);

    let addr = format!("{host}:{port}")
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses found");

    TARGET.set(Target { addr, host, path }).unwrap();

    // Configure TLS with h2 ALPN.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec()];

    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.tls_client = Some(TlsClientConfig {
        client_config: Arc::new(tls),
    });

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .launch::<HttpHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
}
