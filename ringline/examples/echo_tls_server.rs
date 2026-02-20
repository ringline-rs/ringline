use std::sync::Arc;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, TlsConfig};

struct TlsEcho {
    worker_id: usize,
}

impl AsyncEventHandler for TlsEcho {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        let worker_id = self.worker_id;
        async move {
            eprintln!(
                "[worker {worker_id}] TLS connection accepted {}",
                conn.index()
            );
            loop {
                let consumed = conn
                    .with_data(|data| {
                        // Handler sees plaintext — TLS is transparent.
                        if let Err(e) = conn.send_nowait(data) {
                            eprintln!("[worker {worker_id}] send error: {e}");
                        }
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if consumed == 0 {
                    break;
                }
            }
            eprintln!(
                "[worker {worker_id}] TLS connection {} closed",
                conn.index()
            );
        }
    }

    fn create_for_worker(worker_id: usize) -> Self {
        eprintln!("[worker {worker_id}] starting");
        TlsEcho { worker_id }
    }
}

fn load_tls_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_pem = std::env::var("TLS_CERT").unwrap_or_else(|_| "cert.pem".into());
    let key_pem = std::env::var("TLS_KEY").unwrap_or_else(|_| "key.pem".into());

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert_pem)
        .unwrap_or_else(|e| panic!("failed to read {cert_pem}: {e}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("failed to parse certs from {cert_pem}: {e}"));

    if certs.is_empty() {
        panic!("no certificates found in {cert_pem}");
    }

    let key = PrivateKeyDer::from_pem_file(&key_pem)
        .unwrap_or_else(|e| panic!("failed to parse private key from {key_pem}: {e}"));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("invalid TLS certificate/key");

    Arc::new(config)
}

fn main() {
    let bind_addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7879".to_string());

    let server_config = load_tls_config();

    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 128;
    config.recv_buffer.ring_size = 128;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 1024;
    config.tls = Some(TlsConfig { server_config });

    eprintln!("starting TLS echo server on {bind_addr}");
    eprintln!("test with: openssl s_client -connect {bind_addr}");

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .bind(bind_addr.parse().expect("invalid bind address"))
        .launch::<TlsEcho>()
        .expect("failed to launch workers");

    for handle in handles {
        if let Err(e) = handle.join().expect("worker thread panicked") {
            eprintln!("worker exited with error: {e}");
        }
    }
}
