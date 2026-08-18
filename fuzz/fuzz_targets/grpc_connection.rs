//! Fuzz the gRPC-over-h2 stack end to end: open a real unary request so
//! a stream exists, then deliver arbitrary bytes in fuzzer-chosen chunks
//! through `GrpcConnection::recv` (h2 framing → gRPC reassembly →
//! trailer/status mapping).
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ringline_grpc::{GrpcConnection, Settings};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    splits: [u8; 4],
    data: &'a [u8],
}

fuzz_target!(|input: Input| {
    let mut conn = GrpcConnection::new(Settings::client_default());
    let _ = conn.take_pending_send();
    let _ = conn.send_unary("fuzz.Service", "Method", b"payload", &[]);
    let _ = conn.take_pending_send();

    let mut rest = input.data;
    for split in input.splits {
        if rest.is_empty() {
            break;
        }
        let n = (split as usize % rest.len()) + 1;
        let (chunk, tail) = rest.split_at(n.min(rest.len()));
        rest = tail;
        if conn.recv(chunk).is_err() {
            return;
        }
        while let Some(event) = conn.poll_event() {
            std::hint::black_box(&event);
        }
        let _ = conn.take_pending_send();
    }
    if !rest.is_empty() {
        let _ = conn.recv(rest);
    }
    while let Some(event) = conn.poll_event() {
        std::hint::black_box(&event);
    }
    let _ = conn.take_pending_send();
});
