//! Fuzz the full HTTP/2 connection state machine: open a real request
//! stream, then deliver arbitrary bytes in fuzzer-chosen chunk sizes so
//! partial-frame buffering and cross-read state stay covered.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ringline_h2::hpack::HeaderField;
use ringline_h2::{H2Connection, Settings};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    splits: [u8; 4],
    data: &'a [u8],
}

fuzz_target!(|input: Input| {
    let mut conn = H2Connection::new(Settings::client_default());
    let _ = conn.take_pending_send();

    let request = [
        HeaderField::new(":method", "GET"),
        HeaderField::new(":scheme", "https"),
        HeaderField::new(":authority", "fuzz.invalid"),
        HeaderField::new(":path", "/"),
    ];
    let _ = conn.send_request(&request, true);
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
