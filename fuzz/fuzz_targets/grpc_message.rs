//! Fuzz gRPC message framing: direct `decode` at two size limits, and
//! `MessageBuffer` reassembly with fuzzer-chosen chunk boundaries.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ringline_grpc::message::{BufferDecode, MessageBuffer, decode};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    splits: [u8; 4],
    data: &'a [u8],
}

fuzz_target!(|input: Input| {
    for max_size in [4 << 20, 16usize] {
        std::hint::black_box(decode(input.data, max_size));
    }

    let mut buffer = MessageBuffer::new(1 << 16);
    let mut rest = input.data;
    let mut chunks = input.splits.iter().cycle();
    while !rest.is_empty() {
        let n = (*chunks.next().unwrap() as usize % rest.len()) + 1;
        let (chunk, tail) = rest.split_at(n.min(rest.len()));
        rest = tail;
        if buffer.push(chunk).is_err() {
            return;
        }
        loop {
            match buffer.try_decode() {
                BufferDecode::Complete(payload, compressed) => {
                    std::hint::black_box((payload.len(), compressed));
                }
                BufferDecode::Incomplete => break,
                BufferDecode::TooLarge(n) => {
                    std::hint::black_box(n);
                    return;
                }
            }
        }
    }
});
