//! Fuzz the HPACK decoder: one whole-input decode, then the same input
//! split into blocks against a small-table decoder so dynamic-table
//! insertions, evictions, and size updates carry state across calls.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringline_h2::hpack::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(4096);
    std::hint::black_box(decoder.decode(data).ok());

    let mut small = Decoder::new(256);
    for block in data.chunks(31) {
        std::hint::black_box(small.decode(block).ok());
    }
});
