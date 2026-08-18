//! Fuzz the QPACK (static-table-only) header block decoder.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringline_h3::qpack::decode;

fuzz_target!(|data: &[u8]| {
    if let Ok(fields) = decode(data) {
        for field in &fields {
            std::hint::black_box(field.name.len() + field.value.len());
        }
    }
});
