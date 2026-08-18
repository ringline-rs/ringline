//! Fuzz the HTTP/2 frame decoder directly: arbitrary bytes through
//! `decode_frame` at both the spec-default and a tiny max_frame_size,
//! consuming frames in sequence like the connection does.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringline_h2::frame::{decode_frame, decode_frame_header};

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(decode_frame_header(data));

    for max_frame_size in [16_384u32, 64] {
        let mut offset = 0;
        while offset < data.len() {
            match decode_frame(&data[offset..], max_frame_size) {
                Ok(Some((frame, consumed))) => {
                    std::hint::black_box(&frame);
                    if consumed == 0 {
                        break;
                    }
                    offset += consumed;
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
});
