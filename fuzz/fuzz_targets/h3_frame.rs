//! Fuzz the HTTP/3 varint and frame decoders, including the zero-copy
//! `decode_frame_in` variant over `Bytes`, consuming frames in sequence.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringline_h3::frame::{decode_frame, decode_frame_in, decode_varint};

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(decode_varint(data));

    let mut offset = 0;
    while offset < data.len() {
        match decode_frame(&data[offset..]) {
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

    let parent = bytes::Bytes::copy_from_slice(data);
    let mut offset = 0;
    while offset < parent.len() {
        match decode_frame_in(&parent, offset) {
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
});
