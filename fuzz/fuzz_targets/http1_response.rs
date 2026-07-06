//! Fuzz the HTTP/1.1 response parsers (status line + headers with the
//! request-smuggling defenses, and chunked transfer decoding with
//! trailers) via the `fuzzing`-feature seams in ringline-http.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ringline_http::h1_conn::{fuzz_decode_chunk, fuzz_parse_response_headers};

fuzz_target!(|data: &[u8]| {
    fuzz_parse_response_headers(data);
    fuzz_decode_chunk(data, usize::MAX, 16 * 1024);
    fuzz_decode_chunk(data, 64, 8);
});
