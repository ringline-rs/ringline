use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use ringline_h2::H2Connection;
use ringline_h2::frame::{self, Frame};
use ringline_h2::hpack::{Decoder, Encoder, HeaderField};
use ringline_h2::settings::Settings;

fn bench_hpack_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpack_encode");

    let headers = vec![
        HeaderField::new(b":method", b"GET"),
        HeaderField::new(b":path", b"/index.html"),
        HeaderField::new(b":scheme", b"https"),
        HeaderField::new(b":authority", b"example.com"),
        HeaderField::new(b"user-agent", b"ringline/0.1"),
        HeaderField::new(b"accept", b"text/html,application/xhtml+xml"),
    ];

    group.throughput(Throughput::Elements(headers.len() as u64));

    group.bench_function("6_headers", |b| {
        let mut encoder = Encoder::new(4096);
        let mut buf = Vec::with_capacity(256);
        b.iter(|| {
            buf.clear();
            encoder.encode(black_box(&headers), &mut buf);
            black_box(&buf);
        });
    });

    group.finish();
}

fn bench_hpack_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpack_decode");

    let headers = vec![
        HeaderField::new(b":status", b"200"),
        HeaderField::new(b"content-type", b"text/html; charset=utf-8"),
        HeaderField::new(b"content-length", b"1234"),
        HeaderField::new(b"server", b"nginx"),
        HeaderField::new(b"date", b"Thu, 26 Mar 2026 12:00:00 GMT"),
        HeaderField::new(b"cache-control", b"max-age=3600"),
    ];

    // Encode once to get the wire format.
    let mut encoder = Encoder::new(4096);
    let mut encoded = Vec::new();
    encoder.encode(&headers, &mut encoded);

    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("6_headers", |b| {
        let mut decoder = Decoder::new(4096);
        b.iter(|| {
            let result = decoder.decode(black_box(&encoded));
            black_box(&result);
        });
    });

    group.finish();
}

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_encode");

    group.bench_function("data_1kb", |b| {
        let payload = vec![0u8; 1024];
        let frame = Frame::Data {
            stream_id: 1,
            payload: payload.clone(),
            end_stream: false,
        };
        let mut buf = Vec::with_capacity(1100);
        b.iter(|| {
            buf.clear();
            frame.encode(&mut buf);
            black_box(&buf);
        });
    });

    group.bench_function("headers", |b| {
        let frame = Frame::Headers {
            stream_id: 1,
            encoded: vec![0x82, 0x86, 0x84, 0x41, 0x8a], // small HPACK
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::with_capacity(64);
        b.iter(|| {
            buf.clear();
            frame.encode(&mut buf);
            black_box(&buf);
        });
    });

    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame_decode");

    // Encode a data frame to get wire format.
    let payload = vec![0xABu8; 1024];
    let frame = Frame::Data {
        stream_id: 1,
        payload,
        end_stream: false,
    };
    let mut encoded = Vec::new();
    frame.encode(&mut encoded);

    group.throughput(Throughput::Bytes(encoded.len() as u64));

    group.bench_function("data_1kb", |b| {
        b.iter(|| {
            let result = frame::decode_frame(black_box(&encoded), 16384);
            black_box(&result);
        });
    });

    group.finish();
}

fn bench_h2_request_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("h2_roundtrip");

    // Pre-build server settings frame.
    let settings_frame = {
        let f = Frame::Settings {
            ack: false,
            settings: Settings::default(),
        };
        let mut buf = Vec::new();
        f.encode(&mut buf);
        buf
    };

    // Pre-build a response (HEADERS with :status 200, end_stream).
    let response_frame = {
        let mut enc = Encoder::new(4096);
        let mut encoded = Vec::new();
        enc.encode(&[HeaderField::new(b":status", b"200")], &mut encoded);
        let f = Frame::Headers {
            stream_id: 0, // placeholder — will be patched per iteration
            encoded,
            end_stream: true,
            end_headers: true,
            priority: None,
        };
        let mut buf = Vec::new();
        f.encode(&mut buf);
        buf
    };

    group.bench_function("send_request_recv_response", |b| {
        b.iter(|| {
            let mut conn = H2Connection::new(Settings::client_default());
            let _ = conn.take_pending_send();

            // Settings exchange.
            conn.recv(&settings_frame).unwrap();
            let _ = conn.take_pending_send();

            // Send request.
            let headers = vec![
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":path", b"/"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"example.com"),
            ];
            let stream_id = conn.send_request(&headers, true).unwrap();
            let _ = conn.take_pending_send();

            // Patch stream_id in response frame and feed it.
            let mut resp = response_frame.clone();
            let sid_bytes = stream_id.to_be_bytes();
            resp[5] = sid_bytes[0] & 0x7F;
            resp[6] = sid_bytes[1];
            resp[7] = sid_bytes[2];
            resp[8] = sid_bytes[3];
            conn.recv(&resp).unwrap();

            while let Some(event) = conn.poll_event() {
                black_box(&event);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hpack_encode,
    bench_hpack_decode,
    bench_frame_encode,
    bench_frame_decode,
    bench_h2_request_response,
);
criterion_main!(benches);
