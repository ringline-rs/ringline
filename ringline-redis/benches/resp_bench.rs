use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use resp_proto::Value;

fn make_simple_string() -> Vec<u8> {
    b"+OK\r\n".to_vec()
}

fn make_bulk_string(size: usize) -> Vec<u8> {
    let mut buf = format!("${size}\r\n").into_bytes();
    buf.extend(std::iter::repeat_n(b'x', size));
    buf.extend_from_slice(b"\r\n");
    buf
}

fn make_array_of_bulk_strings(count: usize, value_size: usize) -> Vec<u8> {
    let mut buf = format!("*{count}\r\n").into_bytes();
    for _ in 0..count {
        buf.extend_from_slice(&make_bulk_string(value_size));
    }
    buf
}

fn make_integer() -> Vec<u8> {
    b":42\r\n".to_vec()
}

fn bench_parse_simple_string(c: &mut Criterion) {
    let data = Bytes::from(make_simple_string());
    c.bench_function("resp_parse/simple_string", |b| {
        b.iter(|| {
            let result = Value::parse_bytes(black_box(data.clone()));
            black_box(&result);
        });
    });
}

fn bench_parse_integer(c: &mut Criterion) {
    let data = Bytes::from(make_integer());
    c.bench_function("resp_parse/integer", |b| {
        b.iter(|| {
            let result = Value::parse_bytes(black_box(data.clone()));
            black_box(&result);
        });
    });
}

fn bench_parse_bulk_string(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp_parse/bulk_string");

    for size in [64, 1024, 16384] {
        let data = Bytes::from(make_bulk_string(size));
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("{size}B"), |b| {
            b.iter(|| {
                let result = Value::parse_bytes(black_box(data.clone()));
                black_box(&result);
            });
        });
    }

    group.finish();
}

fn bench_parse_array(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp_parse/array");

    for (count, value_size) in [(10, 64), (100, 64), (10, 1024)] {
        let data = Bytes::from(make_array_of_bulk_strings(count, value_size));
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_function(format!("{count}x{value_size}B"), |b| {
            b.iter(|| {
                let result = Value::parse_bytes(black_box(data.clone()));
                black_box(&result);
            });
        });
    }

    group.finish();
}

fn bench_encode_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("resp_encode");

    group.bench_function("get", |b| {
        let req = resp_proto::Request::new(vec![b"GET", b"mykey"]);
        let len = req.encoded_len();
        let mut buf = vec![0u8; len];
        b.iter(|| {
            req.encode(black_box(&mut buf));
            black_box(&buf);
        });
    });

    group.bench_function("set_64B", |b| {
        let value = vec![b'x'; 64];
        let req = resp_proto::Request::new(vec![b"SET", b"mykey", &value]);
        let len = req.encoded_len();
        let mut buf = vec![0u8; len];
        b.iter(|| {
            req.encode(black_box(&mut buf));
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_simple_string,
    bench_parse_integer,
    bench_parse_bulk_string,
    bench_parse_array,
    bench_encode_request,
);
criterion_main!(benches);
