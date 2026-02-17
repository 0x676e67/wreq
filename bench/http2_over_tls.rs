//! HTTP/2 over TLS benchmark

mod support;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{HttpMode, Tls, bench};

const HTTP_MODE: HttpMode = HttpMode::Http2;
const TLS_MODE: Tls = Tls::Enabled;
const ADDR: &str = "127.0.0.1:6929";
const NUM_REQUESTS_TO_SEND: usize = 300;

#[inline]
fn bench_server_single_thread(c: &mut Criterion) {
    bench::bench_server_single_thread(c, HTTP_MODE, TLS_MODE, ADDR, NUM_REQUESTS_TO_SEND)
        .expect("Failed to run single-threaded HTTP/2 over TLS benchmark server")
}

#[inline]
fn bench_server_multi_thread(c: &mut Criterion) {
    bench::bench_server_multi_thread(c, HTTP_MODE, TLS_MODE, ADDR, NUM_REQUESTS_TO_SEND)
        .expect("Failed to run multi-threaded HTTP/2 over TLS benchmark server")
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_server_single_thread,
        bench_server_multi_thread
);
criterion_main!(benches);
