//! This example runs a server that responds to any request with "Hello, world!"

mod support;

use std::time::Duration;
use support::{HttpMode, bench};

use criterion::{Criterion, criterion_group, criterion_main};

const HTTP_MODE: HttpMode = HttpMode::Http2;
const ADDR: &str = "127.0.0.1:6928";

#[inline]
fn bench_server_single_thread(c: &mut Criterion) {
    bench::bench_server_single_thread(c, HTTP_MODE, ADDR)
        .expect("Failed to run single-threaded HTTP/2 benchmark server")
}

#[inline]
fn bench_server_multi_thread(c: &mut Criterion) {
    bench::bench_server_multi_thread(c, HTTP_MODE, ADDR)
        .expect("Failed to run multi-threaded HTTP/2 benchmark server")
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
