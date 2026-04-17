//! HTTP/2 over TLS benchmark

mod support;

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{HttpVersion, Tls, bench};

const NUM_REQUESTS_TO_SEND: usize = 500;

#[inline]
fn bench(c: &mut Criterion) {
    bench::bench(c, Tls::Enabled, HttpVersion::Http2, NUM_REQUESTS_TO_SEND)
        .expect("Failed to run HTTP/2 over TLS benchmark server")
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(3));
    targets = bench
);
criterion_main!(benches);
