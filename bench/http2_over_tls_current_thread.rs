//! HTTP/2 over TLS current-thread benchmark.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, HttpVersion, ThreadMode, Tls};

const TARGET: BenchTarget = BenchTarget {
    tls: Tls::Enabled,
    http_version: HttpVersion::Http2,
    thread_mode: ThreadMode::Current,
};

fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET, support::NUM_REQUESTS)
        .expect("failed to run HTTP/2 over TLS current-thread benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
