//! HTTP/1.1 over TLS multi-thread benchmark.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, HttpVersion, ThreadMode, Tls};

const TARGET: BenchTarget = BenchTarget {
    tls: Tls::Enabled,
    http_version: HttpVersion::Http1,
    thread_mode: ThreadMode::Multi,
};

fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET, support::NUM_REQUESTS)
        .expect("failed to run HTTP/1.1 over TLS multi-thread benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
