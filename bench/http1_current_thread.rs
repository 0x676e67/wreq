//! HTTP/1.1 current-thread benchmark.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, HttpVersion, ThreadMode, Tls};

const TARGET: BenchTarget = BenchTarget {
    tls: Tls::Disabled,
    http_version: HttpVersion::Http1,
    thread_mode: ThreadMode::Current,
};

fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET, support::NUM_REQUESTS)
        .expect("failed to run HTTP/1.1 current-thread benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
