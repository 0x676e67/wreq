//! Benchmarks plaintext HTTP/1.1 wreq and reqwest on four-worker Tokio.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, HttpVersion, ThreadMode, Tls};

/// Target dimensions for the plaintext HTTP/1.1 multi-thread benchmark.
const TARGET: BenchTarget = BenchTarget {
    tls: Tls::Disabled,
    http_version: HttpVersion::Http1,
    thread_mode: ThreadMode::Multi,
};

/// Runs the full workload matrix for this target.
///
/// Panics if a case fails to configure, execute, or shut down.
fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET, support::NUM_REQUESTS)
        .expect("failed to run HTTP/1.1 multi-thread benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
