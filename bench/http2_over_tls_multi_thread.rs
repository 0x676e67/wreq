//! Benchmarks HTTP/2 over TLS wreq and reqwest on four-worker Tokio.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use support::{BenchTarget, HttpVersion, ThreadMode, Tls};

/// Target dimensions for the HTTP/2 over TLS multi-thread benchmark.
const TARGET: BenchTarget = BenchTarget {
    tls: Tls::Enabled,
    http_version: HttpVersion::Http2,
    thread_mode: ThreadMode::Multi,
};

/// Runs the full workload matrix for this target.
///
/// Panics if a case fails to configure, execute, or shut down.
fn benchmark(c: &mut Criterion) {
    support::bench(c, TARGET, support::NUM_REQUESTS)
        .expect("failed to run HTTP/2 over TLS multi-thread benchmark");
}

criterion_group!(
    name = benches;
    config = support::criterion();
    targets = benchmark
);
criterion_main!(benches);
