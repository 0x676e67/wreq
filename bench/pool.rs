//! Connection-pool strategy benchmarks.
//!
//! Each client is reused across Criterion iterations, so these cases measure
//! steady-state request throughput and body reads rather than client creation.
//! They do not measure cold starts or count physical connections.

#[allow(dead_code, unused_imports)]
mod support;

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use support::{
    BenchTarget, BodyCase, HttpVersion, ThreadMode, Tls, client::bench_wreq_pool_strategies,
    server::with_server,
};

const NUM_REQUESTS_TO_SEND: usize = 500;
const CONCURRENT_CASES: &[usize] = &[10, 100];
const HTTP_VERSIONS: &[HttpVersion] = &[HttpVersion::Http1, HttpVersion::Http2];
const BODY: BodyCase = BodyCase {
    bytes: &[b'a'; 1024],
    chunk_size: 1024,
};
const REUSE_FIRST_TIMEOUT: Duration = Duration::from_millis(10);

#[inline]
fn bench(c: &mut Criterion) {
    for &http_version in HTTP_VERSIONS {
        for &concurrent_limit in CONCURRENT_CASES {
            with_server(Tls::Disabled, |addr| {
                let mut group = c.benchmark_group(format!(
                    "pool/current_thread/{http_version}/{concurrent_limit}/1KB"
                ));
                group.throughput(Throughput::Elements(NUM_REQUESTS_TO_SEND as u64));

                bench_wreq_pool_strategies(
                    &mut group,
                    addr,
                    BenchTarget {
                        tls: Tls::Disabled,
                        http_version,
                        thread_mode: ThreadMode::Current,
                    },
                    NUM_REQUESTS_TO_SEND,
                    concurrent_limit,
                    BODY,
                    REUSE_FIRST_TIMEOUT,
                )?;
                group.finish();
                Ok(())
            })
            .expect("Failed to run connection-pool benchmark server");
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(5));
    targets = bench
);
criterion_main!(benches);
