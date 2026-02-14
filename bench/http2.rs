//! This example runs a server that responds to any request with "Hello, world!"

mod support;

use std::time::Duration;
use support::client::{bench_reqwest, bench_wreq};
use support::server::{spawn_multi_thread_server, spawn_single_thread_server, with_server};
use support::{HttpMode, build_current_thread_runtime, build_multi_thread_runtime};

use criterion::{
    BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};

const NUM_REQUESTS_TO_SEND: usize = 1000;
const CONCURRENT_LIMIT: usize = 100;
const HTTP_MODE: HttpMode = HttpMode::Http2;
const CURRENT_THREAD_LABEL: &str = "current_thread";
const MULTI_THREAD_LABEL: &str = "multi_thread";

fn run_benches(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: fn() -> tokio::runtime::Runtime,
    addr: &'static str,
    label_prefix: &str,
) {
    let runtime = rt();
    bench_wreq(
        group,
        &runtime,
        addr,
        HTTP_MODE,
        label_prefix,
        false,
        NUM_REQUESTS_TO_SEND,
        CONCURRENT_LIMIT,
    );

    bench_reqwest(
        group,
        &runtime,
        addr,
        HTTP_MODE,
        label_prefix,
        false,
        NUM_REQUESTS_TO_SEND,
        CONCURRENT_LIMIT,
    );

    bench_wreq(
        group,
        &runtime,
        addr,
        HTTP_MODE,
        label_prefix,
        true,
        NUM_REQUESTS_TO_SEND,
        CONCURRENT_LIMIT,
    );

    bench_reqwest(
        group,
        &runtime,
        addr,
        HTTP_MODE,
        label_prefix,
        true,
        NUM_REQUESTS_TO_SEND,
        CONCURRENT_LIMIT,
    );
}

// Criterion benchmark functions
fn bench_server_single_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_single_thread");
    group.sample_size(10);

    // single-threaded client
    with_server(
        "127.0.0.1:6928",
        HTTP_MODE,
        spawn_single_thread_server,
        || {
            run_benches(
                &mut group,
                build_current_thread_runtime,
                "127.0.0.1:6928",
                CURRENT_THREAD_LABEL,
            );
        },
    );

    // multi-threaded client
    with_server(
        "127.0.0.1:6930",
        HTTP_MODE,
        spawn_single_thread_server,
        || {
            run_benches(
                &mut group,
                build_multi_thread_runtime,
                "127.0.0.1:6930",
                MULTI_THREAD_LABEL,
            );
        },
    );
    group.finish();
}

fn bench_server_multi_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_multi_thread");
    group.sample_size(10);

    // single-threaded client
    with_server(
        "127.0.0.1:6929",
        HTTP_MODE,
        spawn_multi_thread_server,
        || {
            run_benches(
                &mut group,
                build_current_thread_runtime,
                "127.0.0.1:6929",
                CURRENT_THREAD_LABEL,
            );
        },
    );

    // multi-threaded client
    with_server(
        "127.0.0.1:6931",
        HTTP_MODE,
        spawn_multi_thread_server,
        || {
            run_benches(
                &mut group,
                build_multi_thread_runtime,
                "127.0.0.1:6931",
                MULTI_THREAD_LABEL,
            );
        },
    );
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_server_single_thread,
        bench_server_multi_thread
);
criterion_main!(benches);
