use std::error::Error;

use criterion::{BenchmarkGroup, Criterion, measurement::WallTime};

use crate::support::{
    HttpMode, Tls, build_current_thread_runtime, build_multi_thread_runtime,
    client::bench_both_clients, server::with_server,
};

pub const CONCURRENT_LIMIT: usize = 150;
pub const CURRENT_THREAD_LABEL: &str = "current_thread";
pub const MULTI_THREAD_LABEL: &str = "multi_thread";
pub const BODY_CASES: &[&[u8]] = &[
    &[b'a'; 10 * 1024],       // 10 KB
    &[b'a'; 100 * 1024],      // 100 KB
    &[b'a'; 256 * 1024],      // 256 KB
    &[b'a'; 1024 * 1024],     // 1024 KB
    &[b'a'; 2 * 1024 * 1024], // 2048 KB
    &[b'a'; 4 * 1024 * 1024], // 4096 KB
];

pub fn run_benches(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: fn() -> tokio::runtime::Runtime,
    addr: &'static str,
    tls_mode: Tls,
    http_mode: HttpMode,
    label_prefix: &str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let runtime = rt();
    for body in BODY_CASES {
        bench_both_clients(
            group,
            &runtime,
            addr,
            http_mode,
            tls_mode,
            label_prefix,
            num_requests,
            CONCURRENT_LIMIT,
            body,
        )?;
    }

    Ok(())
}

pub fn bench_server_single_thread(
    c: &mut Criterion,
    tls_mode: Tls,
    http_mode: HttpMode,
    addr: &'static str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_single_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, false, tls_mode, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            tls_mode,
            http_mode,
            CURRENT_THREAD_LABEL,
            num_requests,
        )?;

        // multi-threaded client
        run_benches(
            &mut group,
            build_multi_thread_runtime,
            addr,
            tls_mode,
            http_mode,
            MULTI_THREAD_LABEL,
            num_requests,
        )
    })?;

    group.finish();

    Ok(())
}

pub fn bench_server_multi_thread(
    c: &mut Criterion,
    tls_mode: Tls,
    http_mode: HttpMode,
    addr: &'static str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_multi_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, true, tls_mode, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            tls_mode,
            http_mode,
            CURRENT_THREAD_LABEL,
            num_requests,
        )?;

        // multi-threaded client
        run_benches(
            &mut group,
            build_multi_thread_runtime,
            addr,
            tls_mode,
            http_mode,
            MULTI_THREAD_LABEL,
            num_requests,
        )
    })?;

    group.finish();
    Ok(())
}
