use std::error::Error;

use criterion::{BenchmarkGroup, Criterion, measurement::WallTime};

use crate::support::{
    HttpMode, Tls, build_current_thread_runtime, build_multi_thread_runtime,
    client::bench_both_clients, server::with_server,
};

pub const CONCURRENT_LIMIT: usize = 100;
pub const CURRENT_THREAD_LABEL: &str = "current_thread";
pub const MULTI_THREAD_LABEL: &str = "multi_thread";
pub const BODY_CASES: &[&[u8]] = &[
    &[b'a'; 10 * 1024],        // 10 KB
    &[b'a'; 100 * 1024],       // 100 KB
    &[b'a'; 256 * 1024],       // 256 KB
    &[b'a'; 1024 * 1024],      // 1024 KB
    &[b'a'; 2 * 1024 * 1024],  // 2048 KBa
    &[b'a'; 4 * 1024 * 1024],  // 4096 KB
    &[b'a'; 8 * 1024 * 1024],  // 8192 KB
    &[b'a'; 16 * 1024 * 1024], // 16384 KB
];

pub fn run_benches(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: fn() -> tokio::runtime::Runtime,
    addr: &'static str,
    mode: HttpMode,
    tls: Tls,
    label_prefix: &str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let runtime = rt();
    for body in BODY_CASES {
        bench_both_clients(
            group,
            &runtime,
            addr,
            mode,
            tls,
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
    mode: HttpMode,
    tls: Tls,
    addr: &'static str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_single_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, false, tls, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            mode,
            tls,
            CURRENT_THREAD_LABEL,
            num_requests,
        )?;

        // multi-threaded client
        run_benches(
            &mut group,
            build_multi_thread_runtime,
            addr,
            mode,
            tls,
            MULTI_THREAD_LABEL,
            num_requests,
        )
    })?;

    group.finish();

    Ok(())
}

pub fn bench_server_multi_thread(
    c: &mut Criterion,
    mode: HttpMode,
    tls: Tls,
    addr: &'static str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_multi_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, true, tls, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            mode,
            tls,
            CURRENT_THREAD_LABEL,
            num_requests,
        )?;

        // multi-threaded client
        run_benches(
            &mut group,
            build_multi_thread_runtime,
            addr,
            mode,
            tls,
            MULTI_THREAD_LABEL,
            num_requests,
        )
    })?;

    group.finish();
    Ok(())
}
