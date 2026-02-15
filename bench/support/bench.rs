use std::error::Error;

use criterion::{BenchmarkGroup, Criterion, measurement::WallTime};

use crate::support::client::bench_both_clients;
use crate::support::server::{spawn_multi_thread_server, spawn_single_thread_server, with_server};
use crate::support::{HttpMode, build_current_thread_runtime, build_multi_thread_runtime};

pub const NUM_REQUESTS_TO_SEND: usize = 1000;
pub const CONCURRENT_LIMIT: usize = 100;
pub const CURRENT_THREAD_LABEL: &str = "current_thread";
pub const MULTI_THREAD_LABEL: &str = "multi_thread";

pub static BODY_CASES: &[&'static [u8]] = &[
    &[b'a'; 10 * 1024],       // 10 KB
    &[b'a'; 64 * 1024],       // 64 KB
    &[b'a'; 256 * 1024],      // 256 KB
    &[b'a'; 1 * 1024 * 1024], // 1024 KB
    &[b'a'; 2 * 1024 * 1024], // 2048 KB
    &[b'a'; 4 * 1024 * 1024], // 4096 KB
];

pub fn run_benches(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: fn() -> tokio::runtime::Runtime,
    addr: &'static str,
    mode: HttpMode,
    label_prefix: &str,
) -> Result<(), Box<dyn Error>> {
    let runtime = rt();
    for body in BODY_CASES {
        // Sequential tests
        bench_both_clients(
            group,
            &runtime,
            addr,
            mode,
            label_prefix,
            false,
            NUM_REQUESTS_TO_SEND,
            CONCURRENT_LIMIT,
            body,
        )?;

        // Concurrent tests
        bench_both_clients(
            group,
            &runtime,
            addr,
            mode,
            label_prefix,
            true,
            NUM_REQUESTS_TO_SEND,
            CONCURRENT_LIMIT,
            body,
        )?;
    }

    Ok(())
}

pub fn bench_server_single_thread(
    c: &mut Criterion,
    mode: HttpMode,
    addr: &'static str,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_single_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, mode, spawn_single_thread_server, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            mode,
            CURRENT_THREAD_LABEL,
        )?;

        // multi-threaded client
        run_benches(
            &mut group,
            build_multi_thread_runtime,
            addr,
            mode,
            MULTI_THREAD_LABEL,
        )
    });

    group.finish();

    Ok(())
}

pub fn bench_server_multi_thread(
    c: &mut Criterion,
    mode: HttpMode,
    addr: &'static str,
) -> Result<(), Box<dyn Error>> {
    let mut group = c.benchmark_group("server_multi_thread");
    group.sampling_mode(criterion::SamplingMode::Flat);

    with_server(addr, mode, spawn_multi_thread_server, || {
        // single-threaded client
        run_benches(
            &mut group,
            build_current_thread_runtime,
            addr,
            mode,
            CURRENT_THREAD_LABEL,
        )?;

        // multi-threaded client
        with_server(addr, mode, spawn_multi_thread_server, || {
            run_benches(
                &mut group,
                build_multi_thread_runtime,
                addr,
                mode,
                MULTI_THREAD_LABEL,
            )
        })
    })?;

    group.finish();
    Ok(())
}
