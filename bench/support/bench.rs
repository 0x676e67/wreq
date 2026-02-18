use std::error::Error;

use criterion::Criterion;

use crate::support::{
    HttpMode, Tls, client::bench_clients, current_thread_runtime, multi_thread_runtime,
    server::with_server,
};

pub const CURRENT_THREAD_LABEL: &str = "current_thread";
pub const MULTI_THREAD_LABEL: &str = "multi_thread";
pub const CONCURRENT_CASES: &[usize] = &[10, 20, 50, 100, 150];
pub const BODY_CASES: &[&[u8]] = &[
    &[b'a'; 10 * 1024],       // 10 KB
    &[b'a'; 64 * 1024],       // 64 KB
    &[b'a'; 128 * 1024],      // 128 KB
    &[b'a'; 1024 * 1024],     // 1024 KB
    &[b'a'; 2 * 1024 * 1024], // 2048 KB
    &[b'a'; 4 * 1024 * 1024], // 4096 KB
];

pub fn bench(
    c: &mut Criterion,
    tls_mode: Tls,
    http_mode: HttpMode,
    addr: &'static str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    for &concurrent_limit in CONCURRENT_CASES {
        for body in BODY_CASES {
            with_server(addr, tls_mode, || {
                // single-threaded client
                let mut group = c.benchmark_group(format!(
                    "{CURRENT_THREAD_LABEL}/{tls_mode}/{concurrent_limit}/{}KB",
                    body.len() / 1024,
                ));

                bench_clients(
                    &mut group,
                    current_thread_runtime,
                    addr,
                    http_mode,
                    tls_mode,
                    num_requests,
                    concurrent_limit,
                    body,
                )?;
                group.finish();
                Ok(())
            })?;

            with_server(addr, tls_mode, || {
                // multi-threaded client
                let mut group = c.benchmark_group(format!(
                    "{MULTI_THREAD_LABEL}/{tls_mode}/{concurrent_limit}/{}KB",
                    body.len() / 1024,
                ));
                bench_clients(
                    &mut group,
                    multi_thread_runtime,
                    addr,
                    http_mode,
                    tls_mode,
                    num_requests,
                    concurrent_limit,
                    body,
                )?;
                group.finish();
                Ok(())
            })?;
        }
    }

    Ok(())
}
