use criterion::Criterion;

use crate::support::{
    BoxError, HttpVersion, Tls, client::bench_clients, current_thread_runtime,
    multi_thread_runtime, server::with_server,
};

pub const CURRENT_THREAD_LABEL: &str = "current_thread";
pub const MULTI_THREAD_LABEL: &str = "multi_thread";
pub const CONCURRENT_CASES: &[usize] = &[10, 50, 100, 150];

/// Recommended chunk sizes for real-world network scenarios:
///   - 16 KB: Matches standard TCP buffers, ideal for HTTP/2 frames.
///   - 32 KB: For large HTTP payloads, fits modern socket buffers.
///   - 64 KB: Default Linux buffer size, optimized for large uploads.
///   - 128 KB: For high-throughput, large-scale transfers.
///   - 256 KB: Bulk data, maximum throughput on fast networks.
///
/// For benchmarking latency-sensitive and high-throughput transfers.
pub const BODY_CASES: [(&[u8], usize); 7] = [
    (&[b'a'; 1024], 1024),                  // 1 KB, chunk 1 KB
    (&[b'a'; 10 * 1024], 10 * 1024),        // 10 KB, chunk 10 KB
    (&[b'a'; 64 * 1024], 16 * 1024),        // 64 KB, chunk 16 KB
    (&[b'a'; 128 * 1024], 32 * 1024),       // 128 KB, chunk 32 KB
    (&[b'a'; 1024 * 1024], 64 * 1024),      // 1 MB, chunk 64 KB
    (&[b'a'; 2 * 1024 * 1024], 128 * 1024), // 2 MB, chunk 128 KB
    (&[b'a'; 4 * 1024 * 1024], 256 * 1024), // 4 MB, chunk 256 KB
];

pub fn bench(
    c: &mut Criterion,
    tls: Tls,
    http_version: HttpVersion,
    num_requests: usize,
) -> Result<(), BoxError> {
    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    let system = sysinfo::System::new_all();
    let cpu_model = system
        .cpus()
        .first()
        .map_or("n/a", |cpu| cpu.brand().trim_start().trim_end());

    for &concurrent_limit in CONCURRENT_CASES {
        for body in BODY_CASES {
            with_server(tls, |addr| {
                // single-threaded client
                let mut group = c.benchmark_group(format!(
                    "{cpu_model}/{OS}_{ARCH}/{CURRENT_THREAD_LABEL}/{tls}/{http_version}/{concurrent_limit}/{}KB",
                    body.0.len() / 1024,
                ));

                bench_clients(
                    &mut group,
                    current_thread_runtime,
                    addr,
                    tls,
                    http_version,
                    num_requests,
                    concurrent_limit,
                    body,
                )?;
                group.finish();
                Ok(())
            })?;

            with_server(tls, |addr| {
                // multi-threaded client
                let mut group = c.benchmark_group(format!(
                    "{cpu_model}/{OS}_{ARCH}/{MULTI_THREAD_LABEL}/{tls}/{http_version}/{concurrent_limit}/{}KB",
                    body.0.len() / 1024,
                ));
                bench_clients(
                    &mut group,
                    multi_thread_runtime,
                    addr,
                    tls,
                    http_version,
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
