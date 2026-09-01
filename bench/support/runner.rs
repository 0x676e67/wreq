use std::time::Duration;

use criterion::{Criterion, Throughput};

use super::{
    BenchTarget, BoxError,
    case::{BODY_CASES, CONCURRENT_CASES},
    client::{ClientBenchCase, bench_clients},
    server::with_server,
};

pub fn criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(3))
}

pub fn bench(
    criterion: &mut Criterion,
    target: BenchTarget,
    num_requests: usize,
) -> Result<(), BoxError> {
    const OS: &str = std::env::consts::OS;
    const ARCH: &str = std::env::consts::ARCH;

    let system = sysinfo::System::new_all();
    let cpu_model = system
        .cpus()
        .first()
        .map_or("n/a", |cpu| cpu.brand().trim());
    let throughput = u64::try_from(num_requests)?;

    for &concurrent_limit in CONCURRENT_CASES {
        for &body in BODY_CASES {
            with_server(target.tls, |addr| {
                let mut group = criterion.benchmark_group(format!(
                    "{cpu_model}/{OS}_{ARCH}/{}/{}/{}/{concurrent_limit}/{}KB",
                    target.thread_mode,
                    target.tls,
                    target.http_version,
                    body.bytes.len() / 1024,
                ));
                group.throughput(Throughput::Elements(throughput));
                bench_clients(
                    &mut group,
                    ClientBenchCase::new(addr, target, num_requests, concurrent_limit, body),
                )?;
                group.finish();
                Ok(())
            })?;
        }
    }

    Ok(())
}
