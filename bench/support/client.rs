mod cyper;
mod reqwest;
mod wreq;

use std::{convert::Infallible, fmt::Debug, future::Future, net::SocketAddr};

use bytes::Bytes;
use criterion::{BenchmarkGroup, async_executor::AsyncExecutor, measurement::WallTime};
use futures_util::{Stream, StreamExt};

use super::{BenchTarget, BodyCase, BodyKind, BoxError, ThreadMode};

/// Carries one server and matrix case from the runner into client registration.
#[derive(Clone, Copy)]
pub(super) struct ClientBenchCase {
    addr: SocketAddr,
    target: BenchTarget,
    num_requests: usize,
    concurrent_limit: usize,
    body: BodyCase,
}

// ===== impl ClientBenchCase =====

impl ClientBenchCase {
    pub(super) const fn new(
        addr: SocketAddr,
        target: BenchTarget,
        num_requests: usize,
        concurrent_limit: usize,
        body: BodyCase,
    ) -> Self {
        Self {
            addr,
            target,
            num_requests,
            concurrent_limit,
            body,
        }
    }
}

/// Binds a client case to the server URL for the duration of group execution.
#[derive(Clone, Copy)]
struct ClientCase<'a> {
    url: &'a str,
    target: BenchTarget,
    num_requests: usize,
    concurrent_limit: usize,
    body: BodyCase,
    body_kind: BodyKind,
}

/// Holds the immutable request inputs copied into each fixed worker.
#[derive(Clone, Copy)]
struct WorkerCase {
    body: BodyCase,
    stream: bool,
    expected_version: http::Version,
    expected_size: usize,
}

/// Adapts one concrete client and runtime pair to the shared worker scheduler.
trait ClientAdapter {
    type Client: Clone + 'static;
    type Executor;
    type JoinError: Debug;
    type JoinHandle: Future<Output = Result<(), Self::JoinError>>;

    const NAME: &'static str;

    fn create_client(target: BenchTarget) -> Result<Self::Client, BoxError>;

    fn create_executor(target: BenchTarget) -> Result<Self::Executor, BoxError>;

    fn spawn_worker(
        client: Self::Client,
        url: String,
        case: WorkerCase,
        num_requests: usize,
    ) -> Self::JoinHandle;
}

// ===== impl ClientCase =====

impl ClientCase<'_> {
    fn label(self, client: &str) -> String {
        format!("{}/{client}", self.body_kind)
    }
}

pub(super) fn bench_clients(
    group: &mut BenchmarkGroup<'_, WallTime>,
    bench_case: ClientBenchCase,
) -> Result<(), BoxError> {
    let url = format!("{}://{}", bench_case.target.tls, bench_case.addr);

    for body_kind in BodyKind::ALL {
        let client_case = ClientCase {
            url: &url,
            target: bench_case.target,
            num_requests: bench_case.num_requests,
            concurrent_limit: bench_case.concurrent_limit,
            body: bench_case.body,
            body_kind,
        };

        register::<wreq::Adapter>(group, client_case)?;
        register::<reqwest::Adapter>(group, client_case)?;
        if matches!(bench_case.target.thread_mode, ThreadMode::Current) {
            register::<cyper::Adapter>(group, client_case)?;
        }
    }

    Ok(())
}

fn stream_from_bytes(
    body: BodyCase,
) -> impl futures_util::stream::TryStream<Ok = Bytes, Error = Infallible> + Send + 'static {
    futures_util::stream::unfold((body.bytes, 0), move |(bytes, offset)| async move {
        if offset >= bytes.len() {
            None
        } else {
            let end = offset.saturating_add(body.chunk_size).min(bytes.len());
            let chunk = Bytes::from_static(&bytes[offset..end]);
            Some((Ok::<Bytes, Infallible>(chunk), (bytes, end)))
        }
    })
}

fn add_body_size(body_size: &mut usize, chunk_size: usize) {
    *body_size = body_size
        .checked_add(chunk_size)
        .expect("response body size should fit in usize");
}

async fn assert_response_body<S, E>(
    client: &str,
    version: http::Version,
    expected_version: http::Version,
    stream: S,
    expected_size: usize,
) where
    S: Stream<Item = Result<Bytes, E>>,
    E: Debug,
{
    assert_eq!(
        version, expected_version,
        "{client} used an unexpected HTTP version"
    );

    futures_util::pin_mut!(stream);
    let mut body_size = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.expect("response body should be readable");
        add_body_size(&mut body_size, chunk.len());
    }
    assert_eq!(
        body_size, expected_size,
        "{client} response body had an unexpected size"
    );
}

fn worker_request_counts(
    num_requests: usize,
    concurrent_limit: usize,
) -> impl Iterator<Item = usize> {
    assert!(
        concurrent_limit > 0,
        "benchmark concurrency should be greater than zero"
    );

    let worker_count = num_requests.min(concurrent_limit);
    let requests_per_worker = num_requests.checked_div(worker_count).unwrap_or(0);
    let remainder = num_requests.checked_rem(worker_count).unwrap_or(0);

    // Pre-splitting the work keeps shared counters out of the measured path.
    (0..worker_count).map(move |worker| requests_per_worker + usize::from(worker < remainder))
}

async fn requests<A>(client: &A::Client, case: ClientCase<'_>)
where
    A: ClientAdapter,
{
    let worker_case = WorkerCase {
        body: case.body,
        stream: case.body_kind.is_stream(),
        expected_version: case.target.http_version.expected(),
        expected_size: case.body.bytes.len(),
    };
    let handles = worker_request_counts(case.num_requests, case.concurrent_limit).map(|requests| {
        A::spawn_worker(client.clone(), case.url.to_owned(), worker_case, requests)
    });

    for result in futures_util::future::join_all(handles).await {
        result.expect("request task should complete without panicking");
    }
}

fn register<A>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    case: ClientCase<'_>,
) -> Result<(), BoxError>
where
    A: ClientAdapter,
    for<'a> &'a A::Executor: AsyncExecutor,
{
    let client = A::create_client(case.target)?;
    let executor = A::create_executor(case.target)?;
    group.bench_function(case.label(A::NAME), |bencher| {
        bencher
            .to_async(&executor)
            .iter(|| requests::<A>(&client, case));
    });
    ::std::mem::drop(client);
    Ok(())
}
