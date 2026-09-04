//! wreq adapter for the shared client benchmark scheduler.

use super::{ClientAdapter, WorkerCase, assert_response_body, stream_from_bytes};
use crate::support::{BenchTarget, BodyCase, BoxError, HttpVersion, runtime::tokio_runtime};

/// Stateless adapter for running wreq through the shared benchmark scheduler.
pub(super) struct Adapter;

/// Builds a complete or streamed wreq request body for one request.
fn body(body: BodyCase, stream: bool) -> ::wreq::Body {
    if stream {
        ::wreq::Body::wrap_stream(stream_from_bytes(body))
    } else {
        ::wreq::Body::from(body.bytes)
    }
}

/// Builds a wreq client with the selected connection-pool acquisition policy.
pub(super) fn create_client(
    target: BenchTarget,
    pool_strategy: ::wreq::PoolStrategy,
) -> Result<::wreq::Client, BoxError> {
    let builder = ::wreq::Client::builder()
        .no_proxy()
        .redirect(::wreq::redirect::Policy::none())
        .pool_strategy(pool_strategy)
        .tls_cert_verification(!target.tls.is_enabled());

    let builder = match target.http_version {
        HttpVersion::Http1 => builder.http1_only(),
        HttpVersion::Http2 => builder.http2_only(),
    };

    Ok(builder.build()?)
}

impl ClientAdapter for Adapter {
    type Client = ::wreq::Client;
    type Executor = tokio::runtime::Runtime;
    type JoinError = tokio::task::JoinError;
    type JoinHandle = tokio::task::JoinHandle<()>;

    const NAME: &'static str = "wreq";

    fn create_client(target: BenchTarget) -> Result<Self::Client, BoxError> {
        create_client(target, ::wreq::PoolStrategy::default())
    }

    fn create_executor(target: BenchTarget) -> Result<Self::Executor, BoxError> {
        Ok(tokio_runtime(target.thread_mode)?)
    }

    fn spawn_worker(
        client: Self::Client,
        url: String,
        case: WorkerCase,
        num_requests: usize,
    ) -> Self::JoinHandle {
        let future = async move {
            for _ in 0..num_requests {
                let response = client
                    .post(url.as_str())
                    .body(body(case.body, case.stream))
                    .send()
                    .await
                    .expect("wreq request should succeed");
                let version = response.version();
                assert_response_body(
                    Self::NAME,
                    version,
                    case.expected_version,
                    response.bytes_stream(),
                    case.expected_size,
                )
                .await;
            }
        };
        tokio::spawn(future)
    }
}
