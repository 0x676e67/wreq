//! cyper adapter for the shared client benchmark scheduler.

use futures::TryStreamExt;

use super::{ClientAdapter, WorkerCase, assert_response_body, stream_from_bytes};
use crate::support::{BenchTarget, BodyCase, BoxError, HttpVersion, runtime::CompioBenchExecutor};

/// Stateless adapter for running cyper through the shared benchmark scheduler.
pub(super) struct Adapter;

/// Builds a complete or streamed cyper request body for one request.
fn body(body: BodyCase, stream: bool) -> ::cyper::Body {
    if stream {
        let stream = stream_from_bytes(body).map_err(|never| match never {});
        ::cyper::Body::stream(stream)
    } else {
        ::cyper::Body::from(body.bytes)
    }
}

impl ClientAdapter for Adapter {
    type Client = ::cyper::Client;
    type Executor = CompioBenchExecutor;
    type JoinError = compio::runtime::JoinError;
    type JoinHandle = compio::runtime::JoinHandle<()>;

    const NAME: &'static str = "cyper";

    fn create_client(target: BenchTarget) -> Result<Self::Client, BoxError> {
        let builder = ::cyper::Client::builder()
            .no_proxy()
            .redirect(::cyper::redirect::Policy::none())
            .danger_accept_invalid_certs(target.tls.is_enabled());

        let builder = match target.http_version {
            HttpVersion::Http1 => builder,
            HttpVersion::Http2 => builder.http2_prior_knowledge(),
        };

        Ok(builder.build()?)
    }

    fn create_executor(_target: BenchTarget) -> Result<Self::Executor, BoxError> {
        Ok(CompioBenchExecutor::new()?)
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
                    .expect("cyper request should be valid")
                    .body(body(case.body, case.stream))
                    .send()
                    .await
                    .expect("cyper request should succeed");
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
        compio::runtime::spawn(future)
    }
}
