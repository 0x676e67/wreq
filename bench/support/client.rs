use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use criterion::{BenchmarkGroup, measurement::WallTime};
use http_body_util::BodyExt;
use tokio::{runtime::Runtime, sync::Semaphore};

use super::{BoxError, HttpVersion, Tls};

fn create_wreq_client(tls: Tls, http_version: HttpVersion) -> Result<wreq::Client, BoxError> {
    let builder = wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none())
        .tls_cert_verification(!matches!(tls, Tls::Enabled));

    let builder = match http_version {
        HttpVersion::Http1 => builder.http1_only(),
        HttpVersion::Http2 => builder.http2_only(),
    };

    Ok(builder.build()?)
}

fn create_reqwest_client(tls: Tls, http_version: HttpVersion) -> Result<reqwest::Client, BoxError> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(matches!(tls, Tls::Enabled));

    let builder = match http_version {
        HttpVersion::Http1 => builder.http1_only(),
        HttpVersion::Http2 => builder.http2_prior_knowledge(),
    };

    Ok(builder.build()?)
}

async fn wreq_body_assert(mut response: wreq::Response, expected_body_size: usize) {
    let mut body_size = 0;
    while let Some(Ok(chunk)) = response.frame().await {
        if let Ok(chunk) = chunk.into_data() {
            body_size += chunk.len();
        }
    }
    assert!(
        body_size == expected_body_size,
        "Unexpected response body: got {body_size} bytes, expected {expected_body_size} bytes"
    );
}

async fn reqwest_body_assert(mut response: reqwest::Response, expected_body_size: usize) {
    let mut body_size = 0;
    while let Ok(Some(chunk)) = response.chunk().await {
        body_size += chunk.len();
    }
    assert!(
        body_size == expected_body_size,
        "Unexpected response body: got {body_size} bytes, expected {expected_body_size} bytes"
    );
}

fn stream_from_bytes(
    body: &'static [u8],
    chunk_size: usize,
) -> impl futures_util::stream::TryStream<Ok = Bytes, Error = Infallible> + Send + 'static {
    futures_util::stream::unfold((body, 0), move |(body, offset)| async move {
        if offset >= body.len() {
            None
        } else {
            let end = (offset + chunk_size).min(body.len());
            let chunk = Bytes::from_static(&body[offset..end]);
            Some((Ok::<Bytes, Infallible>(chunk), (body, end)))
        }
    })
}

#[inline]
fn wreq_body(stream: bool, (body, chunk_size): (&'static [u8], usize)) -> wreq::Body {
    if stream {
        let stream = stream_from_bytes(body, chunk_size);
        wreq::Body::wrap_stream(stream)
    } else {
        wreq::Body::from(body)
    }
}

#[inline]
fn reqwest_body(stream: bool, (body, chunk_size): (&'static [u8], usize)) -> reqwest::Body {
    if stream {
        let stream = stream_from_bytes(body, chunk_size);
        reqwest::Body::wrap_stream(stream)
    } else {
        reqwest::Body::from(body)
    }
}

async fn wreq_requests_concurrent(
    client: &wreq::Client,
    url: &str,
    num_requests: usize,
    concurrent_limit: usize,
    body: (&'static [u8], usize),
    stream: bool,
) {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);
    for _ in 0..num_requests {
        let client = client.clone();
        let url = url.to_string();
        let semaphore = semaphore.clone();
        let fut = async move {
            let _permit = semaphore
                .acquire()
                .await
                .expect("Semaphore should be acquirable");
            let response = client
                .post(url)
                .body(wreq_body(stream, body))
                .send()
                .await
                .expect("Unexpected request failure");
            wreq_body_assert(response, body.0.len()).await;
        };
        handles.push(tokio::spawn(fut));
    }
    futures_util::future::join_all(handles).await;
}

async fn reqwest_requests_concurrent(
    client: &reqwest::Client,
    url: &str,
    num_requests: usize,
    concurrent_limit: usize,
    body: (&'static [u8], usize),
    stream: bool,
) {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);
    for _ in 0..num_requests {
        let client = client.clone();
        let url = url.to_string();
        let semaphore = semaphore.clone();
        let fut = async move {
            let _permit = semaphore
                .acquire()
                .await
                .expect("Semaphore should be acquirable");
            let response = client
                .post(url)
                .body(reqwest_body(stream, body))
                .send()
                .await
                .expect("Unexpected request failure");
            reqwest_body_assert(response, body.0.len()).await;
        };
        handles.push(tokio::spawn(fut));
    }
    futures_util::future::join_all(handles).await;
}

#[allow(clippy::too_many_arguments)]
pub fn bench_clients(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: fn() -> Runtime,
    addr: SocketAddr,
    tls: Tls,
    http_version: HttpVersion,
    num_requests: usize,
    concurrent_limit: usize,
    body: (&'static [u8], usize),
) -> Result<(), BoxError> {
    let url = format!("{tls}://{addr}");

    fn make_benchmark_label<T: ?Sized>(stream: bool) -> String {
        let client = std::any::type_name::<T>()
            .split("::")
            .next()
            .expect("Type name should contain at least one segment");

        let body_type = if stream { "stream" } else { "full" };
        format!("{body_type}/{client}")
    }

    for stream in [false, true] {
        let client = create_wreq_client(tls, http_version)?;
        group.bench_function(make_benchmark_label::<wreq::Client>(stream), |b| {
            b.to_async(rt()).iter(|| {
                wreq_requests_concurrent(
                    &client,
                    &url,
                    num_requests,
                    concurrent_limit,
                    body,
                    stream,
                )
            })
        });
        ::std::mem::drop(client);

        let client = create_reqwest_client(tls, http_version)?;
        group.bench_function(make_benchmark_label::<reqwest::Client>(stream), |b| {
            b.to_async(rt()).iter(|| {
                reqwest_requests_concurrent(
                    &client,
                    &url,
                    num_requests,
                    concurrent_limit,
                    body,
                    stream,
                )
            })
        });
        ::std::mem::drop(client);
    }

    Ok(())
}
