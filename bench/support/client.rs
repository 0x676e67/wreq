use std::{convert::Infallible, error::Error, sync::Arc};

use bytes::Bytes;
use criterion::{BenchmarkGroup, measurement::WallTime};
use tokio::{runtime::Runtime, sync::Semaphore};

use super::{HttpMode, Tls};

const STREAM_CHUNK_SIZE: usize = 256 * 1024;

#[inline]
fn box_err<E: Error + Send + 'static>(e: E) -> Box<dyn Error + Send> {
    Box::new(e)
}

fn create_wreq_client(mode: HttpMode, tls: Tls) -> Result<wreq::Client, Box<dyn Error>> {
    let builder = wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none());

    let builder = match tls {
        Tls::Enabled => builder.cert_verification(false),
        Tls::Disabled => builder,
    };

    let builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_only(),
    };

    Ok(builder.build()?)
}

fn create_reqwest_client(mode: HttpMode, tls: Tls) -> Result<reqwest::Client, Box<dyn Error>> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());

    let builder = match tls {
        Tls::Enabled => builder.danger_accept_invalid_certs(true),
        Tls::Disabled => builder,
    };

    let builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_prior_knowledge(),
    };

    Ok(builder.build()?)
}

async fn wreq_body_assert(mut response: wreq::Response, expected_body_size: usize) {
    let mut body_size = 0;
    while let Ok(Some(chunk)) = response.chunk().await {
        body_size += chunk.len();
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
) -> impl futures_util::stream::TryStream<Ok = Bytes, Error = Infallible> + Send + 'static {
    futures_util::stream::unfold((body, 0), |(body, offset)| async move {
        if offset >= body.len() {
            None
        } else {
            let end = (offset + STREAM_CHUNK_SIZE).min(body.len());
            let chunk = Bytes::from_static(&body[offset..end]);
            Some((Ok::<Bytes, Infallible>(chunk), (body, end)))
        }
    })
}

#[inline]
fn wreq_body(stream: bool, body: &'static [u8]) -> wreq::Body {
    if stream {
        let stream = stream_from_bytes(body);
        wreq::Body::wrap_stream(stream)
    } else {
        wreq::Body::from(body)
    }
}

#[inline]
fn reqwest_body(stream: bool, body: &'static [u8]) -> reqwest::Body {
    if stream {
        let stream = stream_from_bytes(body);
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
    body: &'static [u8],
    stream: bool,
) -> Result<(), Box<dyn Error + Send>> {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let url = url.to_owned();
        let client = client.clone();
        let semaphore = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.map_err(box_err)?;
            let response = client
                .post(url)
                .body(wreq_body(stream, body))
                .send()
                .await
                .map_err(box_err)?;

            wreq_body_assert(response, body.len()).await;
            Ok(())
        });

        handles.push(task);
    }

    futures_util::future::join_all(handles)
        .await
        .into_iter()
        .try_for_each(|res| res.map_err(box_err)?)
}

async fn reqwest_requests_concurrent(
    client: &reqwest::Client,
    url: &str,
    num_requests: usize,
    concurrent_limit: usize,
    body: &'static [u8],
    stream: bool,
) -> Result<(), Box<dyn Error + Send>> {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);

    for _ in 0..num_requests {
        let url = url.to_owned();
        let client = client.clone();
        let semaphore = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.map_err(box_err)?;
            let response = client
                .post(url)
                .body(reqwest_body(stream, body))
                .send()
                .await
                .map_err(box_err)?;

            reqwest_body_assert(response, body.len()).await;
            Ok(())
        });

        handles.push(task);
    }

    futures_util::future::join_all(handles)
        .await
        .into_iter()
        .try_for_each(|res| res.map_err(box_err)?)
}

/// Extract the crate name from a type's module path
/// For example: wreq::Client -> "wreq", reqwest::Client -> "reqwest"
fn crate_name<T: ?Sized>() -> &'static str {
    let full_name = std::any::type_name::<T>();
    // Split by "::" and take the first part (the crate name)
    full_name
        .split("::")
        .next()
        .expect("Type name should contain at least one segment")
}

#[allow(clippy::too_many_arguments)]
pub fn bench_both_clients(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &Runtime,
    addr: &str,
    mode: HttpMode,
    tls: Tls,
    label_prefix: &str,
    num_requests: usize,
    concurrent_limit: usize,
    body: &'static [u8],
) -> Result<(), Box<dyn Error>> {
    let url = format!("{tls}://{addr}");
    let body_kb = body.len() / 1024;

    let make_benchmark_label = |client: &str, stream: bool| {
        let body_type = if stream { "stream" } else { "full" };
        format!("{tls}_{mode}_{client}_{label_prefix}_{body_type}_{body_kb}KB")
    };

    for stream in [false, true] {
        let client = create_wreq_client(mode, tls)?;
        group.bench_function(
            make_benchmark_label(crate_name::<wreq::Client>(), stream),
            |b| {
                b.to_async(rt).iter(|| {
                    wreq_requests_concurrent(
                        &client,
                        &url,
                        num_requests,
                        concurrent_limit,
                        body,
                        stream,
                    )
                })
            },
        );
        ::std::mem::drop(client);

        let client = create_reqwest_client(mode, tls)?;
        group.bench_function(
            make_benchmark_label(crate_name::<reqwest::Client>(), stream),
            |b| {
                b.to_async(rt).iter(|| {
                    reqwest_requests_concurrent(
                        &client,
                        &url,
                        num_requests,
                        concurrent_limit,
                        body,
                        stream,
                    )
                })
            },
        );
        ::std::mem::drop(client);
    }

    Ok(())
}
