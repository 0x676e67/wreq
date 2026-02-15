use std::{convert::Infallible, error::Error, sync::Arc};

use super::HttpMode;
use bytes::Bytes;
use criterion::{BenchmarkGroup, measurement::WallTime};
use futures_util::stream;
use tokio::{runtime::Runtime, sync::Semaphore};

const STREAM_CHUNK_SIZE: usize = 8 * 1024;

#[inline]
fn box_err<E: Error + Send + 'static>(e: E) -> Box<dyn Error + Send> {
    Box::new(e)
}

fn create_wreq_client(mode: HttpMode) -> Result<wreq::Client, Box<dyn Error>> {
    let builder = wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none());

    let builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_only(),
    };

    Ok(builder.build()?)
}

fn create_reqwest_client(mode: HttpMode) -> Result<reqwest::Client, Box<dyn Error>> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());

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

#[inline]
fn stream_from_static(
    body: &'static [u8],
) -> impl futures_util::stream::TryStream<Ok = Bytes, Error = Infallible> + Send + 'static {
    stream::iter(
        body.chunks(STREAM_CHUNK_SIZE)
            .map(|chunk| Ok::<Bytes, Infallible>(Bytes::from_static(chunk))),
    )
}

#[inline]
fn wreq_body(stream: bool, body: &'static [u8]) -> wreq::Body {
    if stream {
        let stream = stream_from_static(body);
        wreq::Body::wrap_stream(stream)
    } else {
        wreq::Body::from(body)
    }
}

#[inline]
fn reqwest_body(stream: bool, body: &'static [u8]) -> reqwest::Body {
    if stream {
        let stream = stream_from_static(body);
        reqwest::Body::wrap_stream(stream)
    } else {
        reqwest::Body::from(body)
    }
}

async fn wreq_requests_sequential(
    client: &wreq::Client,
    url: &str,
    num_requests: usize,
    body: &'static [u8],
    stream: bool,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..num_requests {
        let response = client
            .post(url)
            .body(wreq_body(stream, body))
            .send()
            .await?;

        wreq_body_assert(response, body.len()).await;
    }

    Ok(())
}

async fn reqwest_requests_sequential(
    client: &reqwest::Client,
    url: &str,
    num_requests: usize,
    body: &'static [u8],
    stream: bool,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..num_requests {
        let response = client
            .post(url)
            .body(reqwest_body(stream, body))
            .send()
            .await?;

        reqwest_body_assert(response, body.len()).await;
    }

    Ok(())
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
        let body = body;
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
    label_prefix: &str,
    concurrent: bool,
    num_requests: usize,
    concurrent_limit: usize,
    body: &'static [u8],
) -> Result<(), Box<dyn Error>> {
    let wreq_client = create_wreq_client(mode)?;
    let reqwest_client = create_reqwest_client(mode)?;

    let url = format!("http://{addr}");
    let body_kb = body.len() / 1024;

    let make_benchmark_label = |client: &str, stream: bool| {
        let execution_mode = if concurrent {
            "concurrent"
        } else {
            "sequential"
        };
        let body_type = if stream { "stream" } else { "full" };
        format!("{client}_{mode}_{label_prefix}_{execution_mode}_body_{body_type}_{body_kb}KB")
    };

    if concurrent {
        for stream in [false, true] {
            group.bench_function(
                make_benchmark_label(crate_name::<wreq::Client>(), stream),
                |b| {
                    b.iter(|| {
                        rt.block_on(wreq_requests_concurrent(
                            &wreq_client,
                            &url,
                            num_requests,
                            concurrent_limit,
                            body,
                            stream,
                        ))
                    })
                },
            );

            group.bench_function(
                make_benchmark_label(crate_name::<reqwest::Client>(), stream),
                |b| {
                    b.iter(|| {
                        rt.block_on(reqwest_requests_concurrent(
                            &reqwest_client,
                            &url,
                            num_requests,
                            concurrent_limit,
                            body,
                            stream,
                        ))
                    })
                },
            );
        }
    } else {
        for stream in [false, true] {
            group.bench_function(
                make_benchmark_label(crate_name::<wreq::Client>(), stream),
                |b| {
                    b.iter(|| {
                        rt.block_on(wreq_requests_sequential(
                            &wreq_client,
                            &url,
                            num_requests,
                            body,
                            stream,
                        ))
                    })
                },
            );

            group.bench_function(
                make_benchmark_label(crate_name::<reqwest::Client>(), stream),
                |b| {
                    b.iter(|| {
                        rt.block_on(reqwest_requests_sequential(
                            &reqwest_client,
                            &url,
                            num_requests,
                            body,
                            stream,
                        ))
                    })
                },
            );
        }
    }

    Ok(())
}
