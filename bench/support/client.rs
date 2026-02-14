use std::{error::Error, sync::Arc};

use super::HttpMode;
use criterion::{BenchmarkGroup, measurement::WallTime};
use tokio::{runtime::Runtime, sync::Semaphore};

async fn wreq_send_requests(
    client: &wreq::Client,
    url: &str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    for _i in 0..num_requests {
        let mut response = client.get(url).send().await?;
        while let Ok(Some(_chunk)) = response.chunk().await {}
    }

    Ok(())
}

async fn reqwest_send_requests(
    client: &reqwest::Client,
    url: &str,
    num_requests: usize,
) -> Result<(), Box<dyn Error>> {
    for _i in 0..num_requests {
        let mut response = client.get(url).send().await?;
        while let Ok(Some(_chunk)) = response.chunk().await {}
    }

    Ok(())
}

async fn wreq_send_requests_concurrent(
    client: &wreq::Client,
    url: &str,
    num_requests: usize,
    concurrent_limit: usize,
) {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);

    for _i in 0..num_requests {
        let url = url.to_owned();
        let client = client.clone();
        let semaphore = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut response = client.get(url).send().await.unwrap();
            while let Ok(Some(_chunk)) = response.chunk().await {}
        });
        handles.push(task);
    }

    futures_util::future::join_all(handles).await;
}

async fn reqwest_send_requests_concurrent(
    client: &reqwest::Client,
    url: &str,
    num_requests: usize,
    concurrent_limit: usize,
) {
    let semaphore = Arc::new(Semaphore::new(concurrent_limit));
    let mut handles = Vec::with_capacity(num_requests);

    for _i in 0..num_requests {
        let url = url.to_owned();
        let client = client.clone();
        let semaphore = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let mut response = client.get(url).send().await.unwrap();
            while let Ok(Some(_chunk)) = response.chunk().await {}
        });
        handles.push(task);
    }

    futures_util::future::join_all(handles).await;
}

#[allow(clippy::too_many_arguments)]
pub fn bench_wreq(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &Runtime,
    addr: &str,
    mode: HttpMode,
    label_prefix: &str,
    concurrent: bool,
    num_requests: usize,
    concurrent_limit: usize,
) {
    let builder = wreq::Client::builder()
        .no_proxy()
        .redirect(wreq::redirect::Policy::none());
    let builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_only(),
    };
    let client = builder.build().unwrap();
    let url = format!("http://{addr}");

    if concurrent {
        let label = format!("{mode:?}_{label_prefix}_wreq_concurrent");
        group.bench_function(label, |b| {
            b.iter(|| {
                rt.block_on(wreq_send_requests_concurrent(
                    &client,
                    &url,
                    num_requests,
                    concurrent_limit,
                ))
            });
        });
    } else {
        let label = format!("{mode:?}_{label_prefix}_wreq_sequential");
        group.bench_function(label, |b| {
            b.iter(|| rt.block_on(wreq_send_requests(&client, &url, num_requests)));
        });
    }
}

#[allow(clippy::too_many_arguments)]
pub fn bench_reqwest(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &Runtime,
    addr: &str,
    mode: HttpMode,
    label_prefix: &str,
    concurrent: bool,
    num_requests: usize,
    concurrent_limit: usize,
) {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    let builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_prior_knowledge(),
    };
    let client = builder.build().unwrap();
    let url = format!("http://{addr}");

    if concurrent {
        let label = format!("{mode:?}_{label_prefix}_reqwest_concurrent");
        group.bench_function(label, |b| {
            b.iter(|| {
                rt.block_on(reqwest_send_requests_concurrent(
                    &client,
                    &url,
                    num_requests,
                    concurrent_limit,
                ))
            });
        });
    } else {
        let label = format!("{mode:?}_{label_prefix}_reqwest_sequential");
        group.bench_function(label, |b| {
            b.iter(|| rt.block_on(reqwest_send_requests(&client, &url, num_requests)));
        });
    }
}
