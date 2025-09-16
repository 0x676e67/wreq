mod support;

use std::time::Duration;

use futures_util::future::join_all;
use pretty_env_logger::env_logger;
use support::{
    layer::{DelayLayer, SharedConcurrencyLimitLayer},
    server,
};
use tower::{layer::util::Identity, limit::ConcurrencyLimitLayer, timeout::TimeoutLayer};
use wreq::Client;

#[tokio::test]
async fn non_op_layer() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(Identity::new())
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(url).send().await;

    assert!(res.is_ok());
}

#[tokio::test]
async fn non_op_layer_with_timeout() {
    let _ = env_logger::try_init();

    let client = Client::builder()
        .layer(Identity::new())
        .connect_timeout(Duration::from_millis(200))
        .no_proxy()
        .build()
        .unwrap();

    // never returns
    let url = "http://192.0.2.1:81/slow";

    let res = client.get(url).send().await;

    let err = res.unwrap_err();

    assert!(err.is_connect() && err.is_timeout());
}

#[tokio::test]
async fn with_connect_timeout_layer_never_returning() {
    let _ = env_logger::try_init();

    let client = Client::builder()
        .layer(TimeoutLayer::new(Duration::from_millis(100)))
        .no_proxy()
        .build()
        .unwrap();

    // never returns
    let url = "http://192.0.2.1:81/slow";

    let res = client.get(url).send().await;

    let err = res.unwrap_err();

    assert!(err.is_timeout());
}

#[tokio::test]
async fn with_connect_timeout_layer_slow() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(DelayLayer::new(Duration::from_millis(200)))
        .layer(TimeoutLayer::new(Duration::from_millis(100)))
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(url).send().await;

    let err = res.unwrap_err();

    assert!(err.is_timeout());
}

#[tokio::test]
async fn multiple_timeout_layers_under_threshold() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(DelayLayer::new(Duration::from_millis(100)))
        .layer(TimeoutLayer::new(Duration::from_millis(200)))
        .layer(TimeoutLayer::new(Duration::from_millis(300)))
        .layer(TimeoutLayer::new(Duration::from_millis(500)))
        .timeout(Duration::from_millis(200))
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(url).send().await;

    assert!(res.is_ok());
}

#[tokio::test]
async fn multiple_timeout_layers_over_threshold() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(DelayLayer::new(Duration::from_millis(100)))
        .layer(TimeoutLayer::new(Duration::from_millis(50)))
        .layer(TimeoutLayer::new(Duration::from_millis(50)))
        .layer(TimeoutLayer::new(Duration::from_millis(50)))
        .connect_timeout(Duration::from_millis(50))
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(url).send().await;

    let err = res.unwrap_err();

    assert!(err.is_timeout());
}

#[tokio::test]
async fn layer_insert_headers() {
    let _ = env_logger::try_init();

    let server = server::http(move |req| async move {
        let headers = req.headers().clone();
        assert!(headers.contains_key("x-test-header"));
        http::Response::default()
    });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(tower::util::MapRequestLayer::new(
            move |mut req: http::Request<wreq::Body>| {
                req.headers_mut().insert(
                    "x-test-header",
                    http::HeaderValue::from_static("test-value"),
                );
                req
            },
        ))
        .no_proxy()
        .build()
        .unwrap();

    let res = client.get(url).send().await;

    assert!(res.is_ok());
}

#[tokio::test]
async fn with_concurrency_limit_layer_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(DelayLayer::new(Duration::from_millis(100)))
        .layer(SharedConcurrencyLimitLayer::new(2))
        .timeout(Duration::from_millis(200))
        .pool_max_idle_per_host(0) // disable connection reuse to force resource contention on the concurrency limit semaphore
        .no_proxy()
        .build()
        .unwrap();

    // first call succeeds since no resource contention
    let res = client.get(url.clone()).send().await;
    assert!(res.is_ok());

    // 3 calls where the second two wait on the first and time out
    let mut futures = Vec::new();
    for _ in 0..3 {
        futures.push(client.clone().get(url.clone()).send());
    }

    let all_res = join_all(futures).await;

    let timed_out = all_res
        .into_iter()
        .any(|res| res.is_err_and(|err| err.is_timeout()));

    assert!(timed_out, "at least one request should have timed out");
}

#[tokio::test]
async fn with_concurrency_limit_layer_success() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let client = Client::builder()
        .layer(DelayLayer::new(Duration::from_millis(100)))
        .layer(TimeoutLayer::new(Duration::from_millis(200)))
        .layer(ConcurrencyLimitLayer::new(1)) //2
        .timeout(Duration::from_millis(1000))
        .pool_max_idle_per_host(0) // disable connection reuse to force resource contention on the concurrency limit semaphore
        .no_proxy()
        .build()
        .unwrap();

    // first call succeeds since no resource contention
    let res = client.get(url.clone()).send().await;
    assert!(res.is_ok());

    // 3 calls of which all are individually below the inner timeout
    // and the sum is below outer timeout which affects the final call which waited the whole time
    let mut futures = Vec::new();
    for _ in 0..3 {
        futures.push(client.clone().get(url.clone()).send());
    }

    let all_res = join_all(futures).await;

    for res in all_res.into_iter() {
        assert!(
            res.is_ok(),
            "neither outer long timeout or inner short timeout should be exceeded"
        );
    }
}

#[tokio::test]
async fn no_generic_bounds_required_for_client_new() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let url = format!("http://{}", server.addr());

    let res = wreq::get(url).send().await;

    assert!(res.is_ok());
}
