mod support;
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use pretty_env_logger::env_logger;
use support::{layer::DelayLayer, server};
use wreq::Client;

#[tokio::test]
async fn client_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // delay returning the response
            tokio::time::sleep(Duration::from_millis(300)).await;
            http::Response::default()
        }
    });

    let client = Client::builder()
        .timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());
    let err = client.get(&url).send().await.unwrap_err();

    assert!(err.is_timeout());
    assert_eq!(err.uri().map(|u| u.to_string()), Some(url));
}

#[tokio::test]
async fn request_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // delay returning the response
            tokio::time::sleep(Duration::from_millis(300)).await;
            http::Response::default()
        }
    });

    let client = Client::builder().no_proxy().build().unwrap();

    let url = format!("http://{}/slow", server.addr());

    let err = client
        .get(&url)
        .timeout(Duration::from_millis(100))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout() && !err.is_connect());
    assert_eq!(err.uri().map(|u| u.to_string()), Some(url));
}

#[tokio::test]
async fn connect_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });

    let client = Client::builder()
        .connector_layer(DelayLayer::new(Duration::from_secs(60)))
        .connect_timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}", server.addr());

    let err = client
        .get(&url)
        .timeout(Duration::from_millis(1000))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_timeout());
}

#[tokio::test]
async fn connect_many_timeout_succeeds() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::default() });
    let unavailable = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let unavailable_addr = unavailable.local_addr().unwrap();
    drop(unavailable);
    let port = server.addr().port();

    let client = Client::builder()
        .resolve_to_addrs("many_addrs", [unavailable_addr, server.addr()])
        .connect_timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://many_addrs:{port}/eventual");

    let _ = client
        .get(url)
        .timeout(Duration::from_millis(1000))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn connect_many_timeout() {
    let _ = env_logger::try_init();

    let client = Client::builder()
        .resolve_to_addrs(
            "many_addrs",
            [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 81)),
                SocketAddr::from((Ipv4Addr::LOCALHOST, 82)),
            ],
        )
        .connector_layer(DelayLayer::new(Duration::from_secs(60)))
        .connect_timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = "http://many_addrs:81/slow".to_string();

    let err = client
        .get(url)
        .timeout(Duration::from_millis(1000))
        .send()
        .await
        .unwrap_err();

    assert!(err.is_connect() && err.is_timeout());
}

#[cfg(feature = "stream")]
#[tokio::test]
async fn response_timeout() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // immediate response, but delayed body
            let body = wreq::Body::wrap_stream(futures_util::stream::once(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok::<_, std::convert::Infallible>("Hello")
            }));

            http::Response::new(body)
        }
    });

    let client = Client::builder()
        .timeout(Duration::from_millis(500))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());
    let res = client.get(&url).send().await.expect("Failed to get");
    let err = res.text().await.unwrap_err();

    assert!(err.is_body() && err.is_timeout());
}

/// `timeout()` is documented as a budget for the whole request. Head and
/// body delays below are each individually under the configured timeout,
/// but their sum is not — a request that only honors the budget per-phase
/// (restarting it once the body starts) would incorrectly let this succeed.
#[cfg(feature = "stream")]
#[tokio::test]
async fn total_timeout_bounds_head_and_body_combined() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let body = wreq::Body::wrap_stream(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok::<_, std::convert::Infallible>("Hello")
        }));
        http::Response::new(body)
    });

    let client = Client::builder()
        .timeout(Duration::from_millis(220))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());
    let started = std::time::Instant::now();
    let res = client.get(&url).send().await.expect("Failed to get");
    let result = res.text().await;

    assert!(
        result.is_err(),
        "head (150ms) + body (150ms) = 300ms exceeds the 220ms total \
         budget, but succeeded in {:?} — total_timeout was restarted for \
         the body instead of being one deadline for the whole request",
        started.elapsed()
    );
    let err = result.unwrap_err();
    assert!(err.is_body() && err.is_timeout());
}

#[tokio::test]
async fn read_timeout_applies_to_headers() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // delay returning the response
            tokio::time::sleep(Duration::from_millis(300)).await;
            http::Response::default()
        }
    });

    let client = Client::builder()
        .read_timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());

    let err = client.get(&url).send().await.unwrap_err();

    assert!(err.is_timeout());
    assert_eq!(err.uri().map(|u| u.to_string()), Some(url));
}

#[cfg(feature = "stream")]
#[tokio::test]
async fn read_timeout_applies_to_body() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // immediate response, but delayed body
            let body = wreq::Body::wrap_stream(futures_util::stream::once(async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok::<_, std::convert::Infallible>("Hello")
            }));

            http::Response::new(body)
        }
    });

    let client = Client::builder()
        .read_timeout(Duration::from_millis(100))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());
    let res = client.get(&url).send().await.expect("Failed to get");
    let err = res.text().await.unwrap_err();

    assert!(err.is_body() && err.is_timeout());
}

#[cfg(feature = "stream")]
#[tokio::test]
async fn read_timeout_allows_slow_response_body() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| {
        async {
            // immediate response, but body that has slow chunks
            let slow = futures_util::stream::unfold(0, |state| async move {
                if state < 3 {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Some((
                        Ok::<_, std::convert::Infallible>(state.to_string()),
                        state + 1,
                    ))
                } else {
                    None
                }
            });
            let body = wreq::Body::wrap_stream(slow);

            http::Response::new(body)
        }
    });

    let client = Client::builder()
        .read_timeout(Duration::from_millis(200))
        //.timeout(Duration::from_millis(200))
        .no_proxy()
        .build()
        .unwrap();

    let url = format!("http://{}/slow", server.addr());
    let res = client.get(&url).send().await.expect("Failed to get");
    let body = res.text().await.expect("body text");

    assert_eq!(body, "012");
}

#[tokio::test]
async fn response_body_timeout_forwards_size_hint() {
    let _ = env_logger::try_init();

    let server = server::http(move |_req| async { http::Response::new(b"hello".to_vec().into()) });

    let client = Client::builder().no_proxy().build().unwrap();

    let url = format!("http://{}/slow", server.addr());

    let res = client
        .get(&url)
        .timeout(Duration::from_secs(1))
        .send()
        .await
        .expect("response");

    assert_eq!(res.content_length(), Some(5));
}
