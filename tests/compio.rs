//! Compio runtime integration tests.
//!
//! Each test starts an HTTP server on a shared tokio background thread
//! and makes requests via a compio runtime.

#![cfg(feature = "compio-rt")]

use std::{convert::Infallible, sync::OnceLock, time::Duration};

use compio::runtime::Runtime;
use http::Response;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

fn tokio_rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().expect("tokio runtime"))
}

async fn spawn_echo_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://127.0.0.1:{}/echo", addr.port());

    tokio_rt().spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let io = TokioIo::new(stream);
            tokio_rt().spawn(async move {
                let svc = hyper::service::service_fn(|req: http::Request<Incoming>| async move {
                    let path = req.uri().path().to_owned();
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("X-Request-Path", &path)
                            .body(path)
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    url
}

fn with_server<F, Fut>(test: F)
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let url = tokio_rt().block_on(spawn_echo_server());
    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(test(url));
}

// ===== helpers =====

async fn spawn_redirect_server(target_url: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let redirect_url = format!("http://127.0.0.1:{}/redirect", addr.port());

    tokio_rt().spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let io = TokioIo::new(stream);
            let target = target_url.clone();
            tokio_rt().spawn(async move {
                let svc = hyper::service::service_fn(move |_req: http::Request<Incoming>| {
                    let target = target.clone();
                    async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(302)
                                .header("Location", &target)
                                .body(String::new())
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    redirect_url
}

async fn spawn_cookie_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let url = format!("http://127.0.0.1:{}/cookie", addr.port());

    tokio_rt().spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            let io = TokioIo::new(stream);
            tokio_rt().spawn(async move {
                let svc = hyper::service::service_fn(|req: http::Request<Incoming>| async move {
                    let path = req.uri().path();
                    let cookie_header = req
                        .headers()
                        .get("cookie")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_owned();
                    match path {
                        "/cookie/set" => Ok::<_, Infallible>(
                            Response::builder()
                                .header("Set-Cookie", "wreq_test=compio_value; Path=/")
                                .body(format!("cookie was: {cookie_header}"))
                                .unwrap(),
                        ),
                        "/cookie/check" => Ok::<_, Infallible>(
                            Response::builder()
                                .body(format!("cookie: {cookie_header}"))
                                .unwrap(),
                        ),
                        _ => Ok::<_, Infallible>(
                            Response::builder()
                                .status(404)
                                .body("not found".into())
                                .unwrap(),
                        ),
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    url
}

// ===== tests =====

#[test]
fn http_get() {
    with_server(|url| async move {
        let resp = wreq::Client::new().get(&url).send().await.expect("GET");
        assert!(resp.status().is_success());
        assert_eq!(resp.text().await.expect("body"), "/echo");
    });
}

#[test]
fn http_post() {
    with_server(|url| async move {
        let resp = wreq::Client::new()
            .post(&url)
            .body("hello compio")
            .send()
            .await
            .expect("POST");
        assert!(resp.status().is_success());
    });
}

#[test]
fn http_custom_header() {
    with_server(|url| async move {
        let resp = wreq::Client::new()
            .get(&url)
            .header("X-Test", "compio")
            .send()
            .await
            .expect("GET");
        let echoed = resp
            .headers()
            .get("X-Request-Path")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(echoed, "/echo");
    });
}

#[test]
fn http_query_params() {
    with_server(|url| async move {
        let resp = wreq::Client::new()
            .get(&format!("{url}?a=1&b=2"))
            .send()
            .await
            .expect("GET");
        assert!(resp.status().is_success());
    });
}

#[test]
fn http_user_agent() {
    with_server(|url| async move {
        let resp = wreq::Client::new()
            .get(&url)
            .header("User-Agent", "wreq-compio-test/1.0")
            .send()
            .await
            .expect("GET");
        assert!(resp.status().is_success());
    });
}

#[test]
fn https_get_httpbin() {
    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let resp = wreq::Client::new()
            .get("https://httpbin.org/get")
            .send()
            .await
            .expect("GET https");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(body.contains("httpbin"), "body: {body}");
    });
}

// ===== redirect tests =====

#[test]
fn redirect_follow_302() {
    let url = tokio_rt().block_on(async {
        let target = spawn_echo_server().await;
        spawn_redirect_server(target).await
    });

    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let client = wreq::Client::builder()
            .redirect(wreq::redirect::Policy::limited(10))
            .build()
            .expect("client");
        let resp = client.get(&url).send().await.expect("GET redirect");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert_eq!(body, "/echo", "should have followed redirect to /echo");
    });
}

#[test]
fn redirect_no_follow() {
    let url = tokio_rt().block_on(async {
        let target = spawn_echo_server().await;
        spawn_redirect_server(target).await
    });

    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let resp = wreq::Client::new()
            .get(&url)
            .redirect(wreq::redirect::Policy::none())
            .send()
            .await
            .expect("GET no-redirect");
        assert_eq!(resp.status().as_u16(), 302);
    });
}

// ===== cookie tests =====

#[cfg(feature = "cookies")]
#[test]
fn cookie_set_and_send() {
    let url = tokio_rt().block_on(spawn_cookie_server());

    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let client = wreq::Client::builder()
            .cookie_store(true)
            .build()
            .expect("client");

        // First request: set the cookie
        let resp = client
            .get(&format!("{url}/set"))
            .send()
            .await
            .expect("GET /set");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(body.contains("cookie was: none"), "first req: {body}");

        // Second request: cookie should be sent automatically
        let resp = client
            .get(&format!("{url}/check"))
            .send()
            .await
            .expect("GET /check");
        assert!(resp.status().is_success());
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("wreq_test=compio_value"),
            "second req should have cookie: {body}"
        );
    });
}

#[cfg(feature = "cookies")]
#[test]
fn cookie_disabled() {
    let url = tokio_rt().block_on(spawn_cookie_server());

    let runtime = Runtime::new().expect("compio runtime");
    runtime.block_on(async {
        let client = wreq::Client::builder()
            .cookie_store(false)
            .build()
            .expect("client");

        let resp = client
            .get(&format!("{url}/set"))
            .send()
            .await
            .expect("GET /set");
        assert!(resp.status().is_success());

        // Second request: no cookie store, so cookie should not be sent
        let resp = client
            .get(&format!("{url}/check"))
            .send()
            .await
            .expect("GET /check");
        let body = resp.text().await.expect("body");
        assert!(
            body.contains("cookie: none"),
            "without cookie store, should have no cookie: {body}"
        );
    });
}
