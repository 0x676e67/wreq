mod support;
use http_body_util::BodyExt;
use support::server;
use wreq::{Body, redirect::Policy};

#[tokio::test]
async fn test_redirect_301_and_302_and_303_changes_post_to_get() {
    let client = wreq::Client::new();
    let codes = [301u16, 302, 303];

    for &code in &codes {
        let redirect = server::http(move |req| async move {
            if req.method() == "POST" {
                assert_eq!(req.uri(), &*format!("/{code}"));
                http::Response::builder()
                    .status(code)
                    .header("location", "/dst")
                    .header("server", "test-redirect")
                    .body(Body::default())
                    .unwrap()
            } else {
                assert_eq!(req.method(), "GET");

                http::Response::builder()
                    .header("server", "test-dst")
                    .body(Body::default())
                    .unwrap()
            }
        });

        let url = format!("http://{}/{}", redirect.addr(), code);
        let dst = format!("http://{}/{}", redirect.addr(), "dst");
        let res = client
            .post(&url)
            .redirect(Policy::default())
            .send()
            .await
            .unwrap();
        assert_eq!(res.url().as_str(), dst);
        assert_eq!(res.status(), wreq::StatusCode::OK);
        assert_eq!(
            res.headers().get(wreq::header::SERVER).unwrap(),
            &"test-dst"
        );
    }
}

#[tokio::test]
async fn test_redirect_307_and_308_tries_to_get_again() {
    let client = wreq::Client::new();
    let codes = [307u16, 308];
    for &code in &codes {
        let redirect = server::http(move |req| async move {
            assert_eq!(req.method(), "GET");
            if req.uri() == &*format!("/{code}") {
                http::Response::builder()
                    .status(code)
                    .header("location", "/dst")
                    .header("server", "test-redirect")
                    .body(Body::default())
                    .unwrap()
            } else {
                assert_eq!(req.uri(), "/dst");

                http::Response::builder()
                    .header("server", "test-dst")
                    .body(Body::default())
                    .unwrap()
            }
        });

        let url = format!("http://{}/{}", redirect.addr(), code);
        let dst = format!("http://{}/{}", redirect.addr(), "dst");
        let res = client
            .get(&url)
            .redirect(Policy::default())
            .send()
            .await
            .unwrap();
        assert_eq!(res.url().as_str(), dst);
        assert_eq!(res.status(), wreq::StatusCode::OK);
        assert_eq!(
            res.headers().get(wreq::header::SERVER).unwrap(),
            &"test-dst"
        );
    }
}

#[tokio::test]
async fn test_redirect_307_and_308_tries_to_post_again() {
    let _ = pretty_env_logger::env_logger::try_init();
    let client = wreq::Client::new();
    let codes = [307u16, 308];
    for &code in &codes {
        let redirect = server::http(move |mut req| async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-length"], "5");

            let data = req
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap();
            assert_eq!(&*data, b"Hello");

            if req.uri() == &*format!("/{code}") {
                http::Response::builder()
                    .status(code)
                    .header("location", "/dst")
                    .header("server", "test-redirect")
                    .body(Body::default())
                    .unwrap()
            } else {
                assert_eq!(req.uri(), "/dst");

                http::Response::builder()
                    .header("server", "test-dst")
                    .body(Body::default())
                    .unwrap()
            }
        });

        let url = format!("http://{}/{}", redirect.addr(), code);
        let dst = format!("http://{}/{}", redirect.addr(), "dst");
        let res = client
            .post(&url)
            .redirect(Policy::default())
            .body("Hello")
            .send()
            .await
            .unwrap();
        assert_eq!(res.url().as_str(), dst);
        assert_eq!(res.status(), wreq::StatusCode::OK);
        assert_eq!(
            res.headers().get(wreq::header::SERVER).unwrap(),
            &"test-dst"
        );
    }
}

#[tokio::test]
async fn test_redirect_removes_sensitive_headers() {
    use tokio::sync::watch;

    let (tx, rx) = watch::channel::<Option<std::net::SocketAddr>>(None);

    let end_server = server::http(move |req| {
        let mut rx = rx.clone();
        async move {
            assert_eq!(req.headers().get("cookie"), None);

            rx.changed().await.unwrap();
            let mid_addr = rx.borrow().unwrap();
            assert_eq!(
                req.headers()["referer"],
                format!("http://{mid_addr}/sensitive")
            );
            http::Response::default()
        }
    });

    let end_addr = end_server.addr();

    let mid_server = server::http(move |req| async move {
        assert_eq!(req.headers()["cookie"], "foo=bar");
        http::Response::builder()
            .status(302)
            .header("location", format!("http://{end_addr}/end"))
            .body(Body::default())
            .unwrap()
    });

    tx.send(Some(mid_server.addr())).unwrap();

    wreq::Client::builder()
        .redirect(Policy::default())
        .build()
        .unwrap()
        .get(format!("http://{}/sensitive", mid_server.addr()))
        .header(
            wreq::header::COOKIE,
            wreq::header::HeaderValue::from_static("foo=bar"),
        )
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn test_redirect_policy_can_return_errors() {
    let server = server::http(move |req| async move {
        assert_eq!(req.uri(), "/loop");
        http::Response::builder()
            .status(302)
            .header("location", "/loop")
            .body(Body::default())
            .unwrap()
    });

    let url = format!("http://{}/loop", server.addr());
    let err = wreq::Client::new()
        .get(&url)
        .redirect(Policy::default())
        .send()
        .await
        .unwrap_err();
    assert!(err.is_redirect());
}

#[tokio::test]
async fn test_redirect_policy_can_stop_redirects_without_an_error() {
    let server = server::http(move |req| async move {
        assert_eq!(req.uri(), "/no-redirect");
        http::Response::builder()
            .status(302)
            .header("location", "/dont")
            .body(Body::default())
            .unwrap()
    });

    let url = format!("http://{}/no-redirect", server.addr());

    let res = wreq::Client::builder()
        .redirect(Policy::none())
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .unwrap();

    assert_eq!(res.url().as_str(), url);
    assert_eq!(res.status(), wreq::StatusCode::FOUND);
}

#[tokio::test]
async fn test_referer_is_not_set_if_disabled() {
    let server = server::http(move |req| async move {
        if req.uri() == "/no-refer" {
            http::Response::builder()
                .status(302)
                .header("location", "/dst")
                .body(Body::default())
                .unwrap()
        } else {
            assert_eq!(req.uri(), "/dst");
            assert_eq!(req.headers().get("referer"), None);

            http::Response::default()
        }
    });

    wreq::Client::builder()
        .referer(false)
        .build()
        .unwrap()
        .get(format!("http://{}/no-refer", server.addr()))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn test_invalid_location_stops_redirect_gh484() {
    let server = server::http(move |_req| async move {
        http::Response::builder()
            .status(302)
            .header("location", "http://www.yikes{KABOOM}")
            .body(Body::default())
            .unwrap()
    });

    let url = format!("http://{}/yikes", server.addr());

    let res = wreq::Client::new().get(&url).send().await.unwrap();

    assert_eq!(res.url().as_str(), url);
    assert_eq!(res.status(), wreq::StatusCode::FOUND);
}

#[tokio::test]
async fn test_invalid_scheme_is_rejected() {
    let server = server::http(move |_req| async move {
        http::Response::builder()
            .status(302)
            .header("location", "htt://www.yikes.com/")
            .body(Body::default())
            .unwrap()
    });

    let url = format!("http://{}/yikes", server.addr());

    let err = wreq::Client::new()
        .get(&url)
        .redirect(Policy::default())
        .send()
        .await
        .unwrap_err();
    dbg!(&err);
    assert!(err.is_builder());
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn test_redirect_302_with_set_cookies() {
    let code = 302;
    let server = server::http(move |req| async move {
        if req.uri() == "/302" {
            http::Response::builder()
                .status(302)
                .header("location", "/dst")
                .header("set-cookie", "key=value")
                .body(Body::default())
                .unwrap()
        } else {
            assert_eq!(req.uri(), "/dst");
            assert_eq!(req.headers()["cookie"], "key=value");
            http::Response::default()
        }
    });

    let url = format!("http://{}/{}", server.addr(), code);
    let dst = format!("http://{}/{}", server.addr(), "dst");

    let client = wreq::ClientBuilder::new()
        .cookie_store(true)
        .redirect(Policy::default())
        .build()
        .unwrap();
    let res = client.get(&url).send().await.unwrap();

    assert_eq!(res.url().as_str(), dst);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[tokio::test]
async fn test_redirect_limit_to_1() {
    let server = server::http(move |req| async move {
        let i: i32 = req
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap()
            .parse::<i32>()
            .unwrap();
        assert!(req.uri().path().ends_with(&format!("/redirect/{i}")));
        http::Response::builder()
            .status(302)
            .header("location", format!("/redirect/{}", i + 1))
            .body(Body::default())
            .unwrap()
    });
    // The number at the end of the uri indicates the total number of redirections
    let url = format!("http://{}/redirect/0", server.addr());

    let client = wreq::Client::builder()
        .redirect(Policy::limited(1))
        .build()
        .unwrap();
    let res = client.get(&url).send().await.unwrap_err();
    // If the maximum limit is 1, then the final uri should be /redirect/1
    assert_eq!(
        res.url().unwrap().as_str(),
        format!("http://{}/redirect/1", server.addr()).as_str()
    );
    assert!(res.is_redirect());
}

#[tokio::test]
async fn test_scheme_only_check_after_policy_return_follow() {
    let server = server::http(move |_| async move {
        http::Response::builder()
            .status(302)
            .header("location", "htt://www.yikes.com/")
            .body(Body::default())
            .unwrap()
    });

    let url = format!("http://{}/yikes", server.addr());
    let res = wreq::Client::builder()
        .redirect(Policy::custom(|attempt| attempt.stop()))
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await;

    assert!(res.is_ok());
    assert_eq!(res.unwrap().status(), wreq::StatusCode::FOUND);

    let res = wreq::Client::builder()
        .redirect(Policy::custom(|attempt| attempt.follow()))
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await;

    assert!(res.is_err());
    assert!(res.unwrap_err().is_builder());
}

#[tokio::test]
async fn test_redirect_301_302_303_empty_payload_headers() {
    let client = wreq::Client::new();
    let codes = [301u16, 302, 303];
    for &code in &codes {
        let redirect = server::http(move |mut req| async move {
            if req.method() == "POST" {
                let data = req
                    .body_mut()
                    .frame()
                    .await
                    .unwrap()
                    .unwrap()
                    .into_data()
                    .unwrap();

                assert_eq!(&*data, b"Hello");
                if req.headers().get(wreq::header::CONTENT_LENGTH).is_some() {
                    assert_eq!(req.headers()[wreq::header::CONTENT_LENGTH], "5");
                }
                assert_eq!(req.uri(), &*format!("/{code}"));

                http::Response::builder()
                    .header("location", "/dst")
                    .header("server", "test-dst")
                    .status(code)
                    .body(Body::default())
                    .unwrap()
            } else {
                assert_eq!(req.method(), "GET");
                assert!(req.headers().get(wreq::header::CONTENT_TYPE).is_none());
                assert!(req.headers().get(wreq::header::CONTENT_LENGTH).is_none());
                assert!(req.headers().get(wreq::header::CONTENT_ENCODING).is_none());
                http::Response::builder()
                    .header("server", "test-dst")
                    .body(Body::default())
                    .unwrap()
            }
        });

        let url = format!("http://{}/{}", redirect.addr(), code);
        let dst = format!("http://{}/{}", redirect.addr(), "dst");
        let res = client
            .post(&url)
            .redirect(Policy::default())
            .body("Hello")
            .header(wreq::header::CONTENT_TYPE, "text/plain")
            .header(wreq::header::CONTENT_LENGTH, "5")
            .header(wreq::header::CONTENT_ENCODING, "identity")
            .send()
            .await
            .unwrap();
        assert_eq!(res.url().as_str(), dst);
        assert_eq!(res.status(), 200);
        assert_eq!(
            res.headers().get(wreq::header::SERVER).unwrap(),
            &"test-dst"
        );
    }
}
