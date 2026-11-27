use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures_util::future::{self, Ready};
#[cfg(feature = "cookies")]
use http::{HeaderValue, header::COOKIE};
use http::{Method, Response, Uri, Version};
use tower::{BoxError, Service, ServiceExt};

use super::{
    Client, Config,
    prepare::Prepared,
    retry::{Attempt, AttemptOutcome, Retry, Retryable, Step},
};
#[cfg(feature = "cookies")]
use crate::cookie::{CookieStore, Cookies};
use crate::{
    Body,
    client::{
        error::{self, ErrorKind},
        request::RequestVersion,
        upgrade,
    },
    config::{ConnectConfig, RequestConfig},
    conn::{BoxedConnectLayer, Conn, Unnameable},
    dns::DynResolver,
    protocol::Protocol,
    rt::DynRuntime,
};

impl<F, T> Attempt for F
where
    F: FnMut(http::Request<Body>) -> AttemptOutcome<T>,
{
    type Output = T;
    type State = std::convert::Infallible;

    fn start(
        &mut self,
        request: http::Request<Body>,
        _uri: &Uri,
        _cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output> {
        Step::Ready(self(request))
    }

    fn poll(
        &mut self,
        state: &mut Self::State,
        _uri: &Uri,
        _cx: &mut Context<'_>,
    ) -> Poll<AttemptOutcome<Self::Output>> {
        match *state {}
    }
}

fn client(
    mut config: Config,
    connect: impl Fn(Unnameable) -> Ready<Result<Conn, BoxError>> + Clone + Send + Sync + 'static,
) -> Client {
    config
        .conn_config
        .layers
        .push(BoxedConnectLayer::new(tower::layer::layer_fn(move |_| {
            tower::service_fn(connect.clone())
        })));
    let runtime = DynRuntime::new(crate::rt::tokio::TokioRuntime);
    let resolver = DynResolver::new(runtime.resolver());
    Client::new(runtime, resolver, config).unwrap()
}

#[test]
fn entry_checks_reject_requests_and_strip_userinfo_before_keying() {
    let connect_config = RequestConfig::new(ConnectConfig::default());
    let prepare = |mut request: http::Request<Body>| {
        Prepared::prepare(&mut request, Protocol::Auto, &connect_config)
            .map(|prepared| (request, prepared))
    };
    for (method, version, uri, kind) in [
        (
            Method::CONNECT,
            Version::HTTP_10,
            "http://localhost/",
            "UserUnsupportedRequestMethod",
        ),
        (
            Method::GET,
            Version::HTTP_09,
            "http://localhost/",
            "UserUnsupportedVersion",
        ),
        (
            Method::GET,
            Version::HTTP_11,
            "/relative",
            "UserAbsoluteUriRequired",
        ),
    ] {
        let request = http::Request::builder()
            .method(method)
            .version(version)
            .uri(uri)
            .body(Body::default())
            .unwrap();
        let Err(error) = prepare(request) else {
            panic!("{kind} must reject the request");
        };
        assert_eq!(error.to_string(), format!("client error ({kind})"));
    }

    let prepare_uri =
        |uri| prepare(http::Request::get(uri).body(Body::default()).unwrap()).unwrap();
    let (_, plain) = prepare_uri("http://localhost/");
    let (userinfo_req, userinfo) = prepare_uri("http://user:pw@localhost/");
    assert!(plain.key.is_some());
    assert_eq!(userinfo_req.uri(), "http://localhost/");
    assert_eq!(userinfo.key, plain.key);

    let prepare_upgrade =
        |method: Method, version: Option<Version>, mode: Protocol, u: upgrade::Upgrade| {
            let mut builder = http::Request::builder()
                .method(method)
                .uri("https://localhost/");
            if let Some(version) = version {
                builder = builder
                    .version(version)
                    .extension(RequestConfig::<RequestVersion>::new(Some(version)));
            }
            let mut request = builder
                .extension(RequestConfig::<upgrade::Upgrade>::new(Some(u)))
                .body(Body::default())
                .unwrap();
            Prepared::prepare(&mut request, mode, &connect_config)
        };

    #[cfg(feature = "http2")]
    let (_, plain_https) = prepare_uri("https://localhost/");
    let http1 =
        prepare_upgrade(Method::GET, None, Protocol::Auto, upgrade::Upgrade::http1()).unwrap();
    assert!(http1.key.is_none());
    #[cfg(any(feature = "http2", feature = "http3"))]
    assert!(http1.upgrade.is_none());

    let adaptive = prepare_upgrade(
        Method::GET,
        None,
        Protocol::Auto,
        upgrade::Upgrade::adaptive(upgrade::Protocol::WEBSOCKET),
    )
    .unwrap();
    assert!(adaptive.key.is_none());
    #[cfg(feature = "http2")]
    assert!(matches!(
        adaptive.upgrade.as_deref(),
        Some(upgrade::Plan::Adaptive { key, .. }) if plain_https.key.as_ref() == Some(key)
    ));

    for (method, version, mode, u, expected) in [
        (
            Method::GET,
            None,
            Protocol::Auto,
            upgrade::Upgrade::extended_connect(upgrade::Protocol::WEBSOCKET),
            "client error (UserUnsupportedRequestMethod)",
        ),
        (
            Method::CONNECT,
            Some(Version::HTTP_11),
            Protocol::Auto,
            upgrade::Upgrade::extended_connect(upgrade::Protocol::WEBSOCKET),
            "client error (UserUnsupportedVersion): extended CONNECT requires HTTP/2 or HTTP/3",
        ),
        #[cfg(feature = "http2")]
        (
            Method::GET,
            Some(Version::HTTP_2),
            Protocol::Auto,
            upgrade::Upgrade::http1(),
            "client error (UserUnsupportedVersion)",
        ),
        #[cfg(feature = "http3")]
        (
            Method::CONNECT,
            None,
            Protocol::Http3,
            upgrade::Upgrade::extended_connect(upgrade::Protocol::from_static("custom")),
            "client error (UserUnsupportedVersion): extended CONNECT protocol is not supported on HTTP/3",
        ),
    ] {
        assert_eq!(
            prepare_upgrade(method, version, mode, u)
                .err()
                .unwrap()
                .to_string(),
            expected
        );
    }

    // Adaptive upgrade skips HTTP/3 probing when the protocol is unsupported on HTTP/3.
    #[cfg(feature = "http3")]
    {
        let adaptive_h3 = prepare_upgrade(
            Method::GET,
            None,
            Protocol::Http3,
            upgrade::Upgrade::adaptive(upgrade::Protocol::from_static("custom")),
        )
        .unwrap();
        assert!(adaptive_h3.key.is_none() && adaptive_h3.upgrade.is_none());
    }
}

#[tokio::test]
async fn unsent_retries_restore_request_state_and_respect_reused_flag() {
    use http_body_util::BodyExt;

    let connect_config = RequestConfig::new(ConnectConfig::default());
    for reused in [true, false] {
        let mut calls = 0;
        let mut request = http::Request::builder()
            .version(Version::HTTP_10)
            .uri("http://localhost/upload?part=1")
            .body(Body::from("payload"))
            .unwrap();
        let prepared = Prepared::prepare(&mut request, Protocol::Auto, &connect_config).unwrap();
        assert!(prepared.key.is_some());

        let mut retry = Retry::new(request, |mut request: http::Request<Body>| {
            calls += 1;
            if calls == 1 {
                *request.uri_mut() = Uri::from_static("/upload?part=1");
                *request.version_mut() = Version::HTTP_2;
                #[cfg(feature = "cookies")]
                request
                    .headers_mut()
                    .append(COOKIE, HeaderValue::from_static("h2=1"));
                AttemptOutcome::Unsent {
                    retry: Box::new(Retryable {
                        error: error::Error::new(
                            ErrorKind::Canceled,
                            std::io::Error::other("unsent"),
                        ),
                        request,
                    }),
                    connection_reused: reused,
                }
            } else {
                assert_eq!(request.uri(), "http://localhost/upload?part=1");
                assert_eq!(request.version(), Version::HTTP_10);
                #[cfg(feature = "cookies")]
                assert!(!request.headers().contains_key(COOKIE));
                if calls == 2 {
                    AttemptOutcome::CheckoutCanceled(Box::new(Retryable {
                        error: error::Error::from_kind(ErrorKind::Connect),
                        request,
                    }))
                } else {
                    AttemptOutcome::Done(Ok(request.into_body()))
                }
            }
        });

        let result = if reused {
            let mut task = tokio_test::task::spawn(retry);
            assert!(task.poll().is_pending());
            assert!(task.is_woken());
            let Poll::Ready(result) = task.poll() else {
                panic!("the third attempt must finish on the next poll");
            };
            result
        } else {
            Pin::new(&mut retry).await
        };

        if reused {
            assert_eq!(calls, 3);
            let body = result.unwrap().collect().await.unwrap().to_bytes();
            assert_eq!(body, "payload");
        } else {
            let error = result.unwrap_err();
            assert_eq!(calls, 1);
            assert!(error.is::<error::Error>());
            assert_eq!(error.source().unwrap().to_string(), "unsent");
        }
    }

    #[cfg(feature = "cookies")]
    {
        let mut calls = 0;
        let request = http::Request::builder()
            .uri("https://localhost/")
            .header(COOKIE, "user=1")
            .header(COOKIE, "other=2")
            .body(Body::default())
            .unwrap();
        Retry::new(request, |request: http::Request<Body>| {
            let values: Vec<_> = request.headers().get_all(COOKIE).iter().collect();
            assert_eq!(values, ["user=1", "other=2"]);
            calls += 1;
            if calls == 1 {
                AttemptOutcome::Unsent {
                    retry: Box::new(Retryable {
                        error: error::Error::from_kind(ErrorKind::Canceled),
                        request,
                    }),
                    connection_reused: true,
                }
            } else {
                AttemptOutcome::Done(Ok(()))
            }
        })
        .await
        .unwrap();
        assert_eq!(calls, 2);
    }
}

#[tokio::test]
async fn connect_config_reaches_the_connector_without_partitioning_the_pool() {
    use bytes::Bytes;
    use http_body_util::Empty;

    struct DialOption(u8);

    let attempts = Arc::new(crate::sync::Mutex::new(Vec::new()));
    let connect = {
        let attempts = attempts.clone();
        move |Unnameable(request)| {
            attempts.lock().push(
                request
                    .body()
                    .get_ref::<DialOption>()
                    .map(|option| option.0),
            );
            let (client, server) = tokio::io::duplex(4096);
            let service = hyper::service::service_fn(|_| async {
                Ok::<_, std::convert::Infallible>(Response::new(Empty::<Bytes>::new()))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service),
            );
            future::ready(Ok::<_, BoxError>(Conn::test(client)))
        }
    };
    let mut config = ConnectConfig::default();
    config.insert(DialOption(1));
    let mut client = client(
        Config {
            protocol: Protocol::Http1,
            config,
            ..Config::default()
        },
        connect,
    );
    for (uri, option) in [
        ("http://localhost/", None),
        ("http://localhost/", Some(DialOption(2))),
        ("http://localhost:8080/", Some(DialOption(3))),
    ] {
        let mut request = http::Request::get(uri).body(Body::default()).unwrap();
        if let Some(option) = option {
            RequestConfig::<ConnectConfig>::get_mut(request.extensions_mut())
                .get_or_insert_default()
                .insert(option);
        }
        let response = client.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
    }
    assert_eq!(*attempts.lock(), [Some(1), Some(3)]);
}

#[cfg(feature = "cookies")]
#[tokio::test]
async fn cookies_keep_the_request_uri_of_a_connect_target() {
    use std::convert::Infallible;

    use http_body_util::BodyExt;

    #[derive(Default)]
    struct Recorder(crate::sync::Mutex<Vec<String>>);

    impl CookieStore for Recorder {
        fn set_cookies(&self, _: &mut dyn Iterator<Item = &HeaderValue>, uri: &Uri) {
            self.0.lock().push(format!("set {uri}"));
        }

        fn cookies(&self, uri: &Uri, _: Version) -> Cookies {
            self.0.lock().push(format!("get {uri}"));
            Cookies::Compressed(HeaderValue::from_static("a=1"))
        }
    }

    let connect = |_: Unnameable| {
        let (client, server) = tokio::io::duplex(16384);
        let service =
            hyper::service::service_fn(|request: http::Request<hyper::body::Incoming>| {
                let target = format!("{} {:?}", request.uri(), request.headers()[COOKIE]);
                future::ready(Ok::<_, Infallible>(
                    Response::builder()
                        .status(http::StatusCode::FORBIDDEN)
                        .header(http::header::SET_COOKIE, "b=2")
                        .body(target)
                        .unwrap(),
                ))
            });
        tokio::spawn(
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(server), service),
        );
        future::ready(Ok::<_, BoxError>(crate::conn::Conn::test(client)))
    };
    let store = Arc::new(Recorder::default());
    let client = client(
        Config {
            cookie_store: Some(store.clone()),
            ..Config::default()
        },
        connect,
    );
    let response = client
        .oneshot(
            http::Request::connect("http://localhost/")
                .body(Body::default())
                .unwrap(),
        )
        .await
        .unwrap();

    let target = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(target, "localhost:80 \"a=1\"");
    assert_eq!(
        *store.0.lock(),
        ["get http://localhost/", "set http://localhost/"]
    );
}

#[cfg(any(feature = "http2", feature = "http3"))]
#[test]
fn adaptive_upgrade_is_restored_after_extended_connect() {
    #[cfg(feature = "http2")]
    use http::HeaderName;
    use http::header::{CONNECTION, SEC_WEBSOCKET_KEY, UPGRADE};

    #[cfg(feature = "http2")]
    const CUSTOM_KEY: HeaderName = HeaderName::from_static("x-upgrade-nonce");
    for (method, orig_version, target_version, protocol, strip) in [
        #[cfg(feature = "http2")]
        (
            Method::GET,
            Version::HTTP_11,
            Version::HTTP_2,
            upgrade::Protocol::WEBSOCKET,
            SEC_WEBSOCKET_KEY,
        ),
        #[cfg(feature = "http3")]
        (
            Method::GET,
            Version::HTTP_11,
            Version::HTTP_3,
            upgrade::Protocol::WEBSOCKET,
            SEC_WEBSOCKET_KEY,
        ),
        #[cfg(feature = "http2")]
        (
            Method::POST,
            Version::HTTP_10,
            Version::HTTP_2,
            upgrade::Protocol::from_static("custom"),
            CUSTOM_KEY,
        ),
    ] {
        let mut request = http::Request::builder()
            .method(method.clone())
            .uri("https://localhost/chat")
            .version(orig_version)
            .header(http::header::ORIGIN, "https://localhost")
            .header(UPGRADE, protocol.as_str())
            .header(CONNECTION, "upgrade")
            .header(strip.clone(), "nonce")
            .header("x-keep", "1")
            .body(())
            .unwrap();
        let original = request.headers().clone();
        let rewritten =
            upgrade::Rewritten::try_rewrite(&mut request, target_version, &protocol, &[strip])
                .unwrap();

        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(request.version(), target_version);
        #[cfg(feature = "http2")]
        assert_eq!(
            request
                .extensions()
                .get::<http2::ext::Protocol>()
                .map(http2::ext::Protocol::as_str),
            (target_version == Version::HTTP_2).then_some(protocol.as_str())
        );
        #[cfg(feature = "http3")]
        assert_eq!(
            request.extensions().get::<netty::http3::Protocol>(),
            (target_version == Version::HTTP_3).then_some(&netty::http3::Protocol::WEBSOCKET)
        );
        assert!(
            request
                .headers()
                .keys()
                .map(|name| name.as_str())
                .eq(["origin", "x-keep"])
        );

        rewritten.restore(&mut request);
        assert_eq!(request.method(), method);
        assert_eq!(request.version(), orig_version);
        #[cfg(feature = "http2")]
        assert!(request.extensions().get::<http2::ext::Protocol>().is_none());
        #[cfg(feature = "http3")]
        assert!(
            request
                .extensions()
                .get::<netty::http3::Protocol>()
                .is_none()
        );
        assert!(request.headers().iter().eq(original.iter()));
    }
}
