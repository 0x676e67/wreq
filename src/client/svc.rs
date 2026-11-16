//! Tower services used by the low-level client request path.
//!
//! Configuration runs once before internal retries. Each attempt keeps its
//! checkout through dispatch, handing a busy HTTP/1 sender to a readiness task.
//! Only requests returned before encoding can be retried; bodies are never
//! reconstructed.

mod dispatch;

use std::{
    future::Future,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::future::{self, Either, Ready};
#[cfg(feature = "cookies")]
use http::header::COOKIE;
use http::{Method, Request, Uri, Version};
use pin_project_lite::pin_project;
use tower::{
    BoxError, Layer, Service, ServiceBuilder,
    util::{MapErr, Oneshot, future::MapErrFuture},
};

pub(super) use self::dispatch::Dispatch;
use self::dispatch::DispatchError;
use super::{
    error::{Error, ErrorKind},
    request::RequestVersion,
};
#[cfg(any(feature = "http2", feature = "http3"))]
use crate::conn::request::ConnectionKey;
#[cfg(feature = "http3")]
use crate::protocol::TransportKind;
use crate::{
    config::{connect::ConnectConfig, request::RequestConfig},
    conn::request::{ConnectRequest, ConnectionIdentity},
    ext::UriExt,
    protocol::Protocol,
};

/// Checks and configures requests, then wraps dispatch with unsent retries and error mapping.
/// Client values are shared; request-local options are captured once before any attempt,
/// without cloning the body.
pub struct Stack<S, B> {
    #[allow(
        clippy::type_complexity,
        reason = "Keep the concrete Tower stack local without another alias"
    )]
    inner: MapErr<RetryUnsent<S>, fn(DispatchError<B>) -> BoxError>,
    /// Client values a request inherits; keys count only request values that differ.
    protocol: Protocol,
    config: ConnectConfig,
}

/// Requests a new HTTP/1 connection that is never taken from or returned to the pool.
///
/// With `extended_connect`, dispatch first tries an established connection of the
/// default request group whose peer enabled extended CONNECT (RFC 8441, RFC 9220).
#[derive(Clone, Copy)]
#[cfg_attr(
    not(feature = "ws"),
    allow(
        dead_code,
        reason = "Only WebSocket handshakes request dedicated connections"
    )
)]
pub(super) struct DedicatedConnection {
    #[cfg(any(feature = "http2", feature = "http3"))]
    pub(super) extended_connect: bool,
}

/// Retries canceled checkouts and unsent requests on reused connections.
/// Only the original request returned by dispatch is eligible; failures after
/// encoding remain the responsibility of the public retry policy.
#[derive(Clone)]
pub struct RetryUnsent<S> {
    inner: S,
    enabled: bool,
}

pin_project! {
    /// Drives internal retries without cloning the request body.
    /// The first call consumes the caller's readiness reservation; subsequent
    /// attempts use `Oneshot` to pair readiness and dispatch on the same service.
    pub struct RetryUnsentFuture<S, B>
    where
        S: Service<DispatchRequest<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, DispatchRequest<B>>>,
        service: S,
        original: Original,
        enabled: bool,
    }
}

/// Request state restored before each unsent retry.
/// Kept outside `pin_project!`, whose fields cannot carry `cfg` attributes.
struct Original {
    uri: Uri,
    /// Wire version before a connection fitted it; the next connection may differ.
    version: Version,
    /// Whether the caller set `Cookie`; otherwise each attempt regenerates it.
    #[cfg(feature = "cookies")]
    had_cookie: bool,
}

/// An HTTP request and its frozen connection inputs and reuse key.
/// The connection inputs and key survive unsent retries.
/// Dispatch returns this value only when the original body has not been sent.
pub struct DispatchRequest<B> {
    request: Request<B>,
    req: ConnectRequest,
    connection_identity: ConnectionIdentity,
    /// Whether checkout always connects and never returns the sender to the pool.
    dedicated: bool,
    /// Whether the wire version follows the connection, as an explicit `Protocol::Auto` asks.
    negotiable: bool,
    /// Default-group key whose established sender may carry this WebSocket.
    #[cfg(any(feature = "http2", feature = "http3"))]
    extended_connect_key: Option<ConnectionKey>,
}

/// Creates the configuration and unsent-retry layers for a dispatch service.
///
/// Configuration runs once and shares the client's values across service clones.
/// Tower maps terminal dispatch errors only after retry classification, preserving
/// ownership of any request returned before encoding.
pub fn layer<S, B>(
    protocol: Protocol,
    config: ConnectConfig,
    retry_unsent: bool,
) -> impl Layer<S, Service = Stack<S, B>> + Clone {
    ServiceBuilder::new()
        .layer_fn(move |inner| Stack {
            inner,
            protocol,
            config: config.clone(),
        })
        .map_err(DispatchError::into_error as fn(DispatchError<B>) -> BoxError)
        .layer_fn(move |inner| RetryUnsent {
            inner,
            enabled: retry_unsent,
        })
        .into_inner()
}

// ===== impl Stack =====

impl<S, B> Stack<S, B> {
    /// Checks the request, then freezes connection settings before checkout and unsent
    /// retries. Every redirect hop and public retry passes here again.
    fn prepare(&self, mut request: Request<B>) -> Result<DispatchRequest<B>, Error> {
        match request.version() {
            Version::HTTP_10 if request.method() == Method::CONNECT => {
                warn!("CONNECT is not allowed for HTTP/1.0");
                return Err(Error::from_kind(ErrorKind::UserUnsupportedRequestMethod));
            }
            Version::HTTP_10 | Version::HTTP_11 => {}
            #[cfg(feature = "http2")]
            Version::HTTP_2 => {}
            #[cfg(feature = "http3")]
            Version::HTTP_3 => {}
            _unsupported => {
                warn!("Request has unsupported version: {:?}", _unsupported);
                return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
        }

        // Senders must not generate userinfo (RFC 9110 section 4.2.4), and the
        // connection origin is taken from this authority:
        // <https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4>
        if request
            .uri()
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            request.uri_mut().set_userinfo("", None);
        }

        let extensions = request.extensions_mut();
        let request_config = extensions.remove::<ConnectConfig>().unwrap_or_default();
        let dedicated = extensions.remove::<DedicatedConnection>();

        // Normalize wire versions to protocol choices; HTTP/1.0 and HTTP/1.1 share a pool.
        let version = RequestConfig::<RequestVersion>::remove(extensions);
        let uri = request.uri();

        // curl's ordinary H2 mode allows HTTPS negotiation; prior knowledge
        // remains explicit: https://curl.se/libcurl/c/CURLOPT_HTTP_VERSION.html
        let protocol = match version {
            Some(Version::HTTP_10 | Version::HTTP_11) => Some(Protocol::Http1),
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) if uri.is_https() && self.protocol != Protocol::Http2 => {
                Some(Protocol::Auto)
            }
            #[cfg(feature = "http2")]
            Some(Version::HTTP_2) => Some(Protocol::Http2),
            #[cfg(feature = "http3")]
            Some(Version::HTTP_3) => Some(Protocol::Http3),
            Some(_) => {
                return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion));
            }
            None => None,
        };

        let req = ConnectRequest::new(uri, protocol.unwrap_or(self.protocol), request_config)
            .map_err(|source| {
                debug!("Client requires absolute-form URIs, received: {uri:?}");
                Error::new(ErrorKind::UserAbsoluteUriRequired, source)
            })?;

        // HTTP/3 has no cleartext form; an https-to-http redirect also ends here:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
        #[cfg(feature = "http3")]
        if req.protocol().transport() == TransportKind::Quic && !uri.is_https() {
            warn!("HTTP/3 requires an https URI");
            return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion)
                .with_context("HTTP/3 requires an https URI"));
        }

        let connection_identity = ConnectionIdentity::new(&req, &self.config);

        // Probe the default group only where it may be HTTP/2, or HTTP/3 over https. Without
        // Alt-Svc discovery, an automatic client's explicit HTTP/3 group is not probed.
        #[cfg(any(feature = "http2", feature = "http3"))]
        let extended_connect_key = (dedicated.is_some_and(|d| d.extended_connect)
            && match self.protocol {
                #[cfg(feature = "http2")]
                Protocol::Auto | Protocol::Http2 => true,
                #[cfg(feature = "http3")]
                Protocol::Http3 => uri.is_https(),
                _ => false,
            })
        .then(|| ConnectionKey::for_request(&req, self.protocol, &self.config));

        Ok(DispatchRequest {
            request,
            req,
            connection_identity,
            dedicated: dedicated.is_some(),
            negotiable: protocol == Some(Protocol::Auto),
            #[cfg(any(feature = "http2", feature = "http3"))]
            extended_connect_key,
        })
    }
}

impl<S: Clone, B> Clone for Stack<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            protocol: self.protocol,
            config: self.config.clone(),
        }
    }
}

impl<S, B> Service<Request<B>> for Stack<S, B>
where
    S: Service<DispatchRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Either<
        MapErrFuture<RetryUnsentFuture<S, B>, fn(DispatchError<B>) -> BoxError>,
        Ready<Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        match self.prepare(request) {
            Ok(request) => Either::Left(self.inner.call(request)),
            Err(error) => Either::Right(future::err(error.into())),
        }
    }
}

// ===== impl RetryUnsent =====

impl<S, B> Service<DispatchRequest<B>> for RetryUnsent<S>
where
    S: Service<DispatchRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Response = S::Response;
    type Error = DispatchError<B>;
    type Future = RetryUnsentFuture<S, B>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: DispatchRequest<B>) -> Self::Future {
        let original = Original {
            uri: request.request.uri().clone(),
            version: request.request.version(),
            #[cfg(feature = "cookies")]
            had_cookie: request.request.headers().contains_key(COOKIE),
        };
        let replacement = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, replacement);
        let future = service.call(request);

        RetryUnsentFuture {
            future: Either::Left(future),
            service,
            original,
            enabled: self.enabled,
        }
    }
}

// ===== impl RetryUnsentFuture =====

impl<S, B> Future for RetryUnsentFuture<S, B>
where
    S: Service<DispatchRequest<B>, Error = DispatchError<B>> + Clone,
{
    type Output = Result<S::Response, DispatchError<B>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        const MAX_ATTEMPTS_PER_POLL: usize = 2;

        let mut this = self.project();

        // Retry recovery follows hyper-util's legacy client.
        // Poll budgeting follows Hyper's HTTP/1 dispatcher.
        for _ in 0..MAX_ATTEMPTS_PER_POLL {
            let mut request = match ready!(this.future.as_mut().poll(cx)) {
                Ok(response) => return Poll::Ready(Ok(response)),
                Err(DispatchError::CheckoutCanceled {
                    error: _error,
                    request,
                }) if *this.enabled => {
                    trace!("singleton connection batch canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(DispatchError::Unsent {
                    error: _error,
                    request,
                    connection_reused: true,
                }) if *this.enabled => {
                    trace!("unstarted request canceled, trying again (reason={_error:?})");
                    *request
                }
                Err(error) => return Poll::Ready(Err(error)),
            };

            *request.request.uri_mut() = this.original.uri.clone();
            *request.request.version_mut() = this.original.version;
            // Regenerate automatic cookies for the next protocol; retain user headers.
            #[cfg(feature = "cookies")]
            if !this.original.had_cookie {
                request.request.headers_mut().remove(COOKIE);
            }
            this.future
                .set(Either::Right(Oneshot::new(this.service.clone(), request)));
        }

        // The next Oneshot has not registered a waker; resume it after yielding.
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use http::Response;
    use tower::ServiceExt;

    use super::*;
    #[cfg(feature = "cookies")]
    use crate::cookie::CookieStore;
    use crate::{
        client::pool::{self, TransportConnector},
        conn::Conn,
        rt::DynRuntime,
    };

    /// Wraps `service` in the request stack of a client without options.
    pub(super) fn stack<S, B>(service: S, protocol: Protocol, retry_unsent: bool) -> Stack<S, B> {
        layer(protocol, ConnectConfig::default(), retry_unsent).layer(service)
    }

    /// Dispatches over fresh HTTP/1 connections whose server answers with `handler`.
    pub(super) fn http1_dispatch<F>(
        handler: F,
        #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn CookieStore>>,
    ) -> Dispatch<impl TransportConnector>
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<String> + Clone + Send + Sync + 'static,
    {
        let connector = tower::service_fn(move |_: crate::conn::TransportRequest| {
            let handler = handler.clone();
            let service = hyper::service::service_fn(move |request| {
                future::ready(Ok::<_, std::convert::Infallible>(handler(request)))
            });
            let (client, server) = tokio::io::duplex(16384);
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(server), service),
            );
            future::ready(Ok::<_, BoxError>(Conn::test(client)))
        });
        Dispatch::new(
            pool::Config::default(),
            connector,
            &ConnectConfig::default(),
            true,
            #[cfg(feature = "cookies")]
            cookie_store,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
        )
    }

    #[test]
    fn entry_checks_reject_requests_and_strip_userinfo_before_keying() {
        let stack = stack((), Protocol::Auto, false);
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
            let request = Request::builder()
                .method(method)
                .version(version)
                .uri(uri)
                .body(())
                .unwrap();
            let Err(error) = stack.prepare(request) else {
                panic!("{kind} must reject the request");
            };
            assert_eq!(error.to_string(), format!("client error ({kind})"));
        }

        let prepare = |uri| stack.prepare(Request::get(uri).body(()).unwrap()).unwrap();
        let plain = prepare("http://localhost/");
        let userinfo = prepare("http://user:pw@localhost/");
        assert_eq!(userinfo.request.uri(), "http://localhost/");
        assert_eq!(
            userinfo.connection_identity.key(&userinfo.req),
            plain.connection_identity.key(&plain.req)
        );
    }

    #[test]
    fn partial_emulation_keeps_other_options_across_clone_and_conversion() {
        use crate::{Client, Emulation, Group, http1::Http1Options, tls::TlsOptions};

        let tls = TlsOptions::default();
        let initial_http = Http1Options::builder().max_headers(8).build();
        let updated_http = Http1Options::builder().max_headers(16).build();
        let profile = Emulation::builder()
            .http1_options(initial_http.clone())
            .tls_options(tls.clone())
            .build();
        let client = Client::builder(crate::rt::tokio::TokioRuntime)
            .no_proxy()
            .build()
            .unwrap();
        let address = std::net::Ipv4Addr::LOCALHOST;
        let group = Group::new("profile");
        let request = client
            .get("https://localhost/")
            .local_addresses(address, None)
            .group(group.clone())
            .emulation(profile);
        let original = request.try_clone().unwrap().build().unwrap();
        let updated = request.emulation(updated_http.clone()).build().unwrap();
        let stack = stack((), Protocol::Auto, false);
        for (request, http) in [(original, initial_http), (updated, updated_http)] {
            let wire: Request<crate::Body> = request.into();
            let request = crate::Request::from(wire);
            let request = stack.prepare(request.into()).unwrap();
            let config = request.req.config();
            assert_eq!(config.get_ref::<Http1Options>(), Some(&http));
            assert_eq!(config.get_ref::<TlsOptions>(), Some(&tls));
            assert_eq!(config.get_ref::<std::net::Ipv4Addr>(), Some(&address));
            assert_eq!(config.get_ref::<Group>(), Some(&group));
        }
    }

    #[cfg(feature = "cookies")]
    #[tokio::test]
    async fn unsent_retries_regenerate_automatic_cookies() {
        for explicit in [false, true] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let service = tower::service_fn(move |mut request: DispatchRequest<crate::Body>| {
                let headers = request.request.headers_mut();
                let values: Vec<_> = headers.get_all(COOKIE).iter().collect();
                if explicit {
                    assert_eq!(values, ["user=1", "other=2"]);
                } else {
                    assert!(values.is_empty(), "automatic cookies must be refreshed");
                }

                if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    if !explicit {
                        headers.append(COOKIE, http::HeaderValue::from_static("h2=1"));
                        headers.append(COOKIE, http::HeaderValue::from_static("other=2"));
                    }
                    future::ready(Err(DispatchError::Unsent {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                        connection_reused: true,
                    }))
                } else {
                    future::ready(Ok(()))
                }
            });
            let mut request = Request::builder().uri("https://localhost/");
            if explicit {
                request = request.header(COOKIE, "user=1").header(COOKIE, "other=2");
            }
            stack(service, Protocol::Auto, true)
                .oneshot(request.body(crate::Body::default()).unwrap())
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }

    #[cfg(feature = "http2")]
    #[test]
    fn websocket_probe_uses_the_regular_request_key() {
        let stack = stack((), Protocol::Auto, false);
        let request = |dedicated| {
            let mut request = Request::get("https://localhost/chat")
                .extension({
                    let mut config = ConnectConfig::default();
                    config.insert(crate::Group::new("chat"));
                    config
                })
                .body(())
                .unwrap();
            if let Some(extended_connect) = dedicated {
                let extensions = request.extensions_mut();
                *RequestConfig::<RequestVersion>::get_mut(extensions) = Some(Version::HTTP_11);
                extensions.insert(DedicatedConnection { extended_connect });
            }
            stack.prepare(request).unwrap()
        };

        let regular = request(None);
        assert_eq!(
            request(Some(true)).extended_connect_key,
            Some(regular.connection_identity.key(&regular.req))
        );
        assert!(request(Some(false)).extended_connect_key.is_none());
    }

    #[tokio::test]
    async fn unsent_retries_keep_request_state_and_error_sources() {
        use http_body_util::BodyExt;

        for (enabled, reused, expected_calls) in
            [(true, true, 2), (false, true, 1), (true, false, 1)]
        {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let mut key = None;
            let service = tower::service_fn(move |mut request: DispatchRequest<crate::Body>| {
                let result = if attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                    key = Some(request.connection_identity.key(&request.req));
                    *request.request.uri_mut() = Uri::from_static("/upload?part=1");
                    Err(DispatchError::Unsent {
                        error: Error::new(ErrorKind::Canceled, std::io::Error::other("unsent")),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    assert_eq!(request.request.uri(), "http://localhost/upload?part=1");
                    assert_eq!(key, Some(request.connection_identity.key(&request.req)));
                    assert_eq!(
                        request.req.config().get_ref::<std::net::Ipv4Addr>(),
                        Some(&std::net::Ipv4Addr::LOCALHOST)
                    );
                    Ok(request.request.into_body())
                };
                future::ready(result)
            });

            let mut config = ConnectConfig::default();
            config.insert(std::net::Ipv4Addr::LOCALHOST);
            let result = stack(service, Protocol::Auto, enabled)
                .oneshot(
                    Request::builder()
                        .extension(config)
                        .uri("http://localhost/upload?part=1")
                        .body(crate::Body::from("payload"))
                        .unwrap(),
                )
                .await;

            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            if expected_calls == 2 {
                let body = result.unwrap().collect().await.unwrap().to_bytes();
                assert_eq!(body, "payload");
            } else {
                let error = result.unwrap_err();
                assert!(error.is::<Error>());
                assert_eq!(error.source().unwrap().to_string(), "unsent");
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let gate = Arc::new(tokio::sync::Notify::new());
        let ready = gate.clone();
        let service = tower::service_fn(move |request: DispatchRequest<crate::Body>| {
            let first = attempts.fetch_add(1, Ordering::Relaxed) == 0;
            let ready = ready.clone();
            async move {
                if first {
                    Err(DispatchError::CheckoutCanceled {
                        error: Error::from_kind(ErrorKind::Canceled),
                        request: Box::new(request),
                    })
                } else {
                    ready.notified().await;
                    Ok(())
                }
            }
        });
        let mut task = tokio_test::task::spawn(
            stack(service, Protocol::Auto, true).oneshot(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            ),
        );
        assert!(task.poll().is_pending());
        assert!(!task.is_woken(), "a pending retry owns its wakeup");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        gate.notify_one();
        assert!(task.is_woken());
        assert!(matches!(task.poll(), Poll::Ready(Ok(()))));

        let attempts = Arc::new(AtomicUsize::new(0));
        let service = tower::service_fn(move |request: DispatchRequest<crate::Body>| {
            future::ready(if attempts.fetch_add(1, Ordering::Relaxed) < 8 {
                Err(DispatchError::CheckoutCanceled {
                    error: Error::from_kind(ErrorKind::Canceled),
                    request: Box::new(request),
                })
            } else {
                Ok(())
            })
        });
        let mut task = tokio_test::task::spawn(
            stack(service, Protocol::Auto, true).oneshot(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            ),
        );
        assert!(
            task.poll().is_pending(),
            "a run of ready retries must yield"
        );
        assert!(
            task.is_woken(),
            "the yielded retry must schedule another poll"
        );
    }

    #[tokio::test]
    async fn unsent_retries_restore_the_wire_version_for_http1() {
        use http_body_util::BodyExt;

        let dispatch = http1_dispatch(
            |request| Response::new(format!("{:?}", request.version())),
            #[cfg(feature = "cookies")]
            None,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let service = tower::service_fn(move |mut request: DispatchRequest<crate::Body>| {
            let mut dispatch = dispatch.clone();
            let first = attempts.fetch_add(1, Ordering::Relaxed) == 0;
            async move {
                if !first {
                    return dispatch.call(request).await;
                }
                // A multiplexed connection set its version before returning the request unsent.
                *request.request.version_mut() = Version::HTTP_2;
                Err(DispatchError::Unsent {
                    error: Error::from_kind(ErrorKind::Canceled),
                    request: Box::new(request),
                    connection_reused: true,
                })
            }
        });

        // Without a version preference, HTTP/1 accepts only an HTTP/1 wire version.
        let response = stack(service, Protocol::Auto, true)
            .oneshot(
                Request::get("http://localhost/")
                    .version(Version::HTTP_10)
                    .body(crate::Body::default())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let version = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(version, "HTTP/1.0");
    }
}
