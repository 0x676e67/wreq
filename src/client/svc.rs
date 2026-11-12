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
    sync::Arc,
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
#[cfg(feature = "http3")]
use crate::protocol::TransportKind;
use crate::{
    Protocol,
    config::{RequestConfig, connect::ConfigSet},
    conn::{dialer::BindOptions, request::ConnectRequest},
    ext::UriExt,
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
    config_set: ConfigSet,
    bind_options: Arc<BindOptions>,
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

/// A request paired with the connection request shared by its attempts.
/// The connection request is frozen before checkout and retained across unsent retries.
/// Dispatch returns this value only when the original body has not been sent.
pub struct DispatchRequest<B> {
    request: Request<B>,
    req: ConnectRequest,
    /// Whether checkout always connects and never returns the sender to the pool.
    dedicated: bool,
    /// Whether the wire version follows the connection, as an explicit `Protocol::Auto` asks.
    negotiable: bool,
    /// Default-group key whose established sender may carry this WebSocket.
    #[cfg(any(feature = "http2", feature = "http3"))]
    extended_connect_key: Option<crate::conn::request::ConnectionKey>,
}

/// Creates the configuration and unsent-retry layers for a dispatch service.
///
/// Configuration runs once and shares the client's values across service clones.
/// Tower maps terminal dispatch errors only after retry classification, preserving
/// ownership of any request returned before encoding.
pub fn layer<S, B>(
    protocol: Protocol,
    config_set: ConfigSet,
    bind_options: BindOptions,
    retry_unsent: bool,
) -> impl Layer<S, Service = Stack<S, B>> + Clone {
    let bind_options = Arc::new(bind_options);
    ServiceBuilder::new()
        .layer_fn(move |inner| Stack {
            inner,
            protocol,
            config_set: config_set.clone(),
            bind_options: bind_options.clone(),
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
        let config_set = extensions.remove::<ConfigSet>().unwrap_or_default();
        let bind_options = extensions.remove::<Arc<BindOptions>>();
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

        let req = ConnectRequest::new(
            uri,
            protocol,
            self.protocol,
            config_set,
            &self.config_set,
            bind_options,
            &self.bind_options,
        )
        .map_err(|source| {
            debug!("Client requires absolute-form URIs, received: {uri:?}");
            Error::new(ErrorKind::UserAbsoluteUriRequired, source)
        })?;

        // HTTP/3 has no cleartext form; an https-to-http redirect also ends here:
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1
        #[cfg(feature = "http3")]
        if req.resolved_protocol().transport() == TransportKind::Quic && !uri.is_https() {
            warn!("HTTP/3 requires an https URI");
            return Err(Error::from_kind(ErrorKind::UserUnsupportedVersion)
                .with_context("HTTP/3 requires an https URI"));
        }

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
        .then(|| req.key_with_protocol(self.protocol, &self.config_set));

        Ok(DispatchRequest {
            request,
            req,
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
            config_set: self.config_set.clone(),
            bind_options: self.bind_options.clone(),
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http::Response;
    use http_body::Body as _;
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
        layer(
            protocol,
            ConfigSet::default(),
            BindOptions::default(),
            retry_unsent,
        )
        .layer(service)
    }

    /// Dispatches over fresh HTTP/1 connections whose server answers with `handler`.
    pub(super) fn http1_dispatch<F>(
        handler: F,
        #[cfg(feature = "cookies")] cookie_store: Option<Arc<dyn CookieStore>>,
    ) -> Dispatch<impl TransportConnector>
    where
        F: Fn(Request<hyper::body::Incoming>) -> Response<String> + Clone + Send + Sync + 'static,
    {
        let connector = tower::service_fn(move |_: ConnectRequest| {
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
            &ConfigSet::default(),
            true,
            #[cfg(feature = "cookies")]
            cookie_store,
            DynRuntime::new(crate::rt::tokio::TokioRuntime),
        )
    }

    #[tokio::test]
    async fn entry_checks_reject_requests_and_strip_userinfo_before_keying() {
        let stack = stack(
            tower::service_fn(|request: DispatchRequest<()>| {
                future::ready(Ok::<_, DispatchError<()>>(request))
            }),
            Protocol::Auto,
            true,
        );
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
            let Err(error) = stack.clone().oneshot(request).await else {
                panic!("{kind} must reject the request");
            };
            assert_eq!(error.to_string(), format!("client error ({kind})"));
        }

        let prepare = |uri| stack.clone().oneshot(Request::get(uri).body(()).unwrap());
        let plain = prepare("http://localhost/").await.unwrap();
        let userinfo = prepare("http://user:pw@localhost/").await.unwrap();
        assert_eq!(userinfo.request.uri(), "http://localhost/");
        assert_eq!(userinfo.req.key(), plain.req.key());
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

    #[tokio::test]
    #[cfg(feature = "http2")]
    async fn protocol_selection_preserves_wire_versions_and_pool_groups() {
        let mut keys = Vec::new();
        let bind_options = Arc::new(BindOptions {
            ipv4_address: Some(std::net::Ipv4Addr::LOCALHOST),
            ..BindOptions::default()
        });
        for (wire, client, extended, expected) in [
            (
                Some(Version::HTTP_10),
                Protocol::Auto,
                false,
                Some(Protocol::Http1),
            ),
            (
                Some(Version::HTTP_11),
                Protocol::Auto,
                false,
                Some(Protocol::Http1),
            ),
            (
                Some(Version::HTTP_2),
                Protocol::Auto,
                false,
                Some(Protocol::Auto),
            ),
            (None, Protocol::Auto, false, None),
            (
                Some(Version::HTTP_2),
                Protocol::Http2,
                false,
                Some(Protocol::Http2),
            ),
            (
                Some(Version::HTTP_2),
                Protocol::Auto,
                true,
                Some(Protocol::Auto),
            ),
            (
                Some(Version::HTTP_11),
                Protocol::Http2,
                false,
                Some(Protocol::Http1),
            ),
            (
                Some(Version::HTTP_2),
                Protocol::Http1,
                false,
                Some(Protocol::Auto),
            ),
            #[cfg(feature = "http3")]
            (None, Protocol::Http3, false, None),
            #[cfg(feature = "http3")]
            (
                Some(Version::HTTP_3),
                Protocol::Auto,
                false,
                Some(Protocol::Http3),
            ),
            #[cfg(feature = "http3")]
            (
                Some(Version::HTTP_11),
                Protocol::Http3,
                false,
                Some(Protocol::Http1),
            ),
        ] {
            let mut request = Request::builder()
                .uri("https://localhost/upload?part=1")
                .version(wire.unwrap_or(Version::HTTP_11))
                .body(())
                .unwrap();
            *RequestConfig::<RequestVersion>::get_mut(request.extensions_mut()) = wire;
            request.extensions_mut().insert(bind_options.clone());
            request
                .extensions_mut()
                .get_or_insert_default::<ConfigSet>()
                .insert(crate::Group::new("seven"));
            if extended {
                *request.method_mut() = http::Method::CONNECT;
                request
                    .extensions_mut()
                    .insert(http2::ext::Protocol::from_static("websocket"));
            }
            let service = tower::service_fn(|request: DispatchRequest<()>| {
                future::ready(Ok::<_, DispatchError<()>>(request))
            });
            let request = stack(service, client, true).oneshot(request).await.unwrap();
            assert_eq!(request.req.resolved_protocol(), expected.unwrap_or(client));
            assert_eq!(request.negotiable, expected == Some(Protocol::Auto));
            assert_eq!(
                request.req.bind_options().as_deref(),
                Some(bind_options.as_ref())
            );
            assert!(
                request
                    .request
                    .extensions()
                    .get::<Arc<BindOptions>>()
                    .is_none()
            );
            assert_eq!(request.request.version(), wire.unwrap_or(Version::HTTP_11));
            assert!(RequestConfig::<RequestVersion>::get(request.request.extensions()).is_none());
            assert_eq!(
                request.req.config_set().get::<crate::Group>(),
                Some(&crate::Group::new("seven"))
            );
            keys.push(request.req.key());
        }
        assert_eq!(
            keys[0], keys[1],
            "HTTP/1.0 and HTTP/1.1 select one protocol pool"
        );
        assert_eq!(keys[1], keys[6], "explicit H1 overrides the client mode");
        assert_ne!(
            keys[1], keys[2],
            "fixed H1 and negotiated requests remain isolated"
        );
        assert_eq!(
            keys[2], keys[3],
            "explicit negotiation shares the pool of an automatic client"
        );
        assert_ne!(
            keys[2], keys[4],
            "negotiated and fixed H2 must not share a pool entry"
        );
        assert_eq!(keys[2], keys[5], "Protocol does not override negotiation");
        assert_eq!(keys[2], keys[7], "request negotiation overrides fixed H1");
        #[cfg(feature = "http3")]
        {
            assert_eq!(keys[8], keys[9], "explicit and inherited H3 share a pool");
            assert_eq!(keys[1], keys[10], "explicit H1 overrides fixed H3");
        }
    }

    #[tokio::test]
    async fn unsent_retries_keep_request_state_and_error_sources() {
        for (enabled, reused, unsent, expected_calls) in [
            (true, true, false, 1),
            (true, true, true, 2),
            (false, true, true, 1),
            (true, false, true, 1),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let attempts = calls.clone();
            let mut req = None;
            let service = tower::service_fn(move |mut request: DispatchRequest<crate::Body>| {
                assert_eq!(request.request.uri(), "http://localhost/upload?part=1");
                assert_eq!(
                    request.request.body().size_hint().exact(),
                    Some("payload".len() as u64)
                );
                assert_eq!(request.req.uri(), "http://localhost/");

                let result = if attempts.fetch_add(1, Ordering::Relaxed) == 0 && unsent {
                    req = Some(request.req.clone());
                    *request.request.uri_mut() = Uri::from_static("/upload?part=1");
                    Err(DispatchError::Unsent {
                        error: Error::new(ErrorKind::Canceled, std::io::Error::other("unsent")),
                        request: Box::new(request),
                        connection_reused: reused,
                    })
                } else {
                    if let Some(req) = &req {
                        assert_eq!(req.key(), request.req.key());
                    }
                    Ok(())
                };
                future::ready(result)
            });

            let result = stack(service, Protocol::Auto, enabled).oneshot(
                Request::builder()
                    .uri("http://localhost/upload?part=1")
                    .body(crate::Body::from("payload"))
                    .unwrap(),
            );
            let mut task = tokio_test::task::spawn(result);
            let Poll::Ready(result) = task.poll() else {
                panic!("a successful or terminal result should finish without yielding");
            };
            assert!(!task.is_woken());

            assert_eq!(calls.load(Ordering::Relaxed), expected_calls);
            if !unsent || expected_calls == 2 {
                result.unwrap();
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

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = calls.clone();
        let service = tower::service_fn(move |request: DispatchRequest<crate::Body>| {
            attempts.fetch_add(1, Ordering::Relaxed);
            future::ready(Err::<(), _>(DispatchError::CheckoutCanceled {
                error: Error::from_kind(ErrorKind::Canceled),
                request: Box::new(request),
            }))
        });
        let mut task = tokio_test::task::spawn(
            stack(service, Protocol::Auto, true).oneshot(
                Request::builder()
                    .uri("http://localhost/")
                    .body(crate::Body::default())
                    .unwrap(),
            ),
        );
        for expected in [2, 4] {
            assert!(task.poll().is_pending());
            assert!(task.is_woken());
            assert_eq!(calls.load(Ordering::Relaxed), expected);
        }
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
