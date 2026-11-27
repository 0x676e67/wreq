//! Single-attempt pool checkout, protocol reconciliation, cookie application, and send completion.

use std::{
    future::{Future, poll_fn},
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use http::{HeaderValue, Method, Response, Uri, Version, header::HOST, uri::Authority};
use netty::{body::Incoming, conn::TrySendError};
use tower::BoxError;
#[cfg(feature = "cookies")]
use {
    crate::cookie::{CookieStore, Cookies},
    http::header::COOKIE,
    std::sync::Arc,
};

#[cfg(any(feature = "http2", feature = "http3"))]
use super::super::upgrade;
use super::{
    super::{
        error::{self, ErrorKind},
        pool,
    },
    prepare::Prepared,
    retry::{Attempt, AttemptOutcome, Retryable, Step},
};
use crate::{
    Body, conn,
    ext::UriExt,
    reuse,
    rt::{DynRuntime, Executor},
};

/// Shared pool, cookie store, and prepared connection metadata for one HTTP dispatch.
pub(super) struct Dispatch {
    pub(super) pool: pool::Pool<reuse::Key, conn::ConnectService, DynRuntime>,
    #[cfg(feature = "cookies")]
    pub(super) cookie_store: Option<Arc<dyn CookieStore>>,
    pub(super) prepared: Prepared,
}

/// Per-attempt dispatch state owned by [`super::retry::Retry`] while [`Dispatch`] is in flight.
pub(super) enum SendState {
    /// Cold dial or queued checkout; boxed so warm hits do not pay for `Checkout + Request`.
    Checkout(Box<(pool::Checkout, http::Request<Body>)>),
    /// `future` drops before `pooled` so cancellation tears down the stream first.
    Sending {
        future: netty::conn::ResponseFuture<Body>,
        pooled: pool::Pooled,
        #[cfg(any(feature = "http2", feature = "http3"))]
        extended: bool,
        #[cfg(any(feature = "http2", feature = "http3"))]
        rewritten: Option<Box<upgrade::Rewritten>>,
    },
    Done,
}

impl Dispatch {
    /// Transitions after a completed pool checkout.
    fn on_checkout(
        &self,
        result: Result<pool::Pooled, BoxError>,
        request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<SendState, Response<Incoming>> {
        match result {
            Ok(pooled) => self.poll_send(
                request,
                pooled,
                #[cfg(any(feature = "http2", feature = "http3"))]
                None,
                uri,
                cx,
            ),
            Err(error) if pool::is_canceled(&*error) => {
                Step::Ready(AttemptOutcome::CheckoutCanceled(Box::new(Retryable {
                    error: error::Error::new(ErrorKind::Connect, error),
                    request,
                })))
            }
            Err(error) => Step::Ready(AttemptOutcome::Done(Err(error::Error::new(
                ErrorKind::Connect,
                error,
            )))),
        }
    }

    /// Reconciles `request` for `pooled`, applies cookies, sends, and polls once.
    fn poll_send(
        &self,
        mut request: http::Request<Body>,
        mut pooled: pool::Pooled,
        #[cfg(any(feature = "http2", feature = "http3"))] rewritten: Option<
            Box<upgrade::Rewritten>,
        >,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<SendState, Response<Incoming>> {
        let _extended = match reconcile(
            &mut request,
            &pooled,
            self.prepared.negotiable,
            #[cfg(any(feature = "http2", feature = "http3"))]
            self.prepared.upgrade.as_deref(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            rewritten.is_some(),
        ) {
            Ok(extended) => extended,
            Err(error) => return Step::Ready(AttemptOutcome::Done(Err(error))),
        };

        // Cookies keep the original request URI; only the wire target of a CONNECT changes.
        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = self.cookie_store.as_deref() {
            apply_request_cookies(&mut request, cookie_store, uri, pooled.version());
        }

        let mut future = match pooled.send_request(request) {
            Ok(future) => future,
            Err(error) => {
                return Step::Ready(AttemptOutcome::Done(Err(
                    error.with_connect_info(pooled.connected().clone())
                )));
            }
        };

        match Pin::new(&mut future).poll(cx) {
            Poll::Pending => Step::Pending(SendState::Sending {
                future,
                pooled,
                #[cfg(any(feature = "http2", feature = "http3"))]
                extended: _extended,
                #[cfg(any(feature = "http2", feature = "http3"))]
                rewritten,
            }),
            Poll::Ready(result) => {
                drop(future);
                Step::Ready(self.finish(
                    result,
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    _extended,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
                    uri,
                ))
            }
        }
    }

    /// Finalizes a completed send, classifying unsent errors or attaching metadata and cookies.
    fn finish(
        &self,
        result: Result<Response<Incoming>, TrySendError<http::Request<Body>>>,
        mut pooled: pool::Pooled,
        #[cfg(any(feature = "http2", feature = "http3"))] extended: bool,
        #[cfg(any(feature = "http2", feature = "http3"))] rewritten: Option<
            Box<upgrade::Rewritten>,
        >,
        uri: &Uri,
    ) -> AttemptOutcome<Response<Incoming>> {
        let mut response = match result {
            Ok(response) => response,
            Err(mut error) => {
                let connection_reused = pooled.is_reused();
                let connect_info = pooled.connected().clone();
                let unnegotiated_h2 = pooled.version() == Version::HTTP_2
                    && uri.is_https()
                    && !connect_info.is_negotiated_h2();

                // A returned request was not sent; only protocol rejections are final,
                // since they repeat on the same connection.
                if !error.error().is_user()
                    && let Some(unsent) = error.take_message()
                {
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    let mut unsent = unsent;
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    if let Some(rewritten) = rewritten {
                        rewritten.restore(&mut unsent);
                    } else if matches!(
                        self.prepared.upgrade.as_deref(),
                        Some(upgrade::Plan::ExtendedConnect(_))
                    ) {
                        upgrade::Protocol::clear_from(&mut unsent);
                    }

                    return AttemptOutcome::Unsent {
                        retry: Box::new(Retryable {
                            error: with_h2_alpn_context(
                                error::Error::new(ErrorKind::Canceled, error.into_error()),
                                unnegotiated_h2,
                            )
                            .with_connect_info(connect_info),
                            request: unsent,
                        }),
                        connection_reused,
                    };
                }

                // The peer's SETTINGS may have arrived while the send was pending.
                #[cfg(any(feature = "http2", feature = "http3"))]
                if extended && pooled.extended_connect() == Some(false) {
                    return AttemptOutcome::Done(Err(extended_connect_disabled(&pooled)));
                }

                return AttemptOutcome::Done(Err(with_h2_alpn_context(
                    error::Error::new(ErrorKind::SendRequest, error.into_error()),
                    unnegotiated_h2,
                )
                .with_connect_info(connect_info)));
            }
        };

        #[cfg(feature = "cookies")]
        if let Some(cookie_store) = self.cookie_store.as_deref() {
            store_response_cookies(&response, cookie_store, uri);
        }

        pooled.connected().set_extras(response.extensions_mut());
        response.extensions_mut().insert(pooled.connected().clone());

        // Multiplexed senders are shared; only busy HTTP/1 senders wait for readiness
        // before dropping so they can return to the pool once the response finishes.
        if pooled.version() != Version::HTTP_11 || !pooled.is_pool_enabled() || pooled.is_ready() {
            drop(pooled);
        } else {
            self.pool.execute(Box::pin(async move {
                let _ = poll_fn(|cx| pooled.poll_ready(cx)).await;
            }));
        }

        AttemptOutcome::Done(Ok(response))
    }
}

impl Attempt for Dispatch {
    type Output = Response<Incoming>;
    type State = SendState;

    fn start(
        &mut self,
        #[allow(unused_mut)] mut request: http::Request<Body>,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Step<Self::State, Self::Output> {
        // RFC 8441 §3 and RFC 9220 §3: extended CONNECT only after the peer enabled it.
        // A miss keeps the dedicated HTTP/1.1 upgrade without opening H2/H3.
        #[cfg(any(feature = "http2", feature = "http3"))]
        if let Some(upgrade::Plan::Adaptive {
            key,
            protocol,
            strip_headers,
        }) = self.prepared.upgrade.as_deref()
            && let Some(pooled) = self.pool.checkout_extended_connect(key)
        {
            if let Some(rewritten) = upgrade::Rewritten::try_rewrite(
                &mut request,
                pooled.version(),
                protocol,
                strip_headers.as_deref().unwrap_or(&[]),
            ) {
                return self.poll_send(request, pooled, Some(rewritten), uri, cx);
            }
            drop(pooled);
        }

        let mut future = self
            .pool
            .checkout(self.prepared.key.as_ref(), &self.prepared.request);
        match Pin::new(&mut future).poll(cx) {
            Poll::Pending => Step::Pending(SendState::Checkout(Box::new((future, request)))),
            Poll::Ready(result) => {
                drop(future);
                self.on_checkout(result, request, uri, cx)
            }
        }
    }

    fn poll(
        &mut self,
        state: &mut Self::State,
        uri: &Uri,
        cx: &mut Context<'_>,
    ) -> Poll<AttemptOutcome<Self::Output>> {
        match state {
            SendState::Checkout(pending) => {
                let result = ready!(Pin::new(&mut pending.0).poll(cx));
                let SendState::Checkout(pending) = mem::replace(state, SendState::Done) else {
                    return Poll::Pending;
                };
                let (future, request) = *pending;
                drop(future);
                match self.on_checkout(result, request, uri, cx) {
                    Step::Pending(next) => {
                        *state = next;
                        Poll::Pending
                    }
                    Step::Ready(outcome) => Poll::Ready(outcome),
                }
            }
            SendState::Sending { future, .. } => {
                let result = ready!(Pin::new(future).poll(cx));
                let SendState::Sending {
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    extended,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
                    ..
                } = mem::replace(state, SendState::Done)
                else {
                    return Poll::Pending;
                };
                Poll::Ready(self.finish(
                    result,
                    pooled,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    extended,
                    #[cfg(any(feature = "http2", feature = "http3"))]
                    rewritten,
                    uri,
                ))
            }
            SendState::Done => Poll::Pending,
        }
    }
}

/// Explains failures of HTTP/2 used over HTTPS without negotiating `h2` in ALPN.
#[must_use]
fn with_h2_alpn_context(error: error::Error, unnegotiated_h2: bool) -> error::Error {
    if unnegotiated_h2 {
        error.with_context(
            "HTTP/2 was used for HTTPS without reported h2 ALPN; \
             the peer may not support HTTP/2",
        )
    } else {
        error
    }
}

/// Adjusts `request` to match `pooled` and returns `true` if it uses extended CONNECT.
///
/// Sets the wire version for multiplexed or negotiable requests, rejects incompatible
/// versions on HTTP/1, and fills in the default port for plain CONNECT targets.
fn reconcile(
    request: &mut http::Request<Body>,
    pooled: &pool::Pooled,
    negotiable: bool,
    #[cfg(any(feature = "http2", feature = "http3"))] plan: Option<&upgrade::Plan>,
    #[cfg(any(feature = "http2", feature = "http3"))] rewritten: bool,
) -> Result<bool, error::Error> {
    let extended = cfg_select! {
        any(feature = "http2", feature = "http3") => {{
            let extended = if rewritten {
                true
            } else if let Some(upgrade::Plan::ExtendedConnect(protocol)) = plan {
                protocol
                    .insert_into(request, pooled.version())
                    .map_err(|error| error.with_connect_info(pooled.connected().clone()))?;
                true
            } else {
                request.method() == Method::CONNECT && matched_extended_connect(request, pooled)?
            };
            if extended && !rewritten && pooled.extended_connect() == Some(false) {
                return Err(extended_connect_disabled(pooled));
            }
            extended
        }}
        _ => false,
    };

    let version = pooled.version();
    let multiplexed = version != Version::HTTP_11;
    if multiplexed || negotiable {
        *request.version_mut() = version;
    } else if !matches!(request.version(), Version::HTTP_10 | Version::HTTP_11) {
        warn!(
            "Connection is HTTP/1, but request requires {:?}",
            request.version()
        );
        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_connect_info(pooled.connected().clone()));
    }

    if request.method() == Method::CONNECT && !extended {
        connect_target_port(request, multiplexed)?;
    }
    Ok(extended)
}

/// Validates protocol markers provided directly through request extensions.
#[cfg(any(feature = "http2", feature = "http3"))]
fn matched_extended_connect(
    request: &http::Request<Body>,
    pooled: &pool::Pooled,
) -> Result<bool, error::Error> {
    let extensions = request.extensions();
    let http2 = cfg_select! {
        feature = "http2" => extensions.get::<http2::ext::Protocol>().is_some(),
        _ => false,
    };
    let http3 = cfg_select! {
        feature = "http3" => extensions.get::<netty::http3::Protocol>().is_some(),
        _ => false,
    };
    let matched = match pooled.version() {
        Version::HTTP_2 => http2,
        Version::HTTP_3 => http3,
        _ => false,
    };
    if (http2 || http3) && !matched {
        warn!("extended CONNECT protocol does not match the connection's HTTP version");
        return Err(error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
            .with_connect_info(pooled.connected().clone()));
    }
    Ok(matched)
}

/// Rejects extended CONNECT unless the peer enabled it (RFC 8441 §3, RFC 9220 §3).
#[must_use]
#[cfg(any(feature = "http2", feature = "http3"))]
fn extended_connect_disabled(pooled: &pool::Pooled) -> error::Error {
    warn!("peer did not enable extended CONNECT");
    error::Error::from_kind(ErrorKind::UserUnsupportedVersion)
        .with_context("peer did not enable extended CONNECT")
        .with_connect_info(pooled.connected().clone())
}

/// Fills in the scheme's default port on a plain CONNECT target when omitted
/// ([RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)).
///
/// On HTTP/2 and HTTP/3, also updates a matching `Host` header so it stays consistent with
/// `:authority` ([RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113#section-8.3.1),
/// [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1)).
fn connect_target_port<B>(
    request: &mut http::Request<B>,
    multiplexed: bool,
) -> Result<(), error::Error> {
    let uri = request.uri();
    let Some(authority) = uri.authority() else {
        return Ok(());
    };

    // `Uri` also accepts ports a u16 cannot hold; only an absent or empty port is elided.
    let port = authority
        .as_str()
        .rsplit('@')
        .next()
        .and_then(|host_port| host_port.strip_prefix(authority.host()));

    if !matches!(port, Some("" | ":")) {
        return Ok(());
    }

    let target = format!("{}:{}", authority.host(), uri.port_or_default())
        .parse::<Authority>()
        .map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;

    if multiplexed
        && request
            .headers()
            .get(HOST)
            .is_some_and(|host| host == authority.as_str())
    {
        let host = HeaderValue::from_str(target.as_str())
            .map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;
        request.headers_mut().insert(HOST, host);
    }

    let mut parts = mem::take(request.uri_mut()).into_parts();
    parts.authority = Some(target);
    *request.uri_mut() =
        Uri::from_parts(parts).map_err(|error| error::Error::new(ErrorKind::SendRequest, error))?;
    Ok(())
}

/// Populates `Cookie` headers from `cookie_store` unless the caller already set one.
#[cfg(feature = "cookies")]
fn apply_request_cookies<B>(
    request: &mut http::Request<B>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
    version: Version,
) {
    let headers = request.headers_mut();
    if headers.contains_key(COOKIE) {
        return;
    }
    match cookie_store.cookies(uri, version) {
        Cookies::Compressed(value) => {
            headers.insert(COOKIE, value);
        }
        Cookies::Uncompressed(values) => {
            for value in values {
                headers.append(COOKIE, value);
            }
        }
        Cookies::Empty => {}
    }
}

/// Persists any `Set-Cookie` response headers into `cookie_store`.
#[cfg(feature = "cookies")]
fn store_response_cookies(
    response: &Response<Incoming>,
    cookie_store: &dyn CookieStore,
    uri: &Uri,
) {
    let mut cookies = response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .peekable();
    if cookies.peek().is_some() {
        cookie_store.set_cookies(&mut cookies, uri);
    }
}
