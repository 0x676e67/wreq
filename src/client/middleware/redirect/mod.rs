//! Middleware for following redirections.
//!
//! # Overview
//!
//! The [`FollowRedirect`] middleware retries requests with the inner [`Service`] to follow HTTP
//! redirections.
//!
//! The middleware tries to clone the original [`Request`] when making a redirected request.
//! However, the request body cannot always be cloned. When the
//! original body is known to be empty by [`Body::size_hint`], the middleware uses `Default`
//! implementation of the body type to create a new request body. If you know that the body can be
//! cloned in some way, you can tell the middleware to clone it by configuring a [`policy`].

pub mod policy;

use std::{
    convert::TryFrom,
    future::Future,
    mem,
    pin::Pin,
    str,
    task::{Context, Poll, ready},
};

use futures_util::future::Either;
use http::{
    Extensions, HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, TRANSFER_ENCODING},
};
use http_body::Body;
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use pin_project_lite::pin_project;
use tower::{Layer, util::Oneshot};
use tower_service::Service;

use self::policy::{Action, Attempt, Policy};

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Clone, Copy, Debug, Default)]
pub struct FollowRedirectLayer<P> {
    policy: P,
}

impl<P> FollowRedirectLayer<P> {
    /// Create a new [`FollowRedirectLayer`] with the given redirection [`Policy`].
    pub const fn with_policy(policy: P) -> Self {
        FollowRedirectLayer { policy }
    }
}

impl<S, P> Layer<S> for FollowRedirectLayer<P>
where
    S: Clone,
    P: Clone,
{
    type Service = FollowRedirect<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        FollowRedirect::with_policy(inner, self.policy.clone())
    }
}

/// Middleware that retries requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Clone, Copy, Debug)]
pub struct FollowRedirect<S, P> {
    inner: S,
    policy: P,
}

impl<S, P> FollowRedirect<S, P>
where
    P: Clone,
{
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    pub const fn with_policy(inner: S, policy: P) -> Self {
        FollowRedirect { inner, policy }
    }
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for FollowRedirect<S, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    ReqBody: Body + Default,
    P: Policy<ReqBody, S::Error> + Clone,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, P>;

    #[inline(always)]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let service = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, service);
        let mut policy = self.policy.clone();
        let mut body = BodyRepr::None;
        body.try_clone_from(req.body(), &policy);
        policy.on_request(&mut req);
        ResponseFuture {
            method: req.method().clone(),
            uri: req.uri().clone(),
            version: req.version(),
            headers: req.headers().clone(),
            extensions: req.extensions().clone(),
            body,
            future: Either::Left(service.call(req)),
            service,
            policy,
        }
    }
}

pin_project! {
    /// Response future for [`FollowRedirect`].
    #[derive(Debug)]
    pub struct ResponseFuture<S, B, P>
    where
        S: Service<Request<B>>,
    {
        #[pin]
        future: Either<S::Future, Oneshot<S, Request<B>>>,
        service: S,
        policy: P,
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap<HeaderValue>,
        extensions: Extensions,
        body: BodyRepr<B>,
    }
}

impl<S, ReqBody, ResBody, P> Future for ResponseFuture<S, ReqBody, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    ReqBody: Body + Default,
    P: Policy<ReqBody, S::Error>,
{
    type Output = Result<Response<ResBody>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let mut res = ready!(this.future.as_mut().poll(cx)?);
        res.extensions_mut().insert(RequestUri(this.uri.clone()));

        let drop_payload_headers = |headers: &mut HeaderMap| {
            for header in &[
                CONTENT_TYPE,
                CONTENT_LENGTH,
                CONTENT_ENCODING,
                TRANSFER_ENCODING,
            ] {
                headers.remove(header);
            }
        };
        match res.status() {
            StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => {
                // User agents MAY change the request method from POST to GET
                // (RFC 7231 section 6.4.2. and 6.4.3.).
                if *this.method == Method::POST {
                    *this.method = Method::GET;
                    *this.body = BodyRepr::Empty;
                    drop_payload_headers(this.headers);
                }
            }
            StatusCode::SEE_OTHER => {
                // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                if *this.method != Method::HEAD {
                    *this.method = Method::GET;
                }
                *this.body = BodyRepr::Empty;
                drop_payload_headers(this.headers);
            }
            StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
            _ => return Poll::Ready(Ok(res)),
        };

        let body = if let Some(body) = this.body.take() {
            body
        } else {
            return Poll::Ready(Ok(res));
        };

        let location = res
            .headers()
            .get(&LOCATION)
            .and_then(|loc| resolve_uri(str::from_utf8(loc.as_bytes()).ok()?, this.uri));
        let location = if let Some(loc) = location {
            loc
        } else {
            return Poll::Ready(Ok(res));
        };

        let attempt = Attempt {
            status: res.status(),
            location: &location,
            previous: this.uri,
        };
        match this.policy.redirect(&attempt)? {
            Action::Follow => {
                *this.uri = location;
                this.body.try_clone_from(&body, &this.policy);

                let mut req = Request::new(body);
                *req.uri_mut() = this.uri.clone();
                *req.method_mut() = this.method.clone();
                *req.version_mut() = *this.version;
                *req.headers_mut() = this.headers.clone();
                *req.extensions_mut() = this.extensions.clone();
                this.policy.on_request(&mut req);
                this.future
                    .set(Either::Right(Oneshot::new(this.service.clone(), req)));

                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Action::Stop => Poll::Ready(Ok(res)),
        }
    }
}

/// Response [`Extensions`][http::Extensions] value that represents the effective request URI of
/// a response returned by a [`FollowRedirect`] middleware.
///
/// The value differs from the original request's effective URI if the middleware has followed
/// redirections.
#[derive(Clone)]
pub struct RequestUri(pub Uri);

#[derive(Debug)]
enum BodyRepr<B> {
    Some(B),
    Empty,
    None,
}

impl<B> BodyRepr<B>
where
    B: Body + Default,
{
    fn take(&mut self) -> Option<B> {
        match mem::replace(self, BodyRepr::None) {
            BodyRepr::Some(body) => Some(body),
            BodyRepr::Empty => {
                *self = BodyRepr::Empty;
                Some(B::default())
            }
            BodyRepr::None => None,
        }
    }

    fn try_clone_from<P, E>(&mut self, body: &B, policy: &P)
    where
        P: Policy<B, E>,
    {
        match self {
            BodyRepr::Some(_) | BodyRepr::Empty => {}
            BodyRepr::None => {
                if let Some(body) = clone_body(policy, body) {
                    *self = BodyRepr::Some(body);
                }
            }
        }
    }
}

fn clone_body<P, B, E>(policy: &P, body: &B) -> Option<B>
where
    P: Policy<B, E>,
    B: Body + Default,
{
    if body.size_hint().exact() == Some(0) {
        Some(B::default())
    } else {
        policy.clone_body(body)
    }
}

/// Try to resolve a URI reference `relative` against a base URI `base`.
fn resolve_uri(relative: &str, base: &Uri) -> Option<Uri> {
    let relative = UriReferenceStr::new(relative).ok()?;
    let base = UriAbsoluteString::try_from(base.to_string()).ok()?;
    let uri = relative.resolve_against(&base).to_string();
    Uri::try_from(uri).ok()
}
