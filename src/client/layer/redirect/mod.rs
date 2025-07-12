//! Middleware for following redirections.

mod future;
pub mod policy;

use std::{
    mem,
    task::{Context, Poll},
};

use futures_util::future::Either;
use http::{Request, Response, Uri};
use http_body::Body;
use tower::Layer;
use tower_service::Service;

use self::{future::ResponseFuture, policy::Policy};

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
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
        policy.load(&req);

        if policy.allowed() {
            let mut body = BodyRepr::None;
            body.try_clone_from(req.body(), &policy);
            policy.on_request(&mut req);
            ResponseFuture::Redirect {
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
        } else {
            ResponseFuture::NoRedirect {
                future: service.call(req),
            }
        }
    }
}

/// Response [`http::Extensions`] value that represents the effective request URI of
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
