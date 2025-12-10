use std::{
    mem,
    task::{Context, Poll},
};

use futures_util::future::Either;
use http::{Request, Response};
use http_body::Body;
use tower::{Layer, Service};

use super::{BodyRepr, future::ResponseFuture, policy::Policy};
use crate::error::BoxError;

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
#[derive(Clone, Copy, Default)]
pub struct FollowRedirectLayer<P> {
    policy: P,
}

impl<P> FollowRedirectLayer<P> {
    /// Create a new [`FollowRedirectLayer`] with the given redirection [`Policy`].
    #[inline(always)]
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

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        FollowRedirect::with_policy(inner, self.policy.clone())
    }
}

/// Middleware that retries requests with a [`Service`] to follow redirection responses.
#[derive(Clone, Copy)]
pub struct FollowRedirect<S, P> {
    inner: S,
    policy: P,
}

impl<S, P> FollowRedirect<S, P>
where
    P: Clone,
{
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    #[inline(always)]
    pub const fn with_policy(inner: S, policy: P) -> Self {
        FollowRedirect { inner, policy }
    }
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for FollowRedirect<S, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    S::Error: From<BoxError>,
    P: Policy<ReqBody, S::Error> + Clone,
    ReqBody: Body + Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<S, ReqBody, P>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let service = self.inner.clone();
        let mut service = mem::replace(&mut self.inner, service);
        let mut policy = self.policy.clone();

        if policy.follow_redirects(req.extensions()) {
            let mut body_repr = BodyRepr::None;
            body_repr.try_clone_from(req.body(), &policy);
            policy.on_request(&mut req);

            let (parts, body) = req.into_parts();
            let req = Request::from_parts(parts.clone(), body);
            ResponseFuture::Redirect {
                future: Either::Left(service.call(req)),
                pending_future: None,
                service,
                policy,
                parts,
                body_repr,
            }
        } else {
            ResponseFuture::Direct {
                future: service.call(req),
            }
        }
    }
}
