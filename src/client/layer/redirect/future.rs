use std::{
    future::Future,
    pin::Pin,
    str,
    task::{Context, Poll, ready},
};

use futures_util::future::Either;
use http::{
    HeaderMap, Method, Request, Response, StatusCode, Uri,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, LOCATION, TRANSFER_ENCODING},
    request::Parts,
};
use http_body::Body;
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use pin_project_lite::pin_project;
use tower::{Service, util::Oneshot};

use super::{
    BodyRepr,
    policy::{Action, Attempt, Policy},
};
use crate::{Error, error::BoxError, ext::RequestUri};

pub type RedirectFuturePin<'a, S, ReqBody> =
    Pin<&'a mut Either<<S as Service<Request<ReqBody>>>::Future, Oneshot<S, Request<ReqBody>>>>;

pub type PendingFuture = Pin<Box<dyn Future<Output = Action> + Send>>;

macro_rules! ready_ok {
    ($expr:expr, $ret:expr) => {
        match $expr {
            Some(v) => v,
            None => return Poll::Ready(Ok($ret)),
        }
    };
}

/// Pending state for a redirect decision
pub struct PendingState<ReqBody, Response> {
    future: PendingFuture,
    location: Uri,
    req_body: ReqBody,
    res: Response,
}

pin_project! {
    /// Response future for [`FollowRedirect`].
    #[project = ResponseFutureProj]
    pub enum ResponseFuture<S, B, P>
    where
        S: Service<Request<B>>,
    {
        Redirect {
            #[pin]
            future: Either<S::Future, Oneshot<S, Request<B>>>,
            pending_future: Option<PendingState<B, S::Response>>,
            service: S,
            policy: P,
            parts: Parts,
            body: BodyRepr<B>,
        },

        Direct {
            #[pin]
            future: S::Future,
        },
    }
}

impl<S, ReqBody, ResBody, P> Future for ResponseFuture<S, ReqBody, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    S::Error: From<BoxError>,
    P: Policy<ReqBody, S::Error>,
    ReqBody: Body + Default,
{
    type Output = Result<Response<ResBody>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResponseFutureProj::Direct { mut future } => future.as_mut().poll(cx),
            ResponseFutureProj::Redirect {
                mut future,
                pending_future,
                service,
                policy,
                parts,
                body,
            } => {
                // Check if we have a pending action to resolve
                if let Some(mut state) = pending_future.take() {
                    let action = match state.future.as_mut().poll(cx) {
                        Poll::Ready(action) => action,
                        Poll::Pending => {
                            *pending_future = Some(state);
                            return Poll::Pending;
                        }
                    };

                    // Process the resolved action
                    return handle_action(
                        action,
                        &mut future,
                        service,
                        policy,
                        cx,
                        parts,
                        state.req_body,
                        body,
                        state.res,
                        state.location,
                    );
                }

                // Poll the current future to get the response
                let mut res = {
                    let mut res = ready!(future.as_mut().poll(cx)?);
                    res.extensions_mut().insert(RequestUri(parts.uri.clone()));
                    res
                };

                // Determine if the response is a redirect
                match res.status() {
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => {
                        // User agents MAY change the request method from POST to GET
                        // (RFC 7231 section 6.4.2. and 6.4.3.).
                        if parts.method == Method::POST {
                            parts.method = Method::GET;
                            *body = BodyRepr::Empty;
                            drop_payload_headers(&mut parts.headers);
                        }
                    }
                    StatusCode::SEE_OTHER => {
                        // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                        if parts.method != Method::HEAD {
                            parts.method = Method::GET;
                        }
                        *body = BodyRepr::Empty;
                        drop_payload_headers(&mut parts.headers);
                    }
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
                    _ => {
                        // Not a redirect status code, return the response as is.
                        policy.on_response(&mut res);
                        return Poll::Ready(Ok(res));
                    }
                };

                // Extract the request body for potential reuse
                let req_body = ready_ok!(body.take(), res);

                // Get and resolve the Location header
                let location = {
                    let location = res
                        .headers()
                        .get(LOCATION)
                        .and_then(|loc| loc.to_str().ok())
                        .and_then(|loc| resolve_uri(loc, &parts.uri));
                    ready_ok!(location, res)
                };

                // Prepare the attempt for the policy decision
                let attempt = Attempt {
                    status: res.status(),
                    headers: res.headers(),
                    location: &location,
                    previous: &parts.uri,
                };

                // Resolve the action, awaiting if it's pending
                let action = match policy.redirect(attempt)? {
                    Action::Pending(future) => {
                        // Save the task and necessary state for next poll
                        *pending_future = Some(PendingState {
                            future,
                            location,
                            req_body,
                            res,
                        });
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    action => action,
                };

                handle_action(
                    action,
                    &mut future,
                    service,
                    policy,
                    cx,
                    parts,
                    req_body,
                    body,
                    res,
                    location,
                )
            }
        }
    }
}

/// Try to resolve a URI reference `relative` against a base URI `base`.
fn resolve_uri(relative: &str, base: &Uri) -> Option<Uri> {
    let relative = UriReferenceStr::new(relative).ok()?;
    let base = UriAbsoluteString::try_from(base.to_string()).ok()?;
    let uri = relative.resolve_against(&base).to_string();
    Uri::try_from(uri).ok()
}

/// Handle the response based on its status code
fn drop_payload_headers(headers: &mut HeaderMap) {
    for header in &[
        CONTENT_TYPE,
        CONTENT_LENGTH,
        CONTENT_ENCODING,
        TRANSFER_ENCODING,
    ] {
        headers.remove(header);
    }
}

/// Handle the redirect action and return the appropriate poll result.
#[allow(clippy::too_many_arguments)]
fn handle_action<S, ReqBody, ResBody, P>(
    action: Action,
    future: &mut RedirectFuturePin<'_, S, ReqBody>,
    service: &S,
    policy: &mut P,
    cx: &mut Context<'_>,
    parts: &mut Parts,
    req_body: ReqBody,
    body: &mut BodyRepr<ReqBody>,
    res: Response<ResBody>,
    location: Uri,
) -> Poll<Result<Response<ResBody>, S::Error>>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    S::Error: From<BoxError>,
    P: Policy<ReqBody, S::Error>,
    ReqBody: Body + Default,
{
    match action {
        Action::Follow => {
            parts.uri = location;
            body.try_clone_from(&req_body, policy);

            let mut req = Request::from_parts(parts.clone(), req_body);
            policy.on_request(&mut req);
            future.set(Either::Right(Oneshot::new(service.clone(), req)));

            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Action::Stop => Poll::Ready(Ok(res)),
        Action::Pending(_) => {
            // Nested pending is not supported.
            Poll::Ready(Err(S::Error::from(
                Error::redirect(
                    "Nested pending Action is not supported in redirect policy",
                    parts.uri.clone(),
                )
                .into(),
            )))
        }
        Action::Error(err) => Poll::Ready(Err(err.into())),
    }
}
