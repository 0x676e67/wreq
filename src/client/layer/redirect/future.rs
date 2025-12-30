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
use pin_project_lite::pin_project;
use tower::{Service, util::Oneshot};
use url::Url;

use super::{Action, Attempt, BodyRepr, Policy};
use crate::{Error, error::BoxError, ext::RequestUri, into_uri::IntoUriSealed};

/// Pending future state for handling redirects.
pub struct Pending<ReqBody, Response> {
    future: Pin<Box<dyn Future<Output = Action> + Send>>,
    location: Uri,
    body: ReqBody,
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
            pending_future: Option<Pending<B, S::Response>>,
            service: S,
            policy: P,
            parts: Parts,
            body_repr: BodyRepr<B>,
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
                body_repr,
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

                    return handle_action(
                        cx,
                        RedirectAction {
                            action,
                            future: &mut future,
                            service,
                            policy,
                            parts,
                            body: state.body,
                            body_repr,
                            res: state.res,
                            location: state.location,
                        },
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
                            *body_repr = BodyRepr::Empty;
                            drop_payload_headers(&mut parts.headers);
                        }
                    }
                    StatusCode::SEE_OTHER => {
                        // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                        if parts.method != Method::HEAD {
                            parts.method = Method::GET;
                        }
                        *body_repr = BodyRepr::Empty;
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
                let Some(body) = body_repr.take() else {
                    return Poll::Ready(Ok(res));
                };

                // Get and resolve the Location header
                let Some(location) = res
                    .headers()
                    .get(LOCATION)
                    .and_then(|loc| loc.to_str().ok())
                    .and_then(|loc| resolve_uri(loc, &parts.uri))
                else {
                    return Poll::Ready(Ok(res));
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
                        *pending_future = Some(Pending {
                            future,
                            location,
                            body,
                            res,
                        });
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    action => action,
                };

                handle_action(
                    cx,
                    RedirectAction {
                        action,
                        future: &mut future,
                        service,
                        policy,
                        parts,
                        body,
                        body_repr,
                        res,
                        location,
                    },
                )
            }
        }
    }
}

/// Try to resolve a URI reference `relative` against a base URI `base`.
fn resolve_uri(relative: &str, base: &Uri) -> Option<Uri> {
    Url::parse(&base.to_string())
        .ok()?
        .join(relative)
        .map(String::from)
        .ok()?
        .into_uri()
        .ok()
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

type RedirectFuturePin<'a, S, ReqBody> =
    Pin<&'a mut Either<<S as Service<Request<ReqBody>>>::Future, Oneshot<S, Request<ReqBody>>>>;

struct RedirectAction<'a, S, ReqBody, ResBody, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    P: Policy<ReqBody, S::Error>,
{
    action: Action,
    future: &'a mut RedirectFuturePin<'a, S, ReqBody>,
    service: &'a S,
    policy: &'a mut P,
    parts: &'a mut Parts,
    body: ReqBody,
    body_repr: &'a mut BodyRepr<ReqBody>,
    res: Response<ResBody>,
    location: Uri,
}

fn handle_action<S, ReqBody, ResBody, P>(
    cx: &mut Context<'_>,
    redirect: RedirectAction<'_, S, ReqBody, ResBody, P>,
) -> Poll<Result<Response<ResBody>, S::Error>>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone,
    S::Error: From<BoxError>,
    P: Policy<ReqBody, S::Error>,
    ReqBody: Body + Default,
{
    match redirect.action {
        Action::Follow => {
            redirect.parts.uri = redirect.location;
            redirect
                .body_repr
                .try_clone_from(&redirect.body, redirect.policy);

            let mut req = Request::from_parts(redirect.parts.clone(), redirect.body);
            redirect.policy.on_request(&mut req);
            redirect
                .future
                .set(Either::Right(Oneshot::new(redirect.service.clone(), req)));

            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Action::Stop => Poll::Ready(Ok(redirect.res)),
        Action::Pending(_) => Poll::Ready(Err(S::Error::from(
            Error::redirect(
                "Nested pending Action is not supported in redirect policy",
                redirect.parts.uri.clone(),
            )
            .into(),
        ))),
        Action::Error(err) => Poll::Ready(Err(err.into())),
    }
}
