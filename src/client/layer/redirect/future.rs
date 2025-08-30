use std::{
    future::Future,
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
use tower::{Service, util::Oneshot};

use super::{
    BodyRepr,
    policy::{Action, Attempt, Policy},
};
use crate::ext::RequestUri;

pin_project! {
    /// Response future for [`FollowRedirectLayer`].
    #[project = ResponseFutureProj]
    pub enum ResponseFuture<S, B, P>
    where
        S: Service<Request<B>>,
    {
        Redirect {
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
    ReqBody: Body + Default,
    P: Policy<ReqBody, S::Error>,
{
    type Output = Result<Response<ResBody>, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            ResponseFutureProj::Redirect {
                mut future,
                service,
                policy,
                method,
                uri,
                version,
                headers,
                extensions,
                body,
            } => {
                let mut res = ready!(future.as_mut().poll(cx)?);
                res.extensions_mut().insert(RequestUri(uri.clone()));

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
                        if *method == Method::POST {
                            *method = Method::GET;
                            *body = BodyRepr::Empty;
                            drop_payload_headers(headers);
                        }
                    }
                    StatusCode::SEE_OTHER => {
                        // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                        if *method != Method::HEAD {
                            *method = Method::GET;
                        }
                        *body = BodyRepr::Empty;
                        drop_payload_headers(headers);
                    }
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
                    _ => {
                        // Not a redirect status code, return the response as is.
                        policy.on_response(&mut res);
                        return Poll::Ready(Ok(res));
                    }
                };

                let take_body = if let Some(body) = body.take() {
                    body
                } else {
                    return Poll::Ready(Ok(res));
                };

                let location = res
                    .headers()
                    .get(&LOCATION)
                    .and_then(|loc| resolve_uri(str::from_utf8(loc.as_bytes()).ok()?, uri));
                let location = if let Some(loc) = location {
                    loc
                } else {
                    return Poll::Ready(Ok(res));
                };

                let attempt = Attempt {
                    status: res.status(),
                    headers: res.headers(),
                    location: &location,
                    previous: uri,
                };

                match policy.redirect(&attempt)? {
                    Action::Follow => {
                        *uri = location;
                        body.try_clone_from(&take_body, policy);

                        let mut req = Request::new(take_body);
                        *req.uri_mut() = uri.clone();
                        *req.method_mut() = method.clone();
                        *req.version_mut() = *version;
                        *req.headers_mut() = headers.clone();
                        *req.extensions_mut() = extensions.clone();
                        policy.on_request(&mut req);
                        future.set(Either::Right(Oneshot::new(service.clone(), req)));

                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Action::Stop => Poll::Ready(Ok(res)),
                }
            }
            ResponseFutureProj::Direct { mut future } => {
                let res = ready!(future.as_mut().poll(cx)?);
                Poll::Ready(Ok(res))
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
