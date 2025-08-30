//! Tools for customizing the behavior of a [`FollowRedirect`][super::FollowRedirect] middleware.

use http::{Extensions, HeaderMap, Request, StatusCode, Uri};

/// Trait for the policy on handling redirection responses.
pub trait Policy<B, E> {
    /// Invoked when the service received a response with a redirection status code (`3xx`).
    ///
    /// This method returns an [`Action`] which indicates whether the service should follow
    /// the redirection.
    fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E>;

    /// Invoked right before the service makes a request, regardless of whether it is redirected
    /// or not.
    ///
    /// This can for example be used to remove sensitive headers from the request
    /// or prepare the request in other ways.
    ///
    /// The default implementation does nothing.
    fn on_request(&mut self, _request: &mut Request<B>) {}

    /// Invoked right after the service received a response, regardless of whether it is redirected
    /// or not.
    ///
    /// This can for example be used to inspect the response before any redirection is handled.
    ///
    /// The default implementation does nothing.
    fn on_response<Body>(&mut self, _response: &mut http::Response<Body>) {}

    /// Loads redirect policy configuration from the request's [`Extensions`].
    ///
    /// This method is called once at the beginning of request processing to extract
    /// request-specific redirect settings that may override the policy's default behavior.
    /// Examples include per-request maximum redirect limits, allowed/blocked domains,
    /// or security policies.
    ///
    /// The default implementation does nothing, meaning the policy uses its default
    /// configuration for all requests.
    ///
    /// The default implementation does nothing.
    fn on_extensions(&mut self, _extensions: &Extensions) {}

    /// Returns whether redirection is currently permitted by this policy.
    ///
    /// This check typically occurs after [`load()`] has initialized the internal state
    /// and determines whether any redirect should proceed at all.
    ///
    /// If redirection is not allowed, the client will return the original `3xx` response as-is.
    fn allowed(&self) -> bool;

    /// Try to clone a request body before the service makes a redirected request.
    ///
    /// If the request body cannot be cloned, return `None`.
    ///
    /// This is not invoked when [`B::size_hint`][http_body::Body::size_hint] returns zero,
    /// in which case `B::default()` will be used to create a new request body.
    ///
    /// The default implementation returns `None`.
    fn clone_body(&self, _body: &B) -> Option<B> {
        None
    }
}

/// A type that holds information on a redirection attempt.
pub struct Attempt<'a> {
    pub(super) status: StatusCode,
    pub(super) headers: &'a HeaderMap,
    pub(super) location: &'a Uri,
    pub(super) previous: &'a Uri,
}

impl<'a> Attempt<'a> {
    /// Returns the redirection response.
    #[inline(always)]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the headers of the redirection response.
    #[inline(always)]
    pub fn headers(&self) -> &'a HeaderMap {
        self.headers
    }

    /// Returns the destination URI of the redirection.
    #[inline(always)]
    pub fn location(&self) -> &'a Uri {
        self.location
    }

    /// Returns the URI of the original request.
    #[inline(always)]
    pub fn previous(&self) -> &'a Uri {
        self.previous
    }
}

/// A value returned by [`Policy::redirect`] which indicates the action
/// [`FollowRedirect`][super::FollowRedirect] should take for a redirection response.
#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// Follow the redirection.
    Follow,
    /// Do not follow the redirection, and return the redirection response as-is.
    Stop,
}
