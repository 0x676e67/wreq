//! Tools for customizing the behavior of a [`FollowRedirect`][super::FollowRedirect] middleware.

use http::{Request, StatusCode, Uri};

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

impl<B, E, P> Policy<B, E> for &mut P
where
    P: Policy<B, E> + ?Sized,
{
    fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E> {
        (**self).redirect(attempt)
    }

    fn on_request(&mut self, request: &mut Request<B>) {
        (**self).on_request(request)
    }

    fn clone_body(&self, body: &B) -> Option<B> {
        (**self).clone_body(body)
    }
}

impl<B, E, P> Policy<B, E> for Box<P>
where
    P: Policy<B, E> + ?Sized,
{
    fn redirect(&mut self, attempt: &Attempt<'_>) -> Result<Action, E> {
        (**self).redirect(attempt)
    }

    fn on_request(&mut self, request: &mut Request<B>) {
        (**self).on_request(request)
    }

    fn clone_body(&self, body: &B) -> Option<B> {
        (**self).clone_body(body)
    }
}

/// A type that holds information on a redirection attempt.
pub struct Attempt<'a> {
    pub(crate) status: StatusCode,
    pub(crate) location: &'a Uri,
    pub(crate) previous: &'a Uri,
}

impl<'a> Attempt<'a> {
    /// Returns the redirection response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the destination URI of the redirection.
    pub fn location(&self) -> &'a Uri {
        self.location
    }

    /// Returns the URI of the original request.
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

impl<B, E> Policy<B, E> for Action {
    fn redirect(&mut self, _: &Attempt<'_>) -> Result<Action, E> {
        Ok(*self)
    }
}

impl<B, E> Policy<B, E> for Result<Action, E>
where
    E: Clone,
{
    fn redirect(&mut self, _: &Attempt<'_>) -> Result<Action, E> {
        self.clone()
    }
}
