//! Tools for customizing the behavior of a [`FollowRedirect`][super::FollowRedirect] middleware.

use std::{fmt, pin::Pin};

use http::{HeaderMap, Request, Response, StatusCode, Uri};

use crate::error::BoxError;

/// Trait for the policy on handling redirection responses.
pub trait Policy<B, E> {
    /// Invoked when the service received a response with a redirection status code (`3xx`).
    ///
    /// This method returns an [`Action`] which indicates whether the service should follow
    /// the redirection.
    fn redirect(&mut self, attempt: Attempt<'_>) -> Result<Action, E>;

    /// Returns whether redirection is currently permitted by this policy.
    ///
    /// This method is called to determine whether the client should follow redirects at all.
    /// It allows policies to enable or disable redirection behavior based on the [`Request`].
    fn follow_redirects(&mut self, _request: &mut Request<B>) -> bool;

    /// Invoked right before the service makes a [`Request`].
    fn on_request(&mut self, _request: &mut Request<B>);

    /// Invoked right after the service received a [`Response`].
    fn on_response<Body>(&mut self, _response: &mut Response<Body>);

    /// Try to clone a request body before the service makes a redirected request.
    fn clone_body(&self, _body: &B) -> Option<B>;
}

/// A type that holds information on a redirection attempt.
pub struct Attempt<'a> {
    pub(crate) status: StatusCode,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) location: &'a Uri,
    pub(crate) previous: &'a Uri,
}

/// A value returned by [`Policy::redirect`] which indicates the action
/// [`FollowRedirect`][super::FollowRedirect] should take for a redirection response.
pub enum Action {
    /// Follow the redirection.
    Follow,
    /// Do not follow the redirection, and return the redirection response as-is.
    Stop,
    /// Pending async decision. The async task will be awaited to determine the final action.
    Pending(Pin<Box<dyn Future<Output = Action> + Send>>),
    /// An error occurred while determining the redirection action.
    Error(BoxError),
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Follow => f.debug_tuple("Follow").finish(),
            Action::Stop => f.debug_tuple("Stop").finish(),
            Action::Pending(_) => f.debug_tuple("Pending").finish(),
            Action::Error(_) => f.debug_tuple("Error").finish(),
        }
    }
}
