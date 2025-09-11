//! Redirect Handling
//!
//! By default, a `Client` will automatically handle HTTP redirects, having a
//! maximum redirect chain of 10 hops. To customize this behavior, a
//! `redirect::Policy` can be used with a `ClientBuilder`.

use std::{error::Error as StdError, fmt, sync::Arc};

use bytes::Bytes;
use http::{Extensions, HeaderMap, HeaderValue, StatusCode, Uri, uri::Authority};

use crate::{
    client::{
        Body,
        layer::{config::RequestRedirectPolicy, redirect::policy},
    },
    core::ext::RequestConfig,
    error::{BoxError, Error},
    ext::{Extension, UriExt},
    header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, REFERER, WWW_AUTHENTICATE},
};

/// A type that controls the policy on how to handle the following of redirects.
///
/// The default value will catch redirect loops, and has a maximum of 10
/// redirects it will follow in a chain before returning an error.
///
/// - `limited` can be used have the same as the default behavior, but adjust the allowed maximum
///   redirect hops in a chain.
/// - `none` can be used to disable all redirect behavior.
/// - `custom` can be used to create a customized policy.
#[derive(Debug, Clone)]
pub struct Policy {
    inner: PolicyKind,
}

/// A type that holds information on the next request and previous requests
/// in redirect chain.
#[derive(Debug)]
pub struct Attempt<'a> {
    status: StatusCode,
    headers: &'a HeaderMap,
    next: &'a Uri,
    previous: &'a [Uri],
}

/// An action to perform when a redirect status code is found.
#[derive(Debug)]
pub struct Action {
    inner: ActionKind,
}

/// An entry in the redirect history.
#[derive(Clone, Debug)]
pub struct History {
    status: StatusCode,
    uri: Uri,
    previous: Uri,
    headers: HeaderMap,
}

// ===== impl Policy =====

impl Policy {
    /// Create a `Policy` with a maximum number of redirects.
    ///
    /// An `Error` will be returned if the max is reached.
    pub fn limited(max: usize) -> Self {
        Self {
            inner: PolicyKind::Limit(max),
        }
    }

    /// Create a `Policy` that does not follow any redirect.
    pub fn none() -> Self {
        Self {
            inner: PolicyKind::None,
        }
    }

    /// Create a custom `Policy` using the passed function.
    ///
    /// # Note
    ///
    /// The default `Policy` handles a maximum loop
    /// chain, but the custom variant does not do that for you automatically.
    /// The custom policy should have some way of handling those.
    ///
    /// Information on the next request and previous requests can be found
    /// on the [`Attempt`] argument passed to the closure.
    ///
    /// Actions can be conveniently created from methods on the
    /// [`Attempt`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wreq::{Error, redirect};
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let custom = redirect::Policy::custom(|attempt| {
    ///     if attempt.previous().len() > 5 {
    ///         attempt.error("too many redirects")
    ///     } else if attempt.uri().host_str() == Some("example.domain") {
    ///         // prevent redirects to 'example.domain'
    ///         attempt.stop()
    ///     } else {
    ///         attempt.follow()
    ///     }
    /// });
    /// let client = wreq::Client::builder().redirect(custom).build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Attempt`]: struct.Attempt.html
    pub fn custom<T>(policy: T) -> Self
    where
        T: Fn(Attempt) -> Action + Send + Sync + 'static,
    {
        Self {
            inner: PolicyKind::Custom(Arc::new(policy)),
        }
    }

    /// Apply this policy to a given [`Attempt`] to produce a [`Action`].
    ///
    /// # Note
    ///
    /// This method can be used together with `Policy::custom()`
    /// to construct one `Policy` that wraps another.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wreq::{Error, redirect};
    /// #
    /// # fn run() -> Result<(), Error> {
    /// let custom = redirect::Policy::custom(|attempt| {
    ///     eprintln!("{}, Location: {:?}", attempt.status(), attempt.uri());
    ///     redirect::Policy::default().redirect(attempt)
    /// });
    /// # Ok(())
    /// # }
    /// ```
    pub fn redirect(&self, attempt: Attempt) -> Action {
        match self.inner {
            PolicyKind::Custom(ref custom) => custom(attempt),
            PolicyKind::Limit(max) => {
                // The first URI in the previous is the initial URI and not a redirection. It needs
                // to be excluded.
                if attempt.previous.len() > max {
                    attempt.error(TooManyRedirects)
                } else {
                    attempt.follow()
                }
            }
            PolicyKind::None => attempt.stop(),
        }
    }

    fn check(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        next: &Uri,
        previous: &[Uri],
    ) -> ActionKind {
        self.redirect(Attempt {
            status,
            headers,
            next,
            previous,
        })
        .inner
    }
}

impl Default for Policy {
    fn default() -> Policy {
        // Keep `is_default` in sync
        Policy::limited(10)
    }
}

// ===== impl Attempt =====

impl<'a> Attempt<'a> {
    /// Get the type of redirect.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the headers of redirect.
    pub fn headers(&self) -> &HeaderMap {
        self.headers
    }

    /// Get the next URI to redirect to.
    pub fn uri(&self) -> &Uri {
        self.next
    }

    /// Get the list of previous URIs that have already been requested in this chain.
    pub fn previous(&self) -> &[Uri] {
        self.previous
    }

    /// Returns an action meaning wreq should follow the next URI.
    pub fn follow(self) -> Action {
        Action {
            inner: ActionKind::Follow,
        }
    }

    /// Returns an action meaning wreq should not follow the next URI.
    ///
    /// The 30x response will be returned as the `Ok` result.
    pub fn stop(self) -> Action {
        Action {
            inner: ActionKind::Stop,
        }
    }

    /// Returns an action failing the redirect with an error.
    ///
    /// The `Error` will be returned for the result of the sent request.
    pub fn error<E: Into<BoxError>>(self, error: E) -> Action {
        Action {
            inner: ActionKind::Error(error.into()),
        }
    }
}

// ===== impl History =====

impl History {
    /// Get the status code of the redirect response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the URI of the redirect response.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Get the previous URI before the redirect response.
    pub fn previous(&self) -> &Uri {
        &self.previous
    }

    /// Get the headers of the redirect response.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

impl From<&policy::Attempt<'_>> for History {
    fn from(attempt: &policy::Attempt<'_>) -> Self {
        Self {
            status: attempt.status(),
            uri: attempt.location().clone(),
            previous: attempt.previous().clone(),
            headers: attempt.headers().clone(),
        }
    }
}

#[derive(Clone)]
enum PolicyKind {
    Custom(Arc<dyn Fn(Attempt) -> Action + Send + Sync + 'static>),
    Limit(usize),
    None,
}

// ===== impl PolicyKind =====

impl fmt::Debug for PolicyKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PolicyKind::Custom(..) => f.pad("Custom"),
            PolicyKind::Limit(max) => f.debug_tuple("Limit").field(&max).finish(),
            PolicyKind::None => f.pad("None"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum ActionKind {
    Follow,
    Stop,
    Error(BoxError),
}

#[derive(Debug)]
struct TooManyRedirects;

// ===== impl TooManyRedirects =====

impl fmt::Display for TooManyRedirects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("too many redirects")
    }
}

impl StdError for TooManyRedirects {}

/// A redirect policy handler for HTTP clients.
///
/// `FollowRedirectPolicy` manages how HTTP redirects are handled by the client,
/// including the maximum number of redirects, whether to set the `Referer` header,
/// HTTPS-only enforcement, and redirect history tracking.
///
/// This type is used internally by the client to implement redirect logic according to
/// the configured [`Policy`]. It ensures that only allowed redirects are followed,
/// sensitive headers are removed when crossing hosts, and the `Referer` header is set
/// when appropriate.
#[derive(Clone)]
pub(crate) struct FollowRedirectPolicy {
    policy: RequestConfig<RequestRedirectPolicy>,
    referer: bool,
    uris: Vec<Uri>,
    https_only: bool,
    history: bool,
    history_entries: Option<Vec<History>>,
}

// ===== impl FollowRedirectPolicy =====

impl FollowRedirectPolicy {
    /// Creates a new redirect policy handler with the given [`Policy`].
    pub(crate) const fn new(policy: Policy) -> Self {
        Self {
            policy: RequestConfig::new(Some(policy)),
            referer: false,
            uris: Vec::new(),
            https_only: false,
            history: false,
            history_entries: None,
        }
    }

    /// Enables or disables automatic Referer header management.
    pub(crate) const fn with_referer(mut self, referer: bool) -> Self {
        self.referer = referer;
        self
    }

    /// Enables or disables HTTPS-only redirect enforcement.
    pub(crate) const fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    /// Enables or disables redirect history tracking.
    pub(crate) const fn with_history(mut self, history: bool) -> Self {
        self.history = history;
        self
    }
}

impl policy::Policy<Body, BoxError> for FollowRedirectPolicy {
    fn redirect(&mut self, attempt: &policy::Attempt<'_>) -> Result<policy::Action, BoxError> {
        // Parse the next URI from the attempt.
        let previous_uri = attempt.previous();
        let next_uri = attempt.location();

        // Push the previous URI to the list of URLs.
        self.uris.push(previous_uri.clone());

        // Get policy from config
        let policy = self
            .policy
            .as_ref()
            .expect("FollowRedirectPolicy should always have a policy set");

        // Check if the next URI is already in the list of URLs.
        match policy.check(attempt.status(), attempt.headers(), next_uri, &self.uris) {
            ActionKind::Follow => {
                // Validate the next URI's scheme.
                if !next_uri.is_http() && !next_uri.is_https() {
                    return Err(Error::uri_bad_scheme(next_uri.clone()).into());
                }

                // Validate HTTPS-only policy.
                if self.https_only && !next_uri.is_https() {
                    return Err(Error::redirect(
                        Error::uri_bad_scheme(next_uri.clone()),
                        next_uri.clone(),
                    )
                    .into());
                }

                // Record redirect history.
                if self.history {
                    self.history_entries
                        .get_or_insert_with(Vec::new)
                        .push(History::from(attempt));
                }

                Ok(policy::Action::Follow)
            }
            ActionKind::Stop => Ok(policy::Action::Stop),
            ActionKind::Error(err) => Err(Error::redirect(err, previous_uri.clone()).into()),
        }
    }

    fn on_request(&mut self, req: &mut http::Request<Body>) {
        let next_url = req.uri().clone();
        remove_sensitive_headers(req.headers_mut(), &next_url, &self.uris);
        if self.referer {
            if let Some(previous_url) = self.uris.last() {
                if let Some(v) = make_referer(&next_url, previous_url) {
                    req.headers_mut().insert(REFERER, v);
                }
            }
        }
    }

    fn on_response<Body>(&mut self, response: &mut http::Response<Body>) {
        if self.history {
            if let Some(history_entries) = self.history_entries.take() {
                response.extensions_mut().insert(Extension(history_entries));
            }
        }
    }

    #[inline(always)]
    fn on_extensions(&mut self, extensions: &Extensions) {
        self.policy.load(extensions);
    }

    #[inline(always)]
    fn allowed(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| !matches!(policy.inner, PolicyKind::None))
    }

    #[inline(always)]
    fn clone_body(&self, body: &Body) -> Option<Body> {
        body.try_clone()
    }
}

fn make_referer(next: &Uri, previous: &Uri) -> Option<HeaderValue> {
    if next.is_http() && previous.is_https() {
        return None;
    }

    let referer = {
        let mut parts = previous.clone().into_parts();
        if let Some(authority) = &mut parts.authority {
            let host = authority.host();
            parts.authority = match authority.port() {
                Some(port) => {
                    Authority::from_maybe_shared(Bytes::from(format!("{host}:{port}"))).ok()
                }
                None => host.parse().ok(),
            };
        }
        Uri::from_parts(parts).ok()?
    };

    HeaderValue::from_maybe_shared(Bytes::from(referer.to_string())).ok()
}

fn remove_sensitive_headers(headers: &mut HeaderMap, next: &Uri, previous: &[Uri]) {
    if let Some(previous) = previous.last() {
        let cross_host = next.host() != previous.host()
            || next.port() != previous.port()
            || next.scheme() != previous.scheme();
        if cross_host {
            headers.remove(AUTHORIZATION);
            headers.remove(COOKIE);
            headers.remove("cookie2");
            headers.remove(PROXY_AUTHORIZATION);
            headers.remove(WWW_AUTHENTICATE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redirect_policy_limit() {
        let policy = Policy::default();
        let next = Uri::try_from("http://x.y/z").unwrap();
        let mut previous = (0..=9)
            .map(|i| Uri::try_from(&format!("http://a.b/c/{i}")).unwrap())
            .collect::<Vec<_>>();

        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &previous) {
            ActionKind::Follow => (),
            other => panic!("unexpected {other:?}"),
        }

        previous.push(Uri::try_from("http://a.b.d/e/33").unwrap());

        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &previous) {
            ActionKind::Error(err) if err.is::<TooManyRedirects>() => (),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_redirect_policy_limit_to_0() {
        let policy = Policy::limited(0);
        let next = Uri::try_from("http://x.y/z").unwrap();
        let previous = vec![Uri::try_from("http://a.b/c").unwrap()];

        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &previous) {
            ActionKind::Error(err) if err.is::<TooManyRedirects>() => (),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_redirect_policy_custom() {
        let policy = Policy::custom(|attempt| {
            if attempt.uri().host() == Some("foo") {
                attempt.stop()
            } else {
                attempt.follow()
            }
        });

        let next = Uri::try_from("http://bar/baz").unwrap();
        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &[]) {
            ActionKind::Follow => (),
            other => panic!("unexpected {other:?}"),
        }

        let next = Uri::try_from("http://foo/baz").unwrap();
        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &[]) {
            ActionKind::Stop => (),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_remove_sensitive_headers() {
        use http::header::{ACCEPT, AUTHORIZATION, COOKIE, HeaderValue};

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("*/*"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("let me in"));
        headers.insert(COOKIE, HeaderValue::from_static("foo=bar"));

        let next = Uri::try_from("http://initial-domain.com/path").unwrap();
        let mut prev = vec![Uri::try_from("http://initial-domain.com/new_path").unwrap()];
        let mut filtered_headers = headers.clone();

        remove_sensitive_headers(&mut headers, &next, &prev);
        assert_eq!(headers, filtered_headers);

        prev.push(Uri::try_from("http://new-domain.com/path").unwrap());
        filtered_headers.remove(AUTHORIZATION);
        filtered_headers.remove(COOKIE);

        remove_sensitive_headers(&mut headers, &next, &prev);
        assert_eq!(headers, filtered_headers);
    }
}
