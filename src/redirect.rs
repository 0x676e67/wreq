//! Redirect Handling
//!
//! By default, a `Client` does not follow HTTP redirects. To enable automatic
//! redirect handling with a maximum redirect chain of 10 hops, use a [`Policy`]
//! with [`ClientBuilder::redirect()`](crate::ClientBuilder::redirect).

use std::{borrow::Cow, error::Error as StdError, fmt, sync::Arc};

use bytes::Bytes;
use futures_util::FutureExt;
use http::{Extensions, HeaderMap, HeaderValue, StatusCode, Uri};

use crate::{
    client::{
        Body,
        ext::RequestConfig,
        layer::{config::RequestRedirectPolicy, redirect},
    },
    error::{BoxError, Error},
    ext::UriExt,
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
#[non_exhaustive]
pub struct Attempt<'a, const PENDING: bool = true> {
    status: StatusCode,
    headers: Cow<'a, HeaderMap>,
    next: Cow<'a, Uri>,
    previous: Cow<'a, [Uri]>,
}

/// An action to perform when a redirect status code is found.
#[derive(Debug)]
pub struct Action {
    inner: redirect::Action,
}

/// Redirect history information for a response.
#[derive(Debug, Clone)]
pub struct History(Vec<HistoryEntry>);

/// An entry in the redirect history.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HistoryEntry {
    /// The status code of the redirect response.
    pub status: StatusCode,
    /// The URI of the redirect response.
    pub uri: Uri,
    /// The previous URI before the redirect response.
    pub previous: Uri,
    /// The headers of the redirect response.
    pub headers: HeaderMap,
}

#[derive(Clone)]
enum PolicyKind {
    Custom(Arc<dyn Fn(Attempt) -> Action + Send + Sync + 'static>),
    Limit(usize),
    None,
}

#[derive(Debug)]
struct TooManyRedirects;

/// A redirect policy handler for HTTP clients.
///
/// [`FollowRedirectPolicy`] manages how HTTP redirects are handled by the client,
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
    history: Option<Vec<HistoryEntry>>,
}

// ===== impl Policy =====

impl Policy {
    /// Create a [`Policy`] with a maximum number of redirects.
    ///
    /// An [`Error`] will be returned if the max is reached.
    #[inline]
    pub fn limited(max: usize) -> Self {
        Self {
            inner: PolicyKind::Limit(max),
        }
    }

    /// Create a [`Policy`] that does not follow any redirect.
    #[inline]
    pub fn none() -> Self {
        Self {
            inner: PolicyKind::None,
        }
    }

    /// Create a custom [`Policy`] using the passed function.
    ///
    /// # Note
    ///
    /// The default [`Policy`] handles a maximum loop
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
    ///     if attempt.previous.len() > 5 {
    ///         attempt.error("too many redirects")
    ///     } else if attempt.uri() == "example.domain" {
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
    #[inline]
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
    /// This method can be used together with [`Policy::custom()`]
    /// to construct one [`Policy`] that wraps another.
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

    #[inline]
    fn check(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        next: &Uri,
        previous: &[Uri],
    ) -> redirect::Action {
        self.redirect(Attempt {
            status,
            headers: Cow::Borrowed(headers),
            next: Cow::Borrowed(next),
            previous: Cow::Borrowed(previous),
        })
        .inner
    }
}

impl Default for Policy {
    #[inline]
    fn default() -> Policy {
        // Keep `is_default` in sync
        Policy::limited(10)
    }
}

// ===== impl Attempt =====

impl<'a, const PENDING: bool> Attempt<'a, PENDING> {
    /// Get the type of redirect.
    #[inline]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the headers of redirect.
    #[inline]
    pub fn headers(&self) -> &HeaderMap {
        self.headers.as_ref()
    }

    /// Get the next URI to redirect to.
    #[inline]
    pub fn uri(&self) -> &Uri {
        self.next.as_ref()
    }

    /// Get the list of previous URIs that have already been requested in this chain.
    #[inline]
    pub fn previous(&self) -> &[Uri] {
        self.previous.as_ref()
    }

    /// Returns an action meaning wreq should follow the next URI.
    #[inline]
    pub fn follow(self) -> Action {
        Action {
            inner: redirect::Action::Follow,
        }
    }

    /// Returns an action meaning wreq should not follow the next URI.
    ///
    /// The 30x response will be returned as the `Ok` result.
    #[inline]
    pub fn stop(self) -> Action {
        Action {
            inner: redirect::Action::Stop,
        }
    }

    /// Returns an [`Action`] failing the redirect with an error.
    ///
    /// The [`Error`] will be returned for the result of the sent request.
    #[inline]
    pub fn error<E: Into<BoxError>>(self, error: E) -> Action {
        Action {
            inner: redirect::Action::Error(error.into()),
        }
    }
}

impl<'a> Attempt<'a, true> {
    /// Returns an action meaning wreq should perform the redirect asynchronously.
    ///
    /// The provided async closure receives an owned [`Attempt<'static>`] and should
    /// return an [`Action`] to determine the final redirect behavior.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use wreq::redirect;
    /// #
    /// let policy = redirect::Policy::custom(|attempt| {
    ///     attempt.pending(|attempt| async move {
    ///         // Perform some async operation
    ///         if attempt.uri().host() == Some("trusted.domain") {
    ///             attempt.follow()
    ///         } else {
    ///             attempt.stop()
    ///         }
    ///     })
    /// });
    /// ```
    pub fn pending<F, Fut>(self, task: F) -> Action
    where
        F: FnOnce(Attempt<'static, false>) -> Fut + Send + 'static,
        Fut: Future<Output = Action> + Send + 'static,
    {
        let attempt = Attempt {
            status: self.status,
            headers: Cow::Owned(self.headers.into_owned()),
            next: Cow::Owned(self.next.into_owned()),
            previous: Cow::Owned(self.previous.into_owned()),
        };
        let pending = Box::pin(task(attempt).map(|action| action.inner));
        Action {
            inner: redirect::Action::Pending(pending),
        }
    }
}

// ===== impl History =====

impl IntoIterator for History {
    type Item = HistoryEntry;
    type IntoIter = std::vec::IntoIter<HistoryEntry>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a History {
    type Item = &'a HistoryEntry;
    type IntoIter = std::slice::Iter<'a, HistoryEntry>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
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

// ===== impl TooManyRedirects =====

impl fmt::Display for TooManyRedirects {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("too many redirects")
    }
}

impl StdError for TooManyRedirects {}

// ===== impl FollowRedirectPolicy =====

impl FollowRedirectPolicy {
    /// Creates a new redirect policy handler with the given [`Policy`].
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: RequestConfig::new(Some(policy)),
            referer: false,
            uris: Vec::new(),
            https_only: false,
            history: None,
        }
    }

    /// Enables or disables automatic Referer header management.
    #[inline]
    pub fn with_referer(mut self, referer: bool) -> Self {
        self.referer = referer;
        self
    }

    /// Enables or disables HTTPS-only redirect enforcement.
    #[inline]
    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }
}

impl redirect::Policy<Body, BoxError> for FollowRedirectPolicy {
    fn redirect(&mut self, attempt: redirect::Attempt<'_>) -> Result<redirect::Action, BoxError> {
        // Parse the next URI from the attempt.
        let previous_uri = attempt.previous;
        let next_uri = attempt.location;

        // Push the previous URI to the list of URLs.
        self.uris.push(previous_uri.clone());

        // Get policy from config
        let policy = self
            .policy
            .as_ref()
            .expect("[BUG] FollowRedirectPolicy should always have a policy set");

        // Check if the next URI is already in the list of URLs.
        match policy.check(attempt.status, attempt.headers, next_uri, &self.uris) {
            redirect::Action::Follow => {
                // Validate the redirect URI scheme
                if !(next_uri.is_http() || next_uri.is_https()) {
                    return Err(Error::uri_bad_scheme(next_uri.clone()).into());
                }

                // Check HTTPS-only policy
                if self.https_only && !next_uri.is_https() {
                    return Err(Error::redirect(
                        Error::uri_bad_scheme(next_uri.clone()),
                        next_uri.clone(),
                    )
                    .into());
                }

                // Record redirect history
                if !matches!(policy.inner, PolicyKind::None) {
                    self.history.get_or_insert_default().push(HistoryEntry {
                        status: attempt.status,
                        uri: attempt.location.clone(),
                        previous: attempt.previous.clone(),
                        headers: attempt.headers.clone(),
                    });
                }

                Ok(redirect::Action::Follow)
            }
            redirect::Action::Stop => Ok(redirect::Action::Stop),
            redirect::Action::Pending(task) => Ok(redirect::Action::Pending(task)),
            redirect::Action::Error(err) => Err(Error::redirect(err, previous_uri.clone()).into()),
        }
    }

    fn on_request(&mut self, req: &mut http::Request<Body>) {
        let next_url = req.uri().clone();
        remove_sensitive_headers(req.headers_mut(), &next_url, &self.uris);
        if self.referer {
            if let Some(previous_url) = self.uris.last() {
                if let Some(v) = make_referer(next_url, previous_url) {
                    req.headers_mut().insert(REFERER, v);
                }
            }
        }
    }

    fn on_response<Body>(&mut self, response: &mut http::Response<Body>) {
        if let Some(history) = self.history.take() {
            response.extensions_mut().insert(History(history));
        }
    }

    fn follow_redirects(&mut self, extensions: &Extensions) -> bool {
        self.policy.load(extensions);
        self.policy
            .as_ref()
            .is_some_and(|policy| !matches!(policy.inner, PolicyKind::None))
    }

    #[inline]
    fn clone_body(&self, body: &Body) -> Option<Body> {
        body.try_clone()
    }
}

fn make_referer(next: Uri, previous: &Uri) -> Option<HeaderValue> {
    if next.is_http() && previous.is_https() {
        return None;
    }

    let mut referer = previous.clone();
    referer.set_userinfo("", None);
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
            redirect::Action::Follow => (),
            other => panic!("unexpected {other:?}"),
        }

        previous.push(Uri::try_from("http://a.b.d/e/33").unwrap());

        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &previous) {
            redirect::Action::Error(err) if err.is::<TooManyRedirects>() => (),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn test_redirect_policy_limit_to_0() {
        let policy = Policy::limited(0);
        let next = Uri::try_from("http://x.y/z").unwrap();
        let previous = vec![Uri::try_from("http://a.b/c").unwrap()];

        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &previous) {
            redirect::Action::Error(err) if err.is::<TooManyRedirects>() => (),
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
            redirect::Action::Follow => (),
            other => panic!("unexpected {other:?}"),
        }

        let next = Uri::try_from("http://foo/baz").unwrap();
        match policy.check(StatusCode::FOUND, &HeaderMap::new(), &next, &[]) {
            redirect::Action::Stop => (),
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
