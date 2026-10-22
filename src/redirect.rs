//! Redirect Handling
//!
//! By default, a `Client` does not follow HTTP redirects. To enable automatic
//! redirect handling with a maximum redirect chain of 10 hops, use a [`Policy`]
//! with [`ClientBuilder::redirect()`](crate::ClientBuilder::redirect).

use std::{borrow::Cow, error::Error as StdError, fmt, sync::Arc};

use futures_util::FutureExt;
use http::{HeaderMap, HeaderName, StatusCode, Uri};

use self::referrer::Referrer;
use crate::{
    client::layer::redirect,
    config::RequestConfig,
    error::{BoxError, Error},
    ext::UriExt,
    header::{AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, REFERER, WWW_AUTHENTICATE},
};

type RequestCallback = dyn Fn(&mut http::Request<()>) + Send + Sync;
type ResponseCallback = dyn Fn(&http::Request<()>, &http::Response<()>) + Send + Sync;

/// A type that controls the policy on how to handle the following of redirects.
///
/// The default value will catch redirect loops, and has a maximum of 10
/// redirects it will follow in a chain before returning an error.
///
/// - `limited` can be used have the same as the default behavior, but adjust the allowed maximum
///   redirect hops in a chain.
/// - `none` can be used to disable following redirects.
/// - `custom` can be used to create a customized policy.
///
/// Request and response callbacks run synchronously and are shared by cloned policies.
/// Request policies inherit client callbacks they do not replace.
#[derive(Clone)]
pub struct Policy {
    inner: PolicyKind,
    on_request: Option<Arc<RequestCallback>>,
    on_response: Option<Arc<ResponseCallback>>,
}

/// A type that holds information on the next request and previous requests
/// in redirect chain.
#[derive(Debug)]
#[non_exhaustive]
pub struct Attempt<'a, const PENDING: bool = true> {
    /// The status code of the redirect response.
    pub status: StatusCode,

    /// The headers of the redirect response.
    pub headers: Cow<'a, HeaderMap>,

    /// The URI to redirect to.
    pub uri: Cow<'a, Uri>,

    /// The list of previous URIs that have already been requested in this chain.
    pub previous: Cow<'a, [Uri]>,
}

/// An action to perform when a redirect status code is found.
#[derive(Debug)]
pub struct Action(redirect::Action);

/// Redirect history information for a response.
#[derive(Debug, Clone)]
pub struct History(Vec<HistoryEntry>);

/// An entry in the redirect history.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HistoryEntry {
    /// The status code of the redirect response.
    pub status: StatusCode,

    /// The destination URI, including changes made by the request callback.
    pub uri: Uri,

    /// The URI that produced the redirect response.
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
/// including the maximum number of redirects, `Referer` policy handling,
/// HTTPS-only enforcement, and redirect history tracking.
///
/// This type is used internally by the client to implement redirect logic according to
/// the configured [`Policy`]. It ensures that only allowed redirects are followed,
/// sensitive headers are removed when crossing origins, and response referrer policies
/// are applied.
#[derive(Clone)]
pub(crate) struct FollowRedirectPolicy {
    policy: RequestConfig<Policy>,
    referrer: Option<Referrer>,
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
            on_request: None,
            on_response: None,
        }
    }

    /// Create a [`Policy`] that does not follow any redirect.
    #[inline]
    pub fn none() -> Self {
        Self {
            inner: PolicyKind::None,
            on_request: None,
            on_response: None,
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
            on_request: None,
            on_response: None,
        }
    }

    /// Sets a callback for the initial request and each followed redirect.
    ///
    /// Runs after redirect method changes and built-in credential and referrer handling.
    /// Changes to headers and extensions carry over to later hops. Cookie injection and
    /// protocol header preparation happen afterward, so these are not the final wire headers.
    /// This also runs when redirects are disabled with [`Policy::none`].
    /// The body is represented by `()`. If the URI changes, target validation and
    /// cross-origin security handling run again before dispatch.
    /// Changing the method does not change the body.
    /// Same-origin edits to the initial URI leave an explicit `Referer` unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// use wreq::{header::HeaderValue, redirect::Policy};
    ///
    /// let policy = Policy::default()
    ///     .on_request(|request| {
    ///         request.headers_mut().insert("x-client", HeaderValue::from_static("wreq"));
    ///     })
    ///     .on_response(|request, response| {
    ///         eprintln!("{} {}", request.uri(), response.status());
    ///     });
    /// ```
    pub fn on_request<F>(mut self, callback: F) -> Self
    where
        F: Fn(&mut http::Request<()>) + Send + Sync + 'static,
    {
        self.on_request = Some(Arc::new(callback));
        self
    }

    /// Sets a callback for every hop's response, including responses that are not followed.
    ///
    /// Runs before preparing the next request, borrowing its source request and response.
    /// Both bodies are represented by `()`; response headers and extensions are not copied.
    /// The request reflects the [`on_request`](Self::on_request) stage, not final wire headers.
    pub fn on_response<F>(mut self, callback: F) -> Self
    where
        F: Fn(&http::Request<()>, &http::Response<()>) + Send + Sync + 'static,
    {
        self.on_response = Some(Arc::new(callback));
        self
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
            uri: Cow::Borrowed(next),
            previous: Cow::Borrowed(previous),
        })
        .0
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("inner", &self.inner)
            .field("on_request", &self.on_request.is_some())
            .field("on_response", &self.on_response.is_some())
            .finish()
    }
}

impl Default for Policy {
    #[inline]
    fn default() -> Policy {
        // Keep `is_default` in sync
        Policy::limited(10)
    }
}

impl_request_config_value!(Policy);

// ===== impl Attempt =====

impl<const PENDING: bool> Attempt<'_, PENDING> {
    /// Returns an action meaning wreq should follow the next URI.
    #[inline]
    pub fn follow(self) -> Action {
        Action(redirect::Action::Follow)
    }

    /// Returns an action meaning wreq should not follow the next URI.
    ///
    /// The 30x response will be returned as the `Ok` result.
    #[inline]
    pub fn stop(self) -> Action {
        Action(redirect::Action::Stop)
    }

    /// Returns an [`Action`] failing the redirect with an error.
    ///
    /// The [`Error`] will be returned for the result of the sent request.
    #[inline]
    pub fn error<E: Into<BoxError>>(self, error: E) -> Action {
        Action(redirect::Action::Error(error.into()))
    }
}

impl Attempt<'_, true> {
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
    pub fn pending<F, Fut>(self, func: F) -> Action
    where
        F: FnOnce(Attempt<'static, false>) -> Fut + Send + 'static,
        Fut: Future<Output = Action> + Send + 'static,
    {
        let attempt = Attempt {
            status: self.status,
            headers: Cow::Owned(self.headers.into_owned()),
            uri: Cow::Owned(self.uri.into_owned()),
            previous: Cow::Owned(self.previous.into_owned()),
        };

        Action(redirect::Action::Pending(Box::pin(
            func(attempt).map(|action| action.0),
        )))
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
        FollowRedirectPolicy {
            policy: RequestConfig::new(Some(policy)),
            referrer: None,
            uris: Vec::new(),
            https_only: false,
            history: None,
        }
    }

    /// Enables or disables automatic Referer header management.
    #[inline]
    pub fn with_referer(mut self, referer: bool) -> Self {
        self.referrer = referer.then(Referrer::default);
        self
    }

    /// Enables or disables HTTPS-only redirect enforcement.
    #[inline]
    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }
}

impl FollowRedirectPolicy {
    pub(crate) fn redirect(
        &mut self,
        attempt: redirect::Attempt<'_>,
    ) -> Result<redirect::Action, BoxError> {
        // Parse the next URI from the attempt.
        let previous_uri = attempt.previous;
        let next_uri = attempt.location;
        self.uris.push(previous_uri.clone());
        if let Some(referrer) = &mut self.referrer {
            referrer.on_redirect(attempt.headers);
        }

        // Get policy from config
        let policy = self
            .policy
            .as_ref()
            .expect("[BUG] FollowRedirectPolicy should always have a policy set");
        let action = policy.check(attempt.status, attempt.headers, next_uri, &self.uris);

        // Handle errors from the policy immediately
        if let redirect::Action::Error(err) = action {
            return Err(Error::redirect(err, previous_uri.clone()).into());
        }

        Ok(action)
    }

    pub(crate) fn for_request<B>(&self, request: &mut http::Request<B>) -> Option<Self> {
        let mut policy = self.policy.take(request.extensions_mut())?;
        if let Some(client_policy) = self.policy.as_ref() {
            policy.on_request = policy
                .on_request
                .or_else(|| client_policy.on_request.clone());
            policy.on_response = policy
                .on_response
                .or_else(|| client_policy.on_response.clone());
        }
        if matches!(policy.inner, PolicyKind::None)
            && policy.on_request.is_none()
            && policy.on_response.is_none()
        {
            return None;
        }

        Some(Self {
            policy: RequestConfig::new(Some(policy)),
            referrer: self
                .referrer
                .as_ref()
                .map(|_| Referrer::new(request.headers())),
            uris: Vec::new(),
            https_only: self.https_only,
            history: None,
        })
    }

    /// Returns whether the policy may follow a redirect response.
    pub(crate) fn follows_redirects(&self) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|policy| !matches!(policy.inner, PolicyKind::None))
    }

    pub(crate) fn on_request(&mut self, req: &mut http::Request<()>) -> Result<(), BoxError> {
        let redirected = !self.uris.is_empty();
        let callback = self
            .policy
            .as_ref()
            .and_then(|policy| policy.on_request.as_ref());
        // Keep the source and header metadata if the callback chooses a different destination.
        let original_referrer = callback
            .filter(|_| redirected)
            .and(self.referrer.as_ref())
            .map(|referrer| (referrer.clone(), req.headers().get(REFERER).cloned()));

        remove_sensitive_headers(req, &self.uris);
        if redirected && let Some(referrer) = &mut self.referrer {
            referrer.apply(req);
        }

        if let Some(callback) = callback {
            let previous = req.uri().clone();
            let prepared_referrer = req.headers().get(REFERER).cloned();
            callback(req);
            let changed = req.uri() != &previous;
            if changed {
                remove_sensitive_headers(req, std::slice::from_ref(&previous));
            }
            if let Some(referrer) = &mut self.referrer {
                if changed
                    && req.headers().get(REFERER) == prepared_referrer.as_ref()
                    && let Some((original, header)) = original_referrer
                {
                    *referrer = original;
                    if !req.headers().contains_key(REFERER)
                        && let Some(header) = header
                    {
                        req.headers_mut().insert(REFERER, header);
                    }
                } else {
                    referrer.set_source(req.headers());
                }
                if changed && (redirected || !same_origin(req.uri(), &previous)) {
                    referrer.apply(req);
                }
            }
        }

        let uri = req.uri();
        if !(uri.is_http() || uri.is_https()) {
            return Err(Error::uri_bad_scheme(uri.clone()).into());
        }
        if self.https_only && !uri.is_https() {
            let error = Error::uri_bad_scheme(uri.clone());
            return Err(if redirected {
                Error::redirect(error, uri.clone())
            } else {
                error
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn on_response<B>(
        &self,
        request: &http::Request<()>,
        response: http::Response<B>,
    ) -> http::Response<B> {
        if let Some(callback) = self
            .policy
            .as_ref()
            .and_then(|policy| policy.on_response.as_ref())
        {
            let (parts, body) = response.into_parts();
            let response = http::Response::from_parts(parts, ());
            callback(request, &response);
            return response.map(|_| body);
        }
        response
    }

    pub(crate) fn record_redirect<B>(&mut self, response: &http::Response<B>, uri: &Uri) {
        if let Some(previous) = self.uris.last() {
            self.history.get_or_insert_default().push(HistoryEntry {
                status: response.status(),
                uri: uri.clone(),
                previous: previous.clone(),
                headers: response.headers().clone(),
            });
        }
    }

    pub(crate) fn finish<B>(&mut self, mut response: http::Response<B>) -> http::Response<B> {
        if let Some(history) = self.history.take() {
            response.extensions_mut().insert(History(history));
        }
        response
    }
}

fn remove_sensitive_headers<B>(req: &mut http::Request<B>, previous: &[Uri]) {
    if let Some(previous) = previous.last()
        && !same_origin(req.uri(), previous)
    {
        /// Avoid dynamic allocation of `HeaderName` by using `from_static`.
        /// https://github.com/hyperium/http/blob/e9de46c9269f0a476b34a02a401212e20f639df2/src/header/map.rs#L3794
        const COOKIE2: HeaderName = HeaderName::from_static("cookie2");
        let headers = req.headers_mut();
        headers.remove(AUTHORIZATION);
        headers.remove(COOKIE);
        headers.remove(COOKIE2);
        headers.remove(PROXY_AUTHORIZATION);
        headers.remove(WWW_AUTHENTICATE);
    }
}

fn same_origin(left: &Uri, right: &Uri) -> bool {
    let same_host = match (left.host(), right.host()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    };

    same_host
        && left.scheme() == right.scheme()
        && left.port_or_default() == right.port_or_default()
}

mod referrer {
    use http::{
        HeaderMap, HeaderValue, Uri,
        header::{REFERER, REFERRER_POLICY},
        uri::Scheme,
    };
    use url::Url;

    use crate::ext::UriExt;

    /// Referrer state carried across a redirect chain.
    #[derive(Clone, Default)]
    pub(super) struct Referrer {
        source: Option<Url>,
        policy: ReferrerPolicy,
    }

    impl Referrer {
        /// Captures the caller-provided referrer without changing the initial request.
        ///
        /// Redirect processing updates the policy before computing the next referrer:
        /// https://w3c.github.io/webappsec-referrer-policy/#integration-with-fetch
        pub(super) fn new(headers: &HeaderMap) -> Self {
            Self {
                source: headers.get(REFERER).and_then(parse_referrer),
                policy: ReferrerPolicy::default(),
            }
        }

        /// Carries callback edits into later hops without resetting the response policy.
        pub(super) fn set_source(&mut self, headers: &HeaderMap) {
            let value = headers.get(REFERER);
            if self.source.as_ref().map(Url::as_str) != value.and_then(|value| value.to_str().ok())
            {
                self.source = value.and_then(parse_referrer);
            }
        }

        /// Applies the last recognized policy from a redirect response.
        ///
        /// https://w3c.github.io/webappsec-referrer-policy/#set-requests-referrer-policy-on-redirect
        pub(super) fn on_redirect(&mut self, headers: &HeaderMap) {
            match ReferrerPolicy::from(headers) {
                ReferrerPolicy::None => {}
                policy => self.policy = policy,
            }
        }

        /// Computes the referrer for the next request in the redirect chain.
        ///
        /// https://w3c.github.io/webappsec-referrer-policy/#determine-requests-referrer
        pub(super) fn apply<B>(&mut self, req: &mut http::Request<B>) {
            let Some(mut source) = self.source.take() else {
                req.headers_mut().remove(REFERER);
                return;
            };
            let sensitive = req
                .headers_mut()
                .get(REFERER)
                .is_some_and(HeaderValue::is_sensitive);

            let Ok(source_scheme) = source.scheme().parse::<Scheme>() else {
                req.headers_mut().remove(REFERER);
                return;
            };

            let destination = req.uri();
            let same_origin = same_origin(&source, &source_scheme, destination);
            let downgrade =
                source_scheme == Scheme::HTTPS && destination.scheme() == Some(&Scheme::HTTP);

            let strip_to_origin = match self.policy {
                ReferrerPolicy::NoReferrer => {
                    req.headers_mut().remove(REFERER);
                    return;
                }
                ReferrerPolicy::NoReferrerWhenDowngrade if downgrade => {
                    req.headers_mut().remove(REFERER);
                    return;
                }
                ReferrerPolicy::SameOrigin if !same_origin => {
                    req.headers_mut().remove(REFERER);
                    return;
                }
                ReferrerPolicy::StrictOrigin if downgrade => {
                    req.headers_mut().remove(REFERER);
                    return;
                }
                ReferrerPolicy::StrictOriginWhenCrossOrigin | ReferrerPolicy::None
                    if !same_origin && downgrade =>
                {
                    req.headers_mut().remove(REFERER);
                    return;
                }
                ReferrerPolicy::Origin | ReferrerPolicy::StrictOrigin => true,
                ReferrerPolicy::OriginWhenCrossOrigin
                | ReferrerPolicy::StrictOriginWhenCrossOrigin
                | ReferrerPolicy::None => !same_origin,
                ReferrerPolicy::NoReferrerWhenDowngrade
                | ReferrerPolicy::SameOrigin
                | ReferrerPolicy::UnsafeUrl => false,
            };

            if strip_to_origin {
                strip_to_origin_url(&mut source);
            }

            match HeaderValue::try_from(source.as_str()) {
                Ok(mut value) => {
                    value.set_sensitive(sensitive);
                    req.headers_mut().insert(REFERER, value);
                    self.source = Some(source);
                }
                Err(_) => {
                    req.headers_mut().remove(REFERER);
                }
            }
        }
    }

    /// Referrer policies defined by the Referrer Policy specification.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum ReferrerPolicy {
        None,
        NoReferrer,
        NoReferrerWhenDowngrade,
        SameOrigin,
        Origin,
        StrictOrigin,
        OriginWhenCrossOrigin,
        #[default]
        StrictOriginWhenCrossOrigin,
        UnsafeUrl,
    }

    /// Parses all policy tokens and keeps the last recognized value.
    ///
    /// https://w3c.github.io/webappsec-referrer-policy/#parse-referrer-policy-from-header
    impl From<&HeaderMap> for ReferrerPolicy {
        fn from(headers: &HeaderMap) -> Self {
            let mut policy = Self::None;

            for value in headers.get_all(REFERRER_POLICY) {
                let Ok(value) = value.to_str() else {
                    continue;
                };

                for token in value.split(',') {
                    let parsed = Self::from(token.trim());
                    if parsed != Self::None {
                        policy = parsed;
                    }
                }
            }

            policy
        }
    }

    impl From<&str> for ReferrerPolicy {
        fn from(token: &str) -> Self {
            const TOKENS: &[(&str, ReferrerPolicy)] = &[
                ("no-referrer", ReferrerPolicy::NoReferrer),
                (
                    "no-referrer-when-downgrade",
                    ReferrerPolicy::NoReferrerWhenDowngrade,
                ),
                ("same-origin", ReferrerPolicy::SameOrigin),
                ("origin", ReferrerPolicy::Origin),
                ("strict-origin", ReferrerPolicy::StrictOrigin),
                (
                    "origin-when-cross-origin",
                    ReferrerPolicy::OriginWhenCrossOrigin,
                ),
                (
                    "strict-origin-when-cross-origin",
                    ReferrerPolicy::StrictOriginWhenCrossOrigin,
                ),
                ("unsafe-url", ReferrerPolicy::UnsafeUrl),
            ];

            match TOKENS
                .iter()
                .find(|(name, _)| token.eq_ignore_ascii_case(name))
            {
                Some((_, policy)) => *policy,
                None => Self::None,
            }
        }
    }

    /// Parses an HTTP(S) referrer and strips credentials and fragments.
    ///
    /// `Referer` field syntax:
    /// https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3
    ///
    /// Referrer Policy URL stripping:
    /// https://w3c.github.io/webappsec-referrer-policy/#strip-url
    fn parse_referrer(value: &HeaderValue) -> Option<Url> {
        let mut source = Url::parse(value.to_str().ok()?).ok()?;
        let scheme = source.scheme().parse::<Scheme>().ok()?;
        if scheme != Scheme::HTTP && scheme != Scheme::HTTPS {
            return None;
        }

        source.set_username("").ok()?;
        source.set_password(None).ok()?;
        source.set_fragment(None);

        if source.as_str().len() > 4096 {
            strip_to_origin_url(&mut source);
        }

        Some(source)
    }

    fn strip_to_origin_url(url: &mut Url) {
        url.set_path("");
        url.set_query(None);
        url.set_fragment(None);
    }

    fn same_origin(source: &Url, source_scheme: &Scheme, destination: &Uri) -> bool {
        let same_host = match (source.host_str(), destination.host()) {
            (Some(source), Some(destination)) => source.eq_ignore_ascii_case(destination),
            (None, None) => true,
            _ => false,
        };

        same_host
            && destination.scheme() == Some(source_scheme)
            && source.port_or_known_default() == Some(destination.port_or_default())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn headers_with_referrer(value: &'static str) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(REFERER, HeaderValue::from_static(value));
            headers
        }

        fn request(headers: HeaderMap, destination: &'static str) -> http::Request<()> {
            let mut req = http::Request::new(());
            *req.headers_mut() = headers;
            *req.uri_mut() = Uri::from_static(destination);
            req
        }

        fn apply(
            source: &'static str,
            destination: &'static str,
            policy: Option<&'static str>,
        ) -> Option<HeaderValue> {
            let headers = headers_with_referrer(source);
            let mut referrer = Referrer::new(&headers);

            if let Some(policy) = policy {
                let mut response_headers = HeaderMap::new();
                response_headers.insert(REFERRER_POLICY, HeaderValue::from_static(policy));
                referrer.on_redirect(&response_headers);
            }

            let mut req = request(headers, destination);
            referrer.apply(&mut req);
            req.headers().get(REFERER).cloned()
        }

        fn header_str(value: &Option<HeaderValue>) -> Option<&str> {
            value.as_ref().and_then(|value| value.to_str().ok())
        }

        #[test]
        fn applies_referrer_policy() {
            let mut headers = HeaderMap::new();
            headers.append(
                REFERRER_POLICY,
                HeaderValue::from_static("same-origin, future-policy"),
            );
            headers.append(REFERRER_POLICY, HeaderValue::from_static("ORIGIN, unknown"));

            assert_eq!(ReferrerPolicy::from(&headers), ReferrerPolicy::Origin);
            assert_eq!(ReferrerPolicy::from("future-policy"), ReferrerPolicy::None);

            let cases = [
                (
                    "default same-origin",
                    "https://user:pass@example.com/source?q=1#fragment",
                    "https://example.com/target",
                    None,
                    Some("https://example.com/source?q=1"),
                ),
                (
                    "default cross-origin",
                    "https://example.com/source?q=1",
                    "https://other.example/target",
                    None,
                    Some("https://example.com/"),
                ),
                (
                    "default downgrade",
                    "https://example.com/source",
                    "http://example.com/target",
                    None,
                    None,
                ),
                (
                    "no-referrer",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("no-referrer"),
                    None,
                ),
                (
                    "no-referrer-when-downgrade",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("no-referrer-when-downgrade"),
                    Some("https://example.com/source"),
                ),
                (
                    "same-origin",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("same-origin"),
                    None,
                ),
                (
                    "origin",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("origin"),
                    Some("https://example.com/"),
                ),
                (
                    "strict-origin",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("strict-origin"),
                    Some("https://example.com/"),
                ),
                (
                    "origin-when-cross-origin",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("origin-when-cross-origin"),
                    Some("https://example.com/"),
                ),
                (
                    "strict-origin-when-cross-origin",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("strict-origin-when-cross-origin"),
                    Some("https://example.com/"),
                ),
                (
                    "unsafe-url",
                    "https://example.com/source",
                    "https://other.example/target",
                    Some("unsafe-url"),
                    Some("https://example.com/source"),
                ),
            ];

            for (name, source, destination, policy, expected) in cases {
                let actual = apply(source, destination, policy);
                assert_eq!(header_str(&actual), expected, "case: {name}");
            }

            let mut value = HeaderValue::from_static("https://example.com/private");
            value.set_sensitive(true);
            let mut headers = HeaderMap::new();
            headers.insert(REFERER, value);
            let mut referrer = Referrer::new(&headers);

            let mut req = request(headers, "https://other.example/");
            referrer.apply(&mut req);
            assert!(req.headers()[REFERER].is_sensitive());

            let headers = headers_with_referrer("https://example.com/source");
            let mut referrer = Referrer::new(&headers);
            let mut req = request(headers, "https://example.com/first");

            let mut response_headers = HeaderMap::new();
            response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
            referrer.on_redirect(&response_headers);

            referrer.apply(&mut req);

            response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("unsafe-url"));
            referrer.on_redirect(&response_headers);

            *req.uri_mut() = Uri::from_static("https://example.com/second");
            referrer.apply(&mut req);

            assert_eq!(req.headers().get(REFERER), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_callbacks_preserve_security_and_isolation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let handler = FollowRedirectPolicy::new(Policy::none());
        let mut request = http::Request::builder()
            .uri("https://example.com/source")
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(RequestConfig::<Policy>::new(Some(
                Policy::default().on_request(move |_| {
                    observed.fetch_add(1, Ordering::Relaxed);
                }),
            )));

        handler
            .for_request(&mut request)
            .unwrap()
            .on_request(&mut request)
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(handler.for_request(&mut request).is_none());

        for (target, https_only, redirected, follows) in [
            ("https://other.example/target", false, false, true),
            ("http://other.example/target", true, false, false),
            ("http://other.example/target", true, true, false),
            ("ftp://other.example/target", false, false, false),
        ] {
            let mut request = http::Request::builder()
                .uri("https://example.com/source")
                .header(AUTHORIZATION, "secret")
                .header(COOKIE, "key=value")
                .header(http::header::REFERER, "https://example.com/private")
                .body(())
                .unwrap();
            let handler = FollowRedirectPolicy::new(Policy::none().on_request(move |request| {
                *request.uri_mut() = Uri::from_static(target);
            }))
            .with_referer(true)
            .with_https_only(https_only);
            let mut policy = handler.for_request(&mut request).unwrap();
            if redirected {
                policy
                    .uris
                    .push(Uri::from_static("https://example.com/source"));
            }
            let result = policy.on_request(&mut request);

            assert_eq!(result.is_ok(), follows, "target: {target}");
            if follows {
                assert!(!request.headers().contains_key(AUTHORIZATION));
                assert!(!request.headers().contains_key(COOKIE));
                assert_eq!(
                    request.headers()[http::header::REFERER],
                    "https://example.com/"
                );
            } else {
                let error = result.unwrap_err().downcast::<Error>().unwrap();
                assert_eq!(error.is_builder(), !redirected);
                assert_eq!(error.is_redirect(), redirected);
            }
        }
    }

    #[test]
    fn request_callbacks_recompute_referrer_for_final_uri() {
        const SOURCE: &str = "https://example.com/private?q=1";

        for (candidate, target, redirected, remove, expected) in [
            (
                "http://example.com/next",
                "https://example.com/next",
                true,
                false,
                Some(SOURCE),
            ),
            (
                "https://other.example/next",
                "https://example.com/next",
                true,
                false,
                Some(SOURCE),
            ),
            (
                "https://example.com/next",
                "http://example.com/next",
                true,
                false,
                None,
            ),
            (
                "https://example.com/next",
                "https://example.com/final",
                true,
                true,
                None,
            ),
            (
                "https://other.example/start",
                "https://other.example/final",
                false,
                false,
                Some(SOURCE),
            ),
        ] {
            let mut source = http::HeaderValue::from_static(SOURCE);
            source.set_sensitive(true);
            let mut request = http::Request::builder()
                .uri(candidate)
                .header(REFERER, source)
                .body(())
                .unwrap();
            let handler = FollowRedirectPolicy::new(Policy::default().on_request(move |request| {
                *request.uri_mut() = Uri::from_static(target);
                if remove {
                    request.headers_mut().remove(http::header::REFERER);
                }
            }))
            .with_referer(true);
            let mut policy = handler.for_request(&mut request).unwrap();
            if redirected {
                policy
                    .uris
                    .push(Uri::from_static("https://example.com/start"));
            }

            let hops = if redirected { 2 } else { 1 };
            for _ in 0..hops {
                policy.on_request(&mut request).unwrap();
                let value = request.headers().get(REFERER);
                assert_eq!(
                    value.map(|value| value.to_str().unwrap()),
                    expected,
                    "{candidate} -> {target}, redirected: {redirected}, remove: {remove}",
                );
                if let Some(value) = value {
                    assert!(value.is_sensitive(), "{candidate} -> {target}");
                }
            }
        }
    }

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
            if attempt.uri.host() == Some("foo") {
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

        let mut req = http::Request::new(());
        *req.headers_mut() = headers;
        *req.uri_mut() = next;

        remove_sensitive_headers(&mut req, &prev);
        assert_eq!(req.headers(), &filtered_headers);

        prev.push(Uri::try_from("http://new-domain.com/path").unwrap());
        filtered_headers.remove(AUTHORIZATION);
        filtered_headers.remove(COOKIE);

        remove_sensitive_headers(&mut req, &prev);
        assert_eq!(req.headers(), &filtered_headers);

        let mut default_port_headers = HeaderMap::new();
        default_port_headers.insert(AUTHORIZATION, HeaderValue::from_static("let me in"));

        let next = Uri::from_static("http://EXAMPLE.com:80/next");
        let previous = vec![Uri::from_static("http://example.com/previous")];

        let mut req = http::Request::new(());
        *req.headers_mut() = default_port_headers;
        *req.uri_mut() = next;

        remove_sensitive_headers(&mut req, &previous);
        assert_eq!(
            req.headers().get(AUTHORIZATION),
            Some(&HeaderValue::from_static("let me in"))
        );

        req.headers_mut()
            .insert(COOKIE, HeaderValue::from_static("foo=bar"));
        *req.uri_mut() = Uri::from_static("http://example.com:8443/next");
        let previous = [Uri::from_static("https://example.com:8443/previous")];

        remove_sensitive_headers(&mut req, &previous);
        assert_eq!(req.headers().get(AUTHORIZATION), None);
        assert_eq!(req.headers().get(COOKIE), None);
    }
}
