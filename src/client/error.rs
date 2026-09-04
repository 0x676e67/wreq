//! Error types produced by the low-level HTTP client.

use std::{error::Error as StdError, fmt};

use tower::BoxError;

use crate::{
    conn::{Connected, proxy},
    error::ProxyConnect,
};

/// Error returned by the low-level client service.
///
/// The category identifies the failed stage. When another component supplied
/// the failure, `source` keeps its error chain and `connect_info` records the
/// selected transport for higher-level diagnostics.
#[derive(Debug)]
pub struct Error {
    /// Stage that classified the failure.
    kind: ErrorKind,
    /// Original error, when one was available.
    source: Option<BoxError>,
    /// Metadata for the connection that observed the failure.
    #[allow(unused)]
    connect_info: Option<Connected>,
}

/// Internal categories used by the public error inspection methods.
#[derive(Debug)]
pub(super) enum ErrorKind {
    /// A request was canceled before protocol encoding began.
    Canceled,

    /// The protocol sender closed while becoming ready.
    ChannelClosed,

    /// Physical connection establishment failed.
    Connect,

    /// Proxy connection or tunneling failed.
    ProxyConnect,

    /// The selected HTTP version does not allow the request method.
    UserUnsupportedRequestMethod,

    /// The request requires an unsupported HTTP version.
    UserUnsupportedVersion,

    /// The request target could not be normalized from an absolute URI.
    UserAbsoluteUriRequired,

    /// Protocol dispatch failed after a sender was selected.
    SendRequest,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|error| &**error as _)
    }
}

impl Error {
    /// Creates a classified error without an underlying source.
    pub(super) fn from_kind(kind: ErrorKind) -> Self {
        Self {
            kind,
            source: None,
            connect_info: None,
        }
    }

    /// Creates a classified error and preserves its underlying source.
    pub(super) fn new<E>(kind: ErrorKind, error: E) -> Self
    where
        E: Into<BoxError>,
    {
        let error = error.into();
        let kind = if is_proxy_connect_error(&*error) {
            ErrorKind::ProxyConnect
        } else {
            kind
        };

        Self {
            kind,
            source: Some(error),
            connect_info: None,
        }
    }

    /// Returns true when physical connection establishment failed.
    #[inline]
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns true when proxy connection or tunneling failed.
    #[inline]
    pub fn is_proxy_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::ProxyConnect)
    }

    /// Attaches metadata for the connection that observed the error.
    #[inline]
    pub(super) fn with_connect_info(self, connect_info: Connected) -> Self {
        Self {
            connect_info: Some(connect_info),
            ..self
        }
    }

    /// Converts a closed protocol sender into a client error.
    #[inline]
    pub(super) fn closed(source: wreq_proto::Error) -> Self {
        Self::new(ErrorKind::ChannelClosed, source)
    }
}

/// Returns whether any error in the source chain came from proxy setup.
fn is_proxy_connect_error(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<proxy::tunnel::TunnelError>() || error.is::<ProxyConnect>() || {
            #[cfg(feature = "socks")]
            {
                error.is::<proxy::socks::SocksError>()
            }
            #[cfg(not(feature = "socks"))]
            {
                false
            }
        } {
            return true;
        }
        current = error.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct WrappedError(BoxError);

    impl fmt::Display for WrappedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("wrapped error")
        }
    }

    impl StdError for WrappedError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&*self.0)
        }
    }

    #[test]
    fn classifies_wrapped_proxy_errors() {
        let source = std::io::Error::other("proxy unavailable");
        let error = WrappedError(Box::new(ProxyConnect(Box::new(source))));
        let error = Error::new(ErrorKind::Connect, error);

        assert!(error.is_proxy_connect());
        assert!(!error.is_connect());
    }
}
