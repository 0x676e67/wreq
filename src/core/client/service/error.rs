use std::{error::Error as StdError, fmt};

use http::Request;

use crate::core::{
    self,
    client::{connect::Connected, pool},
    error::BoxError,
};

macro_rules! e {
    ($kind:ident) => {
        Error {
            kind: ErrorKind::$kind,
            source: None,
            connect_info: None,
        }
    };
    ($kind:ident, $src:expr) => {
        Error {
            kind: ErrorKind::$kind,
            source: Some($src.into()),
            connect_info: None,
        }
    };
}

#[derive(Debug)]
pub struct Error {
    pub(super) kind: ErrorKind,
    pub(super) source: Option<BoxError>,
    pub(super) connect_info: Option<Connected>,
}

#[derive(Debug)]
pub(super) enum ErrorKind {
    Canceled,
    ChannelClosed,
    Connect,
    UserUnsupportedRequestMethod,
    UserUnsupportedVersion,
    UserAbsoluteUriRequired,
    SendRequest,
}

pub(super) enum ClientConnectError {
    Normal(Error),
    CheckoutIsClosed(pool::Error),
}

#[allow(clippy::large_enum_variant)]
pub(super) enum TrySendError<B> {
    Retryable {
        error: Error,
        req: Request<B>,
        connection_reused: bool,
    },
    Nope(Error),
}

// ==== impl Error ====

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "client error ({:?})", self.kind)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| &**e as _)
    }
}

impl Error {
    /// Returns true if this was an error from `Connect`.
    pub fn is_connect(&self) -> bool {
        matches!(self.kind, ErrorKind::Connect)
    }

    /// Returns the info of the client connection on which this error occurred.
    pub fn connect_info(&self) -> Option<&Connected> {
        self.connect_info.as_ref()
    }

    pub(super) fn with_connect_info(self, connect_info: Connected) -> Self {
        Self {
            connect_info: Some(connect_info),
            ..self
        }
    }
    pub(super) fn is_canceled(&self) -> bool {
        matches!(self.kind, ErrorKind::Canceled)
    }

    pub(super) fn tx(src: core::Error) -> Self {
        e!(SendRequest, src)
    }

    pub(super) fn closed(src: core::Error) -> Self {
        e!(ChannelClosed, src)
    }
}
