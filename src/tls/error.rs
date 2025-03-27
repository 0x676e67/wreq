use boring2::error::ErrorStack;
use std::{error, fmt};

#[derive(Debug)]
pub enum Error {
    Normal(ErrorStack),
    EmptyChain,
    NotPkcs8,
    IO(std::io::Error),
    InvalidCert,
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Normal(ref e) => error::Error::source(e),
            Error::EmptyChain => None,
            Error::NotPkcs8 => None,
            Error::IO(ref e) => Some(e),
            Error::InvalidCert => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Normal(ref e) => fmt::Display::fmt(e, fmt),
            Error::EmptyChain => write!(
                fmt,
                "at least one certificate must be provided to create an identity"
            ),
            Error::NotPkcs8 => write!(fmt, "expected PKCS#8 PEM"),
            Error::IO(ref e) => fmt::Display::fmt(e, fmt),
            Error::InvalidCert => write!(fmt, "invalid certificate"),
        }
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Error {
        Error::Normal(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IO(err)
    }
}
