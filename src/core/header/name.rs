use std::borrow::Cow;

use bytes::Bytes;
use http::HeaderName;

/// Represents an HTTP header name with its original casing preserved.
///
/// `HeaderCaseName` is used to store the original case-sensitive form of an HTTP header name as
/// it appeared in the request or response. While HTTP header names are case-insensitive according
/// to the specification, preserving the original casing can be important for certain applications,
/// such as proxies, logging, debugging, or when reproducing requests exactly as received.
///
/// This type allows you to associate a normalized `HeaderName` with its original string
/// representation, enabling accurate restoration or inspection of header names in their original
/// form.
pub struct OriginalHeaderName {
    /// The original header name in its original case.
    pub orig: Bytes,
    /// The normalized header name in lowercase.
    pub name: HeaderName,
}

impl From<HeaderName> for OriginalHeaderName {
    fn from(name: HeaderName) -> Self {
        Self {
            orig: Bytes::from_owner(name.clone()),
            name,
        }
    }
}

impl<'a> From<&'a HeaderName> for OriginalHeaderName {
    fn from(src: &'a HeaderName) -> OriginalHeaderName {
        Self::from(src.clone())
    }
}

impl TryFrom<String> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: String) -> Result<Self, Self::Error> {
        let name = HeaderName::from_bytes(orig.as_bytes())?;
        Ok(Self {
            orig: Bytes::from_owner(orig),
            name,
        })
    }
}

impl TryFrom<Cow<'static, str>> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: Cow<'static, str>) -> Result<Self, Self::Error> {
        match orig {
            Cow::Borrowed(orig) => Self::try_from(orig.as_bytes()),
            Cow::Owned(orig) => Self::try_from(orig),
        }
    }
}

impl TryFrom<Bytes> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: Bytes) -> Result<Self, Self::Error> {
        let name = HeaderName::from_bytes(&orig)?;
        Ok(Self { orig, name })
    }
}

impl<'a> TryFrom<&'a Bytes> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: &'a Bytes) -> Result<Self, Self::Error> {
        let name = HeaderName::from_bytes(orig)?;
        Ok(Self {
            orig: orig.clone(),
            name,
        })
    }
}

impl TryFrom<&'static [u8]> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: &'static [u8]) -> Result<Self, Self::Error> {
        let name = HeaderName::from_bytes(orig)?;
        Ok(Self {
            orig: Bytes::from_static(orig),
            name,
        })
    }
}

impl TryFrom<&'static str> for OriginalHeaderName {
    type Error = http::Error;

    fn try_from(orig: &'static str) -> Result<Self, Self::Error> {
        Self::try_from(orig.as_bytes())
    }
}
