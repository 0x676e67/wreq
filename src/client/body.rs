use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http_body::{Body as HttpBody, SizeHint};
use http_body_util::{BodyExt, Either, combinators::BoxBody};
use pin_project_lite::pin_project;
#[cfg(feature = "stream")]
use {tokio::fs::File, tokio_util::io::ReaderStream};

use crate::error::{BoxError, Error};

/// An request body.
pub struct Body(Either<Bytes, BoxBody<Bytes, BoxError>>);

pin_project! {
    /// We can't use `map_frame()` because that loses the hint data (for good reason).
    /// But we aren't transforming the data.
    struct IntoBytesBody<B> {
        #[pin]
        inner: B,
    }
}

// ===== impl Body =====

impl Body {
    /// Returns a reference to the internal data of the `Body`.
    ///
    /// `None` is returned, if the underlying data is a stream.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.0 {
            Either::Left(bytes) => Some(bytes.as_ref()),
            Either::Right(..) => None,
        }
    }

    /// Wrap a futures `Stream` in a box inside `Body`.
    ///
    /// # Example
    ///
    /// ```
    /// # use wreq::Body;
    /// # use futures_util;
    /// # fn main() {
    /// let chunks: Vec<Result<_, ::std::io::Error>> = vec![Ok("hello"), Ok(" "), Ok("world")];
    ///
    /// let stream = futures_util::stream::iter(chunks);
    ///
    /// let body = Body::wrap_stream(stream);
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `stream` feature to be enabled.
    #[cfg(feature = "stream")]
    #[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
    pub fn wrap_stream<S>(stream: S) -> Body
    where
        S: futures_util::stream::TryStream + Send + 'static,
        S::Error: Into<BoxError>,
        Bytes: From<S::Ok>,
    {
        Body::stream(stream)
    }

    #[cfg(any(feature = "stream", feature = "multipart"))]
    pub(crate) fn stream<S>(stream: S) -> Body
    where
        S: futures_util::stream::TryStream + Send + 'static,
        S::Error: Into<BoxError>,
        Bytes: From<S::Ok>,
    {
        use futures_util::TryStreamExt;
        use http_body::Frame;
        use http_body_util::StreamBody;
        use sync_wrapper::SyncStream;

        let body = StreamBody::new(SyncStream::new(
            stream
                .map_ok(Bytes::from)
                .map_ok(Frame::data)
                .map_err(Into::into),
        ));
        Body(Either::Right(body.boxed()))
    }

    /// Wrap a [`HttpBody`] in a box inside `Body`.
    ///
    /// # Example
    ///
    /// ```
    /// # use wreq::Body;
    /// # use futures_util;
    /// # fn main() {
    /// let content = "hello,world!".to_string();
    ///
    /// let body = Body::wrap(content);
    /// # }
    /// ```
    pub fn wrap<B>(inner: B) -> Body
    where
        B: HttpBody + Send + Sync + 'static,
        B::Data: Into<Bytes>,
        B::Error: Into<BoxError>,
    {
        Body(Either::Right(
            IntoBytesBody { inner }.map_err(Into::into).boxed(),
        ))
    }

    #[inline]
    pub(crate) fn empty() -> Body {
        Body::reusable(Bytes::new())
    }

    #[inline]
    pub(crate) fn reusable(chunk: Bytes) -> Body {
        Body(Either::Left(chunk))
    }

    #[cfg(feature = "multipart")]
    pub(crate) fn content_length(&self) -> Option<u64> {
        match self.0 {
            Either::Left(ref bytes) => Some(bytes.len() as u64),
            Either::Right(ref body) => body.size_hint().exact(),
        }
    }

    pub(crate) fn try_clone(&self) -> Option<Body> {
        match self.0 {
            Either::Left(ref chunk) => Some(Body::reusable(chunk.clone())),
            Either::Right { .. } => None,
        }
    }
}

impl Default for Body {
    #[inline]
    fn default() -> Body {
        Body::empty()
    }
}

impl From<BoxBody<Bytes, BoxError>> for Body {
    #[inline]
    fn from(body: BoxBody<Bytes, BoxError>) -> Self {
        Self(Either::Right(body))
    }
}

impl From<Bytes> for Body {
    #[inline]
    fn from(bytes: Bytes) -> Body {
        Body::reusable(bytes)
    }
}

impl From<Vec<u8>> for Body {
    #[inline]
    fn from(vec: Vec<u8>) -> Body {
        Body::reusable(vec.into())
    }
}

impl From<&'static [u8]> for Body {
    #[inline]
    fn from(s: &'static [u8]) -> Body {
        Body::reusable(Bytes::from_static(s))
    }
}

impl From<String> for Body {
    #[inline]
    fn from(s: String) -> Body {
        Body::reusable(s.into())
    }
}

impl From<&'static str> for Body {
    #[inline]
    fn from(s: &'static str) -> Body {
        s.as_bytes().into()
    }
}

#[cfg(feature = "stream")]
#[cfg_attr(docsrs, doc(cfg(feature = "stream")))]
impl From<File> for Body {
    #[inline]
    fn from(file: File) -> Body {
        Body::wrap_stream(ReaderStream::new(file))
    }
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Body").finish()
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.0 {
            Either::Left(ref mut bytes) => {
                let out = bytes.split_off(0);
                if out.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(http_body::Frame::data(out))))
                }
            }
            Either::Right(ref mut body) => {
                Poll::Ready(ready!(Pin::new(body).poll_frame(cx)).map(|opt_chunk| {
                    opt_chunk.map_err(|err| match err.downcast::<Error>() {
                        Ok(err) => *err,
                        Err(err) => Error::body(err),
                    })
                }))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self.0 {
            Either::Left(ref bytes) => SizeHint::with_exact(bytes.len() as u64),
            Either::Right(ref body) => body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self.0 {
            Either::Left(ref bytes) => bytes.is_empty(),
            Either::Right(ref body) => body.is_end_stream(),
        }
    }
}

// ===== impl IntoBytesBody =====

impl<B> HttpBody for IntoBytesBody<B>
where
    B: HttpBody,
    B::Data: Into<Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match ready!(self.project().inner.poll_frame(cx)) {
            Some(Ok(f)) => Poll::Ready(Some(Ok(f.map_data(Into::into)))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[cfg(test)]
mod tests {
    use http_body::Body as _;

    use super::Body;

    #[test]
    fn test_as_bytes() {
        let test_data = b"Test body";
        let body = Body::from(&test_data[..]);
        assert_eq!(body.as_bytes(), Some(&test_data[..]));
    }

    #[test]
    fn body_exact_length() {
        let empty_body = Body::empty();
        assert!(empty_body.is_end_stream());
        assert_eq!(empty_body.size_hint().exact(), Some(0));

        let bytes_body = Body::reusable("abc".into());
        assert!(!bytes_body.is_end_stream());
        assert_eq!(bytes_body.size_hint().exact(), Some(3));

        // can delegate even when wrapped
        let stream_body = Body::wrap(empty_body);
        assert!(stream_body.is_end_stream());
        assert_eq!(stream_body.size_hint().exact(), Some(0));
    }
}
