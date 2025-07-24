use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use http_body::Body as HttpBody;
use http_body_util::combinators::BoxBody;
use pin_project_lite::pin_project;
#[cfg(feature = "stream")]
use {tokio::fs::File, tokio_util::io::ReaderStream};

use crate::error::{BoxError, Error};

/// An request body.
pub struct Body {
    inner: Inner,
}

enum Inner {
    Reusable(Bytes),
    Streaming(BoxBody<Bytes, BoxError>),
}

/// Converts any `impl Body` into a `impl Stream` of just its DATA frames.
#[cfg(any(feature = "stream", feature = "multipart"))]
pub(crate) struct DataStream<B>(pub(crate) B);

// ===== impl Body =====

impl Body {
    /// Returns a reference to the internal data of the `Body`.
    ///
    /// `None` is returned, if the underlying data is a stream.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.inner {
            Inner::Reusable(bytes) => Some(bytes.as_ref()),
            Inner::Streaming(..) => None,
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

        let body = http_body_util::BodyExt::boxed(StreamBody::new(sync_wrapper::SyncStream::new(
            stream
                .map_ok(|d| Frame::data(Bytes::from(d)))
                .map_err(Into::into),
        )));
        Body {
            inner: Inner::Streaming(body),
        }
    }

    pub(crate) fn empty() -> Body {
        Body::reusable(Bytes::new())
    }

    pub(crate) fn reusable(chunk: Bytes) -> Body {
        Body {
            inner: Inner::Reusable(chunk),
        }
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
        use http_body_util::BodyExt;

        let boxed = IntoBytesBody { inner }.map_err(Into::into).boxed();

        Body {
            inner: Inner::Streaming(boxed),
        }
    }

    pub(crate) fn try_clone(&self) -> Option<Body> {
        match self.inner {
            Inner::Reusable(ref chunk) => Some(Body::reusable(chunk.clone())),
            Inner::Streaming { .. } => None,
        }
    }

    #[cfg(feature = "multipart")]
    pub(crate) fn into_stream(self) -> DataStream<Body> {
        DataStream(self)
    }

    #[cfg(feature = "multipart")]
    pub(crate) fn content_length(&self) -> Option<u64> {
        match self.inner {
            Inner::Reusable(ref bytes) => Some(bytes.len() as u64),
            Inner::Streaming(ref body) => body.size_hint().exact(),
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
        Self {
            inner: Inner::Streaming(body),
        }
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
        match self.inner {
            Inner::Reusable(ref mut bytes) => {
                let out = bytes.split_off(0);
                if out.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(http_body::Frame::data(out))))
                }
            }
            Inner::Streaming(ref mut body) => {
                Poll::Ready(ready!(Pin::new(body).poll_frame(cx)).map(|opt_chunk| {
                    opt_chunk.map_err(|err| match err.downcast::<Error>() {
                        Ok(err) => *err,
                        Err(err) => Error::body(err),
                    })
                }))
            }
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self.inner {
            Inner::Reusable(ref bytes) => http_body::SizeHint::with_exact(bytes.len() as u64),
            Inner::Streaming(ref body) => body.size_hint(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self.inner {
            Inner::Reusable(ref bytes) => bytes.is_empty(),
            Inner::Streaming(ref body) => body.is_end_stream(),
        }
    }
}

pub(crate) type ResponseBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

pub(crate) fn boxed<B>(body: B) -> ResponseBody
where
    B: HttpBody<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    use http_body_util::BodyExt;

    body.map_err(Into::into).boxed()
}

// ===== impl DataStream =====

#[cfg(any(feature = "stream", feature = "multipart",))]
impl<B> futures_util::Stream for DataStream<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
{
    type Item = Result<Bytes, B::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            return match ready!(Pin::new(&mut self.0).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    // skip non-data frames
                    if let Ok(buf) = frame.into_data() {
                        Poll::Ready(Some(Ok(buf)))
                    } else {
                        continue;
                    }
                }
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            };
        }
    }
}

// ===== impl IntoBytesBody =====

pin_project! {
    struct IntoBytesBody<B> {
        #[pin]
        inner: B,
    }
}
// We can't use `map_frame()` because that loses the hint data (for good reason).
// But we aren't transforming the data.
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
    fn size_hint(&self) -> http_body::SizeHint {
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
