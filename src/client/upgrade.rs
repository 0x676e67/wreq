use std::{
    io,
    pin::Pin,
    task::{self, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use wreq_proto::upgrade;

use crate::Error;

/// An upgraded HTTP connection.
/// Returned after the response completes an HTTP upgrade.
/// Owns the connection and exposes asynchronous reads and writes.
#[derive(Debug)]
pub struct Upgraded(upgrade::Upgraded);

impl AsyncRead for Upgraded {
    #[inline(always)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    #[inline(always)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline(always)]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    #[inline(always)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline(always)]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    #[inline(always)]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl From<upgrade::Upgraded> for Upgraded {
    fn from(inner: upgrade::Upgraded) -> Self {
        Upgraded(inner)
    }
}

impl super::response::Response {
    /// Consumes the response and returns a future for a possible HTTP upgrade.
    pub async fn upgrade(self) -> crate::Result<Upgraded> {
        upgrade::on(http::Response::from(self))
            .await
            .map(Upgraded::from)
            .map_err(Error::upgrade)
    }
}
