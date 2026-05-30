//! Compio-based TCP connector.

#![allow(dead_code)]

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use compio::net::{TcpSocket, TcpStream};
use wreq_rt::rt::compio::{future::SendFuture, io::CompioIO};

use super::BoxConnecting;
use crate::conn::{info::ConnectionInfo, net::io::CompioConnection};

/// A connector that uses `compio` for TCP connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector {
    _priv: (),
}

// ===== impl TcpConnector =====

impl TcpConnector {
    /// Creates a new [`TcpConnector`].
    #[inline]
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl super::TcpConnector for TcpConnector {
    type TcpStream = std::net::TcpStream;
    type Connection = CompioConnection<TcpStream>;
    type Error = io::Error;
    type Future = BoxConnecting<Self::Connection, Self::Error>;
    type Sleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    #[inline]
    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future {
        Box::pin(SendFuture::new(async move {
            let socket = TcpSocket::from_std_stream(socket)?;
            let tcp_stream = socket.connect(addr).await?;
            Ok(CompioConnection {
                peer_addr: tcp_stream.peer_addr().ok(),
                local_addr: tcp_stream.local_addr().ok(),
                inner: CompioIO::new(tcp_stream),
            })
        }))
    }

    #[inline]
    fn sleep(&self, duration: Duration) -> Self::Sleep {
        Box::pin(SendFuture::new(compio::time::sleep(duration)))
    }
}

impl ConnectionInfo for CompioConnection<TcpStream> {
    #[inline]
    fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    #[inline]
    fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}
