//! Compio-based TCP connector.

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use compio::net::{TcpSocket, TcpStream};
use wreq_rt::rt::compio::io::CompioIO;

use super::TcpConnector;
use crate::{
    conn::{Connected, Connection, http::HttpInfo},
    util::SendFuture,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct CompioTcpConnector {
    _priv: (),
}

impl CompioTcpConnector {
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl TcpConnector for CompioTcpConnector {
    type TcpStream = std::net::TcpStream;
    type Connection = CompioIO<compio::net::TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type Sleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    #[inline]
    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future {
        Box::pin(SendFuture::new(async move {
            let socket = TcpSocket::from_std_stream(socket)?;
            let tcp_stream = socket.connect(addr).await?;
            Ok(CompioIO::new(tcp_stream))
        }))
    }

    #[inline]
    fn sleep(&self, duration: Duration) -> Self::Sleep {
        Box::pin(SendFuture::new(compio::time::sleep(duration)))
    }
}

impl Connection for TcpStream {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if let (Ok(remote_addr), Ok(local_addr)) = (self.peer_addr(), self.local_addr()) {
            connected.extra(HttpInfo {
                remote_addr,
                local_addr,
            })
        } else {
            connected
        }
    }
}

impl Connection for CompioIO<TcpStream> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
