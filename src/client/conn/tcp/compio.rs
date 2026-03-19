use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use compio::net::TcpStream;
use send_wrapper::SendWrapper;

use super::TcpConnector;
use crate::client::{Connected, Connection, conn::HttpInfo, core::rt::CompioIO};

/// A connector that uses `compio` for TCP connections.
#[derive(Clone, Copy, Debug, Default)]
pub struct CompioTcpConnector {
    _priv: (),
}

impl CompioTcpConnector {
    /// Create a new [`CompioTcpConnector`].
    pub fn new() -> Self {
        Self { _priv: () }
    }
}

impl TcpConnector for CompioTcpConnector {
    type TcpStream = socket2::Socket;
    type Connection = CompioIO<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send>>;
    type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future {
        let _ = socket.connect(&addr.into());
        let fut = async move {
            let stream = TcpStream::from_std(socket.into())?;
            stream.to_poll_fd()?.connect_ready().await?;
            Ok(CompioIO::new(stream))
        };
        Box::pin(SendWrapper::new(fut))
    }

    #[inline]
    fn sleep(&self, duration: Duration) -> Self::Sleep {
        Box::pin(SendWrapper::new(compio::time::sleep(duration)))
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
        self.get_ref().connected()
    }
}
