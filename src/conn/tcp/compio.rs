#![allow(dead_code)]
//! Compio-based TCP connector.

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use super::TcpConnector;
use crate::{
    conn::{Connected, Connection, compio_io::CompioIO},
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
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Connection, Self::Error>> + Send + 'static>>;
    type Sleep = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

    fn connect(&self, socket: Self::TcpStream, addr: SocketAddr) -> Self::Future {
        // Read the nodelay setting that tcp.rs already applied to the socket,
        // then apply it to the compio TcpStream after connect.
        let nodelay = socket.nodelay().unwrap_or(false);
        drop(socket);
        Box::pin(SendFuture::new(async move {
            let tcp_stream = compio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            tcp_stream.set_nodelay(nodelay)?;
            Ok(CompioIO::new(tcp_stream))
        }))
    }

    fn sleep(&self, duration: Duration) -> Self::Sleep {
        Box::pin(SendFuture::new(compio::time::sleep(duration)))
    }
}

impl Connection for CompioIO<compio::net::TcpStream> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
