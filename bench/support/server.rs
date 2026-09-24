//! Loopback echo-server lifecycle used by every protocol benchmark group.

use std::{convert::Infallible, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use btls::{
    pkey::PKey,
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::X509,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Collected, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};
use tokio_btls::SslStream;

use super::{BoxError, ThreadMode, Tls, runtime::tokio_runtime};

/// Owns the listener and protocol configuration for one benchmark group.
///
/// The value moves to a dedicated server thread when [`Server::run`] starts.
struct Server {
    listener: std::net::TcpListener,
    tls_acceptor: Option<Arc<SslAcceptor>>,
    builder: Builder<TokioExecutor>,
}

// ===== impl Server =====

impl Server {
    /// Binds a loopback echo server with the selected transport.
    ///
    /// Returns an error if TLS setup or listener configuration fails.
    fn new(tls: Tls) -> Result<Self, BoxError> {
        let tls_acceptor = match tls {
            Tls::Enabled => {
                let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

                let cert = X509::from_der(include_bytes!("../../tests/support/server.cert"))?;
                let key =
                    PKey::private_key_from_der(include_bytes!("../../tests/support/server.key"))?;

                builder.set_certificate(&cert)?;
                builder.set_private_key(&key)?;
                builder.check_private_key()?;

                Some(Arc::new(builder.build()))
            }
            Tls::Disabled => None,
        };

        let mut builder = Builder::new(TokioExecutor::new());
        builder.http1().timer(TokioTimer::new()).keep_alive(true);
        builder
            .http2()
            .timer(TokioTimer::new())
            .keep_alive_interval(Duration::from_secs(30));

        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;

        Ok(Server {
            listener,
            tls_acceptor,
            builder,
        })
    }

    /// Returns the address assigned to the bound listener.
    ///
    /// Returns an error if the operating system cannot query the address.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts connections until shutdown, then cancels group-owned connections.
    ///
    /// Returns an error if listener registration, accepting a connection, or TLS
    /// state construction fails, or if a connection task panics.
    async fn run(self, mut shutdown: oneshot::Receiver<()>) -> Result<(), BoxError> {
        let mut join_set = JoinSet::new();
        let listener = TcpListener::from_std(self.listener)?;

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                accept = listener.accept() => {
                    let (socket, _peer_addr) = accept?;
                    let tls_acceptor = self.tls_acceptor.clone();
                    let builder = self.builder.clone();
                    join_set.spawn(handle_connection(socket, tls_acceptor, builder));
                }
            }
        }

        // Stop accepting first, then cancel keep-alive connections owned by this group.
        ::std::mem::drop(listener);
        join_set.abort_all();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}

/// Signals and joins the server thread owned by one benchmark group.
struct Handle {
    shutdown: oneshot::Sender<()>,
    join: std::thread::JoinHandle<Result<(), BoxError>>,
}

// ===== impl Handle =====

impl Handle {
    /// Requests shutdown and waits for the server thread to finish.
    ///
    /// Returns an error if the thread panics or the server loop fails.
    fn shutdown(self) -> Result<(), BoxError> {
        // A closed receiver means the server already stopped; joining below returns its result.
        let _ = self.shutdown.send(());
        self.join
            .join()
            .map_err(|_| io::Error::other("benchmark server thread panicked"))?
    }
}

/// Runs a callback against a fresh server and joins it before returning.
///
/// Teardown still runs when the callback fails. Setup, callback, and shutdown
/// failures are propagated, with the callback result taking precedence.
pub(crate) fn with_server<F>(tls: Tls, f: F) -> Result<(), BoxError>
where
    F: FnOnce(SocketAddr) -> Result<(), BoxError>,
{
    let server = Server::new(tls)?;
    let addr = server.local_addr()?;

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let join = std::thread::spawn(move || {
        let runtime = tokio_runtime(ThreadMode::Multi)?;
        runtime.block_on(server.run(shutdown_rx))
    });

    let handle = Handle {
        shutdown: shutdown_tx,
        join,
    };

    let result = f(addr);
    let shutdown_result = handle.shutdown();

    result?;
    shutdown_result
}

/// Serves one accepted stream and echoes each fully collected request body.
///
/// Body read failures yield an empty response. Connection-driver errors are
/// ignored because benchmark teardown may close otherwise healthy streams.
async fn serve<S>(builder: Builder<TokioExecutor>, stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Client teardown can close an otherwise healthy connection.
    let _ = builder
        .serve_connection(
            TokioIo::new(stream),
            service_fn(|req: http::Request<Incoming>| async {
                let bytes = req
                    .into_body()
                    .collect()
                    .await
                    .map(Collected::<Bytes>::to_bytes);
                let bytes = bytes.unwrap_or_else(|_| Bytes::new());
                Ok::<_, Infallible>(http::Response::new(Full::new(bytes)))
            }),
        )
        .await;
}

/// Applies optional TLS and serves one accepted socket.
///
/// TLS handshake failures end only the current connection and are not returned.
/// Returns an error if BoringSSL cannot create the connection's TLS state.
async fn handle_connection(
    socket: TcpStream,
    tls_acceptor: Option<Arc<SslAcceptor>>,
    builder: Builder<TokioExecutor>,
) -> Result<(), BoxError> {
    if let Some(acceptor) = tls_acceptor {
        let ssl = Ssl::new(acceptor.context())?;
        let mut stream = SslStream::new(ssl, socket)?;

        // Clients may disconnect while a benchmark group is tearing down.
        if Pin::new(&mut stream).accept().await.is_err() {
            return Ok(());
        }
        serve(builder, stream).await;
    } else {
        serve(builder, socket).await;
    }

    Ok(())
}
