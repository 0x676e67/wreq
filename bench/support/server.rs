use std::{convert::Infallible, error::Error, pin::Pin, sync::Arc, time::Duration};

use boring2::{
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
use tokio_boring2::SslStream;

use super::{Tls, multi_thread_runtime};

pub struct Server {
    addr: &'static str,
    tls_acceptor: Option<Arc<SslAcceptor>>,
    builder: Builder<TokioExecutor>,
}

impl Server {
    pub fn new(addr: &'static str, tls: Tls) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let tls_acceptor = match tls {
            Tls::Enabled => {
                let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;

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

        Ok(Server {
            addr,
            tls_acceptor,
            builder,
        })
    }

    async fn serve<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _ = self
            .builder
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

    async fn run(
        self: Arc<Self>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener = TcpListener::bind(self.addr).await?;
        let mut join_set = JoinSet::new();

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                accept = listener.accept() => {
                    if let Ok((socket, _peer_addr)) = accept {
                        let tls_acceptor = self.tls_acceptor.clone();
                        let server = self.clone();
                        join_set.spawn(async move {
                            handle_connection(socket, tls_acceptor, server).await;
                        });
                    }
                }
            }
        }

        while let Some(result) = join_set.join_next().await {
            if let Err(e) = result {
                eprintln!("connection task failed: {e}");
            }
        }

        // Tokio internally accepts TCP connections while the TCPListener is active;
        // drop the listener to immediately refuse connections rather than letting
        // them hang.
        ::std::mem::drop(listener);
        Ok(())
    }
}

pub struct Handle {
    shutdown: oneshot::Sender<()>,
    join: std::thread::JoinHandle<()>,
}

impl Handle {
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.join();
    }
}

pub fn with_server<F>(addr: &'static str, tls: Tls, f: F) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = std::thread::spawn(move || {
        let server = Arc::new(Server::new(addr, tls).expect("Failed to create server"));
        let rt = multi_thread_runtime();
        rt.block_on(server.clone().run(shutdown_rx))
            .expect("Failed to run server with shutdown");
    });

    std::thread::sleep(Duration::from_millis(100));
    let server = Handle {
        shutdown: shutdown_tx,
        join,
    };

    f()?;
    server.shutdown();
    Ok(())
}

async fn handle_connection(
    socket: TcpStream,
    tls_acceptor: Option<Arc<SslAcceptor>>,
    server: Arc<Server>,
) {
    if let Some(acceptor) = tls_acceptor {
        let ssl = Ssl::new(acceptor.context()).expect("failed to create Ssl");
        let mut stream = SslStream::new(ssl, socket).expect("failed to create SslStream");

        // The client (or its connection pool) may proactively close the connection,
        // especially during benchmarks or when cleaning up idle connections.
        // This can cause TLS handshake failures (e.g., ConnectionReset, ConnectionAborted).
        // Such errors are expected and should be handled gracefully to avoid panicking
        // and to ensure the server remains robust under load.
        if Pin::new(&mut stream).accept().await.is_err() {
            return;
        }
        server.serve(stream).await;
    } else {
        server.serve(socket).await;
    }
}
