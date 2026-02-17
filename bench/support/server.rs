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
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};
use tokio_boring2::SslStream;

use super::{Tls, build_current_thread_runtime, build_multi_thread_runtime};

pub struct ServerHandle {
    shutdown: oneshot::Sender<()>,
    join: std::thread::JoinHandle<()>,
}

impl ServerHandle {
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.join.join();
    }
}

pub fn with_server<F>(
    addr: &'static str,
    multi_thread: bool,
    tls: Tls,
    f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let server = spawn_server(addr, multi_thread, tls);
    f()?;
    server.shutdown();
    Ok(())
}

pub fn spawn_server(addr: &'static str, multi_thread: bool, tls: Tls) -> ServerHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = std::thread::spawn(move || {
        let rt = if multi_thread {
            build_multi_thread_runtime()
        } else {
            build_current_thread_runtime()
        };
        rt.block_on(server_with_shutdown(addr, shutdown_rx, tls))
            .expect("Failed to run server with shutdown");
    });
    std::thread::sleep(Duration::from_millis(100));
    ServerHandle {
        shutdown: shutdown_tx,
        join,
    }
}

fn build_tls_acceptor() -> Result<Arc<SslAcceptor>, Box<dyn Error + Send + Sync>> {
    let mut ctx = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;

    let cert_bytes = include_bytes!("../../tests/support/server.cert");
    let key_bytes = include_bytes!("../../tests/support/server.key");

    let cert = X509::from_der(cert_bytes).or_else(|_| X509::from_pem(cert_bytes))?;
    let key =
        PKey::private_key_from_der(key_bytes).or_else(|_| PKey::private_key_from_pem(key_bytes))?;

    ctx.set_certificate(&cert)?;
    ctx.set_private_key(&key)?;
    ctx.check_private_key()?;

    Ok(Arc::new(ctx.build()))
}

async fn serve<S>(stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let result = Builder::new(TokioExecutor::new())
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

    if let Err(e) = result {
        eprintln!("error serving: {e}");
    }
}

async fn handle_connection(socket: TcpStream, tls_acceptor: Option<Arc<SslAcceptor>>) {
    if let Some(acceptor) = tls_acceptor {
        let ssl = Ssl::new(acceptor.context()).expect("failed to create Ssl");
        let mut stream = SslStream::new(ssl, socket).expect("failed to create SslStream");
        Pin::new(&mut stream)
            .accept()
            .await
            .expect("TLS accept failed");
        serve(stream).await;
    } else {
        serve(socket).await;
    }
}

async fn server_with_shutdown(
    addr: &str,
    mut shutdown: oneshot::Receiver<()>,
    tls: Tls,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    let mut join_set = JoinSet::new();

    let tls_acceptor = match tls {
        Tls::Enabled => Some(build_tls_acceptor()?),
        Tls::Disabled => None,
    };

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept = listener.accept() => {
                if let Ok((socket, _peer_addr)) = accept {
                    let tls_acceptor = tls_acceptor.clone();
                    join_set.spawn(async move {
                        handle_connection(socket, tls_acceptor).await;
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
    Ok(())
}
