use std::{convert::Infallible, error::Error, time::Duration};

use http::{Request, Response};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use super::{HttpMode, build_current_thread_runtime, build_multi_thread_runtime};

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

#[inline]
pub fn spawn_single_thread_server(addr: &'static str, mode: HttpMode) -> ServerHandle {
    spawn_server(addr, false, mode)
}

#[inline]
pub fn spawn_multi_thread_server(addr: &'static str, mode: HttpMode) -> ServerHandle {
    spawn_server(addr, true, mode)
}

pub fn with_server<F>(
    addr: &'static str,
    mode: HttpMode,
    spawn: fn(&'static str, HttpMode) -> ServerHandle,
    f: F,
) -> Result<(), Box<dyn Error>>
where
    F: FnOnce() -> Result<(), Box<dyn Error>>,
{
    let server = spawn(addr, mode);
    f()?;
    server.shutdown();
    Ok(())
}

fn spawn_server(addr: &'static str, multi_thread: bool, mode: HttpMode) -> ServerHandle {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = std::thread::spawn(move || {
        let rt = if multi_thread {
            build_multi_thread_runtime()
        } else {
            build_current_thread_runtime()
        };
        let _ = rt.block_on(server_with_shutdown(addr, shutdown_rx, mode));
    });
    std::thread::sleep(Duration::from_millis(100));
    ServerHandle {
        shutdown: shutdown_tx,
        join,
    }
}

async fn server_with_shutdown(
    addr: &str,
    mut shutdown: oneshot::Receiver<()>,
    mode: HttpMode,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept = listener.accept() => {
                if let Ok((socket, _peer_addr)) = accept {
                    tokio::spawn(async move {
                        if let Err(e) = serve(socket, mode).await {
                            println!("  -> err={:?}", e);
                        }
                    });
                }
            }
        }
    }
    Ok(())
}

async fn serve(stream: TcpStream, mode: HttpMode) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut builder = Builder::new(TokioExecutor::new());
    builder = match mode {
        HttpMode::Http1 => builder.http1_only(),
        HttpMode::Http2 => builder.http2_only(),
    };
    let result = builder
        .serve_connection(TokioIo::new(stream), service_fn(handle_request))
        .await;

    if let Err(e) = result {
        eprintln!("error serving: {e}");
    }

    Ok(())
}

#[inline]
async fn handle_request(request: Request<Incoming>) -> Result<Response<Incoming>, Infallible> {
    let body = request.into_body();
    Ok(Response::new(body))
}
