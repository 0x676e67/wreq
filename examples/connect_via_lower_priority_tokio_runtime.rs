// This example demonstrates how to delegate the connect calls, which contain TLS handshakes,
// to a secondary tokio runtime of lower OS thread priority using a custom tower layer.
// This helps to ensure that long-running futures during handshake crypto operations don't block
// other I/O futures.
// New QUIC endpoints and their transport drivers are also created on this runtime.
// Existing endpoints keep their original runtime; HTTP protocol drivers are separate.
// Use `--features "http3 tracing" -- --http3 https://cloudflare-quic.com` to select HTTP/3.
//
// This does introduce overhead of additional threads, channels, extra vtables, etc,
// so it is best suited to services with large numbers of incoming connections or that
// are otherwise very sensitive to any blocking futures.  Or, you might want fewer threads
// and/or to use the current_thread runtime.
//
// This is using the `tokio` runtime and certain other dependencies:
//
// `tokio = { version = "1", features = ["full"] }`
// `libc = "0"`
// `pin-project-lite = "0.2"`
// `tower = { version = "0.5", default-features = false}`

use wreq::Client;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
    background_threadpool::init_background_runtime();

    let mut args = std::env::args().skip(1);
    let url = args.next();
    let builder = Client::builder_tokio()
        .connector_layer(background_threadpool::BackgroundProcessorLayer::new());
    #[cfg(feature = "http3")]
    let (builder, url) = match url.as_deref() {
        Some("--http3") => (builder.http3_only(), args.next()),
        _ => (builder, url),
    };
    let client = builder
        .build()
        .expect("should be able to build wreq client");

    let url = if let Some(url) = url {
        url
    } else {
        println!("No CLI URL provided, using default.");
        "https://hyper.rs".into()
    };

    eprintln!("Fetching {url:?}...");

    let res = client.get(url).send().await?;

    eprintln!("Response: {:?} {}", res.version(), res.status());
    eprintln!("Headers: {:#?}\n", res.headers());

    let body = res.text().await?;

    println!("{body}");

    Ok(())
}

// separating out for convenience to avoid a million
mod background_threadpool {
    use std::{
        future::Future,
        pin::Pin,
        sync::OnceLock,
        task::{Context, Poll},
    };

    use futures_util::{TryFutureExt, future::BoxFuture};
    use pin_project_lite::pin_project;
    use tokio::{runtime::Handle, select, sync::mpsc::error::TrySendError};
    use tower::{BoxError, Layer, Service};

    static CPU_HEAVY_THREAD_POOL: OnceLock<tokio::sync::mpsc::Sender<BoxFuture<'static, ()>>> =
        OnceLock::new();

    pub(crate) fn init_background_runtime() {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        CPU_HEAVY_THREAD_POOL.set(tx).unwrap();
        std::thread::Builder::new()
            .name("cpu-heavy-background-threadpool".to_string())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .thread_name("cpu-heavy-background-pool-thread")
                    .worker_threads(std::thread::available_parallelism().unwrap().get())
                    // ref: https://github.com/tokio-rs/tokio/issues/4941
                    // consider uncommenting if seeing heavy task contention
                    // .disable_lifo_slot()
                    .on_thread_start(move || {
                        #[cfg(target_os = "linux")]
                        unsafe {
                            // Increase thread pool thread niceness, so they are lower priority
                            // than the foreground executor and don't interfere with I/O tasks
                            {
                                *libc::__errno_location() = 0;
                                if libc::nice(10) == -1 && *libc::__errno_location() != 0 {
                                    let error = std::io::Error::last_os_error();
                                    tracing::error!("failed to set threadpool niceness: {error}");
                                }
                            }
                        }
                    })
                    .enable_all()
                    .build()
                    .unwrap_or_else(|e| panic!("cpu heavy runtime failed_to_initialize: {e}"));
                rt.block_on(async {
                    tracing::debug!("starting background cpu-heavy work");
                    process_cpu_work(rx).await;
                });
            })
            .unwrap_or_else(|e| panic!("cpu heavy thread failed_to_initialize: {e}"));
    }

    async fn process_cpu_work(mut rx: tokio::sync::mpsc::Receiver<BoxFuture<'static, ()>>) {
        while let Some(work) = rx.recv().await {
            tokio::task::spawn(work);
        }
    }

    // retrieve the sender to the background channel, and send the future over to it for execution
    fn send_to_background_runtime(future: impl Future<Output = ()> + Send + 'static) {
        let tx = CPU_HEAVY_THREAD_POOL.get().expect(
            "start up the secondary tokio runtime before sending to `CPU_HEAVY_THREAD_POOL`",
        );

        match tx.try_send(Box::pin(future)) {
            Ok(_) => (),
            Err(TrySendError::Closed(_)) => {
                panic!("background cpu heavy runtime channel is closed")
            }
            Err(TrySendError::Full(msg)) => {
                tracing::warn!(
                    "background cpu heavy runtime channel is full, task spawning loop delayed"
                );
                let tx = tx.clone();
                Handle::current().spawn(async move {
                    tx.send(msg)
                        .await
                        .expect("background cpu heavy runtime channel is closed")
                });
            }
        }
    }

    // This tower layer injects futures with a oneshot channel, and then sends them to the
    // background runtime for processing. We don't use the Buffer service because that is
    // intended to process sequentially on a single task, whereas we want to spawn a new task
    // per call.
    #[derive(Copy, Clone)]
    pub struct BackgroundProcessorLayer {}
    impl BackgroundProcessorLayer {
        pub fn new() -> Self {
            Self {}
        }
    }
    impl<S> Layer<S> for BackgroundProcessorLayer {
        type Service = BackgroundProcessor<S>;
        fn layer(&self, service: S) -> Self::Service {
            BackgroundProcessor::new(service)
        }
    }

    impl std::fmt::Debug for BackgroundProcessorLayer {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_struct("BackgroundProcessorLayer").finish()
        }
    }

    // This tower service injects futures with a oneshot channel, and then sends them to the
    // background runtime for processing.
    #[derive(Debug, Clone)]
    pub struct BackgroundProcessor<S> {
        inner: S,
    }

    impl<S> BackgroundProcessor<S> {
        pub fn new(inner: S) -> Self {
            BackgroundProcessor { inner }
        }
    }

    impl<S, Request> Service<Request> for BackgroundProcessor<S>
    where
        S: Service<Request>,
        S::Response: Send + 'static,
        S::Error: Into<BoxError> + Send,
        S::Future: Send + 'static,
    {
        type Response = S::Response;

        type Error = BoxError;

        type Future = BackgroundResponseFuture<S::Response>;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            match self.inner.poll_ready(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(r) => Poll::Ready(r.map_err(Into::into)),
            }
        }

        fn call(&mut self, req: Request) -> Self::Future {
            let response = self.inner.call(req);

            // wrap our inner service's future with a future that writes to this oneshot channel
            let (mut tx, rx) = tokio::sync::oneshot::channel();
            let future = async move {
                select!(
                    _ = tx.closed() => {
                        // receiver already dropped, don't need to do anything
                    }
                    result = response.map_err(Into::<BoxError>::into) => {
                        // if this fails, the receiver already dropped, so we don't need to do anything
                        let _ = tx.send(result);
                    }
                )
            };
            // send the wrapped future to the background
            send_to_background_runtime(future);

            BackgroundResponseFuture::new(rx)
        }
    }

    // `BackgroundProcessor` response future
    pin_project! {
        #[derive(Debug)]
        pub struct BackgroundResponseFuture<S> {
            #[pin]
            rx: tokio::sync::oneshot::Receiver<Result<S, BoxError>>,
        }
    }

    impl<S> BackgroundResponseFuture<S> {
        pub(crate) fn new(rx: tokio::sync::oneshot::Receiver<Result<S, BoxError>>) -> Self {
            BackgroundResponseFuture { rx }
        }
    }

    impl<S> Future for BackgroundResponseFuture<S>
    where
        S: Send + 'static,
    {
        type Output = Result<S, BoxError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.project();

            // now poll on the receiver end of the oneshot to get the result
            match this.rx.poll(cx) {
                Poll::Ready(v) => match v {
                    Ok(v) => Poll::Ready(v),
                    Err(err) => Poll::Ready(Err(Box::new(err) as BoxError)),
                },
                Poll::Pending => Poll::Pending,
            }
        }
    }
}
