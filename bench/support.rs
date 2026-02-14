pub mod client;
pub mod server;

#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub enum HttpMode {
    Http1,
    Http2,
}

pub fn build_current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

pub fn build_multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}
