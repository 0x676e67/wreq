pub mod bench;
pub mod client;
pub mod server;

use std::fmt;

#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub enum HttpMode {
    Http1,
    Http2,
}

impl fmt::Display for HttpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            HttpMode::Http1 => "http1",
            HttpMode::Http2 => "http2",
        };
        f.write_str(value)
    }
}

#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub enum Tls {
    Enabled,
    Disabled,
}

impl fmt::Display for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Tls::Enabled => "https",
            Tls::Disabled => "http",
        };
        f.write_str(value)
    }
}

pub fn build_current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build current-thread runtime")
}

pub fn build_multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to build multi-thread runtime")
}
