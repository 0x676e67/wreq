pub mod bench;
pub mod client;
pub mod server;

use std::fmt;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[allow(unused)]
#[derive(Clone, Copy, Debug)]
pub enum HttpVersion {
    Http1,
    Http2,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            HttpVersion::Http1 => "h1",
            HttpVersion::Http2 => "h2",
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

pub fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to build current-thread runtime")
}

pub fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("Failed to build multi-thread runtime")
}
