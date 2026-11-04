//! Network connection types and utilities.

pub(super) mod tcp;

if_any_rt!(
    mod io;
    #[cfg(unix)]
    mod uds;
);

if_all_rt! {
    pub use tcp::tokio::TcpConnector;
    #[cfg(unix)]
    pub use uds::tokio::UnixConnector;
}

if_tokio_rt! {
    pub use tcp::tokio::TcpConnector;
    #[cfg(unix)]
    pub use uds::tokio::UnixConnector;
}

if_compio_rt! {
    pub use tcp::compio::TcpConnector;
    #[cfg(unix)]
    pub use uds::compio::UnixConnector;
}
