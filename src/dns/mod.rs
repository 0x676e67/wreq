//! DNS resolution

pub(crate) mod gai;
#[cfg(feature = "hickory-dns")]
pub(crate) mod hickory;
pub(crate) mod resolve;

pub use resolve::{Addrs, IntoResolve, Name, Resolve, Resolving};

pub(crate) use self::{
    gai::{GaiResolver, SocketAddrs},
    resolve::{DnsResolverWithOverrides, DynResolver},
    sealed::{InternalResolve, resolve},
};

mod sealed {
    use std::{
        future::Future,
        net::SocketAddr,
        task::{self, Poll},
    };

    use tower::Service;

    use super::Name;
    use crate::error::BoxError;

    /// Internal adapter trait for DNS resolvers.
    ///
    /// This trait provides a unified interface for different resolver implementations,
    /// allowing both custom [`super::Resolve`] types and Tower [`Service`] implementations
    /// to be used interchangeably within the connector.
    pub trait InternalResolve {
        type Addrs: Iterator<Item = SocketAddr>;
        type Error: Into<BoxError>;
        type Future: Future<Output = Result<Self::Addrs, Self::Error>>;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>>;
        fn resolve(&mut self, name: Name) -> Self::Future;
    }

    /// Automatic implementation for any Tower [`Service`] that resolves names to socket addresses.
    impl<S> InternalResolve for S
    where
        S: Service<Name>,
        S::Response: Iterator<Item = SocketAddr>,
        S::Error: Into<BoxError>,
    {
        type Addrs = S::Response;
        type Error = S::Error;
        type Future = S::Future;

        fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
            Service::poll_ready(self, cx)
        }

        fn resolve(&mut self, name: Name) -> Self::Future {
            Service::call(self, name)
        }
    }

    pub async fn resolve<R>(resolver: &mut R, name: Name) -> Result<R::Addrs, R::Error>
    where
        R: InternalResolve,
    {
        std::future::poll_fn(|cx| resolver.poll_ready(cx)).await?;
        resolver.resolve(name).await
    }
}
