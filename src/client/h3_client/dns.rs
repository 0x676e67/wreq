use std::net::SocketAddr;

use tower::Service;

use crate::dns::{DynResolver, Name};

pub(super) async fn resolve(
    resolver: &mut DynResolver,
    name: Name,
) -> Result<impl Iterator<Item = SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    std::future::poll_fn(|cx| Service::<Name>::poll_ready(resolver, cx)).await?;
    Service::<Name>::call(resolver, name).await
}

pub(super) fn name_from_str(host: &str) -> Name {
    Name::new(host.into())
}
