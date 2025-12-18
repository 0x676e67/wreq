use std::{future::Future, pin::Pin, sync::Arc};

use crate::client::core::rt::Executor;

pub(crate) type BoxSendFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

// Either the user provides an executor for background tasks, or we use `tokio::spawn`.
#[derive(Clone)]
pub struct Exec(Arc<dyn Executor<BoxSendFuture> + Send + Sync>);

// ===== impl Exec =====

impl Exec {
    pub(crate) fn new<E>(inner: E) -> Self
    where
        E: Executor<BoxSendFuture> + Send + Sync + 'static,
    {
        Exec(Arc::new(inner))
    }
}

impl<F> Executor<F> for Exec
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        self.0.execute(Box::pin(fut));
    }
}
