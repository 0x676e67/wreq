use criterion::async_executor::AsyncExecutor;

use super::ThreadMode;

const MULTI_THREAD_WORKERS: usize = 4;

pub(super) struct CompioBenchExecutor {
    runtime: compio::runtime::Runtime,
}

impl CompioBenchExecutor {
    pub(super) fn new() -> std::io::Result<Self> {
        Ok(Self {
            runtime: compio::runtime::Runtime::new()?,
        })
    }
}

impl AsyncExecutor for &CompioBenchExecutor {
    fn block_on<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        self.runtime.block_on(future)
    }
}

pub(super) fn tokio_runtime(mode: ThreadMode) -> std::io::Result<tokio::runtime::Runtime> {
    match mode {
        ThreadMode::Current => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
        ThreadMode::Multi => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(MULTI_THREAD_WORKERS)
            .enable_all()
            .build(),
    }
}
