//! Async runtime construction for benchmark clients and the local server.

use criterion::async_executor::AsyncExecutor;

use super::ThreadMode;

/// Worker threads used by every Tokio multi-thread runtime.
const MULTI_THREAD_WORKERS: usize = 4;

/// Owns the Compio runtime that drives one registered cyper benchmark case.
///
/// The executor is created outside the measured Criterion iterations.
pub(super) struct CompioBenchExecutor {
    runtime: compio::runtime::Runtime,
}

impl CompioBenchExecutor {
    /// Creates a Compio executor, returning any runtime initialization error.
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

/// Builds a Tokio runtime for the selected threading model.
///
/// Returns any runtime initialization error to the benchmark runner.
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
