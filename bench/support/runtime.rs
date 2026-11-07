//! Async runtime construction for benchmark clients and the local server.

use super::ThreadMode;

/// Worker threads used by every Tokio multi-thread runtime.
const MULTI_THREAD_WORKERS: usize = 4;

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
