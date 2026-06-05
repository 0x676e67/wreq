use criterion::async_executor::AsyncExecutor;

pub struct CompioBenchExecutor {
    runtime: compio::runtime::Runtime,
}

impl CompioBenchExecutor {
    pub fn new() -> std::io::Result<Self> {
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
