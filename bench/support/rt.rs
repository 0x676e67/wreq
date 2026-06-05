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
