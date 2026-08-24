use std::{future::Future, sync::Arc};

use anyhow::{Context as _, Result};
use tokio::{runtime::Runtime, task::JoinHandle};

/// Owns the process-wide Tokio reactor used by HTTP and AI work.
///
/// GPUI has its own executor. Futures that require Tokio's I/O or timer driver
/// must be spawned through this bridge and their result explicitly returned to
/// a GPUI entity. The SSH subsystem intentionally keeps its existing runtime.
pub struct TokioBridge {
    runtime: Runtime,
}

impl TokioBridge {
    pub fn new() -> Result<Arc<Self>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .thread_name("lovelyres-http")
            .enable_all()
            .build()
            .context("failed to create the LovelyRes Tokio runtime")?;
        Ok(Arc::new(Self { runtime }))
    }

    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.runtime.spawn(future)
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_drives_tokio_timers() {
        let bridge = TokioBridge::new().unwrap();
        let task = bridge.spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            42
        });
        assert_eq!(bridge.runtime.block_on(task).unwrap(), 42);
    }
}
