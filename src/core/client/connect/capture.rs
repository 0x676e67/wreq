use std::sync::Arc;

use tokio::sync::watch;

use super::Connected;

/// TxSide for [`CaptureConnection`]
///
/// This is inserted into `Extensions` to allow Hyper to back channel connection info
#[derive(Clone)]
pub(crate) struct CaptureConnectionExtension {
    tx: Arc<watch::Sender<Option<Connected>>>,
}

impl CaptureConnectionExtension {
    pub(crate) fn set(&self, connected: &Connected) {
        self.tx.send_replace(Some(connected.clone()));
    }
}
