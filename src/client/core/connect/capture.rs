use std::{ops::Deref, sync::Arc};

use http::Request;
use tokio::sync::watch;

use super::Connected;

/// [`CaptureConnection`] allows callers to capture [`Connected`] information
#[derive(Debug, Clone)]
pub struct CaptureConnection {
    rx: watch::Receiver<Option<Connected>>,
}

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

impl CaptureConnection {
    /// Capture the connection for a given request
    ///
    /// [`CaptureConnection::new`] allows a caller to capture the returned [`Connected`] structure
    /// as soon as the connection is established.
    pub(crate) fn new<B>(request: &mut Request<B>) -> CaptureConnection {
        let (tx, rx) = watch::channel(None);
        request
            .extensions_mut()
            .insert(CaptureConnectionExtension { tx: Arc::new(tx) });
        CaptureConnection { rx }
    }

    /// Retrieve the connection metadata, if available
    pub fn connection_metadata(&self) -> impl Deref<Target = Option<Connected>> + '_ {
        self.rx.borrow()
    }
}
