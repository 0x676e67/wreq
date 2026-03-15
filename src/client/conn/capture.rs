use std::{ops::Deref, sync::Arc};

use http::Request;
use tokio::sync::watch;

use super::Connected;

/// [`CaptureConnection`] allows callers to capture [`Connected`] information
#[derive(Debug, Clone)]
pub struct CaptureConnection(watch::Receiver<Option<Connected>>);

/// TxSide for [`CaptureConnection`]
///
/// This is inserted into `Extensions` to allow Hyper to back channel connection info
#[derive(Clone)]
pub(crate) struct CaptureConnectionExtension(Arc<watch::Sender<Option<Connected>>>);

impl CaptureConnectionExtension {
    /// Set the connection info
    #[inline]
    pub(crate) fn set(&self, connected: &Connected) {
        self.0.send_replace(Some(connected.clone()));
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
            .insert(CaptureConnectionExtension(Arc::new(tx)));
        CaptureConnection(rx)
    }

    /// Retrieve the connection metadata, if available
    #[inline]
    pub fn connection_metadata(&self) -> impl Deref<Target = Option<Connected>> + '_ {
        self.0.borrow()
    }
}
