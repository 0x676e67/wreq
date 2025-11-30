//! Middleware for tracking compressed/wire body size.

mod body;
mod layer;

pub use body::CountingBody;
pub use layer::{WireSize, WireSizeLayer};

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Tracks the compressed (wire) size of a response body.
///
/// This type is available as a response extension when wire size tracking is enabled.
/// The size is accumulated as the body is read, so the final value is only available
/// after the entire body has been consumed.
///
/// # Example
///
/// ```
/// # async fn run() -> wreq::Result<()> {
/// use wreq::CompressedSize;
///
/// let resp = wreq::get("https://httpbin.org/gzip").send().await?;
/// let compressed_size = resp.compressed_size();
///
/// // Read the body
/// let body = resp.bytes().await?;
///
/// // Now the compressed size reflects all bytes read
/// println!("Decompressed size: {} bytes", body.len());
/// println!("Compressed size: {} bytes", compressed_size.get());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct CompressedSize {
    inner: Arc<AtomicU64>,
}

impl CompressedSize {
    /// Creates a new `CompressedSize` counter initialized to zero.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the current accumulated size in bytes.
    ///
    /// This value increases as the response body is read. The final value
    /// represents the total compressed size only after the body is fully consumed.
    #[inline]
    pub fn get(&self) -> u64 {
        self.inner.load(Ordering::Relaxed)
    }

    /// Adds bytes to the counter.
    #[inline]
    pub(crate) fn add(&self, bytes: u64) {
        self.inner.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Default for CompressedSize {
    fn default() -> Self {
        Self::new()
    }
}
