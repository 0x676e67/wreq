//! Middleware for decoding

mod layer;

pub use layer::{Decompression, DecompressionLayer};

/// Configuration for supported content-encoding algorithms.
///
/// `AcceptEncoding` controls which compression formats are enabled for decoding
/// response bodies. Each field corresponds to a specific algorithm and is only
/// available if the corresponding feature is enabled.
#[derive(Clone, Debug)]
pub(crate) struct AcceptEncoding {
    #[cfg(feature = "gzip")]
    gzip: bool,

    #[cfg(feature = "brotli")]
    brotli: bool,

    #[cfg(feature = "zstd")]
    zstd: bool,

    #[cfg(feature = "deflate")]
    deflate: bool,
}

impl AcceptEncoding {
    /// Enable or disable gzip decoding.
    #[inline(always)]
    #[cfg(feature = "gzip")]
    pub fn gzip(&mut self, enabled: bool) {
        self.gzip = enabled;
    }

    /// Enable or disable brotli decoding.
    #[inline(always)]
    #[cfg(feature = "brotli")]
    pub fn brotli(&mut self, enabled: bool) {
        self.brotli = enabled;
    }

    /// Enable or disable zstd decoding.
    #[inline(always)]
    #[cfg(feature = "zstd")]
    pub fn zstd(&mut self, enabled: bool) {
        self.zstd = enabled;
    }

    /// Enable or disable deflate decoding.
    #[inline(always)]
    #[cfg(feature = "deflate")]
    pub fn deflate(&mut self, enabled: bool) {
        self.deflate = enabled;
    }
}

impl Default for AcceptEncoding {
    fn default() -> AcceptEncoding {
        AcceptEncoding {
            #[cfg(feature = "gzip")]
            gzip: true,
            #[cfg(feature = "brotli")]
            brotli: true,
            #[cfg(feature = "zstd")]
            zstd: true,
            #[cfg(feature = "deflate")]
            deflate: true,
        }
    }
}
