//! Middleware for decoding

mod layer;

pub use layer::{Decompression, DecompressionLayer};

#[derive(Clone, Debug)]
pub(crate) struct AcceptEncoding {
    #[cfg(feature = "gzip")]
    pub(super) gzip: bool,
    #[cfg(feature = "brotli")]
    pub(super) brotli: bool,
    #[cfg(feature = "zstd")]
    pub(super) zstd: bool,
    #[cfg(feature = "deflate")]
    pub(super) deflate: bool,
}

impl AcceptEncoding {
    #[inline(always)]
    #[cfg(feature = "gzip")]
    pub fn gzip(&mut self, enabled: bool) {
        self.gzip = enabled;
    }

    #[inline(always)]
    #[cfg(feature = "brotli")]
    pub fn brotli(&mut self, enabled: bool) {
        self.brotli = enabled;
    }

    #[inline(always)]
    #[cfg(feature = "zstd")]
    pub fn zstd(&mut self, enabled: bool) {
        self.zstd = enabled;
    }

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
