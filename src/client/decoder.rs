#[derive(Clone, Debug)]
pub(crate) struct Accepts {
    #[cfg(feature = "gzip")]
    pub(super) gzip: bool,
    #[cfg(feature = "brotli")]
    pub(super) brotli: bool,
    #[cfg(feature = "zstd")]
    pub(super) zstd: bool,
    #[cfg(feature = "deflate")]
    pub(super) deflate: bool,
}

// ===== impl Accepts ====o

impl Accepts {
    #[cfg(feature = "gzip")]
    #[inline(always)]
    pub fn gzip(&mut self, enabled: bool) {
        self.gzip = enabled;
    }

    #[cfg(feature = "brotli")]
    #[inline(always)]
    pub fn brotli(&mut self, enabled: bool) {
        self.brotli = enabled;
    }

    #[cfg(feature = "zstd")]
    #[inline(always)]
    pub fn zstd(&mut self, enabled: bool) {
        self.zstd = enabled;
    }

    #[cfg(feature = "deflate")]
    #[inline(always)]
    pub fn deflate(&mut self, enabled: bool) {
        self.deflate = enabled;
    }
}

#[allow(clippy::all)]
impl Default for Accepts {
    fn default() -> Accepts {
        Accepts {
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
