//! TLS certificate compression [RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879).
//!
//! Reduces handshake latency by compressing certificate chains.
//! Supports Zlib, Brotli, and Zstd algorithms to minimize bytes-on-wire
//! and fit within the initial congestion window.

use std::{
    fmt::Debug,
    hash::{Hash, Hasher},
    io,
    sync::Arc,
};

use btls::{
    error::ErrorStack,
    ssl::{self, SslContextBuilder},
};
use btls_sys as ffi;
// Re-export the `CertificateCompressionAlgorithm` enum for users of this module.
pub use ssl::CertificateCompressionAlgorithm;

/// Certificate compression or decompression.
///
/// Wraps a function pointer or closure that processes certificate data.
#[allow(clippy::type_complexity)]
pub enum Codec {
    /// Function pointer.
    Pointer(fn(&[u8], &mut dyn io::Write) -> io::Result<()>),
    /// Closure or function object.
    Dynamic(Box<dyn Fn(&[u8], &mut dyn io::Write) -> io::Result<()> + Send + Sync>),
}

/// Trait for TLS certificate compression implementations.
///
/// Provides methods for compressing and decompressing certificate data,
/// as well as identifying the algorithm in use.
///
/// `algorithm()` must return a consistent value for the lifetime of the compressor, and
/// both codecs must implement it. Implementations reporting the same algorithm are treated
/// as interchangeable for connection pooling, session resumption, and context caching.
///
/// See [RFC 8879, §3](https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms)
/// for the list of IANA-assigned compression algorithm identifiers.
pub trait CertificateCompressor: Debug + Sync + Send + 'static {
    /// Returns the [`Codec`] used to compress certificate chains for this algorithm.
    fn compress(&self) -> Codec;

    /// Returns the [`Codec`] used to decompress certificate chains for this algorithm.
    fn decompress(&self) -> Codec;

    /// Returns the IANA-assigned identifier read when configuring this compressor.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

/// Configured certificate compressors in offer order, compared and hashed by algorithm.
///
/// Empty lists collapse to `None` so an empty list and an unset option share the same cache
/// and pool identity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Compressors(Option<Arc<[ConfiguredCompressor]>>);

/// Single compressor entry paired with the algorithm snapshot read at configuration time.
///
/// Equality and hashing inspect only `algorithm` so comparing options never re-invokes
/// [`CertificateCompressor::algorithm`].
#[derive(Debug)]
struct ConfiguredCompressor {
    algorithm: CertificateCompressionAlgorithm,
    compressor: &'static dyn CertificateCompressor,
}

/// BoringSSL [`ssl::CertificateCompressor`] adapter specialized by IANA algorithm constant.
///
/// Bridges a dynamic [`Codec`] pair to `btls`'s const-generic compressor registration API.
struct Compressor<const ALGORITHM: i32> {
    compress: Codec,
    decompress: Codec,
}

// ===== impl Codec =====

impl Codec {
    #[inline]
    fn call(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        match self {
            Codec::Pointer(func) => func(input, output),
            Codec::Dynamic(closure) => closure(input, output),
        }
    }
}

// ===== impl Compressors =====

impl Compressors {
    pub(crate) fn new(compressors: &[&'static dyn CertificateCompressor]) -> Self {
        Self((!compressors.is_empty()).then(|| {
            compressors
                .iter()
                .map(|&compressor| ConfiguredCompressor {
                    algorithm: compressor.algorithm(),
                    compressor,
                })
                .collect()
        }))
    }

    pub(crate) fn register(&self, builder: &mut SslContextBuilder) -> Result<(), ErrorStack> {
        for compressor in self.0.as_deref().unwrap_or_default() {
            compressor.register(builder)?;
        }
        Ok(())
    }
}

// ===== impl ConfiguredCompressor =====

impl PartialEq for ConfiguredCompressor {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
    }
}

impl Eq for ConfiguredCompressor {}

impl Hash for ConfiguredCompressor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
    }
}

impl ConfiguredCompressor {
    fn register(&self, builder: &mut SslContextBuilder) -> Result<(), ErrorStack> {
        let compressor = self.compressor;
        match self.algorithm {
            CertificateCompressionAlgorithm::ZLIB => {
                builder.add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_zlib },
                > {
                    compress: compressor.compress(),
                    decompress: compressor.decompress(),
                })
            }
            CertificateCompressionAlgorithm::BROTLI => builder
                .add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_brotli },
                > {
                    compress: compressor.compress(),
                    decompress: compressor.decompress(),
                }),
            CertificateCompressionAlgorithm::ZSTD => {
                builder.add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_zstd },
                > {
                    compress: compressor.compress(),
                    decompress: compressor.decompress(),
                })
            }
            _ => unreachable!(),
        }
    }
}

// ===== impl Compressor =====

impl<const ALGORITHM: i32> ssl::CertificateCompressor for Compressor<ALGORITHM> {
    const ALGORITHM: CertificateCompressionAlgorithm = match ALGORITHM {
        ffi::TLSEXT_cert_compression_zlib => CertificateCompressionAlgorithm::ZLIB,
        ffi::TLSEXT_cert_compression_brotli => CertificateCompressionAlgorithm::BROTLI,
        ffi::TLSEXT_cert_compression_zstd => CertificateCompressionAlgorithm::ZSTD,
        _ => unreachable!(),
    };
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    #[inline]
    fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        self.compress.call(input, output)
    }

    #[inline]
    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        self.decompress.call(input, output)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{cell::Cell, hash::BuildHasher};

    use super::*;

    pub(crate) fn compare_options<T: Debug + Eq + Hash>(
        default: T,
        with: impl Fn(Vec<&'static dyn CertificateCompressor>) -> T,
    ) {
        std::thread_local! {
            static ALGORITHM_CALLS: Cell<usize> = const { Cell::new(0) };
        }

        #[derive(Debug)]
        struct TestCompressor(CertificateCompressionAlgorithm);

        impl CertificateCompressor for TestCompressor {
            fn algorithm(&self) -> CertificateCompressionAlgorithm {
                ALGORITHM_CALLS.with(|calls| calls.set(calls.get() + 1));
                self.0
            }

            fn compress(&self) -> Codec {
                Codec::Pointer(|_, _| Err(io::ErrorKind::Unsupported.into()))
            }

            fn decompress(&self) -> Codec {
                self.compress()
            }
        }

        static ZLIB: TestCompressor = TestCompressor(CertificateCompressionAlgorithm::ZLIB);
        static OTHER_ZLIB: TestCompressor = TestCompressor(CertificateCompressionAlgorithm::ZLIB);
        static BROTLI: TestCompressor = TestCompressor(CertificateCompressionAlgorithm::BROTLI);

        let hasher = std::hash::RandomState::new();
        let empty = with(Vec::new());
        let first = with(vec![&ZLIB, &BROTLI]);
        let same = with(vec![&OTHER_ZLIB, &BROTLI]);
        let reversed = with(vec![&BROTLI, &ZLIB]);
        let before = ALGORITHM_CALLS.with(Cell::get);
        assert_eq!(default, empty);
        assert_eq!(hasher.hash_one(&default), hasher.hash_one(&empty));
        assert_eq!(first, same);
        assert_eq!(hasher.hash_one(&first), hasher.hash_one(&same));
        assert_ne!(first, reversed);
        assert_eq!(ALGORITHM_CALLS.with(Cell::get), before);
    }

    #[test]
    fn options_compare_compressors_by_algorithm_in_order() {
        use crate::tls::TlsOptions;
        compare_options(TlsOptions::default(), |compressors| {
            TlsOptions::builder()
                .certificate_compressors(compressors)
                .build()
        });
    }
}
