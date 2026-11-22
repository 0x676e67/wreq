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
/// The algorithm must remain stable for the object's lifetime, and both codecs
/// must implement it. Implementations reporting the same algorithm are treated
/// as interchangeable for connection, TLS session and compiled context identity.
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

/// Compressors in offer order. Their recorded algorithms are the cache identity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Compressors(Option<Arc<[ConfiguredCompressor]>>);

#[derive(Debug)]
struct ConfiguredCompressor {
    algorithm: CertificateCompressionAlgorithm,
    compressor: &'static dyn CertificateCompressor,
}

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

    pub(super) fn register(&self, builder: &mut SslContextBuilder) -> Result<(), ErrorStack> {
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
mod tests {
    use std::{
        hash::BuildHasher,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[test]
    fn options_compare_compressors_by_algorithm_in_order() {
        #[derive(Debug)]
        struct TestCompressor(CertificateCompressionAlgorithm, AtomicUsize);

        impl CertificateCompressor for TestCompressor {
            fn algorithm(&self) -> CertificateCompressionAlgorithm {
                self.1.fetch_add(1, Ordering::Relaxed);
                self.0
            }

            fn compress(&self) -> Codec {
                Codec::Pointer(|_, _| Err(io::ErrorKind::Unsupported.into()))
            }

            fn decompress(&self) -> Codec {
                self.compress()
            }
        }

        fn check<T: Debug + Eq + Hash>(
            default: T,
            with: impl Fn(Vec<&'static dyn CertificateCompressor>) -> T,
        ) {
            static ZLIB: TestCompressor =
                TestCompressor(CertificateCompressionAlgorithm::ZLIB, AtomicUsize::new(0));
            static OTHER_ZLIB: TestCompressor =
                TestCompressor(CertificateCompressionAlgorithm::ZLIB, AtomicUsize::new(0));
            static BROTLI: TestCompressor =
                TestCompressor(CertificateCompressionAlgorithm::BROTLI, AtomicUsize::new(0));

            let hasher = std::hash::RandomState::new();
            let empty = with(Vec::new());
            let first = with(vec![&ZLIB, &BROTLI]);
            let same = with(vec![&OTHER_ZLIB, &BROTLI]);
            let reversed = with(vec![&BROTLI, &ZLIB]);
            let algorithm_calls = || {
                [&ZLIB, &OTHER_ZLIB, &BROTLI].map(|compressor| compressor.1.load(Ordering::Relaxed))
            };
            let before = algorithm_calls();
            assert_eq!(default, empty);
            assert_eq!(hasher.hash_one(&default), hasher.hash_one(&empty));
            assert_eq!(first, same);
            assert_eq!(hasher.hash_one(&first), hasher.hash_one(&same));
            assert_ne!(first, reversed);
            assert_eq!(algorithm_calls(), before);
        }

        use crate::tls::TlsOptions;
        check(TlsOptions::default(), |compressors| {
            TlsOptions::builder()
                .certificate_compressors(compressors)
                .build()
        });

        #[cfg(feature = "http3")]
        {
            use crate::quic::QuicOptions;
            check(QuicOptions::default(), |compressors| {
                QuicOptions::builder()
                    .certificate_compressors(compressors)
                    .build()
            });
        }
    }
}
