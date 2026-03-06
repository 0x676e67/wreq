//! TLS certificate compression support.

use std::{
    hash::{Hash, Hasher},
    io,
};

use btls::{
    error::ErrorStack,
    ssl::{self, CertificateCompressionAlgorithm},
};
use btls_sys as ffi;

type CompressFn = fn(&[u8], &mut dyn io::Write) -> io::Result<()>;
type DecompressFn = fn(&[u8], &mut dyn io::Write) -> io::Result<()>;

/// IANA assigned identifier of compression algorithm. See https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms
#[derive(Debug, Clone, Copy)]
pub struct CertificateCompressor {
    alg: CertificateCompressionAlgorithm,
    compress: CompressFn,
    decompress: DecompressFn,
}

#[derive(Debug, Clone, Copy)]
struct Compressor<const ALGORITHM: i32> {
    compress: CompressFn,
    decompress: DecompressFn,
}

// ===== impl CertificateCompressor =====

impl CertificateCompressor {
    /// Create a new [`CertificateCompressor`] for the given algorithm.
    #[inline]
    pub const fn new(
        algorithm: CertificateCompressionAlgorithm,
        compress: CompressFn,
        decompress: DecompressFn,
    ) -> Self {
        Self {
            alg: algorithm,
            compress,
            decompress,
        }
    }

    pub(crate) fn add_to_tls(
        self,
        builder: &mut btls::ssl::SslConnectorBuilder,
    ) -> Result<(), ErrorStack> {
        match self.alg {
            CertificateCompressionAlgorithm::BROTLI => builder
                .add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_brotli },
                > {
                    compress: self.compress,
                    decompress: self.decompress,
                }),
            CertificateCompressionAlgorithm::ZLIB => {
                builder.add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_zlib },
                > {
                    compress: self.compress,
                    decompress: self.decompress,
                })
            }
            CertificateCompressionAlgorithm::ZSTD => {
                builder.add_certificate_compression_algorithm(Compressor::<
                    { ffi::TLSEXT_cert_compression_zstd },
                > {
                    compress: self.compress,
                    decompress: self.decompress,
                })
            }
            _ => unreachable!(),
        }?;
        Ok(())
    }
}

impl Hash for CertificateCompressor {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.alg.hash(state);
    }
}

impl PartialEq for CertificateCompressor {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg
    }
}

impl Eq for CertificateCompressor {}

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
        (self.compress)(input, output)
    }

    #[inline]
    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        (self.decompress)(input, output)
    }
}

impl<const ALGORITHM: i32> Hash for Compressor<ALGORITHM> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        ALGORITHM.hash(state);
    }
}

impl<const ALGORITHM: i32> PartialEq for Compressor<ALGORITHM> {
    #[inline]
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl<const ALGORITHM: i32> Eq for Compressor<ALGORITHM> {}
