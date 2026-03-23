//! TLS certificate compression support.

use std::{fmt::Debug, io};

use btls::ssl::{self, CertificateCompressionAlgorithm};

/// Trait for TLS certificate compression implementations.
///
/// Provides methods for compressing and decompressing certificate data,
/// as well as identifying the algorithm in use.
pub trait CertificateCompressor: Debug + Send + Sync + 'static {
    /// Compresses the input buffer and writes the result to `output`.
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()>;

    /// Decompresses the input buffer and writes the result to `output`.
    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()>;

    /// Returns the IANA identifier for the compression algorithm.
    fn algorithm(&self) -> CertificateCompressionAlgorithm;
}

impl ssl::CertificateCompressor for &'static dyn CertificateCompressor {
    #[inline]
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        (*self).compress(input, output)
    }

    #[inline]
    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()> {
        (*self).decompress(input, output)
    }

    #[inline]
    fn algorithm(&self) -> CertificateCompressionAlgorithm {
        (*self).algorithm()
    }
}
