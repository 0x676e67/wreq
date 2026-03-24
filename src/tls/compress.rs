//! TLS certificate compression [RFC 8879](https://datatracker.ietf.org/doc/html/rfc8879).
//!
//! Reduces handshake latency by compressing certificate chains.
//! Supports Zlib, Brotli, and Zstd algorithms to minimize bytes-on-wire
//! and fit within the initial congestion window.

use std::{fmt::Debug, io};

use btls::ssl;
// Re-export the `CertificateCompressionAlgorithm` enum for users of this module.
pub use ssl::CertificateCompressionAlgorithm;

/// Trait for TLS certificate compression implementations.
///
/// Provides methods for compressing and decompressing certificate data,
/// as well as identifying the algorithm in use.
pub trait CertificateCompressor: Debug + Send + Sync + 'static {
    /// Perform compression of `input` buffer and write compressed data to `output`.
    fn compress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()>;

    /// Perform decompression of `input` buffer and write compressed data to `output`.
    fn decompress(&self, input: &[u8], output: &mut dyn io::Write) -> io::Result<()>;

    /// An IANA assigned identifier of compression algorithm
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
