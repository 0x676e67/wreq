use std::io::{self, Result, Write};

use boring2::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZlibCertificateCompressor;

impl CertificateCompressor for ZlibCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut encoder = ZlibEncoder::new(output, Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut decoder = ZlibDecoder::new(input);
        io::copy(&mut decoder, output)?;
        Ok(())
    }
}
