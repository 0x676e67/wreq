use std::io::Write;

use flate2::Compression;

pub struct ZlibCertificateCompressor {
    level: u32,
}

impl Default for ZlibCertificateCompressor {
    fn default() -> Self {
        Self { level: 6 }
    }
}

impl boring2::ssl::CertificateCompressor for ZlibCertificateCompressor {
    const ALGORITHM: boring2::ssl::CertificateCompressionAlgorithm =
        boring2::ssl::CertificateCompressionAlgorithm::ZLIB;

    const CAN_COMPRESS: bool = true;

    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut encoder = flate2::write::ZlibEncoder::new(output, Compression::new(self.level));
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}
