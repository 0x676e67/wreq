use std::io::Write;

use boring2::ssl::CertificateCompressor;

pub struct ZstdCertificateCompressor {
    level: i32,
}

impl Default for ZstdCertificateCompressor {
    fn default() -> Self {
        Self { level: 3 }
    }
}

impl CertificateCompressor for ZstdCertificateCompressor {
    const ALGORITHM: boring2::ssl::CertificateCompressionAlgorithm =
        boring2::ssl::CertificateCompressionAlgorithm::ZSTD;

    const CAN_COMPRESS: bool = true;

    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut writer = zstd::stream::Encoder::new(output, self.level)?;
        writer.write_all(input)?;
        writer.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut reader = zstd::stream::Decoder::new(input)?;
        std::io::copy(&mut reader, output)?;
        Ok(())
    }
}
