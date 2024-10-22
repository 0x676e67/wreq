use boring_sys as ffi;
use brotli_crate::enc::encode::BrotliEncoderInitParams;
use libc::c_int;
use std::{io::Read, slice};

/// A certificate compression algorithm.
#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CertCompressionAlgorithm {
    Brotli = ffi::TLSEXT_cert_compression_brotli as _,
    Zlib = ffi::TLSEXT_cert_compression_zlib as _,
}

impl CertCompressionAlgorithm {
    pub fn compression_fn(&self) -> ffi::ssl_cert_compression_func_t {
        match &self {
            Self::Brotli => Some(brotli_compressor),
            Self::Zlib => Some(zlib_compressor),
        }
    }

    pub fn decompression_fn(&self) -> ffi::ssl_cert_decompression_func_t {
        match &self {
            Self::Brotli => Some(brotli_decompressor),
            Self::Zlib => Some(zlib_decompressor),
        }
    }
}

unsafe extern "C" fn brotli_compressor(
    _ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    let mut uncompressed = slice::from_raw_parts(in_, in_len);
    let mut compressed: Vec<u8> = Vec::new();

    let params = BrotliEncoderInitParams();

    if let Err(_) = brotli_crate::BrotliCompress(&mut uncompressed, &mut compressed, &params) {
        return 0;
    }

    boring_sys::CBB_add_bytes(out, compressed.as_ptr(), compressed.len())
}

unsafe extern "C" fn zlib_compressor(
    _ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    let mut uncompressed = slice::from_raw_parts(in_, in_len);
    let mut compressed: Vec<u8> = Vec::new();

    let params = flate2::Compression::default();

    let mut encoder = flate2::bufread::ZlibEncoder::new(&mut uncompressed, params);
    if let Err(_) = encoder.read_to_end(&mut compressed) {
        return 0;
    }

    boring_sys::CBB_add_bytes(out, compressed.as_ptr(), compressed.len())
}

unsafe extern "C" fn brotli_decompressor(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    let mut compressed = slice::from_raw_parts(in_, in_len);
    let mut uncompressed: Vec<u8> = Vec::with_capacity(uncompressed_len);

    if let Err(_) = brotli_crate::BrotliDecompress(&mut compressed, &mut uncompressed) {
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    let buffer = ffi::CRYPTO_BUFFER_new(
        uncompressed.as_ptr(),
        uncompressed_len,
        std::ptr::null_mut(),
    );

    *out = buffer;

    1
}

unsafe extern "C" fn zlib_decompressor(
    _ssl: *mut ffi::SSL,
    out: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> c_int {
    let mut compressed = slice::from_raw_parts(in_, in_len);
    let mut uncompressed: Vec<u8> = Vec::with_capacity(uncompressed_len);

    let mut decoder = flate2::bufread::ZlibDecoder::new(&mut compressed);
    if let Err(_) = decoder.read_to_end(&mut uncompressed) {
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    let buffer = ffi::CRYPTO_BUFFER_new(
        uncompressed.as_ptr(),
        uncompressed_len,
        std::ptr::null_mut(),
    );

    *out = buffer;

    1
}
