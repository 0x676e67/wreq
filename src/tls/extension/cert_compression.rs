use boring_sys as ffi;
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

extern "C" fn brotli_compressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut uncompressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut compressed: Vec<u8> = Vec::new();

    let params = brotli_crate::enc::encode::BrotliEncoderInitParams();

    if let Err(e) = brotli_crate::BrotliCompress(&mut uncompressed, &mut compressed, &params) {
        log::debug!("brotli compression error: {:?}", e);
        return 0;
    }

    unsafe { boring_sys::CBB_add_bytes(buffer, compressed.as_ptr(), compressed.len()) }
}

extern "C" fn zlib_compressor(
    _ssl: *mut ffi::SSL,
    out: *mut ffi::CBB,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut uncompressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut compressed: Vec<u8> = Vec::new();

    let params = flate2::Compression::default();

    let mut encoder = flate2::bufread::ZlibEncoder::new(&mut uncompressed, params);
    if let Err(e) = encoder.read_to_end(&mut compressed) {
        log::debug!("zlib compression error: {:?}", e);
        return 0;
    }

    unsafe { boring_sys::CBB_add_bytes(out, compressed.as_ptr(), compressed.len()) }
}

extern "C" fn brotli_decompressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut compressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut uncompressed: Vec<u8> = Vec::with_capacity(uncompressed_len);

    if let Err(e) = brotli_crate::BrotliDecompress(&mut compressed, &mut uncompressed) {
        log::debug!("brotli decompression error: {:?}", e);
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    unsafe {
        *buffer = ffi::CRYPTO_BUFFER_new(
            uncompressed.as_ptr(),
            uncompressed_len,
            std::ptr::null_mut(),
        )
    }

    1
}

extern "C" fn zlib_decompressor(
    _ssl: *mut ffi::SSL,
    buffer: *mut *mut ffi::CRYPTO_BUFFER,
    uncompressed_len: usize,
    in_: *const u8,
    in_len: usize,
) -> ::std::os::raw::c_int {
    let mut compressed = unsafe { slice::from_raw_parts(in_, in_len) };
    let mut uncompressed: Vec<u8> = Vec::with_capacity(uncompressed_len);

    let mut decoder = flate2::bufread::ZlibDecoder::new(&mut compressed);
    if let Err(e) = decoder.read_to_end(&mut uncompressed) {
        log::debug!("zlib decompression error: {:?}", e);
        return 0;
    }

    if uncompressed.len() != uncompressed_len {
        return 0;
    }

    unsafe {
        *buffer = ffi::CRYPTO_BUFFER_new(
            uncompressed.as_ptr(),
            uncompressed_len,
            std::ptr::null_mut(),
        )
    }

    1
}
