//! Shared TLS context configuration for both H1/H2 and H3/QUIC paths.

use btls::ssl::{SslContextBuilder, SslOptions};

#[cfg(feature = "http3")]
use crate::http3::Http3Options;
use crate::tls::TlsOptions;
use crate::Error;

/// Apply fingerprint-relevant TLS options to an [`SslContextBuilder`].
///
/// Both the H1/H2 path ([`super::conn::TlsConnectorBuilder`]) and the
/// H3/QUIC path ([`crate::client::h3_client::connect::H3Connector`]) call
/// this function so that cipher suites, extensions, and other ClientHello
/// signals are configured consistently.
///
/// When `h3` is `Some`, QUIC-specific overrides (e.g. `quic_curves_list`)
/// take priority over the corresponding [`TlsOptions`] values, and options
/// that are irrelevant for QUIC/TLS 1.3 (session tickets, renegotiation,
/// PSK DHE KE) are skipped.
pub(crate) fn apply_tls_context_options(
    builder: &mut SslContextBuilder,
    tls: &TlsOptions,
    #[cfg(feature = "http3")] h3: Option<&Http3Options>,
) -> crate::Result<()> {
    #[cfg(feature = "http3")]
    let is_quic = h3.is_some();
    #[cfg(not(feature = "http3"))]
    let is_quic = false;

    // === Options NOT applicable to QUIC (TLS 1.3 has no renegotiation/tickets) ===
    if !is_quic {
        set_bool!(tls, !session_ticket, builder, set_options, SslOptions::NO_TICKET);
        set_bool!(tls, !psk_dhe_ke, builder, set_options, SslOptions::NO_PSK_DHE_KE);
        set_bool!(tls, !renegotiation, builder, set_options, SslOptions::NO_RENEGOTIATION);
    }

    // === OCSP stapling / SCT: QUIC override, fall back to TlsOptions ===
    #[cfg(feature = "http3")]
    let ocsp = h3
        .and_then(|o| o.quic_enable_ocsp_stapling)
        .unwrap_or(tls.enable_ocsp_stapling);
    #[cfg(not(feature = "http3"))]
    let ocsp = tls.enable_ocsp_stapling;

    if ocsp {
        builder.enable_ocsp_stapling();
    }

    #[cfg(feature = "http3")]
    let sct = h3
        .and_then(|o| o.quic_enable_signed_cert_timestamps)
        .unwrap_or(tls.enable_signed_cert_timestamps);
    #[cfg(not(feature = "http3"))]
    let sct = tls.enable_signed_cert_timestamps;

    if sct {
        builder.enable_signed_cert_timestamps();
    }

    // IMPORTANT: preserve_tls13_cipher_list MUST be called before cipher_list.
    set_option!(tls, preserve_tls13_cipher_list, builder, set_preserve_tls13_cipher_list);
    set_option_ref_try!(tls, cipher_list, builder, set_cipher_list);
    set_option_ref_try!(tls, delegated_credentials, builder, set_delegated_credentials);
    set_option!(tls, record_size_limit, builder, set_record_size_limit);
    set_option!(tls, aes_hw_override, builder, set_aes_hw_override);

    // === Options with QUIC overrides ===

    // Curves
    #[cfg(feature = "http3")]
    let curves = h3
        .and_then(|o| o.quic_curves_list.as_deref())
        .or(tls.curves_list.as_deref());
    #[cfg(not(feature = "http3"))]
    let curves = tls.curves_list.as_deref();

    if let Some(curves) = curves {
        builder.set_curves_list(curves).map_err(Error::tls)?;
    }

    // Signature algorithms
    #[cfg(feature = "http3")]
    let sigalgs = h3
        .and_then(|o| o.quic_sigalgs_list.as_deref())
        .or(tls.sigalgs_list.as_deref());
    #[cfg(not(feature = "http3"))]
    let sigalgs = tls.sigalgs_list.as_deref();

    if let Some(sigalgs) = sigalgs {
        builder.set_sigalgs_list(sigalgs).map_err(Error::tls)?;
    }

    // GREASE
    #[cfg(feature = "http3")]
    let grease = h3
        .and_then(|o| o.quic_grease_enabled)
        .or(tls.grease_enabled);
    #[cfg(not(feature = "http3"))]
    let grease = tls.grease_enabled;

    if let Some(grease) = grease {
        builder.set_grease_enabled(grease);
    }

    // Certificate compressors
    #[cfg(feature = "http3")]
    let compressors = h3
        .and_then(|o| o.quic_certificate_compressors.as_deref())
        .or(tls.certificate_compressors.as_deref());
    #[cfg(not(feature = "http3"))]
    let compressors = tls.certificate_compressors.as_deref();

    if let Some(compressors) = compressors {
        for c in compressors {
            builder
                .add_certificate_compression_algorithm(*c)
                .map_err(Error::tls)?;
        }
    }

    // Extension permutation
    //
    // H1/H2: both `permute_extensions` (bool) and `extension_permutation`
    //         (explicit order) are applied independently; BoringSSL resolves
    //         precedence.
    // QUIC:   explicit permutation (with quic override) takes priority;
    //         `permute_extensions` is a fallback only when no explicit order
    //         is given.
    #[cfg(feature = "http3")]
    let ext_perm = h3
        .and_then(|o| o.quic_extension_permutation.as_deref())
        .or(tls.extension_permutation.as_deref());
    #[cfg(not(feature = "http3"))]
    let ext_perm = tls.extension_permutation.as_deref();

    if is_quic {
        if let Some(perm) = ext_perm {
            builder
                .set_extension_permutation(perm)
                .map_err(Error::tls)?;
        } else if let Some(permute) = tls.permute_extensions {
            builder.set_permute_extensions(permute);
        }
    } else {
        set_option!(tls, permute_extensions, builder, set_permute_extensions);
        if let Some(perm) = ext_perm {
            builder
                .set_extension_permutation(perm)
                .map_err(Error::tls)?;
        }
    }

    Ok(())
}
