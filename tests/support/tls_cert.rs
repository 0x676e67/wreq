use std::net::IpAddr;

use btls::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509NameBuilder, extension::SubjectAlternativeName},
};

/// Generates a self-signed test certificate covering a DNS name and an IP address.
pub fn self_signed(dns_name: &str, ip: IpAddr) -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "wreq test")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns(dns_name)
        .ip(&ip.to_string())
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&san).unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();

    (builder.build(), key)
}

/// Builds a TLS acceptor for a test certificate and its key.
pub fn acceptor(cert: &X509, key: &PKey<Private>) -> btls::ssl::SslAcceptor {
    use btls::ssl::{SslAcceptor, SslMethod};

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor.set_certificate(cert).unwrap();
    acceptor.set_private_key(key).unwrap();
    acceptor.build()
}
