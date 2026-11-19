use btls::{
    pkcs12::Pkcs12,
    pkey::{PKey, Private},
    ssl::SslContextBuilder,
    x509::X509,
};

use crate::Error;

/// Client TLS identity consisting of a private key, leaf X.509 certificate, and chain.
///
/// Use [`ClientBuilder::tls_identity`](crate::ClientBuilder::tls_identity) for mutual TLS.
#[derive(Debug, Clone)]
pub struct Identity {
    pkey: PKey<Private>,
    cert: X509,
    chain: Vec<X509>,
}

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that allow the server to build a chain to a trusted root.
    /// The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use wreq::tls::trust::Identity;
    ///
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn pkcs12() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my-ident.pfx")?.read_to_end(&mut buf)?;
    /// let pkcs12 = Identity::from_pkcs12_der(&buf, "my-privkey-password")?;
    /// # drop(pkcs12);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pkcs12_der(buf: &[u8], pass: &str) -> crate::Result<Identity> {
        let pkcs12 = Pkcs12::from_der(buf).map_err(Error::tls)?;
        let parsed = pkcs12.parse(pass).map_err(Error::tls)?;
        Ok(Identity {
            pkey: parsed.pkey,
            cert: parsed.cert,
            // > The stack is the reverse of what you might expect due to the way
            // > PKCS12_parse is implemented, so we need to load it backwards.
            // > https://github.com/sfackler/rust-native-tls/commit/05fb5e583be589ab63d9f83d986d095639f8ec44
            chain: parsed.chain.into_iter().flatten().rev().collect(),
        })
    }

    /// Parses a chain of PEM encoded X509 certificates, with the leaf certificate first.
    /// `key` is a PEM encoded PKCS #8 formatted private key for the leaf certificate.
    ///
    /// The certificate chain should contain any intermediate certificates that should be sent to
    /// the server to allow it to build a chain to a trusted root.
    ///
    /// A certificate chain here means a series of PEM encoded certificates concatenated together.
    ///
    /// # Examples
    ///
    /// ```
    /// use wreq::tls::trust::Identity;
    ///
    /// # use std::fs;
    /// # fn pkcs8() -> Result<(), Box<dyn std::error::Error>> {
    /// let cert = fs::read("client.pem")?;
    /// let key = fs::read("key.pem")?;
    /// let pkcs8 = Identity::from_pkcs8_pem(&cert, &key)?;
    /// # drop(pkcs8);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pkcs8_pem(buf: &[u8], key: &[u8]) -> crate::Result<Identity> {
        if !key.starts_with(b"-----BEGIN PRIVATE KEY-----") {
            return Err(Error::builder("expected PKCS#8 PEM"));
        }

        let pkey = PKey::private_key_from_pem(key).map_err(Error::tls)?;
        let mut cert_chain = X509::stack_from_pem(buf).map_err(Error::tls)?.into_iter();
        let cert = cert_chain.next().ok_or_else(|| {
            Error::builder("at least one certificate must be provided to create an identity")
        })?;
        let chain = cert_chain.collect();
        Ok(Identity { pkey, cert, chain })
    }

    /// Installs the client certificate, private key, and chain in leaf-to-root order.
    pub(in crate::tls) fn configure(&self, builder: &mut SslContextBuilder) -> crate::Result<()> {
        builder.set_certificate(&self.cert).map_err(Error::tls)?;
        builder.set_private_key(&self.pkey).map_err(Error::tls)?;
        for cert in self.chain.iter() {
            builder
                .add_extra_chain_cert(cert.clone())
                .map_err(Error::tls)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Identity;

    #[test]
    fn identity_from_pkcs12_der_invalid() {
        Identity::from_pkcs12_der(b"not der", "nope").unwrap_err();
    }

    #[test]
    fn identity_from_pkcs8_pem_invalid() {
        Identity::from_pkcs8_pem(b"not pem", b"not key").unwrap_err();
    }
}
