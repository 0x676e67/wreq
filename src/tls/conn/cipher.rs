use btls::ssl::Tls13Cipher;

pub(super) const AES_FIRST: [Tls13Cipher; 3] = [
    Tls13Cipher::AES_128_GCM_SHA256,
    Tls13Cipher::AES_256_GCM_SHA384,
    Tls13Cipher::CHACHA20_POLY1305_SHA256,
];

pub(super) const CHACHA_FIRST: [Tls13Cipher; 3] = [
    Tls13Cipher::CHACHA20_POLY1305_SHA256,
    Tls13Cipher::AES_128_GCM_SHA256,
    Tls13Cipher::AES_256_GCM_SHA384,
];

// The caller first validates the whole rule string with set_cipher_list. Only
// these three suites participate in the old TLS 1.3 preservation rule parser.
// https://github.com/0x676e67/btls/blob/de7ab84fdb58641a2bdfdf9d8ebd7db1dcf4b29b/btls-sys/patches/0007-boringssl-cipher-preferences.patch
pub(super) fn preserved_ciphers(rules: &str) -> Vec<Tls13Cipher> {
    let mut order = vec![(0usize, false), (1, false), (2, false)];
    for rule in rules.split([':', ' ', ';', ',', '[', ']', '|']) {
        if rule.is_empty() {
            continue;
        }
        if rule == "@STRENGTH" {
            // AES-256 and ChaCha20 have equal strength; retain their relative order.
            order.sort_by_key(|&(id, active)| (active, active && id == 0));
            continue;
        }
        let (operator, name) = match rule.as_bytes()[0] {
            b'+' | b'-' | b'!' => (rule.as_bytes()[0], &rule[1..]),
            _ => (b' ', rule),
        };
        let mask = match name {
            "TLS_AES_128_GCM_SHA256" => 1,
            "TLS_AES_256_GCM_SHA384" => 2,
            "TLS_CHACHA20_POLY1305_SHA256" => 4,
            _ => name.split('+').fold(7, |mask, alias| {
                mask & match alias {
                    "ALL" | "HIGH" | "FIPS" => 7,
                    "AES" | "AESGCM" => 3,
                    "AES128" => 1,
                    "AES256" => 2,
                    "CHACHA20" => 4,
                    _ => 0,
                }
            }),
        };
        // Snapshot the matching IDs: each rule may move entries as it walks them.
        let mut selected: Vec<_> = order
            .iter()
            .filter(|&&(id, _)| mask & (1 << id) != 0)
            .map(|&(id, _)| id)
            .collect();
        if operator == b'-' {
            selected.reverse();
        }
        for id in selected {
            let Some(index) = order.iter().position(|&(candidate, _)| candidate == id) else {
                continue;
            };
            match operator {
                b'!' => {
                    order.remove(index);
                }
                b'-' if order[index].1 => {
                    order.remove(index);
                    order.insert(0, (id, false));
                }
                b'+' if order[index].1 => {
                    let entry = order.remove(index);
                    order.push(entry);
                }
                b' ' if !order[index].1 => {
                    order.remove(index);
                    order.push((id, true));
                }
                _ => {}
            }
        }
    }
    order
        .into_iter()
        .filter(|&(_, active)| active)
        .map(|(id, _)| AES_FIRST[id])
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Read, Write};

    use btls::ssl::{ErrorCode, Ssl, SslConnector, SslMethod, SslStream};
    use http::Uri;

    use super::super::TlsConnector;
    use crate::{conn::descriptor::ConnectionDescriptor, group::Group, tls::TlsOptions};

    #[test]
    fn cipher_preferences_reach_client_hello_without_changing_tls12() {
        let legacy = ":ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384";
        for (rules, preserve, aes, random, expected) in [
            ("", false, true, false, vec![0x1301, 0x1302, 0x1303]),
            ("", false, false, false, vec![0x1303, 0x1301, 0x1302]),
            ("", true, false, false, vec![0x1303, 0x1301, 0x1302]),
            (
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
                true,
                false,
                true,
                vec![0x1302, 0x1303, 0x1301],
            ),
            (
                "ALL:!AES128:-CHACHA20:AESGCM:CHACHA20",
                true,
                true,
                false,
                vec![0x1302, 0x1303],
            ),
            (
                "[TLS_CHACHA20_POLY1305_SHA256|TLS_AES_128_GCM_SHA256]:TLS_AES_256_GCM_SHA384",
                true,
                true,
                false,
                vec![0x1303, 0x1301, 0x1302],
            ),
            (
                "@STRENGTH:ALL",
                true,
                true,
                false,
                vec![0x1301, 0x1302, 0x1303],
            ),
            (
                "ALL:@STRENGTH",
                true,
                true,
                false,
                vec![0x1302, 0x1303, 0x1301],
            ),
            (
                "AESGCM+AES128:CHACHA20",
                true,
                false,
                false,
                vec![0x1301, 0x1303],
            ),
        ] {
            let rules = format!("{rules}{legacy}");
            let mut baseline = SslConnector::bare_builder(SslMethod::tls()).unwrap();
            baseline.set_cipher_list(&rules).unwrap();
            let legacy_ciphers: Vec<_> = client_ciphers(
                baseline
                    .build()
                    .configure()
                    .unwrap()
                    .into_ssl("example.com")
                    .unwrap(),
            )
            .into_iter()
            .filter(|id| !(0x1301..=0x1303).contains(id))
            .collect();
            let opts = TlsOptions::builder()
                .cipher_list(rules.clone())
                .preserve_tls13_cipher_list(preserve)
                .aes_hw_override(aes)
                .random_aes_hw_override(random)
                .build();
            let connector = TlsConnector::builder()
                .build(std::borrow::Cow::Borrowed(&opts))
                .unwrap();
            // Reuse the connector so a per-connection override cannot defeat preservation.
            for _ in 0..2 {
                let descriptor = ConnectionDescriptor::new(
                    Uri::from_static("https://example.com/"),
                    Group::default(),
                    None,
                    None,
                    None,
                    None,
                );
                let ssl = connector.setup_ssl2(descriptor).unwrap();
                let ciphers = client_ciphers(ssl);
                let mut expected = expected.clone();
                expected.extend(&legacy_ciphers);
                assert_eq!(ciphers, expected, "{rules}: preserve={preserve}, aes={aes}");
            }
        }
    }

    fn client_ciphers(ssl: Ssl) -> Vec<u16> {
        let mut stream = SslStream::new(ssl, Capture(Vec::new())).unwrap();
        assert_eq!(stream.connect().unwrap_err().code(), ErrorCode::WANT_READ);
        let hello = &stream.get_ref().0;
        assert_eq!(&hello[..1], &[22]);
        let offset = 44 + usize::from(hello[43]);
        let len = usize::from(u16::from_be_bytes([hello[offset], hello[offset + 1]]));
        hello[offset + 2..offset + 2 + len]
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_be_bytes)
            .collect()
    }

    struct Capture(Vec<u8>);

    impl Read for Capture {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
