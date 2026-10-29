#![cfg(all(feature = "tokio-rt", not(target_arch = "wasm32")))]

use std::time::Duration;

use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};
use wreq::{Client, Emulation, Group, tls::TlsOptions};

#[tokio::test]
async fn server_padding_is_optional_and_survives_emulation_reuse() {
    let request_client = Client::builder().no_proxy().build().unwrap();
    for requested in [None, Some(0), Some(1024)] {
        let options = match requested {
            Some(bytes) => TlsOptions::builder().server_padding(bytes).build(),
            None => TlsOptions::default(),
        };
        let native = Emulation::builder()
            .tls_options(options)
            .build(Group::new("server-padding-test"));
        let client = Client::builder()
            .no_proxy()
            .emulation(native.clone())
            .build()
            .unwrap();
        let expected = requested.map(|bytes| u16::to_be_bytes(bytes).to_vec());
        for _ in 0..2 {
            assert_eq!(capture_server_padding(&client, None).await, expected);
            assert_eq!(
                capture_server_padding(&request_client, Some(&native)).await,
                expected
            );
        }
    }
}

#[test]
fn server_padding_can_be_disabled_after_configuration() {
    let options = TlsOptions::builder()
        .server_padding(1024)
        .server_padding(None)
        .build();
    assert_eq!(options.server_padding, None);
}

// Close after ClientHello; inspecting the extension needs no certificate or
// external service and exercises both client-wide and per-request emulation.
async fn capture_server_padding(client: &Client, native: Option<&Emulation>) -> Option<Vec<u8>> {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let mut request = client.get(format!("https://{}/", listener.local_addr().unwrap()));
        if let Some(native) = native {
            request = request.emulation(native.clone());
        }
        let capture = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut handshake = Vec::new();
            loop {
                let mut header = [0; 5];
                socket.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22, "expected a TLS handshake record");
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let offset = handshake.len();
                handshake.resize(offset + length, 0);
                socket.read_exact(&mut handshake[offset..]).await.unwrap();
                if handshake.len() >= 4 {
                    assert_eq!(handshake[0], 1, "expected ClientHello");
                    let length = handshake[1..4]
                        .iter()
                        .fold(0usize, |n, &byte| (n << 8) | usize::from(byte));
                    if handshake.len() >= length + 4 {
                        return server_padding_from_client_hello(&handshake[4..length + 4]);
                    }
                }
            }
        };
        let (result, extension) = tokio::join!(request.send(), capture);
        assert!(result.unwrap_err().is_connect());
        extension
    })
    .await
    .expect("ClientHello capture timed out")
}

fn server_padding_from_client_hello(mut hello: &[u8]) -> Option<Vec<u8>> {
    take(&mut hello, 2 + 32); // Legacy version and random.
    take_vector(&mut hello, 1); // Session ID.
    take_vector(&mut hello, 2); // Cipher suites.
    take_vector(&mut hello, 1); // Compression methods.
    let mut extensions = take_vector(&mut hello, 2);
    while !extensions.is_empty() {
        let kind = take(&mut extensions, 2);
        let data = take_vector(&mut extensions, 2);
        if u16::from_be_bytes([kind[0], kind[1]]) == 4832 {
            return Some(data.to_vec());
        }
    }
    None
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> &'a [u8] {
    let (value, rest) = input.split_at(length);
    *input = rest;
    value
}

fn take_vector<'a>(input: &mut &'a [u8], prefix: usize) -> &'a [u8] {
    let length = take(input, prefix)
        .iter()
        .fold(0usize, |n, &byte| (n << 8) | usize::from(byte));
    take(input, length)
}
