#![allow(
    dead_code,
    reason = "Each HTTP/3 test target uses only part of the shared fixture"
)]
//! Local HTTP/3 servers for integration tests.

use std::{future::Future, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use http::Request;
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::ResolvesServerCert,
    sign::{CertifiedKey, SingleCertAndKey},
};
use tokio::task::{JoinHandle, JoinSet};
use wreq::tls::trust::CertStore;

/// The server side of an HTTP/3 connection.
pub type Connection = http3::server::Connection<http3_quic::Connection, Bytes>;

/// The server side of one HTTP/3 request.
pub type RequestStream = http3::server::RequestStream<http3_quic::BidiStream<Bytes>, Bytes>;

/// A self-signed certificate for one host, which is also its common name, so a trust store
/// holding several of them tells them apart.
pub struct Certificate {
    der: CertificateDer<'static>,
    key: Arc<CertifiedKey>,
}

/// An HTTP/3 endpoint and the task serving it. Dropping it closes the endpoint and stops the
/// task.
pub struct Server {
    endpoint: quic::Endpoint,
    task: JoinHandle<()>,
}

/// Returns a TLS 1.3 server configuration offering `h3` with certificates from `resolver`.
pub fn tls(resolver: Arc<dyn ResolvesServerCert>) -> rustls::ServerConfig {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls
}

/// Binds an HTTP/3 endpoint on `127.0.0.1` for `tls`, a [`Certificate`] or a full configuration.
/// `transport` replaces the default QUIC transport configuration.
pub fn endpoint(
    tls: impl Into<rustls::ServerConfig>,
    transport: Option<quic::TransportConfig>,
) -> quic::Endpoint {
    let mut config = quic::ServerConfig::with_crypto(Arc::new(
        quic::crypto::rustls::QuicServerConfig::try_from(tls.into()).unwrap(),
    ));
    if let Some(transport) = transport {
        config.transport_config(Arc::new(transport));
    }
    quic::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
}

/// Accepts the next connection on `endpoint` and starts HTTP/3 on it.
pub async fn accept(endpoint: &quic::Endpoint) -> (quic::Connection, Connection) {
    let connection = endpoint.accept().await.unwrap().await.unwrap();
    let server = http3::server::builder()
        .build(http3_quic::Connection::new(connection.clone()))
        .await
        .unwrap();
    (connection, server)
}

/// Serves the requests of one connection for [`Server::serve`].
async fn serve_connection<F, Fut>(connecting: quic::Incoming, extended_connect: bool, handler: F)
where
    F: Fn(Request<()>, RequestStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let Ok(connection) = connecting.await else {
        return;
    };
    let Ok(mut server) = http3::server::builder()
        .enable_extended_connect(extended_connect)
        .build::<_, Bytes>(http3_quic::Connection::new(connection))
        .await
    else {
        return;
    };
    // Declared after the connection so that its request streams drop first: a stream outliving
    // its connection logs an error.
    let mut requests = FuturesUnordered::new();
    loop {
        tokio::select! {
            accepted = server.accept() => {
                let Ok(Some(resolver)) = accepted else { break };
                let handler = handler.clone();
                requests.push(async move {
                    if let Ok((request, stream)) = resolver.resolve_request().await {
                        handler(request, stream).await;
                    }
                });
            }
            Some(()) = requests.next() => {}
        }
    }
    // Dropping the connection would cut off responses still being sent.
    while requests.next().await.is_some() {}
}

// ===== impl Certificate =====

impl Certificate {
    pub fn new(host: &str) -> Self {
        let mut params = rcgen::CertificateParams::new(vec![host.into()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().clone();
        let key = CertifiedKey::from_der(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            &rustls::crypto::aws_lc_rs::default_provider(),
        )
        .unwrap();
        Self {
            der,
            key: Arc::new(key),
        }
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns a client trust store holding only this certificate.
    pub fn cert_store(&self) -> CertStore {
        CertStore::from_der_certs([self.der()]).unwrap()
    }
}

impl From<&Certificate> for rustls::ServerConfig {
    fn from(certificate: &Certificate) -> Self {
        tls(Arc::new(SingleCertAndKey::from(certificate.key.clone())))
    }
}

// ===== impl Server =====

impl Server {
    /// Runs `task` for `endpoint` until the server is dropped.
    pub fn spawn<F>(endpoint: quic::Endpoint, task: F) -> Self
    where
        F: Future<Output = ()> + Send + 'static,
    {
        Self {
            endpoint,
            task: tokio::spawn(task),
        }
    }

    /// Serves every connection on `endpoint`, running `handler` concurrently for each request.
    /// `extended_connect` advertises extended CONNECT
    /// ([RFC 9220 Section 3](https://www.rfc-editor.org/rfc/rfc9220#section-3)).
    pub fn serve<F, Fut>(endpoint: quic::Endpoint, extended_connect: bool, handler: F) -> Self
    where
        F: Fn(Request<()>, RequestStream) -> Fut + Clone + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let incoming = endpoint.clone();
        Self::spawn(endpoint, async move {
            let mut connections = JoinSet::new();
            while let Some(connecting) = incoming.accept().await {
                connections.spawn(serve_connection(
                    connecting,
                    extended_connect,
                    handler.clone(),
                ));
            }
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.endpoint.local_addr().unwrap()
    }

    pub fn endpoint(&self) -> &quic::Endpoint {
        &self.endpoint
    }

    /// Returns how many connections the endpoint has accepted.
    pub fn connections(&self) -> u64 {
        self.endpoint.stats().accepted_handshakes
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"done");
        self.task.abort();
    }
}
