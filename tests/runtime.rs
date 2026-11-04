#![cfg(feature = "compio-rt")]

mod support;

use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use http::Version;
use http_body_util::BodyExt;
use wreq::{Body, Client};

#[test]
fn compio_client_uses_its_own_dns_io_and_timer() {
    let server = support::server::http(|request| async move {
        let version = request.version();
        let body = request.into_body().collect().await.unwrap().to_bytes();
        http::Response::builder()
            .version(version)
            .body(Body::from(body))
            .unwrap()
    });
    let runtime = compio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        // The server has its own Tokio thread; this client thread has no Tokio runtime.
        // Resolving localhost must therefore use the selected Compio runtime as well.
        let client = Client::builder_compio()
            .no_proxy()
            .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let url = format!("http://localhost:{}/echo", server.addr().port());
        let payload = vec![b'x'; 4096];
        for version in [Version::HTTP_11, Version::HTTP_2] {
            let response = client
                .post(&url)
                .version(version)
                .body(payload.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.bytes().await.unwrap(), payload);
        }
    });
}
