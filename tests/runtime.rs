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
        let echo = async |version| {
            let response = client
                .post(&url)
                .version(version)
                .body(payload.clone())
                .send()
                .await
                .unwrap();
            assert_eq!(response.version(), version);
            assert_eq!(response.bytes().await.unwrap(), payload);
        };
        echo(Version::HTTP_11).await;
        #[cfg(feature = "http2")]
        echo(Version::HTTP_2).await;
    });
}

#[test]
fn oversized_timeouts_do_not_overflow() {
    let server = support::server::http(|_| async { http::Response::new(Body::from("ok")) });
    let url = format!("http://{}/", server.addr());
    let get = async |builder: wreq::ClientBuilder| {
        let client = builder
            .no_proxy()
            .timeout(Duration::MAX)
            .read_timeout(Duration::MAX)
            .connect_timeout(Duration::MAX)
            .pool_idle_timeout(Duration::MAX)
            .build()
            .unwrap();
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.text().await.unwrap(), "ok");
    };

    compio::runtime::Runtime::new()
        .unwrap()
        .block_on(get(Client::builder_compio()));
    #[cfg(feature = "tokio-rt")]
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(get(Client::builder_tokio()));
}
