mod support;
use support::server;
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use wreq::Client;

#[tokio::test]
async fn websocket_read_error_is_websocket() {
    let server = server::http(move |req| {
        let accept = derive_accept_key(req.headers()["sec-websocket-key"].as_bytes());

        tokio::spawn(async move {
            let mut upgraded = hyper_util::rt::TokioIo::new(hyper::upgrade::on(req).await.unwrap());
            // A frame with the reserved opcode 0x3.
            upgraded.write_all(&[0x83, 0x00]).await.unwrap();
        });

        async move {
            http::Response::builder()
                .status(http::StatusCode::SWITCHING_PROTOCOLS)
                .header(http::header::CONNECTION, "upgrade")
                .header(http::header::UPGRADE, "websocket")
                .header(http::header::SEC_WEBSOCKET_ACCEPT, accept)
                .body(wreq::Body::default())
                .unwrap()
        }
    });

    let mut websocket = Client::new()
        .websocket(format!("ws://{}", server.addr()))
        .send()
        .await
        .unwrap()
        .into_websocket()
        .await
        .unwrap();

    let err = websocket.recv().await.unwrap().unwrap_err();
    assert!(err.is_websocket() && !err.is_body());
}
