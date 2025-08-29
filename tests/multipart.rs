mod support;
use http_body_util::BodyExt;
use pretty_env_logger::env_logger;
use support::server;

#[tokio::test]
async fn text_part() {
    let _ = env_logger::try_init();

    let form = wreq::multipart::Form::new().text("foo", "bar");

    let expected_body = format!(
        "\
         --{0}\r\n\
         Content-Disposition: form-data; name=\"foo\"\r\n\r\n\
         bar\r\n\
         --{0}--\r\n\
         ",
        form.boundary()
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |mut req| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            assert_eq!(
                req.headers()["content-length"],
                expected_body.len().to_string()
            );

            let mut full: Vec<u8> = Vec::new();
            while let Some(item) = req.body_mut().frame().await {
                full.extend(&*item.unwrap().into_data().unwrap());
            }

            assert_eq!(full, expected_body.as_bytes());

            http::Response::default()
        }
    });

    let url = format!("http://{}/multipart/1", server.addr());

    let res = wreq::post(&url).multipart(form).send().await.unwrap();

    assert_eq!(res.uri().to_string(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[cfg(feature = "stream")]
#[tokio::test]
async fn stream_part() {
    use futures_util::{future, stream};

    let _ = env_logger::try_init();

    let stream = wreq::Body::wrap_stream(stream::once(future::ready(Ok::<_, wreq::Error>(
        "part1 part2".to_owned(),
    ))));
    let part = wreq::multipart::Part::stream(stream);

    let form = wreq::multipart::Form::new()
        .text("foo", "bar")
        .part("part_stream", part);

    let expected_body = format!(
        "\
         --{0}\r\n\
         Content-Disposition: form-data; name=\"foo\"\r\n\
         \r\n\
         bar\r\n\
         --{0}\r\n\
         Content-Disposition: form-data; name=\"part_stream\"\r\n\
         \r\n\
         part1 part2\r\n\
         --{0}--\r\n\
         ",
        form.boundary()
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |req| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            assert_eq!(req.headers()["transfer-encoding"], "chunked");

            let full = req.collect().await.unwrap().to_bytes();

            assert_eq!(full, expected_body.as_bytes());

            http::Response::default()
        }
    });

    let url = format!("http://{}/multipart/1", server.addr());

    let res = wreq::post(&url)
        .multipart(form)
        .send()
        .await
        .expect("Failed to post multipart");
    assert_eq!(res.uri().to_string(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}

#[cfg(feature = "stream")]
#[tokio::test]
async fn async_impl_file_part() {
    let _ = env_logger::try_init();

    let form = wreq::multipart::Form::new()
        .file("foo", "Cargo.lock")
        .await
        .unwrap();

    let fcontents = std::fs::read_to_string("Cargo.lock").unwrap();

    let expected_body = format!(
        "\
         --{0}\r\n\
         Content-Disposition: form-data; name=\"foo\"; filename=\"Cargo.lock\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n\
         {1}\r\n\
         --{0}--\r\n\
         ",
        form.boundary(),
        fcontents
    );

    let ct = format!("multipart/form-data; boundary={}", form.boundary());

    let server = server::http(move |req| {
        let ct = ct.clone();
        let expected_body = expected_body.clone();
        async move {
            assert_eq!(req.method(), "POST");
            assert_eq!(req.headers()["content-type"], ct);
            // files know their exact size
            assert_eq!(
                req.headers()["content-length"],
                expected_body.len().to_string()
            );
            let full = req.collect().await.unwrap().to_bytes();

            assert_eq!(full, expected_body.as_bytes());

            http::Response::default()
        }
    });

    let url = format!("http://{}/multipart/3", server.addr());

    let res = wreq::post(&url).multipart(form).send().await.unwrap();

    assert_eq!(res.uri().to_string(), url);
    assert_eq!(res.status(), wreq::StatusCode::OK);
}
