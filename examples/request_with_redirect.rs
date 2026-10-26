use std::ops::ControlFlow;

use wreq::{header::HeaderValue, redirect::Policy};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    let policy = Policy::default()
        .on_request(|request| {
            request
                .headers_mut()
                .insert("x-client", HeaderValue::from_static("wreq"));

            // Cookie injection and protocol header preparation happen after this callback.
            println!("--> {} {}", request.method(), request.uri());
            println!("{:#?}", request.headers());
        })
        .on_response(|request, response| {
            println!(
                "<-- {} {:?} {}",
                response.status(),
                response.version(),
                request.uri(),
            );
            println!("{:#?}", response.headers());
            ControlFlow::Continue(())
        });

    let resp = wreq::get("https://google.com/")
        .redirect(policy)
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
