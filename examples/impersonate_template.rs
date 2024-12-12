use http::{header, HeaderMap, HeaderValue};
use rquest::tls::{chrome, ImpersonateSettings};
use std::borrow::Cow;

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Create a pre-configured TLS settings
    let settings = ImpersonateSettings::builder()
        .tls(chrome::tls_template_1())
        .http2(chrome::http2_template_1())
        .headers({
            let mut headers = HeaderMap::new();
            headers.insert(header::USER_AGENT, HeaderValue::from_static("rquest"));
            Cow::Owned(headers)
        })
        .build();

    // Build a client with pre-configured TLS settings
    let client = rquest::Client::builder()
        .impersonate_settings(settings)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
