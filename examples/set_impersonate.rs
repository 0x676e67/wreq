use http::{header, HeaderName};
use rquest::Impersonate;

static HEADER_ORDER: [HeaderName; 6] = [
    header::ACCEPT_LANGUAGE,
    header::USER_AGENT,
    header::ACCEPT_ENCODING,
    header::HOST,
    header::COOKIE,
    HeaderName::from_static("priority"),
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Build a client to impersonate Chrome131
    let mut client = rquest::Client::builder()
        .impersonate(Impersonate::Chrome131)
        .build()?;

    // Set the headers order
    {
        client.as_mut().headers_order(&HEADER_ORDER);
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Safari18
    {
        client.as_mut().impersonate(Impersonate::Safari18);
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    // Change the impersonate to Edge127 without setting the headers
    {
        client.as_mut().impersonate(Impersonate::Edge127);
        let resp = client.get("https://tls.peet.ws/api/all").send().await?;
        println!("{}", resp.text().await?);
    }

    Ok(())
}
