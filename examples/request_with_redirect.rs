use wreq::redirect::Policy;

#[tokio::main]
async fn main() -> wreq::Result<()> {
    // Use the API you're already familiar with
    let resp = wreq::get("https://google.com/")
        .redirect(Policy::custom(|attempt| {
            // we can inspect the redirect attempt
            println!(
                "Redirecting (status: {}) to {:?} and headers: {:#?}",
                attempt.status(),
                attempt.uri(),
                attempt.headers()
            );

            // we can follow redirects as normal
            attempt.follow()
        }))
        .send()
        .await?;
    println!("{}", resp.text().await?);

    Ok(())
}
