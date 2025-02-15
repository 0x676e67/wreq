use rquest::{Client, Emulation, EmulationOS, EmulationOption};

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Build a client to emulation Firefox128
    let emulation = EmulationOption::builder()
        .emulation(Emulation::Firefox128)
        .emulation_os(EmulationOS::Windows)
        .skip_http2(true)
        .build();

    // Apply the emulation to the client
    let client = Client::builder()
        .emulation(emulation)
        .http1_only()
        .build()?;

    // Use the API you're already familiar with
    let text = client
        .get("https://tls.peet.ws/api/all")
        .send()
        .await?
        .text()
        .await?;

    println!("{}", text);

    Ok(())
}
