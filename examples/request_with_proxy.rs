use wreq::{
    Client,
    http2::{
        Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder, StreamDependency, StreamId,
    },
};

#[tokio::main]
async fn main() -> wreq::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // HTTP/2 headers frame pseudo-header order
    let headers_pseudo_order = PseudoOrder::builder()
        .extend([
            PseudoId::Method,
            PseudoId::Path,
            PseudoId::Authority,
            PseudoId::Scheme,
        ])
        .build();

    // HTTP/2 settings frame order
    let settings_order = SettingsOrder::builder()
        .extend([
            SettingId::HeaderTableSize,
            SettingId::EnablePush,
            SettingId::MaxConcurrentStreams,
            SettingId::InitialWindowSize,
            SettingId::MaxFrameSize,
            SettingId::MaxHeaderListSize,
            SettingId::EnableConnectProtocol,
            SettingId::NoRfc7540Priorities,
        ])
        .build();

    let http2 = Http2Options::builder()
        .header_table_size(65536)
        .enable_push(false)
        .initial_window_size(131072)
        .max_frame_size(16384)
        .initial_connection_window_size(12517377 + 65535)
        .headers_stream_dependency(StreamDependency::new(StreamId::ZERO, 41, false))
        .headers_pseudo_order(headers_pseudo_order)
        .settings_order(settings_order)
        .build();

    // Build a client with emulation config
    let client = Client::builder().cert_verification(false).build()?;

    // Use the API you're already familiar with
    let resp = client
        .get("https://api.ip.sb/ip")
        .emulation(http2)
        .send()
        .await?;
    let text = resp.text().await?;
    println!("Response: {}", text);

    let resp = client.get("https://api.ip.sb/ip").send().await?;
    let text = resp.text().await?;
    println!("Response: {}", text);

    Ok(())
}
