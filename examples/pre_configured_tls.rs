use boring::ssl::{SslConnector, SslCurve, SslMethod, SslOptions};
use http::{header, HeaderMap, HeaderName, HeaderValue};
use rquest::{
    tls::{Http2Settings, ImpersonateSettings, TlsSettings, Version},
    HttpVersionPref,
};
use rquest::{PseudoOrder::*, SettingsOrder::*};
use std::borrow::Cow;

static HEADER_ORDER: [HeaderName; 5] = [
    header::USER_AGENT,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_ENCODING,
    header::COOKIE,
    header::HOST,
];

#[tokio::main]
async fn main() -> Result<(), rquest::Error> {
    // Create a TLS connector builder
    let mut connector = SslConnector::no_default_verify_builder(SslMethod::tls_client())?;
    connector.set_curves(&[SslCurve::SECP224R1, SslCurve::SECP521R1])?;
    connector.set_options(SslOptions::NO_TICKET);

    // Create a pre-configured TLS settings
    let settings = ImpersonateSettings::builder()
        .tls(
            TlsSettings::builder()
                .connector(connector)
                .tls_sni(true)
                .http_version_pref(HttpVersionPref::All)
                .application_settings(true)
                .pre_shared_key(true)
                .enable_ech_grease(true)
                .permute_extensions(true)
                .min_tls_version(Version::TLS_1_0)
                .max_tls_version(Version::TLS_1_3)
                .build(),
        )
        .http2(
            Http2Settings::builder()
                .initial_stream_window_size(6291456)
                .initial_connection_window_size(15728640)
                .max_concurrent_streams(1000)
                .max_header_list_size(262144)
                .header_table_size(65536)
                .enable_push(false)
                .headers_priority((0, 255, true))
                .headers_pseudo_order([Method, Scheme, Authority, Path])
                .settings_order([
                    HeaderTableSize,
                    EnablePush,
                    MaxConcurrentStreams,
                    InitialWindowSize,
                    MaxFrameSize,
                    MaxHeaderListSize,
                    UnknownSetting8,
                    UnknownSetting9,
                ])
                .build(),
        )
        .headers({
            let mut headers = HeaderMap::new();
            headers.insert(header::USER_AGENT, HeaderValue::from_static("rquest"));
            headers.insert(
                header::ACCEPT_LANGUAGE,
                HeaderValue::from_static("en-US,en;q=0.9"),
            );
            headers.insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("gzip, deflate, br"),
            );
            headers.insert(header::HOST, HeaderValue::from_static("tls.peet.ws"));
            headers.insert(header::COOKIE, HeaderValue::from_static("foo=bar"));
            Cow::Owned(headers)
        })
        .headers_order(Cow::Borrowed(&HEADER_ORDER))
        .build();

    // Build a client with pre-configured TLS settings
    let client = rquest::Client::builder()
        .use_preconfigured_tls(settings)
        .build()?;

    // Use the API you're already familiar with
    let resp = client.get("https://tls.peet.ws/api/all").send().await?;
    println!("{}", resp.text().await?);

    Ok(())
}
