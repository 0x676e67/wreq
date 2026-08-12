//! Reusable TLS-aware client facade modeled after the Go `tls-client` API.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    Client, Method, Proxy,
    header::{HeaderMap, HeaderName, HeaderValue, OrigHeaderMap},
    redirect::Policy,
};

/// Configuration used to construct a [`TlsClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientConfig {
    /// Named profile. `default` and the empty string use wreq defaults.
    ///
    /// Named browser profiles require the separate `wreq-util` crate and are
    /// intentionally rejected here rather than silently emulated incorrectly.
    pub tls_profile: String,
    /// Total request timeout.
    pub timeout: Option<Duration>,
    /// Timeout while waiting for the next response-body read.
    pub idle_timeout: Option<Duration>,
    /// Optional proxy URL.
    pub proxy_url: Option<String>,
    /// Whether redirects should be followed.
    pub follow_redirects: bool,
    /// Disable certificate and hostname verification.
    pub insecure_skip_verify: bool,
}

impl Default for TlsClientConfig {
    fn default() -> Self {
        Self {
            tls_profile: String::new(),
            timeout: Some(Duration::from_secs(30)),
            idle_timeout: Some(Duration::from_secs(30)),
            proxy_url: None,
            follow_redirects: false,
            insecure_skip_verify: false,
        }
    }
}

/// A fully configured, shareable HTTP client.
#[derive(Clone)]
pub struct TlsClient {
    client: Client,
    config: TlsClientConfig,
}

/// A collected response returned by [`TlsClient::execute`].
#[derive(Debug, Clone)]
pub struct TlsResponse {
    /// Final response URL.
    pub url: String,
    /// HTTP status code.
    pub status: u16,
    /// Negotiated HTTP protocol version.
    pub protocol: crate::Version,
    /// Response headers.
    pub headers: HeaderMap,
    /// Full response body.
    pub body: Vec<u8>,
}

impl TlsClient {
    /// Builds a client from configuration.
    pub fn new(config: TlsClientConfig) -> crate::Result<Self> {
        if !config.tls_profile.is_empty() && config.tls_profile != "default" {
            return Err(crate::Error::builder(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "unsupported TLS profile {:?}; use wreq-util to provide named emulation",
                    config.tls_profile
                ),
            )));
        }

        let mut builder = Client::builder();
        if let Some(proxy_url) = &config.proxy_url {
            builder = builder.proxy(Proxy::all(proxy_url)?);
        }
        if let Some(timeout) = config.timeout {
            builder = builder.timeout(timeout);
        }
        builder = builder.redirect(if config.follow_redirects {
            Policy::limited(10)
        } else {
            Policy::none()
        });
        if config.insecure_skip_verify {
            builder = builder
                .tls_cert_verification(false)
                .tls_verify_hostname(false);
        }
        Ok(Self {
            client: builder.build()?,
            config,
        })
    }

    /// Executes a request and collects its complete response body.
    pub async fn execute(
        &self,
        method: Method,
        url: impl Into<String>,
        headers: HeaderMap,
        header_order: OrigHeaderMap,
        body: Option<Vec<u8>>,
    ) -> crate::Result<TlsResponse> {
        let mut request = self.client.request(method, url.into());
        request = request.headers(headers).orig_headers(header_order);
        if let Some(body) = body {
            request = request.body(body);
        }
        if let Some(timeout) = self.config.timeout {
            request = request.timeout(timeout);
        }
        if let Some(timeout) = self.config.idle_timeout {
            request = request.read_timeout(timeout);
        }
        let response = request.send().await?;
        let result = TlsResponse {
            url: response.uri().to_string(),
            status: response.status().as_u16(),
            protocol: response.version(),
            headers: response.headers().clone(),
            body: response.bytes().await?.to_vec(),
        };
        Ok(result)
    }

    /// Returns the immutable configuration used to create this client.
    pub fn config(&self) -> &TlsClientConfig {
        &self.config
    }
}

/// Thread-safe cache of clients keyed by the Go implementation's `Id` field.
#[derive(Default, Clone)]
pub struct TlsClientPool {
    clients: Arc<Mutex<HashMap<String, (TlsClientConfig, Arc<TlsClient>)>>>,
}

impl TlsClientPool {
    /// Returns a cached client or creates one when the configuration changed.
    pub fn get_or_create(
        &self,
        id: impl Into<String>,
        config: TlsClientConfig,
    ) -> crate::Result<Arc<TlsClient>> {
        let id = id.into();
        let mut clients = self.clients.lock().map_err(|_| {
            crate::Error::builder(std::io::Error::other("TLS client pool lock poisoned"))
        })?;
        if let Some((cached_config, client)) = clients.get(&id) {
            if cached_config == &config {
                return Ok(Arc::clone(client));
            }
        }
        let client = Arc::new(TlsClient::new(config.clone())?);
        clients.insert(id, (config, Arc::clone(&client)));
        Ok(client)
    }

    /// Removes a cached client. Dropping it closes its pool when no other
    /// `TlsClient` clone is alive; wreq has no explicit close-idle operation.
    pub fn remove(&self, id: &str) -> crate::Result<bool> {
        let mut clients = self.clients.lock().map_err(|_| {
            crate::Error::builder(std::io::Error::other("TLS client pool lock poisoned"))
        })?;
        Ok(clients.remove(id).is_some())
    }
}

/// Parses `Name: value` lines into request headers.
pub fn parse_headers(input: &str) -> crate::Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            crate::Error::builder(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid header line: {line}"),
            ))
        })?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(|error| {
            crate::Error::builder(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            ))
        })?;
        let value = HeaderValue::from_str(value.trim()).map_err(|error| {
            crate::Error::builder(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                error.to_string(),
            ))
        })?;
        headers.append(name, value);
    }
    Ok(headers)
}

/// Parses comma- or newline-separated header names.
pub fn parse_header_order(input: &str) -> OrigHeaderMap {
    let mut order = OrigHeaderMap::new();
    for name in input
        .split(|ch: char| ch == ',' || ch == '\r' || ch == '\n')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        order.insert(name.to_owned());
    }
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_header_formats() {
        let headers = parse_headers("Host: example.test\r\nX-Test: value").unwrap();
        assert_eq!(headers["host"], "example.test");
        assert_eq!(parse_header_order("Host\r\nX-Test").len(), 2);
    }

    #[test]
    fn rejects_unknown_named_profiles() {
        let config = TlsClientConfig {
            tls_profile: "chrome_146".into(),
            ..Default::default()
        };
        assert!(TlsClient::new(config).is_err());
    }
}
