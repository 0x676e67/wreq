//! Application-facing boundary around `wreq`.

/// Small HTTP client facade that keeps `wreq` details out of application code.
pub struct HttpClient {
    inner: wreq::Client,
}

impl HttpClient {
    /// Builds a client using the features configured by the `wreq` dependency.
    pub fn new() -> wreq::Result<Self> {
        Ok(Self {
            inner: wreq::Client::builder().build()?,
        })
    }

    /// Sends a GET request and returns its response body as text.
    pub async fn get_text(&self, url: &str) -> wreq::Result<String> {
        self.inner.get(url).send().await?.text().await
    }
}
