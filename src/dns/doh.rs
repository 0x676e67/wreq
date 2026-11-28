//! DNS-over-HTTPS resolver ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)).

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name as DnsName, RData, RecordType},
};
use http::{HeaderValue, StatusCode, Uri, header};
use lru::LruCache;
use tokio::sync::OnceCell;
use tower::BoxError;

use super::{Addrs, GaiResolver, Name, Resolve, Resolving};
use crate::{Client, ClientBuilder, IntoUri, sync::Mutex};

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_MESSAGE_LEN: usize = u16::MAX as usize;

const DEFAULT_CACHE_SIZE: usize = 256;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MIN_TTL: Duration = Duration::ZERO;
const DEFAULT_MAX_TTL: Duration = Duration::from_secs(86_400);
const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(30);

/// A resolver that sends DNS queries over HTTPS.
///
/// Queries go through an internal [`Client`], so they use the same TLS stack as
/// every other request. A and AAAA lookups run in parallel and the results are
/// cached according to their TTL. If a query fails, the system resolver is
/// used instead unless [`DohResolverBuilder::strict`] is set.
///
/// # Example
///
/// ```no_run
/// # fn main() -> wreq::Result<()> {
/// use std::net::{IpAddr, Ipv4Addr};
///
/// use wreq::dns::DohResolver;
///
/// let resolver = DohResolver::builder()
///     .endpoint("https://dns.example/dns-query")
///     .bootstrap([IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))])
///     .build()?;
/// let client = wreq::Client::builder().dns_resolver(resolver).build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct DohResolver {
    inner: Arc<Inner>,
}

struct Inner {
    client: Client,
    endpoint: Uri,
    timeout: Duration,
    min_ttl: Duration,
    max_ttl: Duration,
    cache: Option<Mutex<Cache>>,
    fallback: Option<GaiResolver>,
}

/// A builder for constructing a [`DohResolver`].
#[must_use]
pub struct DohResolverBuilder {
    endpoint: Option<crate::Result<Uri>>,
    bootstrap: Vec<IpAddr>,
    client: Option<ClientBuilder>,
    timeout: Duration,
    min_ttl: Duration,
    max_ttl: Duration,
    cache_size: usize,
    strict: bool,
}

/// Each slot is filled once by the first query for that name.
type Cache = LruCache<Box<str>, Arc<OnceCell<Lookup>>>;

#[derive(Clone)]
struct Lookup {
    addrs: Arc<[IpAddr]>,
    expires: Instant,
}

// ===== impl DohResolver =====

impl DohResolver {
    /// Creates a new [`DohResolverBuilder`].
    #[inline]
    pub fn builder() -> DohResolverBuilder {
        DohResolverBuilder {
            endpoint: None,
            bootstrap: Vec::new(),
            client: None,
            timeout: DEFAULT_TIMEOUT,
            min_ttl: DEFAULT_MIN_TTL,
            max_ttl: DEFAULT_MAX_TTL,
            cache_size: DEFAULT_CACHE_SIZE,
            strict: false,
        }
    }

    async fn lookup(&self, host: &str) -> Result<Lookup, BoxError> {
        let Some(cache) = &self.inner.cache else {
            return self.query(host).await;
        };

        let key: Box<str> = host.to_ascii_lowercase().into();
        let slot = {
            let mut cache = cache.lock();
            match cache.get(&key) {
                Some(slot) if slot.get().is_none_or(|l| l.expires > Instant::now()) => slot.clone(),
                _ => {
                    let slot = Arc::new(OnceCell::new());
                    cache.put(key, slot.clone());
                    slot
                }
            }
        };

        // Concurrent lookups of the same name share one query. A failed query
        // leaves the cell empty, so the next caller tries again.
        slot.get_or_try_init(|| self.query(host)).await.cloned()
    }

    async fn query(&self, host: &str) -> Result<Lookup, BoxError> {
        let mut name = DnsName::from_ascii(host)?;
        name.set_fqdn(true);

        let (v4, v6) = futures_util::future::join(
            self.exchange(name.clone(), RecordType::A),
            self.exchange(name, RecordType::AAAA),
        )
        .await;

        let (addrs, ttl) = match (v4, v6) {
            (Ok((mut v4, v4_ttl)), Ok((v6, v6_ttl))) => {
                // An empty side carries a negative TTL, which should not
                // shorten the lifetime of the addresses we did get.
                let ttl = match (v4.is_empty(), v6.is_empty()) {
                    (false, true) => v4_ttl,
                    (true, false) => v6_ttl,
                    _ => v4_ttl.min(v6_ttl),
                };
                v4.extend(v6);
                (v4, ttl)
            }
            // One family failed. Keep the other one only if it has addresses,
            // otherwise an empty answer would hide the failure.
            (Ok(answer), Err(_err)) | (Err(_err), Ok(answer)) if !answer.0.is_empty() => {
                debug!("DoH lookup of {} partially failed: {}", host, _err);
                answer
            }
            (Ok(_), Err(err)) | (Err(err), Ok(_)) | (Err(err), Err(_)) => return Err(err),
        };

        let ttl = if addrs.is_empty() {
            ttl.min(DEFAULT_NEGATIVE_TTL)
        } else {
            ttl.clamp(self.inner.min_ttl, self.inner.max_ttl)
        };

        Ok(Lookup {
            addrs: addrs.into(),
            expires: Instant::now() + ttl,
        })
    }

    async fn exchange(
        &self,
        name: DnsName,
        record_type: RecordType,
    ) -> Result<(Vec<IpAddr>, Duration), BoxError> {
        // RFC 8484 section 4.1: use ID 0 so responses are cache friendly.
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, record_type));
        let body = request.to_vec()?;

        let response = self
            .inner
            .client
            .post(&self.inner.endpoint)
            .header(header::CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE))
            .header(header::ACCEPT, HeaderValue::from_static(DNS_MESSAGE))
            .timeout(self.inner.timeout)
            .body(body)
            .send()
            .await?;

        if response.status() != StatusCode::OK {
            return Err(format!("DoH server returned status {}", response.status()).into());
        }

        let body = read_limited(response).await?;
        let message = Message::from_vec(&body)?;
        parse_answer(&message, record_type)
    }
}

impl Resolve for DohResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.clone();
        Box::pin(async move {
            let lookup = match (
                resolver.lookup(name.as_str()).await,
                &resolver.inner.fallback,
            ) {
                (Ok(lookup), _) => lookup,
                // Only fall back when DoH itself failed. A valid "no such name"
                // answer is returned as-is, and fallback results are not cached.
                (Err(_err), Some(fallback)) => {
                    debug!("DoH lookup of {} failed, using system DNS: {}", name, _err);
                    return fallback.resolve(name).await;
                }
                (Err(err), None) => return Err(err),
            };
            if lookup.addrs.is_empty() {
                return Err(format!("no addresses found for {name}").into());
            }

            let addrs: Addrs = Box::new(
                lookup
                    .addrs
                    .iter()
                    .map(|ip| SocketAddr::new(*ip, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}

impl fmt::Debug for DohResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohResolver")
            .field("endpoint", &self.inner.endpoint)
            .finish()
    }
}

async fn read_limited(response: crate::Response) -> Result<Bytes, BoxError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_MESSAGE_LEN as u64)
    {
        return Err("DoH response is too large".into());
    }

    let body = response.bytes().await?;
    if body.len() > MAX_MESSAGE_LEN {
        return Err("DoH response is too large".into());
    }
    Ok(body)
}

fn parse_answer(
    message: &Message,
    record_type: RecordType,
) -> Result<(Vec<IpAddr>, Duration), BoxError> {
    let metadata = &message.metadata;
    if metadata.message_type != MessageType::Response || metadata.id != 0 {
        return Err("DoH server returned an unexpected message".into());
    }

    match metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        code => return Err(format!("DoH server returned {code}").into()),
    }

    let mut ttl = u32::MAX;
    let mut addrs = Vec::new();
    for record in &message.answers {
        let ip = match (&record.data, record_type) {
            (RData::A(a), RecordType::A) => IpAddr::V4(a.0),
            (RData::AAAA(aaaa), RecordType::AAAA) => IpAddr::V6(aaaa.0),
            _ => continue,
        };
        ttl = ttl.min(record.ttl);
        addrs.push(ip);
    }

    if addrs.is_empty() {
        // RFC 2308 section 5: negative answers live for min(SOA TTL, SOA MINIMUM).
        ttl = message
            .authorities
            .iter()
            .find_map(|record| match &record.data {
                RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                _ => None,
            })
            .unwrap_or(0);
    }

    Ok((addrs, Duration::from_secs(u64::from(ttl))))
}

// ===== impl DohResolverBuilder =====

impl DohResolverBuilder {
    /// Sets the URL of the DoH service, for example `https://dns.example/dns-query`.
    #[inline]
    pub fn endpoint<U: IntoUri>(mut self, endpoint: U) -> Self {
        self.endpoint = Some(endpoint.into_uri());
        self
    }

    /// Sets the addresses used to reach the DoH server.
    ///
    /// When set, the endpoint host is never looked up. Without it, the host is
    /// resolved with the system resolver, which sends that one name in plain text.
    #[inline]
    pub fn bootstrap<I>(mut self, addrs: I) -> Self
    where
        I: IntoIterator<Item = IpAddr>,
    {
        self.bootstrap = addrs.into_iter().collect();
        self
    }

    /// Uses `builder` to create the client that talks to the DoH server.
    ///
    /// Use this to set an emulation profile, a proxy, or TLS options for DNS
    /// traffic. Do not give it a resolver that depends on this one.
    #[inline]
    pub fn client_builder(mut self, builder: ClientBuilder) -> Self {
        self.client = Some(builder);
        self
    }

    /// Sets the timeout for a single DoH request. Defaults to 5 seconds.
    #[inline]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the lower bound for cached record lifetimes. Defaults to 0.
    #[inline]
    pub fn min_ttl(mut self, ttl: Duration) -> Self {
        self.min_ttl = ttl;
        self
    }

    /// Sets the upper bound for cached record lifetimes. Defaults to 1 day.
    #[inline]
    pub fn max_ttl(mut self, ttl: Duration) -> Self {
        self.max_ttl = ttl;
        self
    }

    /// Sets how many names are cached. `0` disables the cache. Defaults to 256.
    #[inline]
    pub fn cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }

    /// Disables falling back to the system resolver when a DoH query fails.
    ///
    /// By default a failed query (network error, timeout, HTTP error or a DNS
    /// server failure) is retried with the system resolver, which sends the
    /// name in plain text. In strict mode the error is returned instead.
    #[inline]
    pub fn strict(mut self, enabled: bool) -> Self {
        self.strict = enabled;
        self
    }

    /// Builds the resolver.
    ///
    /// # Errors
    ///
    /// Fails if the endpoint is missing or is not a valid `http` or `https` URL, or if the
    /// internal client cannot be built.
    pub fn build(self) -> crate::Result<DohResolver> {
        let endpoint = self
            .endpoint
            .ok_or_else(|| crate::Error::builder("DoH endpoint is not set"))??;
        if !matches!(endpoint.scheme_str(), Some("https" | "http")) {
            return Err(crate::Error::uri_bad_scheme(endpoint));
        }
        if self.min_ttl > self.max_ttl {
            return Err(crate::Error::builder("DoH min_ttl is greater than max_ttl"));
        }

        let mut builder = self.client.unwrap_or_else(Client::builder);
        if !self.bootstrap.is_empty() {
            let host = endpoint
                .host()
                .map(crate::util::strip_ipv6_brackets)
                .ok_or_else(|| crate::Error::builder("DoH endpoint is missing a host"))?
                .to_owned();
            let addrs = self.bootstrap.iter().map(|ip| SocketAddr::new(*ip, 0));
            builder = builder.resolve_to_addrs(host, addrs);
        }

        let cache = NonZeroUsize::new(self.cache_size).map(|n| Mutex::new(LruCache::new(n)));

        Ok(DohResolver {
            inner: Arc::new(Inner {
                client: builder.build()?,
                endpoint,
                timeout: self.timeout,
                min_ttl: self.min_ttl,
                max_ttl: self.max_ttl,
                cache,
                fallback: (!self.strict).then(GaiResolver::new),
            }),
        })
    }
}

impl fmt::Debug for DohResolverBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohResolverBuilder")
            .field(
                "endpoint",
                &self.endpoint.as_ref().and_then(|e| e.as_ref().ok()),
            )
            .field("bootstrap", &self.bootstrap)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use hickory_proto::rr::{
        Record,
        rdata::{A, CNAME, SOA},
    };

    use super::*;

    fn response(code: ResponseCode) -> Message {
        let mut message = Message::response(0, OpCode::Query);
        message.metadata.response_code = code;
        message
    }

    fn name(s: &str) -> DnsName {
        DnsName::from_ascii(s).unwrap()
    }

    #[test]
    fn parse_answer_follows_cname_and_uses_min_ttl() {
        let mut message = response(ResponseCode::NoError);
        message.add_answer(Record::from_rdata(
            name("www.example.com."),
            600,
            RData::CNAME(CNAME(name("example.com."))),
        ));
        message.add_answer(Record::from_rdata(
            name("example.com."),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        message.add_answer(Record::from_rdata(
            name("example.com."),
            120,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));

        let (addrs, ttl) = parse_answer(&message, RecordType::A).unwrap();
        assert_eq!(
            addrs,
            [
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            ]
        );
        assert_eq!(ttl, Duration::from_secs(120));
    }

    #[test]
    fn parse_answer_negative_ttl_from_soa() {
        let mut message = response(ResponseCode::NXDomain);
        message.add_authority(Record::from_rdata(
            name("example.com."),
            900,
            RData::SOA(SOA::new(
                name("ns.example.com."),
                name("admin.example.com."),
                1,
                3600,
                600,
                86400,
                60,
            )),
        ));

        let (addrs, ttl) = parse_answer(&message, RecordType::A).unwrap();
        assert!(addrs.is_empty());
        assert_eq!(ttl, Duration::from_secs(60));
    }

    #[test]
    fn parse_answer_rejects_server_failure() {
        let message = response(ResponseCode::ServFail);
        assert!(parse_answer(&message, RecordType::A).is_err());
    }
}
