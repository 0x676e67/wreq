//! DNS resolution via the [hickory-resolver](https://github.com/hickory-dns/hickory-dns) crate
//!
//! ## Fork safety
//!
//! `TokioResolver` binds to the Tokio runtime that was active when it was
//! created. A plain `static LazyLock` would survive `fork(2)` already
//! initialized, but its runtime handle would point at the parent's dead
//! worker threads — every lookup would hang until the connect timeout.
//!
//! We tag the cached resolver with the PID that built it. `shared_resolver()`
//! rebuilds a fresh resolver whenever it sees a different PID (we are in a
//! forked child that has already built a new Tokio runtime). The inherited
//! resolver is `mem::forget`-ed rather than dropped — its sockets are
//! registered in the parent's (dead) I/O driver, and running `Drop` against
//! a dead reactor could panic or hang (same reasoning as the runtime hook in
//! wreq-php's `runtime.rs`).
//!
//! ## Locking trade-off
//!
//! The previous `LazyLock` was lock-free after initialization. This
//! replacement takes a short `Mutex` lock on every `resolve()` call (lock →
//! PID check → `Arc::clone` → unlock). The critical section is microscopic
//! (no I/O on the fast path), so contention is negligible even under heavy
//! concurrent DNS load. An `ArcSwap` + atomic PID check would remove the
//! lock entirely, but the added complexity is not justified for a resolver
//! that is typically called once per connection, not once per packet.

use std::{
    mem,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use hickory_resolver::{
    TokioResolver,
    config::{self, LookupIpStrategy, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};

use super::{Addrs, Name, Resolve, Resolving};

/// Process-global DNS resolver, tagged with the PID that built it.
/// See the module-level "Fork safety" note.
static RESOLVER: Mutex<Option<(u32, Arc<TokioResolver>)>> = Mutex::new(None);

/// Returns a shared reference to the process-global `TokioResolver`, building
/// it on first use and rebuilding after a `fork` (PID mismatch).
///
/// Must be called from within a Tokio runtime context (inside `block_on`),
/// because `TokioResolver::builder_tokio()` captures the current runtime
/// handle.
fn shared_resolver() -> Arc<TokioResolver> {
    let pid = std::process::id();
    // Poison-resilient: if a previous build() panicked under the guard,
    // recover the inner value rather than aborting every subsequent lookup.
    let mut guard = RESOLVER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match guard.as_ref() {
        Some((owner, resolver)) if *owner == pid => return Arc::clone(resolver),
        // Inherited across a fork: the resolver's sockets are registered in
        // the parent's I/O driver, which is dead here. Abandon it without
        // running Drop (same pattern as the runtime fork-safety hook).
        Some(_) => {
            if let Some((_, stale)) = guard.take() {
                mem::forget(stale);
            }
        }
        None => {}
    }

    let resolver = Arc::new(build());
    *guard = Some((pid, Arc::clone(&resolver)));
    resolver
}

fn build() -> TokioResolver {
    let mut builder = match TokioResolver::builder_tokio() {
        Ok(resolver) => {
            debug!("using system DNS configuration");
            resolver
        }
        Err(_err) => {
            debug!("error reading DNS system conf: {}, using defaults", _err);
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&config::GOOGLE),
                TokioRuntimeProvider::default(),
            )
        }
    };
    builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    builder.build().expect("failed to create DNS resolver")
}

/// Wrapper around a shared [`TokioResolver`], which implements the [`Resolve`] trait.
///
/// Stateless handle — the actual resolver is a process-global singleton
/// (see [`shared_resolver`]) that is rebuilt automatically after `fork`.
#[derive(Debug, Clone)]
pub struct HickoryDnsResolver {
    _priv: (),
}

impl HickoryDnsResolver {
    /// Create a new resolver with the default configuration,
    /// which reads from `/etc/resolv.conf`. The options are
    /// overridden to look up both IPv4 and IPv6 addresses
    /// to support the "happy eyeballs" algorithm.
    ///
    /// SAFETY: `build` only fails if DNS-over-TLS is enabled and default TLS config creation fails.
    pub fn new() -> HickoryDnsResolver {
        HickoryDnsResolver { _priv: () }
    }
}

impl Resolve for HickoryDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let resolver = shared_resolver();
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            let addrs: Addrs = Box::new(
                lookup
                    .iter()
                    .map(|ip_addr| SocketAddr::new(ip_addr, 0))
                    .collect::<Vec<_>>()
                    .into_iter(),
            );
            Ok(addrs)
        })
    }
}
