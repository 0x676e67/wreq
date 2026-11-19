//! Session ticket resumption for QUIC connections.

use std::{
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use ::quic::crypto::btls::SessionCache;
use btls::{
    asn1::{Asn1Time, TimeDiff},
    ssl::SslSession,
    x509::X509StoreContextRef,
};
use bytes::Bytes;
use http::Uri;
use zeroize::Zeroizing;

use super::QuicOptions;
use crate::{
    Error, Result,
    config::ConnectConfig,
    sync::Mutex,
    tls::session::{Key, Ticket as StoredTicket, Tickets},
};

/// Session ticket store handle scoped to a QUIC connection's identity.
///
/// Shared across all address attempts of a dial; each attempt builds an [`Attempt`] adapter
/// that pops and stores tickets under this key.
pub(super) struct Resumption {
    tickets: Arc<Tickets>,
    key: Key,
}

/// Serialized QUIC session state paired with the peer certificate chain's earliest expiry.
///
/// Stored as the opaque payload of a [`StoredTicket`] so expired peer chains are skipped
/// before offering a ticket when certificate verification is enabled.
#[derive(Clone)]
struct Ticket {
    state: Zeroizing<Vec<u8>>,
    not_after: Option<i64>,
}

/// Per-attempt [`SessionCache`] adapter.
///
/// Pops its own ticket before acquiring the endpoint lock so concurrent address attempts
/// do not share a single-use TLS 1.3 ticket
/// ([RFC 8446 Appendix C.4](https://www.rfc-editor.org/rfc/rfc8446#appendix-C.4)).
pub(super) struct Attempt {
    resumption: Arc<Resumption>,
    ticket: Mutex<Option<Zeroizing<Vec<u8>>>>,
    not_after: OnceLock<i64>,
}

// ===== impl Resumption =====

impl Resumption {
    /// Creates a resumption handle scoped to this origin, TLS peer, and request options.
    pub(super) fn new(
        tickets: &Arc<Tickets>,
        origin: &Uri,
        peer: &Uri,
        connect_config: &ConnectConfig,
    ) -> Result<Self> {
        let key = tickets
            .key::<QuicOptions, Ticket>(origin, peer, connect_config)
            .map_err(Error::tls)?;
        Ok(Self {
            tickets: tickets.clone(),
            key,
        })
    }

    /// Pops a ticket for a handshake attempt, skipping expired certificate chains when
    /// peer verification is enabled.
    #[must_use]
    fn take(&self, verify_peer: bool) -> Option<Zeroizing<Vec<u8>>> {
        let StoredTicket::Opaque { payload, .. } = self.tickets.pop(&self.key)? else {
            return None;
        };
        let ticket = payload.downcast::<Ticket>().ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|now| i64::try_from(now.as_secs()).ok());
        let expired =
            matches!((ticket.not_after, now), (Some(not_after), Some(now)) if now >= not_after);
        (!(verify_peer && expired)).then(|| Arc::unwrap_or_clone(ticket).state)
    }

    fn put(&self, session: SslSession, ticket: Ticket) {
        self.tickets.put(
            self.key.clone(),
            StoredTicket::Opaque {
                session,
                payload: Arc::new(ticket),
            },
        );
    }
}

// ===== impl Attempt =====

impl Attempt {
    /// Pops a ticket for this attempt before entering the endpoint lock.
    #[must_use]
    pub(super) fn new(resumption: &Arc<Resumption>, verify_peer: bool) -> Self {
        Self {
            resumption: resumption.clone(),
            ticket: Mutex::new(resumption.take(verify_peer)),
            not_after: OnceLock::new(),
        }
    }

    /// Records the earliest `notAfter` timestamp in the verified certificate chain.
    pub(super) fn verified(&self, ok: bool, ctx: &X509StoreContextRef) {
        if !ok || ctx.error_depth() != 0 {
            return;
        }

        if let Some(not_after) = ctx.chain().and_then(|chain| {
            let epoch = Asn1Time::from_unix(0).ok()?;
            chain
                .iter()
                .filter_map(|cert| {
                    let TimeDiff { days, secs } = epoch.diff(cert.not_after()).ok()?;
                    Some(i64::from(days) * 86_400 + i64::from(secs))
                })
                .min()
        }) {
            let _ = self.not_after.set(not_after);
        }
    }
}

impl SessionCache for Attempt {
    fn put(&self, _key: Bytes, state: Zeroizing<Vec<u8>>, session: SslSession) {
        // Without a verified path every certificate the server sent counts.
        let not_after = self
            .not_after
            .get()
            .copied()
            .or_else(|| session.peer_chain_not_after());
        self.resumption.put(session, Ticket { state, not_after });
    }

    fn take(&self, _key: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        self.ticket.lock().take()
    }

    fn remove(&self, _key: &[u8]) {
        // A failed handshake has already consumed its ticket.
    }

    fn clear(&self) {
        // This adapter holds no shared tickets to clear.
    }
}

#[cfg(test)]
mod tests {
    use btls::ssl::ClientSession;

    use super::*;
    use crate::tls::TlsOptions;

    #[test]
    fn ticket_identity_uses_only_the_adapter_session_options() {
        let tickets = Tickets::new(None);
        let origin = Uri::from_static("https://example.com/");
        let mut config = ConnectConfig::default();
        let quic_key = |config: &ConnectConfig| {
            tickets
                .key::<QuicOptions, Ticket>(&origin, &origin, config)
                .unwrap()
        };
        let native_key = |config: &ConnectConfig| {
            tickets
                .key::<TlsOptions, ClientSession>(&origin, &origin, config)
                .unwrap()
        };
        let quic = quic_key(&config);
        let native = native_key(&config);
        assert!(quic != native);

        let mut stream_config = ConnectConfig::default();
        stream_config.insert(TlsOptions::builder().key_shares(Vec::new()).build());
        assert!(quic == quic_key(&stream_config));

        let options = QuicOptions::builder().pre_shared_key(true);
        config.insert(options.clone().build());
        assert!(native == native_key(&config));
        let resumed = quic_key(&config);
        assert!(quic != resumed);

        config.insert(
            options
                .clone()
                .initial_mtu(1280)
                .enable_alps_protocol(true)
                .build(),
        );
        assert!(resumed == quic_key(&config));

        config.insert(options.key_shares(Vec::new()).build());
        assert!(resumed != quic_key(&config));
    }
}
