//! Connection identities projected from client and request configuration.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use derive_deftly::{Deftly, define_derive_deftly};
use http::Uri;

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    config::connect::ConnectConfig, group::Group, http1::Http1Options, protocol::Protocol,
    proxy::Matcher, tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

define_derive_deftly! {
    /// Generates reuse identities from their shared field list.
    ConnectIdentities for struct:
    ${defcond PROTOCOL_FIELD fmeta(identity)}
    ${define FIELD {
        $fvis $fname: Option<Arc<$ftype>>,
    }}
    ${define APPLIES {
        ${select1
            fmeta(identity(stream)) {
                cfg_select! {
                    feature = "http3" => protocol != Protocol::Http3,
                    _ => true,
                }
            }
            fmeta(identity(http1)) { matches!(protocol, Protocol::Auto | Protocol::Http1) }
            fmeta(identity(http2)) { matches!(protocol, Protocol::Auto | Protocol::Http2) }
            fmeta(identity(http3)) { protocol == Protocol::Http3 }
        }
    }}
    ${define READ_OVERRIDE {
        connect_config.override_if_different(PartialEq::eq)
            .cloned()
    }}
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct CommonIdentity {
        ${for fields { ${when not(PROTOCOL_FIELD)} $FIELD }}
    }
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct Identity {
        pub(crate) origin: Uri,
        pub(crate) protocol: Protocol,
        common: CommonIdentity,
        ${for fields { ${when PROTOCOL_FIELD} $FIELD }}
    }
    impl CommonIdentity {
        pub(crate) fn new(connect_config: &ConnectConfig) -> Self {
            Self {
                ${for fields { ${when not(PROTOCOL_FIELD)} $fname: $READ_OVERRIDE, }}
            }
        }
    }
    impl Identity {
        pub(crate) fn new(
            origin: Uri,
            protocol: Protocol,
            connect_config: &ConnectConfig,
        ) -> Self {
            Self {
                origin,
                protocol,
                common: CommonIdentity::new(connect_config),
                ${for fields {
                    ${when PROTOCOL_FIELD}
                    $fname: if $APPLIES { $READ_OVERRIDE } else { None },
                }}
            }
        }
    }
}

// Unmarked fields are shared by the connection pool and TLS session keys.
#[allow(dead_code)]
#[derive(Deftly)]
#[derive_deftly(ConnectIdentities)]
struct IdentityFields {
    group: Group,
    proxy: Matcher,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
    interface: Arc<str>,

    #[deftly(identity(stream))]
    tls: TlsOptions,
    #[deftly(identity(http1))]
    pub(crate) http1: Http1Options,
    #[cfg(feature = "http2")]
    #[deftly(identity(http2))]
    pub(crate) http2: Http2Options,
    #[cfg(feature = "http3")]
    #[deftly(identity(http3))]
    pub(crate) http3: Http3Options,
    #[cfg(feature = "http3")]
    #[deftly(identity(http3))]
    quic: QuicOptions,
}
