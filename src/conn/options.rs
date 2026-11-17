//! Request overrides used to select and establish compatible connections.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use derive_deftly::{Deftly, define_derive_deftly};

#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    config::connect::ConnectConfig, group::Group, http1::Http1Options, protocol::Protocol,
    proxy::Matcher, tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

define_derive_deftly! {
    /// Reads applicable overrides and reconstructs the connector's configuration.
    ConnectOverrides for struct:
    ${define APPLIES {
        ${select1
            fmeta(overrides(stream)) {
                cfg_select! {
                    feature = "http3" => protocol != Protocol::Http3,
                    _ => true,
                }
            }
            fmeta(overrides(http1)) { matches!(protocol, Protocol::Auto | Protocol::Http1) }
            fmeta(overrides(http2)) { matches!(protocol, Protocol::Auto | Protocol::Http2) }
            fmeta(overrides(http3)) { protocol == Protocol::Http3 }
        }
    }}

    ${define READ_OVERRIDE {
        overrides.get_arc_ref()
            .filter(|value| base.get_arc_ref() != Some(*value))
            .cloned()
    }}

    impl $ttype {
        pub(crate) fn new(
            ${if tmeta(overrides(protocol)) { protocol: Protocol, }}
            overrides: &ConnectConfig,
            base: &ConnectConfig,
        ) -> Self {
            Self {
                ${for fields {
                    $fname: ${if fmeta(overrides(flatten)) {
                        <$ftype>::new(overrides, base)
                    } else if tmeta(overrides(protocol)) {
                        if $APPLIES {
                            $READ_OVERRIDE
                        } else {
                            None
                        }
                    } else {
                        $READ_OVERRIDE
                    }},
                }}
            }
        }

        fn insert_into(self, config: &mut ConnectConfig) {
            ${for fields {
                ${if fmeta(overrides(flatten)) {
                    self.$fname.insert_into(config);
                } else {
                    if let Some(value) = self.$fname {
                        config.insert_arc(value);
                    }
                }}
            }}
        }

        ${if tmeta(overrides(protocol)) {
            /// Materializes the connector request when a checkout needs a new connection.
            pub(crate) fn into_config(self) -> ConnectConfig {
                let mut config = ConnectConfig::default();
                self.insert_into(&mut config);
                config
            }
        }}
    }
}

macro_rules! connect_options {
    (
        common { $($common:ident: $common_ty:ty),* $(,)? }
        protocol {
            $($(#[$attr:meta])* $vis:vis $field:ident: $ty:ty => $target:ident),* $(,)?
        }
    ) => {
        /// Overrides that partition both live connections and TLS sessions.
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Deftly)]
        #[derive_deftly(ConnectOverrides)]
        pub(crate) struct CommonOptions {
            $($common: Option<Arc<$common_ty>>,)*
        }

        /// The pool key and the connector use the same protocol-specific overrides.
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Deftly)]
        #[derive_deftly(ConnectOverrides)]
        #[deftly(overrides(protocol))]
        pub(crate) struct Options {
            #[deftly(overrides(flatten))]
            common: CommonOptions,
            $(
                $(#[$attr])*
                #[deftly(overrides($target))]
                $vis $field: Option<Arc<$ty>>,
            )*
        }
    };
}

connect_options! {
    common {
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        interface: Arc<str>,
        proxy: Matcher,
        group: Group,
    }
    protocol {
        tls: TlsOptions => stream,
        pub(crate) http1: Http1Options => http1,
        #[cfg(feature = "http2")]
        pub(crate) http2: Http2Options => http2,
        #[cfg(feature = "http3")]
        pub(crate) http3: Http3Options => http3,
        #[cfg(feature = "http3")]
        quic: QuicOptions => http3,
    }
}
