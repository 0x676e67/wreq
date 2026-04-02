use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use h3::client::SendRequest;
use h3_quinn::{Connection, OpenStreams};
use http::Uri;
use quinn::Endpoint;
use quinn_proto::{ConnectionIdGenerator, RandomConnectionIdGenerator, TransportConfig, VarInt};
use tower::BoxError;

use super::dns;
use crate::client::core::http3::Http3Options;
use crate::dns::DynResolver;
use crate::tls::TlsOptions;
use crate::tls::keylog::KeyLog;
use crate::tls::trust::{CertStore, Identity};

type H3Connection = (
    h3::client::Connection<Connection, Bytes>,
    SendRequest<OpenStreams, Bytes>,
);

/// Configuration passed to `h3::client::builder()` on each new connection.
#[derive(Clone)]
struct H3BuilderConfig {
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
    max_field_section_size: Option<u64>,
    enable_connect_protocol: Option<bool>,
    enable_datagram: Option<bool>,
    send_grease: Option<bool>,
    settings_order: Option<Vec<h3::SettingId>>,
    extra_settings: Option<Vec<(h3::SettingId, u64)>>,
}

#[derive(Clone)]
pub(crate) struct H3Connector {
    resolver: DynResolver,
    endpoint: Endpoint,
    h3_builder_config: H3BuilderConfig,
    pseudo_header_order: Option<h3::PseudoOrder>,
}

impl H3Connector {
    pub(crate) fn new(
        resolver: DynResolver,
        local_addr: Option<IpAddr>,
        tls_options: Option<&TlsOptions>,
        http3_options: Option<&Http3Options>,
        cert_store: &CertStore,
        cert_verification: bool,
        identity: Option<&Identity>,
        keylog: Option<&KeyLog>,
    ) -> Result<H3Connector, BoxError> {
        use btls::ssl::{SslContextBuilder, SslMethod};

        let h3opts = http3_options;
        let tls_defaults = TlsOptions::default();
        let tls = tls_options.unwrap_or(&tls_defaults);

        // ===== TLS setup via btls =====
        let mut builder = SslContextBuilder::new(SslMethod::tls())?;

        // Certificate store
        cert_store.add_to_ssl_ctx(&mut builder);

        if !cert_verification {
            builder.set_verify(btls::ssl::SslVerifyMode::NONE);
        }

        // Identity (client certificate)
        if let Some(identity) = identity {
            identity.add_to_tls(&mut builder)?;
        }

        // Apply shared TLS context options (ciphers, curves, extensions, etc.)
        crate::tls::ctx::apply_tls_context_options(&mut builder, tls, h3opts)?;

        // Keylog
        if let Some(policy) = keylog {
            let handle = policy.clone().handle()?;
            builder.set_keylog_callback(move |_, line| {
                handle.write(line);
            });
        }

        // Build quinn-btls client config
        let mut client_crypto = quinn_btls::ClientConfig::from_builder(builder)?;

        // Per-session settings
        {
            let settings = client_crypto.session_settings_mut();

            if let Some(alps) = h3opts.and_then(|o| o.quic_alps_protocols.as_ref()) {
                settings.alps_protocols = alps.clone();
            }

            if let Some(new_cp) = h3opts.and_then(|o| o.quic_alps_use_new_codepoint) {
                settings.alps_use_new_codepoint = new_cp;
            }

            if let Some(ech) = h3opts.and_then(|o| o.quic_ech_grease) {
                settings.enable_ech_grease = ech;
            } else {
                settings.enable_ech_grease = tls.enable_ech_grease;
            }
        }

        // ===== QUIC Transport Config =====
        let mut transport_config = TransportConfig::default();

        if let Some(opts) = h3opts {
            if let Some(ms) = opts.max_idle_timeout {
                transport_config.max_idle_timeout(Some(VarInt::from_u32(ms as u32).into()));
            }
            if let Some(val) = opts.conn_receive_window {
                transport_config.receive_window(VarInt::from_u32(val));
            }
            if let Some(val) = opts.stream_receive_window {
                transport_config.stream_receive_window(VarInt::from_u32(val));
            }
            if let Some(val) = opts.max_concurrent_bidi_streams {
                transport_config.max_concurrent_bidi_streams(VarInt::from_u32(val));
            }
            if let Some(val) = opts.max_concurrent_uni_streams {
                transport_config.max_concurrent_uni_streams(VarInt::from_u32(val));
            }
            if let Some(val) = opts.datagram_receive_buffer_size {
                transport_config.datagram_receive_buffer_size(Some(val));
            }
            if let Some(val) = opts.send_window {
                transport_config.send_window(val);
            }
            if let Some(ref config) = opts.transport_parameter_config {
                transport_config.transport_parameter_config(config.clone());
            }
        }

        // ===== Quinn Client Config =====
        let mut quinn_client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        quinn_client_config.transport_config(Arc::new(transport_config));

        if let Some(len) = h3opts.and_then(|o| o.initial_dst_cid_length) {
            quinn_client_config.initial_dst_cid_provider(Arc::new(move || {
                RandomConnectionIdGenerator::new(len).generate_cid()
            }));
        }

        // ===== Endpoint Config =====
        let mut endpoint_config = quinn_btls::helpers::default_endpoint_config();

        if let Some(opts) = h3opts {
            if let Some(cid_len) = opts.connection_id_length {
                endpoint_config
                    .cid_generator(move || Box::new(RandomConnectionIdGenerator::new(cid_len)));
            }
            if let Some(grease) = opts.grease_quic_bit {
                endpoint_config.grease_quic_bit(grease);
            }
        }

        // ===== Create Endpoint =====
        let socket_addr = match local_addr {
            Some(ip) => SocketAddr::new(ip, 0),
            None => "[::]:0".parse::<SocketAddr>().unwrap(),
        };

        let socket = std::net::UdpSocket::bind(socket_addr)?;

        let endpoint = Endpoint::new(
            endpoint_config,
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(quinn_client_config);

        // ===== H3 Builder Config =====
        let h3_builder_config = H3BuilderConfig {
            qpack_max_table_capacity: h3opts.and_then(|o| o.qpack_max_table_capacity),
            qpack_blocked_streams: h3opts.and_then(|o| o.qpack_blocked_streams),
            max_field_section_size: h3opts.and_then(|o| o.max_field_section_size),
            enable_connect_protocol: h3opts.and_then(|o| o.enable_connect_protocol),
            enable_datagram: h3opts.and_then(|o| o.enable_datagram),
            send_grease: h3opts.and_then(|o| o.send_grease),
            settings_order: h3opts.and_then(|o| o.settings_order.clone()),
            extra_settings: h3opts.and_then(|o| o.extra_settings.clone()),
        };

        let pseudo_header_order = h3opts.and_then(|o| o.pseudo_header_order.clone());

        Ok(Self {
            resolver,
            endpoint,
            h3_builder_config,
            pseudo_header_order,
        })
    }

    pub(crate) fn pseudo_header_order(&self) -> Option<h3::PseudoOrder> {
        self.pseudo_header_order.clone()
    }

    pub(crate) async fn connect(&mut self, dest: Uri) -> Result<H3Connection, BoxError> {
        let host = dest
            .host()
            .ok_or("destination must have a host")?
            .trim_start_matches('[')
            .trim_end_matches(']');
        let port = dest.port_u16().unwrap_or(443);

        let addrs = if let Ok(addr) = IpAddr::from_str(host) {
            vec![SocketAddr::new(addr, port)]
        } else {
            let name = dns::name_from_str(host);
            let addrs = dns::resolve(&mut self.resolver, name).await?;
            let addrs = addrs.map(|mut addr| {
                addr.set_port(port);
                addr
            });
            addrs.collect()
        };

        self.remote_connect(addrs, host).await
    }

    async fn remote_connect(
        &mut self,
        addrs: Vec<SocketAddr>,
        server_name: &str,
    ) -> Result<H3Connection, BoxError> {
        let mut err = None;
        for addr in addrs {
            match self.endpoint.connect(addr, server_name)?.await {
                Ok(new_conn) => {
                    let quinn_conn = Connection::new(new_conn);
                    let mut h3_builder = h3::client::builder();

                    // Apply h3 builder config
                    let cfg = &self.h3_builder_config;
                    if let Some(val) = cfg.qpack_max_table_capacity {
                        h3_builder.qpack_max_table_capacity(val);
                    }
                    if let Some(val) = cfg.qpack_blocked_streams {
                        h3_builder.qpack_blocked_streams(val);
                    }
                    if let Some(val) = cfg.max_field_section_size {
                        h3_builder.max_field_section_size(val);
                    }
                    if let Some(val) = cfg.enable_connect_protocol {
                        h3_builder.enable_extended_connect(val);
                    }
                    if let Some(val) = cfg.enable_datagram {
                        h3_builder.enable_datagram(val);
                    }
                    if let Some(val) = cfg.send_grease {
                        h3_builder.send_grease(val);
                    }
                    if let Some(ref order) = cfg.settings_order {
                        h3_builder.settings_order(order.clone());
                    }
                    if let Some(ref extras) = cfg.extra_settings {
                        for &(id, val) in extras {
                            h3_builder.extra_setting(id, val);
                        }
                    }

                    return Ok(h3_builder.build(quinn_conn).await?);
                }
                Err(e) => err = Some(e),
            }
        }

        match err {
            Some(e) => Err(Box::new(e) as BoxError),
            None => Err("failed to establish connection for HTTP/3 request".into()),
        }
    }
}
