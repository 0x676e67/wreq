//! Re-export the `http2` module for HTTP/2 frame types and utilities.

use std::time::Duration;

use http2::frame::ExperimentalSettings;
pub use http2::frame::{
    Priorities, PrioritiesBuilder, Priority, PseudoId, PseudoOrder, Setting, SettingId,
    SettingsOrder, SettingsOrderBuilder, StreamDependency, StreamId,
};

use super::super::proto;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
const DEFAULT_CONN_WINDOW_SIZE: u32 = 1024 * 1024 * 5; // 5mb
const DEFAULT_WINDOW_SIZE: u32 = 1024 * 1024 * 2; // 2mb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 1024; // 1mb

// The maximum number of concurrent streams that the client is allowed to open
// before it receives the initial SETTINGS frame from the server.
// This default value is derived from what the HTTP/2 spec recommends as the
// minimum value that endpoints advertise to their peers. It means that using
// this value will minimize the chance of the failure where the local endpoint
// attempts to open too many streams and gets rejected by the remote peer with
// the `REFUSED_STREAM` error.
const DEFAULT_INITIAL_MAX_SEND_STREAMS: usize = 100;

/// Builder for `Http2Options`.
#[must_use]
#[derive(Debug)]
pub struct Http2OptionsBuilder {
    opts: Http2Options,
}

/// Configuration config for an HTTP/2 connection.
///
/// This struct defines various parameters to fine-tune the behavior of an HTTP/2 connection,
/// including stream management, window sizes, frame limits, and header config.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Http2Options {
    pub(crate) adaptive_window: bool,
    pub(crate) initial_stream_id: Option<u32>,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_window_size: u32,
    pub(crate) initial_max_send_streams: usize,
    pub(crate) max_frame_size: Option<u32>,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) keep_alive_while_idle: bool,
    pub(crate) max_concurrent_reset_streams: Option<usize>,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) max_header_list_size: Option<u32>,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) enable_push: Option<bool>,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) enable_connect_protocol: Option<bool>,
    pub(crate) no_rfc7540_priorities: Option<bool>,
    pub(crate) headers_pseudo_order: Option<PseudoOrder>,
    pub(crate) headers_stream_dependency: Option<StreamDependency>,
    pub(crate) experimental_settings: Option<ExperimentalSettings>,
    pub(crate) settings_order: Option<SettingsOrder>,
    pub(crate) priorities: Option<Priorities>,
}

impl Http2OptionsBuilder {
    /// Sets the [`SETTINGS_INITIAL_WINDOW_SIZE`][spec] option for HTTP2
    /// stream-level flow control.
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, crate::core: will use a default.
    ///
    /// [spec]: https://httpwg.org/specs/rfc9113.html#SETTINGS_INITIAL_WINDOW_SIZE
    pub fn initial_window_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.adaptive_window = false;
            self.opts.initial_window_size = sz;
        }
        self
    }

    /// Sets the max connection-level flow control for HTTP2
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, crate::core: will use a default.
    pub fn initial_connection_window_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.adaptive_window = false;
            self.opts.initial_conn_window_size = sz;
        }
        self
    }

    /// Sets the initial maximum of locally initiated (send) streams.
    ///
    /// This value will be overwritten by the value included in the initial
    /// SETTINGS frame received from the peer as part of a [connection preface].
    ///
    /// Passing `None` will do nothing.
    ///
    /// If not set, crate::core: will use a default.
    ///
    /// [connection preface]: https://httpwg.org/specs/rfc9113.html#preface
    pub fn initial_max_send_streams(mut self, initial: impl Into<Option<usize>>) -> Self {
        if let Some(initial) = initial.into() {
            self.opts.initial_max_send_streams = initial;
        }
        self
    }

    /// Sets the initial stream id for the connection.
    pub fn initial_stream_id(mut self, id: impl Into<Option<u32>>) -> Self {
        if let Some(id) = id.into() {
            self.opts.initial_stream_id = Some(id);
        }
        self
    }

    /// Sets whether to use an adaptive flow control.
    ///
    /// Enabling this will override the limits set in
    /// `initial_stream_window_size` and
    /// `initial_connection_window_size`.
    pub fn adaptive_window(mut self, enabled: bool) -> Self {
        use proto::h2::SPEC_WINDOW_SIZE;

        self.opts.adaptive_window = enabled;
        if enabled {
            self.opts.initial_window_size = SPEC_WINDOW_SIZE;
            self.opts.initial_conn_window_size = SPEC_WINDOW_SIZE;
        }
        self
    }

    /// Sets the maximum frame size to use for HTTP2.
    ///
    /// Default is currently 16KB, but can change.
    pub fn max_frame_size(mut self, sz: impl Into<Option<u32>>) -> Self {
        if let Some(sz) = sz.into() {
            self.opts.max_frame_size = Some(sz);
        }
        self
    }

    /// Sets the max size of received header frames.
    ///
    /// Default is currently 16KB, but can change.
    pub fn max_header_list_size(mut self, max: u32) -> Self {
        self.opts.max_header_list_size = Some(max);
        self
    }

    /// Sets the header table size.
    ///
    /// This setting informs the peer of the maximum size of the header compression
    /// table used to encode header blocks, in octets. The encoder may select any value
    /// equal to or less than the header table size specified by the sender.
    ///
    /// The default value of crate `h2` is 4,096.
    pub fn header_table_size(mut self, size: impl Into<Option<u32>>) -> Self {
        if let Some(size) = size.into() {
            self.opts.header_table_size = Some(size);
        }
        self
    }

    /// Sets the maximum number of concurrent streams.
    ///
    /// The maximum concurrent streams setting only controls the maximum number
    /// of streams that can be initiated by the remote peer. In other words,
    /// when this setting is set to 100, this does not limit the number of
    /// concurrent streams that can be created by the caller.
    ///
    /// It is recommended that this value be no smaller than 100, so as to not
    /// unnecessarily limit parallelism. However, any value is legal, including
    /// 0. If `max` is set to 0, then the remote will not be permitted to
    /// initiate streams.
    ///
    /// Note that streams in the reserved state, i.e., push promises that have
    /// been reserved but the stream has not started, do not count against this
    /// setting.
    ///
    /// Also note that if the remote *does* exceed the value set here, it is not
    /// a protocol level error. Instead, the `h2` library will immediately reset
    /// the stream.
    ///
    /// See [Section 5.1.2] in the HTTP/2 spec for more details.
    ///
    /// [Section 5.1.2]: https://http2.github.io/http2-spec/#rfc.section.5.1.2
    pub fn max_concurrent_streams(mut self, max: impl Into<Option<u32>>) -> Self {
        if let Some(max) = max.into() {
            self.opts.max_concurrent_streams = Some(max);
        }
        self
    }

    /// Sets an interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    ///
    /// Pass `None` to disable HTTP2 keep-alive.
    ///
    /// Default is currently disabled.
    pub fn keep_alive_interval(&mut self, interval: impl Into<Option<Duration>>) -> &mut Self {
        self.opts.keep_alive_interval = interval.into();
        self
    }

    /// Sets a timeout for receiving an acknowledgement of the keep-alive ping.
    ///
    /// If the ping is not acknowledged within the timeout, the connection will
    /// be closed. Does nothing if `keep_alive_interval` is disabled.
    ///
    /// Default is 20 seconds.
    pub fn keep_alive_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.opts.keep_alive_timeout = timeout;
        self
    }

    /// Sets whether HTTP2 keep-alive should apply while the connection is idle.
    ///
    /// If disabled, keep-alive pings are only sent while there are open
    /// request/responses streams. If enabled, pings are also sent when no
    /// streams are active. Does nothing if `keep_alive_interval` is
    /// disabled.
    ///
    /// Default is `false`.
    pub fn keep_alive_while_idle(&mut self, enabled: bool) -> &mut Self {
        self.opts.keep_alive_while_idle = enabled;
        self
    }

    /// Enables and disables the push feature for HTTP2.
    ///
    /// Passing `None` will do nothing.
    pub fn enable_push(mut self, opt: bool) -> Self {
        self.opts.enable_push = Some(opt);
        self
    }

    /// Sets the enable connect protocol.
    pub fn enable_connect_protocol(mut self, opt: bool) -> Self {
        self.opts.enable_connect_protocol = Some(opt);
        self
    }

    /// Disable RFC 7540 Stream Priorities (set to `true` to disable).
    /// [RFC 9218]: <https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1>
    pub fn no_rfc7540_priorities(mut self, opt: bool) -> Self {
        self.opts.no_rfc7540_priorities = Some(opt);
        self
    }

    /// Sets the maximum number of HTTP2 concurrent locally reset streams.
    ///
    /// See the documentation of [`http2::client::Builder::max_concurrent_reset_streams`] for more
    /// details.
    ///
    /// The default value is determined by the `h2` crate.
    ///
    /// [`http2::client::Builder::max_concurrent_reset_streams`]: https://docs.rs/h2/client/struct.Builder.html#method.max_concurrent_reset_streams
    pub fn max_concurrent_reset_streams(mut self, max: usize) -> Self {
        self.opts.max_concurrent_reset_streams = Some(max);
        self
    }

    /// Set the maximum write buffer size for each HTTP/2 stream.
    ///
    /// Default is currently 1MB, but may change.
    ///
    /// # Panics
    ///
    /// The value must be no larger than `u32::MAX`.
    pub fn max_send_buf_size(mut self, max: usize) -> Self {
        assert!(max <= u32::MAX as usize);
        self.opts.max_send_buffer_size = max;
        self
    }

    /// Configures the maximum number of pending reset streams allowed before a GOAWAY will be sent.
    ///
    /// See <https://github.com/hyperium/hyper/issues/2877> for more information.
    pub fn max_pending_accept_reset_streams(mut self, max: impl Into<Option<usize>>) -> Self {
        if let Some(max) = max.into() {
            self.opts.max_pending_accept_reset_streams = Some(max);
        }
        self
    }

    /// Sets the stream dependency and weight for the outgoing HEADERS frame.
    ///
    /// This configures the priority of the stream by specifying its dependency and weight,
    /// as defined by the HTTP/2 priority mechanism. This can be used to influence how the
    /// server allocates resources to this stream relative to others.
    pub fn headers_stream_dependency<T>(mut self, stream_dependency: T) -> Self
    where
        T: Into<Option<StreamDependency>>,
    {
        if let Some(stream_dependency) = stream_dependency.into() {
            self.opts.headers_stream_dependency = Some(stream_dependency);
        }
        self
    }

    /// Sets the HTTP/2 pseudo-header field order for outgoing HEADERS frames.
    ///
    /// This determines the order in which pseudo-header fields (such as `:method`, `:scheme`, etc.)
    /// are encoded in the HEADERS frame. Customizing the order may be useful for interoperability
    /// or testing purposes.
    pub fn headers_pseudo_order<T>(mut self, headers_pseudo_order: T) -> Self
    where
        T: Into<Option<PseudoOrder>>,
    {
        if let Some(headers_pseudo_order) = headers_pseudo_order.into() {
            self.opts.headers_pseudo_order = Some(headers_pseudo_order);
        }
        self
    }

    /// Configures custom experimental HTTP/2 setting.
    ///
    /// This setting is reserved for future use or experimental purposes.
    /// Enabling or disabling it may have no effect unless explicitly supported
    /// by the server or client implementation.
    pub fn experimental_settings<T>(mut self, experimental_settings: T) -> Self
    where
        T: Into<Option<ExperimentalSettings>>,
    {
        if let Some(experimental_settings) = experimental_settings.into() {
            self.opts.experimental_settings = Some(experimental_settings);
        }
        self
    }

    /// Sets the order of settings parameters in the initial SETTINGS frame.
    ///
    /// This determines the order in which settings are sent during the HTTP/2 handshake.
    /// Customizing the order may be useful for testing or protocol compliance.
    pub fn settings_order<T>(mut self, settings_order: T) -> Self
    where
        T: Into<Option<SettingsOrder>>,
    {
        if let Some(settings_order) = settings_order.into() {
            self.opts.settings_order = Some(settings_order);
        }
        self
    }

    /// Sets the list of PRIORITY frames to be sent immediately after the connection is established,
    /// but before the first request is sent.
    ///
    /// This allows you to pre-configure the HTTP/2 stream dependency tree by specifying a set of
    /// PRIORITY frames that will be sent as part of the connection preface. This can be useful for
    /// optimizing resource allocation or testing custom stream prioritization strategies.
    ///
    /// Each `Priority` in the list must have a valid (non-zero) stream ID. Any priority with a
    /// stream ID of zero will be ignored.
    pub fn priorities<T>(mut self, priorities: T) -> Self
    where
        T: Into<Option<Priorities>>,
    {
        if let Some(priorities) = priorities.into() {
            self.opts.priorities = Some(priorities);
        }
        self
    }

    /// Builds the `Http2Options` instance.
    pub fn build(self) -> Http2Options {
        self.opts
    }
}

impl Http2Options {
    /// Creates a new `Http2OptionsBuilder` instance.
    pub fn builder() -> Http2OptionsBuilder {
        Http2OptionsBuilder {
            opts: Http2Options {
                adaptive_window: false,
                initial_stream_id: None,
                initial_conn_window_size: DEFAULT_CONN_WINDOW_SIZE,
                initial_window_size: DEFAULT_WINDOW_SIZE,
                initial_max_send_streams: DEFAULT_INITIAL_MAX_SEND_STREAMS,
                max_frame_size: None,
                max_header_list_size: None,
                keep_alive_interval: None,
                keep_alive_timeout: Duration::from_secs(20),
                keep_alive_while_idle: false,
                max_concurrent_reset_streams: None,
                max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
                max_pending_accept_reset_streams: None,
                header_table_size: None,
                max_concurrent_streams: None,
                enable_push: None,
                enable_connect_protocol: None,
                no_rfc7540_priorities: None,
                experimental_settings: None,
                settings_order: None,
                headers_pseudo_order: None,
                headers_stream_dependency: None,
                priorities: None,
            },
        }
    }
}

impl Default for Http2Options {
    #[inline]
    fn default() -> Self {
        Http2Options::builder().build()
    }
}
