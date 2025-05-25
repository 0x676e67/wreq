//! Re-export the `http2` module for HTTP/2 frame types and utilities.

pub use http2::frame::{
    Priorities, PrioritiesBuilder, Priority, PseudoId, PseudoOrder, Setting, SettingId,
    SettingsOrder, SettingsOrderBuilder, StreamDependency, StreamId,
};

/// Builder for `Http2Config`.
#[must_use]
#[derive(Debug)]
pub struct Http2ConfigBuilder {
    config: Http2Config,
}

/// Configuration config for an HTTP/2 connection.
///
/// This struct defines various parameters to fine-tune the behavior of an HTTP/2 connection,
/// including stream management, window sizes, frame limits, and header config.
#[derive(Debug, Default)]
pub struct Http2Config {
    pub(crate) initial_stream_id: Option<u32>,
    pub(crate) initial_connection_window_size: Option<u32>,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) enable_push: Option<bool>,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) initial_stream_window_size: Option<u32>,
    pub(crate) max_frame_size: Option<u32>,
    pub(crate) max_header_list_size: Option<u32>,
    pub(crate) enable_connect_protocol: Option<bool>,
    pub(crate) no_rfc7540_priorities: Option<bool>,
    pub(crate) settings_order: Option<SettingsOrder>,
    pub(crate) headers_stream_dependency: Option<StreamDependency>,
    pub(crate) headers_pseudo_order: Option<PseudoOrder>,
    pub(crate) priorities: Option<Priorities>,
}

impl Http2ConfigBuilder {
    /// Sets the initial stream ID for HTTP/2 communication.
    ///
    /// - **Purpose:** Identifies the starting stream ID for client-server communication.
    pub fn initial_stream_id<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.initial_stream_id = value.into();
        self
    }

    /// Sets the initial connection-level window size.
    ///
    /// - **Purpose:** Controls the maximum amount of data the connection can send without acknowledgment.
    pub fn initial_connection_window_size<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.initial_connection_window_size = value.into();
        self
    }

    /// Sets the size of the header compression table.
    ///
    /// - **Purpose:** Adjusts the memory used for HPACK header compression.
    pub fn header_table_size<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.header_table_size = value.into();
        self
    }

    /// Enables or disables server push functionality.
    ///
    /// - **Purpose:** Allows the server to send resources to the client proactively.
    pub fn enable_push<T>(mut self, value: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.enable_push = value.into();
        self
    }

    /// Sets the maximum number of concurrent streams allowed.
    ///
    /// - **Purpose:** Limits the number of simultaneous open streams.
    pub fn max_concurrent_streams<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.max_concurrent_streams = value.into();
        self
    }

    /// Sets the initial window size for stream-level flow control.
    ///
    /// - **Purpose:** Controls the amount of data a single stream can send without acknowledgment.
    pub fn initial_stream_window_size<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.initial_stream_window_size = value.into();
        self
    }

    /// Sets the maximum frame size allowed.
    ///
    /// - **Purpose:** Limits the size of individual HTTP/2 frames.
    pub fn max_frame_size<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.max_frame_size = value.into();
        self
    }

    /// Sets the maximum size of header lists.
    ///
    /// - **Purpose:** Limits the total size of header blocks to prevent resource exhaustion.
    pub fn max_header_list_size<T>(mut self, value: T) -> Self
    where
        T: Into<Option<u32>>,
    {
        self.config.max_header_list_size = value.into();
        self
    }

    /// Placeholder for an enable connect protocol setting.
    ///
    /// - **Purpose:** Reserved for experimental or vendor-specific extensions.
    pub fn enable_connect_protocol<T>(mut self, value: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.enable_connect_protocol = value.into();
        self
    }

    /// Disable RFC 7540 Stream Priorities (set to `true` to disable).
    /// [RFC 9218]: <https://www.rfc-editor.org/rfc/rfc9218.html#section-2.1>
    pub fn no_rfc7540_priorities<T>(mut self, value: T) -> Self
    where
        T: Into<Option<bool>>,
    {
        self.config.no_rfc7540_priorities = value.into();
        self
    }

    /// Sets the order of settings parameters in the initial SETTINGS frame.
    ///
    /// This determines the order in which settings are sent during the HTTP/2 handshake.
    /// Customizing the order may be useful for testing or protocol compliance.
    pub fn settings_order(mut self, value: SettingsOrder) -> Self {
        self.config.settings_order = Some(value);
        self
    }

    /// Sets the stream dependency and weight for the outgoing HEADERS frame.
    ///
    /// This configures the priority of the stream by specifying its dependency and weight,
    /// as defined by the HTTP/2 priority mechanism. This can be used to influence how the
    /// server allocates resources to this stream relative to others.
    pub fn headers_stream_dependency<T>(mut self, value: T) -> Self
    where
        T: IntoStreamDependency,
    {
        self.config.headers_stream_dependency = value.into();
        self
    }

    /// Sets the HTTP/2 pseudo-header field order for outgoing HEADERS frames.
    ///
    /// This determines the order in which pseudo-header fields (such as `:method`, `:scheme`, etc.)
    /// are encoded in the HEADERS frame. Customizing the order may be useful for interoperability
    /// or testing purposes.
    pub fn headers_pseudo_order<T>(mut self, value: T) -> Self
    where
        T: Into<Option<PseudoOrder>>,
    {
        self.config.headers_pseudo_order = value.into();
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
    pub fn priorities<T>(mut self, value: T) -> Self
    where
        T: Into<Priorities>,
    {
        self.config.priorities = Some(value.into());
        self
    }

    /// Builds the `Http2Config` instance.
    pub fn build(self) -> Http2Config {
        self.config
    }
}

impl Http2Config {
    /// Creates a new `Http2ConfigBuilder` instance.
    pub fn builder() -> Http2ConfigBuilder {
        Http2ConfigBuilder {
            config: Http2Config::default(),
        }
    }
}

/// A trait for converting various types into an optional `StreamDependency`.
///
/// This trait is used to provide a unified way to convert different types
/// into an optional `StreamDependency` instance.
pub trait IntoStreamDependency {
    /// Converts the implementing type into an optional `StreamDependency`.
    fn into(self) -> Option<StreamDependency>;
}

// Macro to implement IntoStreamDependency for various types
macro_rules! impl_into_stream_dependency {
    ($($t:ty => $body:expr),*) => {
        $(
            impl IntoStreamDependency for $t {
                fn into(self) -> Option<StreamDependency> {
                    $body(self)
                }
            }
        )*
    };
}

impl_into_stream_dependency!(
    (u32, u8, bool) => |(id, weight, exclusive)| Some(StreamDependency::new(StreamId::from(id), weight, exclusive)),
    Option<(u32, u8, bool)> => |opt: Option<(u32, u8, bool)>| opt.map(|(id, weight, exclusive)| StreamDependency::new(StreamId::from(id), weight, exclusive)),
    StreamDependency => Some,
    Option<StreamDependency> => |opt| opt
);
