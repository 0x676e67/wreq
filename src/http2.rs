//! HTTP/2 config.
use hyper2::{Priority, PseudoOrder, SettingsOrder, StreamDependency, StreamId};
use std::borrow::Cow;
use typed_builder::TypedBuilder;

/// Configuration config for an HTTP/2 connection.
///
/// This struct defines various parameters to fine-tune the behavior of an HTTP/2 connection,
/// including stream management, window sizes, frame limits, and header config.
#[derive(Clone, Debug, TypedBuilder)]
pub struct Http2Config {
    /// The initial stream ID for HTTP/2 communication.
    ///
    /// - **Purpose:** Identifies the starting stream ID for client-server communication.
    #[builder(default, setter(into))]
    pub initial_stream_id: Option<u32>,

    // ============== Window Update Frame Settings ==============
    /// The initial connection-level window size.
    ///
    /// - **Purpose:** Controls the maximum amount of data the connection can send without acknowledgment.
    #[builder(default, setter(into))]
    pub initial_connection_window_size: Option<u32>,

    // ============== Settings Frame Parameters ==============
    /// The size of the header compression table.
    ///
    /// - **Purpose:** Adjusts the memory used for HPACK header compression.
    #[builder(default, setter(into))]
    pub header_table_size: Option<u32>,

    /// Enables or disables server push functionality.
    ///
    /// - **Purpose:** Allows the server to send resources to the client proactively.
    #[builder(default, setter(into))]
    pub enable_push: Option<bool>,

    /// The maximum number of concurrent streams allowed.
    ///
    /// - **Purpose:** Limits the number of simultaneous open streams.
    #[builder(default, setter(into))]
    pub max_concurrent_streams: Option<u32>,

    /// The initial window size for stream-level flow control.
    ///
    /// - **Purpose:** Controls the amount of data a single stream can send without acknowledgment.
    #[builder(default, setter(into))]
    pub initial_stream_window_size: Option<u32>,

    /// The maximum frame size allowed.
    ///
    /// - **Purpose:** Limits the size of individual HTTP/2 frames.
    #[builder(default, setter(into))]
    pub max_frame_size: Option<u32>,

    /// The maximum size of header lists.
    ///
    /// - **Purpose:** Limits the total size of header blocks to prevent resource exhaustion.
    #[builder(default, setter(into))]
    pub max_header_list_size: Option<u32>,

    /// Placeholder for an unknown HTTP/2 setting with identifier `8`.
    ///
    /// - **Purpose:** Reserved for experimental or vendor-specific extensions.
    #[builder(default, setter(into))]
    pub unknown_setting8: Option<bool>,

    /// Placeholder for an unknown HTTP/2 setting with identifier `9`.
    ///
    /// - **Purpose:** Reserved for experimental or vendor-specific extensions.
    #[builder(default, setter(into))]
    pub unknown_setting9: Option<bool>,

    /// The order in which settings are applied.
    ///
    /// - **Structure:** Array of `SettingsOrder` with up to 8 elements.
    /// - **Purpose:** Defines the sequence for applying HTTP/2 settings.
    #[builder(default, setter(strip_option))]
    pub settings_order: Option<[SettingsOrder; 8]>,

    // ============== Headers Frame Settings ==============
    /// The priority settings for header frames.
    ///
    /// - **Structure:** `(stream_dependency, weight, exclusive_flag)`
    /// - **Purpose:** Specifies how header frames are prioritized during transmission.
    #[builder(default, setter(transform = |input: impl IntoStreamDependency| input.into()))]
    pub headers_priority: Option<StreamDependency>,

    /// The order of pseudo-header fields.
    ///
    /// - **Structure:** Array of `PseudoOrder` with up to 4 elements.
    /// - **Purpose:** Determines the sequence in which pseudo-headers are transmitted.
    #[builder(default, setter(into))]
    pub headers_pseudo_order: Option<[PseudoOrder; 4]>,

    // ============== Priority Frame Settings ==============
    /// The priority configuration for priority frames.
    ///
    /// - **Structure:** A borrowed slice of `Priority` settings.
    /// - **Purpose:** Defines stream dependencies and priorities.
    #[builder(default, setter(strip_option, into))]
    pub priority: Option<Cow<'static, [Priority]>>,
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
