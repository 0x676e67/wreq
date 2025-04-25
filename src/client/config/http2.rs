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
    #[builder(default, setter(into))]
    pub(crate) initial_stream_id: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) initial_connection_window_size: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) header_table_size: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) enable_push: Option<bool>,

    #[builder(default, setter(into))]
    pub(crate) max_concurrent_streams: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) initial_stream_window_size: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) max_frame_size: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) max_header_list_size: Option<u32>,

    #[builder(default, setter(into))]
    pub(crate) unknown_setting8: Option<bool>,

    #[builder(default, setter(into))]
    pub(crate) unknown_setting9: Option<bool>,

    #[builder(default, setter(strip_option))]
    pub(crate) settings_order: Option<[SettingsOrder; 8]>,

    #[builder(default, setter(transform = |input: impl IntoStreamDependency| input.into()))]
    pub(crate) headers_priority: Option<StreamDependency>,

    #[builder(default, setter(into))]
    pub(crate) headers_pseudo_order: Option<[PseudoOrder; 4]>,

    #[builder(default, setter(strip_option, into))]
    pub(crate) priority: Option<Cow<'static, [Priority]>>,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Http2Config {
    /// Sets the initial stream ID for HTTP/2 communication.
    ///
    /// - **Purpose:** Identifies the starting stream ID for client-server communication.
    pub fn set_initial_stream_id<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.initial_stream_id = value.into();
        self
    }

    /// Sets the initial connection-level window size.
    ///
    /// - **Purpose:** Controls the maximum amount of data the connection can send without acknowledgment.
    pub fn set_initial_connection_window_size<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.initial_connection_window_size = value.into();
        self
    }

    /// Sets the size of the header compression table.
    ///
    /// - **Purpose:** Adjusts the memory used for HPACK header compression.
    pub fn set_header_table_size<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.header_table_size = value.into();
        self
    }

    /// Enables or disables server push functionality.
    ///
    /// - **Purpose:** Allows the server to send resources to the client proactively.
    pub fn set_enable_push<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.enable_push = value.into();
        self
    }

    /// Sets the maximum number of concurrent streams allowed.
    ///
    /// - **Purpose:** Limits the number of simultaneous open streams.
    pub fn set_max_concurrent_streams<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.max_concurrent_streams = value.into();
        self
    }

    /// Sets the initial window size for stream-level flow control.
    ///
    /// - **Purpose:** Controls the amount of data a single stream can send without acknowledgment.
    pub fn set_initial_stream_window_size<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.initial_stream_window_size = value.into();
        self
    }

    /// Sets the maximum frame size allowed.
    ///
    /// - **Purpose:** Limits the size of individual HTTP/2 frames.
    pub fn set_max_frame_size<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.max_frame_size = value.into();
        self
    }

    /// Sets the maximum size of header lists.
    ///
    /// - **Purpose:** Limits the total size of header blocks to prevent resource exhaustion.
    pub fn set_max_header_list_size<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<u32>>,
    {
        self.max_header_list_size = value.into();
        self
    }

    /// Placeholder for an enable connect protocol setting.
    ///
    /// - **Purpose:** Reserved for experimental or vendor-specific extensions.
    pub fn unknown_setting8<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.unknown_setting8 = value.into();
        self
    }

    /// Sets the placeholder for an unknown HTTP/2 setting with identifier `9`.
    ///
    /// - **Purpose:** Reserved for experimental or vendor-specific extensions.
    pub fn set_unknown_setting9<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<bool>>,
    {
        self.unknown_setting9 = value.into();
        self
    }

    /// Sets the order in which settings are applied.
    ///
    /// - **Structure:** Array of `SettingsOrder` with up to 8 elements.
    /// - **Purpose:** Defines the sequence for applying HTTP/2 settings.
    pub fn set_settings_order(&mut self, value: [SettingsOrder; 8]) -> &mut Self {
        self.settings_order = Some(value);
        self
    }

    /// Sets the priority settings for header frames.
    ///
    /// - **Structure:** `(stream_dependency, weight, exclusive_flag)`
    /// - **Purpose:** Specifies how header frames are prioritized during transmission.
    pub fn set_headers_priority<T>(&mut self, value: T) -> &mut Self
    where
        T: IntoStreamDependency,
    {
        self.headers_priority = value.into();
        self
    }

    /// Sets the order of pseudo-header fields.
    ///
    /// - **Structure:** Array of `PseudoOrder` with up to 4 elements.
    /// - **Purpose:** Determines the sequence in which pseudo-headers are transmitted.
    pub fn set_headers_pseudo_order<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Option<[PseudoOrder; 4]>>,
    {
        self.headers_pseudo_order = value.into();
        self
    }

    /// Sets the priority configuration for priority frames.
    ///
    /// - **Structure:** A borrowed slice of `Priority` settings.
    /// - **Purpose:** Defines stream dependencies and priorities.
    pub fn set_priority<T>(&mut self, value: T) -> &mut Self
    where
        T: Into<Cow<'static, [Priority]>>,
    {
        self.priority = Some(value.into());
        self
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
