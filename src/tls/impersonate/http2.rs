#![allow(missing_debug_implementations)]
use hyper::{PseudoOrder, SettingsOrder};
use typed_builder::TypedBuilder;

/// HTTP/2 settings.
#[derive(TypedBuilder)]
pub struct Http2Settings {
    /// The initial stream window size.
    #[builder(default, setter(into))]
    pub(crate) initial_stream_window_size: Option<u32>,

    /// The initial connection window size.
    #[builder(default, setter(into))]
    pub(crate) initial_connection_window_size: Option<u32>,

    /// The maximum concurrent streams.
    #[builder(default, setter(into))]
    pub(crate) max_concurrent_streams: Option<u32>,

    /// The maximum header list size.
    #[builder(default, setter(into))]
    pub(crate) max_header_list_size: Option<u32>,

    /// The header table size.
    #[builder(default, setter(into))]
    pub(crate) header_table_size: Option<u32>,

    /// Enable push.
    #[builder(default, setter(into))]
    pub(crate) enable_push: Option<bool>,

    /// Unknown setting8.
    #[builder(default, setter(into))]
    pub(crate) unknown_setting8: Option<bool>,

    /// Unknown setting9.
    #[builder(default, setter(into))]
    pub(crate) unknown_setting9: Option<bool>,

    /// The priority of the headers.
    #[builder(default, setter(into))]
    pub(crate) headers_priority: Option<(u32, u8, bool)>,

    /// The pseudo header order.
    #[builder(default, setter(into))]
    pub(crate) headers_pseudo_order: Option<[PseudoOrder; 4]>,

    /// The settings order.
    #[builder(default, setter(into))]
    pub(crate) settings_order: Option<Vec<SettingsOrder>>,
}
