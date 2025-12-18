mod layer;
mod options;

pub use self::{
    layer::{ConfigService, ConfigServiceLayer},
    options::{RequestOptions, TransportOptions},
};

/// A marker type for the default headers configuration value.
#[derive(Clone, Copy)]
pub(crate) struct DefaultHeaders;

impl_request_config_value!(DefaultHeaders, bool);
