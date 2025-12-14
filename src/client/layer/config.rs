mod layer;

pub use self::layer::{ConfigService, ConfigServiceLayer};
use crate::config::RequestConfigValue;

/// A marker type for the default headers configuration value.
#[derive(Clone, Copy)]
pub(crate) struct DefaultHeaders;

impl_request_config_value!(DefaultHeaders, bool);
