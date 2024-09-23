use hyper::PseudoOrder::{self, *};
use hyper::SettingsOrder::{self, *};

// ============== http2 headers priority ==============
pub const HEADER_PRORIORITY: &'static (u32, u8, bool) = &(0, 255, true);
pub const NEW_HEADER_PRORIORITY: &'static (u32, u8, bool) = &(0, 255, false);

/// ============== http2 headers pseudo order ==============
pub const HEADERS_PSEUDO_ORDER: &[PseudoOrder; 4] = &[Method, Scheme, Path, Authority];
pub const NEW_HEADERS_PSEUDO_ORDER: &[PseudoOrder; 4] = &[Method, Scheme, Authority, Path];

/// ============== http2 settings frame order ==============
pub const SETTINGS_ORDER: &[SettingsOrder; 7] = &[
    HeaderTableSize,
    EnablePush,
    InitialWindowSize,
    MaxConcurrentStreams,
    MaxFrameSize,
    MaxHeaderListSize,
    EnableConnectProtocol,
];
pub const NEW_SETTINGS_ORDER: &[SettingsOrder; 9] = &[
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    EnableConnectProtocol,
    UnknownSetting8,
    UnknownSetting9,
];
