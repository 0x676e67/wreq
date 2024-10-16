use hyper::PseudoOrder::{self, *};
use hyper::SettingsOrder::{self, *};

// ============== http2 headers priority ==============
pub const HEADER_PRORIORITY: (u32, u8, bool) = (0, 255, true);

/// ============== http2 headers pseudo order ==============
pub const HEADERS_PSEUDO_ORDER: [PseudoOrder; 4] = [Method, Authority, Scheme, Path];

/// ============== http2 settings frame order ==============
pub const SETTINGS_ORDER: [SettingsOrder; 7] = [
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    EnableConnectProtocol,
];
