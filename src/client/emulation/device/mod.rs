//! Emulation for different browsers.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]

#[macro_use]
mod macros;
mod chrome;
mod firefox;
mod okhttp;
mod safari;

use crate::{EmulationProvider, EmulationProviderFactory};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use chrome::*;
use firefox::*;
use okhttp::*;
use safari::*;

mod emulation_imports {
    pub use crate::{EmulationOS, EmulationOption, EmulationProvider, Http2Config};
    pub use http::{
        header::{ACCEPT, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT},
        HeaderMap, HeaderName, HeaderValue,
    };

    #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
    pub use http::header::ACCEPT_ENCODING;
}

mod tls_imports {
    pub use crate::tls::{AlpnProtos, AlpsProtos, TlsConfig, TlsVersion};
    pub use boring2::ssl::{CertCompressionAlgorithm, ExtensionType, SslCurve};
    pub use typed_builder::TypedBuilder;
}

mod http2_imports {
    pub use hyper2::PseudoOrder::{self, *};
    pub use hyper2::SettingsOrder::{self, *};
    pub use hyper2::{Priority, StreamDependency, StreamId};
    pub use std::sync::LazyLock;
}

/// Represents different browser versions for impersonation.
///
/// The `Emulation` enum provides variants for different browser versions that can be used
/// to emulation HTTP requests. Each variant corresponds to a specific browser version.
///
/// # Naming Convention
///
/// The naming convention for the variants follows the pattern `browser_version`, where
/// `browser` is the name of the browser (e.g., `chrome`, `firefox`, `safari`) and `version`
/// is the version number. For example, `Chrome100` represents Chrome version 100.
///
/// The serialized names of the variants use underscores to separate the browser name and
/// version number, following the pattern `browser_version`. For example, `Chrome100` is
/// serialized as `"chrome_100"`.
///
/// # Examples
///
/// ```rust
/// use rquest::Emulation;
///
/// let emulation = Emulation::Chrome100;
/// let serialized = serde_json::to_string(&emulation).unwrap();
/// assert_eq!(serialized, "\"chrome_100\"");
///
/// let deserialized: Emulation = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, Emulation::Chrome100);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum Emulation {
    #[serde(rename = "chrome_100")]
    Chrome100,
    #[serde(rename = "chrome_101")]
    Chrome101,
    #[serde(rename = "chrome_104")]
    Chrome104,
    #[serde(rename = "chrome_105")]
    Chrome105,
    #[serde(rename = "chrome_106")]
    Chrome106,
    #[serde(rename = "chrome_107")]
    Chrome107,
    #[serde(rename = "chrome_108")]
    Chrome108,
    #[serde(rename = "chrome_109")]
    Chrome109,
    #[serde(rename = "chrome_114")]
    Chrome114,
    #[serde(rename = "chrome_116")]
    Chrome116,
    #[serde(rename = "chrome_117")]
    Chrome117,
    #[serde(rename = "chrome_118")]
    Chrome118,
    #[serde(rename = "chrome_119")]
    Chrome119,
    #[serde(rename = "chrome_120")]
    Chrome120,
    #[serde(rename = "chrome_123")]
    Chrome123,
    #[serde(rename = "chrome_124")]
    Chrome124,
    #[serde(rename = "chrome_126")]
    Chrome126,
    #[serde(rename = "chrome_127")]
    Chrome127,
    #[serde(rename = "chrome_128")]
    Chrome128,
    #[serde(rename = "chrome_129")]
    Chrome129,
    #[serde(rename = "chrome_130")]
    Chrome130,
    #[serde(rename = "chrome_131")]
    Chrome131,
    #[serde(rename = "chrome_132")]
    Chrome132,
    #[serde(rename = "chrome_133")]
    #[default]
    Chrome133,

    #[serde(rename = "safari_ios_17.2")]
    SafariIos17_2,
    #[serde(rename = "safari_ios_17.4.1")]
    SafariIos17_4_1,
    #[serde(rename = "safari_ios_16.5")]
    SafariIos16_5,
    #[serde(rename = "safari_15.3")]
    Safari15_3,
    #[serde(rename = "safari_15.5")]
    Safari15_5,
    #[serde(rename = "safari_15.6.1")]
    Safari15_6_1,
    #[serde(rename = "safari_16")]
    Safari16,
    #[serde(rename = "safari_16.5")]
    Safari16_5,
    #[serde(rename = "safari_17.0")]
    Safari17_0,
    #[serde(rename = "safari_17.2.1")]
    Safari17_2_1,
    #[serde(rename = "safari_17.4.1")]
    Safari17_4_1,
    #[serde(rename = "safari_17.5")]
    Safari17_5,
    #[serde(rename = "safari_18")]
    Safari18,
    #[serde(rename = "safari_ipad_18")]
    SafariIPad18,
    #[serde(rename = "safari_18.2")]
    Safari18_2,
    #[serde(rename = "safari_ios_18.1.1")]
    SafariIos18_1_1,

    #[serde(rename = "okhttp_3.9")]
    OkHttp3_9,
    #[serde(rename = "okhttp_3.11")]
    OkHttp3_11,
    #[serde(rename = "okhttp_3.13")]
    OkHttp3_13,
    #[serde(rename = "okhttp_3.14")]
    OkHttp3_14,
    #[serde(rename = "okhttp_4.9")]
    OkHttp4_9,
    #[serde(rename = "okhttp_4.10")]
    OkHttp4_10,
    #[serde(rename = "okhttp_5")]
    OkHttp5,

    #[serde(rename = "edge_101")]
    Edge101,
    #[serde(rename = "edge_122")]
    Edge122,
    #[serde(rename = "edge_127")]
    Edge127,
    #[serde(rename = "edge_131")]
    Edge131,

    #[serde(rename = "firefox_109")]
    Firefox109,
    #[serde(rename = "firefox_117")]
    Firefox117,
    #[serde(rename = "firefox_128")]
    Firefox128,
    #[serde(rename = "firefox_133")]
    Firefox133,
}

/// ======== Emulation impls ========
impl EmulationProviderFactory for Emulation {
    fn emulation(self) -> EmulationProvider {
        EmulationOption::builder()
            .emulation(self)
            .build()
            .emulation()
    }
}

/// Represents different operating systems for impersonation.
///
/// The `EmulationOS` enum provides variants for different operating systems that can be used
/// to emulation HTTP requests. Each variant corresponds to a specific operating system.
///
/// # Naming Convention
///
/// The naming convention for the variants follows the pattern `os_name`, where
/// `os_name` is the name of the operating system (e.g., `windows`, `macos`, `linux`, `android`, `ios`).
///
/// The serialized names of the variants use lowercase letters to represent the operating system names.
/// For example, `Windows` is serialized as `"windows"`.
///
/// # Examples
///
/// ```rust
/// use rquest::EmulationOS;
///
/// let emulation_os = EmulationOS::Windows;
/// let serialized = serde_json::to_string(&emulation_os).unwrap();
/// assert_eq!(serialized, "\"windows\"");
///
/// let deserialized: EmulationOS = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, EmulationOS::Windows);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum EmulationOS {
    #[serde(rename = "windows")]
    Windows,
    #[serde(rename = "macos")]
    #[default]
    MacOS,
    #[serde(rename = "linux")]
    Linux,
    #[serde(rename = "android")]
    Android,
    #[serde(rename = "ios")]
    IOS,
}

/// ======== EmulationOS impls ========
impl EmulationOS {
    #[inline]
    fn platform(&self) -> &'static str {
        match self {
            EmulationOS::MacOS => "\"macOS\"",
            EmulationOS::Linux => "\"Linux\"",
            EmulationOS::Windows => "\"Windows\"",
            EmulationOS::Android => "\"Android\"",
            EmulationOS::IOS => "\"iOS\"",
        }
    }

    #[inline]
    fn is_mobile(&self) -> bool {
        matches!(self, EmulationOS::Android | EmulationOS::IOS)
    }
}

#[derive(Default, TypedBuilder)]
pub struct EmulationOption {
    /// The browser version to emulation.
    #[builder(default)]
    emulation: Emulation,

    /// The operating system.
    #[builder(default)]
    emulation_os: EmulationOS,

    /// Whether to skip HTTP/2.
    #[builder(default = false)]
    skip_http2: bool,

    /// Whether to skip headers.
    #[builder(default = false)]
    skip_headers: bool,
}

/// ======== EmulationOption impls ========
impl EmulationProviderFactory for EmulationOption {
    fn emulation(self) -> EmulationProvider {
        emulation_match!(
            self.emulation,
            self,

            Emulation::Chrome100 => v100::emulation,
            Emulation::Chrome101 => v101::emulation,
            Emulation::Chrome104 => v104::emulation,
            Emulation::Chrome105 => v105::emulation,
            Emulation::Chrome106 => v106::emulation,
            Emulation::Chrome107 => v107::emulation,
            Emulation::Chrome108 => v108::emulation,
            Emulation::Chrome109 => v109::emulation,
            Emulation::Chrome114 => v114::emulation,
            Emulation::Chrome116 => v116::emulation,
            Emulation::Chrome117 => v117::emulation,
            Emulation::Chrome118 => v118::emulation,
            Emulation::Chrome119 => v119::emulation,
            Emulation::Chrome120 => v120::emulation,
            Emulation::Chrome123 => v123::emulation,
            Emulation::Chrome124 => v124::emulation,
            Emulation::Chrome126 => v126::emulation,
            Emulation::Chrome127 => v127::emulation,
            Emulation::Chrome128 => v128::emulation,
            Emulation::Chrome129 => v129::emulation,
            Emulation::Chrome130 => v130::emulation,
            Emulation::Chrome131 => v131::emulation,
            Emulation::Chrome132 => v132::emulation,
            Emulation::Chrome133 => v133::emulation,

            Emulation::SafariIos17_2 => safari_ios_17_2::emulation,
            Emulation::SafariIos17_4_1 => safari_ios_17_4_1::emulation,
            Emulation::SafariIos16_5 => safari_ios_16_5::emulation,
            Emulation::Safari15_3 => safari15_3::emulation,
            Emulation::Safari15_5 => safari15_5::emulation,
            Emulation::Safari15_6_1 => safari15_6_1::emulation,
            Emulation::Safari16 => safari16::emulation,
            Emulation::Safari16_5 => safari16_5::emulation,
            Emulation::Safari17_0 => safari17_0::emulation,
            Emulation::Safari17_2_1 => safari17_2_1::emulation,
            Emulation::Safari17_4_1 => safari17_4_1::emulation,
            Emulation::Safari17_5 => safari17_5::emulation,
            Emulation::Safari18 => safari18::emulation,
            Emulation::SafariIPad18 => safari_ipad_18::emulation,
            Emulation::Safari18_2 => safari18_2::emulation,
            Emulation::SafariIos18_1_1 => safari_ios_18_1_1::emulation,

            Emulation::OkHttp3_9 => okhttp3_9::emulation,
            Emulation::OkHttp3_11 => okhttp3_11::emulation,
            Emulation::OkHttp3_13 => okhttp3_13::emulation,
            Emulation::OkHttp3_14 => okhttp3_14::emulation,
            Emulation::OkHttp4_9 => okhttp4_9::emulation,
            Emulation::OkHttp4_10 => okhttp4_10::emulation,
            Emulation::OkHttp5 => okhttp5::emulation,

            Emulation::Edge101 => edge101::emulation,
            Emulation::Edge122 => edge122::emulation,
            Emulation::Edge127 => edge127::emulation,
            Emulation::Edge131 => edge131::emulation,

            Emulation::Firefox109 => ff109::emulation,
            Emulation::Firefox117 => ff117::emulation,
            Emulation::Firefox128 => ff128::emulation,
            Emulation::Firefox133 => ff133::emulation
        )
    }
}

#[cfg(feature = "json")]
mod tests {
    #[test]
    fn test_emulation_serde() {
        use serde_json::{json, Value};

        let imp = super::Emulation::Chrome100;
        let json = json!({
            "imp": imp,
        });

        let serialized1 = serde_json::to_string(&json).unwrap();
        assert_eq!(serialized1, r#"{"imp":"chrome_100"}"#);

        let serialized2 = serde_json::to_value(imp).unwrap();
        assert_eq!(serialized2, "chrome_100");

        let deserialized: Value = serde_json::from_str(&serialized1).unwrap();
        assert_eq!(deserialized, json);
    }

    #[test]
    fn test_emulation_os_serde() {
        use serde_json::{json, Value};

        let os = super::EmulationOS::Windows;
        let json = json!({
            "os": os
        });

        let serialized1 = serde_json::to_string(&json).unwrap();
        assert_eq!(serialized1, r#"{"os":"windows"}"#);

        let serialized2 = serde_json::to_value(os).unwrap();
        assert_eq!(serialized2, "windows");

        let deserialized: Value = serde_json::from_str(&serialized1).unwrap();
        assert_eq!(deserialized, json);
    }
}
