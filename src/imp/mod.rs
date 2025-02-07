//! Impersonate http_context for different browsers.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]

#[macro_use]
mod macros;
mod chrome;
mod firefox;
mod okhttp;
mod safari;

use crate::{HttpContext, HttpContextProvider};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;

use chrome::*;
use firefox::*;
use okhttp::*;
use safari::*;

mod impersonate_imports {
    pub use crate::{Http2Config, HttpContext, ImpersonateOS, ImpersonateOption};
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
/// The `Impersonate` enum provides variants for different browser versions that can be used
/// to impersonate HTTP requests. Each variant corresponds to a specific browser version.
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
/// use rquest::Impersonate;
///
/// let impersonate = Impersonate::Chrome100;
/// let serialized = serde_json::to_string(&impersonate).unwrap();
/// assert_eq!(serialized, "\"chrome_100\"");
///
/// let deserialized: Impersonate = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, Impersonate::Chrome100);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum Impersonate {
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
    #[default]
    Chrome131,

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

/// ======== Impersonate impls ========
impl HttpContextProvider for Impersonate {
    fn context(self) -> HttpContext {
        ImpersonateOption::builder()
            .impersonate(self)
            .build()
            .context()
    }
}

/// Represents different operating systems for impersonation.
///
/// The `ImpersonateOS` enum provides variants for different operating systems that can be used
/// to impersonate HTTP requests. Each variant corresponds to a specific operating system.
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
/// use rquest::ImpersonateOS;
///
/// let impersonate_os = ImpersonateOS::Windows;
/// let serialized = serde_json::to_string(&impersonate_os).unwrap();
/// assert_eq!(serialized, "\"windows\"");
///
/// let deserialized: ImpersonateOS = serde_json::from_str(&serialized).unwrap();
/// assert_eq!(deserialized, ImpersonateOS::Windows);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum ImpersonateOS {
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

/// ======== ImpersonateOS impls ========
impl ImpersonateOS {
    #[inline]
    fn platform(&self) -> &'static str {
        match self {
            ImpersonateOS::MacOS => "\"macOS\"",
            ImpersonateOS::Linux => "\"Linux\"",
            ImpersonateOS::Windows => "\"Windows\"",
            ImpersonateOS::Android => "\"Android\"",
            ImpersonateOS::IOS => "\"iOS\"",
        }
    }

    #[inline]
    fn is_mobile(&self) -> bool {
        matches!(self, ImpersonateOS::Android | ImpersonateOS::IOS)
    }
}

#[derive(Default, TypedBuilder)]
pub struct ImpersonateOption {
    /// The browser version to impersonate.
    #[builder(default)]
    impersonate: Impersonate,

    /// The operating system.
    #[builder(default)]
    impersonate_os: ImpersonateOS,

    /// Whether to skip HTTP/2.
    #[builder(default = false)]
    skip_http2: bool,

    /// Whether to skip headers.
    #[builder(default = false)]
    skip_headers: bool,
}

/// ======== ImpersonateOption impls ========
impl HttpContextProvider for ImpersonateOption {
    fn context(self) -> HttpContext {
        impersonate_match!(
            self.impersonate,
            self,

            Impersonate::Chrome100 => v100::http_context,
            Impersonate::Chrome101 => v101::http_context,
            Impersonate::Chrome104 => v104::http_context,
            Impersonate::Chrome105 => v105::http_context,
            Impersonate::Chrome106 => v106::http_context,
            Impersonate::Chrome107 => v107::http_context,
            Impersonate::Chrome108 => v108::http_context,
            Impersonate::Chrome109 => v109::http_context,
            Impersonate::Chrome114 => v114::http_context,
            Impersonate::Chrome116 => v116::http_context,
            Impersonate::Chrome117 => v117::http_context,
            Impersonate::Chrome118 => v118::http_context,
            Impersonate::Chrome119 => v119::http_context,
            Impersonate::Chrome120 => v120::http_context,
            Impersonate::Chrome123 => v123::http_context,
            Impersonate::Chrome124 => v124::http_context,
            Impersonate::Chrome126 => v126::http_context,
            Impersonate::Chrome127 => v127::http_context,
            Impersonate::Chrome128 => v128::http_context,
            Impersonate::Chrome129 => v129::http_context,
            Impersonate::Chrome130 => v130::http_context,
            Impersonate::Chrome131 => v131::http_context,

            Impersonate::SafariIos17_2 => safari_ios_17_2::http_context,
            Impersonate::SafariIos17_4_1 => safari_ios_17_4_1::http_context,
            Impersonate::SafariIos16_5 => safari_ios_16_5::http_context,
            Impersonate::Safari15_3 => safari15_3::http_context,
            Impersonate::Safari15_5 => safari15_5::http_context,
            Impersonate::Safari15_6_1 => safari15_6_1::http_context,
            Impersonate::Safari16 => safari16::http_context,
            Impersonate::Safari16_5 => safari16_5::http_context,
            Impersonate::Safari17_0 => safari17_0::http_context,
            Impersonate::Safari17_2_1 => safari17_2_1::http_context,
            Impersonate::Safari17_4_1 => safari17_4_1::http_context,
            Impersonate::Safari17_5 => safari17_5::http_context,
            Impersonate::Safari18 => safari18::http_context,
            Impersonate::SafariIPad18 => safari_ipad_18::http_context,
            Impersonate::Safari18_2 => safari18_2::http_context,
            Impersonate::SafariIos18_1_1 => safari_ios_18_1_1::http_context,

            Impersonate::OkHttp3_9 => okhttp3_9::http_context,
            Impersonate::OkHttp3_11 => okhttp3_11::http_context,
            Impersonate::OkHttp3_13 => okhttp3_13::http_context,
            Impersonate::OkHttp3_14 => okhttp3_14::http_context,
            Impersonate::OkHttp4_9 => okhttp4_9::http_context,
            Impersonate::OkHttp4_10 => okhttp4_10::http_context,
            Impersonate::OkHttp5 => okhttp5::http_context,

            Impersonate::Edge101 => edge101::http_context,
            Impersonate::Edge122 => edge122::http_context,
            Impersonate::Edge127 => edge127::http_context,
            Impersonate::Edge131 => edge131::http_context,

            Impersonate::Firefox109 => ff109::http_context,
            Impersonate::Firefox117 => ff117::http_context,
            Impersonate::Firefox128 => ff128::http_context,
            Impersonate::Firefox133 => ff133::http_context
        )
    }
}

#[cfg(feature = "json")]
mod tests {
    #[test]
    fn test_impersonate_serde() {
        use serde_json::{json, Value};

        let imp = super::Impersonate::Chrome100;
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
    fn test_impersonate_os_serde() {
        use serde_json::{json, Value};

        let os = super::ImpersonateOS::Windows;
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
