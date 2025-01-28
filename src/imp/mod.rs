//! Impersonate settings for different browsers.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]

#[macro_use]
mod macros;
mod chrome;
mod firefox;
mod okhttp;
mod safari;

use http::{HeaderMap, HeaderName};
use serde::{Deserialize, Serialize};
use typed_builder::TypedBuilder;
use Impersonate::*;

use chrome::*;
use firefox::*;
use okhttp::*;
use safari::*;

use impersonate_imports::*;
use tls_imports::TlsSettings;

mod impersonate_imports {
    pub use crate::{http2::Http2Settings, imp::ImpersonateOS, imp::ImpersonateSettings};
    pub use http::{
        header::{ACCEPT, ACCEPT_LANGUAGE, UPGRADE_INSECURE_REQUESTS, USER_AGENT},
        HeaderMap, HeaderName, HeaderValue,
    };
    pub use std::borrow::Cow;

    #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
    pub use http::header::ACCEPT_ENCODING;
}

mod tls_imports {
    pub use crate::tls::{
        AlpnProtos, AlpsProtos, CertCompressionAlgorithm, TlsSettings, TlsVersion,
    };
    pub use boring2::ssl::{ExtensionType, SslCurve};
    pub use typed_builder::TypedBuilder;
}

mod http2_imports {
    pub use hyper2::PseudoOrder::{self, *};
    pub use hyper2::SettingsOrder::{self, *};
    pub use hyper2::{Priority, StreamDependency, StreamId};
    pub use std::sync::LazyLock;
}

/// A builder for impersonate settings.
pub struct ImpersonateBuilder {
    impersonate: Impersonate,
    impersonate_os: ImpersonateOS,
    skip_http2: bool,
    skip_headers: bool,
}

/// ========= Impersonate impls =========
impl ImpersonateBuilder {
    /// Sets the impersonate value.
    ///
    /// # Arguments
    ///
    /// * `impersonate` - The impersonate value to set.
    ///
    /// # Returns
    ///
    /// The updated `ImpersonateBuilder` instance.
    #[inline(always)]
    pub fn impersonate(mut self, impersonate: Impersonate) -> Self {
        self.impersonate = impersonate;
        self
    }

    /// Sets the operating system to impersonate.
    ///
    /// # Arguments
    ///
    /// * `impersonate_os` - The operating system to impersonate.
    ///
    /// # Returns
    ///
    /// The updated `ImpersonateBuilder` instance.
    #[inline(always)]
    pub fn impersonate_os(mut self, impersonate_os: ImpersonateOS) -> Self {
        self.impersonate_os = impersonate_os;
        self
    }

    /// Sets whether to skip HTTP/2.
    ///
    /// # Arguments
    ///
    /// * `skip_http2` - A boolean indicating whether to skip HTTP/2.
    ///
    /// # Returns
    ///
    /// The updated `ImpersonateBuilder` instance.
    #[inline(always)]
    pub fn skip_http2(mut self, skip_http2: bool) -> Self {
        self.skip_http2 = skip_http2;
        self
    }

    /// Sets whether to skip headers.
    ///
    /// # Arguments
    ///
    /// * `skip_headers` - A boolean indicating whether to skip headers.
    ///
    /// # Returns
    ///
    /// The updated `ImpersonateBuilder` instance.
    #[inline(always)]
    pub fn skip_headers(mut self, skip_headers: bool) -> Self {
        self.skip_headers = skip_headers;
        self
    }

    /// Builds the `ImpersonateSettings` instance.
    ///
    /// # Returns
    ///
    /// The constructed `ImpersonateSettings` instance.
    pub fn build(self) -> ImpersonateSettings {
        impersonate_match!(
            self.impersonate,
            self.impersonate_os,
            self.skip_http2,
            self.skip_headers,
            Chrome100 => v100::settings,
            Chrome101 => v101::settings,
            Chrome104 => v104::settings,
            Chrome105 => v105::settings,
            Chrome106 => v106::settings,
            Chrome107 => v107::settings,
            Chrome108 => v108::settings,
            Chrome109 => v109::settings,
            Chrome114 => v114::settings,
            Chrome116 => v116::settings,
            Chrome117 => v117::settings,
            Chrome118 => v118::settings,
            Chrome119 => v119::settings,
            Chrome120 => v120::settings,
            Chrome123 => v123::settings,
            Chrome124 => v124::settings,
            Chrome126 => v126::settings,
            Chrome127 => v127::settings,
            Chrome128 => v128::settings,
            Chrome129 => v129::settings,
            Chrome130 => v130::settings,
            Chrome131 => v131::settings,

            SafariIos17_2 => safari_ios_17_2::settings,
            SafariIos17_4_1 => safari_ios_17_4_1::settings,
            SafariIos16_5 => safari_ios_16_5::settings,
            Safari15_3 => safari15_3::settings,
            Safari15_5 => safari15_5::settings,
            Safari15_6_1 => safari15_6_1::settings,
            Safari16 => safari16::settings,
            Safari16_5 => safari16_5::settings,
            Safari17_0 => safari17_0::settings,
            Safari17_2_1 => safari17_2_1::settings,
            Safari17_4_1 => safari17_4_1::settings,
            Safari17_5 => safari17_5::settings,
            Safari18 => safari18::settings,
            SafariIPad18 => safari_ipad_18::settings,
            Safari18_2 => safari18_2::settings,
            SafariIos18_1_1 => safari_ios_18_1_1::settings,

            OkHttp3_9 => okhttp3_9::settings,
            OkHttp3_11 => okhttp3_11::settings,
            OkHttp3_13 => okhttp3_13::settings,
            OkHttp3_14 => okhttp3_14::settings,
            OkHttp4_9 => okhttp4_9::settings,
            OkHttp4_10 => okhttp4_10::settings,
            OkHttp5 => okhttp5::settings,

            Edge101 => edge101::settings,
            Edge122 => edge122::settings,
            Edge127 => edge127::settings,
            Edge131 => edge131::settings,

            Firefox109 => ff109::settings,
            Firefox117 => ff117::settings,
            Firefox128 => ff128::settings,
            Firefox133 => ff133::settings
        )
    }
}

/// A struct for impersonate settings.
#[derive(TypedBuilder, Default, Debug)]
pub struct ImpersonateSettings {
    #[builder(setter(into))]
    pub tls: TlsSettings,

    #[builder(default, setter(into))]
    pub http2: Option<Http2Settings>,

    #[builder(default, setter(into))]
    pub headers: Option<HeaderMap>,

    #[builder(default, setter(strip_option, into))]
    pub headers_order: Option<Cow<'static, [HeaderName]>>,
}

/// ========= ImpersonateSettings impls =========
impl From<Impersonate> for ImpersonateSettings {
    fn from(impersonate: Impersonate) -> Self {
        Impersonate::builder().impersonate(impersonate).build()
    }
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
impl Impersonate {
    #[inline]
    pub fn builder() -> ImpersonateBuilder {
        ImpersonateBuilder {
            impersonate: Default::default(),
            impersonate_os: Default::default(),
            skip_http2: false,
            skip_headers: false,
        }
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
