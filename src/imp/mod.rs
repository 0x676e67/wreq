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

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Impersonate {
    Chrome100,
    Chrome101,
    Chrome104,
    Chrome105,
    Chrome106,
    Chrome107,
    Chrome108,
    Chrome109,
    Chrome114,
    Chrome116,
    Chrome117,
    Chrome118,
    Chrome119,
    Chrome120,
    Chrome123,
    Chrome124,
    Chrome126,
    Chrome127,
    Chrome128,
    Chrome129,
    Chrome130,
    #[default]
    Chrome131,

    SafariIos17_2,
    SafariIos17_4_1,
    SafariIos16_5,
    Safari15_3,
    Safari15_5,
    Safari15_6_1,
    Safari16,
    Safari16_5,
    Safari17_0,
    Safari17_2_1,
    Safari17_4_1,
    Safari17_5,
    Safari18,
    SafariIPad18,
    Safari18_2,
    SafariIos18_1_1,

    OkHttp3_9,
    OkHttp3_11,
    OkHttp3_13,
    OkHttp3_14,
    OkHttp4_9,
    OkHttp4_10,
    OkHttp5,

    Edge101,
    Edge122,
    Edge127,
    Edge131,

    Firefox109,
    Firefox117,
    Firefox128,
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

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpersonateOS {
    Windows,
    #[default]
    MacOS,
    Linux,
    Android,
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
