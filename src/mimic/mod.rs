//! Mimic settings for different browsers.
#![allow(missing_debug_implementations)]
#![allow(missing_docs)]

#[macro_use]
mod macros;
mod chrome;
mod firefox;
mod okhttp;
mod safari;

use http::{HeaderMap, HeaderName};
use Impersonate::*;

use chrome::*;
use firefox::*;
use okhttp::*;
use safari::*;

use impersonate_imports::*;
use tls_imports::TlsSettings;

mod impersonate_imports {
    pub use crate::{http2::Http2Settings, mimic::ImpersonateSettings};
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
        AlpnProtos, AlpsProto, CertCompressionAlgorithm, TlsSettings, TlsVersion,
    };
    pub use boring::ssl::{ExtensionType, SslCurve};
    pub use std::borrow::Cow;
    pub use typed_builder::TypedBuilder;
}

mod http2_imports {
    pub use hyper2::PseudoOrder::{self, *};
    pub use hyper2::SettingsOrder::{self, *};
    pub use hyper2::{Priority, StreamDependency, StreamId};
    pub use std::sync::LazyLock;
}

#[derive(typed_builder::TypedBuilder, Debug)]
pub struct ImpersonateSettings {
    pub tls: TlsSettings,

    #[builder(default, setter(into))]
    pub http2: Option<Http2Settings>,

    #[builder(default, setter(into))]
    pub headers: Option<Cow<'static, HeaderMap>>,

    #[builder(default, setter(into))]
    pub headers_order: Option<Cow<'static, [HeaderName]>>,
}

#[inline]
pub fn impersonate(ver: Impersonate, with_headers: bool) -> ImpersonateSettings {
    impersonate_match!(
        ver,
        with_headers,
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

#[derive(Clone, Copy, Debug, Default)]
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

#[cfg(feature = "impersonate_str")]
impl_from_str! {
    (Chrome100, "chrome_100"),
    (Chrome101, "chrome_101"),
    (Chrome104, "chrome_104"),
    (Chrome105, "chrome_105"),
    (Chrome106, "chrome_106"),
    (Chrome107, "chrome_107"),
    (Chrome108, "chrome_108"),
    (Chrome109, "chrome_109"),
    (Chrome114, "chrome_114"),
    (Chrome116, "chrome_116"),
    (Chrome117, "chrome_117"),
    (Chrome118, "chrome_118"),
    (Chrome119, "chrome_119"),
    (Chrome120, "chrome_120"),
    (Chrome123, "chrome_123"),
    (Chrome124, "chrome_124"),
    (Chrome126, "chrome_126"),
    (Chrome127, "chrome_127"),
    (Chrome128, "chrome_128"),
    (Chrome129, "chrome_129"),
    (Chrome130, "chrome_130"),
    (Chrome131, "chrome_131"),

    (SafariIos17_2, "safari_ios_17.2"),
    (SafariIos17_4_1, "safari_ios_17.4.1"),
    (SafariIos16_5, "safari_ios_16.5"),
    (Safari15_3, "safari_15.3"),
    (Safari15_5, "safari_15.5"),
    (Safari15_6_1, "safari_15.6.1"),
    (Safari16, "safari_16"),
    (Safari16_5, "safari_16.5"),
    (Safari17_0, "safari_17.0"),
    (Safari17_2_1, "safari_17.2.1"),
    (Safari17_4_1, "safari_17.4.1"),
    (Safari17_5, "safari_17.5"),
    (Safari18, "safari_18"),
    (SafariIPad18, "safari_ipad_18"),
    (Safari18_2, "safari_18.2"),
    (SafariIos18_1_1, "safari_ios_18.1.1"),

    (OkHttp3_9, "okhttp_3.9"),
    (OkHttp3_11, "okhttp_3.11"),
    (OkHttp3_13, "okhttp_3.13"),
    (OkHttp3_14, "okhttp_3.14"),
    (OkHttp4_9, "okhttp_4.9"),
    (OkHttp4_10, "okhttp_4.10"),
    (OkHttp5, "okhttp_5"),

    (Edge101, "edge_101"),
    (Edge122, "edge_122"),
    (Edge127, "edge_127"),
    (Edge131, "edge_131"),

    (Firefox109, "firefox_109"),
    (Firefox117, "firefox_117"),
    (Firefox128, "firefox_128"),
    (Firefox133, "firefox_133"),
}
