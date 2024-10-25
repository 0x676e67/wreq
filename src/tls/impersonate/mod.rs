#![allow(missing_docs, missing_debug_implementations)]

pub mod chrome;
pub mod edge;
pub mod http2;
pub mod okhttp;
pub mod safari;
pub mod tls;

use super::TlsResult;
use chrome::*;
use edge::*;
use http::HeaderMap;
use http2::Http2Settings;
use okhttp::*;
use safari::*;
use std::{fmt::Debug, str::FromStr};
use tls::TlsSettings;
use typed_builder::TypedBuilder;
use Impersonate::*;

/// Impersonate Settings.
#[derive(TypedBuilder)]
pub struct ImpersonateSettings {
    /// The SSL connector builder.
    pub(crate) tls: TlsSettings,

    /// HTTP/2 settings.
    pub(crate) http2: Http2Settings,

    /// Http headers
    #[builder(default, setter(strip_option))]
    pub(crate) headers: Option<Box<dyn FnOnce(&mut HeaderMap)>>,
}

macro_rules! impersonate_match {
    ($ver:expr, $($variant:pat => $path:path),+) => {
        match $ver {
            $(
                $variant => {
                    $path()
                },
            )+
        }
    }
}

/// Get the connection settings for the given impersonate version
pub fn tls_settings(ver: Impersonate) -> TlsResult<ImpersonateSettings> {
    impersonate_match!(
        ver,
        // Chrome
        Chrome100 => v100::get_settings,
        Chrome101 => v101::get_settings,
        Chrome104 => v104::get_settings,
        Chrome105 => v105::get_settings,
        Chrome106 => v106::get_settings,
        Chrome107 => v107::get_settings,
        Chrome108 => v108::get_settings,
        Chrome109 => v109::get_settings,
        Chrome114 => v114::get_settings,
        Chrome116 => v116::get_settings,
        Chrome117 => v117::get_settings,
        Chrome118 => v118::get_settings,
        Chrome119 => v119::get_settings,
        Chrome120 => v120::get_settings,
        Chrome123 => v123::get_settings,
        Chrome124 => v124::get_settings,
        Chrome126 => v126::get_settings,
        Chrome127 => v127::get_settings,
        Chrome128 => v128::get_settings,
        Chrome129 => v129::get_settings,
        Chrome130 => v130::get_settings,

        // Safari
        SafariIos17_2 => safari_ios_17_2::get_settings,
        SafariIos17_4_1 => safari_ios_17_4_1::get_settings,
        SafariIos16_5 => safari_ios_16_5::get_settings,
        Safari15_3 => safari15_3::get_settings,
        Safari15_5 => safari15_5::get_settings,
        Safari15_6_1 => safari15_6_1::get_settings,
        Safari16 => safari16::get_settings,
        Safari16_5 => safari16_5::get_settings,
        Safari17_0 => safari17_0::get_settings,
        Safari17_2_1 => safari17_2_1::get_settings,
        Safari17_4_1 => safari17_4_1::get_settings,
        Safari17_5 => safari17_5::get_settings,
        Safari18 => safari18::get_settings,
        SafariIPad18 => safari_ipad_18::get_settings,

        // OkHttp
        OkHttp3_9 => okhttp3_9::get_settings,
        OkHttp3_11 => okhttp3_11::get_settings,
        OkHttp3_13 => okhttp3_13::get_settings,
        OkHttp3_14 => okhttp3_14::get_settings,
        OkHttp4_9 => okhttp4_9::get_settings,
        OkHttp4_10 => okhttp4_10::get_settings,
        OkHttp5 => okhttp5::get_settings,

        // Edge
        Edge101 => edge101::get_settings,
        Edge122 => edge122::get_settings,
        Edge127 => edge127::get_settings
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub enum Impersonate {
    // Chrome
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
    #[default]
    Chrome130,

    // Safari
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

    // OkHttp
    OkHttp3_9,
    OkHttp3_11,
    OkHttp3_13,
    OkHttp3_14,
    OkHttp4_9,
    OkHttp4_10,
    OkHttp5,

    // Edge
    Edge101,
    Edge122,
    Edge127,
}

/// Impersonate version from string
impl FromStr for Impersonate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            // Chrome
            "chrome_100" => Ok(Chrome100),
            "chrome_101" => Ok(Chrome101),
            "chrome_104" => Ok(Chrome104),
            "chrome_105" => Ok(Chrome105),
            "chrome_106" => Ok(Chrome106),
            "chrome_107" => Ok(Chrome107),
            "chrome_108" => Ok(Chrome108),
            "chrome_109" => Ok(Chrome109),
            "chrome_114" => Ok(Chrome114),
            "chrome_116" => Ok(Chrome116),
            "chrome_117" => Ok(Chrome117),
            "chrome_118" => Ok(Chrome118),
            "chrome_119" => Ok(Chrome119),
            "chrome_120" => Ok(Chrome120),
            "chrome_123" => Ok(Chrome123),
            "chrome_124" => Ok(Chrome124),
            "chrome_126" => Ok(Chrome126),
            "chrome_127" => Ok(Chrome127),
            "chrome_128" => Ok(Chrome128),
            "chrome_129" => Ok(Chrome129),
            "chrome_130" => Ok(Chrome129),

            // Safari
            "safari_ios_17.2" => Ok(SafariIos17_2),
            "safari_ios_17.4.1" => Ok(SafariIos17_4_1),
            "safari_15.3" => Ok(Safari15_3),
            "safari_15.5" => Ok(Safari15_5),
            "safari_15.6.1" => Ok(Safari15_6_1),
            "safari_16" => Ok(Safari16),
            "safari_16.5" => Ok(Safari16_5),
            "safari_ios_16.5" => Ok(SafariIos16_5),
            "safari_17.0" => Ok(Safari17_0),
            "safari_17.2.1" => Ok(Safari17_2_1),
            "safari_17.4.1" => Ok(Safari17_4_1),
            "safari_17.5" => Ok(Safari17_5),
            "safari_18" => Ok(Safari18),
            "safari_ipad_18" => Ok(SafariIPad18),

            // OkHttp
            "okhttp_3.9" => Ok(OkHttp3_9),
            "okhttp_3.11" => Ok(OkHttp3_11),
            "okhttp_3.13" => Ok(OkHttp3_13),
            "okhttp_3.14" => Ok(OkHttp3_14),
            "okhttp_4.9" => Ok(OkHttp4_9),
            "okhttp_4.10" => Ok(OkHttp4_10),
            "okhttp_5" => Ok(OkHttp5),

            // Edge
            "edge_101" => Ok(Edge101),
            "edge_122" => Ok(Edge122),
            "edge_127" => Ok(Edge127),
            _ => Err(format!("Unknown impersonate version: {}", s)),
        }
    }
}
