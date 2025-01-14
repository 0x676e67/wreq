#[macro_export]
macro_rules! conditional_headers {
    ($with_headers:expr, $initializer:expr) => {
        if $with_headers {
            Some($initializer())
        } else {
            None
        }
    };
    ($with_headers:expr, $initializer:expr, $ua:expr) => {
        if $with_headers {
            Some($initializer($ua))
        } else {
            None
        }
    };
}

#[macro_export]
macro_rules! header_chrome_sec_ch_ua {
    ($headers:expr, $ua:expr, $platform:expr, $is_mobile:expr) => {
        let mobile = if $is_mobile { "?1" } else { "?0" };
        $headers.insert("sec-ch-ua", HeaderValue::from_static($ua));
        $headers.insert("sec-ch-ua-mobile", HeaderValue::from_static(mobile));
        $headers.insert("sec-ch-ua-platform", HeaderValue::from_static($platform));
    };
}

#[macro_export]
macro_rules! header_chrome_sec_fetch {
    ($headers:expr) => {
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    };
}

#[macro_export]
macro_rules! header_chrome_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        $headers.insert(USER_AGENT, HeaderValue::from_static($ua));
    };
}

#[macro_export]
macro_rules! header_chrome_accpet {
    ($headers:expr) => {
        $headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    };
    (zstd, $headers:expr) => {
        $headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        #[cfg(all(
            feature = "gzip",
            feature = "deflate",
            feature = "brotli",
            feature = "zstd"
        ))]
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    }
}

#[macro_export]
macro_rules! header_firefox_sec_fetch {
    ($headers:expr) => {
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    };
}

#[macro_export]
macro_rules! header_firefox_accept {
    ($headers:expr) => {
        $headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        #[cfg(all(feature = "gzip", feature = "deflate", feature = "brotli"))]
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    };
    (zstd, $headers:expr) => {
        $headers.insert(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        #[cfg(all(
            feature = "gzip",
            feature = "deflate",
            feature = "brotli",
            feature = "zstd"
        ))]
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    };
}

#[macro_export]
macro_rules! header_firefox_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert(
            HeaderName::from_static("te"),
            HeaderValue::from_static("trailers"),
        );
        $headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        $headers.insert(USER_AGENT, HeaderValue::from_static($ua));
    };
}

#[macro_export]
macro_rules! join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

macro_rules! impersonate_match {
    ($ver:expr, $with_headers:expr, $os:expr, $($variant:pat => $path:expr),+) => {
        match $ver {
            $(
                $variant => $path($with_headers, $os),
            )+
        }
    }
}

#[cfg(feature = "impersonate_str")]
macro_rules! impl_from_str {
    ($(($variant:ident, $string:expr)),* $(,)?) => {
        impl std::str::FromStr for Impersonate {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $string => Ok(Impersonate::$variant), )*
                    _ => Err(format!("Unknown impersonate version: {}", s)),
                }
            }
        }
    };
}

#[cfg(feature = "impersonate_str")]
macro_rules! impl_os_from_str {
    ($(($variant:ident, $string:expr)),* $(,)?) => {
        impl std::str::FromStr for ImpersonateOS {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $( $string => Ok(ImpersonateOS::$variant), )*
                    _ => Err(format!("Unknown impersonate os: {}", s)),
                }
            }
        }
    };
}
