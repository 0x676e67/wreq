#[macro_export]
macro_rules! conditional_headers {
    ($with_headers:expr, $initializer:expr) => {
        if $with_headers {
            use std::borrow::Cow;
            use std::sync::LazyLock;
            static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new($initializer);
            Some(Cow::Borrowed(&*HEADER_INITIALIZER))
        } else {
            None
        }
    };
    ($with_headers:expr, $initializer:expr, $ua:expr) => {
        if $with_headers {
            use std::borrow::Cow;
            use std::sync::LazyLock;
            static HEADER_INITIALIZER: LazyLock<HeaderMap> = LazyLock::new(|| $initializer($ua));
            Some(Cow::Borrowed(&*HEADER_INITIALIZER))
        } else {
            None
        }
    };
}

#[macro_export]
macro_rules! header_chrome_edge_sec_ch_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert("sec-ch-ua", HeaderValue::from_static($ua));
        $headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
        $headers.insert("sec-ch-ua-platform", HeaderValue::from_static("\"macOS\""));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_sec_fetch {
    ($headers:expr) => {
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        $headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        $headers.insert(USER_AGENT, HeaderValue::from_static($ua));
    };
}


#[macro_export]
macro_rules! header_chrome_edge_accpet {
    ($headers:expr) => {
        $headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    };
}

#[macro_export]
macro_rules! header_chrome_edge_accpet_with_zstd {
    ($headers:expr) => {
        $headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"));
        $headers.insert(
            ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        $headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    };
}

#[macro_export]
macro_rules! header_firefox_sec_fetch {
    (1, $headers:expr) => {
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
        $headers.insert("sec-fetch-user", HeaderValue::from_static("?1"));
    };
    (2, $headers:expr) => {
        $headers.insert("sec-fetch-dest", HeaderValue::from_static("document"));
        $headers.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
        $headers.insert("sec-fetch-site", HeaderValue::from_static("none"));
    };
}

#[macro_export]
macro_rules! header_firefox_accept {
    ($headers:expr) => {
        $headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        $headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br"),
        );
        $headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.5"),
        );

    };
}


#[macro_export]
macro_rules! header_firefox_accpet_with_zstd {
    ($headers:expr) => {
        $headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        );
        $headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("gzip, deflate, br, zstd"),
        );
        $headers.insert(
            header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en-US,en;q=0.5"),
        );

    };
}


#[macro_export]
macro_rules! header_firefox_ua {
    ($headers:expr, $ua:expr) => {
        $headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        $headers.insert(USER_AGENT, HeaderValue::from_static($ua));
    };
}


#[macro_export]
macro_rules! static_join {
    ($sep:expr, $first:expr $(, $rest:expr)*) => {
        concat!($first $(, $sep, $rest)*)
    };
}

macro_rules! impersonate_match {
    ($ver:expr, $with_headers:expr, $($variant:pat => $path:path),+) => {
        match $ver {
            $(
                $variant => {
                    $path($with_headers)
                },
            )+
        }
    }
}

macro_rules! impl_from_str {
    ($(($variant:ident, $string:expr)),* $(,)?) => {
        impl FromStr for Impersonate {
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
