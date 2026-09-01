use std::fmt;

/// Selects the transport, HTTP version, and runtime for one benchmark target.
#[derive(Clone, Copy, Debug)]
pub struct BenchTarget {
    pub tls: Tls,
    pub http_version: HttpVersion,
    pub thread_mode: ThreadMode,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum HttpVersion {
    Http1,
    Http2,
}

// ===== impl HttpVersion =====

impl HttpVersion {
    pub(crate) const fn expected(self) -> http::Version {
        match self {
            Self::Http1 => http::Version::HTTP_11,
            Self::Http2 => http::Version::HTTP_2,
        }
    }
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http1 => "h1",
            Self::Http2 => "h2",
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Tls {
    Enabled,
    Disabled,
}

// ===== impl Tls =====

impl Tls {
    pub(crate) const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl fmt::Display for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Enabled => "https",
            Self::Disabled => "http",
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum ThreadMode {
    Current,
    Multi,
}

// ===== impl ThreadMode =====

impl fmt::Display for ThreadMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Current => "current_thread",
            Self::Multi => "multi_thread",
        })
    }
}

/// Defines the request bytes and stream chunk size for one body case.
#[derive(Clone, Copy, Debug)]
pub struct BodyCase {
    pub bytes: &'static [u8],
    pub chunk_size: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum BodyKind {
    Full,
    Stream,
}

// ===== impl BodyKind =====

impl BodyKind {
    pub(crate) const ALL: [Self; 2] = [Self::Full, Self::Stream];

    pub(crate) const fn is_stream(self) -> bool {
        matches!(self, Self::Stream)
    }
}

impl fmt::Display for BodyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Full => "full",
            Self::Stream => "stream",
        })
    }
}

pub(crate) const CONCURRENT_CASES: &[usize] = &[10, 50, 100, 150];

pub(crate) const BODY_CASES: &[BodyCase] = &[
    BodyCase {
        bytes: &[b'a'; 1024],
        chunk_size: 1024,
    },
    BodyCase {
        bytes: &[b'a'; 10 * 1024],
        chunk_size: 10 * 1024,
    },
    BodyCase {
        bytes: &[b'a'; 64 * 1024],
        chunk_size: 16 * 1024,
    },
    BodyCase {
        bytes: &[b'a'; 128 * 1024],
        chunk_size: 32 * 1024,
    },
    BodyCase {
        bytes: &[b'a'; 1024 * 1024],
        chunk_size: 64 * 1024,
    },
    BodyCase {
        bytes: &[b'a'; 2 * 1024 * 1024],
        chunk_size: 128 * 1024,
    },
    BodyCase {
        bytes: &[b'a'; 4 * 1024 * 1024],
        chunk_size: 256 * 1024,
    },
];
