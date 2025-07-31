//! This module provides a builder pattern for configuring HTTP/1 connections.

/// Builder for `Http1Options`.
#[must_use]
#[derive(Debug)]
pub struct Http1OptionsBuilder {
    opts: Http1Options,
}

/// HTTP/1 protocol options for customizing connection behavior.
///
/// These options allow you to customize the behavior of HTTP/1 connections,
/// such as enabling support for HTTP/0.9 responses, header case preservation, etc.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub struct Http1Options {
    /// Enable support for HTTP/0.9 responses.
    pub h09_responses: bool,

    /// Whether to use vectored writes for HTTP/1 connections.
    pub h1_writev: Option<bool>,

    /// Whether to preserve the original case of headers in HTTP/1 responses.
    pub h1_preserve_header_case: bool,

    /// Maximum number of headers allowed in HTTP/1 responses.
    pub h1_max_headers: Option<usize>,

    /// Exact size of the read buffer to use for HTTP/1 connections.
    pub h1_read_buf_exact_size: Option<usize>,

    /// Maximum buffer size for HTTP/1 connections.
    pub h1_max_buf_size: Option<usize>,

    /// Whether to ignore invalid headers in HTTP/1 responses.
    pub ignore_invalid_headers_in_responses: bool,

    /// Whether to allow spaces after header names in HTTP/1 responses.
    pub allow_spaces_after_header_name_in_responses: bool,

    /// Whether to allow obsolete multiline headers in HTTP/1 responses.
    pub allow_obsolete_multiline_headers_in_responses: bool,
}

impl Http1OptionsBuilder {
    /// Set the `http09_responses` field.
    #[inline]
    pub fn http09_responses(mut self, enabled: bool) -> Self {
        self.opts.h09_responses = enabled;
        self
    }

    /// Set whether HTTP/1 connections should try to use vectored writes,
    /// or always flatten into a single buffer.
    ///
    /// Note that setting this to false may mean more copies of body data,
    /// but may also improve performance when an IO transport doesn't
    /// support vectored writes well, such as most TLS implementations.
    ///
    /// Setting this to true will force crate::core: to use queued strategy
    /// which may eliminate unnecessary cloning on some TLS backends
    ///
    /// Default is `auto`. In this mode crate::core: will try to guess which
    /// mode to use
    #[inline]
    pub fn writev(mut self, writev: Option<bool>) -> Self {
        self.opts.h1_writev = writev;
        self
    }

    /// Set whether to support preserving original header cases.
    ///
    /// Currently, this will record the original cases received, and store them
    /// in a http extension on the `Response`. It will also look for and use
    /// such an extension in any provided `Request`.
    ///
    /// Default is false.
    #[inline]
    pub fn preserve_header_case(mut self, preserve_header_case: bool) -> Self {
        self.opts.h1_preserve_header_case = preserve_header_case;
        self
    }

    /// Set the maximum number of headers.
    ///
    /// When a response is received, the parser will reserve a buffer to store headers for optimal
    /// performance.
    ///
    /// If client receives more headers than the buffer size, the error "message header too large"
    /// is returned.
    ///
    /// Note that headers is allocated on the stack by default, which has higher performance. After
    /// setting this value, headers will be allocated in heap memory, that is, heap memory
    /// allocation will occur for each response, and there will be a performance drop of about 5%.
    ///
    /// Default is 100.
    #[inline]
    pub fn max_headers(mut self, max_headers: usize) -> Self {
        self.opts.h1_max_headers = Some(max_headers);
        self
    }

    /// Sets the exact size of the read buffer to *always* use.
    ///
    /// Note that setting this option unsets the `max_buf_size` option.
    ///
    /// Default is an adaptive read buffer.
    #[inline]
    pub fn read_buf_exact_size(mut self, sz: Option<usize>) -> Self {
        self.opts.h1_read_buf_exact_size = sz;
        self.opts.h1_max_buf_size = None;
        self
    }

    /// Set the maximum buffer size for the connection.
    ///
    /// Default is ~400kb.
    ///
    /// Note that setting this option unsets the `read_exact_buf_size` option.
    ///
    /// # Panics
    ///
    /// The minimum value allowed is 8192. This method panics if the passed `max` is less than the
    /// minimum.
    #[inline]
    pub fn max_buf_size(mut self, max: usize) -> Self {
        assert!(
            max >= super::super::proto::h1::MINIMUM_MAX_BUFFER_SIZE,
            "the max_buf_size cannot be smaller than the minimum that h1 specifies."
        );

        self.opts.h1_max_buf_size = Some(max);
        self.opts.h1_read_buf_exact_size = None;
        self
    }

    /// Set whether HTTP/1 connections will accept spaces between header names
    /// and the colon that follow them in responses.
    ///
    /// You probably don't need this, here is what [RFC 7230 Section 3.2.4.] has
    /// to say about it:
    ///
    /// > No whitespace is allowed between the header field-name and colon. In
    /// > the past, differences in the handling of such whitespace have led to
    /// > security vulnerabilities in request routing and response handling. A
    /// > server MUST reject any received request message that contains
    /// > whitespace between a header field-name and colon with a response code
    /// > of 400 (Bad Request). A proxy MUST remove any such whitespace from a
    /// > response message before forwarding the message downstream.
    ///
    /// Default is false.
    ///
    /// [RFC 7230 Section 3.2.4.]: https://tools.ietf.org/html/rfc7230#section-3.2.4
    #[inline]
    pub fn allow_spaces_after_header_name_in_responses(mut self, enabled: bool) -> Self {
        self.opts.allow_spaces_after_header_name_in_responses = enabled;
        self
    }

    /// Set whether HTTP/1 connections will silently ignored malformed header lines.
    ///
    /// If this is enabled and a header line does not start with a valid header
    /// name, or does not include a colon at all, the line will be silently ignored
    /// and no error will be reported.
    ///
    /// Default is false.
    #[inline]
    pub fn ignore_invalid_headers_in_responses(mut self, enabled: bool) -> Self {
        self.opts.ignore_invalid_headers_in_responses = enabled;
        self
    }

    /// Set the `allow_obsolete_multiline_headers_in_responses` field.
    #[inline]
    pub fn allow_obsolete_multiline_headers_in_responses(mut self, value: bool) -> Self {
        self.opts.allow_obsolete_multiline_headers_in_responses = value;
        self
    }

    /// Build the [`Http1Options`] instance.
    #[inline]
    pub fn build(self) -> Http1Options {
        self.opts
    }
}

impl Http1Options {
    /// Create a new [`Http1OptionsBuilder`].
    pub fn builder() -> Http1OptionsBuilder {
        Http1OptionsBuilder {
            opts: Http1Options::default(),
        }
    }
}
