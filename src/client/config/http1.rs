use typed_builder::TypedBuilder;

/// Configuration config for HTTP/1 connections.
///
/// The `Http1Config` struct provides various configuration options for HTTP/1 connections.
/// These config allow you to customize the behavior of the HTTP/1 client, such as
/// enabling support for HTTP/0.9 responses, allowing spaces after header names, and more.
#[derive(Clone, Debug, TypedBuilder)]
pub struct Http1Config {
    #[builder(default = false)]
    pub(crate) http09_responses: bool,

    #[builder(default)]
    pub(crate) writev: Option<bool>,

    #[builder(default = false)]
    pub(crate) title_case_headers: bool,

    #[builder(default = false)]
    pub(crate) preserve_header_case: bool,

    #[builder(default = 100)]
    pub(crate) max_headers: usize,

    #[builder(default)]
    pub(crate) read_buf_exact_size: Option<usize>,

    #[builder(default = 4096 * 100)]
    pub(crate) max_buf_size: usize,

    #[builder(default = false)]
    pub(crate) allow_spaces_after_header_name_in_responses: bool,

    #[builder(default = false)]
    pub(crate) allow_obsolete_multiline_headers_in_responses: bool,

    #[builder(default = false)]
    pub(crate) ignore_invalid_headers_in_responses: bool,
}

impl Default for Http1Config {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl Http1Config {
    /// Set whether HTTP/0.9 responses should be tolerated.
    ///
    /// Default is false.
    pub fn set_http09_responses(&mut self, http09_responses: bool) -> &mut Self {
        self.http09_responses = http09_responses;
        self
    }

    /// Set whether HTTP/1 connections should try to use vectored writes,
    /// or always flatten into a single buffer.
    ///
    /// Note that setting this to false may mean more copies of body data,
    /// but may also improve performance when an IO transport doesn't
    /// support vectored writes well, such as most TLS implementations.
    ///
    /// Setting this to true will force hyper to use queued strategy
    /// which may eliminate unnecessary cloning on some TLS backends.
    ///
    /// Default is `auto`. In this mode hyper will try to guess which
    /// mode to use.
    pub fn set_writev(&mut self, writev: bool) -> &mut Self {
        self.writev = Some(writev);
        self
    }

    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is false.
    pub fn set_title_case_headers(&mut self, title_case_headers: bool) -> &mut Self {
        self.title_case_headers = title_case_headers;
        self
    }

    /// Set whether to support preserving original header cases.
    ///
    /// Currently, this will record the original cases received, and store them
    /// in a private extension on the `Response`. It will also look for and use
    /// such an extension in any provided `Request`.
    ///
    /// Since the relevant extension is still private, there is no way to
    /// interact with the original cases. The only effect this can have now is
    /// to forward the cases in a proxy-like fashion.
    ///
    /// Default is false.
    pub fn set_preserve_header_case(&mut self, preserve_header_case: bool) -> &mut Self {
        self.preserve_header_case = preserve_header_case;
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
    pub fn max_headers(&mut self, max_headers: usize) -> &mut Self {
        self.max_headers = max_headers;
        self
    }

    /// Sets the exact size of the read buffer to *always* use.
    ///
    /// Note that setting this option unsets the `max_buf_size` option.
    ///
    /// Default is an adaptive read buffer.
    pub fn set_read_buf_exact_size(&mut self, read_buf_exact_size: usize) -> &mut Self {
        self.read_buf_exact_size = Some(read_buf_exact_size);
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
    /// The minimum value allowed is 8192. This method panics if the passed `max` is less than the minimum.
    pub fn set_max_buf_size(&mut self, max_buf_size: usize) -> &mut Self {
        self.max_buf_size = max_buf_size;
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
    pub fn set_allow_spaces_after_header_name_in_responses(&mut self, allow: bool) -> &mut Self {
        self.allow_spaces_after_header_name_in_responses = allow;
        self
    }

    /// Set whether HTTP/1 connections will accept obsolete line folding for
    /// header values.
    ///
    /// Newline codepoints (`\r` and `\n`) will be transformed to spaces when
    /// parsing.
    ///
    /// You probably don't need this, here is what [RFC 7230 Section 3.2.4.] has
    /// to say about it:
    ///
    /// > A server that receives an obs-fold in a request message that is not
    /// > within a message/http container MUST either reject the message by
    /// > sending a 400 (Bad Request), preferably with a representation
    /// > explaining that obsolete line folding is unacceptable, or replace
    /// > each received obs-fold with one or more SP octets prior to
    /// > interpreting the field value or forwarding the message downstream.
    ///
    /// > A proxy or gateway that receives an obs-fold in a response message
    /// > that is not within a message/http container MUST either discard the
    /// > message and replace it with a 502 (Bad Gateway) response, preferably
    /// > with a representation explaining that unacceptable line folding was
    /// > received, or replace each received obs-fold with one or more SP
    /// > octets prior to interpreting the field value or forwarding the
    /// > message downstream.
    ///
    /// > A user agent that receives an obs-fold in a response message that is
    /// > not within a message/http container MUST replace each received
    /// > obs-fold with one or more SP octets prior to interpreting the field
    /// > value.
    ///
    /// Default is false.
    ///
    /// [RFC 7230 Section 3.2.4.]: https://tools.ietf.org/html/rfc7230#section-3.2.4
    pub fn set_allow_obsolete_multiline_headers_in_responses(&mut self, allow: bool) -> &mut Self {
        self.allow_obsolete_multiline_headers_in_responses = allow;
        self
    }

    /// Set whether HTTP/1 connections will silently ignored malformed header lines.
    ///
    /// If this is enabled and a header line does not start with a valid header
    /// name, or does not include a colon at all, the line will be silently ignored
    /// and no error will be reported.
    ///
    /// Default is false.
    pub fn set_ignore_invalid_headers_in_responses(&mut self, ignore: bool) -> &mut Self {
        self.ignore_invalid_headers_in_responses = ignore;
        self
    }
}
