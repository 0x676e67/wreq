use typed_builder::TypedBuilder;

/// Configuration config for HTTP/1 connections.
///
/// The `Http1Config` struct provides various configuration options for HTTP/1 connections.
/// These config allow you to customize the behavior of the HTTP/1 client, such as
/// enabling support for HTTP/0.9 responses, allowing spaces after header names, and more.
#[derive(Clone, Debug, TypedBuilder, Default)]
pub struct Http1Config {
    /// Set whether HTTP/0.9 responses should be tolerated.
    ///
    /// Default is false.
    #[builder(default = false)]
    pub http09_responses: bool,

    /// Set whether HTTP/1 connections should try to use vectored writes,
    /// or always flatten into a single buffer.
    ///
    /// Note that setting this to false may mean more copies of body data,
    /// but may also improve performance when an IO transport doesn't
    /// support vectored writes well, such as most TLS implementations.
    ///
    /// Setting this to true will force hyper to use queued strategy
    /// which may eliminate unnecessary cloning on some TLS backends
    ///
    /// Default is `auto`. In this mode hyper will try to guess which
    /// mode to use
    #[builder(default)]
    pub writev: Option<bool>,

    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is false.
    #[builder(default = false)]
    pub title_case_headers: bool,

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
    #[builder(default = false)]
    pub preserve_header_case: bool,

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
    #[builder(default = 100)]
    pub max_headers: usize,

    /// Sets the exact size of the read buffer to *always* use.
    ///
    /// Note that setting this option unsets the `max_buf_size` option.
    ///
    /// Default is an adaptive read buffer.
    #[builder(default)]
    pub read_buf_exact_size: Option<usize>,

    /// Set the maximum buffer size for the connection.
    ///
    /// Default is ~400kb.
    ///
    /// Note that setting this option unsets the `read_exact_buf_size` option.
    ///
    /// # Panics
    ///
    /// The minimum value allowed is 8192. This method panics if the passed `max` is less than the minimum.
    #[builder(default = 4096 * 100)]
    pub max_buf_size: usize,

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
    #[builder(default = false)]
    pub allow_spaces_after_header_name_in_responses: bool,

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
    #[builder(default = false)]
    pub allow_obsolete_multiline_headers_in_responses: bool,

    /// Set whether HTTP/1 connections will silently ignored malformed header lines.
    ///
    /// If this is enabled and a header line does not start with a valid header
    /// name, or does not include a colon at all, the line will be silently ignored
    /// and no error will be reported.
    ///
    /// Default is false.
    #[builder(default = false)]
    pub ignore_invalid_headers_in_responses: bool,
}
