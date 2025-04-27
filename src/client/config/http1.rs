/// Builder for `Http1Config`.
#[derive(Debug)]
pub struct Http1ConfigBuilder {
    config: Http1Config,
}

/// Configuration config for HTTP/1 connections.
///
/// The `Http1Config` struct provides various configuration options for HTTP/1 connections.
/// These config allow you to customize the behavior of the HTTP/1 client, such as
/// enabling support for HTTP/0.9 responses, allowing spaces after header names, and more.
#[derive(Clone, Debug)]
pub struct Http1Config {
    pub(crate) http09_responses: bool,
    pub(crate) writev: Option<bool>,
    pub(crate) title_case_headers: bool,
    pub(crate) preserve_header_case: bool,
    pub(crate) max_headers: usize,
    pub(crate) read_buf_exact_size: Option<usize>,
    pub(crate) max_buf_size: usize,
    pub(crate) allow_spaces_after_header_name_in_responses: bool,
    pub(crate) allow_obsolete_multiline_headers_in_responses: bool,
    pub(crate) ignore_invalid_headers_in_responses: bool,
}

impl Http1ConfigBuilder {
    /// Set the `http09_responses` field.
    pub fn http09_responses(mut self, http09_responses: bool) -> Self {
        self.config.http09_responses = http09_responses;
        self
    }

    /// Set the `writev` field.
    pub fn writev(mut self, writev: Option<bool>) -> Self {
        self.config.writev = writev;
        self
    }

    /// Set the `title_case_headers` field.
    pub fn title_case_headers(mut self, title_case_headers: bool) -> Self {
        self.config.title_case_headers = title_case_headers;
        self
    }

    /// Set the `preserve_header_case` field.
    pub fn preserve_header_case(mut self, preserve_header_case: bool) -> Self {
        self.config.preserve_header_case = preserve_header_case;
        self
    }

    /// Set the `max_headers` field.
    pub fn max_headers(mut self, max_headers: usize) -> Self {
        self.config.max_headers = max_headers;
        self
    }

    /// Set the `read_buf_exact_size` field.
    pub fn read_buf_exact_size(mut self, read_buf_exact_size: Option<usize>) -> Self {
        self.config.read_buf_exact_size = read_buf_exact_size;
        self
    }

    /// Set the `max_buf_size` field.
    pub fn max_buf_size(mut self, max_buf_size: usize) -> Self {
        self.config.max_buf_size = max_buf_size;
        self
    }

    /// Set the `allow_spaces_after_header_name_in_responses` field.
    pub fn allow_spaces_after_header_name_in_responses(
        mut self,
        allow_spaces_after_header_name_in_responses: bool,
    ) -> Self {
        self.config.allow_spaces_after_header_name_in_responses =
            allow_spaces_after_header_name_in_responses;
        self
    }

    /// Set the `allow_obsolete_multiline_headers_in_responses` field.
    pub fn allow_obsolete_multiline_headers_in_responses(
        mut self,
        allow_obsolete_multiline_headers_in_responses: bool,
    ) -> Self {
        self.config.allow_obsolete_multiline_headers_in_responses =
            allow_obsolete_multiline_headers_in_responses;
        self
    }

    /// Set the `ignore_invalid_headers_in_responses` field.
    pub fn ignore_invalid_headers_in_responses(
        mut self,
        ignore_invalid_headers_in_responses: bool,
    ) -> Self {
        self.config.ignore_invalid_headers_in_responses = ignore_invalid_headers_in_responses;
        self
    }

    /// Build the `Http1Config` instance.
    pub fn build(self) -> Http1Config {
        self.config
    }
}

impl Default for Http1Config {
    fn default() -> Self {
        Http1Config {
            http09_responses: false,
            writev: None,
            title_case_headers: false,
            preserve_header_case: false,
            max_headers: 100,
            read_buf_exact_size: None,
            max_buf_size: 4096 * 100,
            allow_spaces_after_header_name_in_responses: false,
            allow_obsolete_multiline_headers_in_responses: false,
            ignore_invalid_headers_in_responses: false,
        }
    }
}

impl Http1Config {
    /// Create a new `Http1ConfigBuilder`.
    pub fn builder() -> Http1ConfigBuilder {
        Http1ConfigBuilder {
            config: Http1Config::default(),
        }
    }
}
