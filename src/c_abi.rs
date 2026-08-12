//! Stable C ABI for the synchronous request path.
//!
//! Strings in [`Request`] are borrowed, NUL-terminated UTF-8 input strings.
//! Strings and the body in [`Response`] are owned by the library and must be
//! released with [`wreq_response_free`]. Error strings are released with
//! [`wreq_error_free`].

#![allow(unsafe_code)]

use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
    sync::OnceLock,
    thread,
    time::Duration,
};

use http::header::{HeaderMap, HeaderName, HeaderValue};
use tokio::runtime::{Builder, Handle, Runtime};

use crate::{Client, Method, Proxy, header::OrigHeaderMap};

/// C-compatible request model.
#[repr(C)]
pub struct Request {
    /// Optional proxy URL.
    pub proxy_url: *const c_char,
    /// Required request URL.
    pub url: *const c_char,
    /// Optional HTTP method; defaults to `GET`.
    pub method: *const c_char,
    /// Optional NUL-terminated request body.
    pub body: *const c_char,
    /// Total request timeout in milliseconds; zero disables the override.
    pub timeout: c_int,
    /// Per-read idle timeout in milliseconds; zero disables the override.
    pub idle_timeout: c_int,
    /// Headers as `Name: value` lines separated by CRLF or LF.
    pub headers: *const c_char,
    /// Header names in preferred order, separated by commas or CRLF.
    pub header_order: *const c_char,
    /// Unsupported by wreq; reserved for a future named emulation profile.
    pub tls_profile: *const c_char,
    /// Unsupported by wreq; retained for ABI compatibility.
    pub id: *const c_char,
    /// Optional value for the `Cookie` request header.
    pub cookies: *const c_char,
    /// Unsupported: wreq does not expose an explicit close-idle-connections operation.
    pub close_idle_connections: bool,
}

/// C-compatible response model. All pointers are owned by the library.
#[repr(C)]
pub struct Response {
    /// Redirect location, if present.
    pub location: *mut c_char,
    /// HTTP protocol version (`HTTP/1.0`, `HTTP/1.1`, or `HTTP/2.0`).
    pub protocol: *mut c_char,
    /// Response body bytes.
    pub body: *mut u8,
    /// Number of bytes at [`Response::body`].
    pub body_length: c_int,
    /// Content-Type header, if present.
    pub content_type: *mut c_char,
    /// HTTP status code.
    pub status: c_int,
    /// Response headers as CRLF-separated `Name: value` lines.
    pub headers: *mut c_char,
    /// Final request URL after wreq processing.
    pub request_url: *mut c_char,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("wreq C ABI runtime initialization failed")
    })
}

fn c_string(value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| "value contains an embedded NUL byte".to_owned())
}

unsafe fn read_string(value: *const c_char, field: &str) -> Result<Option<String>, String> {
    if value.is_null() {
        return Ok(None);
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map(Some)
        .map_err(|_| format!("{field} is not valid UTF-8"))
}

fn parse_headers(input: Option<&str>) -> Result<HeaderMap, String> {
    let mut headers = HeaderMap::new();
    let Some(input) = input else {
        return Ok(headers);
    };
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("invalid header line: {line}"))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|err| format!("invalid header name: {err}"))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|err| format!("invalid header value: {err}"))?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn parse_header_order(input: Option<&str>) -> OrigHeaderMap {
    let mut order = OrigHeaderMap::new();
    if let Some(input) = input {
        for name in input
            .split(|ch: char| ch == ',' || ch == '\r' || ch == '\n')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            order.insert(name.to_owned());
        }
    }
    order
}

fn protocol(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "UNKNOWN",
    }
}

fn serialize_headers(headers: &http::HeaderMap) -> String {
    headers
        .iter()
        .map(|(name, value)| {
            format!(
                "{}: {}",
                name,
                value.to_str().unwrap_or("< non-UTF-8 header value >")
            )
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

struct OwnedResponse {
    response: Response,
}

impl OwnedResponse {
    fn new(response: crate::Response, body: Vec<u8>) -> Result<Self, String> {
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let values = [
            location.to_owned(),
            protocol(response.version()).to_owned(),
            content_type.to_owned(),
            serialize_headers(response.headers()),
            response.uri().to_string(),
        ];
        let mut allocations = values
            .into_iter()
            .map(|value| c_string(&value).map(CString::into_raw))
            .collect::<Result<Vec<_>, _>>()?;
        let body_length = c_int::try_from(body.len())
            .map_err(|_| "response body is too large for the C ABI".to_owned())?;
        let body = body.into_boxed_slice();
        let body_ptr = Box::into_raw(body) as *mut u8;
        let response = Response {
            location: allocations.remove(0),
            protocol: allocations.remove(0),
            body: body_ptr,
            body_length,
            content_type: allocations.remove(0),
            status: c_int::from(response.status().as_u16()),
            headers: allocations.remove(0),
            request_url: allocations.remove(0),
        };
        Ok(Self { response })
    }

    fn into_raw(self) -> *mut Response {
        Box::into_raw(Box::new(self.response))
    }
}

async fn execute_request(request: Request) -> Result<OwnedResponse, String> {
    let proxy = unsafe { read_string(request.proxy_url, "ProxyUrl")? };
    let url =
        unsafe { read_string(request.url, "Url")? }.ok_or_else(|| "Url is required".to_owned())?;
    let method = unsafe { read_string(request.method, "Method")? }?.unwrap_or_else(|| "GET".into());
    let body = unsafe { read_string(request.body, "Body")? };
    let headers = parse_headers(unsafe { read_string(request.headers, "Headers")? }.as_deref())?;
    let header_order =
        parse_header_order(unsafe { read_string(request.header_order, "HeaderOrder")? }.as_deref());
    let cookies = unsafe { read_string(request.cookies, "Cookies")? };

    let client = CLIENT
        .get_or_init(|| {
            Client::builder()
                .build()
                .map_err(|err| format!("client initialization failed: {err}"))
        })
        .as_ref()
        .map_err(Clone::clone)?;
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|err| format!("invalid HTTP method: {err}"))?;
    let mut builder = client.request(method, url);
    if let Some(proxy) = proxy {
        builder =
            builder.proxy(Proxy::all(proxy).map_err(|err| format!("invalid proxy URL: {err}"))?);
    }
    builder = builder.headers(headers).orig_headers(header_order);
    if let Some(cookies) = cookies {
        builder = builder.header("cookie", cookies);
    }
    if let Some(body) = body {
        builder = builder.body(body.into_bytes());
    }
    if request.timeout > 0 {
        builder = builder.timeout(Duration::from_millis(request.timeout as u64));
    }
    if request.idle_timeout > 0 {
        builder = builder.read_timeout(Duration::from_millis(request.idle_timeout as u64));
    }
    let response = builder
        .send()
        .await
        .map_err(|err| format!("request failed: {err}"))?;
    let body = response
        .bytes()
        .await
        .map_err(|err| format!("response body failed: {err}"))?
        .to_vec();
    OwnedResponse::new(response, body)
}

fn run_request(request: Request) -> Result<OwnedResponse, String> {
    let future = execute_request(request);
    if Handle::try_current().is_ok() {
        thread::spawn(move || runtime().block_on(future))
            .join()
            .map_err(|_| "request worker thread panicked".to_owned())?
    } else {
        runtime().block_on(future)
    }
}

fn error_ptr(message: impl AsRef<str>) -> *mut c_char {
    let message = message.as_ref().replace('\0', "\\0");
    CString::new(message).expect("NUL was replaced").into_raw()
}

/// Executes one request. Returns zero on success and nonzero on failure.
///
/// `response_out` and `error_out` must be non-null. On success, `*response_out`
/// is released with [`wreq_response_free`]. On failure, `*error_out` is released
/// with [`wreq_error_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wreq_execute(
    request: *const Request,
    response_out: *mut *mut Response,
    error_out: *mut *mut c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if request.is_null() || response_out.is_null() || error_out.is_null() {
            return Err("request, response_out, and error_out are required".to_owned());
        }
        unsafe {
            *response_out = ptr::null_mut();
            *error_out = ptr::null_mut();
            let response = run_request(ptr::read(request))?;
            *response_out = response.into_raw();
        }
        Ok(())
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            if !error_out.is_null() {
                unsafe {
                    *error_out = error_ptr(error);
                }
            }
            1
        }
        Err(_) => {
            if !error_out.is_null() {
                unsafe {
                    *error_out = error_ptr("panic while executing request");
                }
            }
            1
        }
    }
}

/// Releases a response returned by [`wreq_execute`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wreq_response_free(response: *mut Response) {
    if response.is_null() {
        return;
    }
    unsafe {
        let response = Box::from_raw(response);
        if !response.location.is_null() {
            drop(CString::from_raw(response.location));
        }
        if !response.protocol.is_null() {
            drop(CString::from_raw(response.protocol));
        }
        if !response.body.is_null() {
            drop(Vec::from_raw_parts(
                response.body,
                response.body_length.max(0) as usize,
                response.body_length.max(0) as usize,
            ));
        }
        if !response.content_type.is_null() {
            drop(CString::from_raw(response.content_type));
        }
        if !response.headers.is_null() {
            drop(CString::from_raw(response.headers));
        }
        if !response.request_url.is_null() {
            drop(CString::from_raw(response.request_url));
        }
    }
}

/// Releases an error string returned by [`wreq_execute`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wreq_error_free(error: *mut c_char) {
    if !error.is_null() {
        unsafe {
            drop(CString::from_raw(error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_headers_and_order() {
        let headers = parse_headers(Some("X-Test: one\r\nX-Test: two")).unwrap();
        assert_eq!(headers.get_all("x-test").iter().count(), 2);
        let order = parse_header_order(Some("Host, X-Test\r\nCookie"));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn response_ownership_can_be_freed() {
        let response = Box::into_raw(Box::new(Response {
            location: c_string("").unwrap().into_raw(),
            protocol: c_string("HTTP/1.1").unwrap().into_raw(),
            body: Box::into_raw(vec![1_u8, 2].into_boxed_slice()) as *mut u8,
            body_length: 2,
            content_type: c_string("").unwrap().into_raw(),
            status: 200,
            headers: c_string("").unwrap().into_raw(),
            request_url: c_string("http://example.test").unwrap().into_raw(),
        }));
        unsafe {
            wreq_response_free(response);
        }
    }

    #[test]
    fn invalid_request_returns_owned_error() {
        let mut response = ptr::null_mut();
        let mut error = ptr::null_mut();
        let status = unsafe { wreq_execute(ptr::null(), &mut response, &mut error) };
        assert_eq!(status, 1);
        assert!(response.is_null());
        assert!(!error.is_null());
        unsafe { wreq_error_free(error) };
    }
}
