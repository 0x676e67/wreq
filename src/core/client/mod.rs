//! HTTP Client
//!
//! crate::core: provides HTTP over a single connection. See the [`conn`] module.
//!
//! ## Examples
//!
//! * [`client`] - A simple CLI http client that requests the url passed in parameters and outputs the response content and details to the stdout, reading content chunk-by-chunk.
//!
//! * [`client_json`] - A simple program that GETs some json, reads the body asynchronously, parses it with serde and outputs the result.
//!
//! [`client`]: https://github.com/hyperium/crate::core:/blob/master/examples/client.rs
//! [`client_json`]: https://github.com/hyperium/crate::core:/blob/master/examples/client_json.rs

pub mod conn;
pub(super) mod dispatch;
