//! Tower services used by the low-level client request path.
//!
//! [`configure::Configure`] consumes request-local transport options,
//! [`retry::RetryUnsent`] retries only requests returned before encoding, and
//! [`dispatch::Dispatch`] performs one checkout and dispatch attempt.

use http::Request;

use crate::{conn::descriptor::ConnectionDescriptor, rt::Executor};

pub(super) mod configure;
pub(super) mod dispatch;
pub(super) mod retry;

/// Concrete ordering of the low-level request services.
///
/// Request configuration runs before retry so every attempt reuses the same
/// connection descriptor and request body. [`dispatch::Dispatch`] is terminal
/// and performs one pool checkout and protocol dispatch attempt.
pub(super) type Stack<C, B> = configure::Configure<retry::RetryUnsent<dispatch::Dispatch<C, B>>>;

/// A request with the connection and protocol settings needed for dispatch.
///
/// The request body stays owned by this value until protocol dispatch begins.
/// This lets a canceled pool checkout or an encoding-before-send failure return
/// the same request to [`retry::RetryUnsent`] without cloning its body.
pub struct ConfiguredRequest<B> {
    request: Request<B>,
    descriptor: ConnectionDescriptor,
    h1_builder: wreq_proto::conn::http1::Builder,
    h2_builder: wreq_proto::conn::http2::Builder<Executor>,
}
