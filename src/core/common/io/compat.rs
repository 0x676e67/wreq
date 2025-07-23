use crate::core::rt::TokioIo;

/// A type alias for compatibility with Tokio IO types.
pub(crate) type Compat<T> = TokioIo<T>;
