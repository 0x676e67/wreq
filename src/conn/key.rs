use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use super::context::ContextData;

/// Value identity for interchangeable connections.
/// Pool entries and TLS sessions share the frozen connection context.
/// Cached hashes accelerate lookup; equality still checks the complete values.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionKey(pub(super) Arc<ContextData>);

impl PartialEq for ConnectionKey {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.hash == other.0.hash
                && self.0.uri == other.0.uri
                && self.0.version == other.0.version
                && self.0.extensions == other.0.extensions)
    }
}

impl Eq for ConnectionKey {}

impl Hash for ConnectionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Repeated pool/session lookups do not rehash the full configuration.
        state.write_u64(self.0.hash);
    }
}
