//! User-defined connection-pool partitions.
//!
//! A group can only make reuse more restrictive. Transport compatibility is
//! derived separately from the connection's actual settings.

use std::sync::Arc;

/// An opaque partition added to the automatic connection identity.
/// Requests in different groups never share pooled connections, even when
/// their transport settings are otherwise compatible.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Group(GroupId);

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum GroupId {
    Name(Arc<str>),
    Number(u64),
}

impl Group {
    /// Creates a group from a string or numeric identifier.
    #[inline]
    pub fn new<G: Into<Self>>(group: G) -> Self {
        group.into()
    }
}

impl From<&str> for Group {
    #[inline]
    fn from(value: &str) -> Self {
        Self(GroupId::Name(Arc::from(value)))
    }
}

impl From<String> for Group {
    #[inline]
    fn from(value: String) -> Self {
        Self(GroupId::Name(Arc::from(value)))
    }
}

impl From<Box<str>> for Group {
    #[inline]
    fn from(value: Box<str>) -> Self {
        Self(GroupId::Name(Arc::from(value)))
    }
}

impl From<u64> for Group {
    #[inline]
    fn from(value: u64) -> Self {
        Self(GroupId::Number(value))
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    fn hash(group: &Group) -> u64 {
        let mut hasher = DefaultHasher::new();
        group.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn textual_groups_have_one_identity() {
        let borrowed = Group::new("worker");
        let owned = Group::new(String::from("worker"));

        assert_eq!(borrowed, owned);
        assert_eq!(hash(&borrowed), hash(&owned));
        assert_ne!(borrowed, Group::new(1));
    }
}
