//! # Request Grouping Mechanism
//!
//! This module provides the [`Group`] structure, which defines the logical boundaries
//! for categorizing and segregating outbound requests.
//!
//! ## Concept
//! A `Group` acts as a multi-dimensional identity for a request. In complex networking
//! stack environments, two requests targeting the same destination may belong to
//! distinct logical groups due to different metadata, security contexts, or
//! routing requirements.
//!
//! ## Logical Segregation
//! By assigning requests to different groups, the system ensures:
//! 1. **Contextual Isolation**: Requests are processed and dispatched within their defined logical
//!    partitions.
//! 2. **Deterministic Identity**: The internal `BTreeMap` ensures that the identity of a group is
//!    stable and invariant to the order in which grouping criteria are applied.
//! 3. **Resource Affinity**: Resource management (such as connection pooling) respects these
//!    boundaries, ensuring that resources are never leaked across different request groups.

use std::{borrow::Cow, collections::BTreeMap, hash::Hash};

use http::{Uri, Version};

use crate::{conn::tcp::SocketBindOptions, proxy::Matcher};

macro_rules! impl_group_variants {
    ($($name:ident $(($ty:ty))?,)*) => {
        /// Unique discriminator for request grouping dimensions.
        #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
        enum GroupId {
            $($name,)*
        }

        /// Data container for specific grouping criteria.
        #[derive(Debug, Clone, Hash, PartialEq, Eq)]
        enum GroupPart {
            $($name $(($ty))?,)*
        }
    }
}

impl_group_variants! {
    Request(Group),
    Emulate(Group),
    Named(Cow<'static, str>),
    Number(u64),
    Uri(Uri),
    Version(Version),
    Proxy(Matcher),
    SocketBind(Option<SocketBindOptions>),
}

/// A logical identifier for request grouping.
///
/// `Group` encapsulates the criteria that define a request's execution context.
/// Requests with non-identical `Group` states are treated as belonging to
/// different logical partitions, preventing unintended interaction or
/// resource sharing between them.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct Group(BTreeMap<GroupId, GroupPart>);

impl Group {
    /// Creates a new [`Group`] with a custom name.
    #[inline]
    pub fn named<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Group(BTreeMap::from([(
            GroupId::Named,
            GroupPart::Named(name.into()),
        )]))
    }

    /// Creates a new [`Group`] with a numeric identifier.
    pub fn number<V: Into<u64>>(value: V) -> Self {
        Group(BTreeMap::from([(
            GroupId::Number,
            GroupPart::Number(value.into()),
        )]))
    }

    /// Groups the request by a specific target [`Uri`].
    #[inline]
    pub(crate) fn uri(&mut self, uri: Uri) -> &mut Self {
        self.extend(GroupId::Uri, GroupPart::Uri(uri))
    }

    /// Groups the request by its required HTTP [`Version`].
    #[inline]
    pub(crate) fn version(&mut self, version: Option<Version>) -> &mut Self {
        self.extend(GroupId::Version, version.map(GroupPart::Version))
    }

    /// Groups the request based on its proxy [`Matcher`] criteria.
    #[inline]
    pub(crate) fn proxy(&mut self, proxy: Option<Matcher>) -> &mut Self {
        self.extend(GroupId::Proxy, proxy.map(GroupPart::Proxy))
    }

    /// Groups the request by its resolved socket bind options.
    #[inline]
    pub(crate) fn socket_bind(&mut self, opts: Option<SocketBindOptions>) -> &mut Self {
        self.extend(GroupId::SocketBind, GroupPart::SocketBind(opts))
    }

    /// Creates a nested request group.
    #[inline]
    pub(crate) fn request(&mut self, group: Group) -> &mut Self {
        self.extend(GroupId::Request, GroupPart::Request(group))
    }

    /// Groups the request by its emulation-layer characteristics.
    #[inline]
    pub(crate) fn emulate(&mut self, group: Group) -> &mut Self {
        self.extend(GroupId::Emulate, GroupPart::Emulate(group))
    }

    #[inline]
    fn extend<T: Into<Option<GroupPart>>>(&mut self, id: GroupId, entry: T) -> &mut Self {
        if let Some(entry) = entry.into() {
            self.0.insert(id, entry);
        }
        self
    }
}

impl From<u64> for Group {
    #[inline]
    fn from(value: u64) -> Self {
        Group::number(value)
    }
}

impl From<&'static str> for Group {
    #[inline]
    fn from(value: &'static str) -> Self {
        Group::named(value)
    }
}

impl From<String> for Group {
    #[inline]
    fn from(value: String) -> Self {
        Group::named(value)
    }
}

impl From<Cow<'static, str>> for Group {
    #[inline]
    fn from(value: Cow<'static, str>) -> Self {
        Group::named(value)
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn test_group_identity_invariance() {
        let mut g1 = Group::default();
        g1.extend(GroupId::Number, GroupPart::Number(42));
        g1.extend(GroupId::Named, GroupPart::Named("worker".into()));

        let mut g2 = Group::default();
        g2.extend(GroupId::Named, GroupPart::Named("worker".into()));
        g2.extend(GroupId::Number, GroupPart::Number(42));

        let mut h1 = DefaultHasher::new();
        g1.hash(&mut h1);

        let mut h2 = DefaultHasher::new();
        g2.hash(&mut h2);

        assert_eq!(
            h1.finish(),
            h2.finish(),
            "Request groups must maintain identical hashes regardless of criteria insertion order"
        );
    }
}
