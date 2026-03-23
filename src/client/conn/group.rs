use std::{
    borrow::Cow,
    collections::BTreeMap,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
};

use http::{Uri, Version};

use crate::proxy::Matcher;

/// A connections group identifier for request grouping and connection pool partitioning.
///
/// Connections with different groups will not share pooled connections,
/// even when targeting the same URI.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionGroup(BTreeMap<GroupId, GroupPart>);

impl ConnectionGroup {
    #[inline]
    pub(crate) fn uri(&mut self, uri: Uri) -> &mut Self {
        self.extend(GroupId::Uri, GroupPart::Uri(uri))
    }

    #[inline]
    pub(crate) fn version(&mut self, version: Option<Version>) -> &mut Self {
        self.extend(GroupId::Version, version.map(GroupPart::Version))
    }

    #[inline]
    pub(crate) fn proxy(&mut self, proxy: Option<Matcher>) -> &mut Self {
        self.extend(GroupId::Proxy, proxy.map(GroupPart::Proxy))
    }

    #[inline]
    pub(crate) fn ipv4_addr(&mut self, addr: Option<Ipv4Addr>) -> &mut Self {
        self.extend(GroupId::Ipv4Addr, addr.map(GroupPart::Ipv4Addr))
    }

    #[inline]
    pub(crate) fn ipv6_addr(&mut self, addr: Option<Ipv6Addr>) -> &mut Self {
        self.extend(GroupId::Ipv6Addr, addr.map(GroupPart::Ipv6Addr))
    }

    #[inline]
    #[cfg(any(
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "solaris",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub(crate) fn interface(&mut self, interface: Option<Cow<'static, str>>) -> &mut Self {
        self.extend(GroupId::Interface, interface.map(GroupPart::Interface))
    }

    #[inline]
    pub(crate) fn request(&mut self, group: ConnectionGroup) -> &mut Self {
        self.extend(GroupId::Request, GroupPart::Request(group))
    }

    #[inline]
    pub(crate) fn emulate(&mut self, group: ConnectionGroup) -> &mut Self {
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

impl From<u64> for ConnectionGroup {
    #[inline]
    fn from(value: u64) -> Self {
        ConnectionGroup(BTreeMap::from([(
            GroupId::Number,
            GroupPart::Number(value),
        )]))
    }
}

impl From<&'static str> for ConnectionGroup {
    #[inline]
    fn from(value: &'static str) -> Self {
        ConnectionGroup(BTreeMap::from([(
            GroupId::Named,
            GroupPart::Named(Cow::Borrowed(value)),
        )]))
    }
}

impl From<String> for ConnectionGroup {
    #[inline]
    fn from(value: String) -> Self {
        ConnectionGroup(BTreeMap::from([(
            GroupId::Named,
            GroupPart::Named(Cow::Owned(value)),
        )]))
    }
}

macro_rules! impl_group_variants {
    ($($name:ident $(($ty:ty))?,)*) => {
        #[allow(unused)]
        #[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
        enum GroupId {
            $($name,)*
        }

        #[allow(unused)]
        #[derive(Debug, Clone, Hash, PartialEq, Eq)]
        enum GroupPart {
            $($name $(($ty))?,)*
        }
    }
}

impl_group_variants! {
    Named(Cow<'static, str>),
    Number(u64),
    Uri(Uri),
    Version(Version),
    Proxy(Matcher),
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Interface(Cow<'static, str>),
    Request(ConnectionGroup),
    Emulate(ConnectionGroup),
}

#[cfg(test)]
mod tests {
    use std::hash::{DefaultHasher, Hash, Hasher};

    use super::*;

    #[test]
    fn test_btreeset_hash_order_and_value() {
        let mut set1 = BTreeMap::new();
        set1.insert(GroupId::Number, GroupPart::Number(1));
        set1.insert(GroupId::Named, GroupPart::Named("test".into()));

        let mut set2 = BTreeMap::new();
        set2.insert(GroupId::Named, GroupPart::Named("test".into()));
        set2.insert(GroupId::Number, GroupPart::Number(2));
        set2.insert(GroupId::Number, GroupPart::Number(1));

        let mut hasher1 = DefaultHasher::new();
        set1.hash(&mut hasher1);
        let hash1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        set2.hash(&mut hasher2);
        let hash2 = hasher2.finish();

        assert_eq!(
            hash1, hash2,
            "BTreeSet hash should be equal for same values, regardless of insertion order"
        );
    }
}
