//! Connection options shared by client defaults and request overrides.

mod identity;

use std::{
    any::type_name,
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub(crate) use self::identity::{
    Cached, ConnectConfigValue, HASHER, KeyPart, ScopedConfig, Whole, changed,
    derive_deftly_template_ConfigKey,
};
#[cfg(feature = "http2")]
use crate::http2::Http2Options;
use crate::{
    conn::dialer::Interface, group::Group, http1::Http1Options, proxy::Matcher, tls::TlsOptions,
};
#[cfg(feature = "http3")]
use crate::{http3::Http3Options, quic::QuicOptions};

/// Connection settings stored on a client or an individual request.
#[derive(Clone, Default)]
pub(crate) struct ConnectConfig(Option<Arc<Values>>);

/// A borrowed request overlay, with client defaults for missing types.
pub(crate) struct WithBase<'a> {
    overlay_config: &'a ConnectConfig,
    base_config: &'a ConnectConfig,
}

/// Maps a supported connection setting to its storage slot.
pub(crate) trait ConnectExtension: Sized + Send + Sync + 'static {
    type Stored: Stored<Self>;
    const INDEX: u32;

    fn slot(values: &Values) -> &Option<Self::Stored>;
    fn slot_mut(values: &mut Values) -> &mut Option<Self::Stored>;
}

pub(crate) trait Stored<T>: Clone {
    fn store(value: T) -> Self;
    fn value(&self) -> &T;
}

macro_rules! extension_fields {
    ($($(#[$attr:meta])* $index:literal => $field:ident: $ty:ty as $stored:ty),+ $(,)?) => {
        #[derive(Clone, Default)]
        pub(crate) struct Values {
            fields: u16,
            $($(#[$attr])* $field: Option<$stored>,)+
        }

        impl Values {
            fn extend(&mut self, other: &Self) {
                self.fields |= other.fields;
                $($(#[$attr])* if let Some(value) = &other.$field {
                    self.$field = Some(value.clone());
                })+
            }

            fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut set = f.debug_set();
                $($(#[$attr])* if self.fields & (1 << $index) != 0 {
                    set.entry(&type_name::<$ty>());
                })+
                set.finish()
            }
        }

        $($(#[$attr])*
        impl ConnectExtension for $ty {
            type Stored = $stored;
            const INDEX: u32 = $index;

            fn slot(values: &Values) -> &Option<Self::Stored> {
                &values.$field
            }

            fn slot_mut(values: &mut Values) -> &mut Option<Self::Stored> {
                &mut values.$field
            }
        })+
    };
}

extension_fields! {
    0 => ipv4: Ipv4Addr as Ipv4Addr,
    1 => ipv6: Ipv6Addr as Ipv6Addr,
    2 => interface: Interface as Interface,
    3 => group: Group as Group,
    4 => matcher: Matcher as Cached<Matcher>,
    5 => tls: TlsOptions as Cached<TlsOptions>,
    6 => http1: Http1Options as Cached<Http1Options>,
    #[cfg(feature = "http2")]
    7 => http2: Http2Options as Cached<Http2Options>,
    #[cfg(feature = "http3")]
    8 => quic: QuicOptions as Cached<QuicOptions>,
    #[cfg(feature = "http3")]
    9 => http3: Http3Options as Cached<Http3Options>,
}

impl<T: Clone> Stored<T> for T {
    fn store(value: T) -> Self {
        value
    }

    fn value(&self) -> &T {
        self
    }
}

// ===== impl ConnectConfig =====

impl ConnectConfig {
    pub(crate) fn insert<T: ConnectExtension>(&mut self, value: T) -> &mut Self {
        let values = Arc::make_mut(self.0.get_or_insert_with(Arc::default));
        *T::slot_mut(values) = Some(T::Stored::store(value));
        values.fields |= 1 << T::INDEX;
        self
    }

    /// An absent value clears only this type's local setting.
    pub(crate) fn set<T: ConnectExtension>(&mut self, value: Option<T>) -> &mut Self {
        if let Some(value) = value {
            return self.insert(value);
        }
        let Some(values) = &mut self.0 else {
            return self;
        };
        let field = 1 << T::INDEX;
        if values.fields == field {
            self.0 = None;
        } else if values.fields & field != 0 {
            let values = Arc::make_mut(values);
            *T::slot_mut(values) = None;
            values.fields &= !field;
        }
        self
    }

    /// Replaces only the types supplied by the incoming configuration.
    pub(crate) fn extend(&mut self, other: Self) {
        if let Some(other) = other.0 {
            match &mut self.0 {
                Some(values) => Arc::make_mut(values).extend(&other),
                None => self.0 = Some(other),
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn get_ref<T: ConnectExtension>(&self) -> Option<&T> {
        self.get::<T>().map(Stored::value)
    }

    pub(crate) fn get_arc<T: ConnectExtension<Stored = Cached<T>>>(&self) -> Option<Arc<T>> {
        self.get::<T>().map(Cached::arc)
    }

    /// Borrows the overlay and its defaults without merging or copying either set.
    pub(crate) fn with_base<'a>(&'a self, base_config: &'a Self) -> WithBase<'a> {
        WithBase {
            overlay_config: self,
            base_config,
        }
    }

    pub(super) fn get<T: ConnectExtension>(&self) -> Option<&T::Stored> {
        T::slot(self.0.as_deref()?).as_ref()
    }
}

impl fmt::Debug for ConnectConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(values) => values.debug(f),
            None => f.debug_set().finish(),
        }
    }
}

impl<'a> WithBase<'a> {
    pub(crate) fn get_ref<T: ConnectExtension>(&self) -> Option<&'a T> {
        self.overlay_config
            .get_ref::<T>()
            .or_else(|| self.base_config.get_ref())
    }
}
