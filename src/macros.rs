/// Macro to implement Debug for a type, skipping certain fields.
#[macro_export]
macro_rules! impl_debug {
    ($type:ty, { $($field_name:ident),* }) => {
        impl std::fmt::Debug for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let mut debug_struct = f.debug_struct(stringify!($type));
                $(
                    debug_struct.field(stringify!($field_name), &self.$field_name);
                )*
                debug_struct.finish()
            }
        }
    }
}

/// Macro to conditionally compile code for bindable devices.
#[macro_export]
macro_rules! bind_device {
    (item, $($item:item)*) => {$(
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        ))]
        $item
    )*};

    (tt, $($tt:tt)*) => {
        #[cfg(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        ))]
        $(
            $tt
        )*
    };
}

/// Macro to conditionally compile code for non-bindable devices.
#[macro_export]
macro_rules! not_bind_device {
    (item, $($item:item)*) => {$(
        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        )))]
        $item
    )*};

    (tt, $($tt:tt)*) => {
        #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "linux",
            target_os = "ios",
            target_os = "visionos",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        )))]
        $(
            $tt
        )*
    }
}
