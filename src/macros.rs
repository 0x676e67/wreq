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
