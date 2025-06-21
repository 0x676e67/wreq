macro_rules! set_bool {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if $cfg.$field {
            $conn.$setter();
        }
    };
    ($cfg:expr, !$field:ident, $conn:expr, $setter:ident, $arg:expr) => {
        if !$cfg.$field {
            $conn.$setter($arg);
        }
    };
}

macro_rules! set_option {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field {
            $conn.$setter(val);
        }
    };
}

macro_rules! set_option_ref_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field.as_ref() {
            $conn.$setter(val)?;
        }
    };
}

macro_rules! set_option_inner_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        $conn.$setter($cfg.$field.map(|v| v.0))?;
    };
}

macro_rules! encode_alpns {
    ( $( $arr:expr ),* $(,)? ) => {{
        concat_array!(
            $(
                [($arr.len() as u8)],
                $arr
            ),*
        )
    }};
}

macro_rules! concat_array {
    () => {
        []
    };
    ($a:expr) => {
        $a
    };
    ($a:expr, $b:expr) => {{
        #[doc(hidden)]
        const unsafe fn concat<A: Copy, B: Copy, C: Copy>(a: A, b: B) -> C {
            #[repr(C)]
            struct Both<A, B>(A, B);

            union Transmute<A, B, C> {
                from: std::mem::ManuallyDrop<Both<A, B>>,
                to: std::mem::ManuallyDrop<C>,
            }

            std::mem::ManuallyDrop::into_inner(unsafe {
                Transmute {
                    from: std::mem::ManuallyDrop::new(Both(a, b)),
                }
                .to
            })
        }
        let a = $a;
        let b = $b;
        let c: [_; $a.len() + $b.len()] = unsafe { concat(a, b) };
        // Constrain the element types to be the same to guide inference.
        let _: [*const _; 3] = [a.as_ptr(), b.as_ptr(), c.as_ptr()];
        c
    }};
    ($a:expr, $($rest:expr),*) => {
        concat_array!($a, concat_array!($($rest),*))
    };
    ($a:expr, $($rest:expr),*,) => {
        concat_array!($a, $($rest),*)
    };
}
