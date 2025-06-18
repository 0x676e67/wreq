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

macro_rules! set_option_try_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field.as_deref() {
            $conn.$setter(val)?;
        }
    };
}

macro_rules! set_inner_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        $conn.$setter($cfg.$field.0)?;
    };
}

macro_rules! set_option_inner_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        $conn.$setter($cfg.$field.map(|v| v.0))?;
    };
}
