macro_rules! set_bool {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if $cfg.$field {
            $conn.$setter();
        }
    };
}

macro_rules! set_option {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field {
            $conn.$setter(val);
        }
    };
    // Optional feature switches invert the backend's NO_* disable flags.
    ($cfg:expr, !$field:ident, $conn:expr, $flag:expr) => {
        match $cfg.$field {
            Some(false) => {
                $conn.set_options($flag);
            }
            Some(true) => {
                $conn.clear_options($flag);
            }
            None => {}
        }
    };
}

macro_rules! set_option_ref_try {
    ($cfg:expr, $field:ident, $conn:expr, $setter:ident) => {
        if let Some(val) = $cfg.$field.as_ref() {
            $conn.$setter(val).map_err(Error::tls)?;
        }
    };
}

macro_rules! set_option_inner_try {
    ($field:ident, $conn:expr, $setter:ident) => {
        $conn.$setter($field.map(|v| v.0)).map_err(Error::tls)?;
    };
}
