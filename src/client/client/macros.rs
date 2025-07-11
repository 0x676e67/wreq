macro_rules! take_url {
    ($url:ident) => {
        match $url.take() {
            Some(url) => url,
            None => {
                return Poll::Ready(Err(Error::builder("URL already taken in Pending::Request")))
            }
        }
    };
}

macro_rules! take_err {
    ($err:ident) => {
        match $err.take() {
            Some(err) => err,
            None => Error::builder("Error already taken in Error"),
        }
    };
}

macro_rules! apply_option {
    ($builder:expr, $(($option:expr, $method:ident)),* $(,)?) => {
        $(
            if let Some(value) = $option {
                $builder = $builder.$method(value);
            }
        )*
    };
}
