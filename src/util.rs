use crate::header::{Entry, HeaderMap, HeaderName, HeaderValue, OccupiedEntry};

pub fn basic_auth<U, P>(username: U, password: Option<P>) -> HeaderValue
where
    U: std::fmt::Display,
    P: std::fmt::Display,
{
    use base64::prelude::BASE64_STANDARD;
    use base64::write::EncoderWriter;
    use std::io::Write;

    let mut buf = b"Basic ".to_vec();
    {
        let mut encoder = EncoderWriter::new(&mut buf, &BASE64_STANDARD);
        let _ = write!(encoder, "{}:", username);
        if let Some(password) = password {
            let _ = write!(encoder, "{}", password);
        }
    }
    let mut header = HeaderValue::from_bytes(&buf).expect("base64 is always valid HeaderValue");
    header.set_sensitive(true);
    header
}

// xor-shift
pub(crate) fn fast_random() -> u64 {
    use std::cell::Cell;
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::num::Wrapping;

    thread_local! {
        static RNG: Cell<Wrapping<u64>> = Cell::new(Wrapping(seed()));
    }

    fn seed() -> u64 {
        let seed = RandomState::new();

        let mut out = 0;
        let mut cnt = 0;
        while out == 0 {
            cnt += 1;
            let mut hasher = seed.build_hasher();
            hasher.write_usize(cnt);
            out = hasher.finish();
        }
        out
    }

    RNG.with(|rng| {
        let mut n = rng.get();
        debug_assert_ne!(n.0, 0);
        n ^= n >> 12;
        n ^= n << 25;
        n ^= n >> 27;
        rng.set(n);
        n.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    })
}

pub(crate) fn replace_headers(dst: &mut HeaderMap, src: HeaderMap) {
    // IntoIter of HeaderMap yields (Option<HeaderName>, HeaderValue).
    // The first time a name is yielded, it will be Some(name), and if
    // there are more values with the same name, the next yield will be
    // None.

    let mut prev_entry: Option<OccupiedEntry<_>> = None;
    for (key, value) in src {
        match key {
            Some(key) => match dst.entry(key) {
                Entry::Occupied(mut e) => {
                    e.insert(value);
                    prev_entry = Some(e);
                }
                Entry::Vacant(e) => {
                    let e = e.insert_entry(value);
                    prev_entry = Some(e);
                }
            },
            None => match prev_entry {
                Some(ref mut entry) => {
                    entry.append(value);
                }
                None => unreachable!("HeaderMap::into_iter yielded None first"),
            },
        }
    }
}

/// Sort the headers in the specified order.
///
/// Headers in `headers_order` are sorted to the front, preserving their order.
/// Remaining headers are appended in their original order.
#[inline]
pub(crate) fn sort_headers(headers: &mut HeaderMap, headers_order: &[HeaderName]) {
    if headers.len() <= 1 {
        return;
    }

    let mut sorted_headers = HeaderMap::with_capacity(headers.keys_len());

    // First insert headers in the specified order
    for (key, value) in headers_order
        .iter()
        .filter_map(|key| headers.remove(key).map(|value| (key, value)))
    {
        sorted_headers.insert(key, value);
    }

    // Then insert any remaining headers that were not ordered
    for (key, value) in headers.drain().filter_map(|(k, v)| k.map(|k| (k, v))) {
        sorted_headers.insert(key, value);
    }

    std::mem::swap(headers, &mut sorted_headers);
}

// Convert the headers priority to the correct type
#[cfg(feature = "boring-tls")]
#[inline]
pub(crate) fn convert_headers_priority(
    headers_priority: Option<(u32, u8, bool)>,
) -> Option<hyper::StreamDependency> {
    headers_priority.map(|(a, b, c)| hyper::StreamDependency::new(hyper::StreamId::from(a), b, c))
}
