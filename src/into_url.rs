use url::Url;

use crate::Error;

/// A trait to try to convert some type into a `Url`.
///
/// This trait is "sealed", such that only types within wreq can
/// implement it.
pub trait IntoUrl: IntoUrlSealed {}

impl IntoUrl for Url {}
impl IntoUrl for String {}
impl IntoUrl for &Url {}
impl IntoUrl for &str {}
impl IntoUrl for &String {}

pub trait IntoUrlSealed {
    // Besides parsing as a valid `Url`, the `Url` must be a valid
    // `http::Uri`, in that it makes sense to use in a network request.
    fn into_url(self) -> crate::Result<Url>;

    fn as_str(&self) -> &str;
}

impl IntoUrlSealed for Url {
    fn into_url(self) -> crate::Result<Url> {
        if self.has_host() {
            Ok(self)
        } else {
            Err(Error::url_bad_scheme(self))
        }
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl IntoUrlSealed for &Url {
    fn into_url(self) -> crate::Result<Url> {
        if self.has_host() {
            Ok(self.clone())
        } else {
            Err(Error::url_bad_scheme(self.clone()))
        }
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl<T> IntoUrlSealed for T
where
    T: AsRef<str> + sealed::Sealed,
{
    fn into_url(self) -> crate::Result<Url> {
        Url::parse(self.as_ref())
            .map_err(Error::builder)?
            .into_url()
    }

    fn as_str(&self) -> &str {
        self.as_ref()
    }
}

mod sealed {
    use http::Uri;

    pub trait Sealed {}

    impl Sealed for Uri {}
    impl Sealed for &str {}
    impl Sealed for String {}
    impl Sealed for &String {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_url_file_scheme() {
        let err = "file:///etc/hosts".into_url().unwrap_err();
        assert_eq!(
            err.to_string(),
            "builder error for url (file:///etc/hosts): URL scheme is not allowed"
        );
    }

    #[test]
    fn into_url_blob_scheme() {
        let err = "blob:https://example.com".into_url().unwrap_err();
        assert_eq!(
            err.to_string(),
            "builder error for url (blob:https://example.com): URL scheme is not allowed"
        );
    }

    #[tokio::test]
    async fn execute_request_rejects_invalid_hostname() {
        let url_str = "https://{{hostname}}/";
        let url = url::Url::parse(url_str).unwrap();
        let result = crate::Client::new().get(url).send().await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.is_builder());
        assert_eq!(url_str, err.url().unwrap().as_str());
    }
}
