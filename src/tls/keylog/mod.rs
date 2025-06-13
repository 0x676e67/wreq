mod handle;

use std::{
    borrow::Cow,
    collections::{HashMap, hash_map::Entry},
    io::{Error, ErrorKind, Result},
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

use antidote::RwLock;
pub use handle::KeyLogHandle;

static GLOBAL_KEYLOG_FILE_MAPPING: OnceLock<RwLock<HashMap<PathBuf, KeyLogHandle>>> =
    OnceLock::new();

/// Specifies the intent for a (TLS) keylogger to be used in a client or server configuration.
#[derive(Debug, Clone)]
pub enum KeyLogPolicy {
    /// Uses the default behavior, respecting the `SSLKEYLOGFILE` environment variable.
    ///
    /// If the environment variable is defined, keys will be logged to the specified path.
    /// Otherwise, no key logging will occur.
    Environment,

    /// Logs keys to the specified file path.
    ///
    /// The path is represented by a `PathBuf`, which is an owned, mutable path that can be
    /// manipulated and queried. This is useful for operations that require reading from or
    /// writing to the file system.
    File(PathBuf),
}

impl KeyLogPolicy {
    /// Creates a new key log file handle based on the policy.
    pub fn open_handle(self) -> Result<KeyLogHandle> {
        let path = match self {
            KeyLogPolicy::Environment => std::env::var("SSLKEYLOGFILE")
                .map(PathBuf::from)
                .map(normalize_path)
                .map_err(|err| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!(
                            "KeyLogPolicy: SSLKEYLOGFILE environment is invalid: {}",
                            err
                        ),
                    )
                })?,
            KeyLogPolicy::File(keylog_filename) => normalize_path(keylog_filename),
        };

        let mapping = GLOBAL_KEYLOG_FILE_MAPPING.get_or_init(|| RwLock::new(HashMap::new()));
        if let Some(handle) = mapping.read().get(&path).cloned() {
            return Ok(handle);
        }

        let mut mut_mapping = mapping.write();
        match mut_mapping.entry(path.clone()) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let handle = KeyLogHandle::new(path)?;
                entry.insert(handle.clone());
                Ok(handle)
            }
        }
    }
}

pub fn normalize_path<'a, P>(path: P) -> PathBuf
where
    P: Into<Cow<'a, Path>>,
{
    let path = path.into();
    let mut components = path.components().peekable();
    let mut ret = if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
    } else {
        PathBuf::new()
    };

    for component in components {
        match component {
            Component::Prefix(..) => unreachable!(),
            Component::RootDir => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                ret.pop();
            }
            Component::Normal(c) => {
                ret.push(c);
            }
        }
    }
    ret
}
