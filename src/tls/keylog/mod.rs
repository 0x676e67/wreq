mod handle;

use antidote::RwLock;
pub use handle::KeyLogHandle;
use std::{
    collections::{HashMap, hash_map::Entry},
    io::{Error, Result},
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

static GLOBAL_KEYLOG_FILE_MAPPING: OnceLock<RwLock<HashMap<PathBuf, KeyLogHandle>>> =
    OnceLock::new();

/// Specifies the intent for a (TLS) keylogger to be used in a client or server configuration.
#[derive(Debug, Clone, Default)]
pub enum KeyLogPolicy {
    /// Explicitly disables key logging, even if the environment variable is set.
    #[default]
    Disabled,
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
    pub fn new_handle(&self) -> Result<Option<KeyLogHandle>> {
        let filepath = match self {
            KeyLogPolicy::Disabled => return Ok(None),
            KeyLogPolicy::Environment => std::env::var("SSLKEYLOGFILE").ok().map(PathBuf::from),
            KeyLogPolicy::File(keylog_filename) => Some(keylog_filename.clone()),
        };

        let path = filepath.ok_or_else(|| {
            Error::new(
                std::io::ErrorKind::NotFound,
                "Invalid keylog file path: SSLKEYLOGFILE not set or keylog filepath inavalid",
            )
        })?;

        let path = normalize_path(&path);

        let mapping = GLOBAL_KEYLOG_FILE_MAPPING.get_or_init(|| RwLock::new(HashMap::new()));
        if let Some(handle) = mapping.read().get(&path).cloned() {
            return Ok(Some(handle));
        }

        let mut mut_mapping = mapping.write();
        match mut_mapping.entry(path.clone()) {
            Entry::Occupied(entry) => Ok(Some(entry.get().clone())),
            Entry::Vacant(entry) => {
                let handle = KeyLogHandle::new(path)?;
                entry.insert(handle.clone());
                Ok(Some(handle))
            }
        }
    }
}

/// copied from: <https://github.com/rust-lang/cargo/blob/fede83ccf973457de319ba6fa0e36ead454d2e20/src/cargo/util/paths.rs#L61>
pub fn normalize_path(path: &Path) -> PathBuf {
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
