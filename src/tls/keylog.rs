//! TLS key logging for debugging and traffic analysis.
//!
//! [`KeyLog`] selects a file explicitly or from `SSLKEYLOGFILE`. File handles are
//! shared globally, and a background thread writes the session keys for each file.

use std::{
    collections::{HashMap, hash_map::Entry},
    io::Result,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};

use handle::Handle;

use crate::sync::RwLock;

/// Selects the file used for TLS key logging.
#[derive(Debug, Clone)]
pub struct KeyLog(Option<Arc<Path>>);

impl KeyLog {
    /// Creates a [`KeyLog`] based on the `SSLKEYLOGFILE` environment variable.
    /// Key logging stays off when the variable is unset or blank.
    pub fn from_env() -> KeyLog {
        match std::env::var("SSLKEYLOGFILE") {
            Ok(ref s) if !s.trim().is_empty() => {
                KeyLog(Some(Arc::from(normalize_path(Path::new(s)))))
            }
            _ => KeyLog(None),
        }
    }

    /// Creates a [`KeyLog`] that writes to the specified file path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> KeyLog {
        KeyLog(Some(Arc::from(normalize_path(path.as_ref()))))
    }

    /// Opens the key log file, or returns `None` when the policy names no file.
    pub(crate) fn handle(self) -> Result<Option<Handle>> {
        static GLOBAL_KEYLOG_CACHE: OnceLock<RwLock<HashMap<Arc<Path>, Handle>>> = OnceLock::new();

        let Some(path) = self.0 else {
            return Ok(None);
        };

        let cache = GLOBAL_KEYLOG_CACHE.get_or_init(RwLock::default);
        if let Some(handle) = cache.read().get(path.as_ref()).cloned() {
            return Ok(Some(handle));
        }

        match cache.write().entry(path.clone()) {
            Entry::Occupied(entry) => Ok(Some(entry.get().clone())),
            Entry::Vacant(entry) => {
                let handle = Handle::new(path)?;
                entry.insert(handle.clone());
                Ok(Some(handle))
            }
        }
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut ret = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(..) | Component::RootDir | Component::Normal(_) => {
                ret.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(ret.components().next_back(), Some(Component::Normal(_))) {
                    ret.pop();
                } else if !ret.has_root() {
                    // Preserve relative parents, including those after a Windows drive prefix.
                    ret.push(component.as_os_str());
                }
            }
        }
    }
    ret
}

mod handle {
    use std::{
        fs::OpenOptions,
        io::{Result, Write},
        path::Path,
        sync::{
            Arc,
            mpsc::{self, Sender},
        },
    };

    /// Handle for writing to a key log file.
    #[derive(Debug, Clone)]
    pub struct Handle {
        #[allow(unused)]
        filepath: Arc<Path>,
        sender: Sender<String>,
    }

    impl Handle {
        /// Opens the file for append and starts its background writer.
        pub fn new(filepath: Arc<Path>) -> Result<Self> {
            if let Some(parent) = filepath.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&filepath)?;

            let (sender, receiver) = mpsc::channel::<String>();

            let _path_name = filepath.clone();
            std::thread::spawn(move || {
                trace!(
                    file = ?_path_name,
                    "Handle: receiver task up and running",
                );
                while let Ok(line) = receiver.recv() {
                    if let Err(_err) = file.write_all(line.as_bytes()) {
                        error!(
                            file = ?_path_name,
                            error = %_err,
                            "Handle: failed to write file",
                        );
                    }
                }
            });

            Ok(Handle { filepath, sender })
        }

        /// Write a line to the keylogger.
        pub fn write(&self, line: &str) {
            let line = format!("{line}\n");
            if let Err(_err) = self.sender.send(line) {
                error!(
                    file = ?self.filepath,
                    error = %_err,
                    "Handle: failed to send log line for writing",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_path_disables_key_logging() {
        // `from_env` yields this policy when SSLKEYLOGFILE is unset or blank.
        assert!(KeyLog(None).handle().unwrap().is_none());
    }

    #[test]
    fn normalization_preserves_relative_parents_and_roots() {
        for (input, expected) in [
            ("", ""),
            (".", ""),
            ("..", ".."),
            ("../keys.log", "../keys.log"),
            ("../../keys.log", "../../keys.log"),
            ("foo/../../keys.log", "../keys.log"),
            ("foo/../bar/./keys.log", "bar/keys.log"),
            ("/../../keys.log", "/keys.log"),
            ("/tmp/./keys/../sslkeys.log", "/tmp/sslkeys.log"),
        ] {
            assert_eq!(
                normalize_path(Path::new(input)),
                Path::new(expected),
                "{input}"
            );
        }

        #[cfg(windows)]
        for (input, expected) in [
            (r"C:..\keys.log", r"C:..\keys.log"),
            (r"C:..\..\keys.log", r"C:..\..\keys.log"),
            (r"C:foo\..\..\keys.log", r"C:..\keys.log"),
            (r"C:\..\..\keys.log", r"C:\keys.log"),
            (r"\\server\share\..\keys.log", r"\\server\share\keys.log"),
        ] {
            assert_eq!(
                normalize_path(Path::new(input)),
                Path::new(expected),
                "{input}"
            );
        }
    }
}
