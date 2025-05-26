use std::{path::PathBuf, sync::mpsc::Sender};

/// Handle for writing to a key log file.
#[derive(Debug, Clone)]
pub struct KeyLogHandle {
    #[allow(unused)]
    path: PathBuf,
    sender: Sender<String>,
}

impl KeyLogHandle {
    /// Create a new `KeyLogHandle` with the specified path and sender.
    pub fn new(path: PathBuf, sender: Sender<String>) -> Self {
        Self { path, sender }
    }

    /// Write a line to the keylogger.
    pub fn write_log_line(&self, line: String) {
        if let Err(_err) = self.sender.send(line) {
            error!(
                file = ?self.path,
                error = %_err,
                "KeyLogHandle: failed to send log line for writing",
            );
        }
    }
}
