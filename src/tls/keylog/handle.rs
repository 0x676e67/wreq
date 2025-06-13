use std::{
    fs::OpenOptions,
    io::{Error, Result, Write},
    path::PathBuf,
    sync::mpsc::Sender,
};

/// Handle for writing to a key log file.
#[derive(Debug, Clone)]
pub struct KeyLogHandle {
    #[allow(unused)]
    filepath: PathBuf,
    sender: Sender<String>,
}

impl KeyLogHandle {
    /// Create a new `KeyLogHandle` with the specified path and sender.
    pub fn new(filepath: PathBuf) -> Result<Self> {
        if let Some(parent) = filepath.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                Error::other(format!(
                    "KeyLogHandle: Failed to create keylog parent path directory: {}",
                    err
                ))
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&filepath)?;

        let (tx, rx) = std::sync::mpsc::channel::<String>();

        let _path_name = filepath.clone();
        std::thread::spawn(move || {
            trace!(
                file = ?_path_name,
                "KeyLogHandle: receiver task up and running",
            );
            while let Ok(line) = rx.recv() {
                if let Err(_err) = file.write_all(line.as_bytes()) {
                    error!(
                        file = ?_path_name,
                        error = %_err,
                        "KeyLogHandle: failed to write file",
                    );
                }
            }
        });

        Ok(KeyLogHandle {
            filepath,
            sender: tx,
        })
    }

    /// Write a line to the keylogger.
    pub fn write_log_line(&self, line: String) {
        if let Err(_err) = self.sender.send(line) {
            error!(
                file = ?self.filepath,
                error = %_err,
                "KeyLogHandle: failed to send log line for writing",
            );
        }
    }
}
