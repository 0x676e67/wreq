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
    /// Create a new [`Handle`] with the specified path and sender.
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
