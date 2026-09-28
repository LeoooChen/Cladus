//! Size-bounded engine logs (10 MiB plus five backups).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const LIMIT: u64 = 10 * 1024 * 1024;

pub struct RollingLog {
    path: PathBuf,
    file: Option<File>,
    size: u64,
}

impl RollingLog {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path: path.to_owned(),
            file: Some(file),
            size,
        })
    }

    fn backup(&self, index: usize) -> PathBuf {
        self.path.with_extension(format!("log.{index}"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file.take();
        let result = (|| {
            if self.backup(5).exists() {
                fs::remove_file(self.backup(5))?;
            }
            for index in (1..5).rev() {
                if self.backup(index).exists() {
                    fs::rename(self.backup(index), self.backup(index + 1))?;
                }
            }
            fs::rename(&self.path, self.backup(1))
        })();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = file.metadata()?.len();
        self.file = Some(file);
        result
    }
}

impl Write for RollingLog {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.size >= LIMIT {
            self.rotate()?;
        }
        let written = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log is closed"))?
            .write(bytes)?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("log is closed"))?
            .flush()
    }
}
