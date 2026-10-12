//! One running copy per data directory.
//!
//! Two processes writing the same portable store would race each other's
//! atomic replacements, so the second one stops before opening anything. The
//! lock is keyed by the data directory rather than by the application id, so
//! an automation run with its own archive root can run beside the copy the
//! operator has open, exactly as the per-profile Electron lock allowed.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
};

#[derive(Debug)]
pub struct InstanceLock {
    // Held for the life of the process; the OS releases it on exit or crash.
    _file: File,
}

#[derive(Debug)]
pub enum InstanceLockError {
    AlreadyRunning,
    Io(std::io::Error),
}

pub fn acquire(data_directory: &Path) -> Result<InstanceLock, InstanceLockError> {
    let path = data_directory.join(".lovelyhawk-instance.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(InstanceLockError::Io)?;
    match file.try_lock() {
        Ok(()) => Ok(InstanceLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(InstanceLockError::AlreadyRunning),
        Err(TryLockError::Error(error)) => Err(InstanceLockError::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_holder_in_the_same_directory_is_refused() {
        let root = std::env::temp_dir().join(format!("lovelyhawk-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let first = acquire(&root).unwrap();
        assert!(matches!(
            acquire(&root),
            Err(InstanceLockError::AlreadyRunning)
        ));
        drop(first);
        let again = acquire(&root).unwrap();
        drop(again);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
