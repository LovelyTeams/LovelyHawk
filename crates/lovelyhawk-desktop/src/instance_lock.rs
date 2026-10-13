//! One running copy per data directory.
//!
//! Two processes writing the same portable store would race each other's
//! atomic replacements, so the second one stops before opening anything. The
//! lock is keyed by the data directory rather than by the application id, so
//! an automation run with its own archive root can run beside the copy the
//! operator has open, exactly as the per-profile Electron lock allowed.
//!
//! A second launch asks the running copy to bring its window forward. The
//! request is one fixed file in the data directory whose content is never
//! read: it cannot carry a path, a file to open or anything else, so a local
//! process able to create it can do no more than raise the window.

use std::{
    fs::{File, OpenOptions, TryLockError},
    path::Path,
    time::{Duration, Instant},
};

const SHOW_REQUEST: &str = ".lovelyhawk-show.request";
/// How often the running copy looks for a request.
pub const SHOW_POLL: Duration = Duration::from_millis(300);
/// How long a second launch waits for the running copy to take its request.
pub const SHOW_WAIT: Duration = Duration::from_secs(3);

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

/// Called by a second launch: asks the running copy to show its window and
/// waits for it to take the request. False when nothing took it in time (the
/// running copy is stuck or still starting); the request is then withdrawn.
pub fn request_show(data_directory: &Path, wait: Duration) -> bool {
    let path = data_directory.join(SHOW_REQUEST);
    if OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .is_err()
    {
        return false;
    }
    let started = Instant::now();
    while started.elapsed() < wait {
        if !path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Taken at the last moment counts; otherwise it is withdrawn.
    std::fs::remove_file(&path).is_err() && !path.exists()
}

/// Called by the running copy: whether a second launch asked for the window,
/// consuming the request.
pub fn take_show_request(data_directory: &Path) -> bool {
    std::fs::remove_file(data_directory.join(SHOW_REQUEST)).is_ok()
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

    #[test]
    fn a_second_launch_asks_once_and_hears_whether_it_was_taken() {
        let root = std::env::temp_dir().join(format!("lovelyhawk-show-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        // Nothing asked: nothing to take.
        assert!(!take_show_request(&root));

        // Nobody takes it: the second launch hears so and leaves nothing behind.
        assert!(!request_show(&root, Duration::from_millis(200)));
        assert!(!root.join(SHOW_REQUEST).exists());
        assert!(!take_show_request(&root));

        // The running copy takes it while the second launch waits.
        let taker_root = root.clone();
        let taker = std::thread::spawn(move || {
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(5) {
                if take_show_request(&taker_root) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        });
        assert!(request_show(&root, Duration::from_secs(5)));
        assert!(taker.join().unwrap());
        // Taken once; there is no second request to find.
        assert!(!take_show_request(&root));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
