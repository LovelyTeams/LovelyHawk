//! Reads the operator's own machine for the SSH window's local pane.
//!
//! A page never holds a filesystem path: every directory it can open came back
//! from here as an opaque handle, and a handle only ever names a directory this
//! registry produced. A compromised page therefore cannot ask for an arbitrary
//! path, and the local pane has the same shape as the remote one.

use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde::Serialize;

const MAX_DIRECTORIES: usize = 512;
const MAX_FILES: usize = 4_096;
const READ_DEADLINE: Duration = Duration::from_secs(10);
// Mirrors LOCAL_BROWSER_LIMITS in ui/src/shared/local-browser-contract.ts.
const MAXIMUM_DISPLAYED_ENTRIES: usize = 256;
const MAXIMUM_OBSERVED_ENTRIES: usize = 50_000;
const MAXIMUM_NAME_BYTES: usize = 256;
const MAXIMUM_LABEL_BYTES: usize = 512;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalBrowserEntry {
    entry_handle: String,
    name: String,
    name_truncated: bool,
    kind: &'static str,
    size_bytes: String,
    modified_at: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalDirectorySnapshot {
    directory_handle: String,
    parent_directory_handle: Option<String>,
    directory_label: String,
    directory_label_truncated: bool,
    observed_entry_count: usize,
    displayed_entry_count: usize,
    truncated: bool,
    entries: Vec<LocalBrowserEntry>,
}

#[derive(Debug, Default)]
pub struct LocalBrowser {
    directories: HashMap<String, PathBuf>,
    directory_handles: HashMap<PathBuf, String>,
    directory_order: VecDeque<String>,
    files: HashMap<String, PathBuf>,
    file_order: VecDeque<String>,
}

pub const UNKNOWN_DIRECTORY: &str = "本机目录已失效，请重新打开。";
pub const READ_FAILED: &str = "无法读取这个本机目录。";

impl LocalBrowser {
    /// The operator's home directory, the one fixed entry point.
    pub fn open(&mut self, home: &Path) -> Result<LocalDirectorySnapshot, &'static str> {
        let directory = fs::canonicalize(home).map_err(|_| READ_FAILED)?;
        if !directory.is_dir() {
            return Err(READ_FAILED);
        }
        self.read(&directory)
    }

    pub fn list(&mut self, directory_handle: &str) -> Result<LocalDirectorySnapshot, &'static str> {
        let directory = self
            .directories
            .get(directory_handle)
            .cloned()
            .ok_or(UNKNOWN_DIRECTORY)?;
        self.read(&directory)
    }

    /// The file behind a handle, only for staging an upload in the host. An
    /// unknown handle resolves to nothing rather than to a guess.
    pub fn resolve_file(&self, entry_handle: &str) -> Option<PathBuf> {
        self.files.get(entry_handle).cloned()
    }

    fn read(&mut self, directory: &Path) -> Result<LocalDirectorySnapshot, &'static str> {
        let started = SystemTime::now();
        let reader = fs::read_dir(directory).map_err(|_| READ_FAILED)?;
        let mut names = Vec::new();
        let mut observed = 0usize;
        for entry in reader {
            if started.elapsed().unwrap_or_default() > READ_DEADLINE {
                return Err(READ_FAILED);
            }
            let Ok(entry) = entry else { continue };
            observed += 1;
            if names.len() < MAXIMUM_DISPLAYED_ENTRIES {
                names.push(entry.file_name());
            }
            if observed >= MAXIMUM_OBSERVED_ENTRIES {
                break;
            }
        }
        let mut entries = Vec::with_capacity(names.len());
        for name in names {
            if let Some(entry) = self.describe(directory, &name) {
                entries.push(entry);
            }
        }
        entries.sort_by(|left, right| {
            (left.kind != "directory")
                .cmp(&(right.kind != "directory"))
                .then_with(|| left.name.cmp(&right.name))
        });
        let parent = directory
            .parent()
            .filter(|parent| *parent != directory)
            .map(Path::to_path_buf);
        let (label, label_truncated) = bounded(&display(directory), MAXIMUM_LABEL_BYTES);
        let displayed = entries.len();
        Ok(LocalDirectorySnapshot {
            directory_handle: self.directory_handle(directory.to_path_buf()),
            parent_directory_handle: parent.map(|parent| self.directory_handle(parent)),
            directory_label: label,
            directory_label_truncated: label_truncated,
            observed_entry_count: observed,
            displayed_entry_count: displayed,
            truncated: observed > displayed,
            entries,
        })
    }

    fn describe(&mut self, directory: &Path, name: &std::ffi::OsStr) -> Option<LocalBrowserEntry> {
        let full = directory.join(name);
        let mut kind = "other";
        let mut size_bytes = "0".to_owned();
        let mut modified_at = None;
        // A symbolic link is described by what it is, never followed blindly.
        if let Ok(metadata) = fs::symlink_metadata(&full) {
            if metadata.is_dir() {
                kind = "directory";
            } else if metadata.is_file() {
                kind = "file";
                size_bytes = metadata.len().to_string();
            }
            modified_at = metadata.modified().ok().and_then(iso_timestamp);
        }
        let (label, truncated) = bounded(&name.to_string_lossy(), MAXIMUM_NAME_BYTES);
        if label.is_empty() {
            return None;
        }
        let entry_handle = match kind {
            "directory" => self.directory_handle(full),
            "file" => self.file_handle(full),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        Some(LocalBrowserEntry {
            entry_handle,
            name: label,
            name_truncated: truncated,
            kind,
            size_bytes,
            modified_at,
        })
    }

    fn directory_handle(&mut self, directory: PathBuf) -> String {
        if let Some(existing) = self.directory_handles.get(&directory) {
            return existing.clone();
        }
        if self.directories.len() >= MAX_DIRECTORIES
            && let Some(oldest) = self.directory_order.pop_front()
            && let Some(path) = self.directories.remove(&oldest)
        {
            self.directory_handles.remove(&path);
        }
        let handle = uuid::Uuid::new_v4().to_string();
        self.directories.insert(handle.clone(), directory.clone());
        self.directory_handles.insert(directory, handle.clone());
        self.directory_order.push_back(handle.clone());
        handle
    }

    fn file_handle(&mut self, file: PathBuf) -> String {
        if self.files.len() >= MAX_FILES
            && let Some(oldest) = self.file_order.pop_front()
        {
            self.files.remove(&oldest);
        }
        let handle = uuid::Uuid::new_v4().to_string();
        self.files.insert(handle.clone(), file);
        self.file_order.push_back(handle.clone());
        handle
    }
}

/// Windows canonical paths carry a `\\?\` prefix nobody wants to read.
fn display(path: &Path) -> String {
    let text = path.to_string_lossy();
    text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned()
}

fn iso_timestamp(time: SystemTime) -> Option<String> {
    let since = time.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    let seconds = i64::try_from(since.as_secs()).ok()?;
    let days = seconds.div_euclid(86_400);
    let remainder = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        remainder / 3_600,
        (remainder % 3_600) / 60,
        remainder % 60,
        since.subsec_millis()
    ))
}

/// Howard Hinnant's days-to-civil conversion, for UTC timestamps without a
/// date library.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Renderable display text: no control characters, bounded bytes.
pub fn bounded(value: &str, maximum_bytes: usize) -> (String, bool) {
    let plain: String = value
        .chars()
        .filter(|character| (*character as u32) >= 0x20 && *character != '\u{7f}')
        .collect();
    let mut truncated = plain.chars().count() != value.chars().count();
    if plain.len() <= maximum_bytes {
        return (plain, truncated);
    }
    let mut text = String::new();
    for character in plain.chars() {
        if text.len() + character.len_utf8() > maximum_bytes {
            break;
        }
        text.push(character);
    }
    truncated = true;
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_only_name_what_the_registry_listed() {
        let root = std::env::temp_dir().join(format!("lovelyhawk-local-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("child")).unwrap();
        fs::write(root.join("note.txt"), b"hello").unwrap();
        let mut browser = LocalBrowser::default();
        let snapshot = browser.open(&root).unwrap();
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(snapshot.entries[0].kind, "directory");
        let file = snapshot
            .entries
            .iter()
            .find(|entry| entry.kind == "file")
            .unwrap();
        assert_eq!(file.size_bytes, "5");
        assert!(browser.resolve_file(&file.entry_handle).is_some());
        assert!(browser.resolve_file("made-up").is_none());
        assert_eq!(browser.list("made-up"), Err(UNKNOWN_DIRECTORY));
        let child = browser.list(&snapshot.entries[0].entry_handle).unwrap();
        assert_eq!(
            child.parent_directory_handle.as_deref(),
            Some(snapshot.directory_handle.as_str())
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn display_text_is_bounded_and_plain() {
        assert_eq!(bounded("a\u{1}b", 16), ("ab".to_owned(), true));
        let (text, truncated) = bounded(&"界".repeat(200), 10);
        assert_eq!((text.len(), truncated), (9, true));
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }
}
