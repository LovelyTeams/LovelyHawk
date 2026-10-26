//! Versioned, portable persistence rooted beside the application archive.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, CoreResult};

pub const SCHEMA_VERSION: u32 = 1;

/// Files owned by the portable core store. Callers cannot smuggle arbitrary paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFile {
    Settings,
    Connections,
    Cases,
    Notes,
    History,
    DetectionHistory,
    OperationJournal,
    Snapshots,
    Integrity,
    Audit,
    Database,
    Firewall,
    Baseline,
    WindowsBaseline,
    Batch,
    Java,
    Middleware,
    LogRules,
}

impl StoreFile {
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::Settings => "settings.json",
            Self::Connections => "connections.json",
            Self::Cases => "cases.json",
            Self::Notes => "notes.json",
            Self::History => "history.json",
            Self::DetectionHistory => "detection-history.json",
            Self::OperationJournal => "operation-journal.json",
            Self::Snapshots => "snapshots.json",
            Self::Integrity => "integrity.json",
            Self::Audit => "audit.json",
            Self::Database => "database-connections.json",
            Self::Firewall => "firewall.json",
            Self::Baseline => "baseline-history.json",
            Self::WindowsBaseline => "LovelyHawk-windows-baseline-history.json",
            Self::Batch => "batch-history.json",
            Self::Java => "java-history.json",
            Self::Middleware => "middleware-history.json",
            Self::LogRules => "log-rules.json",
        }
    }

    const fn subject(self) -> &'static str {
        match self {
            Self::Settings => "settings",
            Self::Connections => "connections",
            Self::Cases => "cases",
            Self::Notes => "notes",
            Self::History => "history",
            Self::DetectionHistory => "detection history",
            Self::OperationJournal => "operation journal",
            Self::Snapshots => "snapshots",
            Self::Integrity => "integrity baselines",
            Self::Audit => "command audit deployments",
            Self::Database => "database connections",
            Self::Firewall => "firewall changes",
            Self::Baseline => "baseline changes",
            Self::WindowsBaseline => "Windows baseline changes",
            Self::Batch => "multi-host batch history",
            Self::Java => "Java updates",
            Self::Middleware => "middleware changes",
            Self::LogRules => "log analysis rules",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VersionedDocument<T> {
    schema_version: u32,
    data: T,
}

/// A store whose only persistent root is `<archive-root>/data`.
///
/// Construction never consults AppData, `$HOME`, the current directory, or an
/// environment variable. The caller must provide the executable/archive location.
#[derive(Debug, Clone)]
pub struct PortableStore {
    root: PathBuf,
    write_lock: Arc<Mutex<()>>,
}

impl PortableStore {
    /// Prepare a portable store below an explicit archive root.
    pub fn prepare(archive_root: PathBuf) -> CoreResult<Self> {
        if !archive_root.is_absolute() {
            return Err(CoreError::validation(
                "portable archive root",
                "the archive root must be an absolute path",
            ));
        }
        let store = Self {
            root: archive_root.join("data"),
            write_lock: Arc::new(Mutex::new(())),
        };
        store.ensure_ready()?;
        Ok(store)
    }

    /// Resolve the archive root from an explicit executable path.
    ///
    /// On macOS the data directory is placed beside the `.app` bundle, not
    /// inside it, so updating or signing the bundle never mutates user data.
    pub fn from_executable_path(executable_path: impl AsRef<Path>) -> CoreResult<Self> {
        let executable_path = executable_path.as_ref();
        if !executable_path.is_absolute() {
            return Err(CoreError::validation(
                "executable path",
                "the executable path must be absolute",
            ));
        }

        #[cfg(target_os = "macos")]
        let archive_root = executable_path
            .ancestors()
            .find(|path| path.extension().is_some_and(|extension| extension == "app"))
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .or_else(|| executable_path.parent().map(Path::to_path_buf));

        #[cfg(not(target_os = "macos"))]
        let archive_root = executable_path.parent().map(Path::to_path_buf);

        let archive_root = archive_root.ok_or_else(|| {
            CoreError::validation("executable path", "the executable has no parent directory")
        })?;
        Self::prepare(archive_root)
    }

    /// The actual persistent data root (`<archive-root>/data`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    pub fn temp_dir(&self) -> PathBuf {
        self.root.join("temp")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn path_for(&self, document: StoreFile) -> PathBuf {
        self.root.join(document.file_name())
    }

    /// Create required directories and prove that the data root is writable.
    pub fn ensure_ready(&self) -> CoreResult<()> {
        let _guard = self.write_lock.lock();
        for directory in [
            self.root.clone(),
            self.backups_dir(),
            self.temp_dir(),
            self.logs_dir(),
        ] {
            fs::create_dir_all(&directory)
                .map_err(|source| CoreError::io("create directory", &directory, source))?;
        }
        self.probe_writable_locked()
    }

    pub fn read<T: DeserializeOwned>(&self, document: StoreFile) -> CoreResult<Option<T>> {
        self.read_bounded(document, usize::MAX)
    }

    /// Read a portable document only when its encoded file is within a caller-owned budget.
    /// The metadata check happens before allocating a buffer for attacker-controlled data.
    pub fn read_bounded<T: DeserializeOwned>(
        &self,
        document: StoreFile,
        maximum_bytes: usize,
    ) -> CoreResult<Option<T>> {
        let _guard = self.write_lock.lock();
        let path = self.path_for(document);
        if !path.exists() {
            return Ok(None);
        }
        let encoded_len = fs::metadata(&path)
            .map_err(|source| CoreError::io("inspect", &path, source))?
            .len();
        if encoded_len > maximum_bytes as u64 {
            return Err(CoreError::validation(
                document.subject(),
                "the encoded portable document exceeds its aggregate storage budget",
            ));
        }
        let bytes = if maximum_bytes == usize::MAX {
            fs::read(&path).map_err(|source| CoreError::io("read", &path, source))?
        } else {
            let file = File::open(&path).map_err(|source| CoreError::io("open", &path, source))?;
            let mut bytes = Vec::with_capacity((encoded_len as usize).min(maximum_bytes));
            file.take(maximum_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|source| CoreError::io("read bounded", &path, source))?;
            if bytes.len() > maximum_bytes {
                return Err(CoreError::validation(
                    document.subject(),
                    "the encoded portable document exceeds its aggregate storage budget",
                ));
            }
            bytes
        };
        let envelope: VersionedDocument<T> =
            serde_json::from_slice(&bytes).map_err(|source| CoreError::Decode {
                subject: document.subject(),
                source,
            })?;
        if envelope.schema_version != SCHEMA_VERSION {
            return Err(CoreError::UnsupportedSchema {
                document: document.subject(),
                expected: SCHEMA_VERSION,
                actual: envelope.schema_version,
            });
        }
        Ok(Some(envelope.data))
    }

    pub fn read_or_default<T>(&self, document: StoreFile) -> CoreResult<T>
    where
        T: DeserializeOwned + Default,
    {
        Ok(self.read(document)?.unwrap_or_default())
    }

    pub fn read_or_default_bounded<T>(
        &self,
        document: StoreFile,
        maximum_bytes: usize,
    ) -> CoreResult<T>
    where
        T: DeserializeOwned + Default,
    {
        Ok(self
            .read_bounded(document, maximum_bytes)?
            .unwrap_or_default())
    }

    /// Persist a schema-v1 JSON document using a flushed same-directory temp file.
    /// Existing data is moved to a unique backup before the atomic temp rename.
    pub fn write<T: Serialize>(&self, document: StoreFile, data: &T) -> CoreResult<()> {
        self.write_bounded(document, data, usize::MAX)
    }

    /// Reject an oversized encoded document before creating files or replacing
    /// the previous version. The same budget can be used by read_bounded.
    pub fn write_bounded<T: Serialize>(
        &self,
        document: StoreFile,
        data: &T,
        maximum_bytes: usize,
    ) -> CoreResult<()> {
        let envelope = VersionedDocument {
            schema_version: SCHEMA_VERSION,
            data,
        };
        let bytes = serde_json::to_vec_pretty(&envelope).map_err(|source| CoreError::Encode {
            subject: document.subject(),
            source,
        })?;
        if bytes.len() > maximum_bytes {
            return Err(CoreError::validation(
                "store write size",
                "encoded document exceeds its storage budget; existing data was preserved",
            ));
        }
        let _guard = self.write_lock.lock();
        self.atomic_replace_locked(&self.path_for(document), &bytes, true)
    }

    fn probe_writable_locked(&self) -> CoreResult<()> {
        let path = self.root.join(format!(".write-probe-{}", Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|source| CoreError::io("create write probe", &path, source))?;
            file.write_all(b"lovelyres-portable-store")
                .map_err(|source| CoreError::io("write probe", &path, source))?;
            file.sync_all()
                .map_err(|source| CoreError::io("flush write probe", &path, source))?;
            Ok(())
        })();
        if let Err(source) = fs::remove_file(&path)
            && result.is_ok()
        {
            return Err(CoreError::io("remove write probe", path, source));
        }
        result
    }

    fn atomic_replace_locked(
        &self,
        destination: &Path,
        bytes: &[u8],
        backup: bool,
    ) -> CoreResult<()> {
        let file_name = destination.file_name().ok_or_else(|| {
            CoreError::validation("store destination", "destination has no file name")
        })?;
        let temporary = destination.with_file_name(format!(
            ".{}.tmp-{}",
            file_name.to_string_lossy(),
            Uuid::new_v4()
        ));

        let write_result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)
                .map_err(|source| CoreError::io("create temporary file", &temporary, source))?;
            file.write_all(bytes)
                .map_err(|source| CoreError::io("write temporary file", &temporary, source))?;
            file.flush()
                .map_err(|source| CoreError::io("flush temporary file", &temporary, source))?;
            file.sync_all()
                .map_err(|source| CoreError::io("sync temporary file", &temporary, source))?;
            Ok(())
        })();
        if let Err(error) = write_result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }

        let previous = if destination.exists() {
            let previous = if backup {
                self.backups_dir().join(format!(
                    "{}.{}-{}.bak",
                    file_name.to_string_lossy(),
                    chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"),
                    Uuid::new_v4()
                ))
            } else {
                destination.with_file_name(format!(
                    ".{}.previous-{}",
                    file_name.to_string_lossy(),
                    Uuid::new_v4()
                ))
            };
            if let Err(source) = fs::rename(destination, &previous) {
                let _ = fs::remove_file(&temporary);
                return Err(CoreError::io("move previous file", destination, source));
            }
            Some(previous)
        } else {
            None
        };

        if let Err(source) = fs::rename(&temporary, destination) {
            if let Some(previous) = previous.as_ref() {
                let _ = fs::rename(previous, destination);
            }
            let _ = fs::remove_file(&temporary);
            return Err(CoreError::io(
                "atomically replace destination",
                destination,
                source,
            ));
        }

        if !backup && let Some(previous) = previous {
            let _ = fs::remove_file(previous);
        }
        Ok(())
    }

    pub(crate) fn load_or_create_secret_key(
        &self,
        generate: impl FnOnce() -> [u8; 32],
    ) -> CoreResult<[u8; 32]> {
        let _guard = self.write_lock.lock();
        let path = self.root.join("encryption.key");
        if path.exists() {
            let mut bytes = Vec::new();
            File::open(&path)
                .and_then(|mut file| file.read_to_end(&mut bytes))
                .map_err(|source| CoreError::io("read encryption key", &path, source))?;
            if bytes.len() != 32 {
                return Err(CoreError::Crypto(format!(
                    "encryption key must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        let key = generate();
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|source| CoreError::io("create encryption key", &path, source))?;
        file.write_all(&key)
            .map_err(|source| CoreError::io("write encryption key", &path, source))?;
        file.sync_all()
            .map_err(|source| CoreError::io("sync encryption key", &path, source))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyhawk-core-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn portable_root_is_explicit_and_never_appdata() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        assert_eq!(store.root(), root.0.join("data"));
        assert!(store.backups_dir().is_dir());
        assert!(store.temp_dir().is_dir());
        assert!(store.logs_dir().is_dir());
    }

    #[test]
    fn rejects_relative_roots() {
        assert!(PortableStore::prepare(PathBuf::from("relative/archive")).is_err());
        assert!(PortableStore::from_executable_path("LovelyHawk.exe").is_err());
    }

    #[test]
    fn bounded_write_rejects_the_encoded_envelope_before_touching_existing_data() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        store.write(StoreFile::Cases, &vec!["preserved"]).unwrap();
        let previous = fs::read(store.path_for(StoreFile::Cases)).unwrap();
        let backups = fs::read_dir(store.backups_dir()).unwrap().count();
        assert!(
            store
                .write_bounded(StoreFile::Cases, &vec!["\u{0001}".repeat(30)], 100)
                .is_err()
        );
        assert_eq!(
            fs::read(store.path_for(StoreFile::Cases)).unwrap(),
            previous
        );
        assert_eq!(fs::read_dir(store.backups_dir()).unwrap().count(), backups);
        assert!(
            store
                .read_bounded::<Vec<String>>(StoreFile::Cases, previous.len() - 1)
                .is_err()
        );
    }

    #[test]
    fn writes_schema_v1_and_keeps_previous_backup() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let first = BTreeMap::from([("theme".to_owned(), "dark".to_owned())]);
        let second = BTreeMap::from([("theme".to_owned(), "sakura".to_owned())]);
        store.write(StoreFile::Settings, &first).unwrap();
        store.write(StoreFile::Settings, &second).unwrap();

        let loaded: BTreeMap<String, String> = store.read(StoreFile::Settings).unwrap().unwrap();
        assert_eq!(loaded, second);
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(store.path_for(StoreFile::Settings)).unwrap())
                .unwrap();
        assert_eq!(raw["schema_version"], SCHEMA_VERSION);
        assert_eq!(fs::read_dir(store.backups_dir()).unwrap().count(), 1);
        assert!(
            fs::read_dir(store.root())
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-"))
        );
    }

    #[test]
    fn rejects_unknown_schema_without_rewriting_it() {
        let root = TestRoot::new();
        let store = PortableStore::prepare(root.0.clone()).unwrap();
        let path = store.path_for(StoreFile::Notes);
        fs::write(&path, br#"{"schema_version":2,"data":[]}"#).unwrap();
        let error = store.read::<Vec<String>>(StoreFile::Notes).unwrap_err();
        assert!(matches!(
            error,
            CoreError::UnsupportedSchema { actual: 2, .. }
        ));
        assert!(path.exists());
    }

    #[test]
    fn writable_probe_blocks_when_data_path_is_a_file() {
        let root = TestRoot::new();
        fs::write(root.0.join("data"), b"not a directory").unwrap();
        assert!(PortableStore::prepare(root.0.clone()).is_err());
    }
}
