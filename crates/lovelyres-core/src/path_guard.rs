//! Explicit-root local path protection for SFTP upload and download flows.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use uuid::Uuid;

use crate::{CoreError, CoreResult, PortableStore};

#[derive(Debug, Clone)]
pub struct PathGuard {
    managed_upload_root: PathBuf,
    sensitive_roots: Vec<PathBuf>,
}

impl PathGuard {
    pub fn new(
        managed_upload_root: PathBuf,
        sensitive_roots: impl IntoIterator<Item = PathBuf>,
    ) -> CoreResult<Self> {
        if !managed_upload_root.is_absolute() {
            return Err(CoreError::validation(
                "managed upload root",
                "must be an absolute path",
            ));
        }
        fs::create_dir_all(&managed_upload_root).map_err(|source| {
            CoreError::io("create managed upload root", &managed_upload_root, source)
        })?;
        let managed_upload_root = fs::canonicalize(&managed_upload_root).map_err(|source| {
            CoreError::io(
                "canonicalize managed upload root",
                &managed_upload_root,
                source,
            )
        })?;
        let sensitive_roots = sensitive_roots
            .into_iter()
            .map(|path| {
                if !path.is_absolute() {
                    return Err(CoreError::validation(
                        "sensitive path root",
                        "must be an absolute path",
                    ));
                }
                canonicalize_with_missing_tail(&path)
                    .map_err(|source| CoreError::io("resolve sensitive path root", path, source))
            })
            .collect::<CoreResult<Vec<_>>>()?;
        Ok(Self {
            managed_upload_root,
            sensitive_roots,
        })
    }

    pub fn for_store(
        store: &PortableStore,
        sensitive_roots: impl IntoIterator<Item = PathBuf>,
    ) -> CoreResult<Self> {
        Self::new(store.temp_dir().join("uploads"), sensitive_roots)
    }

    pub fn managed_upload_root(&self) -> &Path {
        &self.managed_upload_root
    }

    /// Stage bytes under an unguessable core-owned name. The original filename
    /// is intentionally not used as a path component.
    pub fn stage_upload(&self, bytes: &[u8]) -> CoreResult<PathBuf> {
        let path = self
            .managed_upload_root
            .join(format!("upload-{}", Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|source| CoreError::io("create staged upload", &path, source))?;
        file.write_all(bytes)
            .map_err(|source| CoreError::io("write staged upload", &path, source))?;
        file.sync_all()
            .map_err(|source| CoreError::io("sync staged upload", &path, source))?;
        Ok(path)
    }

    /// Copy a file chosen by a native path dialog into the core-owned upload
    /// namespace. The original name is never reused as a path component.
    pub fn stage_native_selected_upload(
        &self,
        selected: &Path,
        maximum_bytes: u64,
    ) -> CoreResult<PathBuf> {
        if !selected.is_absolute() {
            return Err(CoreError::validation(
                "native upload selection",
                "must be an absolute path returned by the native dialog",
            ));
        }
        let metadata = fs::symlink_metadata(selected)
            .map_err(|source| CoreError::io("inspect native upload selection", selected, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(CoreError::validation(
                "native upload selection",
                "must be a regular non-symlink file",
            ));
        }
        if metadata.len() > maximum_bytes {
            return Err(CoreError::validation(
                "native upload selection",
                format!("must be no larger than {maximum_bytes} bytes"),
            ));
        }

        let path = self
            .managed_upload_root
            .join(format!("upload-{}", Uuid::new_v4()));
        let result = (|| -> CoreResult<()> {
            let mut source = fs::File::open(selected)
                .map_err(|error| CoreError::io("open native upload selection", selected, error))?;
            let mut target = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .map_err(|error| CoreError::io("create staged upload", &path, error))?;
            let copied = std::io::copy(
                &mut std::io::Read::by_ref(&mut source).take(maximum_bytes + 1),
                &mut target,
            )
            .map_err(|error| CoreError::io("copy staged upload", &path, error))?;
            if copied > maximum_bytes || copied != metadata.len() {
                return Err(CoreError::validation(
                    "native upload selection",
                    "file changed while it was being staged",
                ));
            }
            target
                .sync_all()
                .map_err(|error| CoreError::io("sync staged upload", &path, error))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(path)
    }

    pub fn is_managed_upload_file(&self, candidate: &Path) -> bool {
        let Ok(candidate) = fs::canonicalize(candidate) else {
            return false;
        };
        candidate.is_file() && candidate.parent() == Some(self.managed_upload_root.as_path())
    }

    pub fn ensure_managed_upload_source(&self, candidate: &Path) -> CoreResult<PathBuf> {
        if !self.is_managed_upload_file(candidate) {
            return Err(CoreError::validation(
                "upload source",
                format!(
                    "must be a regular file staged directly below {}",
                    self.managed_upload_root.display()
                ),
            ));
        }
        fs::canonicalize(candidate)
            .map_err(|source| CoreError::io("canonicalize upload source", candidate, source))
    }

    /// Validate a native save-dialog result before writing remote bytes locally.
    pub fn ensure_safe_download_target(&self, candidate: &Path) -> CoreResult<PathBuf> {
        if !candidate.is_absolute() {
            return Err(CoreError::validation(
                "download target",
                "must be an absolute path selected by the native save dialog",
            ));
        }
        if candidate
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(CoreError::validation(
                "download target",
                "must not contain parent-directory components",
            ));
        }
        let resolved = canonicalize_with_missing_tail(candidate).map_err(|source| {
            CoreError::io("resolve download target", candidate.to_path_buf(), source)
        })?;
        for sensitive in &self.sensitive_roots {
            if resolved == *sensitive || resolved.starts_with(sensitive) {
                return Err(CoreError::validation(
                    "download target",
                    format!(
                        "refuses to write below sensitive root {}",
                        sensitive.display()
                    ),
                ));
            }
        }
        Ok(resolved)
    }
}

/// Construct the legacy sensitive-directory set from an explicit home path.
/// The core never discovers a home/AppData directory on its own.
pub fn sensitive_roots_for_home(home: &Path) -> Vec<PathBuf> {
    [".ssh", ".aws", ".gnupg", ".docker", ".kube"]
        .into_iter()
        .map(|relative| home.join(relative))
        .chain(std::iter::once(home.join(".config").join("LovelyRes")))
        .collect()
}

fn canonicalize_with_missing_tail(path: &Path) -> std::io::Result<PathBuf> {
    let mut cursor = path;
    let mut missing = Vec::<OsString>::new();
    while !cursor.exists() {
        let Some(file_name) = cursor.file_name() else {
            break;
        };
        missing.push(file_name.to_os_string());
        cursor = cursor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path has no existing ancestor",
            )
        })?;
    }
    let mut resolved = fs::canonicalize(cursor)?;
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lovelyres-path-{}", Uuid::new_v4()));
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
    fn only_core_staged_files_are_uploadable() {
        let root = TestRoot::new();
        let uploads = root.0.join("uploads");
        let guard = PathGuard::new(uploads.clone(), []).unwrap();
        let staged = guard.stage_upload(b"evidence").unwrap();
        assert_eq!(guard.ensure_managed_upload_source(&staged).unwrap(), staged);

        let arbitrary = root.0.join("ssh-key");
        fs::write(&arbitrary, b"secret").unwrap();
        assert!(guard.ensure_managed_upload_source(&arbitrary).is_err());
        assert!(guard.ensure_managed_upload_source(&uploads).is_err());
        assert!(
            guard
                .ensure_managed_upload_source(Path::new("../../secret"))
                .is_err()
        );
    }

    #[test]
    fn download_blocks_traversal_and_sensitive_roots() {
        let root = TestRoot::new();
        let sensitive = root.0.join("home").join(".ssh");
        fs::create_dir_all(&sensitive).unwrap();
        let guard = PathGuard::new(root.0.join("uploads"), [sensitive.clone()]).unwrap();
        assert!(
            guard
                .ensure_safe_download_target(&sensitive.join("authorized_keys"))
                .is_err()
        );
        assert!(
            guard
                .ensure_safe_download_target(&root.0.join("safe").join("..").join("evil"))
                .is_err()
        );
        assert!(
            guard
                .ensure_safe_download_target(Path::new("relative.bin"))
                .is_err()
        );
    }

    #[test]
    fn download_allows_nonexistent_ordinary_target() {
        let root = TestRoot::new();
        let guard = PathGuard::new(root.0.join("uploads"), []).unwrap();
        let target = root.0.join("evidence").join("capture.pcap");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let resolved = guard.ensure_safe_download_target(&target).unwrap();
        let expected = fs::canonicalize(target.parent().unwrap())
            .unwrap()
            .join(target.file_name().unwrap());
        assert_eq!(resolved, expected);
    }

    #[test]
    fn native_selection_is_streamed_into_an_opaque_bounded_staging_file() {
        let root = TestRoot::new();
        let guard = PathGuard::new(root.0.join("uploads"), []).unwrap();
        let selected = root.0.join("attacker-controlled-name.txt");
        fs::write(&selected, b"evidence").unwrap();
        let staged = guard.stage_native_selected_upload(&selected, 1024).unwrap();
        assert_eq!(fs::read(&staged).unwrap(), b"evidence");
        assert_ne!(staged.file_name(), selected.file_name());
        assert!(guard.is_managed_upload_file(&staged));
        assert!(guard.stage_native_selected_upload(&selected, 2).is_err());
    }
}
