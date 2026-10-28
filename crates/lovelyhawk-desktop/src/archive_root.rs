//! Where the portable data lives.
//!
//! A packaged build keeps everything beside the executable, so a copied folder
//! carries its connections, history and evidence with it and nothing falls
//! back to a per-user profile directory. A development build may be pointed
//! elsewhere with `LOVELYHAWK_ARCHIVE_ROOT`, which automation uses so it never
//! shares a connection library with the copy the operator has open.

use std::path::{Path, PathBuf};

#[cfg(debug_assertions)]
pub const ARCHIVE_ROOT_VARIABLE: &str = "LOVELYHAWK_ARCHIVE_ROOT";

#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveRootError {
    OverrideNotAbsolute,
    ExecutableUnavailable,
    MacBundleMissing,
}

impl std::fmt::Display for ArchiveRootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::OverrideNotAbsolute => "The archive root override must be an absolute path.",
            Self::ExecutableUnavailable => "The executable location could not be resolved.",
            Self::MacBundleMissing => "A packaged macOS executable must be inside an .app bundle.",
        })
    }
}

/// Resolves the archive root for this process.
///
/// `development` is true for debug builds. Only those honour the override, so
/// a shipped build can never be redirected by its environment.
pub fn resolve(
    development: bool,
    executable: &Path,
    override_value: Option<&std::ffi::OsStr>,
) -> Result<PathBuf, ArchiveRootError> {
    if development && let Some(value) = override_value {
        let candidate = PathBuf::from(value);
        if !candidate.is_absolute() {
            return Err(ArchiveRootError::OverrideNotAbsolute);
        }
        return Ok(candidate);
    }
    let directory = executable
        .parent()
        .ok_or(ArchiveRootError::ExecutableUnavailable)?
        .to_path_buf();
    if development {
        // target/debug/lovelyhawk(.exe) → the repository root, beside the
        // Cargo workspace, matching where the Electron build kept its data.
        if let Some(root) = directory
            .ancestors()
            .find(|ancestor| ancestor.join("Cargo.toml").is_file())
        {
            return Ok(root.to_path_buf());
        }
        return Ok(directory);
    }
    if cfg!(target_os = "macos") {
        let mut candidate = directory.as_path();
        loop {
            if candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().ends_with(".app"))
            {
                return candidate
                    .parent()
                    .map(Path::to_path_buf)
                    .ok_or(ArchiveRootError::MacBundleMissing);
            }
            candidate = candidate
                .parent()
                .ok_or(ArchiveRootError::MacBundleMissing)?;
        }
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute(path: &str) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(format!("C:\\{}", path.replace('/', "\\")))
        } else {
            PathBuf::from(format!("/{path}"))
        }
    }

    #[test]
    fn packaged_builds_ignore_the_override_and_stay_beside_the_executable() {
        let executable = absolute("portable/LovelyHawk/lovelyhawk.exe");
        let override_value = absolute("elsewhere");
        let resolved = resolve(false, &executable, Some(override_value.as_os_str())).unwrap();
        if cfg!(target_os = "macos") {
            assert!(resolve(false, &executable, None).is_err());
        } else {
            assert_eq!(resolved, absolute("portable/LovelyHawk"));
        }
    }

    #[test]
    fn development_override_must_be_absolute() {
        let executable = absolute("repo/target/debug/lovelyhawk.exe");
        assert_eq!(
            resolve(
                true,
                &executable,
                Some(std::ffi::OsStr::new("relative/root"))
            ),
            Err(ArchiveRootError::OverrideNotAbsolute)
        );
        let chosen = absolute("automation/run-1");
        assert_eq!(
            resolve(true, &executable, Some(chosen.as_os_str())).unwrap(),
            chosen
        );
    }
}
