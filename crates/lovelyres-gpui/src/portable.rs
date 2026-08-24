use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow, bail};
use uuid::Uuid;

pub const SMOKE_READY_SCHEMA: &str = "lovelyres-smoke-ready/v1";
const SMOKE_READY_PAYLOAD: &[u8] = br#"{"schema":"lovelyres-smoke-ready/v1","status":"ready"}"#;

/// Writes the release-ready marker only when the smoke harness asks for one.
/// Call this from a window's first-frame callback, never from `main`.
pub fn write_requested_smoke_marker() -> Result<Option<PathBuf>> {
    let Some(raw_path) = env::var_os("LOVELYRES_SMOKE_READY_FILE") else {
        return Ok(None);
    };
    if raw_path.is_empty() {
        bail!("LOVELYRES_SMOKE_READY_FILE is empty");
    }
    let path = PathBuf::from(raw_path);
    atomic_replace(&path, SMOKE_READY_PAYLOAD)?;
    Ok(Some(path))
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("smoke marker has no parent directory"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create smoke marker directory {}", parent.display()))?;
    let temp = parent.join(format!(".lovelyres-smoke-{}.tmp", Uuid::new_v4()));

    let write_result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);

        match fs::rename(&temp, path) {
            Ok(()) => Ok(()),
            Err(error) if path.exists() => {
                fs::remove_file(path)?;
                fs::rename(&temp, path)?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    })();

    if write_result.is_err() {
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
    write_result.with_context(|| format!("cannot write smoke marker {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_payload_keeps_release_contract() {
        let payload: serde_json::Value = serde_json::from_slice(SMOKE_READY_PAYLOAD).unwrap();
        assert_eq!(payload["schema"], SMOKE_READY_SCHEMA);
        assert_eq!(payload["status"], "ready");
    }
}
