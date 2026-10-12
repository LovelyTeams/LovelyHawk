//! The readiness marker the portable smoke test waits for.
//!
//! Written once, when the main page reports it rendered, and only into a
//! directory the smoke script created under the system temporary directory.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const ROOT_VARIABLE: &str = "LOVELYHAWK_SMOKE_READY_ROOT";
pub const NONCE_VARIABLE: &str = "LOVELYHAWK_SMOKE_READY_NONCE";
const MARKER: &[u8] = br#"{"schema":"lovelyhawk-smoke-ready/v1","status":"ready"}"#;

pub fn write_requested_marker() -> Result<(), String> {
    let root = std::env::var_os(ROOT_VARIABLE);
    let nonce = std::env::var(NONCE_VARIABLE).ok();
    match (root, nonce) {
        (None, None) => Ok(()),
        (Some(root), Some(nonce)) => write_marker(&std::env::temp_dir(), Path::new(&root), &nonce),
        _ => Err("smoke marker variables must be set together".to_owned()),
    }
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn write_marker(temporary: &Path, requested: &Path, nonce: &str) -> Result<(), String> {
    if !valid_nonce(nonce) {
        return Err("invalid smoke nonce".to_owned());
    }
    let temporary = fs::canonicalize(temporary).map_err(|error| error.to_string())?;
    let root: PathBuf = fs::canonicalize(requested).map_err(|error| error.to_string())?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let controlled = root.parent() == Some(temporary.as_path())
        && name
            .strip_prefix("lovelyhawk-smoke-")
            .is_some_and(valid_nonce);
    if !controlled {
        return Err("smoke marker root must be a controlled temporary directory".to_owned());
    }
    let destination = root.join(format!("ready-{nonce}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| error.to_string())?;
    file.write_all(MARKER)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_go_only_into_a_controlled_directory_once() {
        let temporary = std::env::temp_dir();
        let nonce = "0123456789abcdef0123456789abcdef";
        let root = temporary.join(format!(
            "lovelyhawk-smoke-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).unwrap();
        write_marker(&temporary, &root, nonce).unwrap();
        assert!(write_marker(&temporary, &root, nonce).is_err());
        assert!(write_marker(&temporary, &root, "not-a-nonce").is_err());
        let elsewhere = root.join("nested-lovelyhawk-smoke-0123456789abcdef0123456789abcdef");
        fs::create_dir_all(&elsewhere).unwrap();
        assert!(write_marker(&temporary, &elsewhere, nonce).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
